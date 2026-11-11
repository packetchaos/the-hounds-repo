"""⚡ Optimize navi.db for the Hounds — the index + statistics step from the SQL review
(scale plan §2 / §6).

What it does, on navi.db itself (a SEPARATE write connection; the console's own
connection stays read-only):
  1. CREATE INDEX IF NOT EXISTS for the seven `hx_*` indexes below — only for tables and
     columns this navi.db has (navi versions differ). One index per transaction, so a
     cancel loses at most the one being built.
  2. PRAGMA analysis_limit=1000; ANALYZE   (bounded: seconds even at 420M rows).
  3. The 'unordered' fix: append ' unordered' to the sqlite_stat1 rows of the vulns indexes
     (hx_v_plugin, hx_v_asset and navi's idx_plugin) and reload them (ANALYZE sqlite_schema).
     Without it SQLite answers `DISTINCT asset_uuid` / `GROUP BY asset_uuid` over vulns by
     walking the index in order with one random table read per row (measured 6 s → 301 s).
     EVERY later ANALYZE (navi's own `config optimize` runs one) erases it, so this step always
     re-applies it, and reapply_unordered() is the cheap repair after a sync.

navi's own `navi config optimize` builds idx_plugin/idx_OSes/… — none of them lead with
asset_uuid, so per-asset reads and the tags-for-an-asset-set joins stay full scans.

Figures (SQL review s4, scale.db 6M and scale600k.db 16M vulns, SQLite 3.53):
  • vulns index size ≈ 58.5 B per row each (350 MB @6M, 940 MB @16M) → ≈ 24.5 GB each @420M.
  • build ≈ rows ÷ ~600k rows/s per vulns index when cached (10.1 s @6M, 28.5 s @16M), plus one
    sequential read of navi.db per vulns index when it isn't cached (0.3–1 GB/s) → ≈ 15–25 min
    total @105M, ≈ 1–1.7 h @420M.  ANALYZE with analysis_limit=1000: 1.9 s @6M, 3.7 s @16M.
  • the sorter spills about the index size again to the temp dir → the run needs free disk
    ≥ 2 × the estimated index bytes.
"""
import os
import shutil
import sqlite3
import tempfile
import threading
import time

from core import hx_summary

# (name, table, columns, bytes-per-row estimate). Order = build order: the two big vulns
# indexes first (they are the point), the small ones after.
INDEXES = [
    # severity is in both vulns indexes so they COVER the hounds' severity filters/rollups: on a real
    # navi.db a vulns row averages ~5.5 KB (plugin output — owner's 148 GB benchmark, build 454), so any
    # column read from the table instead of the index costs a 5.5 KB row read. +~7 B/row.
    ("hx_v_plugin", "vulns", ("plugin_id", "asset_uuid", "state", "severity"), 66.0),
    ("hx_v_asset", "vulns", ("asset_uuid", "plugin_id", "state", "severity"), 66.0),
    ("hx_tags_asset", "tags", ("asset_uuid", "tag_key", "tag_value"), 70.0),
    ("hx_tags_kv", "tags", ("tag_key", "tag_value", "asset_uuid"), 70.0),
    ("hx_comp_asset", "compliance", ("asset_uuid",), 45.0),
    ("hx_certs_asset", "certs", ("asset_uuid",), 45.0),
    ("hx_sw_asset", "software", ("asset_uuid",), 45.0),
    # Argos / C2 resolve a host by IP or hostname (build 455): without these, that lookup scans assets
    ("hx_assets_ip", "assets", ("ip_address",), 40.0),
    ("hx_assets_host", "assets", ("hostname",), 50.0),
]
# indexes whose stat1 row must carry 'unordered' (navi's idx_plugin has the same
# GROUP BY plugin_id hazard — the review lists it too).
UNORDERED = ("hx_v_plugin", "hx_v_asset", "idx_plugin")

ROWS_PER_S = 600_000          # cached CPU-bound build rate per index (review: 6M/10.1 s, 16M/28.5 s)
READ_B_PER_S = 300 * 10 ** 6  # pessimistic sequential read of navi.db when not cached (0.3–1 GB/s)
OPS_PER_ROW = 11              # SQLite VM ops per row of a CREATE INDEX (measured: 16.5M ops / 1.5M rows) → ≈ progress %
ANALYZE_LIMIT = 1000
JOB_KIND = "hx_optimize"
SYNC_KINDS = ("assets", "tags", "vulns", "full", "everything", "optimize")   # may run ANALYZE / reload vulns

_RUN_LOCK = threading.Lock()


def _path(path=None):
    if path:
        return path
    from core import db                     # lazy: core.db is heavy and is not needed for tests with a path
    return db.db_path()


def _ro(path):
    """A read connection for status(): mode=ro, falling back to a plain open when the WAL
    -shm file can't be created read-only (navi idle, directory read-only)."""
    try:
        from core import db as _db
        c = sqlite3.connect(_db._ro_uri(path), uri=True, timeout=5)
        c.execute("SELECT 1 FROM sqlite_master LIMIT 1")
        return c
    except sqlite3.Error:
        return sqlite3.connect(path, timeout=5)


def _rw(path, timeout=30):
    """The Hounds' own WRITE connection for this step only (never the console's)."""
    c = sqlite3.connect(path, timeout=timeout, isolation_level=None, check_same_thread=False)
    for p in ("PRAGMA busy_timeout=%d" % int(timeout * 1000), "PRAGMA temp_store=FILE",
              "PRAGMA cache_size=-262144", "PRAGMA threads=2"):
        try:
            c.execute(p)
        except sqlite3.Error:
            pass
    return c


def _tables(c):
    return {r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table'")}


def _index_names(c):
    return {r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='index'")}


def _cols(c, t):
    return {r[1] for r in c.execute('PRAGMA table_info("%s")' % t.replace('"', '""'))}


def _rows(c, t):
    """Cheap row-count estimate: MAX(rowid) is one b-tree descent (COUNT(*) on 420M rows is a
    full scan). Falls back to sqlite_stat1's first number."""
    try:
        v = c.execute('SELECT MAX(rowid) FROM "%s"' % t).fetchone()[0]
        if v is not None:
            return int(v)
        return 0
    except sqlite3.Error:
        pass
    try:
        r = c.execute("SELECT stat FROM sqlite_stat1 WHERE tbl=? LIMIT 1", (t,)).fetchone()
        return int(r[0].split()[0]) if r else None
    except (sqlite3.Error, ValueError, IndexError):
        return None


def _stat1(c):
    try:
        return {r[0]: r[1] for r in c.execute("SELECT idx, stat FROM sqlite_stat1 WHERE idx IS NOT NULL")}
    except sqlite3.Error:
        return None                          # no sqlite_stat1 = ANALYZE never ran


def _est_seconds(rows, file_bytes, is_vulns):
    lo = (rows or 0) / ROWS_PER_S
    hi = lo + ((file_bytes or 0) / READ_B_PER_S if is_vulns else 0)
    return [round(lo, 1), round(hi, 1)]


def _tmp_dir():
    for k in ("SQLITE_TMPDIR", "TMPDIR"):
        d = os.environ.get(k)
        if d and os.path.isdir(d):
            return d
    for d in ("/var/tmp", "/usr/tmp", "/tmp"):
        if os.path.isdir(d):
            return d
    return tempfile.gettempdir()


def _free(d):
    try:
        return shutil.disk_usage(d).free
    except OSError:
        return None


def _same_dev(a, b):
    try:
        return os.stat(a).st_dev == os.stat(b).st_dev
    except OSError:
        return True


def _jobs():
    """(navi jobs running, the running hx job or None) from the console's job table."""
    try:
        from core import cli_jobs
        run = cli_jobs.running()
    except Exception:
        return [], None
    hx = next((j for j in run if j.get("kind") == JOB_KIND), None)
    return [j for j in run if j.get("kind") != JOB_KIND], hx


def _inspect(c, path):
    tabs, idx = _tables(c), _index_names(c)
    st = _stat1(c)
    try:
        fbytes = os.path.getsize(path)
    except OSError:
        fbytes = 0
    rows_cache, out = {}, []
    for name, tbl, cols, bpr in INDEXES:
        applies = tbl in tabs and set(cols) <= (_cols(c, tbl) if tbl in tabs else set())
        if applies and tbl not in rows_cache:
            rows_cache[tbl] = _rows(c, tbl)
        rows = rows_cache.get(tbl) if applies else None
        exists = name in idx
        outdated = False
        if exists and applies:                # built by an older Hounds with different columns → rebuild
            try:
                have = [r[2] for r in c.execute('PRAGMA index_info("%s")' % name)]
            except sqlite3.Error:
                have = list(cols)
            outdated = have != list(cols)
            exists = not outdated
        out.append({"name": name, "table": tbl, "columns": list(cols), "applies": applies,
                    "exists": exists, "outdated": outdated, "rows": rows,
                    "reason": "" if applies else ("no %s table" % tbl if tbl not in tabs
                                                 else "%s lacks a column" % tbl),
                    "est_bytes": (int((rows or 0) * bpr) if applies and not exists else 0),
                    "est_s": (_est_seconds(rows, fbytes, tbl == "vulns") if applies and not exists else [0, 0]),
                    "stats": bool(st and name in st),
                    "unordered": (("unordered" in (st or {}).get(name, "")) if name in UNORDERED else None)})
    return out, st, idx, fbytes


def _unordered_state(st, idx, rows_by_name=None):
    """{index: True/False} for the trap indexes that exist. An index on an empty table has no
    stat1 row (nothing to walk) — that counts as fine."""
    per = {}
    for n in UNORDERED:
        if n not in idx:
            continue
        s = (st or {}).get(n)
        if s is None and rows_by_name is not None and not rows_by_name.get(n):
            per[n] = True
            continue
        per[n] = bool(s and "unordered" in s.split())
    return per


def status(path=None):
    """Cheap, read-only: catalog + sqlite_stat1 + MAX(rowid) + disk. Safe on page open."""
    path = _path(path)
    if not path or not os.path.isfile(path):
        return {"ok": False, "error": "navi.db not found at %r" % path, "db_path": path}
    try:
        c = _ro(path)
        try:
            items, st, idx, fbytes = _inspect(c, path)
            vrows = _rows(c, "vulns") if "vulns" in _tables(c) else None
            try:
                summ = hx_summary.inspect(c)
                summ["applies"] = hx_summary.can_build(c)[0]
            except sqlite3.Error as e:
                summ = {"present": False, "fresh": False, "applies": False, "reason": str(e)}
        finally:
            c.close()
    except sqlite3.Error as e:
        return {"ok": False, "error": "could not read navi.db: %s" % e, "db_path": path}
    rows_by_name = {"hx_v_plugin": vrows, "hx_v_asset": vrows, "idx_plugin": vrows}
    per = _unordered_state(st, idx, rows_by_name)
    missing = [i for i in items if i["applies"] and not i["exists"]]
    est_b = sum(i["est_bytes"] for i in missing)
    est_s = [round(sum(i["est_s"][0] for i in missing), 1), round(sum(i["est_s"][1] for i in missing), 1)]
    d = os.path.dirname(os.path.abspath(path))
    tmp = _tmp_dir()
    navi_busy, hxjob = _jobs()
    have = [i for i in items if i["exists"]]
    stats_ok = bool(have) and all(i["stats"] or not i["rows"] for i in have)
    unordered_ok = all(per.values()) if per else True
    return {"ok": True, "db_path": path, "db_bytes": fbytes, "indexes": items,
            "missing": [i["name"] for i in missing],
            "skipped": [{"name": i["name"], "reason": i["reason"]} for i in items if not i["applies"]],
            "est_bytes": est_b, "est_s": est_s, "need_free_bytes": 2 * est_b,
            "free_bytes": _free(d), "tmp_dir": tmp,
            "tmp_free_bytes": (None if _same_dev(d, tmp) else _free(tmp)),
            "stats_present": st is not None and stats_ok,
            "unordered": {"applied": unordered_ok, "per_index": per},
            "navi_idx": sorted(n for n in idx if n.startswith("idx_")),
            "summary": summ,
            "optimized": (not missing and stats_ok and unordered_ok and bool(have)
                          and (summ.get("fresh") or not summ.get("applies"))),
            "navi_busy": [j.get("cmd") or j.get("label") for j in navi_busy],
            "job": hxjob,
            "rates": {"vulns_bytes_per_row": 58.5, "rows_per_s": ROWS_PER_S,
                      "uncached_read_bytes_per_s": READ_B_PER_S,
                      "source": "SQL review (scale plan §2): 6M rows 10.1 s / 350 MB, 16M rows 28.5 s / 940 MB per vulns index"}}


def _apply_unordered(c, emit=None):
    """Make sure every existing trap index has a stat1 row ending in 'unordered' and reload.
    An index with no stat1 row (built after the last ANALYZE) gets a bounded per-index
    ANALYZE first. Returns the number of rows changed."""
    idx = _index_names(c)
    trap = [n for n in UNORDERED if n in idx]
    if not trap:
        return 0
    st = _stat1(c) or {}
    lacking = [n for n in trap if n not in st]
    if lacking:
        c.execute("PRAGMA analysis_limit=%d" % ANALYZE_LIMIT)
        for n in lacking:
            c.execute('ANALYZE "%s"' % n)
    q = ",".join("?" * len(trap))
    cur = c.execute("UPDATE sqlite_stat1 SET stat = stat || ' unordered' WHERE idx IN (%s) "
                    "AND ' ' || stat || ' ' NOT LIKE '%% unordered %%'" % q, trap)
    n = cur.rowcount if cur.rowcount and cur.rowcount > 0 else 0
    if n or lacking:
        c.execute("ANALYZE sqlite_schema")   # reload the stats into this and every new connection
    if emit and n:
        emit("✓ 'unordered' re-applied to %s" % ", ".join(trap))
    return n


def has_trap_indexes(path=None):
    path = _path(path)
    try:
        c = _ro(path)
        try:
            return bool(_index_names(c) & set(UNORDERED[:2]))
        finally:
            c.close()
    except (sqlite3.Error, OSError):
        return False


def reapply_unordered(path=None, timeout=10):
    """Cheap repair after a sync / ANALYZE / `navi config optimize`: only when the Hounds'
    vulns indexes exist. A catalog read, at most two bounded per-index ANALYZEs, one UPDATE."""
    path = _path(path)
    if not path or not os.path.isfile(path) or not has_trap_indexes(path):
        return {"ok": True, "applied": 0, "skipped": "no hx vulns indexes"}
    try:
        c = _rw(path, timeout=timeout)
        try:
            n = _apply_unordered(c)
        finally:
            c.close()
        return {"ok": True, "applied": n}
    except sqlite3.Error as e:
        return {"ok": False, "applied": 0, "error": str(e)}


def _fmt_s(s):
    s = float(s or 0)
    if s < 60:
        return "%.1fs" % s
    s = int(s)
    return ("%dm %02ds" % divmod(s, 60)) if s < 3600 else "%dh %02dm" % (s // 3600, s % 3600 // 60)


def _fmt_b(b):
    b = float(b or 0)
    for u in ("B", "KB", "MB", "GB", "TB"):
        if b < 1024 or u == "TB":
            return ("%.0f %s" if u in ("B", "KB") else "%.1f %s") % (b, u)
        b /= 1024


class Cancelled(Exception):
    pass


def optimize(path=None, emit=None, live=None, cancel=None):
    """The work itself (synchronous). emit(line) commits a progress line, live(text) sets the
    overwriting status line, cancel is a threading.Event. Returns a summary dict."""
    path = _path(path)
    emit = emit or (lambda s: None)
    live = live or (lambda s: None)
    cancel = cancel or threading.Event()
    t_all = time.time()
    built, existed, skipped, cancelled, busy = [], [], [], False, False
    c = _rw(path)
    try:
        items, _, _, _ = _inspect(c, path)
        page = c.execute("PRAGMA page_size").fetchone()[0]

        for it in items:
            if not it["applies"]:
                skipped.append(it["name"])
                emit("· %s skipped — %s" % (it["name"], it["reason"]))
                continue
            if it["exists"]:
                existed.append(it["name"])
                emit("✓ %s exists" % it["name"])
                continue
            if cancel.is_set():
                cancelled = True
                break
            rows = it["rows"] or 0
            emit("▶ CREATE INDEX %s ON %s(%s) — ~%s rows, est %s–%s, ~%s"
                 % (it["name"], it["table"], ", ".join(it["columns"]), format(rows, ","),
                    _fmt_s(it["est_s"][0]), _fmt_s(it["est_s"][1]), _fmt_b(it["est_bytes"])))
            t0 = time.time()
            ops = [0]
            total_ops = max(1, rows * OPS_PER_ROW)

            def _tick(name=it["name"], t0=t0):
                ops[0] += 1
                if ops[0] % 10 == 0:          # every ~1M VM ops
                    pct = min(99, int(ops[0] * 100000 * 100 / total_ops))
                    live("  %s … ≈%d%% · %s elapsed" % (name, pct, _fmt_s(time.time() - t0)))
                return 1 if cancel.is_set() else 0

            used0 = c.execute("PRAGMA page_count").fetchone()[0] - c.execute("PRAGMA freelist_count").fetchone()[0]
            c.set_progress_handler(_tick, 100000)
            try:
                c.execute("BEGIN IMMEDIATE")
                if it.get("outdated"):         # same transaction: a cancel rolls the DROP back too
                    emit("  (replacing an older %s with the current column set)" % it["name"])
                    c.execute('DROP INDEX IF EXISTS "%s"' % it["name"])
                c.execute('CREATE INDEX IF NOT EXISTS "%s" ON "%s"(%s)'
                          % (it["name"], it["table"], ", ".join('"%s"' % x for x in it["columns"])))
                c.execute("COMMIT")
            except sqlite3.OperationalError as e:
                try:
                    c.execute("ROLLBACK")
                except sqlite3.Error:
                    pass
                if cancel.is_set() or "interrupt" in str(e).lower():
                    cancelled = True
                    live("")
                    emit("✗ %s cancelled after %s — rolled back; the indexes built before it are kept"
                         % (it["name"], _fmt_s(time.time() - t0)))
                    break
                if "locked" in str(e).lower() or "busy" in str(e).lower():
                    # a long reader (a hound run, navi, another tool) held navi.db past busy_timeout —
                    # a rollback-journal navi.db can't commit under a reader (WAL can). Stop cleanly.
                    cancelled, busy = True, True
                    live("")
                    emit("✗ %s not kept — navi.db was busy (another process held it for over %ds). The "
                         "indexes built before it are kept; run ⚡ Optimize again when nothing is reading "
                         "or syncing navi.db." % (it["name"], int(c.execute("PRAGMA busy_timeout").fetchone()[0] / 1000)))
                    break
                raise
            finally:
                c.set_progress_handler(None, 0)
            used1 = c.execute("PRAGMA page_count").fetchone()[0] - c.execute("PRAGMA freelist_count").fetchone()[0]
            el = time.time() - t0
            live("")
            emit("✓ %s built in %s · %s" % (it["name"], _fmt_s(el),
                                           _fmt_b((used1 - used0) * page)))
            built.append({"name": it["name"], "seconds": round(el, 2), "bytes": (used1 - used0) * page})

        t_an = None
        if not cancelled:
            emit("▶ PRAGMA analysis_limit=%d; ANALYZE" % ANALYZE_LIMIT)
            t0 = time.time()
            c.execute("PRAGMA analysis_limit=%d" % ANALYZE_LIMIT)
            c.execute("ANALYZE")
            t_an = round(time.time() - t0, 2)
            emit("✓ ANALYZE in %.1fs" % t_an)
        # always — even after a cancel a freshly built vulns index must not be left as a trap
        n = _apply_unordered(c)
        emit("✓ 'unordered' set on %s" % (", ".join(n_ for n_ in UNORDERED if n_ in _index_names(c)) or "(no vulns index)")
             if n else "✓ 'unordered' already in place")
        # 4. the Phase 1 summary tables (hx_plugin / hx_asset) — after the indexes they read
        summ = None
        sig = None
        if not cancelled and hx_summary.can_build(c)[0]:
            # 4a. Phase 1b: each output-searching hound's predicate, evaluated ONCE (parallel,
            # read-only — no write lock held while it reads the plugin output)
            try:
                from core import hx_signals
                sig = hx_signals.scan(path, emit, live, cancel)
                if sig.get("cancelled"):
                    cancelled = True
                elif sig.get("skipped"):
                    emit("· signal hits skipped — %s" % sig["skipped"])
            except Exception as e:                    # never lose the summaries over it
                emit("· signal hits not built — %s: %s" % (type(e).__name__, e))
                sig = None
        if not cancelled:
            summ = hx_summary.build(c, emit, live, cancel, signals=sig)
            if summ.get("cancelled"):
                cancelled = True
            elif summ.get("busy"):
                cancelled, busy = True, True
            elif summ.get("seconds") is not None:
                c.execute("ANALYZE hx_plugin")
                c.execute("ANALYZE hx_asset")
    finally:
        c.close()
    total = round(time.time() - t_all, 2)
    emit(("⏸ Stopped — navi.db busy" if busy else ("⏹ Cancelled" if cancelled else "✓ navi.db optimized for the Hounds")) + " in " + _fmt_s(total)
         + (" (%d built, %d already there)" % (len(built), len(existed))))
    return {"ok": not cancelled, "cancelled": cancelled and not busy, "busy": busy, "built": built, "existed": existed,
            "skipped": skipped, "analyze_s": t_an, "seconds": total, "summary": summ}


def _writer_free(path):
    """Is navi.db's write lock free right now? (navi running outside the console holds it.)"""
    try:
        c = sqlite3.connect(path, timeout=1, isolation_level=None)
        try:
            c.execute("BEGIN IMMEDIATE")
            c.execute("ROLLBACK")
            return True
        finally:
            c.close()
    except sqlite3.Error:
        return False


def preflight(path=None, st=None):
    """(ok, error) — every refusal reason, cheapest first."""
    st = st or status(path)
    if not st.get("ok"):
        return False, st.get("error") or "navi.db not readable"
    if st.get("navi_busy"):
        return False, ("a navi job is running (%s) — Optimize holds navi.db's write lock for the "
                       "whole build, so wait for it to finish" % st["navi_busy"][0])
    need = st.get("need_free_bytes") or 0
    free = st.get("free_bytes")
    if need and free is not None and free < need:
        return False, ("not enough free disk next to navi.db: %s free, needs %s (2 × the estimated %s "
                       "of new indexes — the sort spills about as much again)"
                       % (_fmt_b(free), _fmt_b(need), _fmt_b(st.get("est_bytes"))))
    tf = st.get("tmp_free_bytes")
    if need and tf is not None and tf < need // 2:
        return False, ("not enough free disk in the temp dir %s for the index sort: %s free, needs %s "
                       "(set SQLITE_TMPDIR to a bigger disk)" % (st.get("tmp_dir"), _fmt_b(tf), _fmt_b(need // 2)))
    if not _writer_free(st["db_path"]):
        return False, ("navi.db is locked by another writer (a navi sync or tag run outside the console?) "
                       "— try again when it finishes")
    return True, ""


def run(path=None):
    """Start the optimize as a console job (Settings ▸ navi CLI window / Recent runs can
    attach and poll it). Refuses while a navi job runs, on low disk, or when another
    writer holds navi.db. A second click while it runs returns the running job."""
    from core import cli_jobs
    path = _path(path)
    with _RUN_LOCK:
        st = status(path)
        if st.get("job"):
            return {"ok": True, "already_running": True, "job": st["job"], "status": st}
        ok, err = preflight(path, st)
        if not ok:
            return {"ok": False, "error": err, "status": st}
        label = "⚡ Optimize navi.db for the Hounds" + ("" if st["missing"] else " (ANALYZE + summary tables)")
        r = cli_jobs.start_task(label, JOB_KIND,
                                lambda emit, live, cancel: optimize(path, emit, live, cancel),
                                cmd="hounds optimize " + path)
    r["status"] = st
    return r
