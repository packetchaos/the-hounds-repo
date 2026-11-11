"""Hounds signal hits + route membership inside navi.db — the "exploded" tables the slow-query
advisor asks for (scale plan Phase 1b).

The hounds that search plugin OUTPUT text for words — AI inventory (`output LIKE '%ollama%'` …,
≈110 patterns) and Identity (service-account / default-credential / krbtgt arms) — each read every
finding's ~5 KB output on every run: 20+ min for AI on a 148 GB navi.db. A leading-wildcard LIKE
can't use an index, and full-text search would store a second ~140 GB index. Instead ⚡ Optimize
evaluates each hound's OWN predicate (the exact SQL text its fallback runs) once per sync and keeps
only the matching findings' rowids:

  hx_hits(hound, vrow)               the vulns rowids whose row satisfies that hound's predicate
  hx_route_plugin(plugin_id, app_name, route_id)   vuln_route.plugin_list exploded (the
                                     `plugin_list LIKE '%''' || plugin_id || '''%'` joins)

A hound's fast path is `… FROM vulns WHERE rowid IN (SELECT vrow FROM hx_hits WHERE hound=?) AND
(<its predicate>)` — the same predicate, so the same rows, read by rowid instead of a full scan.
It is used only when hx_summary.usable() (navi.db unchanged since the build: rowids are stable
until navi re-syncs) AND the predicate's hash still matches what was built (code changes → the
fallback runs until the next ⚡ Optimize).

The scan runs BEFORE Optimize's write transaction (no write lock while it reads ~150 GB), in
parallel threads over rowid ranges: SQLite evaluates the LIKEs in C with the GIL released, so
the threads scale with cores (HOUNDS_SIGNAL_THREADS, default min(8, CPUs)).
"""
import hashlib
import os
import re
import sqlite3
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

CHUNK = int(os.environ.get("HOUNDS_SIGNAL_CHUNK", "250000"))      # rowids per task


def _threads():
    try:
        n = int(os.environ.get("HOUNDS_SIGNAL_THREADS", "0"))
    except ValueError:
        n = 0
    return max(1, n or min(8, os.cpu_count() or 2))


# ── the registry: hound → its output predicate (SQL over vulns, given vulns' columns) ─────────
def predicates(vcols):
    """{hound: sql_predicate} — each hound builds its own (single source of truth)."""
    out = {}
    try:
        from core import ai_assets
        p = ai_assets.signal_predicate(vcols)
        if p:
            out["ai"] = p
    except Exception:
        pass
    try:
        from core import identity
        p = identity.signal_predicate(vcols)
        if p:
            out["identity"] = p
    except Exception:
        pass
    return out


def phash(pred):
    return hashlib.sha1(pred.encode("utf-8")).hexdigest()[:16]


# ── scan (read-only, parallel; before the write transaction) ──────────────────────────────────
def _ro(path):
    from core import db
    c = sqlite3.connect(db._ro_uri(path), uri=True, timeout=30, check_same_thread=False)
    c.execute("PRAGMA query_only=ON")
    return c


def scan(path, emit=None, live=None, cancel=None):
    """Evaluate every registered predicate over vulns once. Returns
    {"hits": {hound: [rowid…]}, "hashes": {hound: hash}, "fingerprint": fp_before, "seconds": s}
    or {"skipped": why} / {"cancelled": True}."""
    from core import hx_summary
    emit = emit or (lambda s: None)
    live = live or (lambda s: None)
    cancel = cancel or threading.Event()
    c = _ro(path)
    try:
        vcols = {r[1] for r in c.execute('PRAGMA table_info("vulns")')}
        if not vcols or "output" not in vcols:
            return {"skipped": "vulns has no output column"}
        preds = predicates(vcols)
        if not preds:
            return {"skipped": "no hound registered an output predicate"}
        fp = hx_summary.fingerprint(c)
        lo_hi = c.execute("SELECT MIN(rowid), MAX(rowid) FROM vulns").fetchone()
    finally:
        c.close()
    lo, hi = (lo_hi or (None, None))
    hounds = sorted(preds)
    hashes = {h: phash(preds[h]) for h in hounds}
    if lo is None:
        return {"hits": {h: [] for h in hounds}, "hashes": hashes, "fingerprint": fp, "seconds": 0.0}
    any_pred = " OR ".join("(%s)" % preds[h] for h in hounds)
    cols = ", ".join("(%s) AS h%d" % (preds[h], i) for i, h in enumerate(hounds))
    sql = "SELECT rowid AS r, %s FROM vulns WHERE rowid BETWEEN ? AND ? AND (%s)" % (cols, any_pred)
    ranges = [(a, min(a + CHUNK - 1, hi)) for a in range(lo, hi + 1, CHUNK)]
    n_threads = min(_threads(), len(ranges))
    emit("▶ signal hits — %s over %s rowid ranges on %d thread%s (one read of plugin output for %s)"
         % (", ".join(hounds), format(len(ranges), ","), n_threads, "" if n_threads == 1 else "s",
            " + ".join(hounds)))
    t0 = time.time()
    local = threading.local()
    conns = []
    lock = threading.Lock()

    def conn():
        cc = getattr(local, "c", None)
        if cc is None:
            cc = _ro(path)
            cc.execute("PRAGMA cache_size=-65536")
            cc.set_progress_handler(lambda: 1 if cancel.is_set() else 0, 200000)
            local.c = cc
            with lock:
                conns.append(cc)
        return cc

    def task(a, b):
        if cancel.is_set():
            return None
        rows = conn().execute(sql, (a, b)).fetchall()
        out = {h: [] for h in hounds}
        for r in rows:
            for i, h in enumerate(hounds):
                if r[1 + i]:
                    out[h].append(r[0])
        return out

    hits = {h: [] for h in hounds}
    done = 0
    try:
        with ThreadPoolExecutor(max_workers=n_threads, thread_name_prefix="hx-signal") as ex:
            futs = [ex.submit(task, a, b) for a, b in ranges]
            for f in as_completed(futs):
                try:
                    part = f.result()
                except sqlite3.OperationalError as e:
                    if cancel.is_set() or "interrupt" in str(e).lower():
                        cancel.set()
                        continue
                    raise
                if part is None:
                    continue
                for h in hounds:
                    hits[h].extend(part[h])
                done += 1
                if done % max(1, len(ranges) // 50) == 0 or done == len(ranges):
                    el = time.time() - t0
                    live("  signal hits … %d/%d ranges · %.0fs%s" % (
                        done, len(ranges), el,
                        (" · ~%.0fs left" % (el / done * (len(ranges) - done))) if done < len(ranges) else ""))
    finally:
        for cc in conns:
            try:
                cc.close()
            except Exception:
                pass
    live("")
    if cancel.is_set():
        return {"cancelled": True}
    for h in hounds:
        hits[h].sort()
    sec = round(time.time() - t0, 1)
    emit("✓ signal hits: %s in %.1fs" % (", ".join("%s %s" % (h, format(len(hits[h]), ",")) for h in hounds), sec))
    return {"hits": hits, "hashes": hashes, "fingerprint": fp, "seconds": sec}


# ── write (inside hx_summary.build's transaction) ─────────────────────────────────────────────
DDL = {
    "hx_hits": "CREATE TABLE hx_hits(hound TEXT, vrow INTEGER, PRIMARY KEY(hound, vrow)) WITHOUT ROWID",
    "hx_route_plugin": ("CREATE TABLE hx_route_plugin(plugin_id TEXT, app_name TEXT, route_id INTEGER, "
                        "PRIMARY KEY(plugin_id, app_name, route_id)) WITHOUT ROWID"),
}
_QUOTED = re.compile(r"'([^']*)'")


def write(c, sig, emit=None):
    """Create hx_hits / hx_route_plugin on write connection c (inside the caller's transaction).
    sig = scan()'s result; its hits are written only when navi.db hasn't changed since the scan
    (the rowids would be stale). Returns the hx_meta rows to add."""
    from core import hx_summary
    emit = emit or (lambda s: None)
    meta = {}
    for t, ddl in DDL.items():
        c.execute('DROP TABLE IF EXISTS "%s"' % t)
        c.execute(ddl)
    if sig and sig.get("hits") is not None:
        if sig.get("fingerprint") == hx_summary.fingerprint(c):
            for h, rows in sig["hits"].items():
                c.executemany("INSERT OR IGNORE INTO hx_hits(hound, vrow) VALUES (?, ?)", ((h, r) for r in rows))
                meta["sig:" + h] = sig["hashes"][h]
                meta["hits:" + h] = str(len(rows))
        else:
            emit("· signal hits not kept — navi.db changed while they were read; run ⚡ Optimize again")
    have = {r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='vuln_route'")}
    rcols = {r[1] for r in c.execute('PRAGMA table_info("vuln_route")')} if have else set()
    if have and not {"app_name", "plugin_list"} <= rcols:
        emit("· hx_route_plugin skipped — vuln_route has no app_name / plugin_list")
        have = set()
    if have:
        n = 0
        rid = "route_id" if "route_id" in rcols else "rowid"      # older navi: no route_id column
        rows = c.execute("SELECT %s, app_name, plugin_list FROM vuln_route" % rid).fetchall()
        for rid, app, pl in rows:
            for pid in set(_QUOTED.findall(str(pl or ""))):
                c.execute("INSERT OR IGNORE INTO hx_route_plugin VALUES (?, ?, ?)", (pid, app, rid))
                n += 1
        meta["route_plugin"] = str(n)
        emit("✓ hx_route_plugin: %s route↔plugin pairs" % format(n, ","))
    return meta


# ── readers ───────────────────────────────────────────────────────────────────────────────────
def usable_for(hound, pred, path=None):
    """True when hx_hits holds THIS predicate's rows for the current navi.db."""
    from core import hx_summary
    if not pred or not hx_summary.usable(path):
        return False
    st = hx_summary.state(path)
    return (st.get("signals") or {}).get(hound) == phash(pred)


def rows_sql(hound):
    """`rowid IN (…)` fragment — the hound's hit rows (bind nothing; hound is a fixed name)."""
    if not re.fullmatch(r"[a-z_]{1,32}", hound or ""):
        raise ValueError("bad hound name")
    return "rowid IN (SELECT vrow FROM hx_hits WHERE hound='%s')" % hound


def routes_usable(path=None):
    from core import hx_summary
    return hx_summary.usable(path) and (hx_summary.state(path).get("route_plugin") is not None)
