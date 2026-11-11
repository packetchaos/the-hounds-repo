"""Hounds summary tables inside navi.db — scale plan Phase 1.

Two small derived tables that answer the questions the hounds keep asking of a 5.5 KB-per-row
vulns table, built once per sync by ⚡ Optimize (core/hx_optimize.py) on its own write connection:

  hx_plugin  one row per plugin: name, family, severity, KEV / EOL flags, VPR, and how many
             findings / assets carry it (all states and open).            ≈ 100 B × plugins
  hx_asset   one row per asset that has findings: open counts by severity (per finding, exact),
             KEV / EOL flags (open and any state), max open VPR, total findings.  ≈ 70 B × assets
  hx_meta    build stamp + the navi.db fingerprint the tables were built from.

They live in navi.db (not a sidecar) so `navi enrich tag --query` and the user/LLM SQL path
(core/db.user_sql_authorizer allows only main/temp) can read them too.

Freshness: navi writes vulns with INSERT OR REPLACE (a new rowid for every re-synced finding) and
`-rebuild` drops/recreates the table (a new root page), so (rootpage, MAX(rowid)) of vulns and
assets changes on every sync. That fingerprint costs two b-tree descents. A hound must call
usable() and fall back to its plain-SQL path when it is False — summaries are an accelerator,
never the source of truth.

Build cost (measured, cached): 19 s @6M findings / 150k assets, 48–60 s @16M / 600k — passes over
the covering hx_v_* indexes (no vulns rows read except one per plugin for its attributes, and no
sort of the findings: temp space is bounded by the number of assets/plugins). ≈ 10–30 min at 120M
findings, mostly the sequential index reads.

Semantics worth knowing:
  • hx_plugin name/family/severity/xrefs-derived flags come from ONE representative finding per
    plugin (a per-finding recast severity is not reflected there; hx_asset's severity counts ARE
    per finding — they come from the index).
  • hx_asset only has assets with at least one finding; a missing asset means zeros.
  • "open" = state open/reopened (any case), the hounds' own definition.
"""
import os
import sqlite3
import threading
import time

VERSION = 1
TABLES = ("hx_plugin", "hx_asset", "hx_meta")

KEV_LIKE = "CISA-KNOWN-EXPLOITED"
# The broad EOL name match the hounds share (eol.py / software.py / fused_score / ai_assets use
# subsets of these). Hounds with a narrower rule filter hx_plugin.lname themselves.
EOL_TERMS = ("unsupported", "end of life", "end-of-life", "end of support", "no longer supported", "seol")


def _sevn(col):
    return ("CASE lower(COALESCE(%s,'')) WHEN 'critical' THEN 4 WHEN '4' THEN 4 WHEN 'high' THEN 3 "
            "WHEN '3' THEN 3 WHEN 'medium' THEN 2 WHEN '2' THEN 2 WHEN 'low' THEN 1 WHEN '1' THEN 1 "
            "ELSE 0 END" % col)


def _open(col):
    return "(lower(COALESCE(%s,'open')) IN ('open','reopened'))" % col


def eol_sql(col="lname"):
    """SQL boolean over a lower-cased plugin name column."""
    return "(" + " OR ".join("%s LIKE '%%%s%%'" % (col, t) for t in EOL_TERMS) + ")"


DDL = {
    "hx_plugin": """CREATE TABLE hx_plugin(
        plugin_id TEXT PRIMARY KEY, name TEXT, lname TEXT, family TEXT, sevn INT,
        kev INT, eol INT, cves TEXT, vpr REAL,
        findings INT, open_findings INT, assets INT, open_assets INT) WITHOUT ROWID""",
    "hx_asset": """CREATE TABLE hx_asset(
        asset_uuid TEXT PRIMARY KEY, findings INT, n_open INT,
        crit INT, high INT, med INT, low INT,
        kev INT, kev_any INT, eol INT, eol_any INT, vpr REAL) WITHOUT ROWID""",
    "hx_meta": "CREATE TABLE hx_meta(k TEXT PRIMARY KEY, v TEXT) WITHOUT ROWID",
}
NEED_VULNS = {"plugin_id", "asset_uuid", "state", "severity", "plugin_name", "plugin_family", "xrefs"}


# ── fingerprint / freshness ──────────────────────────────────────────────────────────────────
def fingerprint(c):
    """'v:<rootpage>:<max rowid>|a:<rootpage>:<max rowid>' — changes on every navi sync."""
    parts = []
    for t, k in (("vulns", "v"), ("assets", "a")):
        r = c.execute("SELECT rootpage FROM sqlite_master WHERE type='table' AND name=?", (t,)).fetchone()
        if not r:
            parts.append("%s:-" % k)
            continue
        m = c.execute('SELECT MAX(rowid) FROM "%s"' % t).fetchone()[0]
        parts.append("%s:%s:%s" % (k, r[0], m if m is not None else 0))
    return "|".join(parts)


def _meta(c):
    try:
        return {r[0]: r[1] for r in c.execute("SELECT k, v FROM hx_meta")}
    except sqlite3.Error:
        return {}


def inspect(c):
    """State of the summaries on an open connection (any mode)."""
    have = {r[0] for r in c.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name IN ('hx_plugin','hx_asset','hx_meta')")}
    m = _meta(c) if "hx_meta" in have else {}
    present = {"hx_plugin", "hx_asset", "hx_meta"} <= have and m.get("version") == str(VERSION)
    try:
        fp = fingerprint(c)
    except sqlite3.Error:
        fp = None
    fresh = bool(present and fp and m.get("fingerprint") == fp)
    reason = ("" if fresh else
              "not built yet — run ⚡ Optimize in Settings" if not present else
              "navi.db changed since they were built (a sync ran) — run ⚡ Optimize to refresh")
    out = {"present": present, "fresh": fresh, "reason": reason,
           "built_at": m.get("built_at"), "build_s": m.get("build_s"),
           "plugins": m.get("plugins"), "assets": m.get("assets")}
    return out


_CACHE = {}
_CACHE_LOCK = threading.Lock()
TTL_S = 20.0


def _file_sig(p):
    sig = []
    for suf in ("", "-wal"):
        try:
            st = os.stat(p + suf)
            sig.append((st.st_size, st.st_mtime_ns))
        except OSError:
            sig.append(None)
    return tuple(sig)


def state(path=None, force=False):
    """inspect() through core.db's read connection, cached per file signature for TTL_S."""
    from core import db
    p = path or db.db_path()
    if not p or not os.path.isfile(p):
        return {"present": False, "fresh": False, "reason": "navi.db not found"}
    sig = _file_sig(p)
    now = time.time()
    with _CACHE_LOCK:
        hit = _CACHE.get(p)
        if hit and not force and hit[0] == sig and now - hit[1] < TTL_S:
            return dict(hit[2])
    try:
        with db.connect(p) as con:
            st = inspect(con)
    except Exception as e:                       # never let a status probe break a hound
        st = {"present": False, "fresh": False, "reason": "could not read navi.db: %s" % e}
    with _CACHE_LOCK:
        _CACHE[p] = (sig, now, st)
    return dict(st)


def usable(path=None):
    """True when hx_plugin/hx_asset exist, match this navi.db, and are this code's version."""
    if os.environ.get("HOUNDS_NO_SUMMARY") == "1":
        return False
    return bool(state(path).get("fresh"))


def invalidate(path=None):
    with _CACHE_LOCK:
        if path:
            _CACHE.pop(path, None)
        else:
            _CACHE.clear()


# ── SQL fragments for hounds (only valid when usable()) ──────────────────────────────────────
def plugins_where(cond):
    """`plugin_id IN (SELECT plugin_id FROM hx_plugin WHERE <cond>)` — resolve a plugin-level
    filter (KEV, EOL, name/family LIKE, severity) against ~100k rows instead of the 5.5 KB rows."""
    return "plugin_id IN (SELECT plugin_id FROM hx_plugin WHERE %s)" % cond


def assets_with(cond, open_only=False, path=None):
    """SELECT DISTINCT asset_uuid for findings of plugins matching cond — one covering range per
    plugin over hx_v_plugin (no table rows), the set navi would tag."""
    from core import db
    ib = db.indexed_by("hx_v_plugin", path)
    st = (" AND " + _open("state")) if open_only else ""
    return "SELECT DISTINCT asset_uuid FROM vulns%s WHERE %s%s" % (ib, plugins_where(cond), st)


# ── build (write connection owned by hx_optimize) ────────────────────────────────────────────
class Cancelled(Exception):
    pass


def can_build(c):
    try:
        cols = {r[1] for r in c.execute('PRAGMA table_info("vulns")')}
    except sqlite3.Error:
        return False, "no vulns table"
    if not cols:
        return False, "no vulns table"
    miss = NEED_VULNS - cols
    if miss:
        return False, "vulns lacks %s" % ", ".join(sorted(miss))
    return True, ""


def build(c, emit=None, live=None, cancel=None):
    """(Re)build all three tables in ONE write transaction on connection c (isolation_level=None).
    WAL readers keep seeing the previous tables until COMMIT; a cancel rolls back to them."""
    emit = emit or (lambda s: None)
    live = live or (lambda s: None)
    cancel = cancel or threading.Event()
    ok, why = can_build(c)
    if not ok:
        emit("· summary tables skipped — %s" % why)
        return {"ok": True, "skipped": why}
    idx = {r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='index'")}
    ib_p = ' INDEXED BY "hx_v_plugin"' if "hx_v_plugin" in idx else ""
    ib_a = ' INDEXED BY "hx_v_asset"' if "hx_v_asset" in idx else ""
    vcols = {r[1] for r in c.execute('PRAGMA table_info("vulns")')}
    pcols = {r[1] for r in c.execute('PRAGMA table_info("plugins")')}
    vpr = ("COALESCE(CAST(NULLIF(pl.vpr_score,'') AS REAL), CAST(NULLIF(v.score,'') AS REAL))"
           if "vpr_score" in pcols else
           ("CAST(NULLIF(v.score,'') AS REAL)" if "score" in vcols else "NULL"))
    pl_join = "LEFT JOIN plugins pl ON pl.plugin_id = a.plugin_id" if "vpr_score" in pcols else ""
    cves = "v.cves" if "cves" in vcols else "NULL"
    t0 = time.time()
    phase = ["hx_plugin"]
    ticks = [0]

    def _tick():
        ticks[0] += 1
        if ticks[0] % 20 == 0:
            live("  %s … %.0fs" % (phase[0], time.time() - t0))
        return 1 if cancel.is_set() else 0

    c.set_progress_handler(_tick, 100000)
    try:
        c.execute("BEGIN IMMEDIATE")
        for t in TABLES:
            c.execute('DROP TABLE IF EXISTS "%s"' % t)
            c.execute(DDL[t])
        emit("▶ hx_plugin — one ordered pass over %s" % ("hx_v_plugin" if ib_p else "vulns (no hx_v_plugin index)"))
        t1 = time.time()
        # one covering pass grouped by plugin (rowid is in every index → MIN(rowid) is free),
        # then ONE row read per plugin for its attributes.
        c.execute("""INSERT INTO hx_plugin
            SELECT a.plugin_id, v.plugin_name, lower(v.plugin_name), v.plugin_family, %s,
                   (COALESCE(v.xrefs,'') LIKE '%%%s%%'), 0, %s, %s, a.f, a.fo, a.n, a.no
            FROM (SELECT plugin_id, MIN(rowid) r, COUNT(*) f, SUM(%s) fo,
                         COUNT(DISTINCT asset_uuid) n, COUNT(DISTINCT CASE WHEN %s THEN asset_uuid END) no
                  FROM vulns%s WHERE plugin_id IS NOT NULL GROUP BY plugin_id) a
            CROSS JOIN vulns v ON v.rowid = a.r %s"""
                  % (_sevn("v.severity"), KEV_LIKE, cves, vpr, _open("state"), _open("state"), ib_p, pl_join))
        c.execute("UPDATE hx_plugin SET eol = 1 WHERE " + eol_sql("lname"))
        np_ = c.execute("SELECT COUNT(*) FROM hx_plugin").fetchone()[0]
        emit("✓ hx_plugin: %s plugins in %.1fs" % (format(np_, ","), time.time() - t1))

        phase[0] = "hx_asset"
        emit("▶ hx_asset — one ordered pass over %s" % ("hx_v_asset" if ib_a else "vulns (no hx_v_asset index)"))
        t1 = time.time()
        o = _open("v.state")
        sv = _sevn("v.severity")
        # distinct asset list first (a temp b-tree of ~assets keys, not of findings), then one
        # covering SEARCH per asset in key order: GROUP BY needs no sort of the findings — the
        # sorter would otherwise spill ~80 B × findings to temp (≈10 GB at 120M).
        c.execute("DROP TABLE IF EXISTS temp.hx_a")
        c.execute("CREATE TEMP TABLE hx_a(u TEXT PRIMARY KEY) WITHOUT ROWID")
        c.execute("INSERT INTO temp.hx_a SELECT DISTINCT asset_uuid FROM vulns%s WHERE asset_uuid IS NOT NULL" % ib_a)
        c.execute("""INSERT INTO hx_asset
            SELECT h.u, COUNT(*), SUM(%(o)s),
                   SUM(%(o)s AND %(sv)s = 4), SUM(%(o)s AND %(sv)s = 3), SUM(%(o)s AND %(sv)s = 2), SUM(%(o)s AND %(sv)s = 1),
                   MAX(%(o)s AND p.kev), MAX(p.kev), MAX(%(o)s AND p.eol), MAX(p.eol),
                   MAX(CASE WHEN %(o)s THEN p.vpr END)
            FROM temp.hx_a h CROSS JOIN vulns v%(ib)s ON v.asset_uuid = h.u
            CROSS JOIN hx_plugin p ON p.plugin_id = v.plugin_id
            GROUP BY h.u""" % {"o": o, "sv": sv, "ib": ib_a})
        c.execute("DROP TABLE temp.hx_a")
        na = c.execute("SELECT COUNT(*) FROM hx_asset").fetchone()[0]
        emit("✓ hx_asset: %s assets in %.1fs" % (format(na, ","), time.time() - t1))

        total = round(time.time() - t0, 2)
        meta = {"version": str(VERSION), "fingerprint": fingerprint(c),
                "built_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "build_s": str(total), "plugins": str(np_), "assets": str(na)}
        c.executemany("INSERT INTO hx_meta(k, v) VALUES (?, ?)", list(meta.items()))
        c.execute("COMMIT")
    except sqlite3.OperationalError as e:
        try:
            c.execute("ROLLBACK")
        except sqlite3.Error:
            pass
        live("")
        if cancel.is_set() or "interrupt" in str(e).lower():
            emit("✗ summary tables cancelled — rolled back; the previous ones (if any) are kept")
            return {"ok": False, "cancelled": True}
        if "locked" in str(e).lower() or "busy" in str(e).lower():
            emit("✗ summary tables not built — navi.db was busy; run ⚡ Optimize again when nothing is syncing")
            return {"ok": False, "busy": True}
        raise
    finally:
        c.set_progress_handler(None, 0)
    live("")
    invalidate()
    emit("✓ summary tables built in %.1fs" % total)
    return {"ok": True, "seconds": total, "plugins": np_, "assets": na}
