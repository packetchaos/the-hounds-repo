"""Regression tests — the Phase 1 summary tables (core/hx_summary.py, build 456).

hx_plugin (one row per plugin) and hx_asset (one row per asset), built inside navi.db by
⚡ Optimize from the covering hx_v_* indexes, plus hx_meta's fingerprint of the navi.db they came
from. Checks: every column against the direct SQL over vulns · plugin-level attributes ·
per-finding severity (a recast finding) · the build plan reads the indexes in order (no temp
b-tree, no table scan) · freshness: a sync's INSERT OR REPLACE and a -rebuild both make them stale,
HOUNDS_NO_SUMMARY forces the fallback · a cancelled rebuild keeps the previous tables · skipped
on a navi.db without the columns · Optimize builds them and status() reports them · the after-sync
hook refreshes only when they were built before · the Settings card.
Synthetic navi.db; no Tenable. Run: python3 tests/test_hx_summary.py"""
import atexit
import os
import random
import shutil
import sqlite3
import sys
import tempfile
import threading
import time
import faulthandler; faulthandler.dump_traceback_later(180, exit=True)

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
TMP = tempfile.mkdtemp(prefix="hounds-hxs-")
atexit.register(shutil.rmtree, TMP, ignore_errors=True)
DB = os.path.join(TMP, "navi.db")
os.environ.update({"NAVI_CACHE_DIR": os.path.join(TMP, "cache"), "HOUNDS_CONFIG": os.path.join(TMP, "cfg.json"),
                   "NAVI_TAGLOG_DB": os.path.join(TMP, "taglog.db"), "NAVI_HISTORY_DIR": os.path.join(TMP, "hist"),
                   "NAVI_DB_PATH": DB})
os.environ.pop("HOUNDS_NO_SUMMARY", None)

from core import hx_optimize, hx_summary  # noqa: E402

fails = []


def check(cond, msg):
    print(("PASS " if cond else "FAIL ") + msg)
    if not cond:
        fails.append(msg)


SEVS = ["Critical", "high", "medium", "low", "info"]


def make_db(path, n=20000, assets=800, plugins=120):
    """navi 8.8.2 shape (the columns that matter); plugin attributes consistent per plugin like
    Tenable data, one plugin with a recast severity on some findings."""
    if os.path.exists(path):
        os.remove(path)
    c = sqlite3.connect(path)
    c.execute("PRAGMA journal_mode=WAL")
    c.execute("CREATE TABLE assets (ip_address text, hostname text, uuid text PRIMARY KEY)")
    c.execute("""CREATE TABLE vulns (finding_id text PRIMARY KEY, asset_uuid text, plugin_id text, plugin_name text,
                 plugin_family text, severity text, state text, xrefs text, cves text, score text, output text)""")
    c.execute("CREATE TABLE plugins (plugin_id text PRIMARY KEY, vpr_score text)")
    r = random.Random(7)
    c.executemany("INSERT INTO assets VALUES (?,?,?)", [("10.1.%d.%d" % (i // 250, i % 250), "h%d" % i, "u%05d" % i)
                                                        for i in range(assets)])
    pl = {}
    for p in range(plugins):
        name = ("Unsupported Thing %d" % p if p % 17 == 0 else
                "Apache End of Life Detection %d" % p if p % 23 == 0 else "Plugin %d" % p)
        pl[str(10000 + p)] = (name, "Fam%d" % (p % 5), SEVS[p % 5],
                              ("CISA-KNOWN-EXPLOITED:2023/01/01" if p % 11 == 0 else ("CVE:x" if p % 2 else None)),
                              "%.1f" % (p % 10 + 0.5) if p % 3 else "")
    rows = []
    for i in range(n):
        pid = str(10000 + r.randrange(plugins))
        name, fam, sev, xr, sc = pl[pid]
        if pid == "10001" and i % 3 == 0:
            sev = "critical"                                  # recast on some findings
        rows.append(("f%06d" % i, "u%05d" % r.randrange(assets - 20), pid, name, fam, sev,
                     r.choice(["OPEN", "open", "REOPENED", "fixed", None]), xr, None, sc, "x" * 30))
    c.executemany("INSERT INTO vulns VALUES (?,?,?,?,?,?,?,?,?,?,?)", rows)
    c.executemany("INSERT INTO plugins VALUES (?,?)", [(p, "9.%d" % (int(p) % 10)) for p in list(pl)[::2]])
    c.commit()
    c.close()


def rw(path=DB):
    return sqlite3.connect(path, isolation_level=None, timeout=10)


def sevn(s):
    return {"critical": 4, "4": 4, "high": 3, "3": 3, "medium": 2, "2": 2, "low": 1, "1": 1}.get((s or "").lower(), 0)


def t_columns():
    make_db(DB)
    c = rw()
    r = hx_summary.build(c)
    check(r.get("ok") and r.get("plugins") and r.get("assets"), "build: ok with plugin and asset counts (%s)" % r)
    rows = c.execute("SELECT asset_uuid, plugin_id, plugin_name, severity, state, xrefs FROM vulns").fetchall()
    isopen = lambda s: (s or "open").lower() in ("open", "reopened")  # noqa: E731
    eolf = lambda n: any(t in n.lower() for t in hx_summary.EOL_TERMS)  # noqa: E731
    exp = {}
    for a, p, n, sv, st, xr in rows:
        e = exp.setdefault(a, {"findings": 0, "n_open": 0, "crit": 0, "high": 0, "med": 0, "low": 0,
                               "kev": 0, "kev_any": 0, "eol": 0, "eol_any": 0})
        kv = "CISA-KNOWN-EXPLOITED" in (xr or "")
        e["findings"] += 1
        e["kev_any"] |= kv
        e["eol_any"] |= eolf(n)
        if isopen(st):
            e["n_open"] += 1
            k = {4: "crit", 3: "high", 2: "med", 1: "low"}.get(sevn(sv))
            if k:
                e[k] += 1
            e["kev"] |= kv
            e["eol"] |= eolf(n)
    got = {row[0]: dict(zip(["findings", "n_open", "crit", "high", "med", "low", "kev", "kev_any", "eol", "eol_any"],
                            [int(x or 0) for x in row[1:]]))
           for row in c.execute("SELECT asset_uuid, findings, n_open, crit, high, med, low, kev, kev_any, eol, eol_any FROM hx_asset")}
    check(set(got) == set(exp), "hx_asset: one row per asset with findings (%d)" % len(got))
    bad = [a for a in exp if exp[a] != got.get(a)]
    check(not bad, "hx_asset: every count / flag equals the direct computation (bad: %s)" % bad[:3])
    # per-finding severity: the recast plugin's critical findings are counted as critical
    direct = c.execute("SELECT COUNT(*) FROM vulns WHERE lower(severity)='critical' AND lower(COALESCE(state,'open')) IN ('open','reopened')").fetchone()[0]
    check(c.execute("SELECT SUM(crit) FROM hx_asset").fetchone()[0] == direct, "hx_asset: crit is per finding (recast findings count)")
    # hx_plugin counts
    pc = {}
    for a, p, n, sv, st, xr in rows:
        d = pc.setdefault(p, [0, 0, set(), set()])
        d[0] += 1
        d[2].add(a)
        if isopen(st):
            d[1] += 1
            d[3].add(a)
    gp = {r[0]: r[1:] for r in c.execute("SELECT plugin_id, findings, open_findings, assets, open_assets FROM hx_plugin")}
    bad = [p for p in pc if gp.get(p) != (pc[p][0], pc[p][1], len(pc[p][2]), len(pc[p][3]))]
    check(not bad, "hx_plugin: findings / open / assets / open assets per plugin (bad: %s)" % bad[:3])
    one = c.execute("SELECT name, lname, family, kev, eol, vpr FROM hx_plugin WHERE plugin_id='10000'").fetchone()
    check(one[0] == "Unsupported Thing 0" and one[1] == "unsupported thing 0" and one[3] == 1 and one[4] == 1,
          "hx_plugin: name / lname / kev / eol for a KEV + unsupported plugin")
    check(one[5] == 9.0, "hx_plugin: vpr from the plugins table when navi has it (%s)" % (one[5],))
    v2 = c.execute("SELECT vpr FROM hx_plugin WHERE plugin_id='10001'").fetchone()[0]
    check(v2 == 1.5, "hx_plugin: vpr falls back to vulns.score (%s)" % v2)
    check(c.execute("SELECT COUNT(*) FROM hx_plugin WHERE kev IS NULL OR eol IS NULL").fetchone()[0] == 0,
          "hx_plugin: kev / eol are never NULL (NULL xrefs)")
    c.close()


def t_plan_and_fresh():
    make_db(DB)
    st = hx_optimize.optimize(DB)
    check(st.get("ok") and (st.get("summary") or {}).get("ok"), "Optimize: builds indexes then the summary tables")
    c = rw()
    check("hx_plugin" in {r[0] for r in c.execute("SELECT tbl FROM sqlite_stat1")}, "Optimize: ANALYZE ran on the summary tables")
    c.execute("CREATE TEMP TABLE hx_a(u TEXT PRIMARY KEY) WITHOUT ROWID")
    q = ("SELECT h.u, COUNT(*) FROM temp.hx_a h CROSS JOIN vulns v INDEXED BY hx_v_asset ON v.asset_uuid=h.u "
         "CROSS JOIN hx_plugin p ON p.plugin_id=v.plugin_id GROUP BY h.u")
    plan = " | ".join(r[3] for r in c.execute("EXPLAIN QUERY PLAN " + q))
    check("COVERING INDEX hx_v_asset" in plan and "TEMP B-TREE" not in plan,
          "hx_asset build plan: covering, in index order, no sort (%s)" % plan)
    s = hx_optimize.status(DB)
    sm = s.get("summary") or {}
    check(sm.get("present") and sm.get("fresh") and s.get("optimized"), "status: summary fresh, navi.db optimized")
    hx_summary.invalidate()
    check(hx_summary.usable(DB), "usable(): True right after the build")
    os.environ["HOUNDS_NO_SUMMARY"] = "1"
    check(not hx_summary.usable(DB), "HOUNDS_NO_SUMMARY=1 forces the fallback")
    os.environ.pop("HOUNDS_NO_SUMMARY")
    # a sync: INSERT OR REPLACE of an existing finding gives it a new rowid
    c.execute("INSERT OR REPLACE INTO vulns (finding_id, asset_uuid, plugin_id, plugin_name, plugin_family, severity, state) "
              "SELECT finding_id, asset_uuid, plugin_id, plugin_name, plugin_family, 'critical', 'OPEN' FROM vulns LIMIT 1")
    hx_summary.invalidate()
    check(not hx_summary.usable(DB), "a re-synced finding (INSERT OR REPLACE) makes them stale")
    s = hx_optimize.status(DB)
    check(not s.get("optimized") and s["summary"]["present"] and not s["summary"]["fresh"],
          "status: stale summaries → not optimized")
    c.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    hx_summary.build(c)
    hx_summary.invalidate()
    check(hx_summary.usable(DB), "a rebuild makes them fresh again")
    # -rebuild: navi drops and recreates the table (new root page) — same max(rowid) can't fool it
    cols = [r[1] for r in c.execute("PRAGMA table_info(vulns)")]
    c.execute("CREATE TABLE v2 AS SELECT * FROM vulns")
    c.execute("DROP TABLE vulns")
    c.execute("CREATE TABLE vulns (%s)" % ", ".join(cols))
    c.execute("INSERT INTO vulns SELECT * FROM v2")
    c.execute("DROP TABLE v2")
    hx_summary.invalidate()
    st2 = hx_summary.inspect(c)
    check(not st2["fresh"], "a navi -rebuild (dropped + recreated vulns) makes them stale")
    c.close()


def t_cancel_and_skip():
    make_db(DB, n=60000)
    c = rw()
    hx_summary.build(c)
    before = c.execute("SELECT COUNT(*), SUM(findings) FROM hx_asset").fetchone()
    ev = threading.Event()
    ev.set()
    r = hx_summary.build(c, cancel=ev)
    check(r.get("cancelled"), "a cancelled rebuild reports cancelled")
    check(c.execute("SELECT COUNT(*), SUM(findings) FROM hx_asset").fetchone() == before,
          "a cancelled rebuild keeps the previous tables (one transaction)")
    c.close()
    p = os.path.join(TMP, "old.db")
    c = sqlite3.connect(p, isolation_level=None)
    c.execute("CREATE TABLE vulns (asset_uuid text, plugin_id text, severity text)")
    r = hx_summary.build(c)
    check(r.get("skipped") and "lacks" in r["skipped"], "a navi.db without plugin_name/state/xrefs is skipped (%s)" % r)
    st = hx_summary.inspect(c)
    check(not st["present"] and not st["fresh"], "skipped → not present, hounds use the fallback")
    c.close()


def t_after_sync():
    from core import cli_jobs
    make_db(DB)
    calls = []
    orig = hx_optimize.run
    hx_optimize.run = lambda path=None: calls.append(1) or {"ok": True}
    try:
        job = {"kind": "vulns", "status": "done", "lines": [], "_local": True}
        cli_jobs._refresh_summaries(job)
        time.sleep(1.5)
        check(not calls, "after a sync: no refresh when the summaries were never built (no opt-in to writes)")
        c = rw()
        hx_summary.build(c)
        c.execute("INSERT INTO vulns (finding_id, asset_uuid, plugin_id) VALUES ('new','u00001','10000')")
        c.close()
        cli_jobs._refresh_summaries(job)
        for _ in range(30):
            if calls:
                break
            time.sleep(0.2)
        check(calls, "after a sync: stale summaries that were built before → ⚡ Optimize starts")
        check(any("refreshing the summary tables" in ln for ln in job["lines"]), "after a sync: the job log says so")
        calls.clear()
        remote = {"kind": "vulns", "status": "done", "lines": [], "_local": False}
        cli_jobs._refresh_summaries(remote)
        time.sleep(1.5)
        check(not calls and any("run ⚡ Optimize" in ln for ln in remote["lines"]),
              "a sync started from a remote browser doesn't start Optimize (writes are loopback-only)")
        cli_jobs._refresh_summaries({"kind": "tags", "status": "done", "lines": [], "_local": True})
        time.sleep(1.5)
        check(not calls, "a tags sync doesn't rebuild the summaries")
    finally:
        hx_optimize.run = orig


def t_page():
    h = open(os.path.join(ROOT, "web", "settings.html"), encoding="utf-8").read()
    check("Summary tables" in h and "summaries stale" in h and "hx_plugin" in h,
          "Settings ⚡ card shows the summary tables' state")


if __name__ == "__main__":
    for t in (t_columns, t_plan_and_fresh, t_cancel_and_skip, t_after_sync, t_page):
        try:
            t()
        except Exception as e:                         # a crash is a failure, not a stop
            import traceback
            traceback.print_exc()
            check(False, "%s crashed: %s" % (t.__name__, e))
    print("\n%d failure(s)" % len(fails))
    sys.exit(1 if fails else 0)
