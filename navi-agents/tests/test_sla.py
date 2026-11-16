"""Regression tests for the SLA Adherence agent (Sköll): the SLA math on a tiny navi.db
with hand-computed answers, equivalence of the fast engine with the original SQL lenses,
the monthly trend buckets, and the snapshot cache (hit, restart, navi.db change, SLA
threshold change, stale day, background build via the API).
Tiny synthetic navi.db files in a temp dir; no navi, no network.
Run: python3 tests/test_sla.py  (or pytest)."""
import atexit
import os
import shutil
import sqlite3
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)
TMP = tempfile.mkdtemp(prefix="hounds-sla-")
atexit.register(shutil.rmtree, TMP, ignore_errors=True)
os.environ["NAVI_CACHE_DIR"] = os.path.join(TMP, "cache")
os.environ["NAVI_HISTORY_DIR"] = os.path.join(TMP, "hist")     # never touch data/history_sla.jsonl

from core import sla  # noqa: E402

fails = []


def check(cond, msg):
    print(("PASS " if cond else "FAIL ") + msg)
    if not cond:
        fails.append(msg)


NOW = sqlite3.connect(":memory:").execute("SELECT julianday('2026-06-15 00:00:00')").fetchone()[0]
sla._NOW_SQL = repr(NOW)          # pin "now" for the SQL reference lenses too


def iso(days_before=None, date=None):
    if date:
        return date + "T00:00:00.000Z"
    c = sqlite3.connect(":memory:")
    return c.execute("SELECT strftime('%Y-%m-%dT%H:%M:%S.000Z', ?)", (NOW - days_before,)).fetchone()[0]


def make(path, with_fixed=True):
    if os.path.exists(path):
        os.remove(path)
    c = sqlite3.connect(path)
    c.executescript("""
    CREATE TABLE sla (critical TEXT, high TEXT, medium TEXT, low TEXT);
    INSERT INTO sla VALUES ('10','20','30','40');
    CREATE TABLE vulns (asset_uuid TEXT, plugin_id TEXT, plugin_name TEXT, severity TEXT,
                        state TEXT, first_found TEXT, last_found TEXT);
    CREATE TABLE assets (uuid TEXT, hostname TEXT, ip_address TEXT, acr TEXT);
    CREATE TABLE tags (tag_id INTEGER PRIMARY KEY, asset_uuid TEXT, tag_key TEXT, tag_value TEXT);
    CREATE TABLE vuln_route (route_id INTEGER PRIMARY KEY, app_name TEXT, plugin_list TEXT);
    CREATE TABLE vuln_paths (path_id INTEGER PRIMARY KEY, plugin_id TEXT, path TEXT, asset_uuid TEXT);
    """)
    V = [("a1", "p1", "One", "critical", "open", iso(15)),          # breached, 5 d over
         ("a1", "p2", "Two", "critical", "open", iso(5)),           # 5 d left → due ≤7
         ("a1", "p3", "Three", "high", "open", iso(17)),            # approaching, 3 d left
         ("a2", "p4", "Four", "high", "reopened", iso(45)),         # breached, 25 d over
         ("a2", "p5", "Five", "medium", "open", "not a date"),      # open, no age
         ("a2", "p6", "Six", "Low", "OPEN", iso(100)),              # breached, 60 d over (odd casing)
         ("a3", "p7", "Seven", "critical", "open", iso(200)),       # on an Accepted route → excluded
         ("a3", "p8", "Eight", "info", "open", iso(300)),           # info → no SLA
         ("a3", "p9", "Nine", "high", "fixed", iso(date="2026-01-10"))]
    for au, pid, pn, sev, st, ff in V:
        lf = iso(date="2026-01-20") if pid == "p9" else iso(0)
        c.execute("INSERT INTO vulns VALUES (?,?,?,?,?,?,?)", (au, pid, pn, sev, st, ff, lf))
    c.executemany("INSERT INTO assets VALUES (?,?,?,?)",
                  [("a1", "web1", "10.0.0.1", "9"), ("a2", "db1", "10.0.0.2", "3"), ("a3", "lab1", "10.0.0.3", "8")])
    c.executemany("INSERT INTO tags(asset_uuid, tag_key, tag_value) VALUES (?,?,?)",
                  [("a1", "Owner", "Team A"), ("a2", "Owner", "Team B"), ("a3", "Owner", "Team A"),
                   ("a3", "Owner", "APP X: Accepted"), ("a1", "Env", "prod"), ("a2", "Env", "dev")])
    c.execute("INSERT INTO vuln_route(app_name, plugin_list) VALUES ('APP X', \"['p7', 'p99']\")")
    if with_fixed:
        c.execute("CREATE TABLE fixed (asset_uuid TEXT, plugin_id TEXT, severity TEXT, state TEXT, first_found TEXT,"
                  " last_found TEXT, last_fixed TEXT, delta TEXT, pass_fail TEXT)")
        F = [("a1", "p10", "critical", "fixed", "2026-03-01", "2026-03-08", "Pass"),   # 7 d
             ("a2", "p11", "high", "fixed", "2026-02-01", "2026-03-15", "Fail"),       # 42 d, late
             ("a1", "p1", "critical", "open", iso(15)[:10], None, "Fail"),
             ("a2", "p12", "medium", "fixed", "2026-04-01", "2026-04-11", "PASS"),     # 10 d
             ("a3", "p7", "critical", "fixed", "2026-01-01", "2026-05-01", "Fail")]     # excluded
        for au, pid, sev, st, ff, lfx, pf in F:
            c.execute("INSERT INTO fixed VALUES (?,?,?,?,?,?,?,?,?)",
                      (au, pid, sev, st, iso(date=ff[:10]), None, iso(date=lfx) if lfx else None, "x", pf))
    c.commit()
    c.close()
    return path


P = make(os.path.join(TMP, "navi.db"))
d = sla.dashboard(P, now_jd=NOW)
oa, vd, rem, m = d["open_aging"], d["verdict"], d["remediation"], d["metrics"]
bs = {r["sev"]: r for r in oa["by_severity"]}

# ---------------------------------------------------------------- open aging
check(oa["open"] == 6 and oa["breached"] == 3 and oa["within"] == 3 and oa["within_pct"] == 50.0,
      "open aging: 6 open (info + dispositioned excluded), 3 past SLA, 50% within")
check(oa["excluded"] == 1, "a finding on an Accepted route is excluded from the SLA clock")
check(oa["approaching"] == 1 and bs["high"]["approaching"] == 1, "approaching = over 80% of the window, not breached")
check(bs["medium"]["open_ct"] == 1 and bs["medium"]["avg_age_days"] is None,
      "an unparseable first_found still counts as open but has no age")
check(bs["low"]["breached"] == 1, "severity / state casing ('Low', 'OPEN') is normalised")
check([r["seg"] for r in oa["by_owner"]] == ["Team B", "Team A"] and oa["by_owner"][0]["breached"] == 2,
      "by owner: Team B (2 breaches) ranks above Team A (1)")
check(oa["by_owner"][1]["due_7"] == 2, "Team A has 2 findings due within 7 days")

# ---------------------------------------------------------------- verdict + remediation
check(vd["met"] == 2 and vd["missed"] == 2 and vd["adherence_pct"] == 50.0,
      "verdict: navi Pass/Fail across SLA-tracked rows ('PASS' counts, excluded route dropped)")
rbs = {r["sev"]: r for r in rem["by_severity"]}
check(rem["met"] == 2 and rem["total"] == 3 and rem["met_pct"] == 66.7, "remediation: 2 of 3 closed findings met")
check(rbs["critical"]["avg_fix_days"] == 7.0 and rbs["high"]["avg_fix_days"] == 42.0, "remediation avg fix days")

# ---------------------------------------------------------------- SLA-owner metrics
t = m["totals"]
check((t["due_7"], t["due_14"], t["due_30"]) == (2, 2, 2), "due within 7/14/30 days")
check(m["oldest_breach"]["plugin_id"] == "p6" and m["oldest_breach"]["days_over"] == 60.0,
      "oldest open breach is the Low finding, 60 d over")
check([b["n"] for b in m["overdue_buckets"]] == [2, 1, 0, 0], "overdue buckets: 5 and 25 d over → 1–30 d; 60 d → 31–90 d")
check(m["crown"]["available"] and m["crown"]["breached"] == 1 and m["crown"]["assets_breached"] == 1
      and m["crown"]["assets"] == 1, "crown jewels (ACR ≥ 7): one breach on web1")
check(m["fixed_source"] == "fixed" and t["fixed"] == 3 and t["mttr_median"] == 10.0 and t["mttr_mean"] == 19.7,
      "MTTR from fixed.last_fixed: median 10 d, mean 19.7 d")
check(t["fixed_in_sla"] == 2 and t["fixed_in_sla_pct"] == 66.7, "fixed within SLA (our math): 2 of 3")
check(m["worst_assets"][0]["hostname"] == "db1" and m["worst_assets"][0]["breached"] == 2, "worst asset = db1")
check({p["plugin_id"] for p in m["worst_plugins"]} == {"p1", "p4", "p6"}, "worst plugins = the breached ones")

# ---------------------------------------------------------------- trend buckets
tr = {r["month"]: r for r in d["trend"]["rows"]}
check(list(tr) == ["2026-02", "2026-03", "2026-04", "2026-05", "2026-06"], "trend window Feb → Jun 2026")
check([tr[k]["new"] for k in tr] == [1, 2, 1, 3, 1], "trend: new findings per month (first found)")
check([tr[k]["fixed"] for k in tr] == [0, 2, 1, 0, 0], "trend: fixed per month (last_fixed)")
check([tr[k]["backlog"] for k in tr] == [1, 1, 1, 4, 5], "trend: open backlog at month end")
check([tr[k]["breaches_opened"] for k in tr] == [1, 0, 1, 1, 1], "trend: breaches opened when the SLA clock ran out")
check([tr[k]["breached_backlog"] for k in tr] == [1, 0, 1, 2, 3], "trend: breached backlog ends at today's 3")
check(tr["2026-03"]["fixed_in_sla_pct"] == 50.0 and tr["2026-03"]["mttr_median"] == 24.5,
      "trend: March fixes — 1 of 2 in SLA, median 24.5 d")

# ---------------------------------------------------------------- scoping
ds = sla.dashboard(P, "Owner", "Team B", now_jd=NOW)
check(ds["scoped"] and ds["open_aging"]["open"] == 3 and ds["metrics"]["crown"]["breached"] == 0,
      "Filter Owner = Team B scopes every number")
check(sla.dashboard(P, "Owner", "Nobody", now_jd=NOW)["tag_value"] is None, "a stale filter value is dropped")

# ---------------------------------------------------------------- fix-date fallback
P2 = make(os.path.join(TMP, "nofixed.db"), with_fixed=False)
d2 = sla.dashboard(P2, now_jd=NOW)
check(d2["metrics"]["fixed_source"] == "vulns" and d2["metrics"]["totals"]["fixed"] == 1
      and d2["metrics"]["totals"]["mttr_median"] == 10.0,
      "without a fixed table, vulns.last_found on fixed rows is the fix-date proxy")
check(not d2["verdict"]["available"] and not d2["remediation"]["available"], "no fixed table → no navi verdict")


# ---------------------------------------------------------------- engine == original SQL
def legacy(dd):
    out = {k: dd[k] for k in ("readiness", "tag_key", "tag_value", "tag_values", "scoped")}
    for lens in ("verdict", "open_aging", "remediation"):
        x = dict(dd[lens])
        x.pop("owners_total", None)
        if "by_owner" in x:
            keep = {"seg", "open_ct", "breached", "breach_pct"} if lens == "open_aging" else \
                   {"seg", "met", "missed", "total", "met_pct"}
            x["by_owner"] = [{k: v for k, v in r.items() if k in keep} for r in x["by_owner"]]
        out[lens] = x
    return out


def canon(dd):
    for lens, key in (("open_aging", lambda r: (-r["breached"], -r["open_ct"], str(r["seg"]))),
                      ("remediation", lambda r: (-r["missed"], -r["total"], str(r["seg"])))):
        if dd[lens].get("by_owner") is not None:
            dd[lens]["by_owner"] = sorted(dd[lens]["by_owner"], key=key)
    return dd


import sla_fixture  # noqa: E402

dbs = [(P, None, None), (P, "Owner", "Team A"), (P, "Env", None), (P2, None, None)]
for i, flags in enumerate([{}, {"routes": False}, {"acr": False, "owner": False}, {"fixed": False}]):
    fp = sla_fixture.build(os.path.join(TMP, "fx%d.db" % i), 120, 2500, seed=30 + i, **flags)
    dbs += [(fp, None, None), (fp, "Env", "prod")]
for fp, k, v in dbs:
    a = canon(legacy(sla.dashboard(fp, k, v, now_jd=NOW)))
    b = canon(sla.dashboard_sql(fp, k, v))
    check(a == b, "engine == original SQL lenses: %s %s=%s" % (os.path.basename(fp), k, v))

# ---------------------------------------------------------------- snapshot cache
from core import jobq  # noqa: E402
from agents.sla import agent as A, api  # noqa: E402

s1 = A.build_snapshot(P)
st = A.snapshot_state(P)
check(st["snap"] is not None and not st["stale"], "snapshot is cached for an unchanged navi.db")
check(A.snapshot_state(P, "Owner")["snap"] is not None, "the default view is also filed under its resolved key")
A._SNAP_MEM.clear()
A._CFG_MEM.clear()
check(A.snapshot_state(P)["snap"] is not None, "snapshot survives a restart (read back from disk)")
check(A.snapshot_state(P, "Owner", "Team B")["snap"] is None, "another view is a separate cache entry")

real_today = A._today
A._today = lambda: "2099-01-01"
check(A.snapshot_state(P)["stale"], "a snapshot built on an earlier day is flagged stale (ages moved)")
A._today = real_today

# threshold change WITHOUT a navi.db signature change (mtime + size restored): the SLA
# policy is part of the key, so a restart must not reuse the old result
st0 = os.stat(P)
c = sqlite3.connect(P); c.execute("UPDATE sla SET critical='11'"); c.commit(); c.close()
os.utime(P, ns=(st0.st_atime_ns, st0.st_mtime_ns))
check(os.stat(P).st_size == st0.st_size and A.db_signature(P) == s1["meta"]["sig"], "(signature unchanged by the edit)")
A._SNAP_MEM.clear()
A._CFG_MEM.clear()
check(A.snapshot_state(P)["snap"] is None, "changing the SLA thresholds invalidates the snapshot")
s2 = A.build_snapshot(P)
check('"critical": 11' in s2["meta"]["cfg"], "the rebuilt snapshot is keyed by the new thresholds")

time.sleep(0.01)
c = sqlite3.connect(P)
c.execute("INSERT INTO vulns VALUES ('a1','p13','Thirteen','critical','open',?,?)", (iso(30), iso(0)))
c.commit(); c.close()
os.utime(P, None)
check(A.snapshot_state(P)["snap"] is None, "changing navi.db invalidates the snapshot")
s3 = A.build_snapshot(P)
check(s3["result"]["open_aging"]["open"] == 7, "the rebuilt snapshot sees the new finding")
left = [n for n in os.listdir(A.CACHE_DIR) if n.startswith("sla_")]
check(len(left) == 2, "superseded cache files for this navi.db are pruned (%d left)" % len(left))
from core import history  # noqa: E402
check(history.latest("sla") and history.latest("sla")["metrics"].get("open_total") == 7,
      "an unscoped build records the day's trend point (temp history dir)")

# ---------------------------------------------------------------- the API: peek never computes
os.environ["NAVI_DB_PATH"] = P2
n0 = len(jobq.list_jobs())
o, _ = api.snapshot({"peek": True})
check(o["result"] is None and not o["building"] and len(jobq.list_jobs()) == n0, "peek on an empty cache computes nothing")
o, _ = api.snapshot({})
check(o["result"] is None and o["building"] and o["building"].get("job_id"), "▶ Run starts a background build")
o2, _ = api.snapshot({})
check((o2.get("building") or {}).get("job_id") == o["building"]["job_id"] or o2.get("result"),
      "a second Run joins the same build (or gets its result if it already finished)")
for _ in range(100):
    j = jobq.get(o["building"]["job_id"])
    if j and j["status"] in ("done", "error"):
        break
    time.sleep(0.05)
o, _ = api.snapshot({"peek": True})
check(o["result"] and o["cached"] and o["result"]["result"]["metrics"]["fixed_source"] == "vulns",
      "after the build, peek returns the cached result")
o, _ = api.snapshot({})
check(o["result"] and o["cached"], "▶ Run on an unchanged navi.db is served from the cache")
check(isinstance(o.get("history"), list), "responses carry the stored daily history")


# ---------------------------------------------------------------- review fixes
# 1) a filter value outside the top-200 (by assets) still scopes the dashboard
PR = os.path.join(TMP, "review.db")
c = sqlite3.connect(PR)
c.executescript("""
CREATE TABLE sla (critical TEXT, high TEXT, medium TEXT, low TEXT); INSERT INTO sla VALUES ('10','20','30','40');
CREATE TABLE vulns (asset_uuid TEXT, plugin_id TEXT, plugin_name TEXT, severity TEXT, state TEXT, first_found TEXT, last_found TEXT);
CREATE TABLE assets (uuid TEXT, hostname TEXT, ip_address TEXT, acr TEXT);
CREATE TABLE tags (tag_id INTEGER PRIMARY KEY, asset_uuid TEXT, tag_key TEXT, tag_value TEXT);""")
for i in range(250):                                       # 250 big teams, 2 assets each
    for j in range(2):
        u = f"t{i}_{j}"
        c.execute("INSERT INTO assets VALUES (?,?,?,?)", (u, u, "", None))
        c.execute("INSERT INTO tags(asset_uuid, tag_key, tag_value) VALUES (?,?,?)", (u, "Owner", f"Team {i:03d}"))
        c.execute("INSERT INTO vulns VALUES (?,?,?,?,?,?,?)", (u, "1", "x", "low", "open", iso(1), iso(0)))
c.execute("INSERT INTO assets VALUES ('z1','z1','',NULL)")
c.execute("INSERT INTO tags(asset_uuid, tag_key, tag_value) VALUES ('z1','Owner','Zed Team')")
for k in range(20):
    c.execute("INSERT INTO vulns VALUES ('z1',?,?,?,?,?,?)", (str(100 + k), "y", "critical", "open", iso(90), iso(0)))
# 4) NULL asset_uuid rows never match (parity with the SQL joins)
c.execute("INSERT INTO tags(asset_uuid, tag_key, tag_value) VALUES (NULL,'Owner','Ghost')")
c.execute("INSERT INTO vulns VALUES (NULL,'7','n','critical','open',?,?)", (iso(90), iso(0)))
c.commit(); c.close()
d = sla.dashboard(PR, "Owner", "Zed Team")
check(d["scoped"] and d["tag_value"] == "Zed Team" and d["open_aging"]["open"] == 20,
      "an owner outside the top-200 by assets still scopes the dashboard (not the whole estate)")
check(any(v["value"] == "Zed Team" for v in d["tag_values"]), "…and is added to the filter options")
check(not sla.dashboard(PR, "Owner", "Nobody")["scoped"], "a value that doesn't exist still falls back to unscoped")
check(not sla.dashboard(PR, "Owner", "Ghost")["scoped"] or sla.dashboard(PR, "Owner", "Ghost")["open_aging"]["open"] == 0,
      "a tag on a NULL asset_uuid matches no finding")
# 3) no thresholds → the reconstructed trend is unavailable, not a backlog falling to zero
PN = os.path.join(TMP, "nosla.db")
sla_fixture.build(PN, n_assets=50, n_findings=3000, sla=False)
t = sla.dashboard(PN).get("trend") or {}
check(not t.get("available"), "without SLA thresholds the monthly trend is reported unavailable")
# 5) concurrent history writes don't lose days
import threading  # noqa: E402
hd = tempfile.mkdtemp(dir=TMP)
_old = history._DATA_DIR
history._DATA_DIR = hd
try:
    def w(off):
        for k in range(40):
            history.record("ztest", {"v": k}, date="2026-01-%02d" % (1 + (off * 40 + k) % 30))
    ts = [threading.Thread(target=w, args=(o,)) for o in range(2)]
    [t_.start() for t_ in ts]; [t_.join() for t_ in ts]
    check(len(history.series("ztest")) == 30, "concurrent history.record() calls keep every day")
finally:
    history._DATA_DIR = _old


def test_sla_regressions():
    assert not fails, "\n".join(fails)


if __name__ == "__main__":
    print(f"\n{len(fails)} failure(s)")
    sys.exit(1 if fails else 0)
