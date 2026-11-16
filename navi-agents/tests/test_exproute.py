"""Regression tests for the Exposure Routes agent (Atlas): ownership math, owner-tag
matching, the plain-English disposition parser, re-tagging, and the snapshot cache.
Tiny synthetic navi.db files in a temp dir; no navi, no network.
Run: python3 tests/test_exproute.py  (or pytest)."""
import atexit
import json
import os
import shutil
import sqlite3
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
TMP = tempfile.mkdtemp(prefix="hounds-exproute-")
atexit.register(shutil.rmtree, TMP, ignore_errors=True)
os.environ["NAVI_CACHE_DIR"] = os.path.join(TMP, "cache")

from core import navi_cli  # noqa: E402

navi_cli.explore_info = lambda sub: {"ok": True, "stdout": ""}   # no live Tenable calls
TAGGED = []
navi_cli.tag = lambda *a, **k: (TAGGED.append(("tag", a, k)) or {"ok": True, "job_id": len(TAGGED)})
navi_cli.tag_capped = lambda *a, **k: (TAGGED.append(("capped", a, k)) or [{"ok": True, "job_id": len(TAGGED)}])
from agents.exproute import agent as A  # noqa: E402

fails = []


def check(cond, msg):
    print(("PASS " if cond else "FAIL ") + msg)
    if not cond:
        fails.append(msg)


def mk(name, routes, vulns, paths, tags):
    p = os.path.join(TMP, name)
    c = sqlite3.connect(p)
    c.executescript("""
    CREATE TABLE assets (uuid TEXT, hostname TEXT, ip_address TEXT, acr TEXT, aes INTEGER, url TEXT);
    CREATE TABLE vulns (asset_uuid TEXT, plugin_id TEXT, plugin_name TEXT, output TEXT, last_found TEXT, cves TEXT,
                        xrefs TEXT, severity TEXT, score REAL, url TEXT, plugin_family TEXT);
    CREATE TABLE vuln_route (route_id INTEGER PRIMARY KEY, app_name TEXT, plugin_list TEXT, total_vulns INTEGER, vuln_type TEXT);
    CREATE TABLE vuln_paths (path_id INTEGER PRIMARY KEY, plugin_id TEXT, path TEXT, asset_uuid TEXT, finding_id TEXT);
    CREATE TABLE tags (tag_id INTEGER PRIMARY KEY, asset_uuid TEXT, asset_ip TEXT, tag_key TEXT, tag_uuid TEXT,
                       tag_value TEXT, tag_added_date TEXT);""")
    for rid, app, pl in routes:
        c.execute("INSERT INTO vuln_route VALUES (?,?,?,?,?)", (rid, app, str([str(x) for x in pl]), 1, "Application"))
    for a, pid, sc in vulns:
        c.execute("INSERT INTO vulns(asset_uuid, plugin_id, score) VALUES (?,?,?)", (a, str(pid), sc))
    for a in sorted({v[0] for v in vulns}):
        c.execute("INSERT INTO assets(uuid, hostname) VALUES (?,?)", (a, a))
    for pid, path, a in paths:
        c.execute("INSERT INTO vuln_paths(plugin_id, path, asset_uuid) VALUES (?,?,?)", (str(pid), path, a))
    for a, v in tags:
        c.execute("INSERT INTO tags(asset_uuid, tag_key, tag_value) VALUES (?,?,?)", (a, "Owner", v))
    c.commit(); c.close()
    return p


# ---------------------------------------------------------------- ownership math
P = mk("case1.db",
       routes=[(1, "Alpha", [1]), (2, "Beta", [2]), (3, "Gamma", [3]), (4, "Under_score", [4]), (6, "Dup", [6]), (7, "Dup", [7])],
       vulns=[(f"a{i}", 1, 5.0) for i in range(1, 6)] + [("b1", 2, None), ("b2", 2, None), ("c1", 3, 9.5),
                                                         ("d1", 4, None), ("f1", 6, None), ("f2", 7, None)],
       paths=[(1, "/p1", "a1"), (3, "/o'q_x", "c1")],
       tags=[("a1", "Alpha: alice"), ("a2", "Alpha: alice")] + [(f"a{i}", "Alpha: Ignored") for i in (3, 4, 5)] +
            [("b1", "Beta: alice"), ("b2", "Beta: bob"), ("c1", "Delta: carol"), ("d1", "UnderXscore: dave"), ("f1", "Dup: erin")])
om = A.ownership_map(P)
R = {r["name"]: r for r in om["routes"]}
check(R["Alpha"]["status"] == "partial" and R["Alpha"]["owned_assets"] == 2,
      "a disposition (Ignored) tag doesn't make an asset owned — Alpha is partial 2/5")
check(R["Under_score"]["status"] == "unowned", "'_' in a route name is not a wildcard ('UnderXscore' doesn't own it)")
check(R["Dup"]["assets"] == 2 and R["Dup"]["status"] == "partial", "routes sharing a name are one route on the map")
load = {e["owner"]: e for e in om["owner_load"]}
check(load["alice"]["assets"] == 3 and load["bob"]["assets"] == 1, "owner workload counts only that owner's assets")
check(om["kpi"]["unowned_assets"] == 3,
      "Ownerless Risk counts assets with no owner/decision on their own routes (a tag for another name doesn't count)")
cv = A.coverage(P)
check(cv["closed"] == 5, "closed = every route on the asset has a real owner for it (Ignored isn't an owner)")
check(cv["routes_owned"] == 1 and cv["total_routes"] == 5, "coverage agrees with the map (1 owned of 5 distinct routes)")

# a path under a fully owned route is owned (inherited) — the map and coverage agree
P2 = mk("inherit.db", routes=[(1, "Web", [10])], vulns=[("w1", 10, 8.0), ("w2", 10, 8.0)],
        paths=[(10, "/srv/web/app.jar", "w1"), (99, "/tmp/orphan", "w2")],
        tags=[("w1", "Web: alice"), ("w2", "Web: alice")])
om2 = A.ownership_map(P2)
pth = {p["name"]: p for p in om2["paths"]}
check(pth["/srv/web/app.jar"]["status"] == "owned" and pth["/srv/web/app.jar"].get("inherited"),
      "a path under an owned route is owned by inheritance")
check(pth["/tmp/orphan"]["status"] == "unowned", "an orphan path stays unowned")
check(A.coverage(P2)["owned_paths"] == 1, "coverage owned_paths matches the map")
check({e["owner"]: e for e in om2["owner_load"]}["alice"]["paths"] == 0, "inherited paths don't add to anyone's workload")

# owner names containing ': '
P3 = mk("colon.db", routes=[(1, "Mail", [5])], vulns=[("m1", 5, None)], paths=[], tags=[("m1", "Mail: Ops: EMEA")])
om3 = A.ownership_map(P3)
check(om3["routes"][0]["owners"] == ["Ops: EMEA"] and not om3["unmatched_owners"],
      "an owner like 'Ops: EMEA' splits at the known route name")

# ---------------------------------------------------------------- disposition parser
rt = [{"app_name": "JENKINS", "total_vulns": 1}, {"app_name": "NGINX WEB SERVER", "total_vulns": 1},
      {"app_name": "CENTOS", "total_vulns": 1}]
pd = lambda t: [(d["match"], d["owner"]) for d in A.parse_dispositions(t, rt, [])]
check(pd("give the JENKINS route to Skip") == [], "'give X to Skip' is an assignment, not a disposition")
check(pd("assign the nginx route to the Fixed Income team") == [], "'Fixed Income' isn't 'fixed' → Mitigated")
check(pd("mark the nginx route as ignored and give centos to the linux team") == [("NGINX WEB SERVER", "Ignored")],
      "a real disposition still parses next to an assignment")

# ---------------------------------------------------------------- tagging paths
TAGGED.clear()
r = A.tag_owner("erin", app="Dup", db_path=P)
check(r.get("route_ids") == [6, 7] and len(TAGGED) == 2 and all(k["remove"] is False for _, _, k in TAGGED),
      "tagging a route by name tags every route_id with that name (never removes)")
TAGGED.clear()
r = A.retag_owner_tags("Delta", "Gamma", db_path=P)
# build 453: the re-tag's --query is the set's own definition (assets carrying the old Owner tag
# value) instead of an inlined UUID list — check navi's selection, not the argument
check(r["ok"] and r["assets"] == 1 and TAGGED and TAGGED[0][1][1] == "Gamma: carol"
      and [x[0] for x in sqlite3.connect(P).execute(TAGGED[0][2]["query"])] == ["c1"],
      "re-tag moves only the assets carrying the old tag, per owner")
check(not A.retag_owner_tags("Delta", "Nope", db_path=P)["ok"], "re-tag refuses a target that isn't a route/path")

# ---------------------------------------------------------------- snapshot cache
s1 = A.build_snapshot(P)
st = A.snapshot_state(P)
check(st["snap"] is not None and st["snap"]["meta"]["sig"] == s1["meta"]["sig"], "snapshot is cached for an unchanged navi.db")
A._SNAP_MEM.clear()
check(A.snapshot_state(P)["snap"] is not None, "snapshot survives a restart (read back from disk)")
time.sleep(0.01)
c = sqlite3.connect(P); c.execute("INSERT INTO tags(asset_uuid, tag_key, tag_value) VALUES ('f2','Owner','Dup: erin')"); c.commit(); c.close()
os.utime(P, None)
check(A.snapshot_state(P)["snap"] is None, "changing navi.db invalidates the snapshot")
s2 = A.build_snapshot(P)
check({r["name"]: r for r in s2["map"]["routes"]}["Dup"]["status"] == "owned", "the rebuilt snapshot sees the new tag")
check(set(s2) == {"load", "coverage", "map", "meta"} and json.dumps(s2, default=list), "snapshot carries owners, coverage and the map")


def test_exproute_regressions():
    assert not fails, "\n".join(fails)


if __name__ == "__main__":
    print(f"\n{len(fails)} failure(s)")
    sys.exit(1 if fails else 0)
