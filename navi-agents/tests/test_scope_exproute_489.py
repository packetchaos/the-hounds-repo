"""Regression tests — build 489: a tag filter on Exposure Routes (Atlas, `exproute`).

  · With no tag, every result (the one-pass base, the Ownership Map, coverage, routes, paths,
    the path drill-down, the snapshot) is what it was before.
  · A tag view covers the routes and paths the tag's assets sit on: route/path asset sets,
    Owner tags, coverage, the funnel and the Sankey numbers are cut to the tag in SQL. An
    asset's own membership and owned / closed state is the same as in the whole estate.
  · Writes from a tag view (apply, retag) recompute the set from navi.db on the server and stay
    inside the tag — a UUID list from the browser is ignored.
  · Tag views have their own snapshot store (exproute_tag, keep=5): a tag never serves or
    evicts the estate snapshot, nor the reverse.
Run: python3 tests/test_scope_exproute_489.py"""
import atexit
import json
import os
import re
import shutil
import sqlite3
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
TMP = tempfile.mkdtemp(prefix="hounds-489-exproute-")
atexit.register(shutil.rmtree, TMP, ignore_errors=True)
DB = os.path.join(TMP, "navi.db")
shutil.copy(os.path.join(ROOT, "sample_navi.db"), DB)
os.environ.update({"NAVI_DB_PATH": DB, "NAVI_CACHE_DIR": os.path.join(TMP, "cache"),
                   "HOUNDS_CONFIG": os.path.join(TMP, "cfg.json"), "NAVI_TAGLOG_DB": os.path.join(TMP, "t.db")})
os.environ.pop("NAVI_ALLOW_WRITES", None)
fails = []


def check(cond, msg):
    print(("PASS " if cond else "FAIL ") + msg)
    if not cond:
        fails.append(msg)


from core import navi_cli, tagscope  # noqa: E402

navi_cli.explore_info = lambda sub: {"ok": True, "stdout": ""}      # no live Tenable calls
WRITES = []                                                         # every navi write, mocked


def _fake_tag_set(category, value, uuids=None, sql="", params=(), **k):
    got = navi_cli.collect_uuids(sql, params, k.get("path")) if sql else sorted(uuids or [])
    WRITES.append({"fn": "tag_set", "category": category, "value": value, "uuids": set(got), "sql": sql,
                   "params": tuple(params)})
    return [{"ok": True, "job_id": len(WRITES)}] if got else []


def _fake_tag(category, value, **k):
    WRITES.append({"fn": "tag", "category": category, "value": value, **k})
    return {"ok": True, "job_id": len(WRITES)}


navi_cli.tag_set = _fake_tag_set
navi_cli.tag = _fake_tag

from agents.exproute import agent as A, api  # noqa: E402

import threading  # noqa: E402

_THREADS = []


def _submit(fn, meta=None):            # the job queue, as a thread we wait on
    t = threading.Thread(target=fn, daemon=True)
    t.start()
    _THREADS.append(t)
    return {"id": "t%d" % len(_THREADS)}


api.jobq.submit = _submit


def snap(p):
    """api.snapshot, then wait for the background build and peek, like the page does."""
    o, st = api.snapshot(p)
    while _THREADS:
        _THREADS.pop().join(120)
    if o.get("ok") and o.get("result") is None and o.get("building") and not p.get("peek"):
        o, st = api.snapshot({k: v for k, v in p.items() if k not in ("force", "refresh_owners")} | {"peek": True})
    return o, st


def norm(x):
    if isinstance(x, dict):
        return sorted((repr(k), norm(v)) for k, v in x.items())
    if isinstance(x, (set, frozenset)):
        return sorted(map(repr, x))
    if isinstance(x, (list, tuple)):
        return [norm(i) for i in x]
    return x


same = lambda a, b: repr(norm(a)) == repr(norm(b))  # noqa: E731

con = sqlite3.connect(DB)
# the tag with the most assets on a route/path, not an Owner tag
TK, TV = con.execute(
    "SELECT tag_key, tag_value FROM tags WHERE tag_key<>'Owner' AND asset_uuid IN "
    "(SELECT asset_uuid FROM vuln_paths UNION SELECT asset_uuid FROM vulns) "
    "GROUP BY 1,2 ORDER BY COUNT(DISTINCT asset_uuid) DESC LIMIT 1").fetchone()
SC = (TK, TV)
S = {r[0] for r in con.execute("SELECT DISTINCT asset_uuid FROM tags WHERE tag_key=? AND tag_value=?", SC)}
print(f"scope {TK} : {TV} — {len(S)} assets")


def pids(pl):
    return {str(x) for x in json.loads(str(pl or "[]").replace("'", '"'))}


# hand-computed over the tag's assets
route_assets_h = {}
for app, pl in con.execute("SELECT app_name, plugin_list FROM vuln_route WHERE app_name IS NOT NULL"):
    ids = pids(pl)
    aus = {a for (p, a) in con.execute("SELECT DISTINCT plugin_id, asset_uuid FROM vulns") if str(p) in ids}
    route_assets_h.setdefault(app, set()).update(aus)
path_rows_h = [(p, a) for p, a in con.execute("SELECT path, asset_uuid FROM vuln_paths WHERE path IS NOT NULL") if a in S]
path_assets_h = {}
for p, a in path_rows_h:
    path_assets_h.setdefault(p, set()).add(a)
on_surface_h = set().union(*[a & S for a in route_assets_h.values()], *path_assets_h.values())
route_findings_h = 0
for pl, in con.execute("SELECT plugin_list FROM vuln_route"):
    ids = pids(pl)
    route_findings_h += sum(1 for p, a in con.execute("SELECT plugin_id, asset_uuid FROM vulns") if str(p) in ids and a in S)
con.close()

# ── 1. whole estate unchanged ─────────────────────────────────────────────────
for name, f in (("_base", lambda **k: A._base(**k)), ("ownership_map", lambda **k: A.ownership_map(**k)),
                ("coverage", lambda **k: A.coverage(**k)), ("routes", lambda **k: A.routes(**k)),
                ("paths", lambda **k: A.paths(**k))):
    check(same(f(), f(scope=None)), f"estate: {name}() with scope=None is the no-scope result")
pth = next(iter(path_assets_h), None) or "/opt/navi"
check(same(A.path_detail(pth), A.path_detail(pth, scope=None)), "estate: path_detail unchanged")
check("scope" not in A.ownership_map() and "scope" not in A.coverage(), "estate results carry no scope")
o_est, _ = snap({"_nocache": True})
o_est2, _ = snap({"_nocache": True, "tag_scope": None})
check(o_est["ok"] and o_est2.get("cached") and same(o_est2["result"], A.snapshot_state()["snap"]),
      "estate: snapshot builds to the estate store; tag_scope=None is the estate")
check(same(o_est2["result"]["map"], A.ownership_map()) and same(o_est2["result"]["coverage"]["closed"], A.coverage()["closed"]),
      "estate snapshot = the direct estate map / coverage")
o_k, _ = snap({"_nocache": True, "tag_key": TK, "tag_value": TV, "peek": True})
check(o_k.get("result") is not None and "scope" not in o_k["result"],
      "tag_key / tag_value are NOT the scope (only tag_scope is)")

# ── 2. scoped counts = hand-computed ─────────────────────────────────────────
b = A._base(scope=SC)
m = A.ownership_map(scope=SC)
cv = A.coverage(scope=SC)
check(all(b["route_assets"].get(a, set()) == (aus & S) for a, aus in route_assets_h.items()),
      "every route's assets = its estate assets ∩ the tag")
check({k: v for k, v in b["path_assets"].items()} == path_assets_h, "every path's assets = the tag's assets on it")
check(m["kpi"]["asset_scope"] == len(on_surface_h), f"assets on a route/path = {len(on_surface_h)} (hand count)")
check(cv["total_paths"] == len(path_assets_h) and cv["path_findings"] == len(path_rows_h),
      "distinct paths / path findings counted over the tag only")
check(cv["route_findings"] == route_findings_h, f"route findings on the tag = {route_findings_h} (hand count)")
check(set(r["name"] for r in m["routes"]) == {a for a, aus in route_assets_h.items() if aus & S} |
      {a for a in route_assets_h if b["name_assets"].get(A._nk(a))},
      "only the routes the tag's assets sit on (or carry an Owner tag for) are listed")
check(all(r["assets"] == len(route_assets_h[r["name"]] & S) for r in m["routes"] if not r.get("disposition")),
      "each route's asset count is over the tag")
check(m["scope"]["label"] == f"{TK} : {TV}" and m["scope"]["assets"] == len(S) and cv["scope"]["assets"] == len(S),
      "scoped results say their scope")
rs = A.routes(scope=SC)
check(all(r["total_vulns"] > 0 and "total_vulns_estate" in r for r in rs), "scoped routes: findings on the tag + navi's estate total kept")
check(sum(p["assets"] for p in A.paths(scope=SC)) == sum(len(v) for v in path_assets_h.values()), "scoped paths: assets on the tag")
fn = m["funnel"]
con = sqlite3.connect(DB)
check(fn.get("findings") == con.execute("SELECT COUNT(*) FROM vulns WHERE asset_uuid IN (SELECT asset_uuid FROM tags "
                                        "WHERE tag_key=? AND tag_value=?)", SC).fetchone()[0],
      "funnel findings = the tag's findings")
con.close()
check(fn.get("routes") == len(m["routes"]) and fn.get("paths") == len(path_assets_h), "funnel routes / paths over the tag")
# an unknown tag: refused before any build, peek computes nothing
o_u, _ = snap({"tag_scope": {"key": "no such", "value": "x"}})
check(not o_u["ok"] and "navi update assets" in o_u["error"], "an unknown tag is refused with how to fix it")
o_p, _ = snap({"tag_scope": {"key": TK, "value": TV}, "peek": True})
check(o_p["ok"] and o_p.get("result") is None, "peek on an unbuilt tag view computes nothing")

# ── 3. per-asset values identical ─────────────────────────────────────────────
be = A._base()
check(all(be["asset_owned"].get(u, set()) == b["asset_owned"].get(u, set()) for u in S),
      "each tagged asset's owned routes/paths = its whole-estate ones")
check(all((u in be["route_assets"].get(a, set())) == (u in b["route_assets"].get(a, set()))
          for u in S for a in b["apps"]), "each tagged asset sits on the same routes")
check(all(A._has_owner_tag(be, u, a) == A._has_owner_tag(b, u, a) for u in S for a in b["apps"]),
      "closed / owned per asset is the same in both views")
mvpr = {r["name"]: r["cvss3"] for r in A.ownership_map()["routes"]}
check(all(r["cvss3"] == mvpr.get(r["name"]) for r in m["routes"]), "a route's CVSS3 (a plugin property) is unchanged")

# ── 4. every action the page calls is declared ───────────────────────────────
man = json.load(open(os.path.join(ROOT, "agents", "exproute", "manifest.json"), encoding="utf-8"))
pol = man.get("tag_scope") or {}
declared = set(pol.get("actions", [])) | set(pol.get("ignore", []))
called = set()
for f in ("agents/exproute/page.html", "web/ownermap.html"):       # the map is embedded in the page
    t = open(os.path.join(ROOT, f), encoding="utf-8").read()
    called |= set(re.findall(r"\bAPI\.post\('([a-z_]+)'", t))
    called |= set(re.findall(r"/api/exproute/([a-z_]+)", t))
check(called and called <= declared, f"page actions {sorted(called)} all declared in tag_scope")
check(set(pol.get("actions", [])) <= set(api.ACTIONS), "every declared action exists")
from core import launcher  # noqa: E402

r = launcher.dispatch("exproute", "load", {"tag_scope": {"key": TK, "value": TV}})
check(isinstance(r, tuple) and r[1] == 400, "an undeclared action (load) is refused when scoped")
p_ign = {"tag_scope": {"key": TK, "value": TV}}
check(tagscope.check("exproute", "refresh", p_ign) is None and "tag_scope" not in p_ign, "refresh ignores the scope")

# ── 5. scoped writes stay inside the tag, set recomputed server-side ─────────
route = next(r for r in m["routes"] if r["assets"])
WRITES.clear()
o, _ = api.apply({"owner": "Ignored", "app": route["name"], "confirm": True,
                  "tag_scope": {"key": TK, "value": TV}, "uuids": ["evil-uuid"], "asset_uuids": ["evil-uuid"]})
w = WRITES[-1] if WRITES else {}
check(w.get("fn") == "tag_set" and w["uuids"] == (route_assets_h[route["name"]] & S) and w["uuids"] <= S,
      "scoped route tag: exactly the tag's assets on the route, re-read from navi.db")
check("evil-uuid" not in w.get("uuids", set()) and o.get("scope", {}).get("assets") == len(S), "browser UUIDs ignored; result names the scope")
check(not any(x.get("route_id") for x in WRITES), "no --route_id (tenant-wide) write from a tag view")
if path_assets_h:
    pth = max(path_assets_h, key=lambda p: len(path_assets_h[p]))
    WRITES.clear()
    api.apply({"owner": "Accepted", "path": pth, "app": pth, "confirm": True, "tag_scope": {"key": TK, "value": TV}})
    check(WRITES and WRITES[-1]["uuids"] == path_assets_h[pth], "scoped path tag: only the tag's assets on the path")
WRITES.clear()
api.apply({"owner": "Ignored", "app": route["name"], "confirm": True})
check(WRITES and WRITES[-1]["fn"] == "tag" and WRITES[-1].get("route_id") not in (None, ""),
      "estate route tag still uses navi's --route_id (unchanged)")
o, _ = api.apply({"owner": "Ignored", "app": route["name"], "tag_scope": {"key": TK, "value": TV}})
check(not o["ok"], "scoped writes still need confirm=true")
o, _ = api.apply({"owner": "Ignored", "app": route["name"], "confirm": "true", "tag_scope": {"key": TK, "value": TV}})
check(not o["ok"], "confirm must be JSON true")
check(all(not x.get("remove") for x in WRITES), "never a removal")
# retag from a tag view: only the tag's assets carrying the old Owner tag
con = sqlite3.connect(DB)
con.execute("INSERT INTO tags(asset_uuid, tag_key, tag_value) SELECT asset_uuid, 'Owner', 'ZZ UNMATCHED: alice' FROM "
            "(SELECT DISTINCT asset_uuid FROM tags WHERE asset_uuid IS NOT NULL LIMIT 40)")
con.commit()
old = {r[0] for r in con.execute("SELECT asset_uuid FROM tags WHERE tag_value='ZZ UNMATCHED: alice'")}
con.close()
WRITES.clear()
o, _ = api.retag({"from": "ZZ UNMATCHED", "to": route["name"], "confirm": True, "tag_scope": {"key": TK, "value": TV}})
check(o.get("ok") and WRITES and WRITES[-1]["uuids"] == (old & S) and len(old & S) < len(old),
      "scoped retag: only the tag's assets that carry the old tag")
WRITES.clear()
api.retag({"from": "ZZ UNMATCHED", "to": route["name"], "confirm": True})
check(WRITES and WRITES[-1]["uuids"] == old, "estate retag unchanged (every asset with the old tag)")
pdp = A.path_detail(pth, scope=SC) if path_assets_h else {"assets": []}
check(all(a["uuid"] in S for a in pdp["assets"]), "path drill-down from a tag view lists only the tag's assets")

# ── 6. own cache: tag views apart from the estate, 5 kept ─────────────────────
# the switcher hook (core/tagscope asks api.scope_cached_at first): never builds
check(api.scope_cached_at(None, None) is None, "scope_cached_at: estate snapshot from an older navi.db → None")
check(api.scope_cached_at(TK, TV) is None and not _THREADS, "scope_cached_at: tag view not built → None, nothing started")
check(A.snapshot_state(scope=SC)["snap"] is None, "scope_cached_at computed nothing")
check(api.scope_cached_at("Nope", None) is None, "scope_cached_at: half a scope → None")
snap({"_nocache": True})                 # navi.db changed above (retag rows) — rebuild the estate
est_before = A.snapshot_state()["snap"]
o1, _ = snap({"_nocache": True, "tag_scope": {"key": TK, "value": TV}, "force": True})
st_tag = A.snapshot_state(scope=SC)["snap"]
st_est = A.snapshot_state()["snap"]
check(st_tag and st_tag["scope"]["label"] == f"{TK} : {TV}" and "scope" not in st_est,
      "the tag view's snapshot carries its scope; the estate's doesn't")
check(st_tag["map"]["kpi"]["asset_scope"] != st_est["map"]["kpi"]["asset_scope"] or len(S) == st_est["map"]["kpi"]["asset_scope"],
      "the tag view is not served the estate snapshot")
check(st_est["meta"]["built_at"] == est_before["meta"]["built_at"], "building a tag view leaves the estate snapshot as it was")
import datetime  # noqa: E402

_ms = lambda iso: int(datetime.datetime.fromisoformat(iso).timestamp() * 1000)  # noqa: E731
check(api.scope_cached_at(None, None) == _ms(st_est["meta"]["built_at"]), "scope_cached_at: estate → its snapshot's built_at (ms)")
check(api.scope_cached_at(TK, TV) == _ms(st_tag["meta"]["built_at"]), "scope_cached_at: tag → its exproute_tag snapshot's built_at (ms)")
check(api.scope_cached_at("no such", "tag") is None, "scope_cached_at: another tag not built → None")
tagscope.remember("exproute", TK, TV)   # the launcher does this for a scoped request
sw = tagscope.scopes("exproute")["scopes"]
check(sw[0]["cached_at"] == api.scope_cached_at(None, None) and
      any(x["key"] == TK and x["value"] == TV and x["cached_at"] == api.scope_cached_at(TK, TV) for x in sw),
      "the switcher (tagscope.scopes) shows the hound's own cache times")
o2, _ = snap({"_nocache": True, "tag_scope": {"key": TK, "value": TV}})
check(o2.get("cached") and o2["result"]["scope"]["key"] == TK, "the tag view's run comes back from its own cache")
o3, _ = snap({"_nocache": True})
check(o3.get("cached") and "scope" not in o3["result"], "switching back: the estate's cached run, no rebuild")
om_s, _ = api.omap({"tag_scope": {"key": TK, "value": TV}})
check(om_s["result"].get("scope", {}).get("key") == TK, "map action serves the tag's snapshot")
con = sqlite3.connect(DB)
pairs = con.execute("SELECT tag_key, tag_value FROM tags WHERE asset_uuid IS NOT NULL GROUP BY 1,2 "
                    "ORDER BY COUNT(*) DESC LIMIT 7").fetchall()
con.close()
for k, v in pairs:
    snap({"_nocache": True, "tag_scope": {"key": k, "value": v}, "force": True})
cache = os.environ["NAVI_CACHE_DIR"]
tag_files = [n for n in os.listdir(cache) if n.startswith("exproute_tag_")]
est_files = [n for n in os.listdir(cache) if n.startswith("exproute_") and not n.startswith("exproute_tag_") and n.endswith(".json.gz")]
check(len(tag_files) <= 5 and len(pairs) > 5, f"tag views keep at most 5 ({len(tag_files)} on disk after {len(pairs)})")
check(len(est_files) == 1 and snap({"_nocache": True})[0].get("cached"), "the estate snapshot is never evicted by tag views")

print(f"\n{len(fails)} failure(s)")
sys.exit(1 if fails else 0)
