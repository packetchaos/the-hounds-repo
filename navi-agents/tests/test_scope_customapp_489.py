"""Regression tests — build 489: Cavall / Argus (Custom App) by tag.

  · With a tag_scope {key, value} the Custom App hunt runs over that tag's assets only: path
    candidates come from the tag's vuln_paths rows, a route candidate is kept when any of its
    plugins sits on one of the tag's assets, and every asset count (assets, crown, unowned) covers
    only the tag's assets. Whether a name is "in the inventory", "named" or "owned" is judged
    exactly as on the whole estate.
  · No tag → byte-for-byte today's result (golden values from the pre-489 code on sample_navi.db).
  · A tag write from a tag view re-reads the set from navi.db (paths matching the keyword + the
    matching routes' plugin assets, both IN the tag) and tags it by UUID — never --route_id,
    never a UUID list from the browser. Add-only.
  · Tag runs use their own agent instance, so the estate's last result is never replaced.
Run: python3 tests/test_scope_customapp_489.py"""
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
TMP = tempfile.mkdtemp(prefix="hounds-489-capp-")
atexit.register(shutil.rmtree, TMP, ignore_errors=True)
DB = os.path.join(TMP, "navi.db")
shutil.copy(os.path.join(ROOT, "sample_navi.db"), DB)
os.environ.update({"NAVI_DB_PATH": DB, "NAVI_CACHE_DIR": os.path.join(TMP, "cache"),
                   "HOUNDS_CONFIG": os.path.join(TMP, "cfg.json"), "NAVI_TAGLOG_DB": os.path.join(TMP, "t.db"),
                   "CUSTOMAPP_IGNORE_PATH": os.path.join(TMP, "ignore.json")})
os.environ.pop("NAVI_ALLOW_WRITES", None)
fails = []


def check(cond, msg):
    print(("PASS " if cond else "FAIL ") + msg)
    if not cond:
        fails.append(msg)


from core import navi_cli, tagscope  # noqa: E402
from agents.customapp import api, agent as ca  # noqa: E402

TK, TV = "Business Tier", "Production"
SC = {"tag_scope": {"key": TK, "value": TV}}
con = sqlite3.connect(DB)
TAGGED = {r[0] for r in con.execute("SELECT DISTINCT asset_uuid FROM tags WHERE tag_key=? AND tag_value=?", (TK, TV))}
ACR = {r[0]: r[1] for r in con.execute("SELECT uuid, acr FROM assets")}
OWNED = {r[0] for r in con.execute("SELECT DISTINCT asset_uuid FROM tags WHERE tag_key='Owner'")}
ROUTE_PL = {r[0]: set(re.findall(r"\d+", r[1] or "")) for r in con.execute("SELECT app_name, plugin_list FROM vuln_route")}


def plugin_assets(pids, within=None):
    s = {r[0] for r in con.execute("SELECT DISTINCT asset_uuid FROM vulns WHERE plugin_id IN (%s)" % ",".join("?" * len(pids)),
                                   sorted(pids)) if r[0]}
    return s & within if within is not None else s


print(f"lab: scope {TK} : {TV} ({len(TAGGED)} assets)")

# ── 1. whole estate unchanged ─────────────────────────────────────────────────
o, code = api.run({})
E = o["result"]
GOLD = [("route", "CENTOS", 316, 29, 14, 0, False), ("route", "JENKINS", 50, 0, 0, 0, False),
        ("route", "APACHE", 5, 0, 0, 0, False), ("route", "NAVI", 3, 0, 0, 0, False),
        ("path", "nessus", 1, 1, 1, 0, False), ("path", "nessus_agent", 1, 1, 0, 0, False),
        ("path", "spring-boot-application", 1, 1, 1, 0, False)]          # pre-489 code (base494) on sample_navi.db
check(code == 200 and [(c["source"], c["name"], c["evidence"], c["assets"], c["crown"], c["unowned"], c["named"])
                       for c in E["candidates"]] == GOLD, "estate: candidates identical to the pre-489 run")
check(E["metrics"] == {'assets': 32, 'candidates': 7, 'crown_assets': 16, 'crown_candidates': 3, 'custom_app_tags': 0,
                       'has_acr': True, 'named': 0, 'named_pct': 0.0, 'paths': 3, 'routes': 4, 'top_assets': 29,
                       'unnamed': 7, 'unowned_assets': 0, 'unowned_candidates': 0}
      and E["counts"] == {'candidates': 7, 'hidden': 0, 'paths': 10, 'routes': 6, 'software': 39},
      "estate: metrics and counts identical to the pre-489 run")
check("scope" not in E and "scope" not in o, "estate: no scope key added to the result")
# an explicit "whole estate" scope is dropped by the launcher contract → same answer
p = {"tag_scope": {}}
check(tagscope.check("customapp", "run", p) is None and "tag_scope" not in p, "an empty tag_scope is the whole estate")
check(api.run(p)[0]["result"] == E, "…and gives exactly the estate result")

# estate SQL is the same text as before (no fragment, no params)
from core import db as _db  # noqa: E402
seen = []
_orig_q = _db.query
_db.query = lambda sql, *a, **k: (seen.append((sql, a)), _orig_q(sql, *a, **k))[1]
ca.search_paths("jen"); ca.search_routes("jen")
_db.query = _orig_q
check(seen[0] == ("SELECT p.path, p.plugin_id, a.hostname, a.ip_address, p.asset_uuid FROM vuln_paths p LEFT JOIN assets a "
                  "ON a.uuid=p.asset_uuid WHERE p.path LIKE '%jen%' GROUP BY p.path;", ())
      and seen[1] == ("SELECT route_id, app_name, vuln_type, total_vulns FROM vuln_route WHERE app_name LIKE '%jen%' "
                      "ORDER BY total_vulns DESC;", ()), "estate: search SQL unchanged")
es, _ = api.search({"keyword": "jenkins"})
check("scope" not in es and "tag_assets" not in es and es["path_count"] == 3 and es["route_count"] == 1,
      "estate: search result shape unchanged")

# ── 2. scoped counts = hand-computed over the tag's assets ───────────────────
o, code = api.run(dict(SC))
S = o["result"]
check(code == 200 and S["scope"]["label"] == f"{TK} : {TV}" and S["scope"]["assets"] == len(TAGGED),
      "scoped: the result names its scope and the tag's asset count")
paths_in = [(r[0], r[1]) for r in con.execute("SELECT path, asset_uuid FROM vuln_paths WHERE path IS NOT NULL AND path<>''")
            if r[1] in TAGGED]
check(S["counts"]["paths"] == len(paths_in), "scoped: path rows counted over the tag's assets only")
tok = {}
for pth, u in paths_in:
    if "/plugins/" in pth.lower():
        continue
    for t in ca.path_tokens(pth):
        tok.setdefault(t, set()).add(u)
SB = {c["name"]: c for c in S["candidates"]}
EB = {c["name"]: c for c in E["candidates"]}
for c in S["candidates"]:
    if c["source"] == "path":
        check(c["assets"] == len(tok[c["keyword"]]) and c["evidence"] == len(tok[c["keyword"]]),
              f"scoped: path candidate {c['name']} counts the tag's assets ({c['assets']})")
    else:
        a = plugin_assets(ROUTE_PL[c["name"]], TAGGED)
        check(c["assets"] == len(a) > 0, f"scoped: route candidate {c['name']} = its plugin assets in the tag ({len(a)})")
        check(c["crown"] == sum(1 for u in a if float(ACR.get(u) or 0) >= 7) and c["unowned"] == len(a - OWNED),
              f"scoped: route {c['name']} crown / unowned over the tag's assets")
check(set(SB) <= set(EB), "scoped: every candidate is also an estate candidate (same verdicts, fewer assets)")
gone = set(EB) - set(SB)
check(all((EB[n]["source"] == "route" and not plugin_assets(ROUTE_PL[n], TAGGED)) or
          (EB[n]["source"] == "path" and n not in tok) for n in gone), "scoped: dropped candidates have no asset in the tag")
allA = set()
for c in S["candidates"]:
    allA |= (plugin_assets(ROUTE_PL[c["name"]], TAGGED) if c["source"] == "route" else tok[c["keyword"]])
check(S["metrics"]["assets"] == len(allA) and allA <= TAGGED, "scoped: 'assets running custom software' = the tag's assets only")
check(S["metrics"]["candidates"] == len(S["candidates"]) and S["counts"]["routes"] == E["counts"]["routes"]
      and S["counts"]["software"] == E["counts"]["software"], "scoped: inventory / route totals stay estate-wide")

# ── 3. per-candidate verdicts identical ──────────────────────────────────────
check(all(SB[n]["named"] == EB[n]["named"] and SB[n]["source"] == EB[n]["source"] and SB[n]["keyword"] == EB[n]["keyword"]
          and SB[n]["in_inventory"] == EB[n]["in_inventory"] for n in SB), "per-candidate: named / source / keyword identical")
check(all(SB[n]["evidence"] == EB[n]["evidence"] for n in SB if SB[n]["source"] == "route"),
      "per-candidate: a route's evidence (findings on the route) is the same number")
check(all(SB[n]["assets"] <= EB[n]["assets"] for n in SB), "per-candidate: never more assets than the estate")

# scoped search
o, _ = api.search({"keyword": "centos", **SC})
want = plugin_assets(ROUTE_PL["CENTOS"], TAGGED)
check(o["route_count"] == 1 and o["routes"][0]["scope_assets"] == len(want) == o["tag_assets"] and o["scope"],
      "scoped search: a route reports its assets in the tag; tag_assets is the write's set size")
o, _ = api.search({"keyword": "nessus", **SC})
check(all(m["asset_uuid"] in TAGGED for m in o["matches"]) and o["path_count"] == len({p for p, u in paths_in if "nessus" in p}),
      "scoped search: path matches only on the tag's assets")

# ignore list: hidden counts only what sits in the tag
ca.save_ignore(["centos", "jenkins"])
hs = api.run(dict(SC))[0]["result"]
he = api.run({})[0]["result"]
check(he["hidden"] == 2 and hs["hidden"] == (1 if plugin_assets(ROUTE_PL["CENTOS"], TAGGED) else 0)
      + (1 if plugin_assets(ROUTE_PL["JENKINS"], TAGGED) else 0), "ignore list: a tag view's 'hidden' counts only ignored apps on the tag")
ca.save_ignore([])

# ── 4. every page-called action is declared ──────────────────────────────────
page = open(os.path.join(ROOT, "agents", "customapp", "page.html"), encoding="utf-8").read()
called = set(re.findall(r"API\.post\('([a-z_]+)'", page))
man = json.load(open(os.path.join(ROOT, "agents", "customapp", "manifest.json")))
ts = man.get("tag_scope") or {}
declared = set(ts.get("actions", [])) | set(ts.get("ignore", []))
check(called and called <= declared, f"every page action is declared ({sorted(called)})")
check(set(ts["actions"]) == {"run", "search", "tag"} and not (set(ts["actions"]) & set(ts["ignore"])),
      "run/search/tag honour the scope; interpret and the ignore list ignore it")
check("mountTagScope({agent:'customapp'" in page and "fetch(" not in page, "the page mounts the tag bar and uses no raw fetch")
check(page.index("mountTagScope(") > page.index("mountAgentHeader("), "mountTagScope comes after mountAgentHeader")
check("tagScopeNote()" in page[page.index("async function cappTag"):], "the tag confirm names the scope")
for a in ts["ignore"]:
    pp = {"tag_scope": {"key": TK, "value": TV}}
    check(tagscope.check("customapp", a, pp) is None and "tag_scope" not in pp, f"{a}: scope dropped (ignore)")
check(tagscope.check("customapp", "nope", {"tag_scope": {"key": TK, "value": TV}})[1] == 400, "an undeclared action is refused")

# ── 5. scoped writes: recomputed server-side, inside the tag ─────────────────
calls = {"tag": [], "tag_set": []}
navi_cli.tag = lambda *a, **k: (calls["tag"].append((a, k)), {"ok": True, "queued": True, "job_id": 1})[1]
navi_cli.tag_set = lambda *a, **k: (calls["tag_set"].append((a, k)), [{"ok": True, "queued": True, "job_id": 7}])[1]
o, code = api.tag({"name": "Jenkins", "keyword": "jenkins", **SC})
check(code == 400 and not calls["tag_set"] and not calls["tag"], "scoped tag: confirm=true still required")
o, code = api.tag({"name": "Jenkins", "keyword": "jenkins", "confirm": "true", **SC})
check(code == 400, "scoped tag: confirm must be JSON true")
o, code = api.tag({"name": "CentOS", "keyword": "centos", "confirm": True, "uuids": ["evil-uuid"], **SC})
want = plugin_assets(ROUTE_PL["CENTOS"], TAGGED) | {u for p, u in paths_in if "centos" in p.lower()}
ts_args = calls["tag_set"][-1] if calls["tag_set"] else ((), {})
sent = set(ts_args[1].get("uuids") or [])
check(o["ok"] and o["scoped_assets"] == len(want) and sent == want, "scoped tag: the set is re-read from navi.db (route plugins + paths in the tag)")
check(sent <= TAGGED and "evil-uuid" not in sent, "scoped tag: every UUID carries the tag; nothing from the browser")
check(not calls["tag"], "scoped tag: no --route_id / --query call that could reach the whole route")
check(ts_args[0][:2] == ("Custom App", "CentOS") and "remove" not in ts_args[1] and o["scope"]["key"] == TK,
      "scoped tag: Custom App : <name>, add-only, scope in the answer")
o, _ = api.tag({"name": "Nope", "keyword": "zzz-nothing", "confirm": True, **SC})
check(not o["ok"] and TV in o["error"] and len(calls["tag_set"]) == 1, "scoped tag: nothing in the tag → nothing written, says so")
# a path on an asset OUTSIDE the tag is never tagged from the tag view
outside = con.execute("SELECT path, asset_uuid FROM vuln_paths").fetchall()
outside = [(p_, u) for p_, u in outside if u not in TAGGED]
if outside:
    kw = outside[0][0].rsplit("/", 1)[-1]
    calls["tag_set"].clear()
    o, _ = api.tag({"name": "X", "keyword": kw, "confirm": True, **SC})
    s2 = set(calls["tag_set"][-1][1]["uuids"]) if calls["tag_set"] else set()
    check(s2 <= TAGGED and outside[0][1] not in s2, f"scoped tag: '{kw}' on an untagged asset is not touched")
# estate write path unchanged: --query for paths and --route_id per route
calls["tag"].clear(); calls["tag_set"].clear()
o, _ = api.tag({"name": "Jenkins", "keyword": "jenkins", "confirm": True})
check([k.get("route_id") for a, k in calls["tag"] if k.get("route_id")] == ["3"]
      and any(len(a) > 2 and a[2] == ca.tag_query_for("jenkins") for a, k in calls["tag"])
      and all(k.get("remove") is False for a, k in calls["tag"]) and not calls["tag_set"],
      "estate tag: unchanged (--query + --route_id, remove=False)")

# ── 6. own state: scoped runs never replace the estate's ─────────────────────
api.run({})
before = api.AGENT.result
api.run(dict(SC))
check(api.AGENT.result is before and api.AGENT_TAG.result is not before and api.AGENT_TAG.result.get("scope"),
      "a tag run uses its own agent instance — the estate's last result stays")
check(api.AGENT.summary()["candidates"] == len(E["candidates"]), "the estate summary still shows the estate")
o2, _ = api.run({"tag_scope": {"key": "Owner", "value": "VM Team"}})
check(o2["result"]["scope"]["value"] == "VM Team" and api.run(dict(SC))[0]["result"] == S,
      "switching tags recomputes each tag the same; nothing leaks between them")
check(api.run({})[0]["result"] == E, "…and the estate result is unchanged after tag runs")
o3, _ = api.run({"tag_scope": {"key": "no such", "value": "tag"}})
check(o3["result"]["candidates"] == [] and o3["result"]["scope"]["assets"] == 0, "an unknown tag scopes to nothing")

con.close()
print(f"\n{'ALL PASS' if not fails else str(len(fails)) + ' FAIL'}")
sys.exit(1 if fails else 0)
