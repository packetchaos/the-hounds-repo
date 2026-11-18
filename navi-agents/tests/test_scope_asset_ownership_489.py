"""Regression tests — build 489: a tag filter on Asset Ownership (Terminus).

  · With no tag the rollup, its KPIs, lists and the store namespace are exactly today's.
  · A tag view (tag_scope {key, value}) rolls up only the assets carrying that tag; every KPI is
    the hand count over those assets, and each asset's row equals its whole-estate row.
  · Every action the page calls is declared in the manifest's tag_scope block.
  · Tag views live in their own result-store namespace (asset_ownership_tag, keep 5): they never
    evict the estate's run, and a drill / blind-apply never mixes a tag's run with the estate's.
  · Writes from a tag view (apply by filter, apply blind, assign) recompute the set on the server
    and touch only the tag's assets; a browser uuid list is refused. navi writes are mocked.
Run: python3 tests/test_scope_asset_ownership_489.py"""
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
TMP = tempfile.mkdtemp(prefix="hounds-489-ao-")
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


from core import asset_ownership as engine, launcher, navi_cli, payload, tagscope, tagq  # noqa: E402

AID = "asset_ownership"
con = sqlite3.connect(DB)
TK, TV = "Business Tier", "Production"
TAGGED = {r[0] for r in con.execute("SELECT DISTINCT t.asset_uuid FROM tags t JOIN assets a ON a.uuid=t.asset_uuid "
                                    "WHERE t.tag_key=? AND t.tag_value=?", (TK, TV))}
N_ASSETS = con.execute("SELECT COUNT(DISTINCT uuid) FROM assets WHERE uuid IS NOT NULL AND uuid<>''").fetchone()[0]
N_CROWN_SQL = con.execute("SELECT COUNT(DISTINCT uuid) FROM assets WHERE CAST(acr AS REAL)>=9 AND uuid IN "
                          "(SELECT asset_uuid FROM tags WHERE tag_key=? AND tag_value=?)", (TK, TV)).fetchone()[0]
con.close()
SC = {"key": TK, "value": TV}
print(f"lab: {N_ASSETS} assets · scope {TK} : {TV} ({len(TAGGED)} assets)")
check(len(TAGGED) >= 10, "the sample has a usable tag")


def canon(o):
    return json.dumps(o, sort_keys=True, default=str)


# ── 1. engine: whole estate unchanged ────────────────────────────────────────
est = engine.overview()
check(est["ok"] and est["kpi"]["assets"] == N_ASSETS, "estate overview counts every asset")
check(canon(est) == canon(engine.overview(scope=None)) == canon(engine.overview(scope=("", ""))),
      "scope=None / an empty scope give the identical estate result")
check(canon(engine.assets_with_tags()) == canon(engine.assets_with_tags(scope=None)), "assets_with_tags unchanged with no scope")
check(engine.match_filter({}) == engine.match_filter({}, scope=None) and len(engine.match_filter({})) == N_ASSETS,
      "match_filter unchanged with no scope")
check(engine.in_scope(["x", "y"], None) == ["x", "y"], "in_scope is a no-op for the whole estate")

# ── 2. engine: a tag view ────────────────────────────────────────────────────
sc = engine.overview(scope=(TK, TV))
by = {r["uuid"]: r for r in est["assets"]}
mine = [by[u] for u in TAGGED]
k = sc["kpi"]
check(sc["ok"] and k["assets"] == len(TAGGED) and len(sc["assets"]) == len(TAGGED), "a tag view counts only the tag's assets")
check({r["uuid"] for r in sc["assets"]} == TAGGED, "every row of a tag view carries the tag")
check(all(canon(r) == canon(by[r["uuid"]]) for r in sc["assets"]), "each asset's row equals its whole-estate row")
check(k["crown"] == sum(1 for r in mine if r["crown"]) and k["crown"] >= N_CROWN_SQL, "crown jewels counted over the tag")
check(k["owned"] == sum(1 for r in mine if r["has_owner"]), "owned counted over the tag")
check(k["no_owner"] == sum(1 for r in mine if not r["has_owner"]), "no-owner counted over the tag")
check(k["unclaimed"] == sum(1 for r in mine if r["surface"] > 0 and r["unclaimed"]), "unclaimed counted over the tag")
check(k["business_owned"] == sum(1 for r in mine if r["business_owners"]), "business-owned counted over the tag")
check(k["crit_assets"] == sum(1 for r in mine if r["crit"]), "assets with critical findings counted over the tag")
check(k["surface_items"] == sum(r["surface"] for r in mine), "route/path items summed over the tag")
check(k["owned_pct"] == (round(100.0 * k["owned"] / k["assets"], 1) if k["assets"] else 0.0), "owned % is of the tag")
check(k["has_vulns"] == est["kpi"]["has_vulns"], "has_vulns means the same in a tag view")
check({r["uuid"] for r in sc["blind_spots"]} == {r["uuid"] for r in est["blind_spots"] if r["uuid"] in TAGGED}
      or len(est["blind_spots"]) >= 200, "blind spots are the estate's blind spots inside the tag")
own_hand = {}
for r in mine:
    names = ([r["asset_owner"]] if r["asset_owner"] else []) + r["business_owners"] + r["tech_owners"]
    for n in set(names):
        own_hand[n] = own_hand.get(n, 0) + 1
check({o["name"]: o["assets"] for o in sc["owners"]} == own_hand, "owners list counted over the tag")
tu = k["top_unowned"]
check(tu is None or tu["uuid"] in TAGGED, "highest-ACR unowned asset comes from the tag")
check(engine.overview(scope=("no such key", "x"))["kpi"]["assets"] == 0, "an unknown tag scopes to nothing")
fm = engine.match_filter({"crown": True}, scope=(TK, TV))
check(set(fm) == {r["uuid"] for r in mine if r["crown"]}, "match_filter in a tag view = the filter over the tag")
pl = engine.plan("the infra team owns all production assets", scope=(TK, TV))
check(pl.get("ok") and set(pl["uuids"]) <= TAGGED, "plan() in a tag view only matches the tag's assets")
check(engine.in_scope(sorted(TAGGED) + ["not-a-uuid"], (TK, TV)) == sorted(TAGGED), "in_scope keeps only tagged uuids")

# ── 3. manifest covers every page-called action ──────────────────────────────
man = json.load(open(os.path.join(ROOT, "agents", AID, "manifest.json")))
ts = man.get("tag_scope") or {}
page = open(os.path.join(ROOT, "agents", AID, "page.html"), encoding="utf-8").read()
called = set(re.findall(r"API\.post\('([a-z_]+)'", page)) | set(re.findall(r"jpost\('/api/asset_ownership/([a-z_]+)'", page))
called |= {"drill"} if "hDrill(" in page else set()
declared = set(ts.get("actions", [])) | set(ts.get("ignore", []))
check(called and called <= declared, f"every page-called action is declared ({sorted(called)})")
check(set(man["actions"]) <= declared, "every manifest action is either scoped or ignored")
check("mountTagScope(" in page and "tagScopeNote()" in page, "the page mounts the tag bar and names the scope in confirms")
check(page.count("tagScopeNote()") >= 3, "all three write confirms name the scope")
check(not re.search(r"fetch\('/api/asset_ownership", page), "no raw fetch to its own API bypasses the scope")

# ── 4. API: separate store namespaces, drill never mixes scopes ──────────────
bo, _ = launcher.dispatch(AID, "overview", {})
ERUN = (bo.get("drill") or {}).get("run")
check(bo.get("ok") and ERUN and ERUN.startswith("asset_ownership-"), "estate run lives in the estate namespace")
check((bo.get("result") or {}).get("scope") is None, "an estate result carries no scope")
so, _ = launcher.dispatch(AID, "overview", {"tag_scope": SC})
SRUN = (so.get("drill") or {}).get("run")
check(so.get("ok") and SRUN and SRUN.startswith("asset_ownership_tag-"), "a tag view's run lives in its own namespace")
check((so.get("result") or {}).get("scope", {}).get("assets") == len(TAGGED), "a scoped result says its scope")
check((so.get("summary") or {}).get("assets") == len(TAGGED), "a scoped summary counts the tag")
check(engine.STORE_NS == "asset_ownership", "the estate namespace is unchanged")
d, _ = launcher.dispatch(AID, "drill", {"run": SRUN, "section": "assets", "sort": "acr", "limit": 200, "tag_scope": SC})
check(d.get("ok") is not False and {r["uuid"] for r in d["top"]} == TAGGED, "drilling a tag view pages only the tag")
d, _ = launcher.dispatch(AID, "drill", {"run": ERUN, "section": "assets", "tag_scope": SC})
check(d.get("ok") is False and d.get("expired"), "a tag view cannot drill the estate's run")
d, _ = launcher.dispatch(AID, "drill", {"run": SRUN, "section": "assets"})
check(d.get("ok") is False and d.get("expired"), "the estate cannot drill a tag view's run")
d, _ = launcher.dispatch(AID, "drill", {"run": SRUN, "section": "assets", "tag_scope": {"key": "Owner", "value": "VM Team"}})
check(d.get("ok") is False and d.get("expired"), "one tag view cannot drill another tag's run")
# 6 tag runs: the estate's survives, and the newest 5 tag runs stay
tags6 = [("Business Tier", "Production"), ("Business Tier", "Staging"), ("Environment", "Cloud"), ("Owner", "VM Team"),
         ("Owner", "CENTOS: Linux Team"), ("Business Tier", "Production")]
runs = []
for kk, vv in tags6:
    o, _ = launcher.dispatch(AID, "overview", {"tag_scope": {"key": kk, "value": vv}, "_n": len(runs)})
    runs.append(((o.get("drill") or {}).get("run"), kk, vv))
check(payload.STORE.run_info(ERUN, "asset_ownership") is not None, "the estate's run survives six tag runs")
alive = [r for r, kk, vv in runs if payload.STORE.run_info(r, "asset_ownership_tag")]
check(len(alive) == tagscope.MAX_TAGS and runs[-1][0] in alive, "tag views keep their newest 5 runs")
d, _ = launcher.dispatch(AID, "drill", {"run": ERUN, "section": "assets", "sort": "acr", "limit": 200})
check(d.get("ok") is not False and len(d["top"]) == min(200, N_ASSETS), "the estate's rows still page after the tag runs")
_ua = navi_cli.update_async
navi_cli.update_async = lambda what: {"ok": True, "job": "x"}
try:
    ro, rc = launcher.dispatch(AID, "refresh", {"tag_scope": SC})
finally:
    navi_cli.update_async = _ua
check(isinstance(ro, dict) and ro.get("ok"), "refresh (navi update assets) ignores a tag scope")

# ── 5. writes from a tag view stay inside the tag (navi writes mocked) ───────
one, bulk, batched, subs = [], [], [], []
_o = (navi_cli.tag, navi_cli.tag_set, navi_cli.tag_uuids_batched, tagq.submit)
navi_cli.tag = lambda cat, val, query="", **kw: (one.append((cat, val, re.findall(r"'([^']+)'", query))) or {"ok": True})
navi_cli.tag_set = lambda cat, val, uuids=None, **kw: (bulk.append((cat, val, tuple(sorted(uuids or ())))) or [{"ok": True, "job_id": 1}])
navi_cli.tag_uuids_batched = lambda cat, val, uuids, **kw: (batched.append((cat, val, tuple(sorted(uuids)))) or [{"ok": True, "job_id": 2}])


def _submit(fn, kwargs, meta=None):
    subs.append((kwargs, meta))
    fn(**kwargs)
    return {"id": 99}


tagq.submit = _submit
try:
    o, st = launcher.dispatch(AID, "apply", {"owner": "Pay", "filter": {}, "layer": "business", "tag_scope": SC})
    check(st == 400 and not batched, "no confirm → refused, nothing written")
    o, st = launcher.dispatch(AID, "apply", {"owner": "Pay", "filter": {}, "layer": "business", "confirm": True, "tag_scope": SC})
    check(o.get("ok") and batched and set(batched[-1][2]) == TAGGED and batched[-1][0] == "Business Owner",
          "business apply by filter tags exactly the tag's assets")
    check((o.get("scope") or {}).get("label") == f"{TK} : {TV}", "the write result names its scope")
    o, st = launcher.dispatch(AID, "apply", {"owner": "Pay", "filter": {}, "layer": "business", "confirm": True})
    check(o.get("ok") and len(batched[-1][2]) == N_ASSETS, "the same apply with no tag still covers the estate")
    bulk.clear()
    o, st = launcher.dispatch(AID, "apply", {"owner": "Pay", "filter": {}, "layer": "asset", "mode": "complete",
                                             "confirm": True, "tag_scope": SC})
    check(o.get("queued") and set(subs[-1][0]["uuids"]) == TAGGED, "asset-layer apply queues only the tag's assets")
    check(bulk and all(set(u) <= TAGGED for _c, _v, u in bulk), "every cascaded Owner / Asset Owner tag stays in the tag")
    check("tagged " + f"{TK} : {TV}" in (subs[-1][1] or {}).get("selector", ""), "the Tagging log entry names the scope")
    o, st = launcher.dispatch(AID, "apply", {"owner": "Pay", "uuids": sorted(TAGGED)[:2], "layer": "business",
                                             "confirm": True, "tag_scope": SC})
    check(st == 400 and not o.get("ok"), "a tag view refuses an asset list from the browser")
    n_before = len(subs)
    o, st = launcher.dispatch(AID, "apply", {"owner": "Pay", "run": ERUN, "key": "blind", "layer": "asset",
                                             "confirm": True, "tag_scope": SC})
    check(not o.get("ok") and len(subs) == n_before, "blind-apply from a tag view cannot use the estate's run")
    o, _ = launcher.dispatch(AID, "overview", {"tag_scope": SC, "_n": "blind"})
    srun = (o.get("drill") or {}).get("run")
    nb = len((o.get("result") or {}).get("blind_spots") or [])
    o, st = launcher.dispatch(AID, "apply", {"owner": "Pay", "run": srun, "key": "blind", "layer": "asset",
                                             "confirm": True, "tag_scope": SC})
    if nb:
        check(o.get("ok") and set(subs[-1][0]["uuids"]) <= TAGGED and len(subs[-1][0]["uuids"]) == nb,
              "blind-apply from a tag view tags only its blind spots, re-checked in navi.db")
    else:
        check(not o.get("ok"), "blind-apply with no blind spots in the tag writes nothing")
    outside = sorted(set(engine.match_filter({})) - TAGGED)[0]
    one.clear()
    o, st = launcher.dispatch(AID, "assign", {"uuid": outside, "owner": "Pay", "confirm": True, "tag_scope": SC})
    check(st == 400 and not one, "assign from a tag view refuses an asset outside the tag (nothing written)")
    inside = sorted(TAGGED)[0]
    o, st = launcher.dispatch(AID, "assign", {"uuid": inside, "owner": "Pay", "confirm": True, "tag_scope": SC})
    check(o.get("ok") and one and all(q == [inside] for _c, _v, q in one), "assign inside the tag writes that asset only")
    one.clear()
    o, st = launcher.dispatch(AID, "assign", {"uuid": outside, "owner": "Pay", "confirm": True})
    check(o.get("ok") and one, "assign with no tag is unchanged")
    p, _ = launcher.dispatch(AID, "plan", {"prompt": "the infra team owns all production assets", "tag_scope": SC})
    check(p.get("ok") and "uuids" not in p and all(m["uuid"] in TAGGED for m in p["matched"])
          and (p.get("scope") or {}).get("assets") == len(TAGGED), "plan from a tag view previews only the tag")
finally:
    navi_cli.tag, navi_cli.tag_set, navi_cli.tag_uuids_batched, tagq.submit = _o

check("remove=True" not in open(os.path.join(ROOT, "core", "asset_ownership.py")).read(),
      "Terminus never removes tags")

print(f"\n{'ALL PASS' if not fails else str(len(fails)) + ' FAILURE(S)'}")
sys.exit(1 if fails else 0)
