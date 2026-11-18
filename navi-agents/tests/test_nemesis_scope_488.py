"""Regression tests — build 488: Nemesis by tag, and a Nemesis column in Software Explorer.

  · Exposure Score (Nemesis) can be scoped to one tag (tag_key : tag_value). Every KPI, band,
    act-now set, leaderboard row and worst-per-Hound entry covers only that tag's assets; each
    asset's own score is the whole-estate score. Tag views are their own cache (fused_tag), so
    switching between a tag and the whole estate never rebuilds or evicts the other. The scope
    is re-read from navi.db in the job — never taken from the browser — and Priority tagging
    from a tag view only tags that tag's assets.
  · A whole-estate, default-weighted build saves every asset's score; Software Explorer shows it
    as a Nemesis column (sortable, in the CSV) and never computes it. A score map built on an
    older navi.db is reported as stale, not shown.
Run: python3 tests/test_nemesis_scope_488.py"""
import atexit
import csv
import io
import os
import shutil
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
TMP = tempfile.mkdtemp(prefix="hounds-488-")
atexit.register(shutil.rmtree, TMP, ignore_errors=True)
DB = os.path.join(TMP, "navi.db")
LAB = os.path.join(ROOT, "sample_navi.db")
shutil.copy(LAB, DB)
os.environ.update({"NAVI_DB_PATH": DB, "NAVI_CACHE_DIR": os.path.join(TMP, "cache"),
                   "HOUNDS_CONFIG": os.path.join(TMP, "cfg.json"), "NAVI_TAGLOG_DB": os.path.join(TMP, "t.db")})
fails = []


def check(cond, msg):
    print(("PASS " if cond else "FAIL ") + msg)
    if not cond:
        fails.append(msg)


import sqlite3  # noqa: E402

from core import fused_score as engine, launcher, snapcache  # noqa: E402

con = sqlite3.connect(DB)
pair = con.execute("SELECT t.tag_key, t.tag_value, COUNT(DISTINCT t.asset_uuid) n FROM tags t JOIN assets a ON a.uuid=t.asset_uuid "
                   "WHERE TRIM(COALESCE(t.tag_value,''))<>'' GROUP BY 1,2 HAVING n>=3 ORDER BY n DESC LIMIT 1").fetchone()
TK, TV, NT = pair
n_assets = con.execute("SELECT COUNT(*) FROM assets").fetchone()[0]
con.close()
print(f"lab: {n_assets} assets · scope {TK} : {TV} ({NT} assets)")

# ── 1. the engine ─────────────────────────────────────────────────────────────
scores = {}
est = engine.overview(limit=5000, scores=scores)
check(est["ok"] and len(scores) == est["total"] == n_assets, "scores= fills a score for every asset")
scope = engine.scope_uuids(TK, TV)
check(len(scope) == NT, "scope_uuids reads the tag's assets from navi.db")
sc = engine.overview(limit=5000, scope=scope)
check(sc["ok"] and sc["total"] == NT and sc["kpi"]["assets"] == NT, "a scoped overview counts only the tag's assets")
check(all(r["uuid"] in scope for r in sc["assets"]), "every leaderboard row is in the tag")
check(all(r["score"] == scores[r["uuid"]] for r in sc["assets"]), "each asset's score equals its whole-estate score")
check(sum(r["score"] for r in sc["assets"]) == sc["kpi"]["estate"], "the scope's exposure total is the sum over its assets")
check(all(w["uuid"] in scope for w in sc["worst"]), "worst-per-Hound picks come from the tag's assets only")
for t in ("80", "60", "40"):
    check(sc["kpi"]["act"][t]["n"] == sum(1 for u in scope if scores.get(u, -1) >= int(t)),
          f"act-now ≥ {t} counted over the tag only")
sel = engine.select_uuids(threshold=1, scope=scope)
check(sel and set(sel) <= scope, "Priority tagging from a tag view selects only that tag's assets")
check(engine.scope_uuids("no such key", "x") == set(), "an unknown tag scopes to nothing")

# ── 2. the API: two caches, scope never from the browser ─────────────────────
from agents.fused_score import api as fapi  # noqa: E402

o, _ = fapi.snapshot({"tag_key": "no such key", "tag_value": "x"})
check(not o["ok"] and "navi update assets" in o["error"], "an unknown tag is refused with how to fix it")
o, _ = fapi.snapshot({"tag_key": TK, "tag_value": TV, "uuids": ["evil"], "peek": True})
check(o["ok"] and o.get("result") is None, "peek on an unbuilt tag computes nothing")
estate_extra = fapi._extra(None)
fapi.SNAP.build(lambda: fapi._estate_build(None), extra=estate_extra)
m = engine.score_map()
check(m and not m.get("stale") and len(m["scores"]) == n_assets and m["scores"] == scores,
      "a whole-estate default-weighted build saves every asset's score")
tx = dict(estate_extra, scope={"tag_key": TK, "tag_value": TV})
fapi.SNAP_TAG.build(lambda: fapi._tag_build(None, TK, TV), extra=tx)
o, _ = fapi.snapshot({"tag_key": TK, "tag_value": TV})
r = (o.get("result") or {}).get("result") or {}
check(o["ok"] and o.get("cached") and r.get("total") == NT and r.get("scope", {}).get("tagged") == NT,
      "the tag snapshot is served from the tag cache, with its scope")
o2, _ = fapi.snapshot({})
check(o2.get("cached") and o2["result"]["result"]["total"] == n_assets, "…and the whole-estate snapshot is still cached")
# weighted estate build does NOT replace the default score map
w = {f["id"]: 1 for f in engine.FACTORS}
fapi.SNAP.build(lambda: fapi._estate_build(w), extra=fapi._extra(w))
check(engine.score_map()["scores"] == scores, "a custom-weighted build leaves the default score map alone")

# ── 3. the switcher ───────────────────────────────────────────────────────────
fapi._remember(TK, TV)
o, _ = fapi.scopes({})
S = o["result"]["scopes"]
check(S[0]["key"] is None and S[0]["cached"], "scopes: the whole estate first, cached")
mine = [x for x in S if x["key"] == TK and x["value"] == TV]
check(mine and mine[0]["cached"] and mine[0]["assets"] == NT, "scopes: the recent tag, cached, with its asset count")
check(any(k["key"] == TK for k in o["result"]["keys"]), "scopes: tag categories for the picker")
o, _ = fapi.scopes({"key": TK})
check(any(v["value"] == TV for v in o["result"]["values"]), "scopes {key}: that category's values")
# many tag views never push the estate out
for i in range(fapi.SNAP_TAG.keep + 3):
    fapi.SNAP_TAG.build(lambda: {"ok": True, "total": 0}, extra=dict(estate_extra, scope={"tag_key": "k", "tag_value": str(i)}))
check(fapi.SNAP.state(extra=estate_extra)["snap"] is not None, "tag views beyond the tag cache's size never evict the estate snapshot")
check(fapi.SNAP_TAG.keep >= 2 and fapi.SNAP.name != fapi.SNAP_TAG.name, "the tag cache is a separate store")
for i in range(10):
    fapi._remember("Owner", "team %d" % i)
check(len(fapi._recent()) == fapi.RECENT_MAX, "the recent list is bounded")
check("scopes" in launcher._LIVE and ("fused_score", "scopes") in launcher._OPEN_ACTIONS,
      "scopes is a live page-open read (never cached, never a counted run)")

# ── 4. Software Explorer's Nemesis column ─────────────────────────────────────
from agents.ex_software import api as sw  # noqa: E402

o, _ = sw.search({"q": "openssl", "limit": 200})
R = o["result"]
check(R["nemesis"]["state"] == "ok" and R["rows"] and all(x["nemesis"] == scores.get(x["asset_uuid"]) for x in R["rows"]),
      "every row carries its asset's saved Nemesis score")
o, _ = sw.search({"q": "openssl", "limit": 200, "sort": "nemesis"})
v = [x["nemesis"] if x["nemesis"] is not None else -1 for x in o["result"]["rows"]]
check(o["result"]["sort"] == "nemesis" and v == sorted(v, reverse=True) and o["result"]["total"] == R["total"],
      "sort: nemesis ranks the same selection most-exposed first")
o, _ = sw.export({"q": "openssl"})
rows = list(csv.reader(io.StringIO(o["csv"])))
check(rows[0][-1] == "nemesis_score" and all(r[-1] == str(scores.get(r[2], "")) for r in rows[1:]),
      "the CSV export ends with the Nemesis score")
# navi.db changes → the map is stale, not shown
time.sleep(0.01)
c2 = sqlite3.connect(DB)
c2.execute("UPDATE assets SET acr=acr")
c2.commit()
c2.close()
os.utime(DB, None)
sw._CACHE.clear()
o, _ = sw.search({"q": "openssl", "limit": 50})
check(o["result"]["nemesis"]["state"] == "stale" and all(x["nemesis"] is None for x in o["result"]["rows"]),
      "after navi.db changes the old scores are not shown — the page says to re-run Exposure Score")
o, _ = sw.search({"q": "openssl", "sort": "nemesis"})
check(o["result"]["sort"] == "", "no sort by a stale score")
shutil.rmtree(os.path.join(TMP, "cache"), ignore_errors=True)
engine._SCORES = None
o, _ = sw.search({"q": "openssl"})
check(o["result"]["nemesis"]["state"] == "none", "no score map yet → state none")

# ── 5. the pages ──────────────────────────────────────────────────────────────
pg = open(os.path.join(ROOT, "agents", "fused_score", "page.html"), encoding="utf-8").read()
check("API.post('scopes'" in pg and "switchScope" in pg and "tag_key=SCOPE.key" in pg and "fused_scope_v1" in pg,
      "Nemesis page: scope switcher, scoped requests, remembered scope")
check("tag_key:SHOWN_SCOPE.key" in pg, "Nemesis page: Priority tagging carries the shown scope")
sp = open(os.path.join(ROOT, "agents", "ex_software", "page.html"), encoding="utf-8").read()
check(">Nemesis</th>" in sp and "nemCell(x.nemesis)" in sp and "colspan=\"7\"" not in sp and "sort:SORT" in sp,
      "Software Explorer: Nemesis column, sort, table widths updated")

print()
print("%d failure(s)" % len(fails) if fails else "ALL PASS")
sys.exit(1 if fails else 0)
