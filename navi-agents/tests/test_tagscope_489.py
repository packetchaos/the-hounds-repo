"""Regression tests — build 489: the shared tag filter (core/tagscope.py + mountTagScope).

  · A hound opts in with manifest "tag_scope": {actions, ignore}. The launcher refuses a scoped
    request to any other action (no action can silently ignore a filter the operator thinks is
    on), drops the scope on `ignore` actions, and refuses it outright on hounds without a filter.
  · The scope is its own parameter, tag_scope:{key,value} — tag_key / tag_value already mean
    "the tag to write / remove / search" in several hounds, and Sköll keeps its own filter.
  · Each hound remembers its last 5 tags; the page cache keeps 5 tag views per hound, outside
    the general pool, and never prunes the whole-estate page.
Run: python3 tests/test_tagscope_489.py"""
import atexit
import json
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
TMP = tempfile.mkdtemp(prefix="hounds-489-")
atexit.register(shutil.rmtree, TMP, ignore_errors=True)
DB = os.path.join(TMP, "navi.db")
shutil.copy(os.path.join(ROOT, "sample_navi.db"), DB)
os.environ.update({"NAVI_DB_PATH": DB, "NAVI_CACHE_DIR": os.path.join(TMP, "cache"),
                   "HOUNDS_CONFIG": os.path.join(TMP, "cfg.json"), "NAVI_TAGLOG_DB": os.path.join(TMP, "t.db")})
fails = []


def check(cond, msg):
    print(("PASS " if cond else "FAIL ") + msg)
    if not cond:
        fails.append(msg)


from core import launcher, pagecache, tagscope  # noqa: E402
import sqlite3  # noqa: E402

c = sqlite3.connect(DB)
K, V, N = c.execute("SELECT tag_key, tag_value, COUNT(DISTINCT asset_uuid) n FROM tags GROUP BY 1,2 "
                    "HAVING n>=3 ORDER BY n DESC LIMIT 1").fetchone()
c.close()

# ── 1. helpers ────────────────────────────────────────────────────────────────
check(tagscope.parse({"tag_scope": {"key": K, "value": V}}) == (K, V), "parse: tag_scope {key, value}")
check(tagscope.parse({"tag_key": K, "tag_value": V}) == (None, None), "parse ignores tag_key / tag_value (other meanings)")
check(tagscope.parse({"tag_scope": {"key": K}}) == (None, None), "half a scope is the whole estate")
check(len(tagscope.uuids(K, V)) == N == tagscope.count(K, V), "uuids / count read the tag from navi.db")
frag, args = tagscope.sql(K, V, "a.uuid")
c = sqlite3.connect(DB)
n = c.execute("SELECT COUNT(*) FROM assets a WHERE 1=1" + frag, args).fetchone()[0]
c.close()
check(n == len(tagscope.uuids(K, V) & {r for r in tagscope.uuids(K, V)}) and frag.startswith(" AND a.uuid IN"),
      "sql(): a WHERE fragment that scopes an asset column")
check(tagscope.sql(None, None) == ("", ()), "sql(): nothing for the whole estate")
check(any(k["key"] == K for k in tagscope.keys()) and any(v["value"] == V for v in tagscope.values(K)),
      "keys / values for the picker")
check(tagscope.describe(K, V)["assets"] == N and tagscope.describe(None, None) is None, "describe(): the result's scope")

# ── 2. the launcher contract ──────────────────────────────────────────────────
tagscope._POLICY["zz_demo"] = {"actions": {"run", "tag"}, "ignore": {"source"}}
p = {"q": 1}
check(tagscope.check("zz_demo", "run", p) is None and p == {"q": 1}, "no scope → untouched")
p = {"tag_scope": {"key": " %s " % K, "value": V}}
check(tagscope.check("zz_demo", "run", p) is None and p["tag_scope"] == {"key": K, "value": V}, "a declared action gets it (trimmed)")
p = {"tag_scope": {"key": K, "value": V}}
check(tagscope.check("zz_demo", "source", p) is None and "tag_scope" not in p, "an `ignore` action: the scope is dropped")
r = tagscope.check("zz_demo", "drill", {"tag_scope": {"key": K, "value": V}})
check(r and r[1] == 400 and "doesn't support a tag filter" in r[0]["error"], "an undeclared action is REFUSED, not run unscoped")
r = tagscope.check("eol_nope", "run", {"tag_scope": {"key": K, "value": V}})
check(r and r[1] == 400 and "has no tag filter" in r[0]["error"], "a hound without a filter refuses a scope")
for bad in ({"key": K}, {"key": "", "value": V}, {"key": K, "value": 5}, {"key": "x" * 201, "value": V}, "K:V", [K, V]):
    r = tagscope.check("zz_demo", "run", {"tag_scope": bad})
    check(r and r[1] == 400, "malformed scope refused: %r" % (bad if not isinstance(bad, dict) else {k: str(v)[:10] for k, v in bad.items()}))
p = {"tag_scope": None}
check(tagscope.check("zz_demo", "run", p) is None and "tag_scope" not in p, "tag_scope: null = the whole estate")
check(tagscope.check("sla", "snapshot", {"tag_key": "Owner", "tag_value": "x"}) is None,
      "Sköll's own tag_key / tag_value filter is untouched")
check(tagscope.check("certificate", "tags_apply", {"tag_key": "Cert", "tag_value": "x", "confirm": True}) is None,
      "hounds that use tag_key / tag_value for the tag to WRITE are untouched")
o, st = launcher.dispatch("fused_score", "snapshot", {"tag_scope": {"key": K, "value": V}, "peek": True})
check(st == 400 and "no tag filter" in o["error"], "the launcher enforces it on a real request")

# ── 3. recent tags: 5 per hound ───────────────────────────────────────────────
for i in range(8):
    tagscope.remember("zz_demo", "Owner", "team %d" % i)
tagscope.remember("zz_demo", "Owner", "team 5")
R = tagscope.recent("zz_demo")
check(len(R) == 5 and R[0]["value"] == "team 5" and [x["value"] for x in R].count("team 5") == 1,
      "recent: newest first, deduplicated, at most 5")
check(tagscope.recent("other_hound") == [], "recent is per hound")

# ── 4. page cache: 5 tag views per hound, the estate page never pruned ────────
pagecache.MAX_PAGES = 2
base = "/agents/zz_demo/page.html"
pagecache.put(base, {"at": 1, "steps": [], "resp": {}})
for i in range(8):
    pagecache.put(base + tagscope.page_query("Owner", "team %d" % i), {"at": i, "steps": [], "resp": {}})
for i in range(3):
    pagecache.put("/agents/zz_other/page.html" + tagscope.page_query("Owner", "t%d" % i), {"at": i, "steps": [], "resp": {}})
for i in range(3):
    pagecache.put("/agents/zz_demo/page.html?target=u%d" % i, {"at": i, "steps": [], "resp": {}})
keys = {x["key"] for x in pagecache.listing()}
mine = [k for k in keys if k.startswith(base + "?tk=")]
check(base in keys, "the whole-estate page is never pruned")
check(len(mine) == 5 and base + tagscope.page_query("Owner", "team 7") in keys
      and base + tagscope.page_query("Owner", "team 0") not in keys, "a hound keeps its 5 newest tag views")
check(sum(1 for k in keys if k.startswith("/agents/zz_other/page.html?tk=")) == 3, "another hound's tag views are its own")
check(sum(1 for k in keys if "?target=" in k) == 2, "per-target variants still follow MAX_PAGES (tag views don't count)")

# ── 5. the page address matches the browser's encodeURIComponent ──────────────
tricky = [("Owner", "/opt/nessus: Web Team"), ("Bü Tier", "a&b=c d"), ("k#1", "50% + ?")]
js = "console.log(JSON.stringify(%s.map(([k,v])=>'?tk='+encodeURIComponent(k)+'&tv='+encodeURIComponent(v))))" % json.dumps(tricky)
try:
    out = json.loads(subprocess.run(["node", "-e", js], capture_output=True, text=True, timeout=30).stdout)
    check(out == [tagscope.page_query(k, v) for k, v in tricky], "page_query == the browser's encodeURIComponent")
except Exception as e:
    print("SKIP node not available:", e)

# ── 6. the switcher + the console ─────────────────────────────────────────────
from agents.hub import api as hub  # noqa: E402

pagecache.put(base + tagscope.page_query("Owner", "team 7"), {"at": 777, "steps": [], "resp": {}})
o, st = hub.tag_scopes({"agent": "zz_demo"})
S = o["result"]["scopes"]
check(st == 200 and S[0]["key"] is None and len(S) == 6 and S[1]["value"] == "team 5", "tag_scopes: estate + 5 recent")
check(any(x.get("cached_at") == 777 for x in S), "tag_scopes: when each tag view last ran")
o, _ = hub.tag_scopes({"agent": "zz_demo", "key": K})
check(any(v["value"] == V for v in o["result"]["values"]), "tag_scopes {key}: values")
check(hub.tag_scopes({"agent": "../x"})[1] == 400, "tag_scopes validates the hound id")
check("tag_scopes" in launcher._LIVE and ("hub", "tag_scopes") in launcher._OPEN_ACTIONS, "tag_scopes is a live page-open read")
js = open(os.path.join(ROOT, "web", "assets", "console.js"), encoding="utf-8").read()
check("tag_scope:{key:ts.key, value:ts.value}" in js and "'/api/'+ta+'/'" in js and "window.__TAG_SCOPE_AGENT = agent" in js,
      "jpost adds the scope only to the hound the filter was mounted for (not whatever agentApi() ran last)")
check("function mountTagScope" in js and "tsRunOnce" in js and "sessionStorage.removeItem('tsRunOnce')" in js,
      "the bar; ▶ Run for this tag presses ▶ Run once, only for the view it opened")
check("'tag_scopes'])" in js and js.count("!hTsClick(ev)") == 2 and "window.__TS_CLICK=b; try{ b.click(); } finally { window.__TS_CLICK=null; }" in js,
      "tag_scopes replays from the page cache; that one click is recorded as a run step (restorable)")

print()
print("%d failure(s)" % len(fails) if fails else "ALL PASS")
sys.exit(1 if fails else 0)
