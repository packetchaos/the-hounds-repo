"""Regression tests — build 489: Mimir (Software Analyzer) by tag.

  · With tag_scope {key, value} every Mimir number covers only the assets carrying that tag:
    the KPIs, each product's assets / versions / installs, crown-jewel roles, lifecycle EOL
    counts (endoflife.date AND Tenable-flagged) and the risk leaderboard. A software row lists
    many assets (navi's list form): only the tag's assets in it count.
  · Without a scope nothing changes (the estate bodies carry no "scope" key, same numbers).
  · Each asset's own values (its versions, its crown role, its KEV / critical rollup) are the
    whole estate's; only the population shrinks.
  · Tag runs live in the result store under their own hound name, so an estate run id never
    answers a tag view (or the reverse), tag runs never evict the estate run, and only the
    newest 5 tags are kept.
  · Tag writes from a tag view are rebuilt server-side over the tag only, never use the
    plugin-regex fallback (it would tag outside the tag), and filter any posted uuid list.
Run: python3 tests/test_scope_software_489.py"""
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
TMP = tempfile.mkdtemp(prefix="hounds-489sw-")
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


# ── the lab: add navi's LIST form (one row, many assets) and a cpes table ───────────────────
con = sqlite3.connect(DB)
TK, TV, NT = con.execute(
    "SELECT t.tag_key, t.tag_value, COUNT(DISTINCT t.asset_uuid) n FROM tags t JOIN assets a ON a.uuid=t.asset_uuid "
    "WHERE TRIM(COALESCE(t.tag_value,''))<>'' GROUP BY 1,2 HAVING n>=3 ORDER BY n DESC LIMIT 1").fetchone()
TAG = {r[0] for r in con.execute("SELECT DISTINCT asset_uuid FROM tags WHERE tag_key=? AND tag_value=?", (TK, TV))}
ALL = [r[0] for r in con.execute("SELECT uuid FROM assets ORDER BY uuid")]
inside = sorted(u for u in ALL if u in TAG)
outside = sorted(u for u in ALL if u not in TAG)
mix = inside[:3] + outside[:3]
con.execute("INSERT INTO software(asset_uuid, software_string) VALUES(?,?)", (str(mix), "listpkg-2.0.1-1.el8"))
con.execute("INSERT INTO software(asset_uuid, software_string) VALUES(?,?)", (str(outside[3:5]), "listpkg-1.9.0-1.el8"))
con.execute("INSERT INTO software(asset_uuid, software_string) VALUES(?,?)", (outside[5], "outsideonly-3.1-1"))
con.execute("CREATE TABLE IF NOT EXISTS cpes(asset_uuid TEXT, cpe_string TEXT)")
con.executemany("INSERT INTO cpes VALUES(?,?)", [(u, "['cpe:/a:acme:widget:4.2']") for u in inside[:2] + outside[:4]])
con.commit()
con.close()
print(f"lab: {len(ALL)} assets · scope {TK} : {TV} ({NT} assets)")

from core import launcher, navi_cli, payload, software as SW, tagscope  # noqa: E402
from agents.software import api  # noqa: E402

SC = {"tag_scope": {"key": TK, "value": TV}}

# ── hand count over the software / cpes tables ─────────────────────────────────────────────
def hand(scope_set=None):
    prod = {}
    c = sqlite3.connect(DB)
    for a, s in c.execute("SELECT asset_uuid, software_string FROM software WHERE software_string IS NOT NULL "
                          "AND software_string<>''"):
        uu = re.findall(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", a or "")
        if scope_set is not None:
            uu = [u for u in uu if u in scope_set]
        n, v = SW.parse_nvr_js(s)
        if not uu or not n:
            continue
        p = prod.setdefault(n.lower(), {"assets": set(), "vers": {}})
        p["assets"].update(uu)
        p["vers"].setdefault(v, set()).update(uu)
    for a, s in c.execute("SELECT asset_uuid, cpe_string FROM cpes"):
        if scope_set is not None and a not in scope_set:
            continue
        for n, v in SW.cpe_parse(s):
            p = prod.setdefault(n.lower(), {"assets": set(), "vers": {}})
            p["assets"].add(a)
            p["vers"].setdefault(v or "", set()).add(a)
    c.close()
    return prod


H_EST, H_TAG = hand(), hand(TAG)

# ── 1. whole estate unchanged ──────────────────────────────────────────────────────────────
e1, _ = api.inventory({})
e2, _ = launcher.dispatch("software", "inventory", {"tag_scope": {}})       # explicit "whole estate"
check(e1["ok"] and "scope" not in e1, "estate inventory carries no scope key")
strip = lambda b: {k: v for k, v in b.items() if k not in ("drill", "meta", "agent")}
check(strip(e1) == strip(e2), "an empty tag_scope is the whole estate, same body")
check(e1["summary"]["nprod"] == len(H_EST), "estate product count = hand count")
check(e1["summary"]["nasset"] == len(set().union(*[p["assets"] for p in H_EST.values()])), "estate asset count = hand count")
ps_none, _i = SW.product_sets()
ps_scope_none, _i2 = SW.product_sets(scope=None)
check({k: len(v["assets"]) for k, v in ps_none.items()} == {k: len(v["assets"]) for k, v in ps_scope_none.items()},
      "product_sets(scope=None) is the old call")
lp = next(r for r in api.drill({"run": e1["drill"]["run"], "section": "products", "view": "all", "limit": 200})[0]["top"] if r["name"] == "listpkg")
check(lp["nasset"] == 8 and lp["installs"] == 8, "estate: a list-form row counts every asset in it")
ERUN = e1["drill"]["run"]

# ── 2. scoped counts = hand count over the tag ─────────────────────────────────────────────
s1, _ = launcher.dispatch("software", "inventory", dict(SC))
check(s1["ok"] and s1["scope"]["label"] == f"{TK} : {TV}" and s1["scope"]["assets"] == NT, "scoped inventory says its scope")
check(s1["summary"]["nprod"] == len(H_TAG), f"scoped product count = hand count ({len(H_TAG)})")
tag_inv = set().union(*[p["assets"] for p in H_TAG.values()]) if H_TAG else set()
check(s1["summary"]["nasset"] == len(tag_inv) and tag_inv <= TAG, "scoped assets inventoried = hand count, all in the tag")
SRUN = s1["drill"]["run"]
rows = []
nxt = None
while True:
    b, _ = launcher.dispatch("software", "drill", dict(SC, run=SRUN, section="products", view="all", limit=200, **({"next": nxt} if nxt else {})))
    rows += b["top"]
    nxt = (b.get("page") or {}).get("next")
    if not nxt:
        break
check(b.get("scope", {}).get("key") == TK, "scoped drill says its scope")
check({r["name"].lower(): r["nasset"] for r in rows} == {k: len(v["assets"]) for k, v in H_TAG.items()},
      "every scoped product's asset count = hand count over the tag")
check(all({v["v"]: v["assets"] for v in r["vers"]} == {v: len(a) for v, a in H_TAG[r["name"].lower()]["vers"].items()}
          for r in rows), "every scoped version's asset count = hand count")
lps = next(r for r in rows if r["name"] == "listpkg")
check(lps["nasset"] == 3 and lps["installs"] == 3 and lps["nver"] == 1,
      "a list-form row only counts the tag's assets in it (3 of 8; the other version is outside)")
check(not any(r["name"] == "outsideonly" for r in rows), "a product only outside the tag is not in the tag view")
check(any(r["name"] == "widget" and r["nasset"] == 2 for r in rows), "cpes rows are scoped too")

# ── 3. per-asset values identical ──────────────────────────────────────────────────────────
for name in list(H_TAG)[:10]:
    est_v = H_EST[name]["vers"]
    check(all(set(a) == (est_v.get(v, set()) & TAG) for v, a in H_TAG[name]["vers"].items()),
          f"{name}: each version's tag assets = the estate's assets on it ∩ the tag")
for name in ("listpkg", "widget"):
    a_est = set(SW.assets_for(product=name))
    a_tag = set(SW.assets_for(product=name, scope=(TK, TV)))
    check(a_tag == a_est & TAG, f"assets_for({name}) in the tag = estate set ∩ tag")
cr_e, _ = api.crown({"run": ERUN})
cr_s, _ = launcher.dispatch("software", "crown", dict(SC, run=SRUN))
er = {r["role"]: r for r in cr_e["top"]}
check(all(r["role"] in er and r["acr"] == er[r["role"]]["acr"] and r["assets"] <= er[r["role"]]["assets"]
          for r in cr_s["top"]), "crown roles: same role + ACR per product, assets ≤ the estate's")
for r in cr_s["top"]:
    check(set(SW.assets_for(role=r["role"], scope=(TK, TV))) == set(SW.assets_for(role=r["role"])) & TAG,
          f"crown role {r['role']}: tag set = estate set ∩ tag")

rk_e, _ = api.risk({"run": ERUN})
rk_s, _ = launcher.dispatch("software", "risk", dict(SC, run=SRUN))
check(rk_e["ok"] and rk_s["ok"] and "scope" in rk_s and "scope" not in rk_e, "risk runs in both views")
# the per-asset rollup is the estate's: a product's KEV / critical host counts in the tag equal
# the number of the tag's assets (running it) whose own rollup has KEV / a critical
c = sqlite3.connect(DB)
vc = {r[1] for r in c.execute("PRAGMA table_info(vulns)")}
kev_a = {r[0] for r in c.execute("SELECT DISTINCT asset_uuid FROM vulns WHERE xrefs LIKE '%CISA-KNOWN-EXPLOITED%'")} \
    if "xrefs" in vc else set()
crit_a = {r[0] for r in c.execute("SELECT DISTINCT asset_uuid FROM vulns WHERE lower(severity)='critical' OR severity='4'")}
c.close()
for x in rk_s["top"]:
    A = H_TAG[x["name"].lower()]["assets"]
    check(x["kev"] == len(A & kev_a) and x["crit"] == len(A & crit_a) and x["nasset"] == len(A),
          f"risk {x['name']}: KEV/critical hosts counted from each asset's own rollup, over the tag")
for x in rk_e["top"]:
    A = H_EST[x["name"].lower()]["assets"]
    check(x["kev"] == len(A & kev_a) and x["crit"] == len(A & crit_a), f"risk {x['name']} (estate) unchanged rule")

# lifecycle: the browser's verdicts → EOL counts over the tag; Tenable-flagged EOL ∩ tag
plan_s, _ = launcher.dispatch("software", "eol_plan", dict(SC, run=SRUN))
check(plan_s["ok"] and "scope" in plan_s, "scoped eol_plan")
res = [{"name": x["name"], "slug": x["slug"], "latest": "999",
        "eolVers": (x["vers"].split("\n") if x.get("vers") else [])[:1]} for x in plan_s["plan"]]
lc, _ = launcher.dispatch("software", "lifecycle", dict(SC, run=SRUN, results=res))
ten_e = SW.tenable_eol_assets()
check(lc["ok"] and lc["summary"]["tenEolAssets"] == len(ten_e & TAG), "Tenable-flagged EOL assets counted over the tag only")
check(SW.tenable_eol_assets(scope=(TK, TV)) == ten_e & TAG, "tenable_eol_assets(scope) = estate ∩ tag")

# ── 4. every page-called action is declared ────────────────────────────────────────────────
page = open(os.path.join(ROOT, "agents", "software", "page.html"), encoding="utf-8").read()
called = set(re.findall(r"API\.post\('([a-z_]+)'", page)) | set(re.findall(r"runAgentJob\('software',\s*'([a-z_]+)'", page))
if "hDrill(" in page:
    called.add("drill")
man = json.load(open(os.path.join(ROOT, "agents", "software", "manifest.json"), encoding="utf-8"))
ts = man.get("tag_scope") or {}
declared = set(ts.get("actions") or []) | set(ts.get("ignore") or [])
check(called and called <= declared, "every action the page calls is declared: " + ", ".join(sorted(called)))
check(set(ts.get("actions")) <= set(api.ACTIONS) and set(ts.get("ignore")) <= set(api.ACTIONS), "declared actions exist")
check("mountTagScope({agent:'software'" in page, "the page mounts the tag filter")
check("tagScopeNote()" in page and re.search(r"confirm\('Tag '[^;]*tagScopeNote\(\)", page) is not None,
      "the tag confirm names the scope")
b, st = launcher.dispatch("software", "nl_translate", dict(SC, prompt=""))
check(st == 400 and "empty question" in b.get("error", ""), "an ignore action drops the scope (reaches the action)")

# ── 5. writes from a tag view stay inside the tag ──────────────────────────────────────────
SENT = []
_orig = navi_cli.tag_capped
navi_cli.tag_capped = lambda cat, val, uuids=None, fallbacks=None, **k: (
    SENT.append((cat, val, list(uuids or []), list(fallbacks or []))) or [{"ok": True, "job_id": len(SENT)}])
try:
    o, st = launcher.dispatch("software", "tag", dict(SC, run=SRUN, category="Software", value="listpkg",
                                                      key={"product": "listpkg"}, name="listpkg", confirm=False))
    check(st == 400 and not SENT, "confirm must be JSON true")
    o, st = launcher.dispatch("software", "tag", dict(SC, run=SRUN, category="Software", value="listpkg",
                                                      key={"product": "listpkg"}, name="listpkg", confirm=True))
    check(o["ok"] and SENT and set(SENT[-1][2]) == set(inside[:3]) and o["scope"]["key"] == TK,
          "a product tag from the tag view = the tag's assets running it (rebuilt server-side)")
    check(SENT[-1][3] == [], "no plugin-regex fallback from a tag view (it would reach outside the tag)")
    o, st = launcher.dispatch("software", "tag", dict(SC, run=SRUN, category="Software", value="x",
                                                      uuids=mix, confirm=True))
    check(o["ok"] and set(SENT[-1][2]) == set(inside[:3]), "a posted uuid list is cut to the tag's assets")
    o, st = launcher.dispatch("software", "tag", dict(SC, run=SRUN, category="Software", value="x",
                                                      uuids=outside[:3], confirm=True))
    check(not o["ok"] and st == 400, "a uuid list wholly outside the tag tags nothing")
    for r in cr_s["top"]:
        o, _ = launcher.dispatch("software", "tag", dict(SC, run=SRUN, category="Crown Jewel", value=r["role"],
                                                         key={"role": r["role"]}, confirm=True))
        check(o["ok"] and set(SENT[-1][2]) <= TAG, f"crown role tag {r['role']} stays inside the tag")
    eolp = [r for r in lc["top"] if (r.get("eol") or {}).get("eolAssetCount")]
    check(bool(eolp), "the scoped lifecycle check found EOL products in the tag")
    for r in eolp[:3]:
        o, _ = launcher.dispatch("software", "tag", dict(SC, run=SRUN, category="Software EOL", value=r["name"],
                                                         key={"product": r["name"], "kind": "eol"}, confirm=True))
        check(o["ok"] and set(SENT[-1][2]) <= TAG and len(SENT[-1][2]) == r["eol"]["eolAssetCount"],
              f"EOL tag {r['name']}: the tag run's verdicts, {r['eol']['eolAssetCount']} asset(s), inside the tag")
    o, _ = launcher.dispatch("software", "tag", {"category": "Software", "value": "listpkg",
                                                 "key": {"product": "listpkg"}, "name": "listpkg", "confirm": True,
                                                 "run": ERUN})
    check(o["ok"] and set(SENT[-1][2]) == set(mix) | set(outside[3:5]) and SENT[-1][3],
          "estate tag unchanged (all 8 assets, both versions; fallbacks kept)")
finally:
    navi_cli.tag_capped = _orig

# ── 6. own cache: scoped and estate runs apart ─────────────────────────────────────────────
b, _ = launcher.dispatch("software", "drill", dict(SC, run=ERUN, section="products", view="all"))
check(b.get("expired"), "an estate run id never answers a tag view")
b, _ = api.drill({"run": SRUN, "section": "products", "view": "all"})
check(b.get("expired"), "a tag run id never answers the estate view")
b, _ = launcher.dispatch("software", "product", dict(SC, run=ERUN, name="listpkg"))
check(b.get("expired"), "product: estate run refused in a tag view")
b, _ = launcher.dispatch("software", "drill", {"run": ERUN, "section": "products", "view": "all", "tag_scope": {"key": TK, "value": TV + "x"}})
check(b.get("expired") or not b.get("ok"), "another tag's view never gets this run")
c = sqlite3.connect(DB)
pairs = c.execute("SELECT tag_key, tag_value FROM tags WHERE TRIM(COALESCE(tag_value,''))<>'' GROUP BY 1,2 "
                  "ORDER BY COUNT(DISTINCT asset_uuid) DESC LIMIT 7").fetchall()
c.close()
for k, v in pairs:
    launcher.dispatch("software", "inventory", {"tag_scope": {"key": k, "value": v}, "_nocache": True})
check(payload.STORE.run_info(ERUN, "software") is not None, "the estate run survives many tag runs")
st_con = payload.STORE._connect()
hs = [r[0] for r in st_con.execute("SELECT DISTINCT hound FROM runs WHERE hound LIKE 'software_t%'")]
st_con.close()
check(len(hs) == tagscope.MAX_TAGS, f"only the newest {tagscope.MAX_TAGS} tags keep runs (have {len(hs)})")
b, _ = launcher.dispatch("software", "inventory", {"tag_scope": {"key": "no such key", "value": "x"}})
check(not b["ok"] and "no assets carry" in b["error"], "an unknown tag is refused with how to fix it")
b, st = launcher.dispatch("software", "bogus_action", dict(SC))
check(st == 400, "the launcher refuses a scoped request to an undeclared action")

print("\n%s — %d failure(s)" % ("FAIL" if fails else "ALL PASS", len(fails)))
sys.exit(1 if fails else 0)
