"""Regression tests for Asset Ownership (Terminus) — core/asset_ownership.py overview()
"At a glance" fields (build 441), the claimed-% overlap fix, missing-table tolerance, the
plan() filter hardening, and the api's confirm gate / input validation.
Tiny synthetic navi.db in a temp dir; no navi, no network, no writes.
Run: python3 tests/test_asset_ownership.py  (or pytest)."""
import atexit
import os
import re
import shutil
import sqlite3
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
TMP = tempfile.mkdtemp(prefix="hounds-ownership-")
atexit.register(shutil.rmtree, TMP, ignore_errors=True)
os.environ["NAVI_CACHE_DIR"] = os.path.join(TMP, "cache")
os.environ.pop("NAVI_ALLOW_WRITES", None)
DB = os.path.join(TMP, "navi.db")
os.environ["NAVI_DB_PATH"] = DB

fails = []


def check(cond, msg):
    print(("PASS " if cond else "FAIL ") + msg)
    if not cond:
        fails.append(msg)


c = sqlite3.connect(DB)
c.executescript("""
CREATE TABLE assets (uuid TEXT, hostname TEXT, ip_address TEXT, acr TEXT, aes INTEGER);
CREATE TABLE vulns (asset_uuid TEXT, plugin_id TEXT, plugin_name TEXT, severity TEXT, xrefs TEXT, state TEXT);
CREATE TABLE tags (asset_uuid TEXT, tag_key TEXT, tag_value TEXT);
CREATE TABLE vuln_route (app_name TEXT, plugin_list TEXT);
CREATE TABLE vuln_paths (asset_uuid TEXT, plugin_id TEXT, path TEXT);""")
A = [("a1", "web", "10.0.0.1", "10"),   # crown, business owner only
     ("a2", "db", "10.0.0.2", "9"),     # crown, NO owner, critical + KEV
     ("a3", "app", "10.0.0.3", "5"),    # single Asset Owner · complete
     ("a4", "ops", "10.0.0.4", "4"),    # Asset Owner · remainder
     ("a5", "dev", "10.0.0.5", "8"),    # route owner AND an Accepted disposition on the same route
     ("a6", "lab", "10.0.0.6", "2"),    # no owner, fixed critical only
     ("a7", "old", "10.0.0.7", "1")]    # bare classic `Owner: VM Team` tag → owned (as Exposure Score reads it)
for r in A:
    c.execute("INSERT INTO assets VALUES (?,?,?,?,0)", r)
c.execute("INSERT INTO vuln_route VALUES ('Apache', \"['100']\")")
for u in ("a1", "a2", "a3", "a4", "a5", "a6", "a7"):
    c.execute("INSERT INTO vulns VALUES (?,?,?,?,?,?)", (u, "100", "apache", "medium", "", "open"))
c.execute("INSERT INTO vulns VALUES ('a2','200','crit','Critical','CISA-KNOWN-EXPLOITED:2024/01/01','open')")
c.execute("INSERT INTO vulns VALUES ('a2','201','crit2','critical','','reopened')")
c.execute("INSERT INTO vulns VALUES ('a6','202','old crit','critical','CISA-KNOWN-EXPLOITED','fixed')")
c.execute("INSERT INTO vuln_paths VALUES ('a5','100','/opt/app')")
T = [("a1", "Business Owner", "Jane <b>Smith</b>"),
     ("a3", "Asset Owner", "netsec · complete"),
     ("a4", "Asset Owner", "ops team · remainder"),
     ("a5", "Owner", "Apache: Linux Team"),
     ("a5", "Owner", "Apache: Accepted"),
     ("a5", "Owner", "/opt/app: Linux Team"),
     ("a7", "Owner", "VM Team"),
     ("a1", "Business Tier", "Production"), ("a3", "Business Tier", "Production")]
for t in T:
    c.execute("INSERT INTO tags VALUES (?,?,?)", t)
c.commit()
c.close()

from core import asset_ownership as eng  # noqa: E402

r = eng.overview(DB)
k = r["kpi"]
rows = {x["uuid"]: x for x in r["assets"]}
check(r["ok"] and k["assets"] == 7, "overview reads 7 assets")
# keys the page / contract / release relied on before build 441 are all still there
for key in ("assets", "with_surface", "fully_claimed", "unclaimed", "business_owned", "asset_owned",
            "tech_owned", "crown", "crown_unclaimed", "crown_owned_pct", "blind", "blind_no_signal",
            "kev_assets", "crown_acr"):
    check(key in k, "kpi keeps " + key)
check(set(r) >= {"kpi", "assets", "crown_jewels", "blind_spots", "owners", "owners_total"}, "result keys")
check(k["owned"] == 5 and k["no_owner"] == 2, "owned 5 / no owner 2 (a2, a6)")
check(k["owned_pct"] == round(500 / 7, 1), "owned_pct")
check(rows["a7"]["has_owner"] and not rows["a7"]["unclaimed"] and rows["a7"]["tech_owners"] == ["VM Team"],
      "bare Owner tag makes the asset owned (matches Exposure Score)")
check(k["business_owned"] == 1 and k["no_business"] == 6, "business-owner layer coverage")
check(k["asset_owned"] == 2 and k["asset_owned_complete"] == 1 and k["asset_owned_remainder"] == 1,
      "asset owner complete vs remainder")
check(k["crown"] == 2 and k["crown_no_owner"] == 1, "crown jewels 2, one with no owner")
check(rows["a2"]["crit"] == 2 and rows["a2"]["kev"] is True, "a2: 2 open/reopened criticals + KEV")
check(rows["a6"]["crit"] == 0 and rows["a6"]["kev"] is False, "fixed findings don't count")
check(k["unowned_crit"] == 1 and k["unowned_kev"] == 1 and k["unowned_crit_findings"] == 2,
      "unowned assets with criticals / KEV")
check(k["has_vulns"] is True and k["kev_finding_assets"] == 1, "has_vulns + kev_finding_assets")
check(k["top_unowned"] and k["top_unowned"]["uuid"] == "a2", "highest-ACR unowned asset → a2")
# a5: route Apache is both owned and Accepted; path owned → 2 of 2 handled, never > 100 %
check(rows["a5"]["claimed_pct"] == 100.0, "owned + dispositioned route counted once (claimed ≤ 100%%): %s"
      % rows["a5"]["claimed_pct"])
check(all(x["claimed_pct"] is None or x["claimed_pct"] <= 100 for x in r["assets"]), "no claimed_pct > 100")
check(k["surface_items"] == 8 and k["surface_handled"] <= k["surface_items"], "route/path items")
own = {o["name"]: o for o in r["owners"]}
check(r["owners_total"] == 5 and own["Linux Team"]["tech"] == 1 and own["Linux Team"]["assets"] == 1,
      "owners by asset count (a name counts an asset once)")
check(own["Jane <b>Smith</b>"]["business"] == 1 and own["Jane <b>Smith</b>"]["crown"] == 1, "business owner row")
check(own["netsec"]["asset"] == 1, "asset owner row")

# the unowned count agrees with Exposure Score (Nemesis), which the page's card links to
from core import fused_score  # noqa: E402
check(fused_score.overview(DB)["kpi"]["unowned"] == k["no_owner"], "no_owner == Exposure Score's unowned")

# ---- missing tables: no crash ----
for name, ddl in [("only_assets", "CREATE TABLE assets (uuid TEXT, hostname TEXT, ip_address TEXT);"
                                  "INSERT INTO assets VALUES ('x','h','1.1.1.1');"),
                  ("empty", "CREATE TABLE foo (a);")]:
    p = os.path.join(TMP, name + ".db")
    cc = sqlite3.connect(p)
    cc.executescript(ddl)
    cc.close()
    try:
        o = eng.overview(p)
        ok = (o["ok"] and o["kpi"]["has_vulns"] is False and o["kpi"]["no_owner"] == 1
              and o["owners"] == []) if name == "only_assets" else (o["ok"] is False and "error" in o)
        check(ok, "overview on %s db: %s" % (name, "ok" if o.get("ok") else o.get("error")))
        pl = eng.plan("assign Jane to production", p)
        check(isinstance(pl, dict), "plan on %s db doesn't crash" % name)
    except Exception as e:  # pragma: no cover
        check(False, "overview on %s db raised %r" % (name, e))

# ---- plan(): a loosely-shaped (model-built) filter can't crash the preview ----
_orig = eng._rule_plan
eng._rule_plan = lambda prompt, schema: {"owner": "Jane", "layer": "business", "mode": None,
                                         "filter": {"tags": [{"value": "x"}, "junk", {"key": "Business Tier",
                                                                                         "value": "Production"}],
                                                    "host_like": [None, 3]}}
try:
    pl = eng.plan("anything", DB)
    check(pl["ok"] and pl["match_count"] == 2, "plan tolerates malformed filter items (%s)" % pl.get("match_count"))
except Exception as e:
    check(False, "plan raised on malformed filter: %r" % e)
eng._rule_plan = _orig
pl = eng.plan("assign Jane Smith to production", DB)
check(pl["ok"] and pl["layer"] == "business" and pl["match_count"] == 2, "plan: business owner of production")

# ---- api: writes need confirm; bad inputs are 400s, not crashes ----
from agents.asset_ownership import api  # noqa: E402

body, code = api.apply({"owner": "x", "uuids": ["a1"]})
check(code == 400 and not body["ok"], "apply without confirm → 400")
body, code = api.assign({"owner": "x", "uuid": "a1"})
check(code == 400 and not body["ok"], "assign without confirm → 400")
body, code = api.apply({"confirm": True, "owner": "x", "uuids": "a1"})
check(code == 400, "apply with a non-list uuids → 400")
body, code = api.apply({"confirm": True, "owner": 5, "uuids": ["a1"]})
check(code == 400, "apply with a non-string owner → 400")
body, code = api.assign({"confirm": True, "owner": ["x"], "uuid": "a1"})
check(code == 400, "assign with a non-string owner → 400")
body, code = api.plan({"prompt": 7})
check(code == 400, "plan with a non-string prompt → 400")
check(api._mode("Remainder") == "remainder" and api._mode("weird") == "complete", "mode normalised")

# ---- page: design pattern + explicit-run + confirm before writes ----
page = open(os.path.join(ROOT, "agents", "asset_ownership", "page.html"), encoding="utf-8").read()
check('data-nav="At a glance"' in page and "mountSectionNav()" in page and "setNavCount(" in page,
      "page has the jump nav + At a glance section")
check("renderGlance('glance'" in page and not re.search(r"^function renderGlance\(", page, re.M) and '.mkpi{' not in page,
      "At a glance uses the shared (phone-safe) renderGlance template without shadowing it")
check("if(FOCUS.uuid||FOCUS.host){ load(); }" not in page, "deep link no longer auto-runs the rollup")
for fn in ("async function doAssign", "async function claimAllBlind", "async function applyPlan"):
    i = page.index(fn)
    body_ = page[i:page.index("API.post(", i)]
    check("confirm(" in body_, fn.split()[-1] + " confirms before the write")
check('onclick="' not in page, "no inline onclick attributes (data-* + listeners only)")
check(page.count("data-run") >= 2, "▶ Run and ✨ Ask carry data-run")

# ── build 464: the asset-layer owner cascade is unbounded and computed in bulk ───────────────
from core import navi_cli  # noqa: E402
_orig_tag, _orig_set = navi_cli.tag, navi_cli.tag_set
one, bulk = [], []
navi_cli.tag = lambda cat, val, query="", **kw: (one.append((cat, val, re.findall(r"'([^']+)'", query)[0])) or {"ok": True})
navi_cli.tag_set = lambda cat, val, uuids=None, **kw: (bulk.append((cat, val, tuple(sorted(uuids)))) or [{"ok": True, "job_id": 1}])
try:
    for mode in ("complete", "remainder"):
        del one[:], bulk[:]
        for u in ("a1", "a2", "a3", "a4", "a5", "a6", "a7"):
            eng.assign_asset_owner(u, "Ops", mode=mode)
        r = eng.assign_assets_owner(["a1", "a2", "a3", "a4", "a5", "a6", "a7"], "Ops", mode=mode)
        per = {}
        for cat, val, u in one:
            per.setdefault((cat, val), set()).add(u)
        got = {(cat, val): set(uu) for cat, val, uu in bulk}
        check(per == got and r["assets"] == 7,
              "bulk owner cascade (%s) writes exactly the per-asset tags, grouped by value (%d values)" % (mode, len(got)))
    many = ["z%06d" % i for i in range(7000)]
    del bulk[:]
    eng.assign_assets_owner(many, "Ops")
    check(any(len(uu) == 7000 for _c, _v, uu in bulk), "no 2,000-asset cap: 7,000 assets → one paged tag of 7,000")
finally:
    navi_cli.tag, navi_cli.tag_set = _orig_tag, _orig_set
src = open(os.path.join(ROOT, "agents", "asset_ownership", "api.py"), encoding="utf-8").read()
check("[:2000]" not in src and "[:2000]" not in open(os.path.join(ROOT, "core", "contract.py"), encoding="utf-8").read(),
      "asset ownership + the Contract carry no 2,000-asset cap")

print("\n%d failure(s)" % len(fails))
sys.exit(1 if fails else 0)
