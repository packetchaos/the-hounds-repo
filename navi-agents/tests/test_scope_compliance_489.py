"""Regression tests — build 489: a tag filter on Minos (Compliance overview, agents/compliance).

  · overview with no tag_scope is exactly what it was (same result as core.compliance.overview()).
  · overview scoped to one tag rebuilds every number over the compliance rows of that tag's
    assets only; each asset's scorecard row is identical to its whole-estate row.
  · the manifest declares every action the page posts while a tag is selected.
  · a scoped Audit-Owner tag write re-reads the control's failing assets from navi.db, narrowed to
    the tag — never from the browser — and stays add-only.
  · a scoped run never replaces the agent's in-memory estate result (its status card), and the
    launcher's read cache keys scoped and estate results apart.
Run: python3 tests/test_scope_compliance_489.py"""
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
TMP = tempfile.mkdtemp(prefix="hounds-489-compliance-")
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


from core import compliance as comp, launcher, navi_cli, tagscope  # noqa: E402
from agents.compliance import api  # noqa: E402

con = sqlite3.connect(DB)
TK, TV, NT = con.execute(
    "SELECT t.tag_key, t.tag_value, COUNT(DISTINCT c.asset_uuid) n FROM tags t JOIN compliance c ON c.asset_uuid=t.asset_uuid "
    "GROUP BY 1,2 HAVING n>=3 ORDER BY n DESC LIMIT 1").fetchone()
TAGGED = {r[0] for r in con.execute("SELECT DISTINCT asset_uuid FROM tags WHERE tag_key=? AND tag_value=?", (TK, TV))}
ROWS = [dict(zip(("asset_uuid", "check_id", "status", "reference", "audit_file"), r)) for r in con.execute(
    "SELECT asset_uuid, check_id, status, reference, audit_file FROM compliance")]
n_estate_assets = len({r["asset_uuid"] for r in ROWS if r["asset_uuid"]})
con.close()
SROWS = [r for r in ROWS if r["asset_uuid"] in TAGGED]
print(f"sample: {len(ROWS)} compliance rows over {n_estate_assets} assets · scope {TK} : {TV} ({NT} audited assets)")
SC = {"tag_scope": {"key": TK, "value": TV}}

# ── 1. whole estate unchanged ─────────────────────────────────────────────────
base = comp.overview()                                   # the no-scope engine baseline
o, code = api.overview({})
check(code == 200 and o["ok"] and o["result"] == base, "no tag_scope: overview result identical to the engine's whole-estate baseline")
check("scope" not in o and "scope" not in o["result"], "no tag_scope: no scope key added to the estate result")
check(comp.overview(None, None) == base, "overview(scope=None) is the whole estate")
check(base["assets"] == n_estate_assets, "baseline counts every audited asset")
o2, _ = api.overview({"tag_scope": {}})
check(o2["result"] == base, "an empty tag_scope is the whole estate")

# ── 2. scoped counts = hand-computed over the tag's assets ────────────────────
ESTATE_RESULT = api._agent().result
s, code = api.overview(dict(SC))
r = s["result"]
check(code == 200 and s["ok"] and r["available"], "scoped overview runs")
check(r["scope"] == {"key": TK, "value": TV, "label": f"{TK} : {TV}", "assets": len(TAGGED)}, "scoped result carries describe()")
up = lambda x: (x or "").upper()
hand = {"passed": sum(up(x["status"]).startswith("PASS") for x in SROWS),
        "failed": sum(up(x["status"]).startswith("FAIL") for x in SROWS),
        "warning": sum(up(x["status"]).startswith("WARN") for x in SROWS)}
check(r["assets"] == NT == len(r["assets_rows"]), f"scoped assets = {NT} (the tag's audited assets)")
check(r["results"] == len(SROWS), "scoped results = the tag's compliance rows")
check(all(r[k] == v for k, v in hand.items()), f"scoped passed/failed/warning = hand count {hand}")
check(r["checks"] == len({x["check_id"] for x in SROWS}), "scoped controls = distinct check_ids of the tag's rows")
hp = hand["passed"] + hand["failed"]
check(r["pass_pct"] == (round(100.0 * hand["passed"] / hp, 1) if hp else None), "scoped pass rate over the tag's rows")
check(all(a["asset_uuid"] in TAGGED for a in r["assets_rows"]), "every asset row is in the tag")
fc = {}
for x in SROWS:
    if up(x["status"]).startswith("FAIL"):
        fc.setdefault(x["check_id"], set()).add(x["asset_uuid"])
check(r["failed_controls"] == len(fc), "scoped failing controls = controls failing on a tagged asset")
check(all(c["failed_assets"] == len(fc.get(c["check_id"], ())) for c in r["top_failing"]),
      "each top-failing control's failed_assets counts only tagged assets")
fw = {}
for x in SROWS:
    if up(x["status"]).startswith("FAIL"):
        for ref in comp.parse_reference(x["reference"]):
            fw[ref["framework"]] = fw.get(ref["framework"], 0) + 1
check({f["framework"]: f["failed"] for f in r["frameworks"]} == dict(sorted(fw.items(), key=lambda kv: (-kv[1], kv[0]))[:20]),
      "framework rollup counted over the tag's failed rows")
check(sum(a["assets"] for a in r["audit_files"]) <= sum(a["assets"] for a in base["audit_files"])
      and all(a["assets"] <= NT for a in r["audit_files"]), "benchmark asset counts stay inside the tag")
check(r["assets"] < base["assets"], "the tag view covers fewer assets than the estate")

# ── 3. per-asset values identical ────────────────────────────────────────────
est = {a["asset_uuid"]: a for a in base["assets_rows"]}
check(all(a == est[a["asset_uuid"]] for a in r["assets_rows"]), "each tagged asset's scorecard row equals its whole-estate row")
check({a["asset_uuid"] for a in r["assets_rows"]} == {u for u in est if u in TAGGED}, "the tag view lists exactly the tagged audited assets")

# empty / unknown tag
e, _ = api.overview({"tag_scope": {"key": "no such key", "value": "x"}})
check(e["ok"] and e["result"]["available"] is False and e["result"].get("scoped_empty"), "an unknown tag reports 'no audit results for this tag'")

# ── 4. manifest covers every page-called action ──────────────────────────────
man = json.load(open(os.path.join(ROOT, "agents", "compliance", "manifest.json"), encoding="utf-8"))
ts = man.get("tag_scope") or {}
declared = set(ts.get("actions") or []) | set(ts.get("ignore") or [])
page = open(os.path.join(ROOT, "agents", "compliance", "page.html"), encoding="utf-8").read()
called = set(re.findall(r"API\.post\('(\w+)'", page)) | set(re.findall(r"runAgentJob\('compliance',\s*'(\w+)'", page))
check(called == {"overview", "tag"} and called <= declared, f"every page-called action is declared ({sorted(called)})")
check(set(ts.get("actions")) == {"overview", "tag"}, "overview and tag both honour the scope")
check("mountTagScope({agent:'compliance'" in page and "fetch('/api/" not in page, "page mounts the tag bar and posts only through jpost")
check("tagScopeNote()" in page and "confirm('Tag '+tagCat('Audit Owner')" in page, "the tag confirm names the scope")
tagscope._POLICY.clear()
pl = {"tag_scope": {"key": TK, "value": TV}}
check(tagscope.check("compliance", "overview", pl) is None and tagscope.check("compliance", "tag", dict(pl)) is None,
      "the launcher lets scoped overview / tag through")
bad = tagscope.check("compliance", "framework", dict(pl))
check(bad is not None and bad[1] == 400, "an undeclared action (framework) refuses a scope")

# ── 5. scoped writes: recomputed server-side, inside the tag ─────────────────
calls = []
real_tag_set = navi_cli.tag_set


def fake_tag_set(category, value, uuids=None, **kw):
    calls.append({"category": category, "value": value, "uuids": list(uuids or []), **kw})
    return [{"ok": True, "queued": True, "job_id": len(calls), "message": "queued (mock)"}]


navi_cli.tag_set = fake_tag_set
try:
    # a control failing on tagged AND untagged assets
    pick = None
    for cid in {x["check_id"] for x in ROWS}:
        allf = {x["asset_uuid"] for x in ROWS if x["check_id"] == cid and up(x["status"]).startswith("FAIL")}
        if allf & TAGGED and allf - TAGGED:
            pick, ALLF = cid, allf
            break
    check(pick is not None, "sample has a control failing inside and outside the tag")
    o, code = api.tag({"confirm": True, "check_id": pick, "owner": "payments-team"})
    check(code == 200 and set(calls[-1]["uuids"]) == ALLF, "estate tag write: the control's failing assets (unchanged)")
    o, code = api.tag({"confirm": True, "check_id": pick, "owner": "payments-team", "uuids": ["evil-uuid"],
                       "tag_scope": {"key": TK, "value": TV}})
    got = set(calls[-1]["uuids"])
    check(code == 200 and got == (ALLF & TAGGED), "scoped tag write: re-read from navi.db, only tagged failing assets")
    check("evil-uuid" not in got and got <= TAGGED, "a browser uuid list is ignored; nothing outside the tag")
    check(o["asset_count"] == len(ALLF & TAGGED) and o["scope"]["key"] == TK, "the scoped write reports its count and scope")
    check(calls[-1].get("op", "tag") == "tag" and calls[-1]["category"] == comp.TAG_OWNER_CATEGORY, "scoped write is add-only (op=tag)")
    n = len(calls)
    o, code = api.tag({"check_id": pick, "owner": "x", "tag_scope": {"key": TK, "value": TV}})
    check(code == 400 and len(calls) == n, "scoped write without confirm=true is refused")
    o, code = api.tag({"confirm": "true", "check_id": pick, "owner": "x", "tag_scope": {"key": TK, "value": TV}})
    check(code == 400 and len(calls) == n, "confirm must be JSON true")
    only_out = next((cid for cid in {x["check_id"] for x in ROWS}
                     if {x["asset_uuid"] for x in ROWS if x["check_id"] == cid and up(x["status"]).startswith("FAIL")}
                     and not ({x["asset_uuid"] for x in ROWS if x["check_id"] == cid and up(x["status"]).startswith("FAIL")} & TAGGED)), None)
    if only_out:
        o, code = api.tag({"confirm": True, "check_id": only_out, "owner": "x", "tag_scope": {"key": TK, "value": TV}})
        check(code == 400 and len(calls) == n and TK in o["error"], "a control with no failing tagged asset tags nothing")
    ct = comp.control_targets(check_id=pick, scope=(TK, TV))
    check(ct["query"] == "", "a scoped control target carries no estate-wide navi query")
    check(comp.control_targets(check_id=pick)["query"] == comp.control_query(pick), "estate control target query unchanged")
finally:
    navi_cli.tag_set = real_tag_set

# ── 6. caches keep scope and estate apart ────────────────────────────────────
check(api._agent().result == ESTATE_RESULT == base, "a scoped run never replaces the agent's estate result (status card)")
check(api._agent().summary()["assets"] == base["assets"], "the status-card summary stays the estate's")
d1, _ = launcher.dispatch("compliance", "overview", {})
d2, _ = launcher.dispatch("compliance", "overview", {"tag_scope": {"key": TK, "value": TV}})
d3, _ = launcher.dispatch("compliance", "overview", {})
check(d1["result"]["assets"] == d3["result"]["assets"] == base["assets"], "launcher: estate overview stays the estate's after a scoped one")
check(d2["result"]["assets"] == NT and d2["result"]["scope"]["key"] == TK, "launcher: scoped overview is the tag's")
other = next(((k, v) for (k, v, n) in [(TK, "Staging", 0), ("Owner", "VM Team", 0), ("Environment", "Cloud", 0)]
              if (k, v) != (TK, TV) and tagscope.count(k, v)), None)
if other:
    d4, _ = launcher.dispatch("compliance", "overview", {"tag_scope": {"key": other[0], "value": other[1]}})
    check(d4["result"]["scope"]["key"] == other[0] and d4["result"]["scope"]["value"] == other[1]
          and d4["result"] != d2["result"], "two tags get two different results")
o, code = launcher.dispatch("compliance", "framework", {"framework": "800-53", "tag_scope": {"key": TK, "value": TV}})
check(code == 400, "launcher refuses a scope on the undeclared framework action")

print("\n" + ("ALL PASS" if not fails else f"{len(fails)} FAILURE(S)"))
sys.exit(1 if fails else 0)
