"""Regression tests — build 489: Orthrus (MITRE ATT&CK) by tag.

  · With no tag the plan is byte-for-byte the whole-estate plan (run, apply, the Contract's call).
  · With tag_scope {key, value} the plan covers only that tag's assets: "CVEs in navi.db" are the
    CVEs on the tag's assets, every asset count (per CVE, per role, per technique, assets
    affected) and the ACR > 7 list are over the tag only. Each asset's own values (its ACR, its
    mapped CVEs) are the same as in the whole estate.
  · 🏷️ Tag assets from a tag view never uses navi tag-by-CVE (it would tag the whole estate): the
    server rebuilds the plan over the tag from navi.db and tags only the tag's assets citing the
    CVEs, as UUID pages (navi_cli.tag_set, add-only). A UUID list from the browser is ignored.
  · Every action the page calls is declared in the manifest's tag_scope; the hound keeps no
    result cache of its own (the launcher's read cache keys on the payload, tag_scope included).
  · Both code paths: the plain vulns scan, and the ⚡ Optimize hx_plugin / hx_v_plugin path.
Run: python3 tests/test_scope_mitre_489.py"""
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
TMP = tempfile.mkdtemp(prefix="hounds-489-mitre-")
atexit.register(shutil.rmtree, TMP, ignore_errors=True)
DB = os.path.join(TMP, "navi.db")
DBX = os.path.join(TMP, "navi_hx.db")
shutil.copy(os.path.join(ROOT, "sample_navi.db"), DB)
shutil.copy(os.path.join(ROOT, "sample_navi.db"), DBX)
os.environ.update({"NAVI_DB_PATH": DB, "NAVI_CACHE_DIR": os.path.join(TMP, "cache"),
                   "HOUNDS_CONFIG": os.path.join(TMP, "cfg.json"), "NAVI_TAGLOG_DB": os.path.join(TMP, "t.db")})
os.environ.pop("NAVI_ALLOW_WRITES", None)
fails = []


def check(cond, msg):
    print(("PASS " if cond else "FAIL ") + msg)
    if not cond:
        fails.append(msg)


from core import mitre, navi_cli, tagscope, launcher  # noqa: E402
from agents.mitre import api  # noqa: E402

CVE_RE = re.compile(r"CVE-\d{4}-\d{3,}", re.I)
MAP = {r["cve"] for r in mitre.fetch_mapping(allow_live=False)[0]}


def hand(path, k=None, v=None):
    """Independent count straight from navi.db: CVE → assets (vulns.cves), and ACR per asset."""
    c = sqlite3.connect(path)
    tagged = None
    if k:
        tagged = {r[0] for r in c.execute("SELECT asset_uuid FROM tags WHERE tag_key=? AND tag_value=?", (k, v))}
    ca = {}
    for u, cv in c.execute("SELECT asset_uuid, cves FROM vulns WHERE TRIM(COALESCE(cves,''))<>''"):
        if tagged is not None and u not in tagged:
            continue
        for x in CVE_RE.findall(cv or ""):
            ca.setdefault(x.upper(), set()).add(u)
    acr = {u: a for u, a in c.execute("SELECT uuid, acr FROM assets")}
    c.close()
    return tagged, ca, acr


def pick_tag(path):
    """A tag holding some, but not all, of the ATT&CK-affected assets (falls back to the biggest)."""
    _, ca, _ = hand(path)
    hit = set().union(*[s for c, s in ca.items() if c in MAP]) if ca else set()
    c = sqlite3.connect(path)
    rows = c.execute("SELECT tag_key, tag_value, COUNT(DISTINCT asset_uuid) n FROM tags "
                     "WHERE TRIM(COALESCE(tag_value,''))<>'' GROUP BY 1,2 HAVING n>=3 ORDER BY n DESC").fetchall()
    best = None
    for k, v, n in rows:
        us = {r[0] for r in c.execute("SELECT asset_uuid FROM tags WHERE tag_key=? AND tag_value=?", (k, v))}
        if 0 < len(us & hit) < len(hit):
            best = (k, v)
            break
    c.close()
    return best or (rows[0][0], rows[0][1])


def dumps(x):
    return json.dumps(x, sort_keys=True, default=str)


def suite(path, label):
    print(f"── {label} ──")
    K, V = pick_tag(path)
    tagged, ca_t, acr = hand(path, K, V)
    _, ca_e, _ = hand(path)
    print(f"   scope {K} : {V} ({len(tagged)} assets)")
    for sc in ("navidb", "all"):
        est = mitre.build_plan(path, scope=sc, allow_live=False)
        est2 = mitre.build_plan(path, scope=sc, allow_live=False, tag_key=None, tag_value=None)
        check(dumps(est) == dumps(est2) and "tag_scope" not in est, f"[{sc}] no tag → the whole-estate plan, unchanged")
        t = mitre.build_plan(path, scope=sc, allow_live=False, tag_key=K, tag_value=V)
        check(t.get("tag_scope", {}).get("assets") == len(tagged), f"[{sc}] the plan names its scope")
        if label == "plain vulns scan":
            # hand count: CVEs on the tag's assets, assets per CVE, assets affected
            check(t["navi_cves"] == len(ca_t), f"[{sc}] 'CVEs in navi.db' = CVEs on the tag's assets ({len(ca_t)})")
            m_t = {c for c in ca_t if c in MAP}
            check(t["matched_cves"] == (len(m_t) if sc == "navidb" else est["matched_cves"]),
                  f"[{sc}] matched CVEs counted over the tag")
            aff = set().union(*[ca_t[c] for c in m_t]) if m_t else set()
            check(t["metrics"]["assets_affected"] == len(aff), f"[{sc}] assets affected = hand count over the tag ({len(aff)})")
            check(all(a["assets"] == len(ca_t.get(a["cve"], ())) for a in t["actions"]), f"[{sc}] assets per CVE = hand count over the tag")
            m_e = {c for c in ca_e if c in MAP}
            aff_e = set().union(*[ca_e[c] for c in m_e]) if m_e else set()
            check(est["metrics"]["assets_affected"] == len(aff_e), f"[{sc}] whole estate assets affected = hand count ({len(aff_e)})")
        # each asset's values identical; population is a subset
        E = {a["asset_uuid"]: a for a in est["high_acr"]}
        check(all(a["asset_uuid"] in tagged for a in t["high_acr"]), f"[{sc}] the ACR > 7 list holds only tagged assets")
        check(all(dumps(a) == dumps(E.get(a["asset_uuid"])) for a in t["high_acr"]),
              f"[{sc}] each ACR > 7 asset's ACR and mapped CVEs match the whole estate")
        check({u for u in E if u in tagged} == {a["asset_uuid"] for a in t["high_acr"]},
              f"[{sc}] the tag's ACR > 7 list = the estate list ∩ the tag")
        ea = {(a["cve"], a["value"]): a["assets"] for a in est["actions"]}
        check(all(a["assets"] <= ea.get((a["cve"], a["value"]), 0) for a in t["actions"]),
              f"[{sc}] no CVE has more assets in the tag than in the estate")
        check(t["metrics"]["assets_affected"] <= est["metrics"]["assets_affected"], f"[{sc}] the tag is never bigger than the estate")
    # every per-CVE asset set in the tag = the estate's set ∩ the tag
    full = mitre.cve_assets(path)
    sco = mitre.cve_assets(path, tag_key=K, tag_value=V)
    check(all(sco[c] == (full.get(c, set()) & tagged) for c in sco)
          and all(c in sco for c, s in full.items() if s & tagged), "cve_assets(tag) = cve_assets() ∩ the tag, CVE by CVE")
    check(mitre.cve_assets(path, tag_key="no such", tag_value="x") == {}, "an unknown tag has no CVE assets")
    return K, V, tagged, sco


# ── 1. the plain path ─────────────────────────────────────────────────────────
K, V, TAGGED, SCO = suite(DB, "plain vulns scan")

# ── 2. the ⚡ Optimize (hx) path ──────────────────────────────────────────────
from core import hx_summary  # noqa: E402

wc = sqlite3.connect(DBX, isolation_level=None)
if "state" not in {r[1] for r in wc.execute("PRAGMA table_info(vulns)")}:   # a real navi.db has it
    wc.execute("ALTER TABLE vulns ADD COLUMN state TEXT DEFAULT 'open'")
wc.execute("CREATE INDEX IF NOT EXISTS hx_v_plugin ON vulns(plugin_id, asset_uuid, state, severity)")
wc.execute("CREATE INDEX IF NOT EXISTS hx_v_asset ON vulns(asset_uuid, plugin_id, state, severity)")
built = hx_summary.build(wc)
wc.close()
hx_summary.invalidate()
if built.get("ok") and mitre._hx(DBX):
    suite(DBX, "hx_plugin / hx_v_plugin path")
else:
    check(False, "hx summary tables built for the hx path: %r" % built)

# ── 3. the API: run, scope in the answer ──────────────────────────────────────
o, st = api.run({"scope": "navidb", "csv_text": "", "approved": False})
o0, _ = api.run({"scope": "navidb", "csv_text": "", "approved": False, "tag_scope": None})
check(st == 200 and o["ok"] and "scope" not in o and dumps(o) == dumps(o0), "run: no tag → today's answer")
ref = mitre.build_plan(scope="navidb", allow_live=False)
check(dumps(o["result"]) == dumps(ref), "run: the whole-estate result equals build_plan()")
o, st = api.run({"scope": "navidb", "csv_text": "", "approved": False, "tag_scope": {"key": K, "value": V}})
check(o["ok"] and o["scope"]["label"] == f"{K} : {V}" and o["scope"]["assets"] == len(TAGGED), "run: scoped answer names its scope")
check(dumps(o["result"]) == dumps(mitre.build_plan(scope="navidb", allow_live=False, tag_key=K, tag_value=V)),
      "run: the scoped result is the tag's plan")

# ── 4. the manifest contract ──────────────────────────────────────────────────
man = json.load(open(os.path.join(ROOT, "agents", "mitre", "manifest.json"), encoding="utf-8"))
ts = man.get("tag_scope") or {}
page = open(os.path.join(ROOT, "agents", "mitre", "page.html"), encoding="utf-8").read()
called = set(re.findall(r"API\.post\('([a-z_]+)'", page)) | set(re.findall(r"runAgentJob\('mitre',\s*'([a-z_]+)'", page))
check(called and called <= set(ts.get("actions", [])) | set(ts.get("ignore", [])),
      f"every action the page calls is declared: {sorted(called)}")
check(set(ts.get("actions", [])) == {"run", "apply"} and set(ts.get("ignore", [])) == {"source"},
      "run + apply honour the scope; source (the download note) ignores it")
check(not re.search(r"fetch\(\s*['\"`]/api/mitre", page), "no raw fetch() to /api/mitre (it would bypass the scope)")
check("mountTagScope({agent:'mitre'" in page and page.index("mountTagScope(") > page.index("mountAgentHeader({"),
      "the page mounts the tag filter after its header")
check("tagScopeNote()" in page.split("document.getElementById('apply').onclick")[1].split("API.post('apply'")[0],
      "the 🏷️ Tag assets confirm names the scope")
check("mitreAppr|" in page, "approvals are kept per view (an 'applied' in a tag view is not the estate's)")
tagscope._POLICY.pop("mitre", None)
p = {"tag_scope": {"key": K, "value": V}}
check(tagscope.check("mitre", "source", p) is None and "tag_scope" not in p, "launcher: source drops the scope")
check(tagscope.check("mitre", "run", {"tag_scope": {"key": K, "value": V}}) is None, "launcher: run accepts the scope")
r = tagscope.check("mitre", "nope", {"tag_scope": {"key": K, "value": V}})
check(r and r[1] == 400, "launcher: an undeclared action is refused")

# ── 5. writes: estate via --cve (unchanged), tag view via UUID pages inside the tag ──
CALLS = {"tag": [], "tag_set": []}
real_tag, real_set = navi_cli.tag, navi_cli.tag_set


def fake_tag(category, value, **kw):
    CALLS["tag"].append({"category": category, "value": value, **kw})
    return {"ok": True, "queued": True, "job_id": len(CALLS["tag"])}


def fake_set(category, value, uuids=None, **kw):
    CALLS["tag_set"].append({"category": category, "value": value, "uuids": list(uuids or []), **kw})
    return [{"ok": True, "queued": True, "job_id": 100 + len(CALLS["tag_set"])}]


navi_cli.tag, navi_cli.tag_set = fake_tag, fake_set
try:
    est = mitre.build_plan(scope="navidb", allow_live=False)
    acts = [{"cve": a["cve"], "category": "Mitre", "value": a["value"]} for a in est["actions"] if a["assets"]]
    check(api.apply({"actions": acts})[1] == 400, "apply: confirm is required")
    check(api.apply({"actions": acts, "confirm": "true", "tag_scope": {"key": K, "value": V}})[1] == 400,
          "apply: confirm must be JSON true (a scoped request too)")
    o, st = api.apply({"actions": acts, "confirm": True})
    check(st == 200 and o["ok"] and CALLS["tag"] and not CALLS["tag_set"]
          and all(c.get("cve") and c["remove"] is False and c["category"] == "Mitre" for c in CALLS["tag"]),
          "whole estate apply: unchanged — navi tag-by-CVE, add-only")
    check("scope" not in o, "whole estate apply: no scope in the answer")
    CALLS["tag"].clear()
    evil = [{"cve": a["cve"], "category": "Evil", "value": a["value"], "uuids": ["evil-uuid"]} for a in acts]
    o, st = api.apply({"actions": evil, "confirm": True, "uuids": ["evil-uuid"], "asset_uuids": ["evil-uuid"],
                       "tag_scope": {"key": K, "value": V}})
    sent = set().union(*[set(c["uuids"]) for c in CALLS["tag_set"]]) if CALLS["tag_set"] else set()
    want = {}
    for a in acts:
        if SCO.get(a["cve"]):
            want.setdefault(a["value"], set()).update(SCO[a["cve"]])
    check(not CALLS["tag"], "tag view apply: never calls navi tag-by-CVE (it would tag the whole estate)")
    check(st == 200 and o["ok"] and o["scope"]["label"] == f"{K} : {V}", "tag view apply: answer names its scope")
    check(sent and sent <= TAGGED and "evil-uuid" not in sent, "tag view apply: every UUID sent carries the tag (browser UUIDs ignored)")
    check({c["value"]: set(c["uuids"]) for c in CALLS["tag_set"]} == want,
          "tag view apply: per Mitre value, exactly the tag's assets citing its CVEs (re-read from navi.db)")
    check(all(c["category"] == "Mitre" for c in CALLS["tag_set"]) and o["skipped"] == len(acts) - sum(1 for a in acts if SCO.get(a["cve"])),
          "tag view apply: category is always Mitre; pairs with no assets in the tag are skipped")
    CALLS["tag_set"].clear()
    outside = [a for a in acts if not SCO.get(a["cve"])]
    if outside:
        o, st = api.apply({"actions": outside, "confirm": True, "tag_scope": {"key": K, "value": V}})
        check(st == 400 and not CALLS["tag_set"] and not CALLS["tag"], "tag view apply: CVEs with no tagged assets write nothing")
    o, st = api.apply({"actions": acts, "confirm": True, "tag_scope": {"key": "no such", "value": "x"}})
    check(st == 400 and not CALLS["tag_set"] and not CALLS["tag"], "tag view apply: an unknown tag writes nothing")
finally:
    navi_cli.tag, navi_cli.tag_set = real_tag, real_set
check(not navi_cli.writes_enabled(), "NAVI_ALLOW_WRITES stays unset")

# ── 6. caches: the hound keeps none of its own; the launcher keys on the payload ─
check(set(vars(api)) & {"SNAP", "CACHE", "_CACHE"} == set() and set(api._LAST) == {"csv"},
      "the hound has no result cache of its own (only the uploaded CSV, an input)")
a1, _ = launcher.dispatch("mitre", "run", {"scope": "navidb", "csv_text": "", "approved": False})
a2, _ = launcher.dispatch("mitre", "run", {"scope": "navidb", "csv_text": "", "approved": False, "tag_scope": {"key": K, "value": V}})
a3, _ = launcher.dispatch("mitre", "run", {"scope": "navidb", "csv_text": "", "approved": False})
check(a1.get("ok") and a2.get("ok") and "scope" not in a1 and a2.get("scope", {}).get("label") == f"{K} : {V}",
      "launcher: the estate and the tag answer apart")
check(dumps(a1.get("result")) == dumps(a3.get("result")) and "scope" not in a3, "launcher: the estate answer after a tag run is still the estate's")

print()
if fails:
    print(f"{len(fails)} FAILED")
    sys.exit(1)
print("ALL PASS")
