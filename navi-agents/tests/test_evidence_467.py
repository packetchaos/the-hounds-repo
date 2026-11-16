"""Regression tests — build 467: At a glance opens the EVIDENCE, not just the hound.

Every On the Scent glance card links to the assets behind its number: an Asset Explorer evidence
list (core/evidence — computed by the hound that owns the number, so its count = the card's), or
the owning hound opened on its own filter (?view= / ?cls= / ?scope=). Run on the sample navi.db.
Run: python3 tests/test_evidence_467.py"""
import atexit
import json
import os
import re
import shutil
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
TMP = tempfile.mkdtemp(prefix="hounds-467-")
atexit.register(shutil.rmtree, TMP, ignore_errors=True)
SAMPLE = os.environ.get("HOUNDS_SAMPLE_DB") or os.path.join(ROOT, "sample_navi.db")
os.environ.update({"NAVI_CACHE_DIR": os.path.join(TMP, "cache"), "HOUNDS_CONFIG": os.path.join(TMP, "cfg.json"),
                   "NAVI_TAGLOG_DB": os.path.join(TMP, "t.db")})
if os.path.exists(SAMPLE):
    shutil.copy(SAMPLE, os.path.join(TMP, "navi.db"))
    os.environ["NAVI_DB_PATH"] = os.path.join(TMP, "navi.db")
fails = []


def check(cond, msg):
    print(("PASS " if cond else "FAIL ") + msg)
    if not cond:
        fails.append(msg)


from core import evidence, fused_score  # noqa: E402
from agents.cisakev.agent import summary as kev_summary  # noqa: E402

if os.environ.get("NAVI_DB_PATH"):
    k = fused_score.overview()["kpi"]
    want = {"kev": kev_summary()["kev_assets"], "score60": k["high"], "crown": k["crown"], "crown_kev": k["crown_kev"],
            "crown_blind": k["crown_blind"], "lit4": sum((k.get("stack") or [])[4:])}
    from core import eol
    from agents.postquantum.agent import discover
    want["eol"] = eol.analyze()["metrics"]["eol_assets"]
    want["pq"] = discover()["assets"]
    got = {key: len(evidence.uuids(key)) for key in evidence.EVIDENCE}
    check(got == want, "every evidence list has its card's count (%s)" % got)

    from agents.ex_assets import api as ex
    o, st = ex.evidence({"key": "eol"})
    check(st == 200 and o["evidence"]["count"] == want["eol"] and o["drill"]["run"] and len(json.dumps(o)) < 200000,
          "Asset Explorer evidence: stored run + page 1 (%d assets)" % o["evidence"]["count"])
    d, _ = ex.drill({"run": o["drill"]["run"], "section": "assets", "limit": 500})
    check(d["total"]["value"] == want["eol"] and len({r["uuid"] for r in d["top"]}) == min(500, want["eol"]),
          "evidence pages on the server — every asset reachable")
    acrs = [float(r.get("acr") or 0) for r in d["top"]]
    check(acrs == sorted(acrs, reverse=True), "riskiest (highest ACR) first")
    e, _ = ex.export({"run": o["drill"]["run"]})
    check(e["ok"] and e["rows"] == want["eol"], "CSV export: every asset of the list")
    b, st = ex.evidence({"key": "DROP"})
    check(st == 400, "unknown evidence key → 400")
else:
    print("SKIP sample navi.db not found — count checks skipped")

# ── On the Scent's cards link to evidence ─────────────────────────────────────────────────────
ins = open(os.path.join(ROOT, "core", "insights.py"), encoding="utf-8").read()
g = ins[ins.index("    glance = ["):ins.index("    # ---- how exposed")]
for key in ("score60", "kev", "crown", "eol", "pq", "crown_kev", "crown_blind", "lit4"):
    check('_EV("%s")' % key in g, "card → Asset Explorer evidence %s" % key)
check('_V("certificate", "view", "expired"' in g and '_V("scan_eval", "view", "blind"' in g
      and '_V("classify", "cls", "Unclassified")' in g and '_V("asset_ownership", "scope", "unclaimed")' in g,
      "cards whose hound filters its own table open the hound on that filter")
check('"#secConverge"' not in g and '_P("acr")' not in g, "no glance card just opens a hound (or a section) any more")
js = open(os.path.join(ROOT, "web", "assets", "console.js"), encoding="utf-8").read()
check("function hViewOnce(" in js and "function _hViewHint(" in js, "console.js: hViewOnce + the '▶ Run to see it' note")
for page, needle in (("certificate", "hViewOnce('view'"), ("scan_eval", "hViewOnce('view'"),
                     ("classify", "hViewOnce('cls'"), ("asset_ownership", "hViewOnce('scope'")):
    src = open(os.path.join(ROOT, "agents", page, "page.html"), encoding="utf-8").read()
    check(needle in src, "%s applies its evidence filter once its data is on screen" % page)
cp = open(os.path.join(ROOT, "agents", "certificate", "page.html"), encoding="utf-8").read()
check("expired:['Expired (any date)']" in cp, "Certificates: an 'expired (any date)' filter (the card's set)")
ex_html = open(os.path.join(ROOT, "agents", "ex_assets", "page.html"), encoding="utf-8").read()
check("get('evidence')" in ex_html and "API.post('evidence',{key, _run:true})" in ex_html and "hDrill(" in ex_html,
      "Asset Explorer: ?evidence=<key> builds the list as a run and pages it on the server")
print("\n%d failure(s)" % len(fails))
sys.exit(1 if fails else 0)
