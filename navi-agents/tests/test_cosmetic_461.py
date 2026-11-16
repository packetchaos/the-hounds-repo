"""Regression tests — build 461 cosmetic batch.

MITRE glance speaks ATT&CK (not tagging) · Release the Hounds runs all four Software widgets
(inventory → lifecycle → crown jewels → risk) with the bodies the page sends · the lifecycle
verdicts mirror the page's eolCycleFor / eolIsDead · Attack Paths' Fix first hands a Patch to C2 ·
AI: MITRE ATLAS right under At a glance · On the Scent: What to do next, On the clock (own
widget) and the projected reduction (Nemesis's recommended play, same numbers as Exposure Score)
directly under At a glance. Run: python3 tests/test_cosmetic_461.py"""
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
TMP = tempfile.mkdtemp(prefix="hounds-461-")
atexit.register(shutil.rmtree, TMP, ignore_errors=True)
os.environ.update({"NAVI_CACHE_DIR": os.path.join(TMP, "cache"), "HOUNDS_CONFIG": os.path.join(TMP, "cfg.json"),
                   "NAVI_TAGLOG_DB": os.path.join(TMP, "taglog.db"), "NAVI_HISTORY_DIR": os.path.join(TMP, "hist")})

fails = []


def check(cond, msg):
    print(("PASS " if cond else "FAIL ") + msg)
    if not cond:
        fails.append(msg)


def page(p):
    return open(os.path.join(ROOT, p), encoding="utf-8").read()


# ── MITRE glance ──────────────────────────────────────────────────────────────────────────────
m = page("agents/mitre/page.html")
g = m[m.index("renderGlance('glxMitre'"):m.index("], {active:FILTER.role")]
check("assets with ATT&CK techniques or impacts" in g and "title:'ATT&CK exposure'" in g,
      "MITRE glance: the hero is assets with ATT&CK techniques or impacts")
check("assets to tag" not in g and "'Tag plan'" not in g and "By tag type" not in g,
      "MITRE glance: no tagging language in the headline")

# ── Software: Release runs all four widgets ──────────────────────────────────────────────────
rec = json.load(open(os.path.join(ROOT, "core", "release_recipes.json"), encoding="utf-8"))
sw = [r for r in rec["pages"] if r["agent"] == "software"][0]
check(sw["steps"] == ["swRun", "swEol", "swCrown", "swRisk"] and sw.get("requests_fn") == "agents.software.api:release_requests",
      "Release recipe: Software replays all four widget buttons and builds its requests")
from agents.software import api as swapi  # noqa: E402
cy = [{"cycle": "3.0", "eol": "2099-01-01", "latest": "3.0.9"}, {"cycle": "1.1", "eol": "2020-01-01"},
      {"cycle": "2", "eol": True}, {"cycle": "11", "eol": False}]
check(swapi._cycle_for("1.1.1w", cy)["cycle"] == "1.1" and swapi._cycle_for("2.4", cy)["cycle"] == "2"
      and swapi._cycle_for("110", cy) is None and swapi._cycle_for("11", cy)["cycle"] == "11",
      "lifecycle: cycle match mirrors the page (prefix + '.', or a non-digit next char)")
check(swapi._is_dead(cy[1]) is True and swapi._is_dead(cy[0]) is False and swapi._is_dead(cy[2]) is True
      and swapi._is_dead(cy[3]) is False and swapi._is_dead({"eol": "soon"}) is None,
      "lifecycle: EOL verdicts mirror the page (true/false/date/unknown)")
orig = swapi._eol_cycles
swapi._eol_cycles = lambda slug: cy if slug == "openssl" else None
try:
    res = swapi.lifecycle_results([{"name": "openssl", "slug": "openssl", "versions": ["1.1.1w", "3.0.2"]},
                                   {"name": "nope", "slug": "nope", "versions": ["1"]}])
finally:
    swapi._eol_cycles = orig
check(res == [{"name": "openssl", "slug": "openssl", "latest": "3.0.9", "eolVers": ["1.1.1w"]},
              {"name": "nope", "slug": "nope", "noData": True}],
      "lifecycle results have the page's exact shape (same request → same cache key)")
calls = []


def fake(agent, action, body):
    calls.append((action, dict(body)))
    if action == "inventory":
        return {"ok": True, "drill": {"run": "software-1"}}, 200
    if action == "eol_plan":
        return ({"ok": True, "plan": [{"name": "p%d" % body["start"], "slug": "x", "vers": "1\n2"}],
                 "next_start": (body["start"] + 1) if body["start"] < 2 else None}, 200)
    return {"ok": True}, 200


swapi._eol_cycles = lambda slug: None
try:
    out = swapi.release_requests(fake)
finally:
    swapi._eol_cycles = orig
acts = [a for a, _b, _o in out]
check(acts == ["inventory", "eol_plan", "eol_plan", "eol_plan", "lifecycle", "crown", "risk"],
      "release_requests: inventory → paged eol_plan → lifecycle → crown → risk (%s)" % acts)
check(all(b.get("run") == "software-1" for a, b, _o in out if a != "inventory")
      and [b["start"] for a, b, _o in out if a == "eol_plan"] == [0, 1, 2],
      "release_requests: every later request carries the inventory's run id, as the page sends it")
rel = page("core/release.py")
check('r.get("requests_fn")' in rel and "importlib.import_module(mod)" in rel, "Release runs a hound's requests_fn")

# ── Attack Paths: Fix first → C2 ──────────────────────────────────────────────────────────────
ap = page("agents/attackpath/page.html")
check("function patchLink(x)" in ap and "c2Link('remediate',{plugin_id:pid,targets,source:'Attack Paths'}" in ap
      and ap.count("${typeCell(x)}") == 2, "Attack Paths: a Patch fix (bundle + choke points) hands plugin + hosts to C2")

# ── AI: ATLAS under At a glance ───────────────────────────────────────────────────────────────
ai = page("agents/ai/page.html")
ids = re.findall(r'<section class="card" id="(sec\w+)"', ai)
check(ids[:2] == ["secGlance", "secAtlas"], "AI: MITRE ATLAS sits right under At a glance (%s)" % ids[:3])

# ── On the Scent: order + projected reduction ─────────────────────────────────────────────────
ins = page("agents/insights/page.html")
bh = ins[ins.index("function boardHtml(){"):ins.index("function renderNone(){")]
order = re.findall(r"sec\('(sec\w+)'", bh)
check(order[:4] == ["secGlance", "secNext", "secClock", "secRed"],
      "On the Scent: glance → What to do next → On the clock → the reduction (%s)" % order)
check("On the clock</h3>" not in bh.split("sec('secWhere'")[1].split("sec('secConverge'")[0] and 'id="ladder"' not in bh,
      "On the clock is its own widget; the Atlas ladder widget is replaced")
from core import insights  # noqa: E402
fused = {"kpi": {"act": {"80": {"n": 2}, "60": {"n": 3}}},
         "factors": [{"id": "expl", "label": "Exploitability", "hound": "Laelaps · KEV"},
                     {"id": "eol", "label": "EOL / unsupported", "hound": "Charon"},
                     {"id": "own", "label": "Ownership gap", "hound": "Terminus"},
                     {"id": "crit", "label": "Business criticality", "hound": "Anubis · ACR"}],
         "assets": [
             {"score": 90, "factors": {"expl": 20, "eol": 5, "crit": 8, "own": 3}, "applies": {"patch": True, "eol": True, "own": True}},
             {"score": 85, "factors": {"expl": 15, "crit": 8}, "applies": {"patch": False}, "disp": "Accepted"},
             {"score": 70, "factors": {"expl": 20}, "applies": {"patch": True}}]}
p = insights.recommended_play(fused)
# by hand (fused page drawRed, all plays on, THR 80): asset1 → crit 8 left → 8; asset2 → no play →
# round(23 × 0.55) = 13; before 90+85 = 175, after 21, −154 (88%), both leave critical (≥80 → <80)
check(p["available"] and p["threshold"] == 80 and p["before"] == 175 and p["after"] == 21 and p["pct"] == 88
      and p["leave_critical"] == 2, "recommended play: the Exposure Score page's numbers (%s)" % {k: p.get(k) for k in ("before", "after", "pct", "leave_critical")})
j = {x["id"]: (x["pts"], x["n"]) for x in p["justify"]}
check(j == {"expl": (20, 1), "eol": (5, 1), "own": (3, 1)} and p["justify"][0]["id"] == "expl",
      "recommended play: justification per cleared signal, largest first")
check(insights.recommended_play({}) == {"available": False}, "no Exposure Score snapshot → not available")
check("renderRed()" in ins and "renderClock()" in ins and "secRed:{" in ins and "secClock:{" in ins,
      "On the Scent renders and exports (CSV / email) both new widgets")

print("\n%d failure(s)" % len(fails))
sys.exit(1 if fails else 0)
