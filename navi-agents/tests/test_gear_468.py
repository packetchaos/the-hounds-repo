"""Regression tests — build 468: the ⚙ settings gear in the header bar.

/api/hub/config_status → red "Key configurations required" (navi.db unreadable / no assets / no
findings), amber "Optional configurations missing" (certs, software, routes / paths, WAS,
compliance, SLA, Fixed, EPSS, ⚡ Optimize, AI model), purple-lit "All set". The gear sits at the
right end of every page's header, after "📧 Email dashboard", and opens Settings.
Run: python3 tests/test_gear_468.py"""
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
_TMP = tempfile.mkdtemp(prefix="hounds-468-")
os.environ["NAVI_CACHE_DIR"] = os.path.join(_TMP, "cache")
# a readable navi.db of our own (the sample) — the red "navi.db can't be read" check must not
# depend on whatever navi.db this machine has configured
import shutil  # noqa: E402
shutil.copy(os.path.join(ROOT, "sample_navi.db"), os.path.join(_TMP, "navi.db"))
os.environ["NAVI_DB_PATH"] = os.path.join(_TMP, "navi.db")
fails = []


def check(cond, msg):
    print(("PASS " if cond else "FAIL ") + msg)
    if not cond:
        fails.append(msg)


from agents.hub import api as hub  # noqa: E402
from core import llm, release  # noqa: E402
import core.hx_optimize as hxo  # noqa: E402

ALL = {"vulns", "assets", "certs", "software", "vuln_route", "vuln_paths", "apps", "compliance", "sla", "fixed", "epss"}
orig = (release._has_rows, llm.available, hxo.status)
hxo.status = lambda: {"optimized": True, "summary": {"applies": True, "fresh": True}}
try:
    llm.available = lambda: True
    release._has_rows = lambda t, db_path=None: t in ALL
    o, _ = hub.config_status({})
    check(o["level"] == "ok" and o["title"] == "All set" and not o["items"], "everything present → All set")
    release._has_rows = lambda t, db_path=None: t in ALL - {"apps", "sla"}
    o, _ = hub.config_status({})
    check(o["level"] == "amber" and o["title"] == "Optional configurations missing"
          and {i["label"] for i in o["items"]} == {"Web Application Scanning (WAS)", "SLA policy"},
          "no WAS / SLA → amber, listing them")
    llm.available = lambda: False
    o, _ = hub.config_status({})
    check(o["level"] == "amber" and any(i["label"] == "AI model" for i in o["items"]), "no AI model → amber")
    hxo.status = lambda: {"optimized": False, "missing": 3, "summary": {}}
    o, _ = hub.config_status({})
    check(any(i["label"].startswith("Hounds indexes") and i["href"].endswith("#secHx") for i in o["items"]),
          "⚡ Optimize not run → amber, linking to its Settings card")
    release._has_rows = lambda t, db_path=None: t in ALL - {"vulns"}
    o, _ = hub.config_status({})
    check(o["level"] == "red" and o["title"] == "Key configurations required"
          and any(i["level"] == "red" and i["label"] == "Findings (vulns)" for i in o["items"]),
          "no findings → red: Key configurations required")
    check(sum(1 for i in o["items"] if i["label"].startswith("Routes")) <= 1, "each check listed once")
finally:
    release._has_rows, llm.available, hxo.status = orig

js = open(os.path.join(ROOT, "web", "assets", "console.js"), encoding="utf-8").read()
check("function mountSettingsGear(" in js and "/api/hub/config_status" in js and "href='/web/settings.html'" in js,
      "console.js mounts the gear on every page (status from config_status, opens Settings)")
check(".hgear.lvl-red i{background:#e5484d" in js and ".hgear.lvl-amber i{background:#f0a020" in js
      and ".hgear.lvl-ok i{background:#8b5cf6" in js, "light: red / amber / purple (fixed colours — the theme's --amber isn't amber)")
check("if(mode==='dashboard') _gearLast();" in js and "mountSettingsGear();                           // innerHTML" in js,
      "the gear stays right of 'Email dashboard' (and survives the header rebuild)")
print("\n%d failure(s)" % len(fails))
sys.exit(1 if fails else 0)
