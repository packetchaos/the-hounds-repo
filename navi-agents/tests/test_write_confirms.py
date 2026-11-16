"""Regression tests for the platform rule "every write asks first": each page that posts
confirm:true shows a browser confirm() naming the exact tag (tagCat → the test-run name) and
how many assets / selectors, plus the gated note when NAVI_ALLOW_WRITES is off — and no page
asks only when writes are gated (that skipped the question once writes were on). Also checks
the read-only helpers the dialogs use: Path/Route Explorer `count` and the Compliance
Dashboard's per-control failing-asset count. Static source checks + a tiny synthetic navi.db.
Run: python3 tests/test_write_confirms.py  (or pytest)."""
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
TMP = tempfile.mkdtemp(prefix="hounds-confirms-")
atexit.register(shutil.rmtree, TMP, ignore_errors=True)
os.environ.update({"NAVI_CACHE_DIR": os.path.join(TMP, "cache"), "HOUNDS_CONFIG": os.path.join(TMP, "cfg.json"),
                   "NAVI_HISTORY_DIR": os.path.join(TMP, "hist"), "NAVI_TAGLOG_DB": os.path.join(TMP, "taglog.db")})
for k in ("NAVI_TAG_TEST_RUN", "NAVI_TAG_PREFIX", "NAVI_ALLOW_WRITES", "NAVI_MCP_ALLOW_WRITES"):
    os.environ.pop(k, None)
DB = os.path.join(TMP, "navi.db")
os.environ["NAVI_DB_PATH"] = DB

fails = []


def check(cond, msg):
    print(("ok   " if cond else "FAIL ") + msg)
    if not cond:
        fails.append(msg)


def src(rel):
    with open(os.path.join(ROOT, rel), encoding="utf-8") as f:
        return f.read()


GATED = "Writes are gated (NAVI_ALLOW_WRITES not set) — the job queues but is blocked."

# ---- the 11 pages the consistency pass flagged: a confirm() naming the tag via tagCat ----
PAGES = {
    "agents/compliance/page.html": ["tagCat('Audit Owner')"],
    "agents/compliance_asset/page.html": ["tagCat('Audit-Vuln Link')"],
    "agents/was/page.html": ["tagCat(c.category", "Email the WAS Overview"],
    "agents/ex_paths/page.html": ["tagCat('Path')", "API.post('count'"],
    "agents/ex_routes/page.html": ["tagCat('Route')", "API.post('count'"],
    "agents/software/page.html": ["tagCat(category)"],
    "agents/customapp/page.html": ["tagCat('Custom App')"],
    "agents/mitre/page.html": ["tagCat(a.category)"],
    "agents/exproute/page.html": ["tagCat('Owner')"],
    "web/ownermap.html": ["tagCat('Owner')", "Email the '+_graphTitle()"],
    "web/compliancedash.html": ["tagCat('Audit Owner')"],
}
for rel, needles in PAGES.items():
    s = src(rel)
    check("confirm(" in s and all(n in s for n in needles), f"{rel}: confirm() names the tag ({', '.join(needles)})")
    check(GATED in s or "Email is gated" in s, f"{rel}: the gated note is in the confirm text")

# ---- the console-wide sweep: no page confirms ONLY when writes are gated ----
import glob  # noqa: E402
pages = glob.glob(os.path.join(ROOT, "agents", "*", "page.html")) + glob.glob(os.path.join(ROOT, "web", "*.html"))
gated_only = []
for p in pages:
    s = open(p, encoding="utf-8").read()
    if os.path.basename(os.path.dirname(p)) == "tagremoval":      # Garmr's removal flow is untouched
        continue
    if re.search(r"if\(\s*!\s*WRITES\s*&&\s*!\s*confirm\(", s):     # fused_score's `!asked && !WRITES` is behind its own confirm
        gated_only.append(os.path.relpath(p, ROOT))
check(not gated_only, "no write path asks only when writes are gated: " + (", ".join(gated_only) or "none"))

# every file that posts confirm:true also calls confirm() (c2's arm box + the browser confirm included)
missing = []
for p in pages:
    s = open(p, encoding="utf-8").read()
    if re.search(r"confirm\s*:\s*true", s) and "confirm(" not in s:
        missing.append(os.path.relpath(p, ROOT))
check(not missing, "every page that posts confirm:true has a confirm(): " + (", ".join(missing) or "all"))

# the shared gated() helpers now always ask, with a caller-supplied plain-text question
for rel in ("agents/ai/page.html", "agents/attackpath/page.html", "agents/certificate/page.html",
            "agents/cisakev/page.html", "agents/eol/page.html", "agents/postquantum/page.html",
            "agents/scan_eval/page.html"):
    s = src(rel)
    check(re.search(r"async function gated\([^)]*ask\)", s) and "if(!confirm((typeof ask==='function'?ask():ask)" in s,
          f"{rel}: gated() always asks (ask text + gated note)")

# ---- read-only helpers behind the dialog counts ----
c = sqlite3.connect(DB)
c.executescript("""CREATE TABLE vuln_paths (path_id INTEGER PRIMARY KEY, plugin_id TEXT, path TEXT, asset_uuid TEXT, finding_id TEXT);
CREATE TABLE vuln_route (route_id INTEGER PRIMARY KEY, app_name TEXT, plugin_list TEXT, total_vulns INTEGER, vuln_type TEXT);
CREATE TABLE vulns (asset_uuid TEXT, plugin_id TEXT, plugin_name TEXT, severity TEXT);
CREATE TABLE compliance (asset_uuid TEXT, check_id TEXT, check_name TEXT, status TEXT, reference TEXT, audit_file TEXT,
  solution TEXT, info TEXT, see_also TEXT, actual_value TEXT, expected_value TEXT, check_info TEXT);""")
c.executemany("INSERT INTO vuln_paths(plugin_id,path,asset_uuid) VALUES (?,?,?)",
              [("1", "/opt/x", "a1"), ("1", "/opt/x", "a1"), ("2", "/opt/x", "a2"), ("3", "/opt/y", "a3")])
c.execute("INSERT INTO vuln_route VALUES (7,'NGINX',\"['51192', '35291']\",3,'Web')")
c.executemany("INSERT INTO vulns VALUES (?,?,?,?)",
              [("a1", "51192", "x", "High"), ("a2", "35291", "y", "High"), ("a2", "51192", "x", "High"), ("a9", "99", "z", "Low")])
R = "[{'framework': '800-53', 'control': 'CM-7'}]"
c.executemany("INSERT INTO compliance(asset_uuid,check_id,check_name,status,reference,audit_file) VALUES (?,?,?,?,?,?)",
              [("a1", "c1", "FW", "FAILED", R, "A"), ("a1", "c1", "FW", "FAILED", R, "A"),
               ("a2", "c1", "FW", "FAILED", R, "A"), ("a3", "c1", "FW", "PASSED", R, "A")])
c.commit(); c.close()

from agents.ex_paths import api as xp  # noqa: E402
from agents.ex_routes import api as xr  # noqa: E402
o, _ = xp.count({"path": "/opt/x"})
check(o.get("ok") and o.get("assets") == 2, "Path Explorer count: distinct assets on a path (2)")
o, code = xp.count({})
check(code == 400, "Path Explorer count: path required")
o, _ = xr.count({"route_id": 7})
check(o.get("ok") and o.get("assets") == 2 and o.get("plugins") == 2, "Route Explorer count: distinct assets carrying the route's plugins (2)")
check("count" in xp.ACTIONS and "count" in xr.ACTIONS, "count is exposed as an action on both explorers")

from core import compliance as comp  # noqa: E402
fw = comp.framework_view("800-53", DB)
tf = (fw or {}).get("top_failing") or []
c1 = next((x for x in tf if x.get("check_id") == "c1"), {})
check(c1.get("failed") == 3 and c1.get("failed_assets") == 2 and c1.get("assets") == 3,
      "Compliance Dashboard: a control carries failed_assets (distinct failing assets = what the tag hits)")

print("\n%d failure(s)" % len(fails))
if fails:
    sys.exit(1)
