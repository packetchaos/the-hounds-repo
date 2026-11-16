"""Regression tests — pre-release back-end bug sweep.

  1. swsearch.vcmp: '2.0.0rc1' < '2.0' (zeros before a pre-release tail are padding).
  2. Software Explorer: an asset's installs are not cut to 20 in the export / KPI (only the page
     row is trimmed), and a version range does not change the install count.
  3. Compliance Explorer: the detail pane's Info reads navi's `check_info`; the framework
     filter matches navi's leading-space frameworks (' 800-53') the facet list trims; a bad
     offset doesn't 500.
  4. Explore run_sql: a string literal with 'update' / 'limit' / ';' is not read as a keyword;
     rows are capped at 500 whatever LIMIT the SQL carries; secrets / 2 statements still refused.
  5. Explore vuln: bounded (count + first N rows, trimmed output).
  6. launcher._invalidate / eviction survive other threads writing the result cache.
  7. navi's " " placeholder (→ None in dict rows) in vuln_route.app_name / vuln_paths.path
     doesn't crash Custom App or Ownership (exproute); "None" text ACR doesn't crash classify.
Run: python3 tests/test_review_bugs.py"""
import atexit
import os
import shutil
import sqlite3
import sys
import tempfile
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
TMP = tempfile.mkdtemp(prefix="hounds-review-")
atexit.register(shutil.rmtree, TMP, ignore_errors=True)
DB = os.path.join(TMP, "navi.db")
os.environ.update({"NAVI_DB_PATH": DB, "NAVI_CACHE_DIR": os.path.join(TMP, "cache"),
                   "HOUNDS_CONFIG": os.path.join(TMP, "cfg.json"), "NAVI_TAGLOG_DB": os.path.join(TMP, "t.db")})
os.environ.pop("ANTHROPIC_API_KEY", None)
fails = []


def check(cond, msg):
    print(("PASS " if cond else "FAIL ") + msg)
    if not cond:
        fails.append(msg)


shutil.copy(os.path.join(ROOT, "sample_navi.db"), DB)
c = sqlite3.connect(DB)
U = c.execute("SELECT uuid FROM assets ORDER BY uuid LIMIT 1").fetchone()[0]
for i in range(30):
    c.execute("INSERT INTO software VALUES (?, ?)", (U, "revpkg%d-1.%d.0" % (i, i)))
c.execute("INSERT INTO software VALUES (?, ?)", (U, "revssl-3.0.2"))
c.execute("INSERT INTO software VALUES (?, ?)", (U, "revssl-3.0.2-0ubuntu1"))
# compliance: navi's check_info column only, and a leading-space framework
c.execute("UPDATE compliance SET info=NULL")
c.execute("UPDATE compliance SET check_info='review-info-text'")
n800 = c.execute("SELECT COUNT(*) FROM compliance WHERE reference LIKE '%''framework'': ''800-53''%'").fetchone()[0]
c.execute("UPDATE compliance SET reference=replace(reference, '''framework'': ''800-53''', "
          "'''framework'': '' 800-53''') WHERE rowid IN (SELECT rowid FROM compliance "
          "WHERE reference LIKE '%''framework'': ''800-53''%' LIMIT 5)")
# navi placeholders
c.execute("UPDATE vuln_route SET app_name=' ' WHERE rowid=(SELECT MIN(rowid) FROM vuln_route)")
c.execute("UPDATE vuln_paths SET path=' ' WHERE rowid=(SELECT MIN(rowid) FROM vuln_paths)")
c.execute("UPDATE assets SET acr='None' WHERE rowid % 3 = 0")
c.commit()
c.close()

from core import db, launcher, swsearch  # noqa: E402

# 1 ── version compare
check(swsearch.vcmp("2.0.0rc1", "2.0") == -1 and swsearch.vcmp("2.0", "2.0.0rc1") == 1,
      "vcmp: 2.0.0rc1 < 2.0")
check(swsearch.vcmp("2.0", "2.0.0") == 0 and swsearch.vcmp("2.0", "2.0.0.1") == -1
      and swsearch.vcmp("1.0.2", "1.0.2a") == -1, "vcmp: zero padding / letter tails unchanged")
check(swsearch.in_ranges("2.0.0rc1", swsearch.parse_ranges("<2.0")), "2.0.0rc1 is inside <2.0")

# 2 ── Software Explorer installs
r = swsearch.search(q="revpkg")
row = r["rows"][0]
check(row["ninstalls"] == 30 and len(row["installs"]) == 30 and r["kpi"]["installs"] == 30,
      "swsearch keeps every install (KPI installs = 30)")
o, _ = launcher.dispatch("ex_software", "search", {"q": "revpkg"})
check(len(o["result"]["rows"][0]["installs"]) == 20 and o["result"]["rows"][0]["ninstalls"] == 30,
      "the page row is trimmed to 20 installs (ninstalls says 30)")
o, _ = launcher.dispatch("ex_software", "export", {"q": "revpkg"})
check(o["rows"] == 30 and o["csv"].count("revpkg") == 30, "export writes all 30 installs")
k0 = swsearch.search(q="revssl")["kpi"]["installs"]
k1 = swsearch.search(q="revssl", ranges=swsearch.parse_ranges("<3.0.7"))["kpi"]["installs"]
check(k0 == k1 == 1, "a range doesn't change the install count (%s / %s)" % (k0, k1))

# 3 ── Compliance Explorer
o, code = launcher.dispatch("ex_compliance", "search", {"limit": 3})
check(code == 200 and o["result"]["rows"] and o["result"]["rows"][0]["info"] == "review-info-text",
      "Compliance Explorer Info reads check_info")
o, _ = launcher.dispatch("ex_compliance", "search", {"framework": "800-53"})
check(o["result"]["kpi"]["results"] == n800,
      "framework filter counts leading-space ' 800-53' rows (%s / %s)" % (o["result"]["kpi"]["results"], n800))
o, code = launcher.dispatch("ex_compliance", "search", {"offset": "x"})
check(code == 200 and o.get("ok"), "a non-numeric offset doesn't 500")

# 4 ── Explore run_sql
o, _ = launcher.dispatch("explore", "run_sql",
                         {"sql": "SELECT plugin_name FROM vulns WHERE plugin_name LIKE '%update%'"})
check(o.get("ok") is True, "LIKE '%update%' is not refused as a write")
o, _ = launcher.dispatch("explore", "run_sql", {"sql": "SELECT 'a;b' AS x"})
check(o.get("ok") is True and o["rows"][0]["x"] == "a;b", "a ';' inside a literal is one statement")
o, _ = launcher.dispatch("explore", "run_sql",
                         {"sql": "SELECT * FROM (SELECT a.uuid FROM assets a, vulns v LIMIT 3000) x"})
check(o.get("ok") and o["count"] == 500 and o["truncated"] is True, "run_sql caps rows at 500 (sub-query LIMIT)")
o, _ = launcher.dispatch("explore", "run_sql",
                         {"sql": "SELECT plugin_id FROM vulns, assets WHERE plugin_name NOT LIKE '%limit%'"})
check(o.get("ok") and o["count"] <= 500, "'limit' in a literal still gets the LIMIT")
o, _ = launcher.dispatch("explore", "run_sql", {"sql": "SELECT * FROM keys"})
check(o.get("ok") is False, "secret tables stay unreadable")
o, _ = launcher.dispatch("explore", "run_sql", {"sql": "SELECT 1; DELETE FROM assets"})
check(o.get("ok") is False, "two statements are refused")

# 5 ── Explore vuln bounded
import agents.explore.api as ex  # noqa: E402
pid = db.scalar("SELECT plugin_id FROM vulns GROUP BY plugin_id ORDER BY COUNT(*) DESC LIMIT 1")
full = db.scalar("SELECT COUNT(*) FROM vulns WHERE plugin_id=?", (pid,))
keep = ex._VULN_ROWS
ex._VULN_ROWS = 1
try:
    o, _ = launcher.dispatch("explore", "vuln", {"plugin": pid})
finally:
    ex._VULN_ROWS = keep
check(o["count"] == full and len(o["assets"]) == 1 and o["truncated"] == (full > 1),
      "explore vuln returns the count + a bounded page (%s of %s)" % (len(o["assets"]), full))

# 6 ── result cache under concurrent writers
errs, stop = [], [False]


def inval():
    while not stop[0]:
        try:
            launcher._invalidate("x")
        except Exception as e:
            errs.append(repr(e))
            return


def writer():
    i = 0
    while not stop[0]:
        i += 1
        launcher._CACHE["y|%d" % i] = (i, None)
        if len(launcher._CACHE) > 300:
            launcher._CACHE.pop(next(iter(list(launcher._CACHE))), None)


old_si = sys.getswitchinterval()
sys.setswitchinterval(1e-6)
ts = [threading.Thread(target=inval), threading.Thread(target=writer)]
[t.start() for t in ts]
time.sleep(1.5)
stop[0] = True
[t.join() for t in ts]
sys.setswitchinterval(old_si)
launcher._CACHE.clear()
check(not errs, "_invalidate survives concurrent cache writes %s" % errs[:1])

# 7 ── placeholders
o, code = launcher.dispatch("customapp", "run", {"_nocache": True})
check(code == 200 and o.get("ok") is not False, "Custom App: a ' ' route name doesn't crash (%s)" % code)
o, code = launcher.dispatch("exproute", "map", {"_nocache": True})
check(code == 200, "Ownership map: ' ' route name / path don't crash (%s %s)" % (code, str(o)[:120]))
from core import classify  # noqa: E402
res = classify.classify(glance=True)
check(res.get("ok") is True and "glance" in res, "classify: ACR text 'None' doesn't crash the glance")

# 8 ── classify tags a cohort over assets.uuid (an asset with no findings is not dropped)
from core import navi_cli  # noqa: E402
import agents.classify.api as capi  # noqa: E402
seen = {}
_orig = navi_cli.tag_set


def _cap(category, value, uuids=None, **kw):
    seen.update(kw, uuids=list(uuids or []))
    return [{"ok": True, "queued": True, "job_id": 1}]


navi_cli.tag_set = _cap
try:
    capi.tag({"confirm": True, "facet": "Class", "value": "Cloud", "uuids": [U]})
finally:
    navi_cli.tag_set = _orig
check(seen.get("uuids") == [U] and seen.get("table", "assets") == "assets",
      "classify tag pages over assets.uuid, not vulns.asset_uuid (%s)" % seen.get("table", "assets"))

# 9 ── Alert Raven 'last N days' reads its UTC stamps as UTC
from core import alerts  # noqa: E402
os.environ["TZ"] = "America/Phoenix"
if hasattr(time, "tzset"):
    time.tzset()
iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - 86400 - 3 * 3600))
check(alerts._within_days(iso, 1) is False, "an alert 1 day 3 h old is not 'within 1 day' (UTC-7)")
iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - 86400 + 3600))
check(alerts._within_days(iso, 1) is True, "an alert 23 h old is within 1 day")

print("\n%s" % ("ALL PASS" if not fails else "%d FAILED" % len(fails)))
sys.exit(1 if fails else 0)
