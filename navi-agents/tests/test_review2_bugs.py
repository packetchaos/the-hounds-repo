"""Regression tests — second pre-release bug sweep (builds 476–478).

  1. The read-only SQL pre-checks (explore / software run_sql, Dashboard builder, Alert Raven)
     accept the replace() FUNCTION that navi's list-shaped software.asset_uuid needs
     (core.software.sw_assets_sql and the model guidance), and still refuse a REPLACE statement.
  2. Alert Raven: a term alert built without a model key (software table present) evaluates to a
     number — it used to answer "metric query must be a read-only SELECT".
  3. Dashboard ▸ "Top 15 software" / "Software footprint" count the assets inside navi's list-shaped
     software.asset_uuid (they showed 1 for every product).
  4. AI Contract: disarm → re-arm within the loop's 5 s poll keeps the autonomous loop running.
Run: python3 tests/test_review2_bugs.py"""
import atexit
import os
import re
import shutil
import sqlite3
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
TMP = tempfile.mkdtemp(prefix="hounds-review2-")
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


# sample_navi.db with its software table rewritten to navi's real shape: ONE row per software
# string, asset_uuid = the Python-list text "['uuid', …]"
shutil.copy(os.path.join(ROOT, "sample_navi.db"), DB)
con = sqlite3.connect(DB)
rows = con.execute("SELECT software_string, asset_uuid FROM software WHERE software_string IS NOT NULL "
                   "AND software_string<>'' AND asset_uuid IS NOT NULL").fetchall()
by = {}
for s, u in rows:
    by.setdefault(s, set()).add(u)
con.execute("DELETE FROM software")
con.executemany("INSERT INTO software(asset_uuid, software_string) VALUES (?,?)",
                [(str(sorted(us)), s) for s, us in by.items()])
con.commit()
con.close()
want_top = max(len(us) for us in by.values())
check(want_top > 1, "fixture: some software string is on more than one asset (%d)" % want_top)

from core import launcher, dashboard, alerts                       # noqa: E402
from core.software import sw_assets_sql                             # noqa: E402
from agents.explore import api as explore_api                       # noqa: E402
from agents.software import api as software_api                     # noqa: E402

# 1 ── pre-checks accept replace() and still refuse REPLACE statements
q = ("SELECT COUNT(DISTINCT j.value) AS n FROM software s, " + sw_assets_sql() + " j")
check(explore_api._safe_select(q)[1] is None, "explore pre-check accepts replace() (software expansion)")
check(software_api._safe_select(q)[1] is None, "software pre-check accepts replace()")
check(dashboard.safe_sql(q)[1] is None, "dashboard pre-check accepts replace()")
check(bool(alerts._read_only(q)), "alerts pre-check accepts replace()")
r = launcher.dispatch("explore", "run_sql", {"sql": q})[0]
check(r.get("ok") and r["rows"][0]["n"] > 0, "explore run_sql runs the software expansion (%s)" % (r.get("rows") or r))
for bad in ("REPLACE INTO assets(uuid) VALUES ('x')",
            "WITH x AS (SELECT 1) REPLACE INTO assets(uuid) SELECT * FROM x",
            "SELECT 1 FROM assets WHERE 0 UNION SELECT 1 FROM (SELECT 1) -- \nREPLACE INTO t VALUES(1)"):
    check(explore_api._safe_select(bad)[1] is not None and software_api._safe_select(bad)[1] is not None
          and dashboard.safe_sql(bad)[1] is not None and not alerts._read_only(bad),
          "REPLACE statement still refused: %s" % bad[:40])

# 2 ── a no-key term alert over a navi.db with a software table evaluates
spec = launcher.dispatch("alert", "craft", {"prompt": "assets with openssl and python"})[0].get("draft") or {}
check("replace(" in (spec.get("metric_sql") or ""), "fixture: the term alert expands software.asset_uuid")
res = launcher.dispatch("alert", "test", {"alert": spec})[0].get("result") or {}
check(isinstance(res.get("value"), (int, float)) and "read-only" not in (res.get("note") or ""),
      "term alert evaluates (value=%r note=%r)" % (res.get("value"), res.get("note")))

# 3 ── dashboard software tiles count the assets inside the list
page = open(os.path.join(ROOT, "agents", "dashboard", "page.html"), encoding="utf-8").read()
tiles = re.findall(r"sql:`(SELECT software_string[^`]*)`", page)
check(len(tiles) == 2, "dashboard has the two software tiles")
for sql in tiles:
    o = launcher.dispatch("explore", "run_sql", {"sql": sql})[0]
    top = (o.get("rows") or [{}])[0].get("installs")
    check(o.get("ok") and top == want_top, "dashboard software tile top count = %r (want %d)" % (top, want_top))

# 4 ── contract scheduler: disarm → re-arm inside the 5 s poll keeps the loop alive
from core import contract                                           # noqa: E402
contract.scheduler_start()
time.sleep(0.3)
contract.scheduler_stop()
time.sleep(0.3)
contract.scheduler_start()
time.sleep(6.5)
check(contract.scheduler_status()["running"], "contract loop still running after disarm → re-arm")
contract.scheduler_stop()
time.sleep(6.5)
check(not contract.scheduler_status()["running"], "contract loop stops on disarm")

print("\n%s — %d failure(s)" % ("ALL PASS" if not fails else "FAILED", len(fails)))
sys.exit(1 if fails else 0)
