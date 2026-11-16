"""Regression tests — pre-release front-end review (UI bug sweep).

  · Plugin detail (/web/vuln.html → explore.vuln) is bounded: a plugin on every asset (19506 fires
    on 193k assets / ~118 MB of JSON at scale) returns the first VULN_ROWS_MAX rows + the true count,
    and the page says "first N of M"; navi's "None" output text is shown as "—", not "None".
  · Alert Raven pins its agent id in the header (a second agentApi('settings') had clobbered it,
    so the codename / "what it does" intro never mounted).
  · Harrier's ✨ zero-day lookup: a failed re-plan clears the previous sources (no stale Approve
    button), a pasted-URL-only plan doesn't claim "searching NVD for “”", and the 10-site warning
    clears when the selection drops back under the limit.
Run: python3 tests/test_review_ui.py"""
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
TMP = tempfile.mkdtemp(prefix="hounds-reviewui-")
atexit.register(shutil.rmtree, TMP, ignore_errors=True)
DB = os.path.join(TMP, "navi.db")
os.environ.update({"NAVI_DB_PATH": DB, "NAVI_CACHE_DIR": os.path.join(TMP, "cache"),
                   "HOUNDS_CONFIG": os.path.join(TMP, "cfg.json"), "NAVI_TAGLOG_DB": os.path.join(TMP, "t.db")})
fails = []


def check(cond, msg):
    print(("PASS " if cond else "FAIL ") + msg)
    if not cond:
        fails.append(msg)


def src(rel):
    with open(os.path.join(ROOT, rel), encoding="utf-8") as f:
        return f.read()


# ── explore.vuln is bounded ───────────────────────────────────────────────────
c = sqlite3.connect(DB)
c.execute("CREATE TABLE assets (uuid TEXT, hostname TEXT, ip_address TEXT)")
c.execute("CREATE TABLE vulns (asset_uuid TEXT, plugin_id TEXT, plugin_name TEXT, output TEXT, last_found TEXT, url TEXT)")
N = 2105
c.executemany("INSERT INTO assets VALUES (?,?,?)",
              [("u%05d" % i, "h%05d" % i, "10.0.%d.%d" % (i // 250, i % 250)) for i in range(N)])
c.executemany("INSERT INTO vulns VALUES (?,?,?,?,?,?)",
              [("u%05d" % i, "19506", "Nessus Scan Information", "Credentialed checks : yes", "2026-11-01", "")
               for i in range(N)] + [("u00001", "10863", "SSL Certificate Information", "None", "2026-11-01", "")])
c.commit()
c.close()

from core import launcher  # noqa: E402
api = __import__("agents.explore.api", fromlist=["x"])

body, st = launcher.dispatch("explore", "vuln", {"plugin": "19506"})
check(st == 200 and body.get("ok"), "explore.vuln answers")
check(len(body["assets"]) == api._VULN_ROWS, "explore.vuln returns at most _VULN_ROWS rows (%d)" % len(body["assets"]))
check(body["count"] == N, "explore.vuln count is the true total (%s)" % body["count"])
check(body.get("truncated") is True, "explore.vuln flags truncated")
body, st = launcher.dispatch("explore", "vuln", {"plugin": "10863"})
check(body["count"] == 1 and len(body["assets"]) == 1 and body.get("truncated") is False, "small plugin: not truncated")

vh = src("web/vuln.html")
check("o.truncated" in vh and "of ${Number(o.count)" in vh, "vuln.html shows 'first N of M' when truncated")
check(re.search(r"a\.output&&String\(a\.output\)\.trim\(\)!=='None'", vh) is not None,
      "vuln.html shows navi's 'None' output as a dash")

# ── Alert Raven pins its id ───────────────────────────────────────────────────
al = src("agents/alert/page.html")
check("agentApi('settings')" not in al or "mountAgentHeader({id:'alert'" in al,
      "alert page pins id:'alert' in mountAgentHeader (second agentApi clobbers __AGENT_ID)")
# any page that creates agentApi() for two different agents must pin its id in the header
for d in sorted(os.listdir(os.path.join(ROOT, "agents"))):
    p = os.path.join("agents", d, "page.html")
    if not os.path.exists(os.path.join(ROOT, p)):
        continue
    s = src(p)
    ids = set(re.findall(r"agentApi\('([a-z_]+)'\)", s))
    if len(ids) > 1 and "mountAgentHeader(" in s:
        check(re.search(r"mountAgentHeader\(\{\s*id\s*:", s) is not None, "%s pins its agent id in the header" % p)

# ── Harrier zero-day lookup UI state ──────────────────────────────────────────
sw = src("agents/ex_software/page.html")
m = re.search(r"async function zplan\(\)\{(.*?)\n\$\('zplan'\)", sw, re.S)
check(m is not None, "zplan() found")
zp = m.group(1) if m else ""
check(re.search(r"if\(!o\|\|!o\.ok\)\{\s*SRC=\[\];\s*drawSources\(\);", zp) is not None,
      "a failed plan clears the previous sources")
check("r.keywords.length?" in zp, "a URL-only plan does not say 'searching NVD for “”'")
check("ZMAX=false" in zp and re.search(r"else if\(ZMAX\)\{\s*ZMAX=false;\s*flashClear\('zflash'\)", sw) is not None,
      "the 10-site warning clears when the selection is back under the limit")

print("\n%d failure(s)" % len(fails))
sys.exit(1 if fails else 0)
