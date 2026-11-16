"""Regression tests — build 471: the Compliance Explorer (Saluki) and the 🔎 search icon.

Saluki searches the compliance table on the server: text (check / audit file / host / IP),
status, audit file, exact framework, exact check, exact asset; failed first; KPIs over the
whole filtered set; CSV export capped. The header gets a search icon just left of the gear.
Run: python3 tests/test_ex_compliance_471.py"""
import atexit
import os
import shutil
import sqlite3
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
TMP = tempfile.mkdtemp(prefix="hounds-471-")
atexit.register(shutil.rmtree, TMP, ignore_errors=True)
DB = os.path.join(TMP, "navi.db")
os.environ.update({"NAVI_DB_PATH": DB, "NAVI_CACHE_DIR": os.path.join(TMP, "cache"),
                   "HOUNDS_CONFIG": os.path.join(TMP, "cfg.json"), "NAVI_TAGLOG_DB": os.path.join(TMP, "t.db")})
fails = []


def check(cond, msg):
    print(("PASS " if cond else "FAIL ") + msg)
    if not cond:
        fails.append(msg)


from agents.ex_compliance import api  # noqa: E402

o, st = api.search({})
check(st == 200 and o["result"].get("missing"), "no compliance table → a 'missing' answer, not an error")

c = sqlite3.connect(DB)
c.execute("CREATE TABLE assets (uuid text, hostname text, ip_address text)")
c.execute("CREATE TABLE compliance (asset_uuid text, check_id text, check_name text, status text, reference text, "
          "audit_file text, solution text, info text, see_also text, actual_value text, expected_value text)")
c.executemany("INSERT INTO assets VALUES (?,?,?)", [("a1", "web01", "10.0.0.1"), ("a2", "db02", "10.0.0.2"),
                                                     ("a3", "pci_box", "10.0.0.3")])
PCI = "[{'framework': 'PCI', 'control': '8.1'}]"
PCIDSS = "[{'framework': 'PCI-DSSv3.2.1', 'control': '8.2'}, {'framework': '800-53', 'control': 'AC-7'}]"
rows = [("a1", "1.1", "Ensure 50% of x", "PASSED", PCI, "CIS.audit", "fix", "", "https://x", "a", "b"),
        ("a1", "1.2", "Lockout duration", "FAILED", PCIDSS, "CIS.audit", "=cmd|' /C calc'!A0", "", "", "0", "15"),
        ("a2", "1.2", "Lockout duration", "FAILED", PCIDSS, "CIS.audit", "fix", "", "", "0", "15"),
        ("a2", "2.1", "Audit log", "WARNING", PCI, "STIG.audit", "fix", "", "", "", ""),
        ("a3", "2.1", "Audit log", "PASSED", PCI, "STIG.audit", "fix", "", "", "", ""),
        ("a3", "3.1", "Odd", "ERROR", "", "STIG.audit", "", "", "", "", "")]
c.executemany("INSERT INTO compliance VALUES (?,?,?,?,?,?,?,?,?,?,?)", rows)
c.commit()
c.close()


def S(**p):
    o, st = api.search(dict(p, limit=50))
    return o["result"]


r = S()
k = r["kpi"]
check(k["results"] == 6 and k["assets"] == 3 and k["checks"] == 4 and k["failed"] == 2 and k["warning"] == 1
      and k["passed"] == 2 and k["failing_assets"] == 2 and k["pass_pct"] == 50.0, "KPIs over the whole set: %s" % k)
check([x["status"] for x in r["rows"]] == ["failed", "failed", "warning", "unknown", "passed", "passed"],
      "failed first, then warning, other, passed")
check(r["rows"][0]["hostname"] and r["rows"][0]["refs"] == "PCI-DSSv3.2.1 8.2, 800-53 AC-7", "host joined; references readable")
p1 = S(limit=2)
o2, _ = api.search({"limit": 2, "offset": 2})
check(len(api.search({"limit": 2})[0]["result"]["rows"]) == 2 and api.search({"limit": 2})[0]["result"]["has_next"]
      and o2["result"]["page"] == 2 and o2["result"]["kpi"]["results"] == 6, "paged on the server; KPIs still the whole set")
check(S(status="failed")["kpi"]["results"] == 2 and S(status="unknown")["kpi"]["results"] == 1, "status filter (incl. other)")
check(S(q="db02")["kpi"]["results"] == 2 and S(q="10.0.0.3")["kpi"]["results"] == 2 and S(q="pci_box")["kpi"]["assets"] == 1, "text search reaches hostname and IP")
check(S(q="50%")["kpi"]["results"] == 1 and S(q="5_%")["kpi"]["results"] == 0, "% and _ in the search box are literal")
check(S(framework="PCI")["kpi"]["results"] == 3 and S(framework="PCI-DSSv3.2.1")["kpi"]["results"] == 2,
      "framework filter is exact (PCI ≠ PCI-DSSv3.2.1)")
check(S(audit_file="STIG.audit")["kpi"]["results"] == 3 and S(check="1.2")["kpi"]["assets"] == 2
      and S(asset="a3")["kpi"]["results"] == 2, "audit-file / check / asset filters")
check(S(q="x' OR 1=1 --")["kpi"]["results"] == 0, "search text is a bound parameter")
f, _ = api.facets({})
check({x["audit_file"]: x["results"] for x in f["result"]["audit_files"]} == {"CIS.audit": 3, "STIG.audit": 3}
      and {x["framework"]: x["results"] for x in f["result"]["frameworks"]} == {"PCI": 3, "PCI-DSSv3.2.1": 2, "800-53": 2},
      "facets: audit files and frameworks with counts")
api.EXPORT_MAX = 3
e, _ = api.export({})
check(e["rows"] == 3 and e["capped"] and e["csv"].count("\n") == 4, "export capped at EXPORT_MAX and says so")
e, _ = api.export({"check": "1.2", "asset": "a1"})
check("'=cmd" in e["csv"] and not e["capped"], "CSV neutralises formula cells")

js = open(os.path.join(ROOT, "web", "assets", "console.js"), encoding="utf-8").read()
check("function mountSearchIcon(" in js and "mountSearchIcon(hdr); hdr.appendChild(g)" in js
      and "s.href='/web/search.html'" in js, "header: 🔎 search icon, mounted just before the gear, opens Search Hounds")
check("'/agents/ex_compliance/page.html'" in js.split("const SEARCH_PAGES")[1].split("];")[0], "Compliance in the Search Hounds bar")
check("/agents/ex_compliance/page.html" in open(os.path.join(ROOT, "web", "search.html"), encoding="utf-8").read(),
      "Compliance card on the Search Hounds page")
check('"ex_compliance"' in open(os.path.join(ROOT, "core", "launcher.py"), encoding="utf-8").read(),
      "search answers are never served from the result cache")
print("\n%d failure(s)" % len(fails))
sys.exit(1 if fails else 0)
