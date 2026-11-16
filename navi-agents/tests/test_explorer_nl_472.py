"""Regression tests — build 472: the "✨ Ask in plain English" box on the Apps, Fixed and
Compliance explorers (the same widget the other search hounds have).

Each page carries the box and wires it to its own table; the explore service accepts those
tables for NL→SQL and the column picker, hands the model the table's real categorical values,
and still runs only a re-validated read-only SELECT.
Run: python3 tests/test_explorer_nl_472.py"""
import atexit
import os
import shutil
import sqlite3
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
TMP = tempfile.mkdtemp(prefix="hounds-472-")
atexit.register(shutil.rmtree, TMP, ignore_errors=True)
DB = os.path.join(TMP, "navi.db")
os.environ.update({"NAVI_DB_PATH": DB, "NAVI_CACHE_DIR": os.path.join(TMP, "cache"),
                   "HOUNDS_CONFIG": os.path.join(TMP, "cfg.json"), "NAVI_TAGLOG_DB": os.path.join(TMP, "t.db")})
fails = []


def check(cond, msg):
    print(("PASS " if cond else "FAIL ") + msg)
    if not cond:
        fails.append(msg)


c = sqlite3.connect(DB)
c.execute("CREATE TABLE apps (name text, uuid text, target text, critical_count text, owasp text, tech_list text)")
c.execute("CREATE TABLE fixed (asset_uuid text, plugin_id text, plugin_name text, severity text, state text, pass_fail text)")
c.execute("CREATE TABLE compliance (asset_uuid text, check_id text, check_name text, status text, audit_file text, reference text)")
c.execute("INSERT INTO apps VALUES ('shop','u1','https://shop','3',\"{'A1': 2}\",\"['PHP']\")")
c.execute("INSERT INTO fixed VALUES ('a1','1','x','high','fixed','Fail')")
c.execute("INSERT INTO compliance VALUES ('a1','1.1','Lockout','FAILED','CIS.audit',\"[{'framework': '800-53', 'control': 'AC-7'}]\")")
c.commit()
c.close()

from core import llm  # noqa: E402
from agents.explore import api  # noqa: E402

SEEN = {}


def fake(prompt, table, cols, timeout=40, value_hint=""):
    SEEN[table] = (cols, value_hint)
    return {"ok": True, "sql": "SELECT * FROM %s LIMIT 10" % table, "model": "test"}


llm.table_query = fake
for agent, table in (("ex_apps", "apps"), ("ex_fixed", "fixed"), ("ex_compliance", "compliance")):
    o, st = api.nl_translate({"table": table, "prompt": "anything"})
    check(st == 200 and o.get("ok") and o["sql"].lower().startswith("select"), "%s: NL→SQL accepts the %s table" % (agent, table))
    r, _ = api.run_sql({"sql": o["sql"]})
    check(r.get("ok") and r["count"] == 1, "%s: the reviewed SELECT runs (%s row)" % (agent, r.get("count")))
    cols, _ = api.columns({"table": table})
    check(cols.get("ok") and cols["columns"], "%s: column picker lists the %s columns" % (agent, table))
    pg = open(os.path.join(ROOT, "agents", agent, "page.html"), encoding="utf-8").read()
    check('id="nlq"' in pg and 'id="nlgo"' in pg and 'id="nlout"' in pg and "wireNlBox('%s');" % table in pg
          and 'class="toolbar needs-llm"' in pg, "%s: page has the ✨ Ask box wired to %s (hidden without a model)" % (agent, table))
check("FAILED" in SEEN["compliance"][1] and "CIS.audit" in SEEN["compliance"][1] and "Fail" in SEEN["fixed"][1],
      "the model is told the real status / audit-file / pass-fail values")
w, _ = api.run_sql({"sql": "DELETE FROM compliance"})
check(not w.get("ok"), "writes are still refused")
o, st = api.nl_translate({"table": "ssh", "prompt": "x"})
check(st == 400, "tables outside the allow-list are refused")
print("\n%d failure(s)" % len(fails))
sys.exit(1 if fails else 0)
