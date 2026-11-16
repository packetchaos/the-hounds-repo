"""Regression tests — build 464: the two largest "large response" offenders.

explore/applied (asked on every page open) returns one row per tag, not one per asset × tag ·
Asset Classification's ▶ Run ships no per-asset list; the class drill-down asks the server.
Run: python3 tests/test_payload_464.py"""
import atexit
import os
import shutil
import sqlite3
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
TMP = tempfile.mkdtemp(prefix="hounds-464-")
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
c.execute("CREATE TABLE tags (asset_uuid text, tag_key text, tag_value text)")
rows = [("u%05d" % i, k, v) for i in range(3000) for k, v in (("Owner", "Shop"), ("Hounds-Lifecycle", "EOL"))]
rows += [("u1", "Owner", None)]
c.executemany("INSERT INTO tags VALUES (?,?,?)", rows)
c.commit()
c.close()
from agents.explore import api as ex  # noqa: E402
o, st = ex.applied({})
got = sorted((r["tag_key"], r["tag_value"], r.get("base")) for r in o["applied"])
check(st == 200 and got == [("Hounds-Lifecycle", "EOL", "Lifecycle"), ("Owner", "Shop", None)],
      "explore/applied: one row per tag, not per asset (%d rows from 6,001)" % len(o["applied"]))
pg = open(os.path.join(ROOT, "agents", "classify", "page.html"), encoding="utf-8").read()
check("DATA.assets" not in pg and "DT=hDrill(" in pg and "filter:['cls:'+cls]" in pg and "search:'dq'" in pg,
      "classify page: the drill-down pages + searches a class on the server (hDrill)")
check("{set:{run:DATA.drill.run, cls:'Unclassified', q:_dq()}}" in pg,
      "classify page: 'Select all' tags the whole class (or search) by key, not a uuid list")
# ── Scan Evaluation on the payload contract ─────────────────────────────────────────────────
import json  # noqa: E402
from agents.scan_eval import api as se  # noqa: E402
from core import scan_eval as SE  # noqa: E402
ST = ["failed", "insufficient", "intermittent", "uncredentialed", "ok", "unknown"]
FR = ["0-7", "8-30", "31-90", "90+", "never", "unknown"]
ROWS = [{"asset_uuid": "u%05d" % i, "host": "h%d" % i, "ip": "10.0.%d.%d" % (i // 250, i % 250), "acr": (i % 10) + 1,
         "crown": (i % 10) + 1 >= 7, "status": ST[i % 6], "patch": "failed" if i % 13 == 0 else "", "fresh": FR[i % 6],
         "age_days": i % 400, "last_scan": "2026-01-01", "scanner": "s%d" % (i % 3), "policy": "=cmd" if i == 7 else "Adv",
         "scan": "Weekly", "type": "Agent" if i % 2 else "Network", "dur": float(i % 5000)} for i in range(25000)]
SE.evaluate = lambda **kw: {"metrics": {"assets": len(ROWS)}, "scanners": [], "policies": [], "scans": [],
                            "slowest": [], "slow_sec": 3600, "assets": ROWS if kw.get("all_rows") else ROWS[:20000],
                            "credential": {"total_assets": 25000, "cred_fail_assets": 1, "assets": [{"asset_uuid": "x"}]}}
o, st = se.run({})
check(st == 200 and len(json.dumps(o)) < 200000 and "assets" not in o["result"] and "assets" not in o["result"]["credential"]
      and o["result"]["assets_total"] == 25000, "scan_eval run: no asset list (%d bytes), every one of 25,000 stored" % len(json.dumps(o)))
run = o["drill"]["run"]


def tot(flt, q=""):
    d, _ = se.drill({"run": run, "section": "assets", "filter": flt, "q": q})
    return d["total"]["value"]


blind = {"failed", "insufficient", "intermittent", "uncredentialed"}
want = {"st:failed": sum(r["status"] == "failed" for r in ROWS),
        "f:blind": sum(r["status"] in blind for r in ROWS),
        "f:stale30": sum(r["fresh"] in ("31-90", "90+") for r in ROWS),
        "f:slow": sum(r["dur"] > 3600 for r in ROWS),
        "f:crownblind": sum(r["crown"] and (r["status"] in blind or r["fresh"] in ("90+", "never")) for r in ROWS),
        "f:agent": sum(r["type"] == "Agent" for r in ROWS), "f:patch": sum(r["patch"] == "failed" for r in ROWS)}
got = {k: tot([k]) for k in want}
check(got == want, "scan_eval filters match the page's rules over every row (past the old 20,000)")
check(tot(["st:failed", "f:crown"]) == sum(r["status"] == "failed" and r["crown"] for r in ROWS), "state + metric filter combine")
check(tot([], "h24999") == 1, "server-side search reaches row 25,000")
e, _ = se.export({"run": run, "filter": ["f:agent"]})
lines = e["csv"].strip().splitlines()
check(e["ok"] and e["rows"] == want["f:agent"] and len(lines) == want["f:agent"] + 1, "CSV export: every row of the view (%d)" % e["rows"])
e2, _ = se.export({"run": run, "q": "h7"})
check("'=cmd" in e2["csv"], "CSV export guards spreadsheet formulas")
b, st = se.export({"run": run, "filter": ["x:y"]})
check(st == 400, "CSV export: undeclared filter → 400")
from core import launcher  # noqa: E402
check(launcher.note_response("scan_eval", "export", 50 * 1024 * 1024) is False, "an explicit CSV download is not a 'large response'")

# ── Attack Paths on the payload contract ─────────────────────────────────────────────────────
from agents.attackpath import api as ap  # noqa: E402
EU = ["e%05d" % i for i in range(12000)]
FULL = {"ok": True, "paths": [{"target": {"uuid": "t1", "host": "crown"}, "entry": {"uuid": EU[0]}, "steps": [], "primary": True}],
        "entries": [{"uuid": u, "host": "h" + u, "ip": "10.0.0.1", "reaches_any": i % 3 == 0, "how": ["empty pw"]} for i, u in enumerate(EU)],
        "reachable": ["t1", "t2"], "unreached": [{"host": "u%d" % i} for i in range(90)],
        "fixes": [{"fix": "plugin:140657", "assets": 12000, "uuids": EU, "exposure_cut_pct": 50.0}],
        "bundle": [{"fix": "plugin:140657", "assets": 12000, "uuids": EU}],
        "controls": [{"key": "laps", "assets": 12000, "uuids": EU, "paths": 1}],
        "graph": {"nodes": [{"id": EU[0], "kind": "asset", "ip": "10.0.0.1", "label": "web"}], "edges": []},
        "metrics": {"crown": 2}}
ap.AGENT.run = lambda crown_acr=7.0: (setattr(ap.AGENT, "result", FULL) or FULL)
o, st = ap.run({})
js = json.dumps(o)
r = o["result"]
check(st == 200 and len(js) < 100000 and EU[5000] not in js, "attackpath run: no entry list or uuid arrays (%d bytes)" % len(js))
check(r["entries_n"] == 12000 and r["entries_reach_n"] == 4000 and r["reachable_n"] == 2 and r["unreached_n"] == 90
      and len(r["unreached"]) == 40, "attackpath: counts for every list kept")
check(r["fixes"][0]["c2_targets"] == [{"ip": "10.0.0.1", "uuid": EU[0], "hostname": "web"}] and "uuids" not in r["fixes"][0]
      and "uuids" not in r["controls"][0], "fixes keep the C2 hand-off hosts (from the map), not the uuid list")
d, _ = ap.drill({"run": o["drill"]["run"], "section": "entries", "filter": ["reach"]})
check(d["total"]["value"] == 4000, "ways-in table pages on the server (reach filter)")
TAGS = []
ap.navi_cli.tag_uuids_batched = lambda cat, val, uu, agent=None: (TAGS.append((val, len(uu))) or [{"ok": True, "job_id": 1}])
ap.tag({"key": "entry", "confirm": True})
ap.tag({"key": "fix:plugin:140657", "confirm": True})
check(TAGS == [("Entry Point", 4000), ("Choke Point", 12000)], "tag keys still rebuild the full sets on the server (%s)" % TAGS)

print("\n%d failure(s)" % len(fails))
sys.exit(1 if fails else 0)
