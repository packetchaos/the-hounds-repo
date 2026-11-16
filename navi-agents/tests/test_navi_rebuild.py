"""Regression tests — build 452: navi.db drift (asset delta), Rebuild navi.db, and Garmr
selecting strictly from navi.db.

Background: navi's asset sync pulls assets seen in the last N days and only UPSERTS, so
assets that age out / fall off licensing stay in navi.db; the Hounds can keep tagging them,
and the next sync never brings their tags back, so navi can't remove them.
  - core.asset_delta: navi.db assets / stale (last_found older than N days) / licensed-marked
    vs Tenable's licensed count (`navi explore info licensed`).
  - core.cli_jobs.start_rebuild: `navi config update full|assets|vulns -rebuild --days N`,
    answering navi's y/N prompt; refuses bad input and a concurrent navi job; optional chain
    of the derived tables (certs, software, routes, paths).
  - Settings API navi_rebuild: confirm === true AND a loopback caller.
  - Garmr: the list is navi.db's tags table only; a removal for a tag no navi.db asset carries
    is skipped (it would "succeed" and change nothing in Tenable).
A fake NAVI_BIN imitates navi's click.confirm (reads a y/N line from stdin). No Tenable.
Run: python3 tests/test_navi_rebuild.py"""
import atexit
import json
import os
import shutil
import sqlite3
import stat
import sys
import tempfile
import time
import faulthandler; faulthandler.dump_traceback_later(120, exit=True)   # a hang fails loudly

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
TMP = tempfile.mkdtemp(prefix="hounds-rebuild-")
atexit.register(shutil.rmtree, TMP, ignore_errors=True)
DB = os.path.join(TMP, "navi.db")
os.environ.update({"NAVI_CACHE_DIR": os.path.join(TMP, "cache"), "HOUNDS_CONFIG": os.path.join(TMP, "cfg.json"),
                   "NAVI_TAGLOG_DB": os.path.join(TMP, "taglog.db"), "NAVI_DB_PATH": DB})

fails = []


def check(cond, msg):
    print(("PASS " if cond else "FAIL ") + msg)
    if not cond:
        fails.append(msg)


# ---- a navi.db with fresh, stale and unlicensed assets ------------------------------------
con = sqlite3.connect(DB)
con.execute("CREATE TABLE assets (uuid text primary key, hostname text, last_found text, last_licensed_scan_date text)")
con.execute("CREATE TABLE tags (asset_uuid text, asset_ip text, tag_key text, tag_uuid text, tag_value text, tag_added_date text)")
con.execute("CREATE TABLE vulns (asset_uuid text)")
fresh = time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime(time.time() - 5 * 86400))
old = time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime(time.time() - 200 * 86400))
for i in range(6):
    con.execute("INSERT INTO assets VALUES (?,?,?,?)", ("f%d" % i, "fresh%d" % i, fresh, fresh))
for i in range(4):
    con.execute("INSERT INTO assets VALUES (?,?,?,?)", ("s%d" % i, "stale%d" % i, old, ""))
for i in range(3):
    con.execute("INSERT INTO tags VALUES (?,?,?,?,?,?)", ("f%d" % i, "", "Owner", "u1", "Team A", ""))
con.execute("INSERT INTO tags VALUES (?,?,?,?,?,?)", ("f5", "", "Scan Health", "u2", "Cred Failure", ""))
con.commit()
con.close()

FAKE = os.path.join(TMP, "navi")
LOG = os.path.join(TMP, "calls.jsonl")
with open(FAKE, "w") as f:
    f.write('''#!/usr/bin/env python3
import json, sys
a = sys.argv[1:]
open(%r, "a").write(json.dumps(a) + "\\n")
if a[:3] == ["explore", "info", "licensed"]:
    print("\\nLicensed Count:  7\\n"); sys.exit(0)
if "-rebuild" in a:
    print("***  -rebuild REQUESTED : THIS IS DESTRUCTIVE  ***")
    sys.stdout.write("Drop the assets and vulns table(s) and start fresh? [y/N]: "); sys.stdout.flush()
    ans = sys.stdin.readline().strip().lower()
    if ans != "y":
        print("Aborted!"); sys.exit(1)
    print("Rebuild complete - downloading into an empty table(s)."); sys.exit(0)
print("ok", " ".join(a))
''' % LOG)
os.chmod(FAKE, os.stat(FAKE).st_mode | stat.S_IXUSR)
os.environ["NAVI_BIN"] = FAKE

from core import asset_delta, cli_jobs, gates  # noqa: E402


def calls():
    try:
        return [json.loads(x) for x in open(LOG)]
    except OSError:
        return []


# ---- asset delta -----------------------------------------------------------------------------
nv = asset_delta.navi_side(days=90)
check(nv["assets"] == 10 and nv["stale"] == 4 and nv["licensed_marked"] == 6 and nv["tagged_assets"] == 4,
      "navi_side: 10 assets, 4 last seen > 90 days, 6 licensed-marked, 4 tagged (got %r)" % nv)
check(asset_delta.navi_side(days=300)["stale"] == 0, "the stale count follows the days window")
check(asset_delta.parse_licensed("\nLicensed Count:  1,234\n") == 1234 and asset_delta.parse_licensed("nope") is None,
      "parse_licensed reads navi's 'Licensed Count:' line (with thousands separators)")
d = asset_delta.delta(days=90)
check(d["tenable"]["licensed"] == 7 and d["delta"] == 3 and d["verdict"] == "drift",
      "delta: navi.db 10 vs licensed 7 → +3, verdict drift")
check(asset_delta.delta(live=False)["tenable"]["licensed"] is None, "live=False makes no Tenable call")
_bare = os.path.join(TMP, "bare.db")
sqlite3.connect(_bare).execute("CREATE TABLE assets (uuid text, hostname text)").connection.commit()
nb = asset_delta.navi_side(_bare)
check(nb["assets"] == 0 and nb["stale"] is None and nb["licensed_marked"] is None,
      "an older navi.db without last_found / licensed columns → unknown (None), not 0")

# ---- rebuild argv + validation -------------------------------------------------------------
check(cli_jobs.rebuild_argv("both", 90)[0] == ["config", "update", "full", "-rebuild", "--days", "90"],
      "both → navi config update full -rebuild --days 90")
check(cli_jobs.rebuild_argv("assets", "30")[0] == ["config", "update", "assets", "-rebuild", "--days", "30"],
      "assets → navi config update assets -rebuild --days 30")
check(cli_jobs.rebuild_argv("vulns", 7)[0][:3] == ["config", "update", "vulns"], "vulns → navi config update vulns")
for bad in [("everything", 90), ("both", 0), ("both", 4000), ("both", "9; rm -rf /"), ("both", None)]:
    check(cli_jobs.rebuild_argv(*bad)[0] is None, "rejected: %r" % (bad,))


def wait(jid, t=20):
    for _ in range(int(t / 0.05)):
        j = (cli_jobs.poll(jid, since=10 ** 9) or {}).get("job") or {}
        if j.get("status") != "running":
            return j
        time.sleep(0.05)
    return {}


# ---- rebuild runs, answers navi's y/N, chains the derived tables ------------------------------
open(LOG, "w").close()
r = cli_jobs.start_rebuild("both", 45, derived=True)
check(r.get("ok") and r.get("then") == ["navi config certificates", "navi config software",
                                         "navi config update route", "navi config update paths"],
      "start_rebuild starts and lists the derived rebuilds it will chain")
j = wait(r["job"]["id"])
full = cli_jobs.poll(r["job"]["id"]).get("job") or {}
check(j.get("status") == "done" and any("Rebuild complete" in ln for ln in full.get("lines", [])),
      "navi's y/N prompt was answered and the rebuild completed")
for _ in range(600):                     # the chain waits on each job (3 s polls)
    if len(calls()) >= 5 and not cli_jobs.running():
        break
    time.sleep(0.05)
check([c[:3] for c in calls()] == [["config", "update", "full"], ["config", "certificates"], ["config", "software"],
                                   ["config", "update", "route"], ["config", "update", "paths"]],
      "then certificates → software → route → paths, one after another (got %r)" % [c[:3] for c in calls()])
check(calls()[0] == ["config", "update", "full", "-rebuild", "--days", "45"], "the rebuild ran with --days 45")

# a running navi job blocks a rebuild (two writers on navi.db)
_busy = cli_jobs._record(["navi", "config", "update", "vulns"], "navi config update vulns")   # status: running
r2 = cli_jobs.start_rebuild("assets", 90)
check(not r2.get("ok") and "another navi job is running" in r2.get("error", ""), "a rebuild refuses while another navi job runs")
with cli_jobs._LOCK:
    _busy["status"] = "done"

# ---- Settings API gate -------------------------------------------------------------------------
from agents.settings import api as sapi  # noqa: E402
b, st = sapi.navi_rebuild({"tables": "both", "days": 90})
check(st == 400 and b.get("needs_confirm"), "navi_rebuild without confirm: true → 400")
b, st = sapi.navi_rebuild({"tables": "both", "days": 90, "confirm": "true"})
check(st == 400, "confirm must be JSON true (a string doesn't count)")
tok = gates.set_client("10.0.0.9", http=True)
b, st = sapi.navi_rebuild({"tables": "both", "days": 90, "confirm": True})
gates.reset_client(tok) if hasattr(gates, "reset_client") else None
check(st == 403, "navi_rebuild from a non-loopback browser → 403")
b, st = sapi.navi_rebuild({"tables": "both", "days": "x", "confirm": True})
check(st == 400 and "whole number" in b.get("error", ""), "bad days → 400 with a reason")
check("navi_rebuild" in sapi.ACTIONS and "asset_delta" in sapi.ACTIONS, "settings exposes navi_rebuild + asset_delta")
b, st = sapi.asset_delta({"live": False})
check(st == 200 and b["navi"]["assets"] == 10, "settings asset_delta (navi side only) reads navi.db")

# ---- Garmr: strictly navi.db --------------------------------------------------------------------
from agents.tagremoval import agent as gagent, api as gapi  # noqa: E402
from core import navi_cli  # noqa: E402
_lt = navi_cli.list_tags
navi_cli.list_tags = lambda: {"ok": True, "tags": [{"category": "Only", "value": "In Tenable"}]}
res = gagent.TagRemovalAgent()._run(db_path=DB)
names = [(t["category"], t["value"], t["assets"]) for t in res["tags"]]
check(names == [("Owner", "Team A", 3), ("Scan Health", "Cred Failure", 1)] and res["source"] == "navi.db tags table",
      "Garmr lists navi.db's tags only, with navi.db asset counts (got %r)" % names)
navi_cli.list_tags = _lt
queued = []
_tag = navi_cli.tag
navi_cli.tag = lambda c, v, **k: (queued.append((c, v)) or {"ok": True, "job_id": 1})
b, st = gapi.remove({"confirm": True, "tags": [{"category": "Owner", "value": "Team A"},
                                               {"category": "Only", "value": "In Tenable"},
                                               {"category": "owner", "value": "team a "}]})
navi_cli.tag = _tag
check(st == 200 and queued == [("Owner", "Team A"), ("owner", "team a")] and len(b["skipped"]) == 1
      and b["skipped"][0]["value"] == "In Tenable" and "not in navi.db" in b["skipped"][0]["reason"],
      "remove queues navi.db tags and skips a Tenable-only tag with a reason")
b, st = gapi.asset_delta({"live": False})
check(st == 200 and b["navi"]["stale"] == 4, "Garmr asset_delta action")

pg = open(os.path.join(ROOT, "agents", "tagremoval", "page.html"), encoding="utf-8").read()
check("Tags in navi.db — select the ones to remove" in pg and "Tenable only — not removable from here" in pg
      and "/web/settings.html#secRebuild" in pg and "asset_delta" in pg,
      "Garmr page: navi.db list, Tenable-only explanation, delta, link to Rebuild")
sp = open(os.path.join(ROOT, "web", "settings.html"), encoding="utf-8").read()
check('id="secRebuild"' in sp and 'id="rbDays"' in sp and "navi_rebuild" in sp and "confirm:true" in sp,
      "Settings page: Rebuild navi.db card with a days input, confirm:true")

if __name__ == "__main__":
    print("\n%d failure(s)" % len(fails))
    sys.exit(1 if fails else 0)
