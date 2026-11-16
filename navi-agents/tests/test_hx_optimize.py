"""Regression tests — ⚡ Optimize navi.db for the Hounds (core/hx_optimize.py, build 453).

The SQL review's index + statistics step: seven hx_* indexes (only where the table/columns
exist), a bounded ANALYZE, and ' unordered' on the vulns indexes' sqlite_stat1 rows — without
it `SELECT DISTINCT asset_uuid FROM vulns WHERE <unindexed>` walks hx_v_asset with a random
table read per row (6 s → 301 s measured). Every ANALYZE erases it, so it's always re-applied.
Checks: status shape · missing-table / missing-column tolerance · idempotent re-run · the trap
plan before/after · reapply after a bare ANALYZE and after a sync hook · cancel keeps the
finished indexes · refusals (navi job running, low disk, another writer) · the Settings
confirm + loopback gate · navi syncs refused while Optimize holds the lock · the rebuild chain.
Synthetic navi.db, fake navi binary; no Tenable. Run: python3 tests/test_hx_optimize.py"""
import atexit
import os
import random
import shutil
import sqlite3
import stat
import sys
import tempfile
import threading
import time
import faulthandler; faulthandler.dump_traceback_later(180, exit=True)   # a hang fails loudly

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
TMP = tempfile.mkdtemp(prefix="hounds-hx-")
atexit.register(shutil.rmtree, TMP, ignore_errors=True)
DB = os.path.join(TMP, "navi.db")
os.environ.update({"NAVI_CACHE_DIR": os.path.join(TMP, "cache"), "HOUNDS_CONFIG": os.path.join(TMP, "cfg.json"),
                   "NAVI_TAGLOG_DB": os.path.join(TMP, "taglog.db"), "NAVI_HISTORY_DIR": os.path.join(TMP, "hist"),
                   "NAVI_DB_PATH": DB})

fails = []


def check(cond, msg):
    print(("PASS " if cond else "FAIL ") + msg)
    if not cond:
        fails.append(msg)


def make_db(path, n=30000, certs=False, software=False, state=True):
    c = sqlite3.connect(path)
    c.execute("PRAGMA journal_mode=WAL")                  # navi's mode
    c.execute("CREATE TABLE assets (uuid text primary key, hostname text, ip_address text)")
    c.execute("CREATE TABLE vulns (asset_uuid text, plugin_id text, %s severity text, plugin_name text, output text)"
              % ("state text," if state else ""))
    c.execute("CREATE TABLE tags (asset_uuid text, tag_key text, tag_value text, tag_uuid text)")
    c.execute("CREATE TABLE compliance (asset_uuid text, check_name text, status text)")
    if certs:
        c.execute("CREATE TABLE certs (asset_uuid text, subject_name text)")
    if software:
        c.execute("CREATE TABLE software (asset_uuid text, software_string text)")
    r = random.Random(4)
    c.executemany("INSERT INTO assets VALUES (?,?,?)", [("a%04d" % i, "h%d" % i, "10.0.%d.%d" % (i // 250, i % 250)) for i in range(2000)])
    rows = [("a%04d" % r.randrange(2000), str(r.randrange(500))) + ((r.choice(["open", "fixed", "reopened"]),) if state else ())
            + (r.choice(["critical", "high", "low", "info"]), "Plugin %d" % r.randrange(500), "o" * 40) for _ in range(n)]
    c.executemany("INSERT INTO vulns VALUES (%s)" % ",".join("?" * len(rows[0])), rows)
    c.executemany("INSERT INTO tags VALUES (?,?,?,?)", [("a%04d" % i, "Owner", "Team %d" % (i % 7), "u") for i in range(2000)])
    c.executemany("INSERT INTO compliance VALUES (?,?,?)", [("a%04d" % (i % 2000), "c%d" % i, "FAILED") for i in range(3000)])
    c.commit()
    c.close()


make_db(DB)

from core import cli_jobs, gates, hx_optimize as hx  # noqa: E402

# the trap needs a predicate on a column the vulns indexes DON'T cover (since build 454 severity is
# covered — that query is now answered from the index alone, which is the point of adding it)
TRAP_Q = "SELECT DISTINCT asset_uuid FROM vulns WHERE plugin_name LIKE 'Op%'"


def plan(q=TRAP_Q, path=DB):
    c = sqlite3.connect(path)
    try:
        return " | ".join(r[3] for r in c.execute("EXPLAIN QUERY PLAN " + q))
    finally:
        c.close()


def stat1(path=DB):
    c = sqlite3.connect(path)
    try:
        return dict(c.execute("SELECT idx, stat FROM sqlite_stat1 WHERE idx LIKE 'hx_%'"))
    except sqlite3.Error:
        return {}
    finally:
        c.close()


def index_names(path=DB):
    c = sqlite3.connect(path)
    try:
        return {r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='index'")}
    finally:
        c.close()


# ---- status shape before anything is built ---------------------------------------------------
s = hx.status(DB)
KEYS = {"ok", "db_path", "indexes", "missing", "skipped", "est_bytes", "est_s", "need_free_bytes", "free_bytes",
        "tmp_dir", "stats_present", "unordered", "navi_idx", "optimized", "navi_busy", "job", "rates"}
check(s["ok"] and KEYS <= set(s), "status() has every key the card reads (missing: %s)" % (KEYS - set(s)))
check([i["name"] for i in s["indexes"]] == ["hx_v_plugin", "hx_v_asset", "hx_tags_asset", "hx_tags_kv",
                                            "hx_comp_asset", "hx_certs_asset", "hx_sw_asset",
                                            "hx_assets_ip", "hx_assets_host"],
      "nine hx_ indexes, vulns first (assets ip/hostname since build 455)")
check(s["missing"] == ["hx_v_plugin", "hx_v_asset", "hx_tags_asset", "hx_tags_kv", "hx_comp_asset",
                      "hx_assets_ip", "hx_assets_host"],
      "missing = the seven whose tables exist (got %r)" % s["missing"])
check({x["name"] for x in s["skipped"]} == {"hx_certs_asset", "hx_sw_asset"}
      and all("no " in x["reason"] for x in s["skipped"]), "no certs / software table → skipped with a reason")
v = next(i for i in s["indexes"] if i["name"] == "hx_v_plugin")
check(v["rows"] == 30000 and v["est_bytes"] == int(30000 * 66.0) and v["est_s"][0] == round(30000 / 600000, 1),
      "vulns estimate from MAX(rowid): 66 B/row (with severity), rows ÷ 600k/s (got %r)" % {k: v[k] for k in ("rows", "est_bytes", "est_s")})
check(s["need_free_bytes"] == 2 * s["est_bytes"] and s["est_bytes"] > 0, "needs 2× the estimated index bytes free")
check(not s["optimized"] and not s["stats_present"] and s["navi_busy"] == [] and s["job"] is None,
      "not optimized, no stats, no jobs")
c = sqlite3.connect(DB)
check(c.execute("SELECT count(*) FROM sqlite_master WHERE name LIKE 'hx_%'").fetchone()[0] == 0,
      "status() built nothing (read-only on page open)")
c.close()

# ---- build ---------------------------------------------------------------------------------------
lines = []
r = hx.optimize(DB, emit=lines.append)
check(r["ok"] and [b["name"] for b in r["built"]] == s["missing"] and r["skipped"] == ["hx_certs_asset", "hx_sw_asset"],
      "optimize builds the seven applicable indexes and skips the two missing tables")
check(any(ln.startswith("▶ CREATE INDEX hx_v_plugin") for ln in lines) and any("ANALYZE" in ln for ln in lines),
      "progress lines per index + ANALYZE")
s1 = stat1()
check(all("unordered" in s1.get(n, "").split() for n in ("hx_v_plugin", "hx_v_asset")),
      "' unordered' is on both vulns index stat rows")
check(all("unordered" not in s1.get(n, "") for n in ("hx_tags_asset", "hx_tags_kv", "hx_comp_asset")),
      "…and only on the vulns indexes")
s = hx.status(DB)
check(s["optimized"] and s["stats_present"] and s["unordered"]["applied"] and s["missing"] == [],
      "status after: optimized, stats present, unordered applied")
check("USING INDEX hx_v_asset" not in plan() and "TEMP B-TREE" in plan(),
      "DISTINCT asset_uuid over an unindexed predicate scans + temp b-tree (no index walk): %s" % plan())
check("hx_v_plugin" in plan("SELECT DISTINCT asset_uuid FROM vulns WHERE plugin_id='7' AND state='open'"),
      "selective plugin_id lookups still use hx_v_plugin")
check("hx_v_asset" in plan("SELECT count(*) FROM vulns WHERE asset_uuid='a0001'"),
      "per-asset lookups still use hx_v_asset")

# ---- idempotent re-run ------------------------------------------------------------------------
before = index_names()
t0 = time.time()
r2 = hx.optimize(DB)
check(r2["ok"] and r2["built"] == [] and len(r2["existed"]) == 7 and index_names() == before,
      "re-run builds nothing (%.2fs)" % (time.time() - t0))
check(all(stat1()[n].split().count("unordered") == 1 for n in ("hx_v_plugin", "hx_v_asset")),
      "re-run leaves exactly one 'unordered' token")

# ---- the trap: a bare ANALYZE erases it; reapply_unordered fixes it -----------------------------
c = sqlite3.connect(DB, isolation_level=None)
c.execute("ANALYZE")                                     # what `navi config optimize` ends with
c.close()
st = hx.status(DB)
check(not st["unordered"]["applied"] and not st["optimized"], "after a bare ANALYZE status reports unordered erased")
check("USING INDEX hx_v_asset" in plan(), "…and the planner walks hx_v_asset (the trap) — %s" % plan())
rr = hx.reapply_unordered(DB)
check(rr["ok"] and rr["applied"] == 2 and "USING INDEX hx_v_asset" not in plan(), "reapply_unordered fixes it (2 rows)")
check(hx.reapply_unordered(DB)["applied"] == 0, "reapply is a no-op when already applied")

# a vulns index created after the last ANALYZE has no stat row — reapply analyzes just that index
c = sqlite3.connect(DB, isolation_level=None)
c.execute("DROP INDEX hx_v_asset")
c.execute("CREATE INDEX hx_v_asset ON vulns(asset_uuid, plugin_id, state, severity)")
c.close()
check("hx_v_asset" not in stat1(), "(fresh index has no stat1 row)")
hx.reapply_unordered(DB)
check("unordered" in stat1().get("hx_v_asset", ""), "reapply gives a fresh vulns index a stat row + unordered")

# a navi.db without the hx indexes: reapply does nothing (no stat1 created)
bare = os.path.join(TMP, "bare.db")
make_db(bare, n=500)
rb = hx.reapply_unordered(bare)
check(rb["applied"] == 0 and rb.get("skipped") and stat1(bare) == {}, "reapply on a db without hx indexes: no-op")

# ---- missing-column tolerance (an old navi.db without vulns.state) --------------------------------
old = os.path.join(TMP, "old.db")
make_db(old, n=500, state=False, certs=True, software=True)
so = hx.status(old)
check({x["name"] for x in so["skipped"]} == {"hx_v_plugin", "hx_v_asset"}
      and all("column" in x["reason"] for x in so["skipped"]), "vulns without state → both vulns indexes skipped")
ro = hx.optimize(old)
check(ro["ok"] and {b["name"] for b in ro["built"]} == {"hx_tags_asset", "hx_tags_kv", "hx_comp_asset",
                                                        "hx_certs_asset", "hx_sw_asset", "hx_assets_ip", "hx_assets_host"},
      "…the other seven are built, certs + software + assets included")
empty = os.path.join(TMP, "empty.db")
sqlite3.connect(empty).execute("CREATE TABLE x (a)").connection.close()
se = hx.status(empty)
check(se["ok"] and se["missing"] == [] and len(se["skipped"]) == 9 and not se["optimized"],
      "a navi.db with none of the tables: everything skipped, nothing to do")
check(not hx.status(os.path.join(TMP, "nope.db"))["ok"], "missing file → ok False")

# ---- cancel: the index in progress rolls back, finished ones stay, unordered still applied -------
cdb = os.path.join(TMP, "cancel.db")
make_db(cdb, n=40000)
ev = threading.Event()
clines = []


def _emit(ln):
    clines.append(ln)
    if ln.startswith("▶ CREATE INDEX hx_v_asset"):
        ev.set()                                          # cancel while hx_v_asset builds


rc = hx.optimize(cdb, emit=_emit, cancel=ev)
names = index_names(cdb)
check(rc["cancelled"] and not rc["ok"] and "hx_v_plugin" in names and "hx_v_asset" not in names
      and "hx_tags_asset" not in names, "cancel mid-index: hx_v_plugin kept, hx_v_asset rolled back, rest not started")
check("unordered" in stat1(cdb).get("hx_v_plugin", ""), "after a cancel the finished vulns index still gets 'unordered'")
check(any("cancelled" in ln for ln in clines), "a 'cancelled … rolled back' line")
r3 = hx.optimize(cdb)
check(r3["ok"] and {b["name"] for b in r3["built"]} == {"hx_v_asset", "hx_tags_asset", "hx_tags_kv", "hx_comp_asset", "hx_assets_ip", "hx_assets_host"},
      "re-run after a cancel builds only what's left")

# ---- refusals ------------------------------------------------------------------------------------
rdb = os.path.join(TMP, "refuse.db")
make_db(rdb, n=2000)
_busy = cli_jobs._record(["navi", "config", "update", "vulns"], "navi config update vulns", "vulns")
rf = hx.run(rdb)
check(not rf["ok"] and "navi job is running" in rf["error"] and rf["status"]["navi_busy"],
      "run() refuses while a navi job runs (status shows it)")
with cli_jobs._LOCK:
    _busy["status"] = "done"
_free = hx._free
hx._free = lambda d: 1000
rf = hx.run(rdb)
hx._free = _free
check(not rf["ok"] and "free disk" in rf["error"], "run() refuses when free disk < 2× the estimate (stub)")
lock = sqlite3.connect(rdb, isolation_level=None)
lock.execute("BEGIN IMMEDIATE")
rf = hx.run(rdb)
lock.execute("ROLLBACK")
lock.close()
check(not rf["ok"] and "locked by another writer" in rf["error"], "run() refuses when another writer holds navi.db")
check(index_names(rdb) & {n for n, *_ in hx.INDEXES} == set(), "no refusal built anything")

# ---- run() as a console job: poll, progress, done; second click returns the running job ----------
r = hx.run(rdb)
check(r["ok"] and r["job"]["kind"] == "hx_optimize", "run() starts an hx_optimize job")
jid = r["job"]["id"]
for _ in range(400):
    j = cli_jobs.poll(jid)["job"]
    if j["status"] != "running":
        break
    time.sleep(0.05)
check(j["status"] == "done" and j["returncode"] == 0 and any("optimized for the Hounds" in ln for ln in j["lines"]),
      "job finishes, lines stream through poll()")
check(hx.status(rdb)["optimized"], "…and the db is optimized")

# a running Optimize blocks navi syncs from the console (it holds the write lock)
gate = threading.Event()
t = cli_jobs.start_task("⚡ Optimize navi.db for the Hounds", "hx_optimize", lambda e, l, c: gate.wait(20) and {"ok": True})
ru = cli_jobs.start_update("vulns")
check(not ru["ok"] and "Optimize" in ru["error"], "navi sync refused while Optimize runs")
check(not cli_jobs.start_rebuild("both", 30)["ok"], "rebuild refused while Optimize runs")
ra = hx.run(rdb)
check(ra["ok"] and ra.get("already_running") and ra["job"]["id"] == t["job"]["id"], "a second run() returns the running job")
cx = cli_jobs.cancel(t["job"]["id"])
check(cx["ok"], "cancel() accepted for an in-process job")
gate.set()
time.sleep(0.3)
check(cli_jobs.hx_busy() is None, "lock released when the job ends")
check(not cli_jobs.cancel(_busy["id"])["ok"], "a navi subprocess job can't be cancelled through cancel()")

# ---- the after-sync hook: a console-launched vulns sync re-applies unordered ----------------------
os.environ["NAVI_DB_PATH"] = DB
hx.optimize(DB)
c = sqlite3.connect(DB, isolation_level=None)
c.execute("ANALYZE")
c.close()
job = {"kind": "agents", "lines": []}
cli_jobs._after_sync(job)
check(not hx.status(DB)["unordered"]["applied"] and job["lines"] == [], "an agents sync doesn't touch navi.db stats")
job = {"kind": "vulns", "lines": []}
cli_jobs._after_sync(job)
check(hx.status(DB)["unordered"]["applied"] and any("unordered" in ln for ln in job["lines"]),
      "a vulns sync (or navi config optimize) → unordered re-applied + a note in its CLI output")
check(set(hx.SYNC_KINDS) >= {"assets", "vulns", "full", "everything", "optimize"}, "hooked kinds")

# ---- Settings API gate ---------------------------------------------------------------------------
from agents.settings import api as sapi  # noqa: E402
check({"hx_status", "hx_optimize", "hx_cancel"} <= set(sapi.ACTIONS), "settings exposes hx_status / hx_optimize / hx_cancel")
b, code = sapi.hx_status({})
check(code == 200 and b["ok"] and b["db_path"] == DB and KEYS <= set(b), "hx_status reads NAVI_DB_PATH")
b, code = sapi.hx_optimize_run({})
check(code == 400 and b.get("needs_confirm"), "hx_optimize without confirm → 400 needs_confirm")
b, code = sapi.hx_optimize_run({"confirm": "true"})
check(code == 400, "confirm must be JSON true")
tok = gates.set_client("10.0.0.9", http=True)
b, code = sapi.hx_optimize_run({"confirm": True})
b2, code2 = sapi.hx_cancel({"job_id": 1})
gates.reset_client(tok)
check(code == 403 and code2 == 403, "hx_optimize / hx_cancel from a non-loopback browser → 403")
b, code = sapi.hx_optimize_run({"confirm": True})
check(code == 200 and b["ok"], "loopback + confirm → started")
for _ in range(400):
    if cli_jobs.hx_busy() is None:
        break
    time.sleep(0.05)

# ---- Rebuild chain: the rebuild, then Optimize --------------------------------------------------
FAKE = os.path.join(TMP, "navi")
with open(FAKE, "w") as f:
    f.write('#!/usr/bin/env python3\nimport sys\nif "-rebuild" in sys.argv:\n    sys.stdin.readline()\nprint("ok")\n')
os.chmod(FAKE, os.stat(FAKE).st_mode | stat.S_IXUSR)
os.environ["NAVI_BIN"] = FAKE
c = sqlite3.connect(DB, isolation_level=None)
c.execute("DROP INDEX hx_v_asset")                        # what -rebuild of vulns would do
c.close()
rr = cli_jobs.start_rebuild("vulns", 30, derived=False, hx=True)
check(rr["ok"] and rr["then"] == ["⚡ Optimize for the Hounds"], "start_rebuild(hx=True) lists Optimize as the last step")
for _ in range(300):
    if "hx_v_asset" in index_names() and cli_jobs.hx_busy() is None:
        break
    time.sleep(0.05)
check("hx_v_asset" in index_names() and hx.status(DB)["optimized"], "…and Optimize ran after the rebuild finished")

# ---- page --------------------------------------------------------------------------------------------
pg = open(os.path.join(ROOT, "web", "settings.html"), encoding="utf-8").read()
check('id="secHx"' in pg and "API.post('hx_status')" in pg and "API.post('hx_optimize',{confirm:true})" in pg
      and "confirm(msg)" in pg and "navi config optimize" in pg and 'id="rbHx"' in pg and "hx_optimize:hxo" in pg,
      "Settings card: status on open, confirmed run, navi-optimize note, rebuild checkbox")

print("\n%d failure(s)" % len(fails))
sys.exit(1 if fails else 0)

# ---- build 454: severity in both vulns indexes (covering on 5.5 KB real rows) + outdated rebuild ----
import sqlite3 as _sq3, tempfile as _tf  # noqa: E402
_d = _tf.mkdtemp(prefix="hx-outdated-")
_p = os.path.join(_d, "navi.db")
_c = _sq3.connect(_p)
_c.execute("CREATE TABLE vulns (asset_uuid TEXT, plugin_id TEXT, state TEXT, severity TEXT, output TEXT)")
_c.executemany("INSERT INTO vulns VALUES (?,?,?,?,?)", [("a%d" % (i % 50), str(i % 7), "OPEN", "high", "x") for i in range(500)])
_c.execute("CREATE INDEX hx_v_plugin ON vulns(plugin_id, asset_uuid, state)")       # an older 3-column build
_c.commit(); _c.close()
_cols = dict((n, c) for n, t, c, b in hx.INDEXES)
check(_cols["hx_v_plugin"] == ("plugin_id", "asset_uuid", "state", "severity")
      and _cols["hx_v_asset"] == ("asset_uuid", "plugin_id", "state", "severity"),
      "both vulns indexes carry severity (cover severity filters without reading 5.5 KB rows)")
_st = hx.status(_p)
_it = next(i for i in _st["indexes"] if i["name"] == "hx_v_plugin")
check(_it["outdated"] and not _it["exists"], "an older 3-column hx_v_plugin is reported outdated")
_r = hx.optimize(_p)
_c = _sq3.connect(_p)
_have = [r[2] for r in _c.execute('PRAGMA index_info("hx_v_plugin")')]
_plan = " ".join(r[3] for r in _c.execute("EXPLAIN QUERY PLAN SELECT asset_uuid FROM vulns WHERE plugin_id='3' AND severity='high'"))
_c.close()
check(_r["ok"] and _have == ["plugin_id", "asset_uuid", "state", "severity"], "optimize replaced it with the current columns")
check("COVERING INDEX hx_v_plugin" in _plan, "plugin + severity lookup is answered from the index alone (%s)" % _plan)
check(not [i for i in hx.status(_p)["indexes"] if i.get("outdated")], "nothing outdated after optimize")
_c = _sq3.connect(_p)
_plan2 = " ".join(r[3] for r in _c.execute("EXPLAIN QUERY PLAN SELECT DISTINCT asset_uuid FROM vulns WHERE severity='high'"))
_c.close()
check("COVERING INDEX" in _plan2 or "TEMP B-TREE" in _plan2,
      "DISTINCT asset_uuid by severity: index-only or scan+sort, never a row-by-row index walk (%s)" % _plan2)


# ---- build 455: a reader holding a rollback-journal navi.db → stop cleanly (busy), no traceback ----
_bd = os.path.join(TMP, "busy.db")
_c = sqlite3.connect(_bd)
_c.execute("CREATE TABLE vulns (asset_uuid TEXT, plugin_id TEXT, state TEXT, severity TEXT)")
_c.executemany("INSERT INTO vulns VALUES (?,?,?,?)", [("a%d" % (i % 90), str(i % 9), "OPEN", "high") for i in range(20000)])
_c.commit(); _c.close()
_r = sqlite3.connect(_bd); _cur = _r.execute("SELECT * FROM vulns"); _cur.fetchone()     # SHARED lock held
_orig = hx._rw
hx._rw = lambda path, timeout=30: _orig(path, timeout=1)
_lines = []
_o = hx.optimize(_bd, emit=_lines.append)
hx._rw = _orig
check(_o.get("busy") and not _o["ok"] and not _o["built"] and any("navi.db was busy" in ln for ln in _lines),
      "a long reader on a rollback-journal navi.db → optimize stops with busy=True and a clear line")
_cur.close(); _r.close()
_o2 = hx.optimize(_bd)
check(_o2["ok"] and {b["name"] for b in _o2["built"]} >= {"hx_v_plugin", "hx_v_asset"}, "…and completes once the reader is gone")

if __name__ == "__main__":
    print("\n%d failure(s)" % len(fails))
