"""Regression tests for the Wave 2 integration (build 455):
 1. console.js — the UI side of request budgets: X-Hounds-Tab on every API POST, X-Hounds-Budget
    open → run after the first ▶ Run click / Enter (or a ?run=1 hand-off / page-cache replay),
    the standard budget banner (message | budget_message, ⏳ Run in background, ⚡ Optimize link)
    and budget-limited answers never stored in the page cache; E's hDrill pager still present.
 2. core/identity.py + core/scan_eval.py — their Python parsing loops call db.checkpoint() every
    ~200 rows and a budget stop propagates (no silent empty result).
 3. core/contract.py — Software / AI / Certificates discovery calls the engines directly (never a
    page `run` action) and payload.called_from is gone; run_cycle runs under budget_scope("job").
 4. core/release_recipes.json — Software = software/inventory {} step swRun; core/insights.py
    reads Mimir's inventory count from summary.nasset.
 5. core/launcher.py — a cached answer whose results.db run was pruned is recomputed, background
    stubs say whether the result will be cached, responses over 2 MB are logged (not refused).
Tiny synthetic navi.db + fake hounds — no navi, no network. Run: python3 tests/test_wave2_integration.py"""
import atexit
import io
import json
import os
import re
import shutil
import sqlite3
import sys
import tempfile
from contextlib import redirect_stderr

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
TMP = tempfile.mkdtemp(prefix="hounds-w2i-")
atexit.register(shutil.rmtree, TMP, ignore_errors=True)
os.environ.update({"NAVI_CACHE_DIR": os.path.join(TMP, "cache"),
                   "HOUNDS_CONFIG": os.path.join(TMP, "cfg.json"),
                   "NAVI_HISTORY_DIR": os.path.join(TMP, "hist"),
                   "NAVI_TAGLOG_DB": os.path.join(TMP, "taglog.db")})
for k in ("NAVI_OPEN_BUDGET_S", "NAVI_RUN_BUDGET_S", "NAVI_JOB_BUDGET_S", "NAVI_QUERY_BUDGET_MS"):
    os.environ.pop(k, None)
DB = os.path.join(TMP, "navi.db")
os.environ["NAVI_DB_PATH"] = DB

con = sqlite3.connect(DB)
con.executescript("""
CREATE TABLE assets (uuid TEXT, hostname TEXT, ip_address TEXT, acr REAL);
CREATE TABLE vulns (asset_uuid TEXT, plugin_id TEXT, plugin_name TEXT, output TEXT, state TEXT,
                    severity TEXT, last_found TEXT, xrefs TEXT, score TEXT);
CREATE TABLE tags (asset_uuid TEXT, tag_key TEXT, tag_value TEXT);
CREATE TABLE software (asset_uuid TEXT, software_string TEXT);
""")
con.executemany("INSERT INTO assets VALUES (?,?,?,?)", [("a%d" % i, "h%d" % i, "10.0.0.%d" % i, 5) for i in range(30)])
out95928 = ("----------[ User Accounts ]----------\n\nUser         : alice\nHome folder  : /home/alice\n"
            "Start script : /bin/bash\n\nUser         : bob\nHome folder  : /home/bob\nStart script : /bin/bash\n")
con.executemany("INSERT INTO vulns (asset_uuid, plugin_id, plugin_name, output, state) VALUES (?,?,?,?,?)",
                [("a%d" % (i % 30), "95928", "Linux User List Enumeration", out95928, "open") for i in range(1000)])
con.executemany("INSERT INTO vulns (asset_uuid, plugin_id, plugin_name, output, state) VALUES (?,?,?,?,?)",
                [("a%d" % i, "19506", "Nessus Scan Information",
                  "Scanner IP : 10.9.9.9\nScan name : s1\nScan policy used : p\nScan type : Normal\n"
                  "Credentialed checks : yes, as 'svc' via ssh\nScan duration : 600 sec\n", "open") for i in range(30)])
con.executemany("INSERT INTO software VALUES (?,?)", [("a%d" % i, "openssl-1.1.%d" % (i % 3)) for i in range(30)])
con.commit()
con.close()

from core import db, launcher, payload, snapcache  # noqa: E402

snapcache.CACHE_DIR = os.environ["NAVI_CACHE_DIR"]
fails = []


def check(cond, msg):
    print(("PASS " if cond else "FAIL ") + msg)
    if not cond:
        fails.append(msg)


# ------------------------------------------------------------------ 1. console.js (budgets UI)
JS = open(os.path.join(ROOT, "web", "assets", "console.js"), encoding="utf-8").read()
hb = JS[JS.index("const HB = (function(){"):JS.index("const HC = (function(){")]
check("h.set('X-Hounds-Tab', TAB)" in hb and "h.set('X-Hounds-Budget', S.ran ? (isRunReq(init && init.body) ? 'run-bg' : 'run') : 'open')" in hb,
      "HB sets X-Hounds-Tab (per tab page) and X-Hounds-Budget open→run-bg on API POSTs (build 458: a ▶ Run may detach)")
check("!h.has('X-Hounds-Budget')" in hb, "a caller's own X-Hounds-Budget header wins")
check("isRunBtn(b)" in hb and "hasAttribute('data-run')" in hb and "/^\\s*▶/" in hb and "ev.key!=='Enter'" in hb,
      "the first trusted click on a [data-run] / ▶ button or Enter in its box switches the page to 'run'")
check("run=1" in hb, "a ?run=1 hand-off starts in 'run'")
check(re.search(r"async function drive\(fresh\)\{[^}]*HB\.markRun", JS) is not None,
      "a page-cache replay (HC drive) re-runs under the 'run' budget")
check("j.budget===true || j.budget_partial===true" in hb and "budget_message" in hb,
      "banner raised for {budget:true} and {budget_partial:true} with message | budget_message")
check("b.background=true" in hb and "cached_result" in hb and "/api/jobs/" in hb,
      "⏳ Run in background re-sends the read with background:true and follows the job")
check("j.optimize" in hb and "/web/settings.html#secHx" in hb, "⚡ Optimize link when the payload says optimize")
check("'confirm' in b" in hb and "H_WRITE_RE.test(ap.action)" in hb, "writes are never re-sent in the background")
check("esc(msg)" in hb and "innerHTML='<span class=\"hb-msg\">" in hb, "the banner escapes the server message")
check("(j.ok===false || j.budget || j.budget_partial)" in JS, "HC never stores a budget / budget_partial answer")
check("const WRITE_RE = H_WRITE_RE" in JS, "HC and HB share one write classifier")
check("function hDrill(o)" in JS and "hdrill-pager" in JS, "E's hDrill paged-table helper is intact")
check(re.search(r"\(\"settings\", \"hx_status\"\)", open(os.path.join(ROOT, "core", "launcher.py")).read()) is not None,
      "server still maps page-open reads to 'open' (core/launcher._OPEN_ACTIONS)")

# ------------------------------------------------------------------ 2. Python loops honour budgets
from core import identity, scan_eval  # noqa: E402

calls = []
_real_cp = db.checkpoint
db.checkpoint = lambda what="python work": calls.append(what)
try:
    res = identity.scan()
    n95 = sum(1 for c in calls if "95928" in c)
    check(n95 >= 1000 // 200, "identity: the 95928 parse loop checkpoints every 200 rows (%d calls)" % n95)
    check(any("19506" in c for c in calls) and any("assets" in c for c in calls),
          "identity: the assets + 19506 (scan credential) loops checkpoint too")
    check({a["user"] for a in res["accounts"]} >= {"alice", "bob"}, "identity: result unchanged with checkpoints")
    calls.clear()
    ev = scan_eval.evaluate()
    check(any("19506" in c for c in calls), "scan_eval: the 19506 output-parsing loop checkpoints")
finally:
    db.checkpoint = _real_cp


def stop_at(n):
    seen = [0]

    def cp(what="python work"):
        seen[0] += 1
        if seen[0] >= n:
            raise db.BudgetExceeded("(%s)" % what, 30, "run")
    return cp


for mod, fn, label in ((identity, identity.scan, "identity.scan"), (scan_eval, scan_eval.evaluate, "scan_eval.evaluate")):
    db.checkpoint = stop_at(1)
    try:
        try:
            fn()
            check(False, "%s: a budget stop in the parsing loop propagates" % label)
        except db.BudgetExceeded:
            check(True, "%s: a budget stop in the parsing loop propagates (not swallowed)" % label)
    finally:
        db.checkpoint = _real_cp

# through the launcher: a 'run' request whose budget is spent answers budget:true
os.environ["NAVI_RUN_BUDGET_S"] = "0.001"
import time  # noqa: E402
_real_q = db.query


def slow_query(*a, **k):
    time.sleep(0.01)
    return _real_q(*a, **k)


identity.db.query = slow_query
try:
    body, st = launcher.dispatch("identity", "run", {"_run": "t1"}, http=True, budget_hint="run")
    check(st == 200 and body.get("budget") is True and body.get("ok") is False,
          "identity ▶ Run past its run budget → 200 {ok:false, budget:true}")
finally:
    identity.db.query = _real_q
    os.environ.pop("NAVI_RUN_BUDGET_S", None)

# ------------------------------------------------------------------ 3. the Contract
from core import contract  # noqa: E402

check(not hasattr(payload, "called_from"), "payload.called_from (the Contract special case) is gone")
for f in ("agents/software/api.py", "agents/ai/api.py", "agents/certificate/api.py"):
    check("called_from" not in open(os.path.join(ROOT, f)).read(), f + ": no called_from branch")
_real_ar = contract._agent_run


def no_run(aid):
    if aid in ("software", "ai", "certificate"):
        raise AssertionError("contract called the page action of " + aid)
    return _real_ar(aid)


contract._agent_run = no_run
try:
    items = contract._ad_software({})
    check(any("openssl" in x["label"].lower() for x in items),
          "Contract software discovery reads core.software.analyze() (not the paged `run`)")
    try:
        contract._ad_ai({})
        check(True, "Contract AI discovery reads ai_assets.scan() (not the paged `run`)")
    except AssertionError as e:
        check(False, str(e))
    try:
        contract._ad_certificate({})
    except contract.NeedsInput:
        pass                                   # no certs table here — the adapter says so
    check(True, "Contract certificate discovery does not call the paged `run`")
finally:
    contract._agent_run = _real_ar
src = open(os.path.join(ROOT, "core", "contract.py")).read()
rc = src[src.index("def run_cycle("):src.index("def loop_log(")]
check('with db.budget_scope("job"):' in rc and rc.index('budget_scope("job")') < rc.index("ex = execute("),
      "run_cycle runs discovery / execute under budget_scope('job')")
check(("contract", "run_now") in launcher._JOB_ACTIONS, "run_now requests get the 'job' scope")

seen_scope = []
_real_ex = contract.execute
contract.execute = lambda *a, **k: (seen_scope.append(db.current_scope()), {"plan": {"agents": []}})[1]
_real_notify = contract._notify_run
contract._notify_run = lambda c, e: {"skipped": "test"}
try:
    contract.run_cycle({"armed": False, "optimize": False, "navi_update": False}, enforce_pause=False)
    check(seen_scope and seen_scope[0] is not None and seen_scope[0].label == "job",
          "run_cycle: execute() sees the 'job' budget scope")
finally:
    contract.execute = _real_ex
    contract._notify_run = _real_notify

# ------------------------------------------------------------------ 4. release recipe + insights
from core import release  # noqa: E402

sw = [r for r in release.recipes()["pages"] if r["agent"] == "software"][0]
# build 461: the release runs all four Software widgets (requests_fn builds the dependent reads)
check(sw["steps"][0] == "swRun" and sw["requests"] == [{"agent": "software", "action": "inventory", "body": {}}],
      "Software recipe starts with software/inventory {} (step swRun)")
check(("software", "inventory") in launcher._run_actions(), "…so the launcher treats it as a ▶ Run action")
rsrc = open(os.path.join(ROOT, "core", "release.py")).read()
check('body.get("budget_partial")' in rsrc, "Release never stores a budget_partial answer in the page cache")
isrc = open(os.path.join(ROOT, "core", "insights.py")).read()
check('R("software", "inventory")' in isrc and '"nasset"' in isrc and 'R("software", "run_sql"' not in isrc,
      "On the Scent reads Mimir's inventory count from summary.nasset")

# ------------------------------------------------------------------ 5. launcher cache vs results.db
S = payload.STORE
calls_n = [0]


def fake_run(p):
    calls_n[0] += 1
    with S.begin("w2ifake") as W:
        W.add("t", {"i": calls_n[0]})
    return payload.response(summary={"n": calls_n[0]}, drill={"action": "drill", "run": W.run, "section": "t"}), 200


launcher.DISPATCH["w2ifake"] = {"run": fake_run, "big": lambda p: ({"ok": True, "x": "y" * 10}, 200)}
b1, _ = launcher.dispatch("w2ifake", "run", {}, http=True)
b2, _ = launcher.dispatch("w2ifake", "run", {}, http=True)
check(calls_n[0] == 1 and b2.get("_cached"), "a fresh cached answer is served while its run is stored")
S.drop(b1["drill"]["run"])
b3, _ = launcher.dispatch("w2ifake", "run", {}, http=True)
check(calls_n[0] == 2 and not b3.get("_cached") and S.run_info(b3["drill"]["run"]),
      "a cached answer whose results.db run was pruned is recomputed (not handed back)")
check(launcher._store_runs({"drill": {"run": "x-0123456789abcdef"}, "sub": {"run": "nope"}}) == {"x-0123456789abcdef"},
      "only real store run ids are checked")
stub, st = launcher.dispatch("w2ifake", "run", {"background": True, "zz": 1}, http=True)
check(st == 202 and stub.get("cached_result") is True, "a background stub says its result will be cached")
from core import jobq  # noqa: E402
for _ in range(100):
    j = jobq.get(stub["job_id"]).get("job") or {}
    if j.get("status") in ("done", "error"):
        break
    time.sleep(0.05)
stub2, st2 = launcher.dispatch("explore", "activity", {"background": True}, http=True)
check(stub2.get("cached_result") is False, "…and a no-cache hound's stub says it won't be")

err = io.StringIO()
with redirect_stderr(err):
    small = launcher.note_response("w2ifake", "big", 1000)
    big = launcher.note_response("postquantum", "run", 3 * 1024 * 1024)
check(small is False and big is True and "postquantum/run" in err.getvalue(),
      "a response over 2 MB is logged with its action name (never refused)")
check(launcher.BIG_RESPONSES and launcher.BIG_RESPONSES[-1]["action"] == "run", "…and kept in BIG_RESPONSES")
asrc = open(os.path.join(ROOT, "app_stdlib.py")).read()
check("launcher.note_response(parts[1], parts[2], len(body))" in asrc, "the stdlib server reports every API response size")

print("\n%d failure(s)" % len(fails))
if fails:
    sys.exit(1)


def test_wave2_integration():
    assert not fails, fails
