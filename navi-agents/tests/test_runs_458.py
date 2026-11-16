"""Regression tests — build 458: long runs, explicit-run pages, AI inventory.

  · no hound times out under 2 hours (run / job budgets)
  · a console ▶ Run (X-Hounds-Budget: run-bg) DETACHES when it takes longer than the foreground
    wait: 202 {pending, job_id, started, now}, it keeps running as a job, an identical ▶ attaches
    to it, its result is served from the cache afterwards (until navi.db changes), and it can be
    cancelled; writes, hub/settings and peeks never detach; one Runs-log entry per run
  · the console shows a detached run's elapsed time and resolves the page's request with the
    result (static checks of console.js) + /api/jobs/cancel in all three servers
  · pages that used to load on open (ACR, Agent Groups, Tag Removal, MCP Compare, Alert
    suggestions, the Compliance Dashboard) wait for ▶
  · AI inventory: a step stopped by its budget is reported (partial), not silently dropped; a
    user's cancel stops the scan
Synthetic; no Tenable. Run: python3 tests/test_runs_458.py"""
import atexit
import os
import re
import shutil
import sqlite3
import sys
import tempfile
import time
import faulthandler; faulthandler.dump_traceback_later(240, exit=True)

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
TMP = tempfile.mkdtemp(prefix="hounds-458-")
atexit.register(shutil.rmtree, TMP, ignore_errors=True)
DB = os.path.join(TMP, "navi.db")
for k in ("NAVI_RUN_BUDGET_S", "NAVI_JOB_BUDGET_S", "NAVI_BUDGET_JOB_S", "NAVI_BUDGET_RUN_S"):
    os.environ.pop(k, None)
os.environ.update({"NAVI_CACHE_DIR": os.path.join(TMP, "cache"), "HOUNDS_CONFIG": os.path.join(TMP, "cfg.json"),
                   "NAVI_TAGLOG_DB": os.path.join(TMP, "taglog.db"), "NAVI_HISTORY_DIR": os.path.join(TMP, "hist"),
                   "NAVI_DB_PATH": DB, "HOUNDS_FOREGROUND_S": "0.6"})
c = sqlite3.connect(DB)
c.execute("""CREATE TABLE vulns (asset_uuid text, plugin_id text, plugin_name text, plugin_family text,
             severity text, state text, output text, port text, xrefs text, score text)""")
c.execute("CREATE TABLE assets (uuid text, hostname text, ip_address text)")
c.execute("INSERT INTO vulns VALUES ('11111111-1111-1111-1111-111111111111','1','Ollama Detection','Service detection','info','OPEN','ollama api on port 11434','11434','','')")
c.commit()
c.close()

from core import db, jobq, launcher  # noqa: E402

fails = []


def check(cond, msg):
    print(("PASS " if cond else "FAIL ") + msg)
    if not cond:
        fails.append(msg)


# ── budgets ──────────────────────────────────────────────────────────────────────────────────
sb = db.scope_budgets()
check(sb["run"] >= 7200 and sb["job"] >= 7200, "run / job scope budgets are at least 2 h (%s)" % sb)
check(db.BUDGETS["run"] >= 7200 and db.BUDGETS["job"] >= 7200, "the explicit 'run' / 'job' presets are at least 2 h")

# ── detached runs ─────────────────────────────────────────────────────────────────────────────
calls = {"slow": 0}


def slow(p):
    calls["slow"] += 1
    t = time.time()
    try:
        while time.time() - t < float(p.get("secs", 1.5)):
            db.checkpoint()
            time.sleep(0.03)
    except db.QueryTimeout:
        return {"ok": False, "cancelled": True}, 200
    return {"ok": True, "q": p.get("q"), "scope": getattr(db.current_scope(), "label", None)}, 200


def quick(p):
    return {"ok": True, "quick": True}, 200


launcher.DISPATCH["fakehound"] = {"run": slow, "quick": quick, "apply": slow}
launcher.DISPATCH["hub"] = dict(launcher.DISPATCH.get("hub") or {}, slowhub=slow)

b, st = launcher.dispatch("fakehound", "quick", {"_run": "a"}, budget_hint="run-bg", tab="t")
check(st == 200 and b.get("quick"), "a quick ▶ Run answers inline, as before")
t0 = time.time()
b, st = launcher.dispatch("fakehound", "run", {"q": 1, "_run": "r1"}, budget_hint="run-bg", tab="t")
check(st == 202 and b.get("pending") and b.get("job_id") and b.get("now"),
      "a long ▶ Run answers 202 pending with its job id after the foreground wait")
check(time.time() - t0 < 1.5, "…after about HOUNDS_FOREGROUND_S, not the whole run")
b2, st2 = launcher.dispatch("fakehound", "run", {"q": 1, "_run": "r2"}, budget_hint="run-bg", tab="t2")
check(b2.get("job_id") == b.get("job_id"), "an identical ▶ Run while it runs attaches to the same job")
for _ in range(60):
    j = jobq.get(b["job_id"])
    if j["status"] in ("done", "error"):
        break
    time.sleep(0.1)
check(j["status"] == "done" and j["result"].get("q") == 1 and j["result"].get("scope") == "run",
      "the detached run finishes under the 2 h 'run' scope (not heavy) with its result on the job")
gj = launcher.jobs_get(b["job_id"])
check(gj.get("ok") and gj.get("now") and gj["job"].get("started"), "/api/jobs/<id> returns the server clock for elapsed time")
recs = [x for x in jobq.list_jobs() if x.get("agent") == "fakehound" and x.get("action") == "run"]
check(len(recs) == 1, "one Runs-log entry per detached run (no duplicate 'record' row) (%d)" % len(recs))
n = calls["slow"]
t0 = time.time()
b3, st3 = launcher.dispatch("fakehound", "run", {"q": 1, "_run": "r3"}, budget_hint="run-bg", tab="t")
check(st3 == 200 and b3.get("_cached") and calls["slow"] == n and time.time() - t0 < 0.5,
      "afterwards the same ▶ Run is served from the cache instantly (no new job)")
key = launcher._cache_key("fakehound", "run", {"q": 1})
check(len(launcher._CACHE.get(key, ())) >= 3 and launcher._CACHE[key][2] >= 3600,
      "a detached run's result is kept far longer than the 5-minute read cache")
with sqlite3.connect(DB) as cc:
    cc.execute("INSERT INTO assets VALUES ('x','x','1.2.3.4')")
time.sleep(0.05)
check(launcher._cache_hit(key, time.time()) is None, "…until navi.db changes (a sync)")

b4, st4 = launcher.dispatch("fakehound", "run", {"q": 9, "secs": 30, "_run": "r4"}, budget_hint="run-bg", tab="t")
check(st4 == 202, "a second long run detaches")
check(launcher.jobs_cancel(b4["job_id"]).get("ok"), "a detached run can be cancelled (/api/jobs/cancel)")
for _ in range(60):
    j4 = jobq.get(b4["job_id"])
    if j4["status"] in ("done", "error"):
        break
    time.sleep(0.1)
check(j4["status"] in ("done", "error") and (j4.get("result") or {}).get("cancelled"), "…and stops")

b5, st5 = launcher.dispatch("fakehound", "apply", {"confirm": True, "secs": 0.8}, budget_hint="run-bg", tab="t")
check(st5 == 200 and not b5.get("pending"), "a write never detaches (it runs to the end inline)")
b6, st6 = launcher.dispatch("hub", "slowhub", {"secs": 0.8}, budget_hint="run-bg", tab="t")
check(not b6.get("pending"), "hub / settings actions never detach")
b7, st7 = launcher.dispatch("fakehound", "run", {"q": 7, "secs": 0.8, "peek": True}, budget_hint="run-bg", tab="t")
check(not b7.get("pending"), "a peek never detaches")
b8, st8 = launcher.dispatch("fakehound", "run", {"q": 8, "secs": 0.8}, budget_hint="run", tab="t")
check(not b8.get("pending") and b8.get("scope") == "run", "without the console's run-bg hint nothing detaches (MCP, scripts)")


# ── sweep of 458: start-time keys, caps, pools, boot ─────────────────────────────────────────
DB2 = os.path.join(TMP, "other.db")
shutil.copy(DB, DB2)


def switcher(p):
    t = time.time()
    while time.time() - t < 1.2:
        time.sleep(0.03)
    return {"ok": True, "db": os.path.basename(db.db_path())}, 200


def syncer(p):
    with sqlite3.connect(DB) as cc:
        cc.execute("INSERT INTO assets VALUES ('y','y','5.6.7.8')")
    time.sleep(1.0)
    return {"ok": True, "n": 1}, 200


launcher.DISPATCH["fakehound"].update(sw=switcher, sync=syncer)
b, st = launcher.dispatch("fakehound", "sw", {"_run": "s1"}, budget_hint="run-bg", tab="t")
os.environ["NAVI_DB_PATH"] = DB2                     # Settings switches navi.db mid-run
for _ in range(60):
    if jobq.get(b["job_id"])["status"] == "done":
        break
    time.sleep(0.1)
kb = launcher._cache_key("fakehound", "sw", {})
check(launcher._cache_hit(kb, time.time()) is None, "a run that outlives a navi.db switch is not served on the new navi.db")
b2, st2 = launcher.dispatch("fakehound", "sw", {"_run": "s2"}, budget_hint="run-bg", tab="t")
check(st2 == 202 and b2.get("job_id") != b.get("job_id"), "…and a ▶ Run on the new navi.db starts its own job")
os.environ["NAVI_DB_PATH"] = DB
for _ in range(60):
    if jobq.get(b2["job_id"])["status"] == "done":
        break
    time.sleep(0.1)
b3, st3 = launcher.dispatch("fakehound", "sync", {"_run": "y1"}, budget_hint="run-bg", tab="t")
for _ in range(60):
    if jobq.get(b3["job_id"])["status"] == "done":
        break
    time.sleep(0.1)
check(launcher._cache_hit(launcher._cache_key("fakehound", "sync", {}), time.time()) is None,
      "a sync that lands during a run discards that run's cached result")
check(b3.get("boot") == jobq.BOOT and launcher.jobs_get(b3["job_id"]).get("boot") == jobq.BOOT
      and launcher.jobs_list().get("boot") == jobq.BOOT, "202 / jobs answers carry the server boot id")
check(jobq.get(b3["job_id"]).get("pool") == "run", "detached runs use their own worker pool")

os.environ["HOUNDS_MAX_DETACHED_AGENT"] = "2"
launcher._MAX_RUNS_AGENT = 2
ids = []
for i in range(2):
    x, s_ = launcher.dispatch("fakehound", "run", {"q": 100 + i, "secs": 6}, budget_hint="run-bg", tab="t")
    ids.append(x.get("job_id"))
x, s_ = launcher.dispatch("fakehound", "run", {"q": 200, "secs": 6}, budget_hint="run-bg", tab="t")
check(s_ == 429 and x.get("busy"), "more ▶ Runs of one hound than the cap answer 429 busy (no unbounded jobs)")
fake_write = jobq.submit(lambda: (time.sleep(2), {"ok": True})[1], {"agent": "fakehound", "action": "tag"})
check(launcher.jobs_cancel(fake_write["id"]).get("ok") is False, "the page's Cancel can't stop a confirmed write / snapshot job")
for i in ids:
    launcher.jobs_cancel(i)
check(launcher.jobs_cancel(1e400).get("ok") is False and jobq.get(1e400) is None, "a huge / infinite job id is refused, not a crash")
jobq._KEEP_RESULTS = 1
for i in range(3):
    x, s_ = launcher.dispatch("fakehound", "quick", {"n": i, "_nocache": True}, budget_hint="run-bg", tab="t")
time.sleep(0.3)
kept = [j for j in jobq._JOBS if j.get("pool") == "run" and j.get("result") is not None]
check(len(kept) <= 1, "finished ▶ Runs don't keep their results in memory beyond the newest few (%d)" % len(kept))

# ── the console + servers ─────────────────────────────────────────────────────────────────────
JS = open(os.path.join(ROOT, "web", "assets", "console.js"), encoding="utf-8").read()
hb = JS[JS.index("const HB = (function(){"):JS.index("const HC = (function(){")]
check("isRunReq(init && init.body) ? 'run-bg' : 'run'" in hb and "r.status===202" in hb and "RUNS.wait(j, ap)" in hb,
      "console: a ▶ Run sends run-bg and waits for a 202 pending run")
check("Still running" in hb and "fmt(sec)" in hb and "/api/jobs/cancel" in hb and "new Response(" in hb,
      "console: the run shows its elapsed time, can be cancelled, and resolves the page's request")
check("localStorage.setItem(SKEY" in hb and "resume" in hb and "▶ Show results" in hb,
      "console: a run started earlier on this page is shown when you come back")
for app in ("app_stdlib.py", "app_flask.py", "app_fastapi.py"):
    check("/api/jobs/cancel" in open(os.path.join(ROOT, app), encoding="utf-8").read(), "%s serves /api/jobs/cancel" % app)


# ── bug sweep of 458: heavy slot, quick reads, stale re-stamp, cache-only replays ─────────────
seen_scope = {}


def probe(p):
    sc = db.current_scope()
    seen_scope.update(label=getattr(sc, "label", None), heavy=getattr(sc, "heavy", None))
    time.sleep(0.8)
    return {"ok": True}, 200


launcher.DISPATCH["fakehound"].update(probe=probe, drill=quick, add_to_contract=quick, run_status=quick)
x, s_ = launcher.dispatch("fakehound", "probe", {"_run": "h"}, budget_hint="run-bg", tab="t")
for _ in range(50):
    if seen_scope:
        break
    time.sleep(0.1)
check(seen_scope.get("label") == "run" and seen_scope.get("heavy") is False,
      "a detached run uses the non-heavy 2 h 'run' scope (one long run can't serialise every other ▶) %s" % seen_scope)
check(not launcher._detachable("fakehound", "drill", {}) and not launcher._detachable("fakehound", "run_status", {}),
      "drill-downs / status polls never detach")
check(not launcher._detachable("fakehound", "add_to_contract", {}), "a write-named action never detaches, even without confirm")
check(launcher._detachable("fakehound", "run", {}), "a hound's run still detaches")

# a ↻ fresh run must not revive an older cached entry for 24 h
launcher._CACHE.clear()
k = launcher._cache_key("fakehound", "quick", {"z": 1})
launcher._CACHE[k] = (time.time() - 100, ({"ok": True, "old": True}, 200))
launcher.dispatch("fakehound", "quick", {"z": 1, "_nocache": True}, budget_hint="run-bg", tab="t")
time.sleep(0.3)
check(len(launcher._CACHE.get(k, ())) < 3, "a ↻ fresh / uncached run doesn't re-stamp an older entry as a 24 h result")

# page-cache replay of a ▶ step: cache-only, never a full run on page open
launcher._CACHE.clear()
calls["slow"] = 0
r1, st1 = launcher.dispatch("fakehound", "run", {"q": 55, "secs": 8, "_cacheonly": True}, budget_hint="run-bg", tab="t")
check(r1.get("not_cached") and calls["slow"] <= 1 and not r1.get("pending"),
      "a replayed ▶ with nothing cached answers not_cached (5 s 'open' budget), never a detached run")
launcher._CACHE[launcher._cache_key("fakehound", "run", {"q": 56})] = (time.time(), ({"ok": True, "q": 56}, 200))
r2, st2 = launcher.dispatch("fakehound", "run", {"q": 56, "_cacheonly": True}, budget_hint="run-bg", tab="t")
check(r2.get("q") == 56 and r2.get("_cached"), "a replayed ▶ is served from the server cache when it has the answer")
check("extra._cacheonly = true" in JS, "console: replay misses are sent cache-only")

# ── explicit-run pages ────────────────────────────────────────────────────────────────────────
def page(p):
    return open(os.path.join(ROOT, p), encoding="utf-8").read()


def tail_script(h):
    return h[h.rindex("<script"):]


acr = page("agents/acr/page.html")
check(not re.search(r"^runAcr\(\); loadMetrics\(\);", acr, re.M) and 'id="runAcr" class="btn run sm" data-run' in acr,
      "ACR: nothing loads on open; ▶ Load")
ag = page("agents/agentgroup/page.html")
check(not re.search(r"^load\(\);", ag, re.M) and 'id="load" style="margin-left:auto" class="btn run sm" data-run' in ag,
      "Agent Groups: no live Tenable call on open; ▶ Load")
tr = page("agents/tagremoval/page.html")
check(not re.search(r"^(compare|loadDelta|load)\(\);", tr, re.M) and "onclick=()=>{ load(); compare(); loadDelta(); }" in tr,
      "Tag Removal: no navi.db read or Tenable call on open; ▶ Load runs all three")
mc = page("agents/mcpcmp/page.html")
check(not re.search(r"^snap\(\);", mc, re.M), "MCP Compare: the snapshot waits for ▶ Load")
al = page("agents/alert/page.html")
check("API.post('suggest')" not in al[al.index("async function load(){"):al.index("function renderHistory")]
      and 'id="refreshSug" data-run' in al, "Alerting: suggestions (live counts) wait for ▶ Suggest")
cd = page("web/compliancedash.html")
check("CAPI.post('overview')" not in cd and "lb.onclick=()=>{ lb.onclick=reload; res(); }" in cd,
      "Compliance Dashboard: waits for ▶ Load and no longer runs the compliance overview for the write flag")

# ── AI inventory: partial steps reported, cancel propagates ──────────────────────────────────
from core import ai_assets  # noqa: E402
orig = db.iter


def boom_budget(sql, *a, **k):
    if "AS m3" in sql:
        raise db.BudgetExceeded(sql, 7200, "run")
    return orig(sql, *a, **k)


db.iter = boom_budget
try:
    r = ai_assets.scan()
finally:
    db.iter = orig
check(r.get("ok") and "plugin output / endpoints" in (r.get("partial") or []) and r.get("budget_partial"),
      "AI: a step stopped by its budget is reported as partial (was silently dropped)")


def boom_cancel(sql, *a, **k):
    if "AS m3" in sql:
        raise db.QueryCancelled(sql)
    return orig(sql, *a, **k)


db.iter = boom_cancel
try:
    try:
        ai_assets.scan()
        raised = False
    except db.QueryCancelled:
        raised = True
finally:
    db.iter = orig
check(raised, "AI: a cancel stops the whole scan (not a silent partial result)")
r2 = ai_assets.scan()
check(r2.get("ok") and r2.get("partial") == [] and not r2.get("budget_partial"), "AI: a full scan has no partial steps")

print("\n%d failure(s)" % len(fails))
sys.exit(1 if fails else 0)
