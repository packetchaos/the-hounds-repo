"""Regression tests — build 477: AI Contract ▸ Release the Hounds pipeline (core/release_pipeline.py).

  · Config is cleaned: unknown update kinds dropped, kinds run in navi's order, ready-by HH:MM.
  · Daily schedule: starts (ready-by − estimate); a late server start before ready-by runs at once;
    weekdays skip the weekend; one run per ready-by slot; estimate = last run + 25 % (≥ 30 min).
  · A run: navi updates one at a time → navi config optimize → ⚡ Optimize → Release the Hounds;
    a failed step is recorded and the rest still run; cancel stops it; history is saved.
  · After tagging: only when the contract cycle applied tags, after the wait.
  · Gates: saving an ON schedule / Run now need confirm === true AND this machine; OFF is free.
  · resume() brings the daily schedule back after a restart; the pages link it.
Run: python3 tests/test_release_pipeline_477.py"""
import atexit
import datetime as dt
import json
import os
import shutil
import sqlite3
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
TMP = tempfile.mkdtemp(prefix="hounds-477-")
atexit.register(shutil.rmtree, TMP, ignore_errors=True)
DB = os.path.join(TMP, "navi.db")
src = "/tmp/claude-0/hp/lab.db" if os.path.exists("/tmp/claude-0/hp/lab.db") else os.path.join(ROOT, "sample_navi.db")
shutil.copy(src, DB)
NAVI = os.path.join(TMP, "navi")
with open(NAVI, "w") as f:
    f.write("#!/bin/sh\necho \"fake navi $*\"\nsleep 1\ncase \"$*\" in *software*) echo boom; exit 3;; esac\nexit 0\n")
os.chmod(NAVI, 0o755)
os.environ.update({"NAVI_DB_PATH": DB, "NAVI_CACHE_DIR": os.path.join(TMP, "cache"), "NAVI_BIN": NAVI,
                   "HOUNDS_CONFIG": os.path.join(TMP, "cfg.json"), "NAVI_TAGLOG_DB": os.path.join(TMP, "t.db")})
fails = []


def check(cond, msg):
    print(("PASS " if cond else "FAIL ") + msg)
    if not cond:
        fails.append(msg)


from core import launcher, release_pipeline as rp  # noqa: E402

# ── 1. config ─────────────────────────────────────────────────────────────────
c = rp.normalize({"enabled": "yes", "ready_by": "6:5", "updates": ["software", "bogus", "vulns", "assets"],
                  "wait_minutes": "99999", "days": "WEEKDAYS", "skip": ["eol", "", "eol"], "hx_optimize": "false"})
check(c["enabled"] is True and c["ready_by"] == "06:05" and c["days"] == "weekdays", "normalize: flags, HH:MM, days")
check(c["updates"] == ["assets", "vulns", "software"], "normalize: unknown kinds dropped, navi's order kept")
check(c["wait_minutes"] == 720 and c["skip"] == ["eol"] and c["hx_optimize"] is False, "normalize: clamps, de-dup, 'false' is off")
check(rp.normalize({"ready_by": "25:99"})["ready_by"] == "07:00", "normalize: bad time → 07:00")
check(rp.default_config()["updates"] == ["assets", "vulns", "certificates", "software"],
      "default updates: assets, vulns, certificates, software")

# ── 2. schedule maths ─────────────────────────────────────────────────────────
on = rp.normalize({"enabled": True, "daily": True, "ready_by": "07:00"})


def at(y, mo, d, h, mi):
    return dt.datetime(y, mo, d, h, mi).timestamp()


check(rp.estimate_s() == rp.DEFAULT_EST_S, "no history: estimate 3 h")
t, ready = rp.next_run(on, now=at(2026, 11, 18, 1, 0))      # Wednesday 01:00
check(ready == dt.datetime(2026, 11, 18, 7, 0) and t == at(2026, 11, 18, 4, 0), "ready 07:00, 3 h estimate → starts 04:00")
t, ready = rp.next_run(on, now=at(2026, 11, 18, 5, 30))
check(t == at(2026, 11, 18, 5, 30) and ready.day == 18, "server up late (05:30, before 07:00) → starts at once")
t, ready = rp.next_run(on, now=at(2026, 11, 18, 8, 0))
check(ready == dt.datetime(2026, 11, 19, 7, 0), "after today's ready-by → tomorrow")
wk = dict(on, days="weekdays")
t, ready = rp.next_run(wk, now=at(2026, 11, 20, 8, 0))      # Friday 08:00
check(ready == dt.datetime(2026, 11, 23, 7, 0), "weekdays: Friday after 07:00 → Monday")
check(rp.next_run(rp.normalize({"enabled": False}), now=at(2026, 11, 18, 1, 0)) == (None, None), "off → no next run")
check(rp.next_run(dict(on, daily=False), now=at(2026, 11, 18, 1, 0)) == (None, None), "daily unticked → no next run")
rp._write({"last_slot": "2026-11-18 07:00"})
t, ready = rp.next_run(on, now=at(2026, 11, 18, 5, 0))
check(ready == dt.datetime(2026, 11, 19, 7, 0), "today's slot already ran → tomorrow (one run per ready-by)")
rp._write({"history": [{"id": "x", "status": "done", "total_s": 2 * 3600, "trigger": "daily"}]})
check(rp.estimate_s() == int(2 * 3600 * 1.25), "estimate = last run 2 h + 25 % = 2 h 30")
rp._write({"history": [{"id": "x", "status": "done", "total_s": 60, "trigger": "manual"}]})
check(rp.estimate_s() == rp.MIN_LEAD_S, "estimate never under 30 min")
rp._write({})

# ── 3. a run (fake navi; real ⚡ Optimize + Release on a lab copy) ─────────────
from core import release  # noqa: E402
runnable = [i["agent"] for i in release.plan()["items"] if i.get("run")]
skip = [a for a in runnable if a not in ("eol", "insights")]
r = rp.start("manual", cfg={"enabled": True, "updates": ["assets", "vulns", "software"], "navi_optimize": True,
                            "hx_optimize": True, "release": True, "skip": skip})
check(r["ok"] and [s["key"] for s in r["state"]["steps"]] ==
      ["update:assets", "update:vulns", "update:software", "navi_optimize", "hx_optimize", "release"],
      "steps in order: updates → navi optimize → ⚡ Optimize → release")
check(rp.start("manual")["already_running"], "a second start reports the running pipeline")
t0 = time.time()
while rp.state()["status"] == "running" and time.time() - t0 < 300:
    time.sleep(1)
st = rp.state()
by = {s["key"]: s for s in st["steps"]}
check(by["update:assets"]["status"] == "done" and by["update:vulns"]["status"] == "done", "assets + vulns synced")
check(by["update:software"]["status"] == "error" and "exit 3" in by["update:software"]["note"],
      "a failing sync is recorded (exit 3) …")
check(by["navi_optimize"]["status"] == "done" and by["hx_optimize"]["status"] == "done",
      "… and the steps after it still run (navi optimize, ⚡ Optimize)")
check(by["release"]["status"] == "done" and "2 hound(s)" in by["release"].get("note", "") or
      "populated" in by["release"].get("note", ""), "release ran the selected hounds (%s)" % by["release"].get("note"))
check(st["status"] == "error" and rp.history()[0]["id"] == st["id"], "run marked error (one step failed) and saved")
from core import cli_jobs  # noqa: E402
kinds = [j["kind"] for j in reversed(cli_jobs.recent())]
check(kinds[:5] == ["assets", "vulns", "software", "optimize", "hx_optimize"], "jobs ran one after another: %s" % kinds[:5])

# cancel during the wait step
r = rp.start("manual", wait_s=600, cfg={"updates": ["assets"], "navi_optimize": False, "hx_optimize": False,
                                         "release": False})
time.sleep(1)
check(rp.cancel(), "cancel accepted while running")
t0 = time.time()
while rp.state()["status"] == "running" and time.time() - t0 < 30:
    time.sleep(0.5)
st = rp.state()
check(st["status"] == "cancelled" and all(s["status"] == "cancelled" for s in st["steps"]),
      "cancel stops at the wait; later steps never start")
check(rp.start("manual", cfg={"updates": [], "navi_optimize": False, "hx_optimize": False, "release": False})["ok"] is False,
      "nothing picked → refused")

# ── 4. after tagging ──────────────────────────────────────────────────────────
rp.save_config({"enabled": True, "daily": False, "after_tagging": False})
check("skipped" in rp.after_cycle(applied=True), "after-tagging off → skipped")
rp.save_config({"enabled": True, "daily": False, "after_tagging": True, "wait_minutes": 30,
                "updates": ["assets"], "navi_optimize": False, "hx_optimize": False, "release": False})
check("skipped" in rp.after_cycle(applied=False), "a plan-only cycle (nothing applied) → skipped")
a = rp.after_cycle(applied=True)
st = rp.state()
check(a.get("started") and st["trigger"] == "after_tagging" and st["steps"][0]["key"] == "wait"
      and "30 min" in st["steps"][0]["label"], "applied cycle → pipeline starts with the 30-min wait")
rp.cancel()
t0 = time.time()
while rp.state()["status"] == "running" and time.time() - t0 < 30:
    time.sleep(0.5)
src_c = open(os.path.join(ROOT, "core", "contract.py"), encoding="utf-8").read()
check("release_pipeline.after_cycle(applied=live and wrote)" in src_c and "queued_tags" in src_c,
      "contract.run_cycle hands off to the pipeline — only when the live cycle actually wrote something")

# ── 5. gates + API ────────────────────────────────────────────────────────────
b, s = launcher.dispatch("contract", "release_save", {"config": {"enabled": True, "daily": True}})
check(s == 400 and b.get("needs_confirm"), "saving an ON schedule without confirm → 400")
b, s = launcher.dispatch("contract", "release_run", {"config": {"updates": ["assets"]}})
check(s == 400, "Run now without confirm → 400")
REMOTE = {"peer": "10.9.8.7", "http": True}           # what the HTTP server passes for a remote browser
b, s = launcher.dispatch("contract", "release_save", {"config": {"enabled": True, "daily": True}, "confirm": True}, **REMOTE)
check(s == 403, "a remote browser can't turn the schedule on (403)")
b, s = launcher.dispatch("contract", "release_run", {"confirm": True}, **REMOTE)
check(s == 403, "a remote browser can't Run now (403)")
b, s = launcher.dispatch("contract", "release_save", {"config": {"enabled": False}}, **REMOTE)
check(s == 200 and b["config"]["enabled"] is False, "turning it OFF is always allowed")
b, s = launcher.dispatch("contract", "release_save",
                         {"config": {"enabled": True, "daily": True, "ready_by": "06:30"}, "confirm": True})
check(s == 200 and b["config"]["ready_by"] == "06:30" and b["scheduler"] and b["next_start"],
      "confirmed save on this machine → scheduled, next start given")
check(json.load(open(os.path.join(TMP, "cache", "release_pipeline.json")))["config"]["ready_by"] == "06:30",
      "schedule saved to CACHE_DIR/release_pipeline.json")
b, s = launcher.dispatch("contract", "release_get", {})
check(s == 200 and b["config"]["enabled"] and len(b["update_kinds"]) == len(rp.UPDATE_ORDER), "release_get: status + update kinds")
check(("contract", "release_get") in launcher._OPEN_ACTIONS and "release_get" in launcher._LIVE, "release_get is a live read")

# ── 6. resume after a restart ─────────────────────────────────────────────────
rp.scheduler_stop()
time.sleep(0.2)
check(not rp.scheduler_running(), "scheduler stopped (simulated restart)")
check(rp.resume().get("running") and rp.scheduler_running(), "resume() brings the daily schedule back")
rp.save_config({"enabled": False})
check(not rp.scheduler_running() and rp.resume().get("running") is False, "off → nothing resumed")
app = open(os.path.join(ROOT, "app_stdlib.py"), encoding="utf-8").read()
check("_resume_schedules()" in app and "release_pipeline.resume()" in app, "app_stdlib resumes at startup")
for f in ("app_flask.py", "app_fastapi.py"):
    check("_rp.resume()" in open(os.path.join(ROOT, f), encoding="utf-8").read(), "%s resumes at startup" % f)

# ── 6b. review fixes ──────────────────────────────────────────────────────────
import threading  # noqa: E402
from core import contract as _contract  # noqa: E402
check(rp.normalize({"wait_minutes": "inf"})["wait_minutes"] == 30, "normalize: wait_minutes 'inf' → default, no OverflowError")
rp._write({"history": ["junk", {"id": "a", "status": "done", "total_s": "abc"}]})
try:
    _st = rp.status()
    check(_st["estimate_s"] == rp.DEFAULT_EST_S, "damaged history entries don't break release_get")
except Exception as e:  # noqa: BLE001
    check(False, "damaged history entries don't break release_get (%s)" % e)
rp._write({})
if hasattr(time, "tzset"):
    _tz = os.environ.get("TZ")
    os.environ["TZ"] = "America/New_York"
    time.tzset()
    try:
        t, ready = rp.next_run(rp.normalize({"enabled": True, "daily": True, "ready_by": "03:30"}),
                               now=dt.datetime(2027, 3, 13, 20, 0).timestamp())
        check(ready.timestamp() - t == rp.DEFAULT_EST_S, "DST spring-forward night: the start keeps the full 3 h lead")
    finally:
        if _tz is None:
            os.environ.pop("TZ", None)
        else:
            os.environ["TZ"] = _tz
        time.tzset()
# the AI Contract's own navi update and the pipeline's syncs never run at once
_maxc, _stop = [0], threading.Event()


def _mon():
    while not _stop.is_set():
        _maxc[0] = max(_maxc[0], len([j for j in cli_jobs.running() if j.get("kind") != "hx_optimize"]))
        time.sleep(0.1)


threading.Thread(target=_mon, daemon=True).start()
rp.start("manual", cfg={"updates": ["assets", "vulns", "certificates"], "navi_optimize": False,
                        "hx_optimize": False, "release": False})
time.sleep(0.5)
_contract._navi_update_bg()
t0 = time.time()
while (rp.state()["status"] == "running" or cli_jobs.running()) and time.time() - t0 < 120:
    time.sleep(0.5)
time.sleep(6)
while cli_jobs.running() and time.time() - t0 < 120:
    time.sleep(0.5)
_stop.set()
check(_maxc[0] == 1, "pipeline + contract navi update: never two navi syncs at once (max %d)" % _maxc[0])
# cancelling the pipeline never cancels a release the user started by hand
_orig = (release.state, release.cancel)
_called = []
release.state = lambda: {"status": "running"}
release.cancel = lambda: _called.append(1)
rp._CANCEL.set()
try:
    ok_, note_ = rp._do_release(0, rp.normalize({}))
finally:
    release.state, release.cancel = _orig
    rp._CANCEL.clear()
check(not ok_ and not _called, "pipeline cancel leaves a hand-started release alone")

# ── 7. pages ──────────────────────────────────────────────────────────────────
pg = open(os.path.join(ROOT, "agents", "contract", "page.html"), encoding="utf-8").read()
check('id="release"' in pg and "release_save" in pg and "confirm:true" in pg and "rpUpdates" in pg,
      "contract page: Release the Hounds section (save / run with confirm)")
ix = open(os.path.join(ROOT, "web", "index.html"), encoding="utf-8").read()
check('href="/agents/contract/page.html#release"' in ix and "release_get" in ix, "home: widget links the schedule")
check("Checking navi.db" in ix, "home: the Release button says it is checking navi.db")
check('id="rpSave" disabled' in pg and "load(first||!RP)" in pg, "contract page: Save waits for the form to be filled (a failed first load can't save a blank schedule)")
check("setTimeout(relSched, 60000); return;" in ix, "home: the schedule line keeps polling after an error")

print()
print("%d failure(s)" % len(fails) if fails else "ALL PASS")
sys.exit(1 if fails else 0)
