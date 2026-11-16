"""Release pipeline — keep the pack ready before anyone logs in (AI Contract ▸ Release the Hounds).

One pipeline, in this order, each step waiting for the one before it:

  1. (after tagging only) wait N minutes, so Tenable has applied the tags the cycle just queued
  2. the navi updates you pick — `navi config update assets`, `… vulns`, `navi config certificates`,
     `navi config software`, compliance, fixed, WAS … (core/cli_jobs.COMMANDS; one at a time —
     two syncs at once lock navi.db)
  3. `navi config optimize`          (navi's own SQL indexes)
  4. ⚡ Optimize for the Hounds      (core/hx_optimize: the Hounds' indexes + summary tables)
  5. Release the Hounds              (core/release: every selected hound, so each page is already
                                      populated — hounds whose data is missing are skipped)

Two triggers, either or both:
  · daily  — "ready by" a time (server-local clock). The start time is worked out from how long the
             last pipeline took (+25 %, at least 30 min; 3 h before there is a last run), so the pack
             is ready at that time. If the server comes up after the start time but before the
             ready-by time, it starts at once.
  · after tagging — at the end of every AI Contract cycle that applied tags, after the wait.
Plus "Run now" from the AI Contract page.

What it writes: navi.db (the syncs, navi's optimize, ⚡ Optimize's indexes / summaries) and the
page cache. It never writes to Tenable — no tags, ACR or sends. Saving the schedule / Run now need
confirm === true and a browser on this machine (the same rule as ⚡ Optimize).

The schedule and the run history are saved to CACHE_DIR/release_pipeline.json and resumed when the
server starts (resume()), so a restart does not drop the morning release.
"""
import datetime as _dt
import json
import os
import threading
import time

from core import snapcache
from core.security import private_open as _popen

# navi update kinds offered, in the order they run (assets before vulns — navi's own order)
UPDATE_ORDER = ["assets", "vulns", "certificates", "software", "compliance", "fixed", "was",
                "agents", "routes", "paths", "plugins", "epss", "sla_calc"]
UPDATE_LABELS = {
    "assets": "Assets", "vulns": "Vulnerabilities", "certificates": "Certificates",
    "software": "Software", "compliance": "Compliance", "fixed": "Fixed (remediated)",
    "was": "WAS web apps", "agents": "Agents", "routes": "Routes", "paths": "Paths",
    "plugins": "Plugins", "epss": "EPSS scores", "sla_calc": "SLA verdicts (navi config sla calculate)",
}
DEFAULT_UPDATES = ["assets", "vulns", "certificates", "software"]
DEFAULT_EST_S = 3 * 3600          # before the first run: assume 3 h
MIN_LEAD_S = 30 * 60
MARGIN = 1.25
STEP_MAX_S = 6 * 3600             # a big tenant's vulns sync can take hours
IDLE_MAX_S = 3 * 3600             # wait at most this long for another navi job to finish
HISTORY_KEEP = 20

_LOCK = threading.Lock()
_STATE = {"status": "idle"}       # the running / last pipeline
_CANCEL = threading.Event()
_SCHED = {"thread": None, "stop": threading.Event()}


# ---------------------------------------------------------------- config
def default_config() -> dict:
    return {"enabled": False,
            "daily": True, "ready_by": "07:00", "days": "every",       # every | weekdays
            "after_tagging": False, "wait_minutes": 30,
            "updates": list(DEFAULT_UPDATES),
            "navi_optimize": True, "hx_optimize": True,
            "release": True, "approve_downloads": False, "skip": []}    # hounds left out (else every one that can run)


def _hhmm(v, default="07:00"):
    try:
        h, m = str(v).strip().split(":")[:2]
        h, m = int(h), int(m)
        if 0 <= h <= 23 and 0 <= m <= 59:
            return "%02d:%02d" % (h, m)
    except (ValueError, AttributeError):
        pass
    return default


def _bool(v):
    return v is True or (isinstance(v, str) and v.strip().lower() in ("1", "true", "yes", "on")) or v == 1


def normalize(cfg) -> dict:
    """A clean config from whatever the page / file sent (unknown kinds dropped, numbers clamped)."""
    d = default_config()
    c = cfg if isinstance(cfg, dict) else {}
    for k in ("enabled", "daily", "after_tagging", "navi_optimize", "hx_optimize", "release",
              "approve_downloads"):
        if k in c:
            d[k] = _bool(c[k])
    d["ready_by"] = _hhmm(c.get("ready_by", d["ready_by"]))
    d["days"] = "weekdays" if str(c.get("days") or "").strip().lower() == "weekdays" else "every"
    try:
        d["wait_minutes"] = max(0, min(720, int(float(c.get("wait_minutes", d["wait_minutes"])))))
    except (TypeError, ValueError, OverflowError):
        pass
    if isinstance(c.get("updates"), list):
        want = {str(x).strip().lower() for x in c["updates"]}
        d["updates"] = [k for k in UPDATE_ORDER if k in want]
    if isinstance(c.get("skip"), list):
        d["skip"] = sorted({str(a).strip() for a in c["skip"] if str(a).strip()})[:100]
    return d


def _path():
    return os.path.join(snapcache.CACHE_DIR, "release_pipeline.json")


def _read():
    try:
        with open(_path(), encoding="utf-8") as f:
            d = json.load(f)
        return d if isinstance(d, dict) else {}
    except Exception:
        return {}


def _write(d):
    os.makedirs(snapcache.CACHE_DIR, exist_ok=True)
    tmp = _path() + ".tmp"
    with _popen(tmp, "w", encoding="utf-8") as f:
        json.dump(d, f, indent=1, default=str)
    os.replace(tmp, _path())


def config() -> dict:
    return normalize(_read().get("config"))


def save_config(cfg) -> dict:
    """Persist the schedule and start / stop the daily scheduler to match it."""
    c = normalize(cfg)
    with _LOCK:
        d = _read()
        d["config"] = c
        _write(d)
    if c["enabled"] and c["daily"]:
        scheduler_start()
    else:
        scheduler_stop()
    return c


def history() -> list:
    h = _read().get("history")
    return [e for e in h if isinstance(e, dict)] if isinstance(h, list) else []


def _record(entry, slot=None):
    with _LOCK:
        d = _read()
        h = d.get("history") if isinstance(d.get("history"), list) else []
        h = [x for x in h if x.get("id") != entry.get("id")]
        h.insert(0, entry)
        d["history"] = h[:HISTORY_KEEP]
        if slot:
            d["last_slot"] = slot
        _write(d)


# ---------------------------------------------------------------- timing
def estimate_s(cfg=None) -> int:
    """How long the pipeline takes: the last finished run that did the updates (+25 %), at least
    30 min; 3 h before there is one."""
    try:
        for e in history():
            if e.get("status") in ("done", "error") and e.get("total_s") and e.get("trigger") != "after_tagging":
                return int(max(MIN_LEAD_S, float(e["total_s"]) * MARGIN))
        for e in history():
            if e.get("status") in ("done", "error") and e.get("total_s"):
                return int(max(MIN_LEAD_S, (float(e["total_s"]) - float(e.get("wait_s") or 0)) * MARGIN))
    except (TypeError, ValueError, OverflowError):      # a hand-edited / damaged history entry
        pass
    return DEFAULT_EST_S


def _slot_key(ready_dt):
    return ready_dt.strftime("%Y-%m-%d %H:%M")


def next_run(cfg=None, now=None):
    """(start_epoch, ready_by_datetime) of the next daily run, or (None, None). If today's start
    time has passed but the ready-by time has not — and today's run hasn't started — start now."""
    c = cfg or config()
    if not (c["enabled"] and c["daily"]):
        return None, None
    now_dt = _dt.datetime.fromtimestamp(now if now is not None else time.time())
    est = estimate_s(c)
    h, m = (int(x) for x in c["ready_by"].split(":"))
    done_slot = _read().get("last_slot")
    for add in range(0, 9):
        day = (now_dt + _dt.timedelta(days=add)).date()
        if c["days"] == "weekdays" and day.weekday() >= 5:
            continue
        ready = _dt.datetime(day.year, day.month, day.day, h, m)
        if ready <= now_dt or _slot_key(ready) == done_slot:
            continue
        start = ready.timestamp() - est             # real seconds, so a DST change keeps the lead
        return max(start, now_dt.timestamp()), ready
    return None, None


# ---------------------------------------------------------------- the run
def state() -> dict:
    with _LOCK:
        return json.loads(json.dumps(_STATE, default=str))


def _set_step(i, **kw):
    with _LOCK:
        _STATE["steps"][i].update(kw)


def _sleep(sec):
    """Sleep in short slices; False when cancelled."""
    end = time.time() + sec
    while time.time() < end:
        if _CANCEL.wait(min(5.0, max(0.0, end - time.time()))):
            return False
    return not _CANCEL.is_set()


def _wait_idle(i):
    """Wait for any other navi / ⚡ Optimize job to finish (they share navi.db's write lock)."""
    from core import cli_jobs
    t0 = time.time()
    while time.time() - t0 < IDLE_MAX_S:
        busy = cli_jobs.running()
        if not busy:
            return True
        _set_step(i, note="waiting for %s to finish" % (busy[0].get("label") or "another navi job"))
        if not _sleep(10):
            return False
    return False


def _follow_job(i, r):
    """Poll a console job to the end; (ok, note)."""
    from core import cli_jobs
    job = (r or {}).get("job") or {}
    jid = job.get("id")
    if not (r or {}).get("ok") or jid is None:
        return False, str((r or {}).get("error") or "could not start")
    _set_step(i, job=jid, note="")
    t0 = time.time()
    while time.time() - t0 < STEP_MAX_S:
        j = (cli_jobs.poll(jid, since=10 ** 9) or {}).get("job") or {}
        if j.get("status") != "running":
            rc = j.get("returncode")
            return (j.get("status") == "done", "" if j.get("status") == "done" else "exit %s" % rc)
        if _CANCEL.is_set():
            if j.get("kind") == "hx_optimize":
                cli_jobs.cancel(jid)
            return False, "cancelled (the navi command itself runs to its end)"
        time.sleep(2)
    return False, "still running after %d h — moved on" % (STEP_MAX_S // 3600)


def _exclusive(i, fn):
    """Run fn() holding cli_jobs.CHAIN_LOCK — the AI Contract's own navi update chain takes it
    too, so its syncs and ours never run at once (two syncs lock navi.db)."""
    from core import cli_jobs
    t0 = time.time()
    while not cli_jobs.CHAIN_LOCK.acquire(timeout=5):
        if _CANCEL.is_set():
            return False, "cancelled"
        if time.time() - t0 > IDLE_MAX_S:
            return False, "the AI Contract's navi update is still running — skipped"
        _set_step(i, note="waiting for the AI Contract's navi update to finish")
    try:
        return fn()
    finally:
        cli_jobs.CHAIN_LOCK.release()


def _blocked_hounds(pl):
    out = set()
    for ch in pl.get("preflight") or []:
        if not ch.get("ok") and ch.get("level") == "block":
            out.update(ch.get("hounds") or [])
    return out


def _do_release(i, c):
    from core import release
    st = release.state()
    mine = st.get("status") != "running"            # only cancel a release this pipeline started
    if mine:
        pl = release.plan(True if c["approve_downloads"] else None)
        runnable = [it["agent"] for it in pl["items"] if it.get("run")]
        want = [a for a in runnable if a not in c["skip"]]
        blocked = _blocked_hounds(pl)
        agents = [a for a in want if a not in blocked]
        if not agents:
            return False, "no hound can run (navi.db is missing the data they need)"
        r = release.start(True if c["approve_downloads"] else None, agents=agents)
        if not r.get("ok"):
            return False, str(r.get("error") or "release did not start")
        note = "%d hound(s)" % len(agents) + (" · %d skipped — missing data" % len(blocked & set(want))
                                               if blocked & set(want) else "")
        _set_step(i, note=note)
    t0 = time.time()
    while time.time() - t0 < 12 * 3600:
        st = release.state()
        if st.get("status") != "running":
            items = st.get("items") or []
            done = sum(1 for x in items if x.get("status") == "done")
            errs = sum(1 for x in items if x.get("status") == "error")
            msg = "%d populated" % done + (" · %d failed" % errs if errs else "")
            return st.get("status") == "done" and not errs, msg
        if _CANCEL.is_set():
            if mine:
                release.cancel()
            return False, "cancelled"
        time.sleep(5)
    return False, "release still running after 12 h"


def _steps(c, wait_s):
    s = []
    if wait_s:
        s.append({"key": "wait", "label": "Wait %d min for Tenable to apply the new tags" % (wait_s // 60)})
    for k in c["updates"]:
        s.append({"key": "update:" + k, "label": "navi update — " + UPDATE_LABELS.get(k, k)})
    if c["navi_optimize"]:
        s.append({"key": "navi_optimize", "label": "navi config optimize"})
    if c["hx_optimize"]:
        s.append({"key": "hx_optimize", "label": "⚡ Optimize for the Hounds"})
    if c["release"]:
        s.append({"key": "release", "label": "Release the Hounds"})
    return s


def _run(c, trigger, wait_s, slot):
    from core import cli_jobs, navi_cli
    with _LOCK:
        steps = _STATE["steps"]
    navi_ok = navi_cli.navi_available()
    all_ok = True
    for i, st in enumerate(steps):
        if _CANCEL.is_set():
            _set_step(i, status="cancelled")
            continue
        t0 = time.time()
        _set_step(i, status="running", started=t0)
        k = st["key"]
        try:
            if k == "wait":
                ok, note = _sleep(wait_s), ""
            elif k.startswith("update:") or k == "navi_optimize":
                if not navi_ok:
                    ok, note = False, "skipped — navi CLI not found"
                else:
                    def _navi_step(i=i, k=k):
                        if not _wait_idle(i):
                            return False, "another navi job is still running — skipped"
                        if k == "navi_optimize":
                            return _follow_job(i, cli_jobs.start_optimize())
                        # summaries are refreshed by the ⚡ Optimize step, not after each sync
                        return _follow_job(i, cli_jobs.start_update(k.split(":", 1)[1], refresh_summaries=False))
                    ok, note = _exclusive(i, _navi_step)
            elif k == "hx_optimize":
                from core import hx_optimize

                def _hx_step(i=i):
                    if not _wait_idle(i):
                        return False, "another navi job is still running — skipped"
                    r = hx_optimize.run()
                    return _follow_job(i, r) if r.get("ok") else (False, str(r.get("error") or "refused"))
                ok, note = _exclusive(i, _hx_step)
            elif k == "release":
                ok, note = _do_release(i, c)
            else:
                ok, note = False, "unknown step"
        except Exception as e:                      # one failed step never stops the rest
            ok, note = False, "%s: %s" % (type(e).__name__, e)
        all_ok = all_ok and ok
        _set_step(i, status=("done" if ok else ("cancelled" if _CANCEL.is_set() else "error")),
                  sec=round(time.time() - t0, 1), note=note or "")
    with _LOCK:
        _STATE["finished"] = time.time()
        _STATE["total_s"] = round(_STATE["finished"] - _STATE["started"], 1)
        _STATE["status"] = "cancelled" if _CANCEL.is_set() else ("done" if all_ok else "error")
        entry = json.loads(json.dumps(_STATE, default=str))
    _record(entry, slot)


def start(trigger="manual", wait_s=0, cfg=None, slot=None) -> dict:
    """Start the pipeline on its own thread (or report the one running)."""
    c = normalize(cfg) if cfg is not None else config()
    steps = _steps(c, int(wait_s or 0))
    if not steps:
        return {"ok": False, "error": "nothing to run — pick at least one update, optimize or the release"}
    with _LOCK:
        if _STATE.get("status") == "running":
            return {"ok": True, "already_running": True, "state": json.loads(json.dumps(_STATE, default=str))}
        _CANCEL.clear()
        _STATE.clear()
        _STATE.update({"id": time.strftime("%Y%m%d-%H%M%S"), "status": "running", "trigger": trigger,
                       "started": time.time(), "finished": None, "wait_s": int(wait_s or 0),
                       "slot": slot, "steps": [dict(s, status="pending") for s in steps]})
    threading.Thread(target=_run, args=(c, trigger, int(wait_s or 0), slot),
                     name="release-pipeline", daemon=True).start()
    return {"ok": True, "state": state()}


def cancel() -> bool:
    with _LOCK:
        if _STATE.get("status") != "running":
            return False
    _CANCEL.set()
    return True


def after_cycle(applied=True) -> dict:
    """Called at the end of an AI Contract cycle — starts the pipeline when 'after tagging' is on."""
    c = config()
    if not (c["enabled"] and c["after_tagging"]):
        return {"skipped": "after-tagging release is off"}
    if not applied:
        return {"skipped": "the cycle wrote nothing (plan only)"}
    r = start("after_tagging", wait_s=c["wait_minutes"] * 60, cfg=c)
    return {"started": bool(r.get("ok")) and not r.get("already_running"),
            "already_running": bool(r.get("already_running")), "error": r.get("error")}


# ---------------------------------------------------------------- daily scheduler
def _sched_loop(stop):
    while not stop.is_set():
        try:
            c = config()
            if not (c["enabled"] and c["daily"]):
                break
            t, ready = next_run(c)
            if t is not None and time.time() >= t and state().get("status") != "running":
                slot = _slot_key(ready)
                with _LOCK:                          # claim the slot first: one run per ready-by
                    d = _read()
                    d["last_slot"] = slot
                    _write(d)
                start("daily", cfg=c, slot=slot)
        except Exception:
            pass
        stop.wait(20)


def scheduler_start() -> dict:
    t = _SCHED["thread"]
    if t is not None and t.is_alive() and not _SCHED["stop"].is_set():
        return {"running": True}
    ev = threading.Event()
    _SCHED["stop"] = ev
    t = threading.Thread(target=_sched_loop, args=(ev,), name="release-pipeline-scheduler", daemon=True)
    _SCHED["thread"] = t
    t.start()
    return {"running": True}


def scheduler_stop() -> dict:
    _SCHED["stop"].set()
    return {"running": False}


def scheduler_running() -> bool:
    t = _SCHED["thread"]
    return bool(t is not None and t.is_alive() and not _SCHED["stop"].is_set())


def resume() -> dict:
    """Server start: bring the daily schedule back."""
    c = config()
    if c["enabled"] and c["daily"]:
        return scheduler_start()
    return {"running": False}


def status() -> dict:
    c = config()
    t, ready = next_run(c)
    h = history()
    return {"config": c, "state": state(), "scheduler": scheduler_running(),
            "next_start": t, "ready_by_at": ready.timestamp() if ready else None,
            "estimate_s": estimate_s(c), "estimate_basis": "last run + 25 %" if any(
                e.get("total_s") for e in h) else "first-run guess (3 h)",
            "last": h[0] if h else None, "history": h[:10],
            "update_kinds": [{"key": k, "label": UPDATE_LABELS[k]} for k in UPDATE_ORDER],
            "server_time": time.time(), "tz": time.strftime("%Z")}
