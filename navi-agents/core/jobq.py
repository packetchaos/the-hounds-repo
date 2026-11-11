"""In-memory, session-only background AGENT-RUN queue.

Mirrors core.tagq, but for read/compute agent actions instead of tag writes.
On a large navi.db an agent's query can take minutes; rather than block the tab
(or abort it), the launcher can run the action here in the background and return
a job stub immediately. The UI polls /api/jobs and shows a "Runs log" — the same
pattern as the Tagging log. Jobs live only for the life of the server process.
"""
import itertools
import os
import threading
import time
import queue as _queue

from . import db, qprofile

_JOBS = []                     # newest-last list of job dicts (the log)
_LOCK = threading.Lock()
_IDS = itertools.count(1)
# Two pools (build 458): "default" for background work the user asked for explicitly (Run in
# background, snapshots, confirmed tag jobs, Release) and "run" for DETACHED ▶ Runs
# (core/launcher._detached). Hours-long ▶ Runs can never take every worker and leave a confirmed
# write or a snapshot queued behind them.
_QS = {"default": _queue.Queue(), "run": _queue.Queue()}
_Q = _QS["default"]
# A small pool — several heavy reads can run at once (each in its own thread).
_DESIRED = max(1, min(16, int(os.environ.get("NAVI_JOB_WORKERS", "4"))))
_POOL_SIZE = {"default": _DESIRED,
              "run": max(1, min(16, int(os.environ.get("NAVI_RUN_WORKERS", "3"))))}
# finished jobs keep their (possibly large) result only while a page may still collect it
_KEEP_RESULTS = int(os.environ.get("NAVI_JOB_KEEP_RESULTS", "20"))
# job ids restart at 1 with the process: pages remember (boot, id) so an id from before a
# restart never matches an unrelated new job
BOOT = "%x" % int(time.time() * 1000)
_WORKERS = []
_WLOCK = threading.Lock()
# Keep the log from growing unbounded over a long session.
_MAX = int(os.environ.get("NAVI_JOB_LOG_MAX", "200"))
_TOKENS = {}                   # job id -> db.Cancel (cancel(job_id) stops its running SQL)


def _now():
    return time.time()


def _ensure_workers():
    with _WLOCK:
        _WORKERS[:] = [t for t in _WORKERS if t.is_alive()]
        for pool, n in _POOL_SIZE.items():
            have = sum(1 for t in _WORKERS if getattr(t, "_pool", "default") == pool)
            while have < n:
                t = threading.Thread(target=_run, args=(have, pool), name=f"jobq-{pool}-{have}", daemon=True)
                t._pool = pool
                _WORKERS.append(t)
                t.start()
                have += 1


def workers_alive() -> int:
    with _WLOCK:
        return sum(1 for t in _WORKERS if t.is_alive())


def _get(job_id):
    with _LOCK:
        for j in _JOBS:
            if j["id"] == job_id:
                return j
    return None


def _run(idx, pool="default"):
    q = _QS[pool]
    while True:
        if idx >= _POOL_SIZE.get(pool, 0):
            return
        try:
            job_id, fn = q.get(timeout=1.0)
        except _queue.Empty:
            continue
        job = _get(job_id)
        if job is None:
            q.task_done()
            continue
        with _LOCK:
            job["status"] = "running"
            job["started"] = _now()
        qprofile.set_context(job.get("agent", ""), job.get("action", ""))
        m = qprofile.mark()
        tok = _TOKENS.setdefault(job_id, db.Cancel())
        try:
            # background work: the "job" budget (2 h, NAVI_JOB_BUDGET_S) for every statement
            # that passes none, heavy (one big scan at a time), stoppable via cancel(job_id)
            with db.budget_scope("job") as sc, db.cancel_scope(tok):
                try:
                    res = fn() or {}
                except (db.QueryTimeout, db.TooManyRows) as e:
                    res = db.budget_payload(e)
            if sc.tripped and isinstance(res, dict):
                res = dict(res, budget_hits=sc.summary()["hits"])
            ok = res.get("ok", True) is not False
            with _LOCK:
                job["status"] = "done" if ok else "error"
                job["ok"] = ok
                job["result"] = res
                job["queries"] = qprofile.since(m)[:80]
                job["message"] = (res.get("message") or res.get("error")
                                  or ("done" if ok else "failed"))
                job["finished"] = _now()
        except Exception as e:                          # pragma: no cover
            with _LOCK:
                job["status"] = "error"
                job["ok"] = False
                job["queries"] = qprofile.since(m)[:80]
                job["message"] = f"{type(e).__name__}: {e}"
                job["finished"] = _now()
        finally:
            _TOKENS.pop(job_id, None)
            qprofile.clear_context()
            _drop_old_results()
            q.task_done()


def _drop_old_results():
    """Finished jobs keep `result` only for the newest _KEEP_RESULTS (a page collects its run's
    result within seconds; an 80 MB body must not live in the log for the session)."""
    with _LOCK:
        done = [j for j in _JOBS if j["status"] in ("done", "error") and j.get("result") is not None
                and j.get("pool") == "run"]     # Release / background jobs keep theirs (core.release reads them)
        for j in done[:-_KEEP_RESULTS] if _KEEP_RESULTS > 0 else done:
            j["result"] = None
            j["result_dropped"] = True


def _trim():
    if len(_JOBS) > _MAX:                               # keep active + newest finished
        keep = [j for j in _JOBS if j["status"] in ("queued", "running")]
        done = [j for j in _JOBS if j["status"] in ("done", "error")]
        _JOBS[:] = done[-(max(0, _MAX - len(keep))):] + keep


def submit(fn, meta=None, pool="default") -> dict:
    """Enqueue fn() (returns the action's result dict); returns the job stub now.
    pool="run": a detached ▶ Run (its own workers; cancellable from the page)."""
    meta = meta or {}
    pool = pool if pool in _QS else "default"
    jid = next(_IDS)
    job = {"id": jid, "status": "queued", "ok": None, "message": "",
           "created": _now(), "started": None, "finished": None,
           "agent": meta.get("agent", ""), "action": meta.get("action", ""),
           "label": meta.get("label", "") or meta.get("action", ""),
           "elapsed": None, "queries": [], "result": None, "pool": pool, "boot": BOOT}
    with _LOCK:
        _JOBS.append(job)
        _trim()
    _ensure_workers()
    _QS[pool].put((jid, fn))
    return {k: v for k, v in job.items() if k not in ("result", "queries")}


def record(meta) -> dict:
    """Append an already-finished SYNCHRONOUS run (with the queries it issued) so the
    Runs log shows every agent run — not just backgrounded ones."""
    meta = meta or {}
    jid = next(_IDS)
    now = _now()
    job = {"id": jid, "status": meta.get("status", "done"), "ok": meta.get("ok", True),
           "message": meta.get("message", ""), "created": now,
           "started": now - float(meta.get("elapsed", 0) or 0), "finished": now,
           "agent": meta.get("agent", ""), "action": meta.get("action", ""),
           "label": meta.get("label", "") or meta.get("action", ""),
           "elapsed": meta.get("elapsed"), "queries": (meta.get("queries") or [])[:80],
           "result": None}
    with _LOCK:
        _JOBS.append(job)
        _trim()
    return {k: v for k, v in job.items() if k not in ("result", "queries")}


def active(pool=None, agent=None) -> int:
    """Queued + running jobs (optionally of one pool / agent)."""
    with _LOCK:
        return sum(1 for j in _JOBS if j["status"] in ("queued", "running")
                   and (pool is None or j.get("pool") == pool) and (agent is None or j.get("agent") == agent))


def _jid(job_id):
    try:
        return int(job_id)
    except (TypeError, ValueError, OverflowError):
        return None


def cancel(job_id, pool=None) -> bool:
    """Stop a queued or running job's SQL (its statements raise db.QueryCancelled).
    pool: only a job of that pool (the page's Cancel stops ▶ Runs, never a confirmed write)."""
    jid = _jid(job_id)
    if jid is None:
        return False
    j = _get(jid)
    if not j or j["status"] not in ("queued", "running"):
        return False
    if pool is not None and j.get("pool") != pool:
        return False
    _TOKENS.setdefault(jid, db.Cancel()).cancel()
    return True


def get(job_id) -> dict:
    """Full job record INCLUDING its result + queries (for the detail poller)."""
    jid = _jid(job_id)
    j = _get(jid) if jid is not None else None
    return dict(j) if j else None


def list_jobs() -> list:
    """Light log view (no heavy result/queries), newest-first, with query summary."""
    with _LOCK:
        jobs = []
        for j in _JOBS:
            qs = j.get("queries") or []
            row = {k: v for k, v in j.items() if k not in ("result", "queries")}
            row["query_count"] = len(qs)
            row["query_ms"] = round(sum(q.get("ms", 0) for q in qs), 1)
            jobs.append(row)
    jobs.reverse()
    return jobs


def counts() -> dict:
    with _LOCK:
        c = {"queued": 0, "running": 0, "done": 0, "error": 0, "total": len(_JOBS)}
        for j in _JOBS:
            c[j["status"]] = c.get(j["status"], 0) + 1
    c["workers"] = workers_alive() or sum(_POOL_SIZE.values())
    return c


def clear() -> int:
    """Drop finished jobs; keep queued/running."""
    global _JOBS
    with _LOCK:
        before = len(_JOBS)
        _JOBS[:] = [j for j in _JOBS if j["status"] in ("queued", "running")]
        return before - len(_JOBS)
