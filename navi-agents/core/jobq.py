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
_Q = _queue.Queue()
_IDS = itertools.count(1)

# A small pool — several heavy reads can run at once (each in its own thread).
_DESIRED = max(1, min(16, int(os.environ.get("NAVI_JOB_WORKERS", "3"))))
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
        while len(_WORKERS) < _DESIRED:
            idx = len(_WORKERS)
            t = threading.Thread(target=_run, args=(idx,), name=f"jobq-worker-{idx}", daemon=True)
            _WORKERS.append(t)
            t.start()


def workers_alive() -> int:
    with _WLOCK:
        return sum(1 for t in _WORKERS if t.is_alive())


def _get(job_id):
    with _LOCK:
        for j in _JOBS:
            if j["id"] == job_id:
                return j
    return None


def _run(idx):
    while True:
        if idx >= _DESIRED:
            return
        try:
            job_id, fn = _Q.get(timeout=1.0)
        except _queue.Empty:
            continue
        job = _get(job_id)
        if job is None:
            _Q.task_done()
            continue
        with _LOCK:
            job["status"] = "running"
            job["started"] = _now()
        qprofile.set_context(job.get("agent", ""), job.get("action", ""))
        m = qprofile.mark()
        tok = _TOKENS.setdefault(job_id, db.Cancel())
        try:
            # background work: the "job" budget (45 min, NAVI_JOB_BUDGET_S) for every statement
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
            _Q.task_done()


def _trim():
    if len(_JOBS) > _MAX:                               # keep active + newest finished
        keep = [j for j in _JOBS if j["status"] in ("queued", "running")]
        done = [j for j in _JOBS if j["status"] in ("done", "error")]
        _JOBS[:] = done[-(max(0, _MAX - len(keep))):] + keep


def submit(fn, meta=None) -> dict:
    """Enqueue fn() (returns the action's result dict); returns the job stub now."""
    meta = meta or {}
    jid = next(_IDS)
    job = {"id": jid, "status": "queued", "ok": None, "message": "",
           "created": _now(), "started": None, "finished": None,
           "agent": meta.get("agent", ""), "action": meta.get("action", ""),
           "label": meta.get("label", "") or meta.get("action", ""),
           "elapsed": None, "queries": [], "result": None}
    with _LOCK:
        _JOBS.append(job)
        _trim()
    _ensure_workers()
    _Q.put((jid, fn))
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


def cancel(job_id) -> bool:
    """Stop a queued or running job's SQL (its statements raise db.QueryCancelled)."""
    try:
        jid = int(job_id)
    except (TypeError, ValueError):
        return False
    j = _get(jid)
    if not j or j["status"] not in ("queued", "running"):
        return False
    _TOKENS.setdefault(jid, db.Cancel()).cancel()
    return True


def get(job_id) -> dict:
    """Full job record INCLUDING its result + queries (for the detail poller)."""
    j = _get(int(job_id))
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
    c["workers"] = workers_alive() or _DESIRED
    return c


def clear() -> int:
    """Drop finished jobs; keep queued/running."""
    global _JOBS
    with _LOCK:
        before = len(_JOBS)
        _JOBS[:] = [j for j in _JOBS if j["status"] in ("queued", "running")]
        return before - len(_JOBS)
