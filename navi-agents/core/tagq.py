"""In-memory, session-only background tag queue.

Tag writes shell out to `navi`, which can take a while (and Tenable adds a
~30-minute propagation window). To keep the UI responsive, every tag write is
enqueued here and executed by a single background worker thread — serially, so
navi writes never collide. Jobs live only for the life of the server process
(no disk persistence); restarting the server clears the log.

A single worker (not a pool) is deliberate: navi/sqlite writes serialize best
one-at-a-time, and the original synchronous behavior was already one-at-a-time.
"""
import itertools
import os
import threading
import time
import queue as _queue

# A small gap between tag writes — a safety margin against Tenable-side API rate
# limits on large runs. The worker is already serial (one tag at a time); tags on
# thousands of assets can take 2-3 min each, so this gap is conservative. Tune via
# NAVI_TAG_GAP_MS (set 0 to disable).
_GAP = max(0.0, float(os.environ.get("NAVI_TAG_GAP_MS", "1500")) / 1000.0)

_JOBS = []                 # newest-last list of job dicts (the log)
_LOCK = threading.Lock()
_Q = _queue.Queue()
_IDS = itertools.count(1)

# Worker POOL — run several tags in parallel. The work is serialized one-per-thread
# but N threads can each have a navi tag in flight at once. Default from
# NAVI_TAG_WORKERS (set 8 to run 8 at a time). Each worker still honors _GAP, so the
# effective rate is ~ workers / gap — fast, but still paced.
_DESIRED = max(1, min(32, int(os.environ.get("NAVI_TAG_WORKERS", "4"))))
_WORKERS = []
_WLOCK = threading.Lock()


def _now():
    return time.time()


def _ensure_workers():
    with _WLOCK:
        _WORKERS[:] = [t for t in _WORKERS if t.is_alive()]
        while len(_WORKERS) < _DESIRED:
            idx = len(_WORKERS)
            t = threading.Thread(target=_run, args=(idx,), name=f"tagq-worker-{idx}", daemon=True)
            _WORKERS.append(t)
            t.start()


def set_workers(n) -> int:
    """Resize the pool at runtime (1-32). Extra workers retire after their current
    job; new ones start immediately."""
    global _DESIRED
    try:
        _DESIRED = max(1, min(32, int(n)))
    except Exception:
        pass
    _ensure_workers()
    return _DESIRED


def workers_alive() -> int:
    with _WLOCK:
        return sum(1 for t in _WORKERS if t.is_alive())


def _run(idx):
    while True:
        if idx >= _DESIRED:           # pool was shrunk — retire this worker
            return
        try:
            job_id, fn, kwargs = _Q.get(timeout=1.0)
        except _queue.Empty:
            continue
        job = _get(job_id)
        if job is None:
            _Q.task_done()
            continue
        with _LOCK:
            job["status"] = "running"
            job["started"] = _now()
        try:
            res = fn(**kwargs) or {}
            ok = bool(res.get("ok"))
            with _LOCK:
                job["status"] = "done" if ok else "error"
                job["ok"] = ok
                job["result"] = res
                job["message"] = (res.get("warning") or res.get("message")
                                  or res.get("stderr") or ("applied" if ok else "failed"))
                job["finished"] = _now()
        except Exception as e:                       # pragma: no cover
            with _LOCK:
                job["status"] = "error"
                job["ok"] = False
                job["message"] = str(e)
                job["finished"] = _now()
        finally:
            _Q.task_done()
            if _GAP:
                time.sleep(_GAP)            # serial pacing to stay under API rate limits


def _get(job_id):
    with _LOCK:
        for j in _JOBS:
            if j["id"] == job_id:
                return j
    return None


def submit(fn, kwargs, meta=None) -> dict:
    """Enqueue fn(**kwargs); returns the job stub immediately (status=queued)."""
    meta = meta or {}
    jid = next(_IDS)
    job = {"id": jid, "status": "queued", "ok": None, "message": "",
           "created": _now(), "started": None, "finished": None,
           "op": meta.get("op", "tag"),
           "agent": meta.get("agent", ""), "category": meta.get("category", ""),
           "value": meta.get("value", ""), "selector": meta.get("selector", ""),
           "detail": meta.get("detail", ""),
           # the raw navi args, retained so the Tagging log can export a runnable
           # navi script (shell / python) for cron.
           "spec": dict(kwargs or {})}
    with _LOCK:
        _JOBS.append(job)
    _ensure_workers()
    _Q.put((jid, fn, kwargs))
    return dict(job)


def record(meta, result) -> dict:
    """Append an already-finished write (e.g. a synchronous ACR change) to the log
    so the Tagging log and the contract builder see ACR changes alongside tags."""
    jid = next(_IDS)
    ok = bool((result or {}).get("ok"))
    now = _now()
    job = {"id": jid, "status": "done" if ok else "error", "ok": ok,
           "message": (result or {}).get("warning") or (result or {}).get("message")
                      or ("applied" if ok else "failed"),
           "created": now, "started": now, "finished": now,
           "op": (meta or {}).get("op", "tag"),
           "agent": (meta or {}).get("agent", ""), "category": (meta or {}).get("category", ""),
           "value": (meta or {}).get("value", ""), "selector": (meta or {}).get("selector", ""),
           "detail": (meta or {}).get("detail", ""),
           "spec": dict((meta or {}).get("spec") or {})}
    with _LOCK:
        _JOBS.append(job)
    return dict(job)


def list_jobs() -> list:
    with _LOCK:
        jobs = [dict(j) for j in _JOBS]
    jobs.reverse()                                   # newest first for the UI
    return jobs


def counts() -> dict:
    with _LOCK:
        c = {"queued": 0, "running": 0, "done": 0, "error": 0, "total": len(_JOBS)}
        for j in _JOBS:
            c[j["status"]] = c.get(j["status"], 0) + 1
    c["workers"] = workers_alive() or _DESIRED
    c["desired_workers"] = _DESIRED
    return c


def clear() -> int:
    """Drop finished (done/error) jobs from the log; keep queued/running."""
    global _JOBS
    with _LOCK:
        before = len(_JOBS)
        _JOBS = [j for j in _JOBS if j["status"] in ("queued", "running")]
        return before - len(_JOBS)
