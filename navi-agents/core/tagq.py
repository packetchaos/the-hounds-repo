"""Background tag queue with a durable, shared log.

Tag writes shell out to `navi`, which can take a while (and Tenable adds a
~30-minute propagation window). To keep the UI responsive, every tag write is
enqueued here and executed by background worker threads. Execution state lives
in-memory, but every job is ALSO mirrored to a small SQLite sidecar
(``tag_jobs.db`` in the repo root, override with ``NAVI_TAGLOG_DB``) so the
Tagging log:

  * survives a server restart (the log used to be wiped on every restart), and
  * is shared across processes (so a job queued in one process is visible to the
    Tagging log even if the read is served by another).

The sidecar is strictly best-effort: if it can't be opened or written, tagging
still works exactly as before off the in-memory list — persistence just degrades
to session-only. Job IDs come from the DB (AUTOINCREMENT) so they never collide
across processes; if the DB is unavailable we fall back to an in-process counter.
"""
import itertools
import json
import os
import sqlite3
import threading
import time
import queue as _queue

# A small gap between tag writes — a safety margin against Tenable-side API rate
# limits on large runs. Tune via NAVI_TAG_GAP_MS (set 0 to disable).
_GAP = max(0.0, float(os.environ.get("NAVI_TAG_GAP_MS", "1500")) / 1000.0)

_JOBS = []                 # in-memory mirror (this process); newest-last
_LOCK = threading.Lock()
_Q = _queue.Queue()
_IDS = itertools.count(1)  # fallback IDs only (when the sidecar DB is unavailable)

# Worker POOL — N threads, each running one navi tag at a time. Default from
# NAVI_TAG_WORKERS. Each worker honors _GAP, so the effective rate is paced.
_DESIRED = max(1, min(32, int(os.environ.get("NAVI_TAG_WORKERS", "4"))))
_WORKERS = []
_WLOCK = threading.Lock()

# ---------------------------------------------------------------------------
# Durable sidecar (SQLite). All ops best-effort — never let a DB hiccup break a
# tag write. Reads fall back to the in-memory mirror when the DB is unavailable.
# ---------------------------------------------------------------------------
_DBPATH = os.environ.get("NAVI_TAGLOG_DB") or os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tag_jobs.db")
_DBLOCK = threading.Lock()
_DB_OK = False


def _b(v):
    return None if v is None else (1 if v else 0)


def _db_init():
    global _DB_OK, _DESIRED
    try:
        con = sqlite3.connect(_DBPATH, timeout=5.0)
        try:
            from core.security import private_file
            private_file(_DBPATH)                 # the ledger is owner-only (it records every write)
            con.execute("PRAGMA journal_mode=WAL")
            con.execute(
                "CREATE TABLE IF NOT EXISTS jobs("
                "id INTEGER PRIMARY KEY AUTOINCREMENT, status TEXT, ok INTEGER, "
                "message TEXT, created REAL, started REAL, finished REAL, op TEXT, "
                "agent TEXT, category TEXT, value TEXT, selector TEXT, detail TEXT, spec TEXT)")
            con.execute("CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, val TEXT)")
            # business case (human-readable ACR Change Reasons + note) — added in build 442; an
            # older tag_jobs.db gains the column in place (existing rows read as '').
            try:
                if "business_case" not in [r[1] for r in con.execute("PRAGMA table_info(jobs)")]:
                    con.execute("ALTER TABLE jobs ADD COLUMN business_case TEXT")
            except sqlite3.OperationalError:
                pass                    # another process added it first (duplicate column)
            con.commit()
        finally:
            con.close()
        _DB_OK = True
    except Exception:
        _DB_OK = False
        return
    # Adopt a previously-saved worker count — so the "parallel tags" setting sticks
    # across restarts and is shared across processes (not just this one's memory).
    try:
        d = _meta_get("desired_workers")
        if d is not None:
            _DESIRED = max(1, min(32, int(d)))
    except Exception:
        pass


def _dbexec(sql, params=(), want=None):
    """want: 'id' → lastrowid, 'all' → fetchall, else commit-only. None on failure."""
    if not _DB_OK:
        return None
    try:
        with _DBLOCK:
            con = sqlite3.connect(_DBPATH, timeout=5.0)
            try:
                con.execute("PRAGMA busy_timeout=5000")
                cur = con.execute(sql, params)
                if want == "all":
                    return cur.fetchall()
                con.commit()
                return cur.lastrowid if want == "id" else True
            finally:
                con.close()
    except Exception:
        return None


def _db_insert(job):
    return _dbexec(
        "INSERT INTO jobs(status,ok,message,created,started,finished,op,agent,"
        "category,value,selector,detail,spec,business_case) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (job.get("status"), _b(job.get("ok")), job.get("message", ""),
         job.get("created"), job.get("started"), job.get("finished"),
         job.get("op", "tag"), job.get("agent", ""), job.get("category", ""),
         job.get("value", ""), job.get("selector", ""), job.get("detail", ""),
         json.dumps(job.get("spec") or {}), job.get("business_case", "")), want="id")


def _db_update(job):
    _dbexec("UPDATE jobs SET status=?,ok=?,message=?,started=?,finished=? WHERE id=?",
            (job.get("status"), _b(job.get("ok")), job.get("message", ""),
             job.get("started"), job.get("finished"), job.get("id")))


def _db_all(limit=2000):
    rows = _dbexec(
        "SELECT id,status,ok,message,created,started,finished,op,agent,category,"
        "value,selector,detail,spec,business_case FROM jobs ORDER BY id DESC LIMIT ?", (limit,), want="all")
    if rows is None:
        return None
    out = []
    for r in rows:
        out.append({"id": r[0], "status": r[1],
                    "ok": (None if r[2] is None else bool(r[2])),
                    "message": r[3], "created": r[4], "started": r[5], "finished": r[6],
                    "op": r[7], "agent": r[8], "category": r[9], "value": r[10],
                    "selector": r[11], "detail": r[12],
                    "spec": (json.loads(r[13]) if r[13] else {}),
                    "business_case": r[14] or ""})
    return out


def _db_counts():
    rows = _dbexec("SELECT status, COUNT(*) FROM jobs GROUP BY status", want="all")
    if rows is None:
        return None
    c = {"queued": 0, "running": 0, "done": 0, "error": 0, "total": 0}
    for st, n in rows:
        c[st] = c.get(st, 0) + n
        c["total"] += n
    return c


def _meta_get(key):
    rows = _dbexec("SELECT val FROM meta WHERE key=?", (key,), want="all")
    if rows:
        try:
            return rows[0][0]
        except Exception:
            return None
    return None


def _meta_set(key, val):
    _dbexec("INSERT OR REPLACE INTO meta(key, val) VALUES(?, ?)", (key, str(val)))


def _synced_desired():
    """The worker count, read from the shared sidecar when available so every
    process/restart agrees; falls back to this process's value."""
    d = _meta_get("desired_workers")
    if d is not None:
        try:
            return max(1, min(32, int(d)))
        except Exception:
            pass
    return _DESIRED


def _now():
    return time.time()


def _ensure_workers():
    global _DESIRED
    # Adopt the shared worker count (another process may have changed it) before
    # sizing this process's pool — keeps parallelism consistent across processes.
    d = _meta_get("desired_workers")
    if d is not None:
        try:
            _DESIRED = max(1, min(32, int(d)))
        except Exception:
            pass
    with _WLOCK:
        _WORKERS[:] = [t for t in _WORKERS if t.is_alive()]
        while len(_WORKERS) < _DESIRED:
            idx = len(_WORKERS)
            t = threading.Thread(target=_run, args=(idx,), name=f"tagq-worker-{idx}", daemon=True)
            _WORKERS.append(t)
            t.start()


def set_workers(n) -> int:
    """Resize the pool at runtime (1-32)."""
    global _DESIRED
    try:
        _DESIRED = max(1, min(32, int(n)))
    except Exception:
        pass
    _meta_set("desired_workers", _DESIRED)   # persist + share across processes/restarts
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
        _db_update(job)
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
            _db_update(job)
        except Exception as e:                       # pragma: no cover
            with _LOCK:
                job["status"] = "error"
                job["ok"] = False
                job["message"] = str(e)
                job["finished"] = _now()
            _db_update(job)
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
    job = {"id": None, "status": "queued", "ok": None, "message": "",
           "created": _now(), "started": None, "finished": None,
           "op": meta.get("op", "tag"),
           "agent": meta.get("agent", ""), "category": meta.get("category", ""),
           "value": meta.get("value", ""), "selector": meta.get("selector", ""),
           "detail": meta.get("detail", ""),
           "business_case": meta.get("business_case", ""),
           # the raw navi args, retained so the Tagging log can export a runnable
           # navi script (shell / python) for cron.
           "spec": dict(kwargs or {})}
    jid = _db_insert(job)          # DB assigns a globally-unique id (best-effort)
    if not jid:
        jid = next(_IDS)           # fallback: in-process id when the sidecar is down
    job["id"] = jid
    with _LOCK:
        _JOBS.append(job)
    _ensure_workers()
    _Q.put((jid, fn, kwargs))
    return dict(job)


def record(meta, result) -> dict:
    """Append an already-finished write (e.g. a synchronous ACR change) to the log
    so the Tagging log and the contract builder see ACR changes alongside tags."""
    ok = bool((result or {}).get("ok"))
    now = _now()
    job = {"id": None, "status": "done" if ok else "error", "ok": ok,
           "message": (result or {}).get("warning") or (result or {}).get("message")
                      or ("applied" if ok else "failed"),
           "created": now, "started": now, "finished": now,
           "op": (meta or {}).get("op", "tag"),
           "agent": (meta or {}).get("agent", ""), "category": (meta or {}).get("category", ""),
           "value": (meta or {}).get("value", ""), "selector": (meta or {}).get("selector", ""),
           "detail": (meta or {}).get("detail", ""),
           "business_case": (meta or {}).get("business_case", ""),
           "spec": dict((meta or {}).get("spec") or {})}
    jid = _db_insert(job)
    if not jid:
        jid = next(_IDS)
    job["id"] = jid
    with _LOCK:
        _JOBS.append(job)
    return dict(job)


def list_jobs() -> list:
    """Newest-first. Reads the durable sidecar (shared + restart-proof); falls back
    to this process's in-memory mirror only if the DB is unavailable."""
    db = _db_all()
    if db is not None:
        return db
    with _LOCK:
        jobs = [dict(j) for j in _JOBS]
    jobs.reverse()
    return jobs


def counts() -> dict:
    c = _db_counts()
    if c is None:
        with _LOCK:
            c = {"queued": 0, "running": 0, "done": 0, "error": 0, "total": len(_JOBS)}
            for j in _JOBS:
                c[j["status"]] = c.get(j["status"], 0) + 1
    c["workers"] = workers_alive() or _DESIRED
    c["desired_workers"] = _synced_desired()
    return c


def clear() -> int:
    """Drop finished (done/error) jobs from the log; keep queued/running."""
    global _JOBS
    before = _db_counts()
    _dbexec("DELETE FROM jobs WHERE status IN ('done','error')")
    with _LOCK:
        mem_before = len(_JOBS)
        _JOBS = [j for j in _JOBS if j["status"] in ("queued", "running")]
        mem_dropped = mem_before - len(_JOBS)
    if before is not None:
        return before.get("done", 0) + before.get("error", 0)
    return mem_dropped


_db_init()
