"""Shared launcher logic — discovery + generic action dispatch.

Both app_fastapi.py and app_flask.py import this so behavior is identical.
Drop a new agent folder into agents/ and restart: it is discovered, its
api.ACTIONS are mounted under /api/<id>/<action>, and the hub lists it.
"""
import json
import os
import time

from . import health as _health, discovery, db, jobq, qprofile

RECORDS = discovery.discover()
DISPATCH = {r["id"]: r["actions"] for r in RECORDS if r["deployed"]}

# ---- shared agent-result cache -------------------------------------------------
# Reading between agents shouldn't rebuild the same query every time — a heavy
# read on a large navi.db is expensive. We memoise read/compute action results
# per (agent, action, params, db_path) for a short TTL. Mutating actions (writes,
# tag/apply/send/…) are never cached and INVALIDATE that agent's cached reads so
# the UI reflects the change. Add refresh:true (or _nocache) to force a re-run.
_CACHE: dict = {}
_CACHE_TTL = float(os.environ.get("NAVI_AGENT_CACHE_TTL_S", "300"))
_CACHE_MAX = int(os.environ.get("NAVI_AGENT_CACHE_MAX", "300"))
# actions that change state or are inherently dynamic — never cache, and they
# invalidate the agent's cached reads.
_MUTATING = {"apply", "tag", "tag_candidate", "send", "delete", "remove", "rotate",
             "encrypt", "decrypt", "refresh", "detections_decide", "ignore_add",
             "ignore_remove", "ignore_import", "promote", "acr", "set_acr",
             # contract state changes — must drop the cached `get` so the UI sees them
             "set", "arm", "disarm", "load", "add_removals",
             # alert (Alert Raven) state changes — new/edited/removed alerts + evaluations + test email
             "save", "toggle", "add_template", "evaluate", "send_test"}


def _cache_key(agent_id, action, payload):
    p = {k: v for k, v in (payload or {}).items() if k not in ("refresh", "_nocache")}
    try:
        ps = json.dumps(p, sort_keys=True, default=str)
    except Exception:
        ps = str(p)
    try:
        dbp = db.db_path()
    except Exception:
        dbp = ""
    return f"{agent_id}|{action}|{ps}|{dbp}"


def _invalidate(agent_id):
    for k in [k for k in _CACHE if k.startswith(agent_id + "|")]:
        _CACHE.pop(k, None)


def clear_cache():
    _CACHE.clear()


def registry() -> dict:
    return discovery.registry(RECORDS)


def health() -> dict:
    return _health.health()


def jobs_list() -> dict:
    return {"ok": True, "jobs": jobq.list_jobs(), "counts": jobq.counts()}


def jobs_get(job_id) -> dict:
    j = jobq.get(job_id)
    return {"ok": True, "job": j} if j else {"ok": False, "error": "no such job"}


def jobs_clear() -> dict:
    return {"ok": True, "cleared": jobq.clear()}


def profile() -> dict:
    """Recent queries (newest-first) + the index advisor's suggestions."""
    log = list(reversed(qprofile.entries()))
    return {"ok": True, "log": log[:300], "advisor": qprofile.suggest(db.db_path())}


def profile_clear() -> dict:
    qprofile.clear()
    return {"ok": True}


def dispatch(agent_id: str, action: str, payload: dict):
    acts = DISPATCH.get(agent_id)
    if acts is None:
        return {"ok": False, "error": f"agent '{agent_id}' is not deployed"}, 404
    fn = acts.get(action)
    if not fn:
        return {"ok": False, "error": f"unknown action '{action}' for '{agent_id}'"}, 404
    payload = payload or {}
    mutating = (action in _MUTATING) or bool(payload.get("confirm"))
    cacheable = (not mutating and not payload.get("refresh") and not payload.get("_nocache"))
    now = time.time()

    # Background mode: run a heavy read/compute action on the job queue and return
    # a job stub immediately (the tab doesn't wait). The result is stored on the job
    # AND in the read cache, so a later normal fetch is instant. Never background a
    # write/mutating action — those stay synchronous + confirmed.
    if payload.get("background") and not mutating:
        key = _cache_key(agent_id, action, payload)
        hit = _CACHE.get(key)
        if hit and (now - hit[0]) < _CACHE_TTL:          # already have it — skip the job
            body, status = hit[1]
            if isinstance(body, dict):
                body = dict(body); body["_cached"] = True
            return body, status

        def _work():
            inner = dict(payload); inner.pop("background", None)
            out = fn(inner)
            if isinstance(out, tuple) and len(out) == 2:
                _CACHE[_cache_key(agent_id, action, inner)] = (time.time(), out)
                return out[0]
            return out

        job = jobq.submit(_work, {"agent": agent_id, "action": action,
                                  "label": payload.get("_label") or action})
        return {"ok": True, "background": True, "job_id": job["id"], "status": job["status"],
                "message": "running in the background — track it in the Runs log"}, 202

    if cacheable:
        key = _cache_key(agent_id, action, payload)
        hit = _CACHE.get(key)
        if hit and (now - hit[0]) < _CACHE_TTL:
            body, status = hit[1]
            if isinstance(body, dict):          # mark it so the UI can show "cached"
                body = dict(body)
                body["_cached"] = True
                body.setdefault("_cache_age", round(now - hit[0], 1))
            return body, status

    # Run synchronously, profiling the queries so the Runs log shows this run + the
    # exact SQL it issued (for troubleshooting the skill/code that produced it).
    qprofile.set_context(agent_id, action)
    _m = qprofile.mark()
    _t0 = now
    try:
        out = fn(payload)
    except Exception as e:  # pragma: no cover
        qs = qprofile.since(_m); qprofile.clear_context()
        if not mutating and qs:
            jobq.record({"agent": agent_id, "action": action,
                         "label": payload.get("_label") or action, "status": "error",
                         "ok": False, "message": f"{type(e).__name__}: {e}",
                         "elapsed": time.time() - _t0, "queries": qs})
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}, 500
    qs = qprofile.since(_m); qprofile.clear_context()

    if not mutating and qs:                      # log every read run that touched the db
        body = out[0] if isinstance(out, tuple) else out
        ok = True if not isinstance(body, dict) else (body.get("ok", True) is not False)
        total_ms = sum(q.get("ms", 0) for q in qs)
        jobq.record({"agent": agent_id, "action": action,
                     "label": payload.get("_label") or action,
                     "status": "done" if ok else "error", "ok": ok,
                     "message": "%d quer%s · %.0f ms" % (len(qs), "ies" if len(qs) != 1 else "y", total_ms),
                     "elapsed": time.time() - _t0, "queries": qs})

    if mutating:
        _invalidate(agent_id)                    # data may have changed — drop stale reads
    elif cacheable and isinstance(out, tuple) and len(out) == 2:
        if len(_CACHE) >= _CACHE_MAX:
            oldest = min(_CACHE, key=lambda k: _CACHE[k][0])
            _CACHE.pop(oldest, None)
        _CACHE[_cache_key(agent_id, action, payload)] = (now, out)
    return out
