"""Shared launcher logic — discovery + generic action dispatch.

Both app_fastapi.py and app_flask.py import this so behavior is identical.
Drop a new agent folder into agents/ and restart: it is discovered, its
api.ACTIONS are mounted under /api/<id>/<action>, and the hub lists it.
"""
import json
import os
import time

from . import health as _health, discovery, db, jobq, qprofile, redact, activity

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
_MUTATING = {"apply", "assign", "tag", "tag_candidate", "send", "delete", "remove", "rotate",
             "encrypt", "decrypt", "refresh", "detections_decide", "ignore_add",
             "ignore_remove", "ignore_import", "promote", "acr", "set_acr",
             # contract state changes — must drop the cached `get` so the UI sees them
             "set", "arm", "disarm", "load", "add_removals",
             # alert (Alert Raven) state changes — new/edited/removed alerts + evaluations + test email
             "save", "toggle", "add_template", "evaluate", "send_test",
             # Settings — env + config-store changes must drop the cached `status`
             "set_env", "config_mode", "sla_set", "reset_usage",
             # Command & Control — remote execution (gated + confirm) and run control
             "command", "upload", "push_file", "campaign", "abort", "run_checks", "cred_test",
             "path_check", "deploy", "rollback"}


# Live state — job progress, status, logs — must never be served from the result cache
# (a cached navi_jobs made Settings' update buttons look dead). The Settings control panel
# is live end to end.
# The Search Hounds (Argos + the explorers + Advanced) answer a question about navi.db as it is
# NOW — every search goes to the database, never a remembered answer.
_NOCACHE_AGENTS = {"settings", "hub", "argos", "explore", "ex_apps", "ex_assets", "ex_fixed", "ex_paths",
                   "ex_plugins", "ex_routes", "ex_tags", "ex_vulns",
                   # Command & Control: live gate / runs / command log — never a remembered answer
                   "c2"}
_LIVE = {"status", "log", "loop_log", "history", "scheduler", "list", "get", "metrics",
         "tag_jobs", "navi_poll", "navi_jobs", "db_checks", "sla_get", "activity"}
# actions with their own server-side snapshot (or a peek of one): the short result cache
# would only serve a stale "building…" / old summary. Still counted as runs (unlike _LIVE).
_OWN_CACHE = {"snapshot", "scent"}


def _cache_key(agent_id, action, payload):
    p = {k: v for k, v in (payload or {}).items() if k not in ("refresh", "_nocache", "_run")}
    try:
        ps = json.dumps(p, sort_keys=True, default=str)
    except Exception:
        ps = str(p)
    try:
        dbp = db.db_path()
    except Exception:
        dbp = ""
    # Settings → Test run changes what a hound writes (tag names in plans / exports / previews)
    # and what its readers match — a result computed under another prefix must not be served
    try:
        from core import tagname
        tp = tagname.prefix() + "|" + tagname.configured_prefix()
    except Exception:
        tp = ""
    return f"{agent_id}|{action}|{ps}|{dbp}|{tp}"


def _invalidate(agent_id):
    for k in [k for k in _CACHE if k.startswith(agent_id + "|")]:
        _CACHE.pop(k, None)


def clear_cache():
    _CACHE.clear()


def registry() -> dict:
    return discovery.registry(RECORDS)


def health() -> dict:
    return redact.scrub(_health.health())


def jobs_list() -> dict:
    return redact.scrub({"ok": True, "jobs": jobq.list_jobs(), "counts": jobq.counts()})


def jobs_get(job_id) -> dict:
    j = jobq.get(job_id)
    return redact.scrub({"ok": True, "job": j} if j else {"ok": False, "error": "no such job"})


def jobs_clear() -> dict:
    return {"ok": True, "cleared": jobq.clear()}


def profile() -> dict:
    """Recent queries (newest-first) + the index advisor's suggestions."""
    log = list(reversed(qprofile.entries()))
    return {"ok": True, "log": log[:300], "advisor": qprofile.suggest(db.db_path())}


def profile_clear() -> dict:
    qprofile.clear()
    return {"ok": True}


def post_guard(get_header):
    """Reject cross-site POSTs (kept for back-compat — the full per-request gate, including
    the Host allowlist and the access token, is core.security.check, which every server
    runs first). Returns an error string, or None when the request is fine."""
    from . import security
    return security.post_guard(get_header)


def request_gate(method, path, get_header, peer_addr=None):
    """Host allowlist + access token + POST guard for ONE request — see core.security."""
    from . import security
    return security.check(method, path, get_header, peer_addr)


def dispatch(agent_id: str, action: str, payload: dict, peer=None, http=False):
    """Run an agent action. Every response is scrubbed of secrets (core.redact) —
    model/cloud keys never reach the browser, even inside a provider error.
    `peer` / `http`: the HTTP servers pass the TCP peer address so actions can tell a
    loopback caller from a remote one (core.gates.client_is_loopback)."""
    from . import gates
    tok = gates.set_client(peer, http=http)
    try:
        return _dispatch_run(agent_id, action, payload)
    finally:
        gates.reset_client(tok)


def _dispatch_run(agent_id: str, action: str, payload: dict):
    payload = dict(payload if isinstance(payload, dict) else {})
    # the browser tags requests set off by a ▶ Run / Run all / Enter with _run:1 — those
    # (and only those) are this hound's durable run history (core.activity)
    run_id = payload.pop("_run", None)
    is_run = bool(run_id)
    t0 = time.time()
    out = _dispatch(agent_id, action, payload)
    if is_run and action not in _LIVE:
        body = out[0] if isinstance(out, tuple) else out
        ok = not (isinstance(body, dict) and body.get("ok") is False)
        activity.note_run(agent_id, action, ok=ok, ms=(time.time() - t0) * 1000,
                          cached=bool(isinstance(body, dict) and body.get("_cached")),
                          rid=run_id if isinstance(run_id, str) else None)
    if isinstance(out, tuple) and len(out) == 2:
        return redact.scrub(out[0]), out[1]
    return redact.scrub(out)


def _dispatch(agent_id: str, action: str, payload: dict):
    acts = DISPATCH.get(agent_id)
    if acts is None:
        return {"ok": False, "error": f"agent '{agent_id}' is not deployed"}, 404
    fn = acts.get(action)
    if not fn:
        return {"ok": False, "error": f"unknown action '{action}' for '{agent_id}'"}, 404
    payload = payload or {}
    # any request that carries a confirm key (true OR a bogus "false") is a write attempt:
    # never cached, and it invalidates this agent's reads. Approval itself is checked
    # strictly (core.gates.confirmed) inside each action.
    mutating = (action in _MUTATING) or ("confirm" in payload)
    cacheable = (not mutating and not payload.get("refresh") and not payload.get("_nocache")
                 and agent_id not in _NOCACHE_AGENTS and action not in _LIVE
                 and action not in _OWN_CACHE)
    now = time.time()

    # Background mode: run a heavy read/compute action on the job queue and return
    # a job stub immediately (the tab doesn't wait). The result is stored on the job
    # AND in the read cache, so a later normal fetch is instant. Never background a
    # write/mutating action — those stay synchronous + confirmed.
    if payload.get("background") and not mutating:
        # the same key the job stores its result under (the payload without `background`)
        key = _cache_key(agent_id, action, {k: v for k, v in payload.items() if k != "background"})
        hit = _CACHE.get(key) if cacheable else None      # no-cache agents always run fresh
        if hit and (now - hit[0]) < _CACHE_TTL:          # already have it — skip the job
            body, status = hit[1]
            if isinstance(body, dict):
                body = dict(body); body["_cached"] = True
            return body, status

        def _work():
            inner = dict(payload); inner.pop("background", None)
            out = fn(inner)
            if isinstance(out, tuple) and len(out) == 2:
                if cacheable:
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
