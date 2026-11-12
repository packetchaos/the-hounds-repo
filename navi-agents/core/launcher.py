"""Shared launcher logic — discovery + generic action dispatch.

Both app_fastapi.py and app_flask.py import this so behavior is identical.
Drop a new agent folder into agents/ and restart: it is discovered, its
api.ACTIONS are mounted under /api/<id>/<action>, and the hub lists it.
"""
import contextvars
import hashlib
import json
import re
import os
import sqlite3
import threading
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
_MUTATING = {"hx_cancel", "tag_cancel", "release_cancel",   # stop work: never cached/backgrounded
             "apply", "assign", "tag", "tag_candidate", "send", "delete", "remove", "rotate",
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


# ---- results.db awareness (core/payload.ResultStore) -----------------------------------
# A contract response points at a stored run ({drill:{run,…}}); the store keeps only the last
# KEEP_RUNS runs per hound, so a remembered response can outlive its rows. A cache hit whose
# run ids are no longer in the store is dropped and the action runs again.
_RUN_ID_RE = None


def _store_runs(body, depth=0, out=None):
    """Run ids (hound-<16 hex>) a response body hands the page: drill.run / run fields, shallow."""
    global _RUN_ID_RE
    if _RUN_ID_RE is None:
        import re
        _RUN_ID_RE = re.compile(r"^[a-z0-9_]{1,40}-[0-9a-f]{16}$")
    out = set() if out is None else out
    if depth > 3 or not isinstance(body, dict):
        return out
    for k, v in body.items():
        if k == "run" and isinstance(v, str) and _RUN_ID_RE.match(v):
            out.add(v)
        elif isinstance(v, dict):
            _store_runs(v, depth + 1, out)
    return out


def _db_sig():
    """navi.db's (size, mtime) incl. its WAL — a sync changes it."""
    p = db.db_path()
    out = []
    for suf in ("", "-wal"):
        try:
            st = os.stat(p + suf)
            out.append((st.st_size, st.st_mtime_ns))
        except (OSError, TypeError):
            out.append(None)
    return tuple(out)


def _cache_hit(key, now):
    """The remembered (body, status) for `key` while fresh AND its stored runs still exist.
    Entries a DETACHED run left (see _detached) live for _DETACHED_TTL instead of _CACHE_TTL,
    until navi.db changes — so coming back to a page after a long run shows its result."""
    hit = _CACHE.get(key)
    if not hit:
        return None
    ttl = hit[2] if len(hit) > 2 else _CACHE_TTL
    if (now - hit[0]) >= ttl or (len(hit) > 3 and hit[3] != _db_sig()):
        if len(hit) > 2:
            _CACHE.pop(key, None)
        return None
    runs = _store_runs(hit[1][0] if isinstance(hit[1], tuple) else None)
    if runs:
        try:
            from . import payload as _payload
            if any(_payload.STORE.run_info(r) is None for r in runs):
                _CACHE.pop(key, None)            # its results.db rows were pruned — recompute
                return None
        except Exception:
            _CACHE.pop(key, None)
            return None
    return hit


# ---- response size watch -----------------------------------------------------------------
# The payload contract caps migrated hounds at ~2 MB (core/payload.MAX_BYTES). Un-migrated
# pages still work — the HTTP layer reports each API response's size here and anything over
# the limit is logged (stderr + the last few kept for Settings/tests), never refused.
# Known Phase 2 offender: postquantum `run` (89 MB at 150k assets, 168 MB partial at 600k).
_BIG_LIMIT = int(os.environ.get("NAVI_RESPONSE_WARN_BYTES", str(2 * 1024 * 1024)))
BIG_RESPONSES: list = []


def note_response(agent_id, action, nbytes):
    """Log (don't fail) an API response over NAVI_RESPONSE_WARN_BYTES (2 MB)."""
    try:
        n = int(nbytes or 0)
    except (TypeError, ValueError):
        return False
    if n <= _BIG_LIMIT or action in ("export",):   # an explicit file download, not a page payload
        return False
    rec = {"agent": agent_id, "action": action, "bytes": n, "at": time.time()}
    BIG_RESPONSES.append(rec)
    del BIG_RESPONSES[:-50]
    try:
        import sys
        print("[hounds] large response: %s/%s %.1f MB (> %.1f MB payload contract — not yet migrated)"
              % (agent_id, action, n / 1048576.0, _BIG_LIMIT / 1048576.0), file=sys.stderr, flush=True)
    except Exception:
        pass
    return True


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
    return redact.scrub({"ok": True, "jobs": jobq.list_jobs(), "counts": jobq.counts(), "boot": jobq.BOOT})


def jobs_get(job_id) -> dict:
    try:
        j = jobq.get(job_id)
    except (TypeError, ValueError):
        j = None
    # `now`: the server's clock, so a page shows a run's elapsed time without trusting its own
    return redact.scrub({"ok": True, "job": j, "now": time.time(), "boot": jobq.BOOT} if j
                        else {"ok": False, "error": "no such job", "boot": jobq.BOOT})


def jobs_cancel(job_id) -> dict:
    """Stop a detached ▶ Run (its SQL raises QueryCancelled at the next statement). Only runs
    of the "run" pool — never a confirmed tag job, a snapshot or a Release run."""
    return {"ok": bool(jobq.cancel(job_id, pool="run"))}


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


# ---- request budgets (core/db.budget_scope) -------------------------------------------
# Every HTTP request runs under a DEFAULT query budget picked here, so no hound has to pass
# one: page-open reads → "open" (NAVI_OPEN_BUDGET_S, 5 s for the whole request), ▶ Run →
# "run" (NAVI_RUN_BUDGET_S, 2 h), background work → "job" (core/jobq, core/release).
# Statements that pass their own budget= keep it. Writes (mutating actions / confirm) get NO
# default budget and are never cancelled mid-way — exactly as before.
# Page-open reads: what each page POSTs on load before any click (recorded with Playwright
# from every agents/*/page.html + web/*.html, build 455). An action a page ALSO sends from a
# ▶ Run / search click (ex_*.search, compliance.overview…) is NOT listed — the server can't
# tell the two apart, so it gets the run budget unless the client says otherwise
# (X-Hounds-Budget: open|run — see request_scope).
_OPEN_ACTIONS = {
    ("acr", "metrics"), ("acr", "run"), ("acr", "log"), ("agentgroup", "run"),
    ("alert", "history"), ("alert", "list"), ("alert", "metrics"), ("alert", "suggest"),
    ("c2", "catalog"), ("c2", "glance"), ("c2", "hosts"), ("c2", "run_status"), ("c2", "status"),
    ("c2", "c2log"), ("cisakev", "source"), ("mitre", "source"), ("settings", "downloads"),
    ("compliance_asset", "detail"), ("contract", "get"), ("contract", "loop_log"),
    ("custom_audit", "benchmarks"), ("custom_audit", "platforms"), ("custom_audit", "render"),
    ("email", "status"), ("mcpcmp", "snapshot"), ("tagremoval", "run"),
    ("tagremoval", "asset_delta"), ("explore", "tags_compare"), ("explore", "activity"),
    ("explore", "tag_jobs"), ("explore", "which_agent"), ("was_asset", "info"),
    ("compliance", "framework"), ("compliance", "frameworks"),
    ("settings", "asset_delta"), ("settings", "db_checks"), ("settings", "hx_status"),
    ("settings", "navi_jobs"), ("settings", "sla_get"), ("settings", "status"),
    ("hub", "pc_get"), ("hub", "pc_put"), ("hub", "pc_list"), ("hub", "roster"),
    ("hub", "release_plan"), ("hub", "release_status"), ("hub", "release_start"),
    ("hub", "release_cancel"),
}
# long orchestration runs started from a page → the background budget (2 h, heavy)
_JOB_ACTIONS = {("contract", "run_now"), ("contract", "plan")}
_HINTS = ("open", "run")                 # what a client may ask for (never "job")
_RUN_SET = None


def _run_actions() -> set:
    """(agent, action) pairs a ▶ Run sends — from core/release_recipes.json."""
    global _RUN_SET
    if _RUN_SET is None:
        out = set()
        try:
            from . import release
            for r in release.recipes().get("pages", []):
                if r.get("kind") == "snapshot":
                    out.add((r["agent"], r.get("action") or "snapshot"))
                for q in r.get("requests") or []:
                    out.add((q["agent"], q["action"]))
        except Exception:
            pass
        _RUN_SET = out
    return _RUN_SET


# ---- detached ▶ Runs (build 458) ---------------------------------------------------------------
# A ▶ Run from the console (X-Hounds-Budget: run-bg) runs as a jobq job from the start. The request
# waits up to _FOREGROUND_S for it: a quick run answers inline exactly as before; a long one answers
# 202 {pending, job_id, started, now} and keeps running on the server under the "job" budget (2 h by
# default) — the page shows it as running with its elapsed time, and leaving the page doesn't stop
# it. An identical ▶ Run while it runs attaches to the same job. Its result stays in the read cache
# for _DETACHED_TTL (until navi.db changes), so a later ▶ shows it instantly.
_FOREGROUND_S = float(os.environ.get("HOUNDS_FOREGROUND_S", "20"))
_DETACHED_TTL = float(os.environ.get("HOUNDS_DETACHED_CACHE_S", str(24 * 3600)))
_NODETACH_AGENTS = {"hub", "settings", "jobs", "profile"}
_DET: dict = {}                           # cache key (agent, action, payload, navi.db, tag prefix) -> job id
_TL = threading.local()                   # .in_job: this thread runs a detached job (its own Runs entry)
_DET_LOCK = threading.Lock()


# never detached: anything that writes (the console's H_WRITE_RE — a write without `confirm` too)
# and the quick reads a page fires around a run (drill-downs, paging, live status polls…)
_WRITE_NAME = re.compile(
    r"^(apply|bulk_apply|assign|tag|tag_.+|.+_tag|tags_.+|send|send_.+|delete|remove|rotate|encrypt|"
    r"decrypt|refresh|save|set|set_.+|.+_set|toggle|add_.+|arm|disarm|run_now|command|upload|push_file|"
    r"campaign|abort|verify|run_checks|cred_test|path_check|deploy|rollback|promote|ignore_.+|"
    r"detections_.+|evaluate|test|trust|run_all|reset_usage|navi_.+|build_from_.+)$")
_READ_OK_NAMES = {"tag_plan", "os_plan", "detections_export"}
_QUICK_NAME = re.compile(
    r"^(drill|page|.+_page|count|counts|status|.+_status|poll|.+_poll|glance|hosts|catalog|c2log|log|"
    r".+_log|detail|lookup|info|source|platforms|benchmarks|render|get|tag_jobs|activity|which_agent)$")


def _detachable(agent_id, action, payload) -> bool:
    acts = DISPATCH.get(agent_id) or {}
    if _WRITE_NAME.match(action) and action not in _READ_OK_NAMES:
        return False
    return (agent_id not in _NODETACH_AGENTS and action in acts and action not in _LIVE
            and not _QUICK_NAME.match(action)
            and not payload.get("background") and not payload.get("peek")
            and not is_mutating(action, payload))


_MAX_RUNS = int(os.environ.get("HOUNDS_MAX_DETACHED", "12"))           # queued + running ▶ Runs
_MAX_RUNS_AGENT = int(os.environ.get("HOUNDS_MAX_DETACHED_AGENT", "3"))  # … per hound


def _detached(agent_id, action, payload):
    p = dict(payload)
    pc = {x: v for x, v in p.items() if x != "_run"}
    # the cache / attach key and navi.db's signature are taken NOW, at the start: a run that
    # outlives a sync or a navi.db switch must not be filed under the new database
    key0 = _cache_key(agent_id, action, pc)
    sig0 = _db_sig()
    if not (p.get("refresh") or p.get("_nocache")) and agent_id not in _NOCACHE_AGENTS \
            and action not in _OWN_CACHE:
        hit = _cache_hit(key0, time.time())
        if hit:                                   # answered before (e.g. by a detached run): no job
            return _dispatch_run(agent_id, action, p)
    with _DET_LOCK:
        jid = _DET.get(key0)
        j = jobq.get(jid) if jid else None
        if j and j.get("boot") != jobq.BOOT:
            j = None
        if not j or j["status"] not in ("queued", "running"):
            if jobq.active(pool="run") >= _MAX_RUNS or jobq.active(pool="run", agent=agent_id) >= _MAX_RUNS_AGENT:
                return {"ok": False, "busy": True,
                        "error": "too many runs in progress — wait for one to finish (or cancel one in the "
                                 "Runs log) and run this again",
                        "message": "too many runs in progress"}, 429
            ctx = contextvars.copy_context()

            def _work():
                # on a jobq "run" worker: the "job" budget + this job's cancel token (core/jobq._run)
                _TL.in_job = True
                t_start = time.time()
                try:
                    # the "run" scope (2 h, NOT heavy), as the same ▶ had inline: jobq's "job" scope
                    # makes every statement heavy, and one long run would serialise every other ▶
                    with db.budget_scope("run"):
                        out = _dispatch_run(agent_id, action, dict(p))
                finally:
                    _TL.in_job = False
                body = out[0] if isinstance(out, tuple) and len(out) == 2 else out
                k_end = _cache_key(agent_id, action, pc)
                if k_end != key0 or _db_sig() != sig0:
                    # navi.db changed (a sync) or was switched while this ran: keep nothing
                    _CACHE.pop(k_end, None)
                    _CACHE.pop(key0, None)
                else:
                    hit = _CACHE.get(key0)
                    # only an entry THIS run wrote (not an older one it bypassed with ↻ fresh, or
                    # one left over when it was cancelled / budget-limited / failed)
                    if hit is not None and hit[0] >= t_start:
                        _CACHE[key0] = (hit[0], hit[1], _DETACHED_TTL, sig0)
                return body if isinstance(body, dict) else {"ok": True, "result": body}

            stub = jobq.submit(lambda: ctx.run(_work), {"agent": agent_id, "action": action,
                                                         "label": p.get("_label") or action}, pool="run")
            jid = stub["id"]
            _DET[key0] = jid
            if len(_DET) > 500:
                for k in list(_DET)[:250]:
                    _DET.pop(k, None)
    t_end = time.time() + _FOREGROUND_S
    nap = 0.05
    while True:
        j = jobq.get(jid)
        if j is None:
            return {"ok": False, "error": "the run was lost — run it again"}, 200
        if j["status"] in ("done", "error"):
            res = j.get("result")
            if not isinstance(res, dict):
                res = {"ok": False, "error": j.get("message") or "failed"}
            return res, 200
        if time.time() >= t_end:
            return {"ok": True, "pending": True, "job_id": jid, "boot": jobq.BOOT, "status": j["status"],
                    "created": j.get("created"), "started": j.get("started"), "now": time.time(),
                    "label": j.get("label") or action, "agent": agent_id, "action": action,
                    "message": "still running on the server — it keeps going if you leave this page"}, 202
        time.sleep(nap)
        nap = min(0.5, nap * 1.5)


def _cache_only(agent_id, action, payload, cancel=None, tab=None):
    if is_mutating(action, payload):
        return {"ok": False, "skipped": True, "error": "write skipped while restoring this page"}, 200
    token = cancel or db.Cancel()
    with db.budget_scope("open"), db.cancel_scope(token):
        out = _dispatch_run(agent_id, action, payload)
    body, status = (out if isinstance(out, tuple) and len(out) == 2 else (out, 200))
    if isinstance(body, dict) and (body.get("budget") or body.get("budget_partial")):
        return {"ok": False, "not_cached": True,
                "error": "The saved result is no longer on the server — click ▶ Run to compute it again.",
                "message": "The saved result is no longer on the server — click ▶ Run to compute it again."}, 200
    return body, status


def is_mutating(action, payload) -> bool:
    return (action in _MUTATING) or ("confirm" in (payload or {}))


def request_scope(agent_id, action, payload, hint=None):
    """The default budget for one API request: "open" | "run" | "job" | None (writes: none).
    Order: writes → none (or "job" for the Contract's runs) · background:true → "open" (the
    request only enqueues; the job runs under "job") · a ▶ Run (_run) → "run" · the client's
    hint (X-Hounds-Budget: open|run) · peek → "open" · a page-open read / live state → "open"
    · a ▶ Run action (release recipes) → "run" · anything else (search, drill-down…) → "run"."""
    payload = payload if isinstance(payload, dict) else {}
    key = (agent_id, action)
    if key in _JOB_ACTIONS:
        return "job"
    if is_mutating(action, payload):
        return None
    if payload.get("background"):
        return "open"
    if payload.get("_run"):
        return "run"
    if hint in _HINTS:
        return hint
    if payload.get("peek"):
        return "open"
    if key in _OPEN_ACTIONS or action in _LIVE:
        return "open"
    return "run"


# supersede: a newer request for the same (tab, agent, action, payload) cancels the older one
_INFLIGHT: dict = {}
_SUP_IGNORE = ("_run", "_nocache", "refresh", "_label")


def _supersede_sig(payload) -> str:
    try:
        p = {k: v for k, v in (payload or {}).items() if k not in _SUP_IGNORE}
        return hashlib.sha1(json.dumps(p, sort_keys=True, default=str).encode()).hexdigest()[:16]
    except Exception:
        return ""
_INFLIGHT_LOCK = threading.Lock()


def dispatch(agent_id: str, action: str, payload: dict, peer=None, http=False, *,
             budget_hint=None, cancel=None, tab=None):
    """Run an agent action. Every response is scrubbed of secrets (core.redact) —
    model/cloud keys never reach the browser, even inside a provider error.
    `peer` / `http`: the HTTP servers pass the TCP peer address so actions can tell a
    loopback caller from a remote one (core.gates.client_is_loopback).
    `budget_hint`: the client's X-Hounds-Budget ("open"/"run"); `cancel`: a db.Cancel the
    server trips when the client disconnects; `tab`: the client's X-Hounds-Tab id — a newer
    request for the same tab+agent+action cancels this one. Reads run under
    db.budget_scope(request_scope(...)) + db.cancel_scope(cancel); a query stopped by its
    budget / cancel / row cap answers 200 {ok:false, budget:true, message} (db.budget_payload)."""
    from . import gates
    tok = gates.set_client(peer, http=http)
    try:
        if isinstance(payload, dict) and payload.get("_cacheonly"):
            # a page-cache replay of a ▶ step whose answer the browser no longer has (console.js
            # HC): opening a page must never start a hound — serve the server's cached answer, or
            # run it under the 5 s "open" budget and say it isn't cached when that isn't enough
            return _cache_only(agent_id, action, {k: v for k, v in payload.items() if k != "_cacheonly"}, cancel, tab)
        detach = budget_hint == "run-bg"          # the console's ▶ Run: may detach (see _detached)
        if detach:
            budget_hint = "run"
        if detach and isinstance(payload, dict) and _detachable(agent_id, action, payload):
            return _detached(agent_id, action, payload)
        scope = request_scope(agent_id, action, payload, budget_hint)
        if is_mutating(action, payload if isinstance(payload, dict) else {}):
            # a write is never cancelled midway (disconnect / supersede): a confirmed Contract
            # run_now would otherwise stop half-applied. Its long run keeps the "job" budget.
            if scope == "job":
                with db.budget_scope("job"):
                    return _dispatch_run(agent_id, action, payload)
            return _dispatch_run(agent_id, action, payload)
        if scope is None:
            return _dispatch_run(agent_id, action, payload)
        token = cancel or db.Cancel()
        # supersede only the SAME request (payload minus run flags) from the same tab — two
        # different reads of one action (two sections, two lookups) must not cancel each other
        key = ((tab, agent_id, action, _supersede_sig(payload)) if tab else None)
        if key:
            with _INFLIGHT_LOCK:
                old = _INFLIGHT.get(key)
                _INFLIGHT[key] = token
            if old is not None and old is not token:
                old.cancel()
        try:
            with db.budget_scope(scope), db.cancel_scope(token):
                return _dispatch_run(agent_id, action, payload)
        finally:
            if key:
                with _INFLIGHT_LOCK:
                    if _INFLIGHT.get(key) is token:
                        _INFLIGHT.pop(key, None)
    finally:
        gates.reset_client(tok)


def _budget_mark(out, sc, n0):
    """After an action under a scope: if a statement hit its budget / was cancelled / hit the
    row cap (even one the hound caught itself), say so in the body. ok:false bodies get
    budget:true + a message (pages already show o.message / o.error); a body that still
    answered gets budget_partial:true + budget_message."""
    if sc is None or len(sc.hits) <= n0:
        return out, False
    body, status = (out if isinstance(out, tuple) and len(out) == 2 else (out, None))
    if isinstance(body, dict) and not body.get("budget"):
        bp = db.budget_payload(sc.first())
        body = dict(body)
        if body.get("ok") is False:
            body["budget"] = True
            body.setdefault("message", bp["message"])
            body.setdefault("error", bp["message"])
            for k in ("label", "seconds", "cancelled", "max_rows", "optimize"):
                if k in bp:
                    body.setdefault(k, bp[k])
        else:
            body["budget_partial"] = True
            body["budget_message"] = bp["message"]
    return ((body, status) if status is not None else body), True


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
        hit = _cache_hit(key, now) if cacheable else None  # no-cache agents always run fresh
        if hit:                                          # already have it — skip the job
            body, status = hit[1]
            if isinstance(body, dict):
                body = dict(body); body["_cached"] = True
            return body, status

        def _work():
            # runs on a jobq worker under db.budget_scope("job") (see core/jobq._run)
            inner = dict(payload); inner.pop("background", None)
            sc = db.current_scope()
            n0 = len(sc.hits) if sc is not None else 0
            out, hit = _budget_mark(fn(inner), sc, n0)
            if isinstance(out, tuple) and len(out) == 2:
                if cacheable and not hit:
                    _CACHE[_cache_key(agent_id, action, inner)] = (time.time(), out)
                return out[0]
            return out

        # carry the request's context (core.gates' client peer) onto the worker thread, so a
        # gate checked inside the action (loopback-only…) sees the real caller, not "in-process"
        _ctx = contextvars.copy_context()
        job = jobq.submit(lambda: _ctx.run(_work), {"agent": agent_id, "action": action,
                                  "label": payload.get("_label") or action})
        # cached_result: whether the finished job's answer is kept in the read cache, so a
        # normal re-run of the same read is served instantly (console.js HB "Show results")
        return {"ok": True, "background": True, "job_id": job["id"], "status": job["status"],
                "cached_result": bool(cacheable),
                "message": "running in the background — track it in the Runs log"}, 202

    if cacheable:
        key = _cache_key(agent_id, action, payload)
        hit = _cache_hit(key, now)
        if hit:
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
    sc = db.current_scope()
    n0 = len(sc.hits) if sc is not None else 0
    try:
        out = fn(payload)
    except Exception as e:  # pragma: no cover
        qs = qprofile.since(_m); qprofile.clear_context()
        # a budget / cancel / row cap (or a private connection interrupted by the scope) is an
        # answer, not a crash: 200 {ok:false, budget:true, message}
        bud = isinstance(e, (db.QueryTimeout, db.TooManyRows)) or (
            sc is not None and len(sc.hits) > n0 and isinstance(e, sqlite3.OperationalError)
            and "interrupt" in str(e).lower())
        if not mutating and qs and not getattr(_TL, "in_job", False):
            jobq.record({"agent": agent_id, "action": action,
                         "label": payload.get("_label") or action, "status": "error",
                         "ok": False, "message": (("budget: " if bud else "") + f"{type(e).__name__}: {e}"),
                         "elapsed": time.time() - _t0, "queries": qs})
        if bud:
            return db.budget_payload(e if isinstance(e, (db.QueryTimeout, db.TooManyRows))
                                     else sc.first()), 200
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}, 500
    qs = qprofile.since(_m); qprofile.clear_context()
    out, hit = _budget_mark(out, sc, n0)
    if hit:
        cacheable = False                        # never remember a budget-limited answer

    if not mutating and qs and not getattr(_TL, "in_job", False):   # log every read run that touched the db
        body = out[0] if isinstance(out, tuple) else out
        ok = True if not isinstance(body, dict) else (body.get("ok", True) is not False)
        total_ms = sum(q.get("ms", 0) for q in qs)
        jobq.record({"agent": agent_id, "action": action,
                     "label": payload.get("_label") or action,
                     "status": "done" if ok else "error", "ok": ok,
                     "message": "%d quer%s · %.0f ms%s" % (len(qs), "ies" if len(qs) != 1 else "y", total_ms,
                                                         " · budget hit" if hit else ""),
                     "elapsed": time.time() - _t0, "queries": qs})

    if mutating:
        _invalidate(agent_id)                    # data may have changed — drop stale reads
    elif cacheable and isinstance(out, tuple) and len(out) == 2:
        if len(_CACHE) >= _CACHE_MAX:
            oldest = min(_CACHE, key=lambda k: _CACHE[k][0])
            _CACHE.pop(oldest, None)
        _CACHE[_cache_key(agent_id, action, payload)] = (now, out)
    return out
