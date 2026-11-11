"""Fused Exposure Score (Nemesis) — self-contained HTTP actions.

snapshot — the page's read. The whole rollup (estate KPIs, act-now sets at 80/60/40,
           worst 500, worst-from-each-Hound) cached on disk per navi.db signature +
           weighting + SLA policy (core/snapcache.py).
             {peek:true}   what's cached / building right now; never computes
             {}            cached result if navi.db, weights and SLA policy are unchanged
                           and it was built today, else start a background build
             {force:true}  rebuild even if cached
           A build answers {building:{job_id, started}}; poll /api/jobs/<id>, then peek.
overview — synchronous read (same engine; kept for the MCP server and other callers).
tag      — Priority : P1..P4 (gated). The asset set is RECOMPUTED here from navi.db —
           {mode:"act", threshold, weights} runs on the job queue and answers
           {background:true, job_id} (poll /api/jobs/<id>; the job's result has the count);
           {mode:"one", uuid} answers at once. Client UUID lists are never trusted. Never
           removes tags.
refresh  — background `navi update assets`.
"""
import datetime

from core import fused_score as engine, jobq, navi_cli, snapcache
from .agent import FusedScoreAgent
from core.gates import confirmed

AGENT = FusedScoreAgent()
SNAP = snapcache.Snapshots("fused", version=4)   # 3: cert dates/PQ plugin, half-up rounding, tiebreak · 4: kpi.stack/cooccur
PRIORITIES = ("P1", "P2", "P3", "P4")
CHUNK = navi_cli.BATCH_UUIDS   # ≤1,999 UUIDs per navi job, byte-guarded (core.navi_cli.uuid_batches)


def _weights(p):
    w = p.get("weights")
    return w if isinstance(w, dict) and w else None


def _extra(w):
    """Cache key: the effective (normalised) weighting + the SLA windows the score uses."""
    wmap, custom = engine._resolve_weights(w)
    try:
        sla = engine._sla_days(None)
    except Exception:
        sla = {}
    return {"w": {k: round(v, 1) for k, v in sorted(wmap.items())} if custom else "default", "sla": sla}


def _submit(fn):
    return jobq.submit(fn, {"agent": "fused_score", "action": "snapshot", "label": "Exposure Score snapshot"})


def _stale(snap):
    return str((snap or {}).get("meta", {}).get("built_at", ""))[:10] != datetime.date.today().isoformat()


def _int(v, default):
    """Whole number from JSON; booleans and fractions are refused (True would read as 1)."""
    if v is None or v == "":
        return default
    if isinstance(v, bool):
        raise ValueError("bool")
    if isinstance(v, float):
        if not v.is_integer():
            raise ValueError("fraction")
        return int(v)
    return int(str(v).strip())


def load(p):
    return {"ok": True, "agent": AGENT.meta(), "result": AGENT.run()}, 200


def overview(p):
    """The fused-score rollup — per-asset score + factors, worst-from-each-Hound, convergence.
    Accepts an optional ``weights`` map (factor id -> relative weight); the engine
    re-normalises it to sum 100 so the score stays 0–100."""
    try:
        limit, offset = _int(p.get("limit"), 500), _int(p.get("offset"), 0)
    except ValueError:
        return {"ok": False, "error": "limit and offset must be whole numbers"}, 400
    if offset < 0 or not 1 <= limit <= engine.LIMIT_MAX:
        return {"ok": False, "error": f"limit must be 1–{engine.LIMIT_MAX} and offset ≥ 0"}, 400
    return {"ok": True, "result": engine.overview(limit=limit, offset=offset, weights=_weights(p))}, 200


def snapshot(p):
    w = _weights(p)
    extra = _extra(w)
    st = SNAP.state(extra=extra)
    snap, bld = st["snap"], st["building"]
    if snap and p.get("peek"):
        return {"ok": True, "result": snap, "cached": True, "stale": _stale(snap), "building": bld}, 200
    if snap and not _stale(snap) and not p.get("force"):
        return {"ok": True, "result": snap, "cached": True, "stale": False}, 200
    if p.get("peek") or bld:
        return {"ok": True, "result": None, "building": bld}, 200
    b = SNAP.start(_submit, lambda: engine.overview(limit=500, weights=w), extra=extra, label="Exposure Score")
    return {"ok": True, "result": None, "building": b}, 200


def refresh(p):
    """Background `navi update assets` so freshly-applied hound tags feed the score."""
    r = navi_cli.update_async(("assets",))
    return {"ok": bool(r.get("ok")), **r}, 200


def tag(p):
    """The one write this view makes itself — flag the act-now set Priority : <P1..P4> (gated)
    so every Hound, dashboard and the AI Contract can filter to it. Everything else hands off
    to the specialist Hounds (Terminus owners, Gabriel email, Anubis ACR, Covenant plan)."""
    if not confirmed(p):
        return {"ok": False, "error": "confirm=true required to write tags"}, 400
    value = str(p.get("value") or "P1").strip().upper()
    if value not in PRIORITIES:
        return {"ok": False, "error": "value must be one of " + ", ".join(PRIORITIES)}, 400
    mode = p.get("mode") or ("one" if p.get("uuid") else "act")
    if mode == "one":
        u = p.get("uuid")
        if not isinstance(u, str) or not u.strip():
            return {"ok": False, "error": "uuid required for a single-asset tag"}, 400
        uuids = engine.select_uuids(uuid=u.strip())
        if not uuids:
            return {"ok": False, "error": "that asset isn't in navi.db"}, 400
    elif mode == "act":
        try:
            thr = _int(p.get("threshold"), 80)
        except (TypeError, ValueError):
            return {"ok": False, "error": "threshold must be a whole number"}, 400
        if not 1 <= thr <= 100:
            return {"ok": False, "error": "threshold must be 1–100"}, 400
        w = _weights(p)
        # Recomputing the set re-scores the whole estate (~2 s at 120k assets, much longer at a
        # million), so it runs on the job queue — the request returns at once and the page polls
        # /api/jobs/<id>. A fast single-asset tag stays synchronous.
        job = jobq.submit(lambda: _tag_set(engine.select_uuids(weights=w, threshold=thr), value),
                          {"agent": "fused_score", "action": "tag", "label": f"Priority : {value} ≥ {thr}"})
        return {"ok": True, "background": True, "job_id": job.get("id"), "value": value, "threshold": thr,
                "writes_enabled": navi_cli.writes_enabled()}, 200
    else:
        return {"ok": False, "error": "mode must be 'act' or 'one'"}, 400
    r = _tag_set(uuids, value)
    return r, (200 if r.get("ok") or r.get("count") else 400)


def _tag_set(uuids, value):
    """Queue Priority : <value> on `uuids`. The set comes from the scoring model (Python), not
    a navi.db predicate; core.navi_cli.tag_set pages it (≤1,999 UUIDs and < 100 KB per --query,
    a tag series above one page — one argument over 128 KB fails with "Argument list too long")."""
    if not uuids:
        return {"ok": False, "error": "no assets to tag", "count": 0}
    jobs = navi_cli.tag_set("Priority", value, uuids=uuids, agent="fused_score")
    ok = bool(jobs) and all(j.get("ok") or j.get("blocked") for j in jobs)   # gated = queued but blocked
    return {"ok": ok, "count": len(uuids), "value": value, "jobs": jobs,
            "writes_enabled": navi_cli.writes_enabled(),
            "message": f"queued Priority : {value} on {len(uuids):,} asset(s) in {len(jobs)} navi job(s)"}


ACTIONS = {"load": load, "run": load, "overview": overview, "snapshot": snapshot,
           "tag": tag, "refresh": refresh}
