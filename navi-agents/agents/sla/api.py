"""Sköll — SLA Adherence HTTP actions.

snapshot — the page's read. The full dashboard for one view (segment key + filter value),
           cached on disk per navi.db signature + SLA thresholds (agents/sla/agent.py).
             {peek:true}   what's cached / building right now; never computes
             {}            cached result if navi.db + SLA policy are unchanged and it was
                           built today, else start a background build
             {force:true}  rebuild even if cached
           A build answers {building:{job_id, started}}; poll /api/jobs/<id>, then peek.
           Every answer carries the stored daily history (core.history) for the trend charts.
run      — legacy synchronous read (same result; uses the cache when valid). Kept for
           callers outside the page.
history  — the stored daily snapshots only.

An unscoped build records the day's point in the app-owned trend store (data/, not
navi.db). Read-only over navi.db — no tag writes here.
"""
from core import jobq

AGENT = None


def _agent():
    global AGENT
    if AGENT is None:
        from .agent import SkollAgent
        AGENT = SkollAgent()
    return AGENT


def _view(p):
    return ((p.get("tag_key") or "").strip() or None, (p.get("tag_value") or "").strip() or None)


def _history():
    """Stored daily points that actually carry numbers (empty days are dropped)."""
    try:
        from core import history
        pts = [{"date": r.get("date"), "metrics": r.get("metrics") or {}}
               for r in history.series("sla", limit=400)]
        return [r for r in pts if r["metrics"]]
    except Exception:
        return []


def _submit(fn):
    return jobq.submit(fn, {"agent": "sla", "action": "snapshot", "label": "SLA snapshot"})


def snapshot(p):
    from .agent import snapshot_state, start_build
    tk, tv = _view(p)
    st = snapshot_state(tag_key=tk, tag_value=tv)
    base = {"ok": True, "history": _history()}
    if st["snap"] and p.get("peek"):
        return {**base, "result": st["snap"], "cached": True, "stale": st["stale"],
                "building": st["building"]}, 200
    if st["snap"] and not st["stale"] and not p.get("force"):
        return {**base, "result": st["snap"], "cached": True, "stale": False}, 200
    if p.get("peek"):
        return {**base, "result": None, "building": st["building"]}, 200
    if st["building"]:
        return {**base, "result": None, "building": st["building"]}, 200
    b = start_build(_submit, tag_key=tk, tag_value=tv)
    return {**base, "result": None, "building": b}, 200


def run(p):
    tk, tv = _view(p)
    res = _agent().run(tag_key=tk, tag_value=tv)
    return {"ok": True, "agent": _agent().meta(), "result": res}, 200


def history(p):
    return {"ok": True, "history": _history()}, 200


ACTIONS = {"run": run, "snapshot": snapshot, "history": history}
