"""Sköll — SLA Adherence HTTP actions.

run — compute the SLA dashboard for a chosen owner/tag and record a daily snapshot in
      the app-owned trend store (core.history) so the coming trending agent has history.
      Read-only over navi.db; the snapshot write goes to the repo's data/ dir, not navi.db.
"""
AGENT = None


def _agent():
    global AGENT
    if AGENT is None:
        from .agent import SkollAgent
        AGENT = SkollAgent()
    return AGENT


def run(p):
    tag_key = (p.get("tag_key") or "").strip() or None
    tag_value = (p.get("tag_value") or "").strip() or None
    res = _agent().run(tag_key=tag_key, tag_value=tag_value)
    try:
        from core import sla as _sla, history
        # snapshot only the GLOBAL (unscoped) view, so the trend store stays a single
        # consistent series — a scoped one-off filter shouldn't pollute the history.
        if not res.get("scoped"):
            history.record("sla", _sla.snapshot_metrics(res), dims={"tag_key": res.get("tag_key")})
    except Exception:
        pass
    return {"ok": True, "agent": _agent().meta(), "result": res}, 200


ACTIONS = {"run": run}
