"""Minos — Compliance Overview HTTP actions.

overview — the consolidated dashboard (read-only over the compliance table) + the
           server's write-gate state (so the page can render the tagging tool + banner).
tag      — GATED: assign an 'Audit Owner' to the assets that FAIL one control, via navi
           (same asset-UUID tag path as every VM/WAS tagger).
"""
from core.gates import confirmed
AGENT = None


def _agent():
    global AGENT
    if AGENT is None:
        from .agent import MinosAgent
        AGENT = MinosAgent()
    return AGENT


def overview(p):
    from core import navi_cli
    return {"ok": True, "agent": _agent().meta(), "result": _agent().run(),
            "writes": {"enabled": navi_cli.writes_enabled(), "navi": navi_cli.navi_available(),
                       "reason": navi_cli.write_gate_reason()}}, 200


def tag(p):
    from core import compliance as _c, navi_cli
    if not confirmed(p):
        return {"ok": False, "error": "confirm=true required to write tags"}, 400
    owner = (p.get("owner") or p.get("value") or "").strip()
    if not owner:
        return {"ok": False, "error": "an owner name is required"}, 400
    tgt = _c.control_targets(check_id=(p.get("check_id") or ""),
                             failed_only=(p.get("failed_only", True) is not False))
    if not tgt:
        return {"ok": False, "error": "check_id required"}, 400
    uuids = tgt["uuids"]
    if not uuids:
        return {"ok": False, "error": "no assets fail that control — nothing to tag"}, 400
    cat = _c.TAG_OWNER_CATEGORY
    # the control's failing set, computed here and paged (≤1,999 per navi job; a series above)
    jobs = navi_cli.tag_set(cat, owner, uuids=uuids, col="asset_uuid", table="compliance",
                            agent="compliance")
    job_ids = [j.get("job_id") for j in jobs if j.get("job_id") is not None]
    first = jobs[0] if jobs else {}
    ok = all(j.get("ok") or j.get("queued") for j in jobs) if jobs else False
    return {"ok": ok, "queued": any(j.get("queued") for j in jobs),
            "category": cat, "value": owner, "check_name": tgt["check_name"],
            "asset_count": len(uuids), "job_id": job_ids[0] if job_ids else first.get("job_id"),
            "job_ids": job_ids, "message": first.get("message"),
            "writes_enabled": navi_cli.writes_enabled(),
            "write_gate_reason": navi_cli.write_gate_reason()}, 200


def frameworks(p):
    """List the compliance frameworks present (HIPAA / PCI / NIST / CIS / ISO …) — the
    Compliance Dashboard dropdown."""
    from core import compliance as _c
    return {"ok": True, "result": _c.frameworks_list()}, 200


def framework(p):
    """Adherence for one framework — every finding mapped to it, rolled up."""
    from core import compliance as _c
    fw = (p.get("framework") or "").strip()
    if not fw:
        return {"ok": False, "error": "framework required"}, 400
    return {"ok": True, "result": _c.framework_view(fw)}, 200


ACTIONS = {"overview": overview, "tag": tag, "frameworks": frameworks, "framework": framework}
