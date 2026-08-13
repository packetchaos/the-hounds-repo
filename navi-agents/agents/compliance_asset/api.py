"""Tiresias — Compliance Asset deep-dive HTTP actions.

run    — readiness stub (the hub's generic Execute).
detail — payload {asset_uuid} (falls back to the worst-failing asset) → its audit checks
         (pass/fail/warn + actual/expected/frameworks), its vulns, and the inferred
         audit↔vuln correlations; plus the compliance asset list for the page selector.
tag    — GATED: tag this asset with an 'Audit-Vuln Link' for a correlated topic, via navi.
"""
AGENT = None


def _agent():
    global AGENT
    if AGENT is None:
        from .agent import TiresiasAgent
        AGENT = TiresiasAgent()
    return AGENT


def run(p):
    return {"ok": True, "agent": _agent().meta(), "result": _agent().run()}, 200


def detail(p):
    from core import compliance as _c, navi_cli
    au = (p.get("asset_uuid") or p.get("asset") or "").strip()
    return {"ok": True, "result": {"detail": _c.asset_detail(asset_uuid=au),
                                   "assets": _c.assets_list()},
            "writes": {"enabled": navi_cli.writes_enabled(), "navi": navi_cli.navi_available(),
                       "reason": navi_cli.write_gate_reason()}}, 200


def tag(p):
    from core import compliance as _c, navi_cli
    if not p.get("confirm"):
        return {"ok": False, "error": "confirm=true required to write tags"}, 400
    topic = (p.get("topic") or p.get("value") or "").strip()
    if not topic:
        return {"ok": False, "error": "correlation topic required"}, 400
    tgt = _c.correlation_targets(asset_uuid=(p.get("asset_uuid") or ""))
    if not tgt or not tgt["uuids"]:
        return {"ok": False, "error": "asset_uuid required"}, 400
    cat = _c.TAG_LINK_CATEGORY
    jobs = navi_cli.tag_capped(cat, topic, uuids=tgt["uuids"], col="asset_uuid",
                               table="compliance", agent="compliance_asset")
    job_ids = [j.get("job_id") for j in jobs if j.get("job_id") is not None]
    first = jobs[0] if jobs else {}
    ok = all(j.get("ok") or j.get("queued") for j in jobs) if jobs else False
    return {"ok": ok, "queued": any(j.get("queued") for j in jobs), "category": cat, "value": topic,
            "asset_count": len(tgt["uuids"]), "job_id": job_ids[0] if job_ids else first.get("job_id"),
            "job_ids": job_ids, "message": first.get("message"),
            "writes_enabled": navi_cli.writes_enabled(),
            "write_gate_reason": navi_cli.write_gate_reason()}, 200


def audit_files(p):
    """The AUDIT-FILE lens (aggregate): the audit-file leaderboard + the estate-wide
    audit↔vuln correlation, side by side."""
    from core import compliance as _c
    return {"ok": True, "result": _c.audit_overview()}, 200


def audit_file(p):
    """One audit file, all its assets: adherence, checks rollup, assets rollup, and the
    file-scoped audit↔vuln correlation."""
    from core import compliance as _c
    return {"ok": True, "result": _c.audit_detail(p.get("audit_file") or p.get("file") or "")}, 200


ACTIONS = {"run": run, "detail": detail, "tag": tag,
           "audit_files": audit_files, "audit_file": audit_file}
