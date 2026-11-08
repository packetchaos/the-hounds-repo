"""Arachne — WAS HTTP actions.

overview — the consolidated dashboard (all apps): severity totals, OWASP Top-10 sums,
           tech inventory, scan coverage, risk-sorted per-app rows.
report   — the per-app App Report for ?app_uuid=<uuid> (falls back to the top-risk app),
           plus the risk-sorted app list for the page's selector.
Read-only over navi.db.
"""
from core.gates import confirmed
AGENT = None


def _agent():
    global AGENT
    if AGENT is None:
        from .agent import ArachneAgent
        AGENT = ArachneAgent()
    return AGENT


def overview(p):
    res = _agent().run()
    return {"ok": True, "agent": _agent().meta(), "result": res}, 200


def report(p):
    from core import was
    au = (p.get("app_uuid") or "").strip()
    return {"ok": True, "result": {"report": was.app_report(app_uuid=au),
                                   "apps": was.apps_list()}}, 200


def plugin_output(p):
    """Raw stored output for one plugin on one web app (findings.output/proof/headers) —
    the drill-down behind a finding row. Shared with Beagle (the WAS recon page)."""
    from core import was
    return {"ok": True, "result": was.plugin_output(
        app_uuid=(p.get("app_uuid") or "").strip(),
        plugin_id=(p.get("plugin_id") or "").strip())}, 200


def tag_plan(p):
    """Read-only: the taggable cohorts (OWASP category / severity / technology) plus the
    server's write-gate state, so the Overview can render the tagging tool + gate banner."""
    from core import was, navi_cli
    return {"ok": True, "result": was.tag_plan(),
            "writes": {"enabled": navi_cli.writes_enabled(),
                       "navi": navi_cli.navi_available(),
                       "reason": navi_cli.write_gate_reason()}}, 200


def tag(p):
    """GATED write: tag every web app matching a cohort (dimension + key) on its Tenable
    asset (asset_uuid) via navi — same path as every VM tagger. Targets are recomputed
    server-side from was.tag_targets (client UUIDs are not trusted)."""
    from core import was, navi_cli
    if not confirmed(p):
        return {"ok": False, "error": "confirm=true required to write tags"}, 400
    tgt = was.tag_targets(dimension=(p.get("dimension") or ""), key=(p.get("key") or ""))
    if not tgt:
        return {"ok": False, "error": "unknown tag cohort"}, 400
    uuids = tgt["uuids"]
    if not uuids:
        return {"ok": False, "error": "no taggable web-app assets for that cohort "
                "(the matching apps have no asset UUID)"}, 400
    cat, val = tgt["category"], tgt["value"]
    # navi tags by --query over apps.asset_uuid; tag_capped chunks past the ~1999 cap.
    jobs = navi_cli.tag_capped(cat, val, uuids=uuids, col="asset_uuid", table="apps", agent="was")
    job_ids = [j.get("job_id") for j in jobs if j.get("job_id") is not None]
    first = jobs[0] if jobs else {}
    ok = all(j.get("ok") or j.get("queued") for j in jobs) if jobs else False
    return {"ok": ok, "queued": any(j.get("queued") for j in jobs),
            "category": cat, "value": val, "asset_count": len(uuids),
            "chunks": len(jobs), "job_id": job_ids[0] if job_ids else first.get("job_id"),
            "job_ids": job_ids, "message": first.get("message"),
            "writes_enabled": navi_cli.writes_enabled(),
            "write_gate_reason": navi_cli.write_gate_reason()}, 200


ACTIONS = {"overview": overview, "report": report, "plugin_output": plugin_output,
           "tag_plan": tag_plan, "tag": tag}
