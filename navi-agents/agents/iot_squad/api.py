"""IoT Discovery Squad — self-contained HTTP actions."""
from core import navi_cli, iot_registry, iot_common
from .agent import IoTSquadOrchestrator
from core.gates import confirmed

AGENT = IoTSquadOrchestrator()


def run(p):
    p = p or {}
    use_pack = bool(p.get("use_pack"))
    try:
        res = AGENT.run(use_pack=use_pack)
    except FileNotFoundError as e:          # no navi.db at all — say so, don't 500
        return {"ok": False, "error": str(e)}, 200
    return {"ok": True, "agent": AGENT.meta(), "result": res,
            "options": {"use_pack": use_pack,
                        "pack_size": len(iot_common.term_pack()),
                        "byo_pack": bool(__import__("os").environ.get("IOT_TERM_PACK_PATH")),
                        "supplied_carriers": len(iot_common.byo_carrier_plugins())}}, 200


def _tag_selector(cat, val, s):
    """Apply ONE navi built-in selector (--plugin/--output/--name), or --query only
    for signal-fusion groups that have no plugin signature. Add-only."""
    if s.get("plugin"):
        return navi_cli.tag(cat, val, plugin=str(s["plugin"]), output=s.get("output", ""),
                            remove=False, agent="iot_squad")
    if s.get("name"):
        return navi_cli.tag(cat, val, plugin_name=s["name"], remove=False, agent="iot_squad")
    return navi_cli.tag(cat, val, query=s.get("query", ""), remove=False, agent="iot_squad")


def _ensure_result(use_pack=False):
    """The page can show a run replayed from the page cache after a server restart, when
    this process has no result yet — re-derive it (a read) instead of failing the write."""
    if AGENT.result is None:
        AGENT.run(use_pack=bool(use_pack))
    return AGENT.result


def tags_apply(p):
    if not confirmed(p):
        return {"ok": False, "error": "confirm=true required to apply tags"}, 400
    if _ensure_result(p.get("use_pack")) is None:
        return {"ok": False, "error": "run the agent first"}, 400
    actions = {a["value"]: a for a in AGENT.result.get("tag_actions", [])}
    # Unified inventory scheme: category 'Asset Inventory', value '<Facet>: <name>'. The UI
    # may override the facet per device (facets map) or set one default for all (facet).
    facets = p.get("facets") or {}
    default_facet = (p.get("facet") or "").strip()
    results = []
    for v in p.get("values", []):
        a = actions.get(v)
        if not a:
            results.append({"value": v, "ok": False, "message": "no matching tag action"})
            continue
        facet = (facets.get(v) or default_facet or a.get("facet") or "Device Type").strip()
        tag_value = f"{facet}: {v}"
        # Each device is tagged via its navi built-in selectors — one navi command
        # per plugin/output/name — so no giant UUID --query (dodges the 1999 cap).
        sels = a.get("selectors") or ([{"query": a.get("query", "")}] if a.get("query") else [])
        jobs = [_tag_selector("Asset Inventory", tag_value, s) for s in sels]
        job_ids = [j.get("job_id") for j in jobs if j.get("job_id") is not None]
        results.append({"value": v, "facet": facet, "tag_value": "Asset Inventory : " + tag_value,
                        "ok": True, "queued": True,
                        "job_ids": job_ids, "job_id": (job_ids[0] if job_ids else None),
                        "commands": len(sels)})
    return {"ok": True, "results": results, "writes_enabled": navi_cli.writes_enabled(),
            "write_gate_reason": navi_cli.write_gate_reason()}, 200


def tag_candidate(p):
    """Tag a single cross-reference candidate asset IoT:<name> (gated).

    Used after a human inspects the candidate's plugin output and decides it is a
    true match, not a false positive."""
    if not confirmed(p):
        return {"ok": False, "error": "confirm=true required to apply tag"}, 400
    name = (p.get("iot_name") or "").strip()
    uuid = (p.get("asset_uuid") or "").strip()
    value = (p.get("value") or name).strip()   # human can rename the tag value
    if not name or not uuid:
        return {"ok": False, "error": "iot_name and asset_uuid required"}, 400
    q = f"SELECT asset_uuid FROM vulns WHERE asset_uuid = '{uuid.replace(chr(39), chr(39)*2)}';"
    res = navi_cli.tag("IoT", value, q, remove=False, agent="iot_squad")
    return {"ok": True, "iot_name": name, "value": value, "asset_uuid": uuid,
            "result": res, "writes_enabled": navi_cli.writes_enabled()}, 200


def detections_decide(p):
    if not confirmed(p):
        return {"ok": False, "error": "confirm=true required to update detections"}, 400
    decisions = p.get("decisions", [])
    if not decisions:
        return {"ok": False, "error": "no decisions supplied"}, 400
    return {"ok": True, **iot_registry.apply_decisions(decisions)}, 200


def detections_export(p):
    """Base-building: write the confirmed proposals from a rich-db hunt to a
    reviewable learned base file (default) — or merge=True to fold in the seeds
    too. Does NOT touch the live registry; the operator swaps the file in."""
    if not confirmed(p):
        return {"ok": False, "error": "confirm=true required to export a base"}, 400
    proposals = p.get("proposals")
    if proposals is None:                       # default: everything Agent 3 confirmed
        proposals = (_ensure_result(p.get("use_pack")) or {}).get("proposals", [])
    if not proposals:
        return {"ok": False, "error": "no proposals to export (run a hunt first)"}, 400
    return {"ok": True, **iot_registry.export_base(proposals, merge=bool(p.get("merge")))}, 200


def registry(p):
    data = iot_registry.load()
    return {"path": iot_registry.registry_path(),
            "detections": data["detections"], "rejected": data.get("rejected", [])}, 200


ACTIONS = {"run": run, "tags_apply": tags_apply, "tag_candidate": tag_candidate,
           "detections_decide": detections_decide, "detections_export": detections_export,
           "registry": registry}
