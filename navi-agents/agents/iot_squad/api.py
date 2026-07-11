"""IoT Discovery Squad — self-contained HTTP actions."""
from core import navi_cli, iot_registry
from .agent import IoTSquadOrchestrator

AGENT = IoTSquadOrchestrator()


def run(p):
    return {"ok": True, "agent": AGENT.meta(), "result": AGENT.run()}, 200


def _tag_selector(cat, val, s):
    """Apply ONE navi built-in selector (--plugin/--output/--name), or --query only
    for signal-fusion groups that have no plugin signature. Add-only."""
    if s.get("plugin"):
        return navi_cli.tag(cat, val, plugin=str(s["plugin"]), output=s.get("output", ""),
                            remove=False, agent="iot_squad")
    if s.get("name"):
        return navi_cli.tag(cat, val, plugin_name=s["name"], remove=False, agent="iot_squad")
    return navi_cli.tag(cat, val, query=s.get("query", ""), remove=False, agent="iot_squad")


def tags_apply(p):
    if AGENT.result is None:
        return {"ok": False, "error": "run the agent first"}, 400
    if not p.get("confirm"):
        return {"ok": False, "error": "confirm=true required to apply tags"}, 400
    actions = {a["value"]: a for a in AGENT.result.get("tag_actions", [])}
    results = []
    for v in p.get("values", []):
        a = actions.get(v)
        if not a:
            results.append({"value": v, "ok": False, "message": "no matching tag action"})
            continue
        # Each device is tagged via its navi built-in selectors — one navi command
        # per plugin/output/name — so no giant UUID --query (dodges the 1999 cap).
        sels = a.get("selectors") or ([{"query": a.get("query", "")}] if a.get("query") else [])
        jobs = [_tag_selector(a["category"], a["value"], s) for s in sels]
        job_ids = [j.get("job_id") for j in jobs if j.get("job_id") is not None]
        results.append({"value": v, "ok": True, "queued": True,
                        "job_ids": job_ids, "job_id": (job_ids[0] if job_ids else None),
                        "commands": len(sels)})
    return {"ok": True, "results": results, "writes_enabled": navi_cli.writes_enabled(),
            "write_gate_reason": navi_cli.write_gate_reason()}, 200


def tag_candidate(p):
    """Tag a single cross-reference candidate asset IoT:<name> (gated).

    Used after a human inspects the candidate's plugin output and decides it is a
    true match, not a false positive."""
    if not p.get("confirm"):
        return {"ok": False, "error": "confirm=true required to apply tag"}, 400
    name = (p.get("iot_name") or "").strip()
    uuid = (p.get("asset_uuid") or "").strip()
    value = (p.get("value") or name).strip()   # human can rename the tag value
    if not name or not uuid:
        return {"ok": False, "error": "iot_name and asset_uuid required"}, 400
    q = f"SELECT asset_uuid FROM vulns WHERE asset_uuid = '{uuid.replace(chr(39), chr(39)*2)}';"
    res = navi_cli.tag("IoT", value, q, remove=False)
    return {"ok": True, "iot_name": name, "value": value, "asset_uuid": uuid,
            "result": res, "writes_enabled": navi_cli.writes_enabled()}, 200


def detections_decide(p):
    if not p.get("confirm"):
        return {"ok": False, "error": "confirm=true required to update detections"}, 400
    decisions = p.get("decisions", [])
    if not decisions:
        return {"ok": False, "error": "no decisions supplied"}, 400
    return {"ok": True, **iot_registry.apply_decisions(decisions)}, 200


def registry(p):
    data = iot_registry.load()
    return {"path": iot_registry.registry_path(),
            "detections": data["detections"], "rejected": data.get("rejected", [])}, 200


ACTIONS = {"run": run, "tags_apply": tags_apply, "tag_candidate": tag_candidate,
           "detections_decide": detections_decide, "registry": registry}
