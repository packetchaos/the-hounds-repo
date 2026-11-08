"""Scan Evaluations (Chronos) — self-contained HTTP actions.

`run` — scanner / policy / scan performance (plugin 19506) plus scan coverage: credential
        health per asset (the Target Credential Status / Issues plugin family), scan freshness,
        agent vs network, scanner plugin-feed currency, crown-jewel blind spots. Read-only.
`tag` — gated. The page sends only a KEY; the server re-runs the evaluation and tags the EXACT
        asset set behind it (by uuid), so a crafted request can't pick a category, value or
        selector. Category is always `Scan Health`.
          {key:'status:failed'}         -> Scan Health : Cred Failure
          {key:'status:insufficient'}   -> Scan Health : Insufficient Privilege
          {key:'status:intermittent'}   -> Scan Health : Intermittent Auth
          {key:'status:uncredentialed'} -> Scan Health : Uncredentialed
          {key:'patch:failed'}          -> Scan Health : Patch Assessment Failed
          {key:'fresh:31-90'}           -> Scan Health : Stale Scan 30d+
          {key:'fresh:90+'}             -> Scan Health : Stale Scan 90d+
          {key:'fresh:never'}           -> Scan Health : Never Scanned
          {key:'slow'}                  -> Scan Health : Slow Scan
          {key:'crown:blind'}           -> Scan Health : Crown Jewel Blind Spot
          {key:'scanner', name}         -> Scan Health : Scanner : <ip>
          {key:'policy',  name}         -> Scan Health : Policy : <name>
          {key:'scan',    name}         -> Scan Health : Scan : <name>
"""
from core import navi_cli, scan_eval
from core.gates import confirmed

AGENT = None
CATEGORY = "Scan Health"
VALUES = {
    "status:failed": "Cred Failure", "status:insufficient": "Insufficient Privilege",
    "status:intermittent": "Intermittent Auth", "status:uncredentialed": "Uncredentialed",
    "patch:failed": "Patch Assessment Failed", "fresh:31-90": "Stale Scan 30d+",
    "fresh:90+": "Stale Scan 90d+", "fresh:never": "Never Scanned", "slow": "Slow Scan",
    "crown:blind": "Crown Jewel Blind Spot",
}
DIM_PREFIX = {"scanner": "Scanner : ", "policy": "Policy : ", "scan": "Scan : "}


def _agent():
    global AGENT
    if AGENT is None:
        from .agent import ScanEvalAgent
        AGENT = ScanEvalAgent()
    return AGENT


def run(p):
    try:
        res = scan_eval.evaluate()
    except Exception as e:
        return {"ok": False, "error": f"scan evaluation failed: {e}"}, 200
    return {"ok": True, "agent": _agent().meta(), "result": res}, 200


def tag(p):
    if not confirmed(p):
        return {"ok": False, "error": "confirm=true required to write tags"}, 400
    key = (p.get("key") or "").strip()
    ev = scan_eval.evaluate(keep_uuids=True)
    if key in VALUES:
        value, uuids = VALUES[key], ev["_sets"].get(key, set())
    elif key in DIM_PREFIX:
        name = (p.get("name") or "").strip()
        uuids = ev["_dim_uuids"][key].get(name)
        if uuids is None:
            return {"ok": False, "error": f"no {key} named '{name}' in navi.db"}, 400
        value = DIM_PREFIX[key] + name
    else:
        return {"ok": False, "error": "unknown tag key"}, 400
    uu = sorted(u for u in uuids if u)
    if not uu:
        return {"ok": False, "error": f"no assets for {value}"}, 200
    inl = ",".join("'" + str(u).replace("'", "''") + "'" for u in uu)
    jobs = navi_cli.tag_capped(CATEGORY, value, uuids=uu,
                               query=f"SELECT uuid AS asset_uuid FROM assets WHERE uuid IN ({inl})",
                               remove=False, agent="scan_eval")
    ids = [j.get("job_id") for j in jobs if j.get("job_id") is not None]
    return {"ok": True, "category": CATEGORY, "value": value, "count": len(uu), "jobs": len(ids),
            "job_ids": ids, "result": (jobs[0] if jobs else {}),
            "writes_enabled": navi_cli.writes_enabled()}, 200


ACTIONS = {"run": run, "tag": tag}
