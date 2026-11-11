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


def _open_only():
    vc = scan_eval._cols("vulns")
    return " AND lower(COALESCE(state,'open')) IN ('open','reopened')" if "state" in vc else ""


# Keys whose set IS a navi.db condition (no Python parsing) are selected by that SQL; every
# other key is computed from parsed plugin-19506 output / worst-state ranking in Python. Either
# way the set is computed HERE and paged by core.navi_cli.tag_set (≤1,999 UUIDs per navi job).
def _predicate(key):
    if key == "patch:failed":     # evaluate(): patch == 'failed' ⇔ an open 21745 finding
        return "SELECT DISTINCT asset_uuid FROM vulns WHERE plugin_id='21745'" + _open_only()
    return ""


def tag_target(key, name="", ev=None):
    """(value, sorted asset uuids, error) for one Scan Health key. Shared by tag() and the AI
    Contract adapter so both write the same set."""
    if key in VALUES:
        value = VALUES[key]
        q = _predicate(key)
        if q:
            return value, navi_cli.collect_uuids(q), None
        ev = ev or scan_eval.evaluate(keep_uuids=True)
        uuids = ev["_sets"].get(key, set())
    elif key in DIM_PREFIX:
        ev = ev or scan_eval.evaluate(keep_uuids=True)
        uuids = ev["_dim_uuids"][key].get(name)
        if uuids is None:
            return None, [], f"no {key} named '{name}' in navi.db"
        value = DIM_PREFIX[key] + name
    else:
        return None, [], "unknown tag key"
    return value, sorted(u for u in uuids if u), None


def tag(p):
    if not confirmed(p):
        return {"ok": False, "error": "confirm=true required to write tags"}, 400
    key = (p.get("key") or "").strip()
    value, uu, err = tag_target(key, (p.get("name") or "").strip())
    if err:
        return {"ok": False, "error": err}, 400
    if not uu:
        return {"ok": False, "error": f"no assets for {value}"}, 200
    jobs = navi_cli.tag_set(CATEGORY, value, uuids=uu, agent="scan_eval")
    ids = [j.get("job_id") for j in jobs if j.get("job_id") is not None]
    return {"ok": True, "category": CATEGORY, "value": value, "count": len(uu), "jobs": len(ids),
            "job_ids": ids, "series": (jobs[0].get("series") if jobs else None),
            "result": (jobs[0] if jobs else {}),
            "writes_enabled": navi_cli.writes_enabled()}, 200


ACTIONS = {"run": run, "tag": tag}
