"""AI Inventory (Pythia) — self-contained HTTP actions.

`run`   — content-first AI/ML discovery (read-only). Accepts {fp, allow}:
          fp = false-positive suppression map {assets,fw,gfw}; allow = egress allowlist.
`tag`   — gated; tag an explicit uuid set via navi tag-by-query. Used by every tag
          button (all AI, by-role, exposed, KEV, egress, ATLAS) with {category,value,uuids}.
`apply` — gated legacy shortcut: tag the whole AI-plugin family AI:Present (cap-aware).
"""
from core import ai_assets, navi_cli, db

AGENT = None


def _agent():
    global AGENT
    if AGENT is None:
        from .agent import AiAgent
        AGENT = AiAgent()
    return AGENT


def run(p):
    try:
        res = ai_assets.scan(fp=(p or {}).get("fp"), allow=(p or {}).get("allow"))
    except Exception as e:
        return {"ok": False, "error": f"AI scan failed: {e}"}, 200
    return {"ok": True, "agent": _agent().meta(), "result": res}, 200


def tag(p):
    """Generic gated tag of an explicit uuid set — the workhorse for the AI page's
    role/exposed/KEV/egress/ATLAS tag buttons."""
    if not p.get("confirm"):
        return {"ok": False, "error": "confirm=true required to write tags"}, 400
    category = (p.get("category") or "AI").strip() or "AI"
    value = (p.get("value") or "Present").strip() or "Present"
    uuids = p.get("uuids") or []
    if not uuids:
        return {"ok": False, "error": "no asset uuids supplied"}, 400
    r = ai_assets.tag_uuids(category, value, uuids, agent="ai")
    return {"ok": bool(r.get("ok", True)), "category": category, "value": value,
            "count": len(uuids), "result": r, "writes_enabled": navi_cli.writes_enabled()}, 200


def _ai_fallbacks_and_count():
    """Whole AI-family shortcut. Over the 1999-UUID cap we tag each distinct AI-family
    plugin id (a navi built-in) so navi pages server-side instead of a huge UUID query."""
    try:
        n = db.scalar("SELECT COUNT(DISTINCT asset_uuid) FROM vulns "
                      "WHERE plugin_family LIKE '%Artificial Intelligence%'") or 0
        pids = [r["plugin_id"] for r in db.query(
            "SELECT DISTINCT plugin_id FROM vulns WHERE plugin_family LIKE "
            "'%Artificial Intelligence%' AND plugin_id IS NOT NULL")]
    except Exception:
        n, pids = 0, []
    return [{"plugin": str(pid)} for pid in pids], int(n)


def apply(p):
    if not p.get("confirm"):
        return {"ok": False, "error": "confirm=true required to write tags"}, 400
    category = (p.get("category") or "AI").strip() or "AI"
    value = (p.get("value") or "Present").strip() or "Present"
    q = "SELECT asset_uuid FROM vulns WHERE plugin_family LIKE '%Artificial Intelligence%'"
    fallbacks, n = _ai_fallbacks_and_count()
    jobs = navi_cli.tag_capped(category, value, query=q, fallbacks=fallbacks, count=n, agent="ai")
    over = n > navi_cli.UUID_CAP and bool(fallbacks)
    job_ids = [j.get("job_id") for j in jobs if j.get("job_id") is not None]
    return {"ok": True, "category": category, "value": value, "count": n,
            "commands": len(jobs), "mode": "builtin" if over else "query",
            "over_cap": over, "job_ids": job_ids, "result": (jobs[0] if jobs else {}),
            "writes_enabled": navi_cli.writes_enabled()}, 200


ACTIONS = {"run": run, "tag": tag, "apply": apply}
