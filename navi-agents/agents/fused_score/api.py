"""Fused Exposure Score (Nemesis) — self-contained HTTP actions."""
from core import fused_score as engine, navi_cli
from .agent import FusedScoreAgent

AGENT = FusedScoreAgent()


def load(p):
    return {"ok": True, "agent": AGENT.meta(), "result": AGENT.run()}, 200


def overview(p):
    """The fused-score rollup — per-asset score + factors, worst-from-each-Hound, convergence."""
    return {"ok": True, "result": engine.overview()}, 200


def refresh(p):
    """Background `navi update assets` so freshly-applied hound tags feed the score."""
    r = navi_cli.update_async(("assets",))
    return {"ok": bool(r.get("ok")), **r}, 200


def tag(p):
    """The one write this view makes itself — flag the act-now set Priority : <value> (gated)
    so every Hound, dashboard and the AI Contract can filter to it. Everything else hands off
    to the specialist Hounds (Terminus owners, Gabriel email, Anubis ACR, Covenant plan)."""
    if not p.get("confirm"):
        return {"ok": False, "error": "confirm=true required to write tags"}, 400
    uuids = p.get("uuids") or []
    value = (p.get("value") or "P1").strip()
    if not uuids:
        return {"ok": False, "error": "no assets supplied"}, 400
    inlist = ",".join("'" + str(u).replace("'", "''") + "'" for u in uuids if u)
    q = "SELECT uuid AS asset_uuid FROM assets WHERE uuid IN (" + inlist + ")"
    r = navi_cli.tag("Priority", value, query=q, remove=False, agent="fused_score")
    return {"ok": r.get("ok", False), "count": len(uuids), **r,
            "writes_enabled": navi_cli.writes_enabled()}, 200


ACTIONS = {"load": load, "run": load, "overview": overview, "tag": tag, "refresh": refresh}
