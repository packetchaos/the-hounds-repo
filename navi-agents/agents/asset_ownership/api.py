"""Asset Ownership (Terminus) — self-contained HTTP actions."""
from core import asset_ownership as engine, navi_cli
from .agent import AssetOwnershipAgent

AGENT = AssetOwnershipAgent()


def load(p):
    return {"ok": True, "agent": AGENT.meta(), "result": AGENT.run()}, 200


def overview(p):
    """The Asset Ownership dashboard — per-asset rollup, KPIs, crown jewels, blind spots."""
    return {"ok": True, "result": engine.overview()}, 200


def refresh(p):
    """Background `navi update assets` so freshly-applied ownership tags land in the
    local tags table (not a tenant write — no gate)."""
    r = navi_cli.update_async(("assets",))
    return {"ok": bool(r.get("ok")), **r}, 200


def plan(p):
    """Plain-English → preview of who owns which assets (reads each asset's tags).
    Nothing is written."""
    prompt = (p.get("prompt") or "").strip()
    if not prompt:
        return {"ok": False, "error": "describe who owns which assets"}, 400
    return engine.plan(prompt), 200


def apply(p):
    """Apply an NL plan — tag the matched assets with the chosen layer's owner (gated)."""
    if not p.get("confirm"):
        return {"ok": False, "error": "confirm=true required to write tags"}, 400
    owner = (p.get("owner") or "").strip()
    uuids = p.get("uuids") or []
    layer = (p.get("layer") or "business").strip().lower()
    mode = (p.get("mode") or "complete").strip().lower()
    if not owner or not uuids:
        return {"ok": False, "error": "owner and matched assets required"}, 400
    if layer == "asset":
        # a single complete owner per asset — cascade routes/paths so both views close it
        results, closed = [], 0
        for u in uuids[:2000]:
            r = engine.assign_asset_owner(u, owner, mode=mode)
            closed += r.get("cascaded", 0)
            results.append({"asset": u, "ok": r.get("ok", True)})
        return {"ok": True, "layer": "asset", "owner": owner, "mode": mode,
                "assets": len(results), "cascaded": closed,
                "writes_enabled": navi_cli.writes_enabled()}, 200
    r = engine.apply_business_owner(owner, uuids)
    return {"ok": r.get("ok", False), "layer": "business", "owner": owner,
            "assets": len(uuids), **r, "writes_enabled": navi_cli.writes_enabled()}, 200


def assign(p):
    """The single-asset 'one owner owns everything / the rest' toggle. Writes an
    Asset Owner tag and cascades Owner tags for that asset's routes & paths (gated)."""
    if not p.get("confirm"):
        return {"ok": False, "error": "confirm=true required to write tags"}, 400
    uuid = (p.get("uuid") or "").strip()
    owner = (p.get("owner") or "").strip()
    mode = (p.get("mode") or "complete").strip().lower()
    if not uuid or not owner:
        return {"ok": False, "error": "asset uuid and owner required"}, 400
    r = engine.assign_asset_owner(uuid, owner, mode=mode)
    return {"ok": r.get("ok", False), **r}, 200


ACTIONS = {"load": load, "run": load, "overview": overview, "plan": plan,
           "apply": apply, "assign": assign, "refresh": refresh}
