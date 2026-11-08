"""Asset Ownership (Terminus) — self-contained HTTP actions."""
from core import asset_ownership as engine, navi_cli, tagname
from .agent import AssetOwnershipAgent
from core.gates import confirmed

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
    prompt = _s(p.get("prompt"))
    if not prompt:
        return {"ok": False, "error": "describe who owns which assets"}, 400
    return engine.plan(prompt), 200


def _s(v):
    """A request field as a stripped string (non-strings → '')."""
    return v.strip() if isinstance(v, str) else ""


def _mode(v):
    return "remainder" if _s(v).lower().startswith("rem") else "complete"


def _uuids(v):
    """The request's asset list — a list of non-empty strings, de-duplicated in order."""
    if not isinstance(v, list):
        return []
    out, seen = [], set()
    for u in v:
        u = _s(u)
        if u and u not in seen:
            seen.add(u)
            out.append(u)
    return out


def _bulk_asset_apply(owner="", uuids=None, mode="complete"):
    """Run the per-asset owner cascade for a whole match set. Executed on the tag
    queue's background worker (see apply()) so the HTTP request can return instantly
    and the user is free to leave the page. Each asset still cascades its routes &
    paths via engine.assign_asset_owner, which queues the individual navi tag writes."""
    uuids = uuids or []
    assets, cascaded = 0, 0
    for u in uuids[:2000]:
        r = engine.assign_asset_owner(u, owner, mode=mode)
        cascaded += r.get("cascaded", 0)
        assets += 1
    return {"ok": True, "assets": assets, "cascaded": cascaded,
            "message": f"assigned {owner} to {assets} asset(s); cascaded "
                       f"{cascaded} route/path owner tag(s)"}


def apply(p):
    """Apply an NL plan — tag the matched assets with the chosen layer's owner (gated).

    The asset layer fans out one owner cascade per asset (its routes + paths), so it
    runs as a single BACKGROUND job on the tag queue: this returns a job stub
    immediately and the user can navigate away while it drains — track it in the
    Tagging log. The business layer is already a single non-blocking tag write."""
    if not confirmed(p):
        return {"ok": False, "error": "confirm=true required to write tags"}, 400
    owner = _s(p.get("owner"))
    uuids = _uuids(p.get("uuids"))
    layer = "asset" if _s(p.get("layer")).lower() == "asset" else "business"
    mode = _mode(p.get("mode"))
    if not owner or not uuids:
        return {"ok": False, "error": "owner and matched assets required"}, 400
    if layer == "asset":
        from core import tagq
        batch = uuids[:2000]
        job = tagq.submit(
            _bulk_asset_apply, {"owner": owner, "uuids": batch, "mode": mode},
            {"agent": "asset_ownership", "category": tagname.effective(engine.ASSET_OWNER_KEY),
             "value": f"{owner} · {mode}", "op": "tag",
             "selector": f"{len(batch)} asset(s)",
             "detail": "bulk asset-owner assign — cascades each asset's routes & paths"})
        return {"ok": True, "queued": True, "job_id": job["id"], "layer": "asset",
                "owner": owner, "mode": mode, "assets": len(batch),
                "message": f"queued (job #{job['id']}) — assigning in the background; "
                           "you can leave this page. Track it in the Tagging log.",
                "writes_enabled": navi_cli.writes_enabled()}, 200
    r = engine.apply_business_owner(owner, uuids)
    return {"ok": r.get("ok", False), "layer": "business", "owner": owner,
            "assets": len(uuids), **r, "writes_enabled": navi_cli.writes_enabled()}, 200


def assign(p):
    """The single-asset 'one owner owns everything / the rest' toggle. Writes an
    Asset Owner tag and cascades Owner tags for that asset's routes & paths (gated)."""
    if not confirmed(p):
        return {"ok": False, "error": "confirm=true required to write tags"}, 400
    uuid = _s(p.get("uuid"))
    owner = _s(p.get("owner"))
    mode = _mode(p.get("mode"))
    if not uuid or not owner:
        return {"ok": False, "error": "asset uuid and owner required"}, 400
    r = engine.assign_asset_owner(uuid, owner, mode=mode)
    return {"ok": r.get("ok", False), **r}, 200


ACTIONS = {"load": load, "run": load, "overview": overview, "plan": plan,
           "apply": apply, "assign": assign, "refresh": refresh}
