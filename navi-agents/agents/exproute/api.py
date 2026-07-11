"""Exposure Routes agent — self-contained HTTP actions."""
from core import navi_cli, llm
from .agent import ExpRouteAgent, owners, routes, paths, tag_owner, coverage, ownership_map, path_detail

AGENT = ExpRouteAgent()


def load(p):
    return {"ok": True, "agent": AGENT.meta(), "result": AGENT.run()}, 200


def omap(p):
    """The Ownership Map dashboard — routes/paths ↔ owners graph + gaps + per-owner load."""
    return {"ok": True, "result": ownership_map()}, 200


def cover(p):
    """Ownership coverage — recompute after tagging + a navi.db refresh."""
    return {"ok": True, "result": coverage()}, 200


def refresh(p):
    """Kick a background `navi update assets` so freshly-applied Owner tags land in the
    local tags table, then coverage rises. Not a tenant write — no gate."""
    r = navi_cli.update_async(("assets",))
    return {"ok": bool(r.get("ok")), **r}, 200


def interpret(p):
    prompt = (p.get("prompt") or "").strip()
    if not prompt:
        return {"ok": False, "error": "describe the mapping first"}, 400
    rt, pa, ow = routes(), paths(), owners()
    out = llm.owner_plan(prompt, [r["app_name"] for r in rt],
                         [x["path"] for x in pa],
                         [{"name": o["name"], "type": o["type"]} for o in ow])
    if not out.get("ok"):
        return {"ok": False, "message": out.get("message", "AI unavailable"),
                "llm_available": llm.available()}, 200
    route_by = {(r["app_name"] or "").lower(): r for r in rt}
    path_by = {(x["path"] or "").lower(): x for x in pa}
    owner_set = {o["name"].lower() for o in ow}
    mappings, rejected = [], []
    for m in out.get("mappings", []):
        owner = str(m.get("owner", "")).strip()
        if owner.lower() not in owner_set:
            rejected.append(f"{m.get('match','?')} → owner '{owner}' not found")
            continue
        if m.get("kind") == "route":
            r = route_by.get(str(m.get("match", "")).lower())
            if not r:
                rejected.append(f"route '{m.get('match')}' not found")
                continue
            mappings.append({"kind": "route", "match": r["app_name"], "owner": owner,
                             "route_id": r["route_id"], "scope": f"{r['total_vulns'] or 0} vulns"})
        else:
            x = path_by.get(str(m.get("match", "")).lower())
            if not x:
                rejected.append(f"path '{m.get('match')}' not found")
                continue
            mappings.append({"kind": "path", "match": x["path"], "owner": owner,
                             "path": x["path"], "scope": f"{x['assets'] or 0} assets"})
    return {"ok": True, "mappings": mappings, "rejected": rejected,
            "model": out.get("model"), "llm_available": True}, 200


def apply(p):
    if not p.get("confirm"):
        return {"ok": False, "error": "confirm=true required to write tags"}, 400
    owner = (p.get("owner") or "").strip()
    if not owner:
        return {"ok": False, "error": "owner required"}, 400
    res = tag_owner(owner, route_id=p.get("route_id"), path=p.get("path"), app=p.get("app"))
    return {"ok": res.get("ok", False), **res,
            "writes_enabled": navi_cli.writes_enabled()}, 200


def pdetail(p):
    """Path drill-down — assets + findings on a single path (a newly-found gap)."""
    return {"ok": True, "result": path_detail((p or {}).get("path", ""))}, 200


ACTIONS = {"load": load, "run": load, "interpret": interpret, "apply": apply,
           "coverage": cover, "refresh": refresh, "map": omap, "path_detail": pdetail}
