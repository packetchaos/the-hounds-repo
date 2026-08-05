"""Exposure Routes agent — self-contained HTTP actions."""
from core import navi_cli, llm
from .agent import (ExpRouteAgent, owners, routes, paths, tag_owner, coverage,
                    ownership_map, path_detail, resolve_owner,
                    parse_dispositions, disposition_label)

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

    # 1) Disposition instructions ("ignore the ICMP route", "accept the OpenSSL route",
    #    "all windows office routes are mitigated") are parsed locally — no model needed.
    disps = parse_dispositions(prompt, rt, pa)
    disp_keys = {(d["kind"], d["match"].strip().lower()) for d in disps}

    # If the model isn't available, still return whatever dispositions we found.
    if not llm.available():
        if disps:
            return {"ok": True, "mappings": disps, "rejected": [], "dispositions": len(disps),
                    "llm_available": False}, 200
        return {"ok": False, "message": "AI unavailable — for owner assignments set "
                "ANTHROPIC_API_KEY (disposition phrases like 'ignore/accept/mitigate the X "
                "route' work without it)", "llm_available": False}, 200
    # Current state so 'assign the remaining' / 'keep it balanced' are exact, not guessed:
    # which routes/paths already have an owner, and each owner's current item count.
    om = ownership_map()
    assigned = {"routes": {r["name"]: ", ".join(r["owners"]) for r in om.get("routes", []) if r.get("owners")},
                "paths": {p["name"]: ", ".join(p["owners"]) for p in om.get("paths", []) if p.get("owners")}}
    owner_load = {e["owner"]: e.get("routes", 0) + e.get("paths", 0) for e in om.get("owner_load", [])}
    # give the model the friendly name too (alt), so it can match "Casey" not just "creid"
    out = llm.owner_plan(prompt, [r["app_name"] for r in rt],
                         [x["path"] for x in pa],
                         [{"name": o["name"], "type": o["type"], "alt": o.get("detail", "")} for o in ow],
                         assigned=assigned, owner_load=owner_load)
    if not out.get("ok"):
        return {"ok": False, "message": out.get("message", "AI unavailable"),
                "llm_available": llm.available()}, 200
    route_by = {(r["app_name"] or "").lower(): r for r in rt}
    path_by = {(x["path"] or "").lower(): x for x in pa}
    mappings, rejected = [], []
    for m in out.get("mappings", []):
        # canonicalise whatever the model returned (username OR friendly/first name)
        entry, err = resolve_owner(str(m.get("owner", "")), ow)
        if not entry:
            rejected.append(f"{m.get('match','?')} → {err}")
            continue
        owner = entry["name"]
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
    # dispositions win over any owner the model tried to assign to the same route/path
    mappings = [m for m in mappings if (m["kind"], m["match"].strip().lower()) not in disp_keys]
    return {"ok": True, "mappings": disps + mappings, "rejected": rejected,
            "dispositions": len(disps), "truncated": out.get("truncated", False),
            "model": out.get("model"), "llm_available": True}, 200


def apply(p):
    if not p.get("confirm"):
        return {"ok": False, "error": "confirm=true required to write tags"}, 400
    owner_in = (p.get("owner") or "").strip()
    if not owner_in:
        return {"ok": False, "error": "owner required"}, 400
    # A disposition (Ignored / Accepted / Mitigated) is a valid "owner" that bypasses the
    # user directory — it marks a route/path as handled so it drops off the gap list.
    disp = disposition_label(owner_in)
    if disp:
        owner = disp
    else:
        # never tag an owner that doesn't resolve to a real navi user/group — the name
        # must always map to a canonical username (or group). Alert instead of tagging junk.
        entry, err = resolve_owner(owner_in)
        if not entry:
            return {"ok": False, "error": err or f"owner '{owner_in}' not found"}, 400
        owner = entry["name"]
    res = tag_owner(owner, route_id=p.get("route_id"), path=p.get("path"), app=p.get("app"))
    res["owner_resolved"] = owner
    return {"ok": res.get("ok", False), **res,
            "writes_enabled": navi_cli.writes_enabled()}, 200


def pdetail(p):
    """Path drill-down — assets + findings on a single path (a newly-found gap)."""
    return {"ok": True, "result": path_detail((p or {}).get("path", ""))}, 200


ACTIONS = {"load": load, "run": load, "interpret": interpret, "apply": apply,
           "coverage": cover, "refresh": refresh, "map": omap, "path_detail": pdetail}
