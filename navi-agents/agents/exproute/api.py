"""Exposure Routes agent — self-contained HTTP actions."""
from core import navi_cli, llm, jobq, tagscope
from .agent import (ExpRouteAgent, owners, routes, paths, tag_owner, coverage,
                    ownership_map, path_detail, resolve_owner,
                    parse_dispositions, disposition_label,
                    snapshot_state, start_build, _base, retag_owner_tags)
from core.gates import confirmed

AGENT = ExpRouteAgent()


def scope_cached_at(key, value):
    """Tag-filter switcher hook (core/tagscope.scopes): epoch ms when the snapshot for this view
    was built — key None = the whole estate (its own store), else that tag's exproute_tag entry —
    or None when nothing is cached for the current navi.db. Only reads the stores; never builds.
    (Atlas has no weighting, so the view is the whole key.)"""
    import datetime
    k = key.strip() if isinstance(key, str) else ""
    v = value.strip() if isinstance(value, str) else ""
    if k and not v:
        return None
    snap = snapshot_state(scope=(k, v) if k else None)["snap"]
    at = ((snap or {}).get("meta") or {}).get("built_at")
    if not at:
        return None
    try:
        return int(datetime.datetime.fromisoformat(at).timestamp() * 1000)
    except (TypeError, ValueError):
        return None


def load(p):
    return {"ok": True, "agent": AGENT.meta(), "result": AGENT.run()}, 200


def _submit(fn):
    return jobq.submit(fn, {"agent": "exproute", "action": "snapshot", "label": "Ownership snapshot"})


def _scope(p):
    """Build 489 tag filter: (tag_key, tag_value) from the request's tag_scope, or None for the
    whole estate. (tag_key / tag_value are never read here — the scope travels separately.)"""
    k, v = tagscope.parse(p or {})
    return (k, v) if k else None


def _submit_for(scope):
    if not scope:
        return _submit
    return lambda fn: jobq.submit(fn, {"agent": "exproute", "action": "snapshot",
                                       "label": f"Ownership snapshot · {scope[0]} : {scope[1]}"})


def snapshot(p):
    """Everything the page shows — owners, routes, paths, coverage and the ownership map —
    from one pass, cached on disk per navi.db signature.
      {peek:true}            what's cached / building right now; never computes
      {}                     cached result if navi.db is unchanged, else start a background build
      {force:true}           rebuild even if cached
      {refresh_owners:true}  re-pull the owner directory from Tenable, then rebuild
    A build answers {building:{job_id, started}}; poll /api/jobs/<id>, then peek."""
    force, ro = bool(p.get("force")), bool(p.get("refresh_owners"))
    sc = _scope(p)
    st = snapshot_state(scope=sc)
    if st["snap"] and not force and not ro:
        return {"ok": True, "result": st["snap"], "cached": True}, 200
    if p.get("peek"):
        return {"ok": True, "result": None, "building": st["building"]}, 200
    if st["building"]:
        return {"ok": True, "result": None, "building": st["building"]}, 200
    if sc and not tagscope.count(*sc):
        return {"ok": False, "error": f"no asset in navi.db carries the tag {sc[0]} : {sc[1]} — "
                                      "a tag added in Tenable reaches navi.db after `navi update assets`"}, 200
    b = start_build(_submit_for(sc), refresh_owners=ro, scope=sc)
    return {"ok": True, "result": None, "building": b}, 200


def omap(p):
    """The Ownership Map dashboard — routes/paths ↔ owners graph + gaps + per-owner load.
    Served from the snapshot when navi.db hasn't changed."""
    sc = _scope(p)
    st = snapshot_state(scope=sc)
    if st["snap"] and not p.get("refresh"):
        return {"ok": True, "result": st["snap"]["map"], "cached": True}, 200
    return {"ok": True, "result": ownership_map(scope=sc)}, 200


def cover(p):
    """Ownership coverage — served from the snapshot when navi.db hasn't changed."""
    sc = _scope(p)
    st = snapshot_state(scope=sc)
    if st["snap"] and not p.get("refresh"):
        return {"ok": True, "result": st["snap"]["coverage"], "cached": True}, 200
    b = _base(scope=sc)
    return {"ok": True, "result": coverage(base=b, om=ownership_map(base=b))}, 200


def refresh(p):
    """Kick a background `navi update assets` so freshly-applied Owner tags land in the
    local tags table, then coverage rises. Not a tenant write — no gate."""
    r = navi_cli.update_async(("assets",))
    return {"ok": bool(r.get("ok")), **r}, 200


def interpret(p):
    prompt = (p.get("prompt") or "").strip()
    if not prompt:
        return {"ok": False, "error": "describe the mapping first"}, 400
    sc = _scope(p)
    _st = snapshot_state(scope=sc)
    if sc and _st["snap"]:      # a tag view: the routes / paths on the tag's assets (from its snapshot)
        rt, pa, ow = _st["snap"]["load"]["routes"], _st["snap"]["load"]["paths"], owners()
    else:
        rt, pa, ow = routes(scope=sc), paths(scope=sc), owners()

    # 1) Disposition instructions ("ignore the ICMP route", "accept the OpenSSL route",
    #    "all windows office routes are mitigated") are parsed locally — no model needed.
    disps = parse_dispositions(prompt, rt, pa)
    disp_keys = {(d["kind"], d["match"].strip().lower()) for d in disps}

    # If the model isn't available, still return whatever dispositions we found.
    if not llm.available():
        if disps:
            return {"ok": True, "mappings": disps, "rejected": [], "dispositions": len(disps),
                    "llm_available": False, **({"scope": tagscope.describe(*sc)} if sc else {})}, 200
        return {"ok": False, "message": "AI unavailable — for owner assignments set "
                "ANTHROPIC_API_KEY (disposition phrases like 'ignore/accept/mitigate the X "
                "route' work without it)", "llm_available": False}, 200
    # Current state so 'assign the remaining' / 'keep it balanced' are exact, not guessed:
    # which routes/paths already have an owner, and each owner's current item count.
    om = _st["snap"]["map"] if _st["snap"] else ownership_map(scope=sc)   # reuse the cached map
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
    res = {"ok": True, "mappings": disps + mappings, "rejected": rejected,
           "dispositions": len(disps), "truncated": out.get("truncated", False),
           "model": out.get("model"), "llm_available": True}
    if sc:
        res["scope"] = tagscope.describe(*sc)
    return res, 200


def apply(p):
    if not confirmed(p):
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
    # a tag view: only the tag's assets on the route/path — the set is re-read from navi.db
    res = tag_owner(owner, route_id=p.get("route_id"), path=p.get("path"), app=p.get("app"), scope=_scope(p))
    res["owner_resolved"] = owner
    return {"ok": res.get("ok", False), **res,
            "writes_enabled": navi_cli.writes_enabled()}, 200


def retag(p):
    """Gated: move an unmatched Owner tag name onto an exact route/path name — only the
    assets that carry the old tag, per owner."""
    if not confirmed(p):
        return {"ok": False, "error": "confirm=true required to write tags"}, 400
    r = retag_owner_tags(p.get("from") or "", p.get("to") or "", scope=_scope(p))
    return {**r, "writes_enabled": navi_cli.writes_enabled()}, (200 if r.get("ok") else 400)


def pdetail(p):
    """Path drill-down — assets + findings on a single path (a newly-found gap)."""
    return {"ok": True, "result": path_detail((p or {}).get("path", ""), scope=_scope(p))}, 200


ACTIONS = {"snapshot": snapshot, "load": load, "run": load, "interpret": interpret, "apply": apply,
           "coverage": cover, "refresh": refresh, "map": omap, "path_detail": pdetail, "retag": retag}
