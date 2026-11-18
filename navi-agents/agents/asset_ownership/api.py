"""Asset Ownership (Terminus) — self-contained HTTP actions.

Payload contract (build 455): `overview` streams the per-asset rollup into the result store
(core.asset_ownership.overview_store) and returns the decision data — every KPI, the top crown
jewels (unclaimed first), the blind spots shown (≤ 200), the top 100 owners and page 1 of the
per-asset table — plus a drill handle. The table, crown list and blind spots page / filter /
search on the server (`drill`); no asset list or uuid array reaches the page. `apply` takes the
plan's FILTER or a KEY ({run, key:"blind"}) and the server rebuilds the set; `plan` no longer
returns the matched uuid list.

Tag filter (build 489): every action the page calls honours `tag_scope` {key, value}
(core.tagscope). A tag view rolls up only the assets carrying that tag — each asset's own row
(owners, claimed %, crown, blind, signals) is exactly its whole-estate row; only the population
changes. Its runs live in their own result-store namespace (engine.STORE_NS_TAG, the newest
tagscope.MAX_TAGS kept), so a tag view never evicts the estate's rows nor is served them: a
`drill` / `apply key=blind` only reads a run of the same scope. Writes from a tag view
(apply / assign) re-read the tag's assets from navi.db and touch only those.
"""
from core import asset_ownership as engine, navi_cli, payload, tagname, tagscope
from .agent import AssetOwnershipAgent
from core.gates import confirmed

AGENT = AssetOwnershipAgent()


def load(p):
    """Back-compat names (load / run) for ▶ Run — the contract response, never the full asset list."""
    body, code = overview(p)
    if isinstance(body, dict):
        body["agent"] = AGENT.meta()
    return body, code


SECTIONS = {
    "assets": {"sorts": {"acr": ("s1", "s2", "s3"), "claimed": ("s2", "s1", "s3")}, "flags": set(engine.SCOPE_FLAGS)},
    "crown": {"sorts": {"rank": ("s1", "s2", "s3")}, "flags": set()},
    "blind": {"sorts": {"rank": ("s1", "s2")}, "flags": set()},
}
BLIND_SHOWN = 200          # the blind-spot list shows (and "Tag owner on all shown" tags) the top 200


def _scope(p):
    """(key, value) of the request's tag_scope, or None for the whole estate."""
    k, v = tagscope.parse(p if isinstance(p, dict) else {})
    return (k, v) if k else None


def _ns(scope):
    """The result-store namespace a run of this scope lives in."""
    return engine.STORE_NS_TAG if scope else engine.STORE_NS


def _run_of_scope(run, scope):
    """run_info of `run` when it is a finished run of exactly this scope, else None — a tag
    view never reads the estate's rows (nor another tag's), and the estate never reads a tag's."""
    info = payload.STORE.run_info(run, _ns(scope))
    if not info:
        return None
    if scope:
        sc = (info.get("meta") or {}).get("scope") or {}
        if (sc.get("key"), sc.get("value")) != scope:
            return None
    return info


def overview(p):
    """The Asset Ownership dashboard — KPIs, crown jewels, blind spots, owners + page 1 of the
    per-asset table (contract response; the rows stay server-side for `drill`)."""
    scope = _scope(p)
    st = engine.overview_store(scope=scope)
    if not st.get("ok"):
        return {"ok": False, "result": st, "error": st.get("error")}, 200
    run = st["run"]
    if not scope:
        AGENT.result = {"kpi": st.get("kpi") or {}}     # the hub card's summary (meta()) after a run — estate only
    ns = _ns(scope)
    first, _c = payload.drill(ns, {"run": run, "section": "assets", "sort": "acr", "limit": 50}, SECTIONS)
    crown, _c = payload.drill(ns, {"run": run, "section": "crown", "sort": "rank", "limit": 50}, SECTIONS)
    blind, _c = payload.drill(ns, {"run": run, "section": "blind", "sort": "rank",
                                   "limit": BLIND_SHOWN}, SECTIONS)
    k = st["kpi"]
    result = {"ok": True, "kpi": k, "crown_jewels": crown.get("top") or [], "crown_total": k.get("crown", 0),
              "crown_next": (crown.get("page") or {}).get("next"),
              "blind_spots": blind.get("top") or [], "blind_total": k.get("blind", 0),
              "owners": st["owners"], "owners_total": st["owners_total"], "signal_keys": st["signal_keys"],
              "run": run}
    if scope:
        result["scope"] = tagscope.describe(*scope)
    return payload.response(summary=k, top=first.get("top") or [], total_=first.get("total"), page=first.get("page"),
                            drill={"action": "drill", "run": run, "section": "assets", "sort": "acr"},
                            tag={"key": "filter", "count": k.get("assets", 0)}, result=result), 200


def drill(p):
    scope = _scope(p)
    if not scope:
        return payload.drill(engine.STORE_NS, p, SECTIONS)
    if not _run_of_scope((p or {}).get("run"), scope):
        return {"ok": False, "expired": True,
                "error": "this tag view's rows are no longer on the server — press ▶ Run again"}, 200
    body, code = payload.drill(engine.STORE_NS_TAG, p, SECTIONS)
    if isinstance(body, dict) and body.get("ok") is not False:
        body["scope"] = tagscope.describe(*scope)
    return body, code


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
    scope = _scope(p)
    out = engine.plan(prompt, scope=scope)
    if scope and isinstance(out, dict):
        out["scope"] = tagscope.describe(*scope)
    # the page previews 12 rows and applies by FILTER — never ship the matched uuid list
    out.pop("uuids", None)
    if isinstance(out.get("matched"), list):
        out["matched"] = out["matched"][:50]
    return out, 200


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
    # build 464: unbounded — the cascade is computed in bulk and each tag value goes as ONE
    # paged tag (≤1,999-UUID tag series), instead of one navi job per asset × route (which is
    # why this was capped at 2,000 assets)
    return engine.assign_assets_owner(uuids or [], owner, mode=mode)


def apply(p):
    """Apply an NL plan — tag the matched assets with the chosen layer's owner (gated).

    The asset layer fans out one owner cascade per asset (its routes + paths), so it
    runs as a single BACKGROUND job on the tag queue: this returns a job stub
    immediately and the user can navigate away while it drains — track it in the
    Tagging log. The business layer is already a single non-blocking tag write."""
    if not confirmed(p):
        return {"ok": False, "error": "confirm=true required to write tags"}, 400
    owner = _s(p.get("owner"))
    scope = _scope(p)
    # the plan's FILTER (preferred): the server rebuilds the matched set itself; a bare uuid
    # list is still accepted for the "claim unclaimed assets" button (both layers page any
    # size in ≤1,999-UUID tag series — build 464)
    if isinstance(p.get("filter"), dict):
        uuids = engine.match_filter(p["filter"], scope=scope)     # a tag view: only the tag's assets
    elif p.get("key") == "blind":
        # "Tag owner on all shown": the blind spots the page shows (top BLIND_SHOWN of the run)
        run = p.get("run")
        if not _run_of_scope(run, scope):
            return {"ok": False, "error": "this run is no longer on the server — press ▶ Run again"}, 200
        rows, _l, _n, _e = payload.STORE.page(run, "blind", sort=("s1", "s2"), limit=BLIND_SHOWN, count=False)
        uuids = [r["uuid"] for r in rows if r.get("uuid")]
        if scope:                                   # re-checked against navi.db's tags now
            uuids = engine.in_scope(uuids, scope)
    elif scope:
        # a tag view never takes an asset list from the browser — use the plan's filter
        return {"ok": False, "error": "from a tag view, assign by plan (✨ Ask) or the blind-spot list — "
                                      "an asset list from the page is not accepted"}, 400
    else:
        uuids = _uuids(p.get("uuids"))
    layer = "asset" if _s(p.get("layer")).lower() == "asset" else "business"
    mode = _mode(p.get("mode"))
    if not owner or not uuids:
        if scope and owner:
            return {"ok": False, "error": f"no matched assets carry the tag {tagscope.label(*scope)}"}, 400
        return {"ok": False, "error": "owner and matched assets required"}, 400
    sdesc = tagscope.describe(*scope) if scope else None
    if layer == "asset":
        from core import tagq
        batch = uuids                    # unbounded (build 464): the job pages it
        job = tagq.submit(
            _bulk_asset_apply, {"owner": owner, "uuids": batch, "mode": mode},
            {"agent": "asset_ownership", "category": tagname.effective(engine.ASSET_OWNER_KEY),
             "value": f"{owner} · {mode}", "op": "tag",
             "selector": f"{len(batch)} asset(s)" + (f" tagged {tagscope.label(*scope)}" if scope else ""),
             "detail": "bulk asset-owner assign — cascades each asset's routes & paths"})
        return {"ok": True, "queued": True, "job_id": job["id"], "layer": "asset",
                "owner": owner, "mode": mode, "assets": len(batch),
                "message": f"queued (job #{job['id']}) — assigning in the background; "
                           "you can leave this page. Track it in the Tagging log.",
                "writes_enabled": navi_cli.writes_enabled(), **({"scope": sdesc} if scope else {})}, 200
    r = engine.apply_business_owner(owner, uuids)
    out = {"ok": r.get("ok", False), "layer": "business", "owner": owner,
           "assets": len(uuids), **r, "writes_enabled": navi_cli.writes_enabled()}
    if scope:
        out["scope"] = sdesc
    return out, 200


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
    scope = _scope(p)
    if scope and not engine.in_scope([uuid], scope):
        # a tag view writes only inside the tag — re-checked in navi.db, not taken from the page
        return {"ok": False, "error": f"that asset doesn't carry the tag {tagscope.label(*scope)} — "
                                      "nothing was written"}, 400
    r = engine.assign_asset_owner(uuid, owner, mode=mode)
    out = {"ok": r.get("ok", False), **r}
    if scope:
        out["scope"] = tagscope.describe(*scope)
    return out, 200


ACTIONS = {"load": load, "run": load, "overview": overview, "drill": drill, "plan": plan,
           "apply": apply, "assign": assign, "refresh": refresh}
