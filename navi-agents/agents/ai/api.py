"""AI Inventory (Pythia) — self-contained HTTP actions.

`run`   — content-first AI/ML discovery (read-only). Accepts {fp, allow}:
          fp = false-positive suppression map {assets,fw,gfw}; allow = egress allowlist.
`tag`   — gated; tag an explicit uuid set via navi tag-by-query. Used by the AI page's
          tag buttons (all AI, by-role, exposed, KEV, software, egress) with {category,value,uuids}.
          Refuses `AI ATLAS` — ATLAS tags go through `tag_atlas`.
`tag_atlas` — gated; the ATLAS drill-down's tag. The page sends only a KEY
          ({key:'tech:AML.T0040'} or {key:'tactic:Exfiltration'}, plus the same fp/allow it
          ran with); the server re-runs the scan and tags the EXACT asset set behind that
          technique / tactic → `AI ATLAS : <technique id>` or `AI ATLAS : Tactic : <tactic>`.
          Category is always `AI ATLAS`; never removes tags.
`acr_roles` — gated; set ACR on AI Role:<role> assets to the role's suggested ACR.
`apply` — gated legacy shortcut: tag the whole AI-plugin family AI:Present (cap-aware).
"""
from core import activity, ai_assets, navi_cli, db, tagname
from core.gates import confirmed

AGENT = None


def _agent():
    global AGENT
    if AGENT is None:
        from .agent import AiAgent
        AGENT = AiAgent()
    return AGENT


ATLAS_CATEGORY = "AI ATLAS"          # the only category tag_atlas writes
ATLAS_TACTIC_PREFIX = "Tactic : "    # tactic-level values: AI ATLAS : Tactic : <tactic>
AI_CATS = ("AI", "AI Role", "AI Exposed", "AI Priority", "AI Egress", "AI ATLAS", "AI Software", "AI ACR Raise")


def _enrich(res):
    """Page metrics on top of the scan: ACR vs the role's suggested ACR, what the pack has
    already tagged, how much was found beyond Tenable's AI plugin family, the framework
    inventory, and the estate denominator. Read-only; best-effort."""
    assets = res.get("assets") or []
    inl = ",".join("'" + str(x["asset_uuid"]).replace("'", "''") + "'" for x in assets)
    acr, tags = {}, {}
    try:
        total = db.scalar("SELECT COUNT(*) FROM assets") or 0
    except Exception:
        total = 0
    if inl:
        try:
            for r in db.query(f"SELECT uuid, acr FROM assets WHERE uuid IN ({inl})"):
                try:
                    acr[r["uuid"]] = float(r.get("acr") or 0) or None
                except (TypeError, ValueError):
                    pass
        except Exception:
            pass
        try:
            frag, args = tagname.sql_in("tag_key", *AI_CATS)     # + test-run names
            for r in db.query(f"SELECT asset_uuid, tag_key, tag_value FROM tags WHERE asset_uuid IN ({inl}) "
                              f"AND {frag}", args):
                tags.setdefault(r["asset_uuid"], []).append(f"{r.get('tag_key')} : {r.get('tag_value')}")
        except Exception:
            pass
    fw = {}
    for x in assets:
        u = x["asset_uuid"]
        x["acr"] = acr.get(u)
        x["acr_suggest"] = ai_assets.ROLE_ACR.get(x["role"], 7)
        x["underrated"] = x["acr"] is not None and x["acr"] < x["acr_suggest"]
        x["content_only"] = "ai-plugin" not in (x.get("sources") or [])
        x["unauth"] = any(e.get("auth") == "unauth" for e in (x.get("exposed") or []))
        x["shadow"] = any(not e.get("sanctioned") for e in (x.get("egress") or []))
        x["ai_tags"] = sorted(set(tags.get(u, [])))
        for e in x.get("evidence") or []:
            if e.get("src") == "ai-plugin":
                continue
            f = fw.setdefault(e["term"], {"name": e["term"], "role": e.get("role"), "assets": set(), "sources": set()})
            f["assets"].add(u)
            f["sources"].add(e["src"])
    frameworks = sorted(({**f, "assets": len(f["assets"]), "uuids": sorted(f["assets"]),
                          "sources": sorted(f["sources"])} for f in fw.values()),
                        key=lambda f: (-f["assets"], f["name"]))
    dests = {}
    for x in assets:
        for e in x.get("egress") or []:
            d = dests.setdefault(e["dest"], {"sanctioned": e.get("sanctioned"), "assets": 0})
            d["assets"] += 1
    atlas = {}
    for x in assets:
        for t in x.get("atlas") or []:
            atlas.setdefault(t["id"], t.get("tactic"))
    rated = [x["acr"] for x in assets if x["acr"] is not None]
    res["frameworks"] = frameworks
    res["metrics"] = {
        "estate": total, "ai_pct": round(100.0 * len(assets) / total, 1) if total else None,
        "content_only": sum(1 for x in assets if x["content_only"]),
        "plugin_found": sum(1 for x in assets if not x["content_only"]),
        "frameworks": len(frameworks), "roles": len(res.get("byRole") or {}),
        "unauth": sum(1 for x in assets if x["unauth"]),
        "crit": sum(1 for x in assets if (x.get("risk") or {}).get("crit")),
        "destinations": len(dests), "shadow_dests": sum(1 for d in dests.values() if not d["sanctioned"]),
        "atlas_techniques": len(atlas), "atlas_tactics": len(set(atlas.values())),
        "underrated": sum(1 for x in assets if x["underrated"]),
        "acr_rated": len(rated), "acr_median": sorted(rated)[len(rated) // 2] if rated else None,
        "crown": sum(1 for x in rated if x >= 7),
        "tagged": sum(1 for x in assets if x["ai_tags"]),
        # roles whose AI ACR Raise tag (or its test-run name) is in navi.db — enables "Set ACR"
        "roles_tagged": sorted({t.split(" : ", 1)[1] for x in assets for t in x["ai_tags"]
                                if " : " in t and tagname.base(t.split(" : ", 1)[0]) == "AI ACR Raise"}),
    }
    return res


def run(p):
    try:
        res = ai_assets.scan(fp=(p or {}).get("fp"), allow=(p or {}).get("allow"))
    except Exception as e:
        return {"ok": False, "error": f"AI scan failed: {e}"}, 200
    try:
        res = _enrich(res)
    except Exception as e:
        res["metrics_error"] = f"metrics failed: {e}"
    return {"ok": True, "agent": _agent().meta(), "result": res}, 200


def acr_roles(p):
    """Gated: set ACR on assets tagged AI ACR Raise : <role> to the role's suggested ACR
    (navi enrich acr by tag). That tag holds ONLY the role's under-rated assets (see tag_underrated),
    so `--mod set` can only raise scores — never lower an asset already rated above the suggestion."""
    if not confirmed(p):
        return {"ok": False, "error": "confirm=true required to change ACR"}, 400
    roles = [r for r in (p.get("roles") or []) if r in ai_assets.ROLE_ACR]
    if not roles:
        return {"ok": False, "error": "no AI roles selected"}, 400
    done = []
    for r in roles:
        score = ai_assets.ROLE_ACR[r]
        # the tag tag_underrated wrote — its test-run name when Settings → Test run is on
        out = navi_cli.acr(tagname.effective("AI ACR Raise"), r, score, mod="set", reasons=["business"],
                           note=f"Pythia: {r} AI asset -> ACR {score}", agent="ai")
        done.append({"role": r, "acr": score, "ok": bool(out.get("ok")), "blocked": bool(out.get("blocked")),
                     "message": out.get("message") or out.get("stderr") or ""})
    ok = sum(1 for d in done if d["ok"])
    return {"ok": ok > 0, "applied": ok, "results": done,
            "error": None if ok else ((done[0]["message"] or "navi rejected the ACR change")[:300]
                                      + ("" if done[0]["blocked"] else " — tag the under-rated assets (AI ACR Raise) first and wait for the tag to reach Tenable")),
            "writes_enabled": navi_cli.writes_enabled()}, 200


def tag_underrated(p):
    """Gated: tag the role's assets whose CURRENT ACR (re-read from navi.db) is below the role's
    suggestion → AI ACR Raise : <role>. Step 1 of the ACR fix; acr_roles is step 2."""
    if not confirmed(p):
        return {"ok": False, "error": "confirm=true required to write tags"}, 400
    role = p.get("role")
    if role not in ai_assets.ROLE_ACR:
        return {"ok": False, "error": "unknown AI role"}, 400
    score = ai_assets.ROLE_ACR[role]
    uu = [u for u in (p.get("uuids") or []) if u]
    if not uu:
        return {"ok": False, "error": "no asset uuids supplied"}, 400
    try:
        inl = ",".join("'" + str(u).replace("'", "''") + "'" for u in uu)
        rows = db.query(f"SELECT uuid, acr FROM assets WHERE uuid IN ({inl})")
        keep = [r["uuid"] for r in rows if r.get("acr") is not None and float(r["acr"]) < score]
    except Exception:
        keep = []
    if not keep:
        return {"ok": False, "error": f"no {role} asset is below ACR {score}"}, 200
    r = ai_assets.tag_uuids("AI ACR Raise", role, keep, agent="ai")
    return {"ok": bool(r.get("ok", True)), "category": tagname.effective("AI ACR Raise"), "value": role,
            "count": len(keep), "result": r, "writes_enabled": navi_cli.writes_enabled()}, 200


def tag(p):
    """Generic gated tag of an explicit uuid set — the workhorse for the AI page's
    role/exposed/KEV/egress/ATLAS tag buttons."""
    if not confirmed(p):
        return {"ok": False, "error": "confirm=true required to write tags"}, 400
    category = (p.get("category") or "AI").strip() or "AI"
    if not activity.allowed_category("ai", category):
        return {"ok": False, "error": f"category '{category}' is not one this agent writes"}, 400
    if tagname.base(category) == ATLAS_CATEGORY:
        return {"ok": False, "error": "ATLAS tags go through tag_atlas (the server rebuilds the asset set)"}, 400
    value = (p.get("value") or "Present").strip() or "Present"
    uuids = p.get("uuids") or []
    if not uuids:
        return {"ok": False, "error": "no asset uuids supplied"}, 400
    r = ai_assets.tag_uuids(category, value, uuids, agent="ai")
    return {"ok": bool(r.get("ok", True)), "category": tagname.effective(category), "value": value,
            "count": len(uuids), "result": r, "writes_enabled": navi_cli.writes_enabled()}, 200


def tag_atlas(p):
    """Gated: tag the assets behind one ATLAS technique (key 'tech:<id>') or tactic
    (key 'tactic:<name>'). Only the key comes from the page; the asset set is rebuilt here
    from a fresh scan (with the same fp suppressions / egress allowlist the page ran with,
    which can only narrow or reclassify the AI set), so a crafted request can't tag
    arbitrary uuids or pick another category. remove=False always."""
    if not confirmed(p):
        return {"ok": False, "error": "confirm=true required to write tags"}, 400
    if not activity.allowed_category("ai", ATLAS_CATEGORY):
        return {"ok": False, "error": f"category '{ATLAS_CATEGORY}' is not one this agent writes"}, 400
    key = (p.get("key") or "").strip()
    kind, _, name = key.partition(":")
    name = name.strip()
    if kind == "tech" and name in ai_assets.ATLAS_TECH:
        value = name
    elif kind == "tactic" and name in ai_assets.ATLAS_TACTIC_ORDER:
        value = ATLAS_TACTIC_PREFIX + name
    else:
        return {"ok": False, "error": "unknown ATLAS technique or tactic"}, 400
    try:
        res = ai_assets.scan(fp=p.get("fp"), allow=p.get("allow"))
    except Exception as e:
        return {"ok": False, "error": f"AI scan failed: {e}"}, 200
    uu = sorted(ai_assets.atlas_sets(res.get("assets"))[kind].get(name, set()))
    if not uu:
        return {"ok": False, "error": f"no AI assets map to {value}"}, 200
    inl = ",".join("'" + str(u).replace("'", "''") + "'" for u in uu)
    jobs = navi_cli.tag_capped(ATLAS_CATEGORY, value, uuids=uu,
                               query=f"SELECT uuid AS asset_uuid FROM assets WHERE uuid IN ({inl})",
                               remove=False, agent="ai")
    ids = [j.get("job_id") for j in jobs if j.get("job_id") is not None]
    return {"ok": True, "category": tagname.effective(ATLAS_CATEGORY), "value": value, "count": len(uu), "jobs": len(ids),
            "job_ids": ids, "result": (jobs[0] if jobs else {}),
            "writes_enabled": navi_cli.writes_enabled()}, 200


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
    if not confirmed(p):
        return {"ok": False, "error": "confirm=true required to write tags"}, 400
    category = (p.get("category") or "AI").strip() or "AI"
    if not activity.allowed_category("ai", category):
        return {"ok": False, "error": f"category '{category}' is not one this agent writes"}, 400
    value = (p.get("value") or "Present").strip() or "Present"
    q = "SELECT asset_uuid FROM vulns WHERE plugin_family LIKE '%Artificial Intelligence%'"
    fallbacks, n = _ai_fallbacks_and_count()
    jobs = navi_cli.tag_capped(category, value, query=q, fallbacks=fallbacks, count=n, agent="ai")
    over = n > navi_cli.UUID_CAP and bool(fallbacks)
    job_ids = [j.get("job_id") for j in jobs if j.get("job_id") is not None]
    return {"ok": True, "category": tagname.effective(category), "value": value, "count": n,
            "commands": len(jobs), "mode": "builtin" if over else "query",
            "over_cap": over, "job_ids": job_ids, "result": (jobs[0] if jobs else {}),
            "writes_enabled": navi_cli.writes_enabled()}, 200


ACTIONS = {"run": run, "tag": tag, "tag_atlas": tag_atlas, "apply": apply, "acr_roles": acr_roles, "tag_underrated": tag_underrated}
