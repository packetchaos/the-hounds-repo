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
`drill` — read; pages / filters / searches the run's AI assets (role, glance filter, ATLAS
          technique / tactic) — core.payload.
`counts` — read; per-role / exposed / KEV counts of a filtered view (the tag buttons' numbers).

Payload contract (build 455): `run` returns the decision data — every metric and the glance
breakdowns, the role × ACR table, frameworks, egress destinations and the ATLAS matrix (all
as COUNTS) plus page 1 of the asset list and a drill handle. The full assets (with evidence)
stay server-side for the run; no uuid arrays reach the page. Every tag button sends a KEY
({run, key:{…}}) and the server rebuilds the set from the stored run (`tag`, `tag_underrated`,
`tag_atlas`); the uuid-list forms remain for server-side callers.
"""
from core import activity, ai_assets, navi_cli, db, hx_summary, payload, tagname
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


_GLANCE_FLAGS = {"content", "exposed", "unauth", "shadow", "kev", "crit", "eol", "mitre", "under", "crown",
                 "tagged", "untagged"}


def _flag_ok(f):
    return f in _GLANCE_FLAGS or (f.split(":", 1)[0] in ("role", "tech", "tactic") and len(f) < 160)


SECTIONS = {"assets": {"sorts": {}, "flags": _flag_ok}}


def _asset_flags(x):
    rk = x.get("risk") or {}
    f = ["role:" + str(x.get("role")),
         "content" if x.get("content_only") else None, "exposed" if x.get("exposed") else None,
         "unauth" if x.get("unauth") else None, "shadow" if x.get("shadow") else None,
         "kev" if rk.get("kev") else None, "crit" if rk.get("crit") else None, "eol" if rk.get("eol") else None,
         "mitre" if rk.get("mitre") else None, "under" if x.get("underrated") else None,
         "crown" if (x.get("acr") or 0) >= 7 else None, "tagged" if x.get("ai_tags") else "untagged"]
    for t in x.get("atlas") or []:
        f.append("tech:" + str(t.get("id")))
        f.append("tactic:" + str(t.get("tactic") or "Other"))
    return f


def _median(vals):
    v = sorted(x for x in vals if x is not None)
    return v[len(v) // 2] if v else None


def _publish(res):
    """Write the run's assets to the result store and build the page's decision data (what the
    page used to compute in the browser over the full asset list)."""
    assets = res.get("assets") or []
    W = payload.STORE.begin("ai")
    W.section("assets")
    src, roles, dests, tech, tacs = {}, {}, {}, {}, {}
    ex = un = sh = 0
    try:
        for x in assets:
            u = x["asset_uuid"]
            W.add("assets", x, uid=u, flags=_asset_flags(x), rk=u,
                  text=" ".join(str(v or "") for v in (x.get("host"), x.get("ip"), x.get("role"), u,
                                                         " ".join(x.get("frameworks") or []))))
            for s_ in x.get("sources") or []:
                src[s_] = src.get(s_, 0) + 1
            if x.get("exposed"):
                ex += 1
            if x.get("unauth"):
                un += 1
            if x.get("shadow") and not x.get("exposed"):
                sh += 1
            r = roles.setdefault(x.get("role"), {"role": x.get("role"), "assets": 0, "under": 0, "_acr": []})
            r["assets"] += 1
            r["under"] += 1 if x.get("underrated") else 0
            r["_acr"].append(x.get("acr"))
            for e in x.get("egress") or []:
                k = (e.get("cat") or "") + "|" + (e.get("dest") or "")
                d = dests.get(k)
                if d is None:
                    d = dests[k] = {"key": k, "cat": e.get("cat"), "dest": e.get("dest"), "via": {}, "assets": 0,
                                    "sanctioned": bool(e.get("sanctioned")), "snip": e.get("snip") or "", "_u": set()}
                if u not in d["_u"]:
                    d["_u"].add(u)
                    W.members("eg:" + k, [u])
                d["via"][e.get("via") or "capability"] = 1
                if e.get("snip") and not d["snip"]:
                    d["snip"] = e["snip"]
            seen_tac = set()
            for t in x.get("atlas") or []:
                d = tech.setdefault(t.get("id"), {"id": t.get("id"), "name": t.get("name"), "tactic": t.get("tactic") or "Other",
                                                  "assets": 0, "whys": {}, "_u": set()})
                if u not in d["_u"]:
                    d["_u"].add(u)
                    d["assets"] += 1
                for w in (t.get("whys") or [t.get("why")]):
                    if w:
                        d["whys"][w] = d["whys"].get(w, 0) + 1
                tac = t.get("tactic") or "Other"
                if tac not in seen_tac:
                    seen_tac.add(tac)
                    tacs[tac] = tacs.get(tac, 0) + 1
        for f in res.get("frameworks") or []:
            W.members("fw:" + str(f.get("name")), f.get("uuids") or [])
        W.meta = {"allow": res.get("allow")}
    except BaseException:
        W.close(ok=False)
        raise
    W.close()
    for d in dests.values():
        d["assets"] = len(d.pop("_u"))
    for d in tech.values():
        d.pop("_u", None)
    role_rows = [{"role": r["role"], "assets": r["assets"], "under": r["under"], "median": _median(r["_acr"])}
                 for r in roles.values()]
    view = {"src": src, "exposed": ex, "unauth": un, "shadow_only": sh, "roles": role_rows,
            "dests": sorted(dests.values(), key=lambda d: (d["sanctioned"], -d["assets"])),
            "dests_total": len(dests),
            "atlas": sorted(tech.values(), key=lambda d: (-d["assets"], str(d["id"]))), "tactic_assets": tacs,
            "frameworks": [{k: v for k, v in f.items() if k != "uuids"} for f in (res.get("frameworks") or [])],
            "frameworks_total": len(res.get("frameworks") or [])}
    return W.run, view


def run(p):
    try:
        res = ai_assets.scan(fp=(p or {}).get("fp"), allow=(p or {}).get("allow"))
    except Exception as e:
        return {"ok": False, "error": f"AI scan failed: {e}"}, 200
    try:
        res = _enrich(res)
    except Exception as e:
        res["metrics_error"] = f"metrics failed: {e}"
    runid, view = _publish(res)
    first, _c = payload.drill("ai", {"run": runid, "section": "assets", "limit": 50}, SECTIONS)
    small = {k: v for k, v in res.items() if k not in ("assets", "frameworks")}
    small["view"] = view
    return payload.response(summary=res.get("metrics") or {}, top=first.get("top") or [],
                            total_=first.get("total"), page=first.get("page"),
                            drill={"action": "drill", "run": runid, "section": "assets"},
                            tag={"key": "filter", "count": res.get("asset_count", 0)},
                            agent=_agent().meta(), result=small), 200


def drill(p):
    return payload.drill("ai", p, SECTIONS)


def _view_args(p):
    flt = p.get("filter") or []
    if isinstance(flt, str):
        flt = [flt]
    if not isinstance(flt, list) or not all(isinstance(f, str) and _flag_ok(f) for f in flt) or len(flt) > 6:
        return None, None
    q = p.get("q") if isinstance(p.get("q"), str) else ""
    return flt, q[:200].strip()


def counts(p):
    """Read: how many assets of a filtered view are in each role, exposed, KEV — the numbers on
    the tag buttons (counted server-side over the run's stored assets)."""
    run = (p or {}).get("run")
    if not payload.STORE.run_info(run, "ai"):
        return {"ok": False, "expired": True, "error": "this run is gone — press ▶ Run again"}, 200
    flt, q = _view_args(p)
    if flt is None:
        return {"ok": False, "error": "unknown filter"}, 400
    by, exp, kev, n = {}, 0, 0, 0
    for x in payload.STORE.iter_rows(run, "assets", flt, q):
        n += 1
        by[x.get("role")] = by.get(x.get("role"), 0) + 1
        exp += 1 if x.get("exposed") else 0
        kev += 1 if (x.get("risk") or {}).get("kev") else 0
    return {"ok": True, "total": n, "by_role": by, "exposed": exp, "kev": kev}, 200


def _key_uuids(p):
    """(uuids, error) for a tag KEY over a stored run: {all} · {filter:[…], q} · {asset} ·
    {fw: name} · {egress: 'cat|dest'} · {shadow}. The page never sends uuids."""
    run = p.get("run")
    if not payload.STORE.run_info(run, "ai"):
        return None, "this run is no longer on the server — press ▶ Run again"
    k = p.get("key") or {}
    S = payload.STORE
    if k.get("all") is True:
        return S.uids(run, "assets"), None
    if "filter" in k or "q" in k:
        flt, q = _view_args(k)
        if flt is None:
            return None, "unknown filter"
        return S.uids(run, "assets", flt, q), None
    if isinstance(k.get("asset"), str):
        return ([k["asset"]] if S.row(run, "assets", k["asset"]) else []), None
    if isinstance(k.get("fw"), str):
        return S.group(run, "fw:" + k["fw"]), None
    if isinstance(k.get("egress"), str):
        return S.group(run, "eg:" + k["egress"]), None
    if k.get("shadow") is True:
        return S.uids(run, "assets", ["shadow"]), None
    return None, "unknown key"


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
    if p.get("run"):              # the page's form: the role's under-rated assets of the stored run
        if not payload.STORE.run_info(p.get("run"), "ai"):
            return {"ok": False, "error": "this run is no longer on the server — press ▶ Run again"}, 200
        uu = payload.STORE.uids(p["run"], "assets", ["role:" + role, "under"])
    else:
        uu = [u for u in (p.get("uuids") or []) if u]
    if not uu:
        return {"ok": False, "error": "no asset uuids supplied"}, 400
    keep = []
    try:
        for part in navi_cli.uuid_batches(uu, size=900):        # bound the SQL, not just argv
            rows = db.query("SELECT uuid, acr FROM assets WHERE uuid IN (" + ",".join("?" * len(part)) + ")",
                            tuple(part))
            keep += [r["uuid"] for r in rows if r.get("acr") is not None and float(r["acr"]) < score]
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
    if isinstance(p.get("key"), dict):          # the page's form: a key, the set is rebuilt here
        uuids, err = _key_uuids(p)
        if err:
            return {"ok": False, "error": err}, 400 if err == "unknown filter" or err == "unknown key" else 200
    else:
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
    if p.get("run") and payload.STORE.run_info(p.get("run"), "ai"):
        # the stored run the page shows (same fp / allow) — no re-scan of navi.db
        uu = payload.STORE.uids(p["run"], "assets", [("tech:" if kind == "tech" else "tactic:") + name])
    else:
        try:
            res = ai_assets.scan(fp=p.get("fp"), allow=p.get("allow"))
        except Exception as e:
            return {"ok": False, "error": f"AI scan failed: {e}"}, 200
        uu = sorted(ai_assets.atlas_sets(res.get("assets"))[kind].get(name, set()))
    if not uu:
        return {"ok": False, "error": f"no AI assets map to {value}"}, 200
    # ATLAS mapping is computed in Python (ai_assets.atlas_sets) → ≤1,999-UUID batches
    jobs = navi_cli.tag_capped(ATLAS_CATEGORY, value, uuids=uu, remove=False, agent="ai")
    ids = [j.get("job_id") for j in jobs if j.get("job_id") is not None]
    return {"ok": True, "category": tagname.effective(ATLAS_CATEGORY), "value": value, "count": len(uu), "jobs": len(ids),
            "job_ids": ids, "result": (jobs[0] if jobs else {}),
            "writes_enabled": navi_cli.writes_enabled()}, 200


def _ai_fallbacks_and_count():
    """Whole AI-family shortcut. Over the 1999-UUID cap we tag each distinct AI-family
    plugin id (a navi built-in) so navi pages server-side instead of a huge UUID query."""
    try:
        if hx_summary.usable():
            # Phase 1: the AI family is a plugin attribute — hx_plugin + covering hx_v_plugin ranges
            fam = "family LIKE '%Artificial Intelligence%'"
            n = db.scalar("SELECT COUNT(asset_uuid) FROM (" + hx_summary.assets_with(fam) + ")") or 0
            pids = [r["plugin_id"] for r in db.query("SELECT plugin_id FROM hx_plugin WHERE " + fam)]
            return [{"plugin": str(pid)} for pid in pids], int(n)
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


ACTIONS = {"run": run, "drill": drill, "counts": counts, "tag": tag, "tag_atlas": tag_atlas, "apply": apply, "acr_roles": acr_roles, "tag_underrated": tag_underrated}
