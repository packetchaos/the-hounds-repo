"""EOL / Unsupported tagging — self-contained HTTP actions.

`run`          — scan navi.db for lifecycle plugins (Unsupported / End of Life): the
                 tag groups, plus the product view (OS vs application, end-of-life date
                 from the plugin output, years past EOL, crown jewels, KEV / critical overlap).
`apply`        — gated; tags the ASSETS in each approved group Lifecycle:<group> via navi's
                 tag-by-plugin-name selector (`navi enrich tag --name "<text>"`).
`tag_eol_date` — gated; tags the assets running software that reached end of life on each
                 chosen date: Lifecycle EOL:<YYYY-MM-DD> (by the exact asset uuids whose plugin
                 output states that date — never --plugin, which would tag every version's hosts).
"""
from core import eol, navi_cli
from core.gates import confirmed

AGENT = None


def _clause(pats):
    return " OR ".join("plugin_name LIKE '%" + p.replace("'", "''") + "%'" for p in pats)


def _agent():
    global AGENT
    if AGENT is None:
        from .agent import EolAgent
        AGENT = EolAgent()
    return AGENT


def run(p):
    groups = p.get("groups")  # optional [[label,[patterns]]] override
    res = _agent().run(groups=groups)
    try:
        res = {**res, "view": eol.analyze(groups=groups)}
    except Exception as e:
        res = {**res, "view": {"ok": False, "error": f"product view failed: {e}"}}
    return {"ok": True, "agent": _agent().meta(), "result": res}, 200


DATE_CATEGORY = "Lifecycle EOL"


def tag_eol_date(p):
    """Tag the assets running software whose end of life was on each chosen date."""
    if not confirmed(p):
        return {"ok": False, "error": "confirm=true required to write tags"}, 400
    want = {d for d in (p.get("dates") or []) if (d or "").strip()}
    if not want:
        return {"ok": False, "error": "no end-of-life dates supplied"}, 400
    view = eol.analyze()                                   # recompute server-side; never trust the page
    groups = [g for g in view.get("date_groups", []) if g["eol_date"] in want]
    if not groups:
        return {"ok": False, "error": "none of those dates match EOL software on assets in navi.db"}, 400
    results = []
    for g in groups:
        uu = g.get("uuids") or []
        inl = ",".join("'" + str(u).replace("'", "''") + "'" for u in uu)
        jobs = navi_cli.tag_capped(DATE_CATEGORY, g["eol_date"], uuids=uu,
                                   query=f"SELECT uuid AS asset_uuid FROM assets WHERE uuid IN ({inl})",
                                   remove=False, agent="eol") if uu else []
        ids = [j["job_id"] for j in jobs if j.get("job_id") is not None]
        results.append({"eol_date": g["eol_date"], "products": g["products"], "plugins": len(g["plugin_ids"]),
                        "jobs": len(ids), "queued": bool(ids)})
    return {"ok": True, "queued": sum(r["jobs"] for r in results), "results": results,
            "writes_enabled": navi_cli.writes_enabled()}, 200


def apply(p):
    if not confirmed(p):
        return {"ok": False, "error": "confirm=true required to write tags"}, 400
    # Groups are rebuilt from the server's DEFAULT_GROUPS: the client only names a group label and
    # the plugin ids it opted out of — never the category or the name patterns.
    known = dict(eol.DEFAULT_GROUPS)
    groups = [g for g in (p.get("apply_groups") or []) if (g.get("value") or "") in known]
    if not groups:
        return {"ok": False, "error": "no groups approved"}, 400
    results = []
    for g in groups:
        cat = "Lifecycle"
        val = g["value"]
        pats = known[val]
        excl = [str(x) for x in (g.get("exclude") or []) if str(x).isdigit()]
        if not val or not pats:
            continue
        if excl:
            # plugins opted out → tag via a query that excludes them (point-in-time)
            where = _clause(pats)
            q = ("SELECT asset_uuid FROM vulns WHERE (" + where + ") AND plugin_id NOT IN ("
                 + ",".join("'" + e.replace("'", "''") + "'" for e in excl) + ")")
            results.append({"value": val, "selector": "query(excluded %d)" % len(excl),
                            **navi_cli.tag(cat, val, query=q, remove=False, agent="eol")})
        else:
            for pat in pats:
                results.append({"value": val, "pattern": pat,
                                **navi_cli.tag(cat, val, plugin_name=pat, remove=False, agent="eol")})
    return {"ok": True, "applied": sum(1 for r in results if r.get("ok")),
            "total": len(results), "results": results,
            "writes_enabled": navi_cli.writes_enabled()}, 200


ACTIONS = {"run": run, "apply": apply, "tag_eol_date": tag_eol_date}
