"""EOL / Unsupported tagging — self-contained HTTP actions.

`run`   — scan navi.db for lifecycle plugins (Unsupported / End of Life) and the
          affected asset counts.
`apply` — gated; tags each approved group via navi's tag-by-plugin-name selector
          (`navi enrich tag --name "<text>"`), one call per pattern in the group.
"""
from core import eol, navi_cli

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
    return {"ok": True, "agent": _agent().meta(), "result": _agent().run(groups=groups)}, 200


def apply(p):
    if not p.get("confirm"):
        return {"ok": False, "error": "confirm=true required to write tags"}, 400
    groups = p.get("apply_groups") or []   # [{category,value,patterns:[...]}]
    if not groups:
        return {"ok": False, "error": "no groups approved"}, 400
    results = []
    for g in groups:
        cat = g.get("category", "Lifecycle")
        val = g.get("value", "")
        pats = g.get("patterns") or []
        excl = [str(x) for x in (g.get("exclude") or [])]
        if not val or not pats:
            continue
        if excl:
            # plugins opted out → tag via a query that excludes them (point-in-time)
            where = _clause(pats)
            q = ("SELECT asset_uuid FROM vulns WHERE (" + where + ") AND plugin_id NOT IN ("
                 + ",".join("'" + e.replace("'", "''") + "'" for e in excl) + ")")
            results.append({"value": val, "selector": "query(excluded %d)" % len(excl),
                            **navi_cli.tag(cat, val, query=q, remove=False)})
        else:
            for pat in pats:
                results.append({"value": val, "pattern": pat,
                                **navi_cli.tag(cat, val, plugin_name=pat)})
    return {"ok": True, "applied": sum(1 for r in results if r.get("ok")),
            "total": len(results), "results": results,
            "writes_enabled": navi_cli.writes_enabled()}, 200


ACTIONS = {"run": run, "apply": apply}
