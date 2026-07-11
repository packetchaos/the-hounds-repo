"""Custom App Name agent — self-contained HTTP actions."""
from core import navi_cli, llm
from .agent import (CustomAppAgent, search_paths, search_routes, tag_query_for,
                    load_ignore, save_ignore, routing_status, _SETUP_HINT)

AGENT = CustomAppAgent()


def run(p):
    return {"ok": True, "agent": AGENT.meta(), "result": AGENT.run()}, 200


def interpret(p):
    prompt = p.get("prompt", "")
    if not prompt.strip():
        return {"ok": False, "error": "empty instruction"}, 400
    out = llm.extract_app(prompt)
    if not out.get("ok"):
        return {"ok": False, "message": out.get("message", "could not parse"),
                "llm_available": llm.available()}, 200
    return {"ok": True, "name": out["name"], "keywords": out["keywords"],
            "fallback": out.get("fallback", False), "llm_available": llm.available()}, 200


def search(p):
    """Search BOTH vuln_paths (filesystem paths) and vuln_route (app routes)."""
    keyword = p.get("keyword", "")
    rows = search_paths(keyword)
    routes = search_routes(keyword)
    assets = sorted({r["asset_uuid"] for r in rows})
    setup = routing_status()
    # if BOTH source tables are empty, tell the operator to populate them —
    # otherwise a keyword match is impossible and the tag would no-op.
    needs = not (setup["vuln_route"] or setup["vuln_paths"])
    return {"ok": True, "keyword": keyword, "matches": rows, "routes": routes,
            "path_count": len(rows), "route_count": len(routes),
            "asset_count": len(assets), "tag_query": tag_query_for(keyword),
            "setup": setup, "needs_setup": needs,
            "setup_hint": (_SETUP_HINT if needs else "")}, 200


def tag(p):
    """Tag a custom app across both tables: filesystem paths via --query, and any
    matching application routes via --route_id (vuln_route has no asset_uuid)."""
    name, keyword = p.get("name", ""), p.get("keyword", "")
    if not p.get("confirm"):
        return {"ok": False, "error": "confirm=true required to tag"}, 400
    if not name or not keyword:
        return {"ok": False, "error": "name and keyword are required"}, 400

    results, ok_any = [], False
    paths = search_paths(keyword)
    if paths:
        r = navi_cli.tag("Custom App", name, tag_query_for(keyword), remove=False)
        ok_any = ok_any or r.get("ok", False)
        results.append({"selector": "query", "via": "vuln_paths",
                        "assets": len({x["asset_uuid"] for x in paths}), **r})

    routes = search_routes(keyword)
    for rt in routes:
        rid = rt.get("route_id")
        if rid is None:
            continue
        r = navi_cli.tag("Custom App", name, route_id=str(rid), remove=False)
        ok_any = ok_any or r.get("ok", False)
        results.append({"selector": "route_id", "via": "vuln_route",
                        "route_id": rid, "app_name": rt.get("app_name"), **r})

    if not results:
        setup = routing_status()
        needs = not (setup["vuln_route"] or setup["vuln_paths"])
        msg = (_SETUP_HINT if needs else
               "no path or route matches for that keyword — try a different keyword")
        return {"ok": False, "error": msg, "message": msg,
                "setup": setup, "needs_setup": needs,
                "writes_enabled": navi_cli.writes_enabled()}, 200
    return {"ok": ok_any, "results": results,
            "path_tags": sum(1 for r in results if r["selector"] == "query"),
            "route_tags": sum(1 for r in results if r["selector"] == "route_id"),
            "writes_enabled": navi_cli.writes_enabled()}, 200


def ignore_list(p):
    return {"ok": True, "ignored": load_ignore()}, 200


def ignore_add(p):
    term = str(p.get("term", "")).strip().lower()
    if not term:
        return {"ok": False, "error": "term required"}, 400
    terms = load_ignore()
    if term not in terms:
        terms.append(term)
    return {"ok": True, "ignored": save_ignore(terms)}, 200


def ignore_remove(p):
    term = str(p.get("term", "")).strip().lower()
    terms = [t for t in load_ignore() if t != term]
    return {"ok": True, "ignored": save_ignore(terms)}, 200


ACTIONS = {"run": run, "interpret": interpret, "search": search, "tag": tag,
           "ignore_list": ignore_list, "ignore_add": ignore_add,
           "ignore_remove": ignore_remove}
