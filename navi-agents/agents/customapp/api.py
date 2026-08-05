"""Custom App Name agent — self-contained HTTP actions."""
from core import navi_cli, llm, db
from .agent import (CustomAppAgent, search_paths, search_routes, tag_query_for,
                    load_ignore, save_ignore, routing_status, _SETUP_HINT)

AGENT = CustomAppAgent()


def _nk(s):
    return " ".join((s or "").strip().lower().split())


def _owned_names(db_path=None):
    """Route/path names that already carry an Atlas Owner tag (value '<name>: <user>').
    These are CLAIMED — the Custom App hunt hides them by default so the operator sees
    only the ownership gaps (what nobody has named/claimed yet)."""
    names = set()
    try:
        for r in db.query("SELECT DISTINCT tag_value FROM tags WHERE tag_key='Owner' "
                          "AND tag_value LIKE '%: %'", path=db_path):
            v = (r.get("tag_value") or "").strip()
            if ": " in v:
                nm = v.rsplit(": ", 1)[0].strip()
                if nm:
                    names.add(_nk(nm))
    except Exception:
        pass
    return names


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
    # annotate what's already OWNED so the page can hide claimed routes/paths (noise) and
    # surface only the gaps — the whole point of the custom-app hunt.
    owned = _owned_names()
    for rt in routes:
        rt["owned"] = _nk(rt.get("app_name")) in owned
    for m in rows:
        m["owned"] = _nk(m.get("path")) in owned
    owned_routes = sum(1 for rt in routes if rt.get("owned"))
    owned_paths = sum(1 for m in rows if m.get("owned"))
    # if BOTH source tables are empty, tell the operator to populate them —
    # otherwise a keyword match is impossible and the tag would no-op.
    needs = not (setup["vuln_route"] or setup["vuln_paths"])
    return {"ok": True, "keyword": keyword, "matches": rows, "routes": routes,
            "path_count": len(rows), "route_count": len(routes),
            "owned_routes": owned_routes, "owned_paths": owned_paths,
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


def ignore_import(p):
    """Bulk-import ignore terms (CSV migration). mode: 'merge' (default) or 'replace'."""
    terms = p.get("terms")
    if not isinstance(terms, list):
        return {"ok": False, "error": "terms (list) required"}, 400
    clean = [str(t).strip().lower() for t in terms if str(t).strip()]
    mode = str(p.get("mode", "merge")).lower()
    merged = clean if mode == "replace" else (load_ignore() + clean)
    saved = save_ignore(merged)
    return {"ok": True, "ignored": saved, "imported": len(clean),
            "total": len(saved), "mode": mode}, 200


ACTIONS = {"run": run, "interpret": interpret, "search": search, "tag": tag,
           "ignore_list": ignore_list, "ignore_add": ignore_add,
           "ignore_remove": ignore_remove, "ignore_import": ignore_import}
