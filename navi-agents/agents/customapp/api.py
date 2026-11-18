"""Custom App Name agent — self-contained HTTP actions."""
from core import navi_cli, llm, db, tagname, tagscope
from .agent import (CustomAppAgent, search_paths, search_routes, tag_query_for, scoped_tag_sql,
                    load_ignore, save_ignore, routing_status, _SETUP_HINT)
from core.gates import confirmed

AGENT = CustomAppAgent()
# tag views run on their own instance, so a tag run never replaces the whole estate's last
# result (meta/summary, the Contract's discovery restore) — build 489
AGENT_TAG = CustomAppAgent()


def _nk(s):
    return " ".join((s or "").strip().lower().split())


def _owned_names(db_path=None):
    """Route/path names that already carry an Atlas Owner tag (value '<name>: <user>').
    These are CLAIMED — the Custom App hunt hides them by default so the operator sees
    only the ownership gaps (what nobody has named/claimed yet)."""
    names = set()
    try:
        for r in db.query("SELECT DISTINCT tag_value FROM tags WHERE " + tagname.sql_lit("tag_key", "Owner") + " "
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
    k, v = tagscope.parse(p)
    if k:
        res = AGENT_TAG.run(scope=(k, v))
        return {"ok": True, "agent": AGENT_TAG.meta(), "result": res, "scope": res.get("scope")}, 200
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
    k, v = tagscope.parse(p)
    if k:
        return _search_scoped(keyword, k, v)
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


def _search_scoped(keyword, k, v):
    """search() over one tag's assets: path rows on the tag's assets, and the routes whose
    plugins sit on at least one of them (route tagging there is by the tag's assets, not
    --route_id, which would reach every asset on the route)."""
    sc = (k, v)
    rows = search_paths(keyword, scope=sc)
    routes = search_routes(keyword, scope=sc)
    setup = routing_status()
    owned = _owned_names()
    for rt in routes:
        rt["owned"] = _nk(rt.get("app_name")) in owned
    for m in rows:
        m["owned"] = _nk(m.get("path")) in owned
    needs = not (setup["vuln_route"] or setup["vuln_paths"])
    # the assets a tag here would touch: computed by the same SQL the write uses
    plugins = sorted({pid for rt in routes for pid in rt.get("plugins") or ()})
    n = 0
    if (keyword or "").strip():
        sql, params = scoped_tag_sql(keyword, plugins, k, v)
        try:
            n = db.scalar(f"SELECT COUNT(*) FROM ({sql})", params) or 0
        except Exception:
            n = 0
    return {"ok": True, "keyword": keyword, "matches": rows, "routes": routes,
            "path_count": len(rows), "route_count": len(routes),
            "owned_routes": sum(1 for rt in routes if rt.get("owned")),
            "owned_paths": sum(1 for m in rows if m.get("owned")),
            "asset_count": len({r["asset_uuid"] for r in rows}),
            "tag_assets": int(n), "tag_query": tag_query_for(keyword),
            "setup": setup, "needs_setup": needs,
            "setup_hint": (_SETUP_HINT if needs else ""),
            "scope": tagscope.describe(k, v)}, 200


def _tag_scoped(name, keyword, k, v):
    """tag() from a tag view: the asset set (paths matching the keyword + assets on the matching
    routes' plugins) is re-read from navi.db here, limited IN SQL to the assets tagged k : v,
    and written as one paged UUID set (add-only). Never --route_id (that reaches the whole
    route) and never a UUID list from the browser."""
    routes = search_routes(keyword, scope=(k, v))
    plugins = sorted({pid for rt in routes for pid in rt.get("plugins") or ()})
    sql, params = scoped_tag_sql(keyword, plugins, k, v)
    uuids = navi_cli.collect_uuids(sql, params) if sql else []
    scope = tagscope.describe(k, v)
    if not uuids:
        setup = routing_status()
        needs = not (setup["vuln_route"] or setup["vuln_paths"])
        msg = (_SETUP_HINT if needs else
               f"no path or route matches for that keyword on the assets tagged {k} : {v} — nothing tagged")
        return {"ok": False, "error": msg, "message": msg, "setup": setup, "needs_setup": needs,
                "scope": scope, "writes_enabled": navi_cli.writes_enabled()}, 200
    jobs = navi_cli.tag_set("Custom App", name, uuids=uuids, agent="customapp")
    js = navi_cli.jobs_summary(jobs)
    res = {"selector": "scoped set", "via": "vuln_paths + vuln_route", "assets": len(uuids),
           "routes": len(routes), "jobs": js["jobs"], "job_ids": js["job_ids"],
           "ok": js["ok"], "message": js.get("error") or (js.get("result") or {}).get("message", "")}
    return {"ok": js["ok"], "results": [res], "scoped_assets": len(uuids),
            "path_tags": js["jobs"], "route_tags": 0, "scope": scope,
            "writes_enabled": navi_cli.writes_enabled()}, 200


def tag(p):
    """Tag a custom app across both tables: filesystem paths via --query, and any
    matching application routes via --route_id (vuln_route has no asset_uuid).
    From a tag view (tag_scope) only that tag's assets are tagged — see _tag_scoped."""
    name, keyword = p.get("name", ""), p.get("keyword", "")
    if not confirmed(p):
        return {"ok": False, "error": "confirm=true required to tag"}, 400
    if not name or not keyword:
        return {"ok": False, "error": "name and keyword are required"}, 400
    k, v = tagscope.parse(p)
    if k:
        return _tag_scoped(name, keyword, k, v)

    results, ok_any = [], False
    paths = search_paths(keyword)
    if paths:
        r = navi_cli.tag("Custom App", name, tag_query_for(keyword), remove=False, agent="customapp")
        ok_any = ok_any or r.get("ok", False)
        results.append({"selector": "query", "via": "vuln_paths",
                        "assets": len({x["asset_uuid"] for x in paths}), **r})

    routes = search_routes(keyword)
    for rt in routes:
        rid = rt.get("route_id")
        if rid is None:
            continue
        r = navi_cli.tag("Custom App", name, route_id=str(rid), remove=False, agent="customapp")
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
