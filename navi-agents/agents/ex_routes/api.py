"""Route Explorer — read-only navi.db search (paginated) + tag-by-route."""
from core import search, navi_cli


def run(p):
    try:
        res = search.routes((p.get("q") or "").strip(), int(p.get("offset") or 0))
    except Exception as e:
        return {"ok": False, "error": str(e)}, 200
    return {"ok": True, "result": res}, 200


def tag(p):
    if not p.get("confirm"):
        return {"ok": False, "error": "confirm=true required to write tags"}, 400
    rid = str(p.get("route_id") or "").strip()
    value = (p.get("value") or "").strip()
    if not rid or not value:
        return {"ok": False, "error": "route_id and value required"}, 400
    r = navi_cli.tag(p.get("category", "Route"), value, route_id=rid, remove=False)
    return {"ok": True, "result": r, "writes_enabled": navi_cli.writes_enabled()}, 200


ACTIONS = {"search": run, "tag": tag}
