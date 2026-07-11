"""Path Explorer — read-only navi.db search (paginated) + tag-by-path."""
from core import search, navi_cli


def run(p):
    try:
        res = search.paths((p.get("q") or "").strip(), int(p.get("offset") or 0))
    except Exception as e:
        return {"ok": False, "error": str(e)}, 200
    return {"ok": True, "result": res}, 200


def tag(p):
    if not p.get("confirm"):
        return {"ok": False, "error": "confirm=true required to write tags"}, 400
    path = (p.get("path") or "").strip()
    value = (p.get("value") or "").strip()
    if not path or not value:
        return {"ok": False, "error": "path and value required"}, 400
    # tag every asset that carries this exact path (navi tag-by-query)
    q = "SELECT asset_uuid FROM vuln_paths WHERE path='" + path.replace("'", "''") + "'"
    r = navi_cli.tag(p.get("category", "Path"), value, query=q, remove=False)
    return {"ok": True, "result": r, "writes_enabled": navi_cli.writes_enabled()}, 200


ACTIONS = {"search": run, "tag": tag}
