"""Route Explorer — read-only navi.db search (paginated) + tag-by-route."""
import re
from core import search, navi_cli, db
from core.gates import confirmed


def run(p):
    try:
        res = search.routes((p.get("q") or "").strip(), int(p.get("offset") or 0), p.get("limit"))
    except Exception as e:
        return {"ok": False, "error": str(e)}, 200
    return {"ok": True, "result": res}, 200


def tag(p):
    if not confirmed(p):
        return {"ok": False, "error": "confirm=true required to write tags"}, 400
    rid = str(p.get("route_id") or "").strip()
    value = (p.get("value") or "").strip()
    if not rid or not value:
        return {"ok": False, "error": "route_id and value required"}, 400
    r = navi_cli.tag(p.get("category", "Route"), value, route_id=rid, remove=False)
    return {"ok": True, "result": r, "writes_enabled": navi_cli.writes_enabled()}, 200


def count(p):
    """Read-only: how many assets carry a plugin on this route (what navi tag --route_id
    selects) — shown in the page's confirm()."""
    rid = str(p.get("route_id") or "").strip()
    if not rid:
        return {"ok": False, "error": "route_id required"}, 400
    try:
        pl = db.scalar("SELECT plugin_list FROM vuln_route WHERE route_id=?", (rid,))
        ids = sorted({x for x in re.findall(r"\d+", str(pl or ""))})
        seen = set()
        for i in range(0, len(ids), 500):          # stay under SQLite's bound-variable limit
            chunk = ids[i:i + 500]
            rows = db.query("SELECT DISTINCT asset_uuid FROM vulns WHERE plugin_id IN (" + ",".join("?" * len(chunk)) + ")",
                            tuple(chunk))
            seen.update(r["asset_uuid"] for r in rows if r.get("asset_uuid"))
        n = len(seen)
    except Exception as e:
        return {"ok": False, "error": str(e)}, 200
    return {"ok": True, "assets": n, "plugins": len(ids)}, 200


ACTIONS = {"search": run, "tag": tag, "count": count}
