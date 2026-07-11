"""Plugin Explorer — read-only navi.db search (paginated)."""
from core import search

def run(p):
    try:
        res = search.plugins((p.get("q") or "").strip(), int(p.get("offset") or 0))
    except Exception as e:
        return {"ok": False, "error": str(e)}, 200
    return {"ok": True, "result": res}, 200

ACTIONS = {"search": run}
