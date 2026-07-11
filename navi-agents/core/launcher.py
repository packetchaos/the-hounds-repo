"""Shared launcher logic — discovery + generic action dispatch.

Both app_fastapi.py and app_flask.py import this so behavior is identical.
Drop a new agent folder into agents/ and restart: it is discovered, its
api.ACTIONS are mounted under /api/<id>/<action>, and the hub lists it.
"""
from . import health as _health, discovery

RECORDS = discovery.discover()
DISPATCH = {r["id"]: r["actions"] for r in RECORDS if r["deployed"]}


def registry() -> dict:
    return discovery.registry(RECORDS)


def health() -> dict:
    return _health.health()


def dispatch(agent_id: str, action: str, payload: dict):
    acts = DISPATCH.get(agent_id)
    if acts is None:
        return {"ok": False, "error": f"agent '{agent_id}' is not deployed"}, 404
    fn = acts.get(action)
    if not fn:
        return {"ok": False, "error": f"unknown action '{action}' for '{agent_id}'"}, 404
    try:
        return fn(payload or {})
    except Exception as e:  # pragma: no cover
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}, 500
