"""Dashboard Builder — self-contained HTTP actions.

`build` — take a plain-English `prompt`, ask the model for ONE read-only SQL
          SELECT over navi.db (core.dashboard validates + runs it read-only), and
          return rows + the chosen visualization for the UI to render.

Read-only end to end: navi.db is opened in SQLite read-only mode and the SQL is
guarded to a single SELECT. This agent never writes anything.
"""
from core import dashboard

AGENT = None


def _agent():
    global AGENT
    if AGENT is None:
        from .agent import DashboardAgent
        AGENT = DashboardAgent()
    return AGENT


def build(p):
    prompt = (p.get("prompt") or "").strip()
    if not prompt:
        return {"ok": False, "error": "describe the dashboard you want to see"}, 200
    try:
        res = dashboard.build(prompt)
    except Exception as e:
        return {"ok": False, "error": f"dashboard build failed: {e}"}, 200
    if not res.get("ok"):
        return {"ok": False, "error": res.get("error", "could not build"),
                "needs_key": res.get("needs_key", False), "sql": res.get("sql")}, 200
    return {"ok": True, "agent": _agent().meta(), "result": res}, 200


ACTIONS = {"build": build}
