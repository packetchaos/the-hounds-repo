"""Template agent — copy this folder to agents/<your-id> and make it yours.

Read-only discovery: subclass Agent and implement _run() to return a dict.
"""
from core.agents.base import Agent

try:
    from core import db
except Exception:                       # pragma: no cover
    db = None


class TemplateAgent(Agent):
    id = "_template"
    name = "Template Agent"
    icon = "🧩"
    description = "A minimal starting point: counts assets in navi.db (read-only)."

    def _run(self, db_path=None, **kwargs):
        n = 0
        if db is not None:
            try:
                rows = db.query("SELECT COUNT(uuid) AS c FROM assets", path=db_path)
                n = (rows[0].get("c") if rows else 0) or 0
            except Exception:
                n = 0
        return {"asset_count": n,
                "hint": "Edit agents/<your-id>/agent.py to build real discovery."}
