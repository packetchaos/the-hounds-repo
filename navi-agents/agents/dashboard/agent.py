"""Dashboard Builder agent.

A read-only, prompt-driven dashboard maker. The operator describes the view they
want; the model proposes ONE read-only SQL SELECT against navi.db (core.dashboard
validates it) and the UI renders the result in the project style. Lets a user
visualize something we never built a dedicated page for, without leaving the app.
"""
from core import dashboard
from core.agents.base import Agent


class DashboardAgent(Agent):
    id = "dashboard"
    name = "Dashboard Builder"
    icon = "📊"
    description = ("Turns a plain-English request into a read-only navi.db query and "
                  "renders it as KPI tiles, a bar chart, or a table — a build-your-own "
                  "dashboard for views we didn't ship a page for.")

    def summary(self):
        if not self.result:
            return {}
        return {"title": self.result.get("title"),
                "rows": self.result.get("row_count"),
                "viz": self.result.get("viz")}

    def _run(self, db_path=None, prompt=""):
        return dashboard.build(prompt, db_path=db_path)
