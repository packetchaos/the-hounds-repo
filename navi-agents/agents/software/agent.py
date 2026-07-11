"""Software Analyzer agent (Mimir Hound).

Aggregates the `software` table into version sprawl, most-deployed software, and
single-install rarities. Read-only analysis; tag writes are gated.
"""
from core import software
from core.agents.base import Agent


class SoftwareAgent(Agent):
    id = "software"
    name = "Software Analyzer"
    icon = "📦"
    description = ("Finds version sprawl, the most-deployed software, and rare "
                  "single-install apps from the software table; tags products/versions.")

    def summary(self):
        if not self.result:
            return {}
        c = self.result.get("counts", {})
        return {"products": c.get("products"), "multi_version": c.get("multi_version"),
                "assets": c.get("assets")}

    def _run(self, db_path=None, **kwargs):
        return software.analyze(db_path)
