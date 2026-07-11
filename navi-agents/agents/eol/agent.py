"""EOL / Unsupported software tagging agent."""
from core import eol
from core.agents.base import Agent


class EolAgent(Agent):
    id = "eol"
    name = "EOL / Unsupported Tagging"
    icon = "⏏️"
    description = ("Detects Unsupported / End-of-Life software from lifecycle text in "
                  "plugin names and tags the affected assets via navi tag-by-name.")

    def summary(self):
        if not self.result:
            return {}
        g = self.result.get("groups", [])
        return {"groups": len(g), "assets": sum(x["asset_count"] for x in g)}

    def _run(self, db_path=None, groups=None):
        return eol.scan(db_path, groups=groups)
