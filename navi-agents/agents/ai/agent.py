"""AI Inventory agent.

Surfaces every asset with Artificial Intelligence software (Tenable's
'Artificial Intelligence' plugin family) and tags them via navi's tag-by-query
selector. Read-only discovery; the tag write is gated.
"""
from core import ai_assets
from core.agents.base import Agent


class AiAgent(Agent):
    id = "ai"
    name = "AI Inventory"
    icon = "🧠"
    description = ("Pythia — content-first AI/ML discovery across the AI plugin family + "
                  "software + cpes + plugin output + network endpoints; classifies role, "
                  "flags exposed/unauth endpoints, maps data-egress (shadow vs sanctioned) "
                  "and MITRE ATLAS, and tags by role (navi tag-by-query). Gated writes.")

    def summary(self):
        if not self.result:
            return {}
        return {"ai_assets": self.result.get("asset_count"),
                "exposed": self.result.get("exposedCount"),
                "kev": self.result.get("kevCount"),
                "shadow": self.result.get("shadowCount")}

    def _run(self, db_path=None, **kwargs):
        return ai_assets.scan(db_path, fp=kwargs.get("fp"), allow=kwargs.get("allow"))
