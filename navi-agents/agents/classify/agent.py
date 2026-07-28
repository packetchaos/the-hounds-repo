"""Asset Classification agent (Linnaeus) — thin wrapper over core.classify."""
from core import classify as _classify
from core.agents.base import Agent


class ClassifyAgent(Agent):
    id = "classify"
    name = "Asset Classification"
    icon = "📇"
    description = ("Classifies every asset (Windows / Linux / macOS / IoT / OT / Network / "
                   "Virtual / Unclassified) to close the detection loop that stalls ownership.")

    def summary(self):
        if not self.result:
            return {}
        return {"total": self.result.get("total"),
                "coverage_pct": self.result.get("coverage_pct"),
                "unclassified": self.result.get("unclassified")}

    def _run(self, db_path=None):
        return _classify.classify(db_path)
