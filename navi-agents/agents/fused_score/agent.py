"""Fused Exposure Score — Nemesis.

The convergence layer over the whole pack: it doesn't find anything new, it fuses
what every other Hound found into one exposure score per asset, ranks the estate,
and drives the highest-leverage action. See core/fused_score.py.
"""
from core import fused_score as engine
from core.agents.base import Agent


class FusedScoreAgent(Agent):
    id = "fused_score"
    name = "Exposure Score"
    icon = "🎯"
    description = ("Nemesis — fuses every Hound's signal into one exposure score per asset, "
                  "surfaces the worst from each and where they converge, ranks worst-first, and "
                  "turns a remediation play into a projected reduction. Priority tagging gated.")

    def summary(self):
        if not self.result:
            return {}
        k = (self.result or {}).get("kpi", {})
        return {"assets": k.get("assets"), "critical": k.get("critical"),
                "crown_kev": k.get("crown_kev"), "estate": k.get("estate")}

    def _run(self, db_path=None, **kwargs):
        return engine.overview(db_path)
