"""Scan Evaluations agent.

Reproduces navi scan evaluate (scanner/policy/scan averages from plugin 19506) and
credential-failure coverage (plugin 104410), and tags problem areas via navi.
Read-only discovery; tag writes are gated.
"""
from core import scan_eval
from core.agents.base import Agent


class ScanEvalAgent(Agent):
    id = "scan_eval"
    name = "Scan Evaluations"
    icon = "📈"
    description = ("What your scans can and can't see: per-asset credential health (the Target "
                   "Credential Status / Issues plugins + 19506), scan freshness, agent vs network, "
                   "crown-jewel blind spots, and scanner / policy / scan time, load and plugin-feed "
                   "currency. Tags the exact assets under Scan Health (gated).")

    def summary(self):
        if not self.result:
            return {}
        c = self.result.get("credential", {})
        m = self.result.get("metrics", {})
        return {"scanners": len(self.result.get("scanners", [])),
                "policies": len(self.result.get("policies", [])),
                "cred_fail": c.get("cred_fail_assets"),
                "blind": m.get("blind"), "stale_90": m.get("stale_90"),
                "crown_blind": m.get("crown_blind"), "cred_ok_pct": m.get("cred_ok_pct")}

    def _run(self, db_path=None):
        return scan_eval.evaluate(db_path)
