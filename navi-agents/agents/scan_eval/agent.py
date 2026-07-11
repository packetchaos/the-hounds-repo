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
    description = ("Average scan time by scanner / policy / scan (plugin 19506) plus "
                  "credential-failure coverage (plugin 104410); tag problem areas via navi.")

    def summary(self):
        if not self.result:
            return {}
        c = self.result.get("credential", {})
        return {"scanners": len(self.result.get("scanners", [])),
                "policies": len(self.result.get("policies", [])),
                "cred_fail": c.get("cred_fail_assets")}

    def _run(self, db_path=None):
        return scan_eval.evaluate(db_path)
