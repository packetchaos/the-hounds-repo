"""Fenrir — Attack Path Analysis agent. The engine lives in core.attackpath."""
from core import attackpath
from core.agents.base import Agent

ENTRY_CAT = "Attack Path"


def analyze(db_path=None, crown_acr=attackpath.CROWN_ACR):
    return attackpath.analyze(db_path, crown_acr=crown_acr)


class AttackPathAgent(Agent):
    id = "attackpath"
    name = "Attack Path Analysis"
    icon = "🕸️"
    description = ("Fenrir — chains exploitable vulnerabilities, privilege escalation, account reuse, "
                   "NTLM relay, failed compliance controls and domain compromise into ranked paths to the "
                   "crown jewels, and finds the fixes that break the most of them. Gated tagging.")

    def summary(self):
        if not self.result:
            return {}
        m = self.result.get("metrics", {})
        return {"paths": m.get("paths"), "entries": m.get("entries"), "targets": m.get("crown_reachable")}

    def _run(self, db_path=None, crown_acr=attackpath.CROWN_ACR, **kwargs):
        return analyze(db_path, crown_acr=crown_acr)
