"""Tiresias — the Compliance Asset deep-dive agent.

The detective of the pack: point Tiresias at one asset and it lays out every audit
check that passed/failed/warned (actual vs expected, framework mappings), pulls in the
asset's real vulns, and INFERS the connection between a failed control and the findings
that back it — then lets you tag that audit↔vuln correlation. Argos/Beagle do the VM
and web-app deep-dives; Tiresias does compliance. Read-only; core.compliance does the
work. Driven by ?asset=<uuid> from Minos (falls back to the worst-failing asset).
"""
from core import compliance as _c
from core.agents.base import Agent


class TiresiasAgent(Agent):
    id = "compliance_asset"
    name = "Compliance Deep-Dive"
    icon = "🔍"
    description = ("Tiresias — the compliance asset detective. Per-asset audit checks "
                   "(pass/fail/warn, actual vs expected, frameworks) plus the inferred link "
                   "between a failed control and the vulns backing it.")

    def summary(self):
        return {"hint": "Open Tiresias from an asset in Minos to inspect its compliance."}

    def _run(self, db_path=None, **kwargs):
        return {"hint": "Pick an asset on the Tiresias page to inspect its audit checks.",
                "ready": bool(_c.status(path=db_path).get("ready"))}
