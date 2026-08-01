"""Minos — the Compliance Overview agent.

Named for the mythic judge who weighs each case and renders a verdict: Minos weighs
the estate against its audit benchmarks. Consolidated compliance over navi's
`compliance` table — pass/fail/warning, the controls failing the most assets, a
framework rollup (NIST/PCI/HIPAA/CIS/ISO), and per-asset scorecards — plus the ability
to assign an Audit Owner to a control's failing assets. Read-only; core.compliance
does the work. Its twin Sherlock handles the per-asset deep-dive + audit↔vuln links.
"""
from core import compliance as _c
from core.agents.base import Agent


class MinosAgent(Agent):
    id = "compliance"
    name = "Compliance"
    icon = "⚖️"
    description = ("Minos — judges the estate against its audit benchmarks. Pass/fail/warning, "
                   "the controls failing the most assets, framework rollup, per-asset scorecards, "
                   "and Audit-Owner tagging over navi's compliance table.")

    def summary(self):
        r = self.result or {}
        return {"assets": r.get("assets"), "failed": r.get("failed"), "pass_pct": r.get("pass_pct")}

    def _run(self, db_path=None, **kwargs):
        return _c.overview(path=db_path)
