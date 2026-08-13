"""Arachne — the WAS (Web Application Scanning) agent.

Named for the Aztec dog-god who guards and guides souls: Arachne watches over the web
apps. It owns two dashboards over navi's `apps`/`findings` tables — a consolidated
Overview (all apps) and a per-app App Report — surfacing severity, the OWASP Top-10
profile, the technology stack, and scan coverage. All read-only; core.was does the work.
"""
from core import was
from core.agents.base import Agent


class ArachneAgent(Agent):
    id = "was"
    name = "WAS · Web Apps"
    icon = "🕸️"
    description = ("Arachne — guards the web apps. Consolidated WAS overview + per-app scan "
                   "reports over navi's apps/findings: severity, OWASP Top-10, tech stack, "
                   "and scan coverage.")

    def summary(self):
        r = self.result or {}
        sev = r.get("severity") or {}
        return {"apps": r.get("apps"), "critical": sev.get("critical"), "high": sev.get("high")}

    def _run(self, db_path=None, **kwargs):
        return was.overview(path=db_path)
