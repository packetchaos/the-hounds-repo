"""Sköll — the SLA Adherence agent.

Named for the Norse wolf that eternally chases the sun across the sky: Sköll chases
the SLA clock. It measures two things, segmented by owner/tag:
  • remediation — were CLOSED findings fixed inside their SLA window (Pass/Fail),
  • open aging  — how OPEN findings are aging against the per-severity SLA window.
Plus navi's own Pass/Fail verdict as the headline. All read-only over navi.db — the
computation lives in core.sla. (Its twin Hati will chase the moon: the trending agent.)
"""
from core import sla as _sla
from core.agents.base import Agent


class SkollAgent(Agent):
    id = "sla"
    name = "SLA Adherence"
    icon = "⏱"
    description = ("Sköll — chases the SLA clock. Remediation adherence on closed findings "
                   "and open-vuln aging vs the per-severity SLA window, by owner/tag. Records "
                   "a daily snapshot for the trend view.")

    def summary(self):
        r = self.result or {}
        oa = r.get("open_aging") or {}
        vd = r.get("verdict") or {}
        return {"adherence_pct": vd.get("adherence_pct"),
                "open": oa.get("open"), "open_breached": oa.get("breached")}

    def _run(self, db_path=None, tag_key=None, tag_value=None, **kwargs):
        return _sla.dashboard(path=db_path, tag_key=tag_key, tag_value=tag_value)
