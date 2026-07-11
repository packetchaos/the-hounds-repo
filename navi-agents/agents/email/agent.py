"""Gabriel — the email / reporting agent (the loop-closer).

Gabriel, the messenger, carries the pack's findings to the humans who own them.
It reads Atlas's `Owner:` tags so each owner gets *only their* assets, pulls
Laelaps (KEV) fire-alarms and Certania (cert) countdowns, and folds in the On the
Scent morning briefing — then emails it with deep-links back into the Tenable
platform. Composing/preview is read-only; the actual send is double-gated
(writes + a separate email opt-in + an explicit confirm).
"""
from core.agents.base import Agent


class GabrielAgent(Agent):
    id = "email"
    name = "Email & Reports"
    icon = "📧"
    description = ("Gabriel — turns the pack's findings into owner-routed remediation, "
                   "KEV alarms, cert countdowns and briefings, emailed to the right humans "
                   "with Tenable deep-links. Owner routing comes from Atlas Owner: tags.")

    def summary(self):
        if not self.result:
            return {}
        return {"owners": self.result.get("owner_count", 0),
                "email_enabled": self.result.get("email_enabled", False)}

    def _run(self, db_path=None, **kwargs):
        from core import navi_cli
        try:
            from . import api
            owners = api._owner_index()
            n = len(owners)
        except Exception:
            n = 0
        return {"ready": True, "owner_count": n,
                "email_enabled": navi_cli.email_enabled(),
                "hint": "Pick a report on the Gabriel page, preview it, then send "
                        "(sending needs NAVI_ALLOW_WRITES=1 + NAVI_EMAIL=1 + confirm)."}
