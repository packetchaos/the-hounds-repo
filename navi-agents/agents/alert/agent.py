"""Alert Raven — the alerting companion that rides with the pack. Read-only detection
over navi.db; the card metric is the number of enabled alerts. All the real work lives
in core/alerts.py."""
from core.agents.base import Agent

try:
    from core import alerts as _alerts
except Exception:                       # pragma: no cover
    _alerts = None


class AlertAgent(Agent):
    id = "alert"
    name = "Alerting"
    icon = "🚨"
    description = ("Alert Raven watches navi.db for conditions worth an email — coverage drops, "
                   "slow scans, new KEV, expiring certs — fires on change, digests by email (gated).")

    def _run(self, db_path=None, **kwargs):
        if _alerts is None:
            return {"ok": False, "error": "alerts engine unavailable"}
        return _alerts.metrics(db_path)
