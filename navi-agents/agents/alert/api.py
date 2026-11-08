"""Alert Raven (Alerting) — HTTP actions. Thin wrappers over core.alerts.

Reads: metrics / list / suggest / history. Compute: craft (NL→query) / test (dry-run —
no state change, no send). Mutations: save / delete / toggle / add_template (local JSON,
not a tenant write). evaluate: run every enabled alert, fire on change, optionally email a
gated digest (send=true)."""
from core import alerts, navi_cli
from core.gates import confirmed
from .agent import AlertAgent

AGENT = AlertAgent()


def run(p):
    return {"ok": True, "agent": AGENT.meta(), "result": alerts.metrics()}, 200


def metrics(p):
    return {"ok": True, **alerts.metrics()}, 200


def list_(p):
    return {"ok": True, "alerts": alerts.list_alerts()}, 200


def suggest(p):
    return {"ok": True, **alerts.suggest()}, 200


def history(p):
    return {"ok": True, "history": alerts.history(int((p or {}).get("limit") or 50))}, 200


def craft(p):
    p = p or {}
    return {"ok": True, "draft": alerts.craft(p.get("prompt") or "", include_output=bool(p.get("include_output")))}, 200


def test(p):
    p = p or {}
    a = p.get("alert") or p
    if a.get("id") and not (a.get("metric_sql") or a.get("builtin")):
        for d in alerts.list_alerts():
            if d.get("id") == a["id"]:
                a = d
                break
    return {"ok": True, "result": alerts.test(a)}, 200


def save(p):
    p = p or {}
    return alerts.save_alert(p.get("alert") or p), 200


def delete(p):
    return alerts.delete_alert((p or {}).get("id")), 200


def toggle(p):
    p = p or {}
    return alerts.toggle(p.get("id"), bool(p.get("enabled"))), 200


def add_template(p):
    p = p or {}
    return alerts.add_template(p.get("template"), p.get("overrides")), 200


def send_test(p):
    """Send a REAL test email for one alert so the operator can confirm delivery works —
    regardless of whether the alert would fire. Gated by NAVI_EMAIL + confirm === true, and
    only to a configured alert recipient (NAVI_ALERT_EMAIL). Changes no state."""
    p = p or {}
    if not confirmed(p):
        return {"ok": False, "error": "confirm=true required to send a test email"}, 400
    ok_r, why = alerts.recipient_allowed(p.get("recipient"))
    if not ok_r:
        return {"ok": False, "error": why, "result": {"ok": False, "reason": why}}, 400
    a = p.get("alert") or {"id": p.get("id"), "name": p.get("name")}
    if a.get("id") and not (a.get("metric_sql") or a.get("builtin")):
        for d in alerts.list_alerts():
            if d.get("id") == a["id"]:
                a = d
                break
    return {"ok": True, "result": alerts.send_test(a, recipient=(p.get("recipient") or None)),
            "email_enabled": navi_cli.email_enabled()}, 200


def evaluate(p):
    """Evaluate all enabled alerts now. send=true emails a digest of what NEWLY fired
    (gated by NAVI_EMAIL). Without send it's a live dry-run — nothing leaves the box."""
    p = p or {}
    send = p.get("send") is True
    if send:
        if not confirmed(p):
            return {"ok": False, "error": "confirm=true required to email the digest (send=true)"}, 400
        ok_r, why = alerts.recipient_allowed(p.get("recipient"))
        if not ok_r:
            return {"ok": False, "error": why}, 400
    res = alerts.evaluate_all(send=send, recipient=(p.get("recipient") or None),
                              source=p.get("source") or "manual")
    res["email_enabled"] = navi_cli.email_enabled()
    return {"ok": True, **res}, 200


ACTIONS = {"run": run, "metrics": metrics, "list": list_, "suggest": suggest, "history": history,
           "craft": craft, "test": test, "send_test": send_test, "save": save, "delete": delete,
           "toggle": toggle, "add_template": add_template, "evaluate": evaluate}
