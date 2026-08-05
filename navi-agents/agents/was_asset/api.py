"""Beagle / Web App Recon — self-contained HTTP actions.

`run`           — readiness stub (the hub's generic Execute).
`info`          — the workhorse: payload {app_uuid} (an app uuid OR asset_uuid; falls
                  back to the top-risk app) → the app's identity plus its recon (WAS
                  info) plugins, drawn from navi's findings, plus the risk-sorted app
                  list for the page selector.
`plugin_output` — the special SQL there is no navi primitive for: raw findings.output
                  (+ proof / request+response headers) for one plugin on the app.
Read-only over navi.db.
"""
AGENT = None


def _agent():
    global AGENT
    if AGENT is None:
        from .agent import BeagleAgent
        AGENT = BeagleAgent()
    return AGENT


def run(p):
    return {"ok": True, "agent": _agent().meta(), "result": _agent().run()}, 200


def info(p):
    from core import was
    au = (p.get("app_uuid") or p.get("app") or p.get("asset") or "").strip()
    return {"ok": True, "result": {"info": was.app_info(app_uuid=au),
                                   "apps": was.apps_list()}}, 200


def plugin_output(p):
    from core import was
    return {"ok": True, "result": was.plugin_output(
        app_uuid=(p.get("app_uuid") or "").strip(),
        plugin_id=(p.get("plugin_id") or "").strip())}, 200


ACTIONS = {"run": run, "info": info, "plugin_output": plugin_output}
