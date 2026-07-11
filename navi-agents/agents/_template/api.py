"""Template agent HTTP actions. ACTIONS maps action name -> fn(payload)->(dict, status)."""
AGENT = None


def _agent():
    global AGENT
    if AGENT is None:
        from .agent import TemplateAgent
        AGENT = TemplateAgent()
    return AGENT


def run(p):
    return {"ok": True, "agent": _agent().meta(), "result": _agent().run()}, 200


ACTIONS = {"run": run}
