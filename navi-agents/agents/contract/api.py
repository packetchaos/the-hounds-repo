"""AI Navi Contract — HTTP actions (authoring, plan, arm, run, schedule)."""
from core import contract, navi_cli
from .agent import ContractAgent

AGENT = ContractAgent()


def get(p):
    return {"ok": True, "agent": AGENT.meta(), "contract": contract.current(),
            "scheduler": contract.scheduler_status(), "saved": contract.list_saved(),
            "writes_enabled": navi_cli.writes_enabled()}, 200


def set_(p):
    doc = p.get("contract") or p
    return {"ok": True, "contract": contract.set_contract(doc)}, 200


def build_from_log(p):
    from core import tagq
    n = len(tagq.list_jobs())
    return {"ok": True, "contract": contract.build_from_log(), "log_count": n}, 200


def build_from_csv(p):
    """Build the contract from rows parsed out of an exported tag-log CSV, so the
    policy can be seeded even after a restart (in-memory log is gone). Each row is
    a dict with at least agent/category/value (and detail for ACR score)."""
    rows = p.get("rows") or []
    rows = [r for r in rows if isinstance(r, dict) and (r.get("agent") or r.get("category"))]
    return {"ok": True, "contract": contract.build_from_log(rows), "log_count": len(rows)}, 200


def plan(p):
    return {"ok": True, "plan": contract.plan()}, 200


def export(p):
    return {"ok": True, "script": contract.export_script()}, 200


def run_now(p):
    # manual trigger: removal + re-tag, but DON'T block the request for the 30-min
    # pause (that pause is enforced only in the autonomous scheduler loop)
    return {"ok": True, "cycle": contract.run_cycle(enforce_pause=False)}, 200


def arm(p):
    c = contract.current(); c["armed"] = True
    contract.set_contract(c)
    contract.scheduler_start()
    return {"ok": True, "armed": True, "scheduler": contract.scheduler_status(),
            "writes_enabled": navi_cli.writes_enabled()}, 200


def disarm(p):
    c = contract.current(); c["armed"] = False
    contract.set_contract(c)
    contract.scheduler_stop()
    return {"ok": True, "armed": False, "scheduler": contract.scheduler_status()}, 200


def save(p):
    return {**contract.save(p.get("name"))}, 200


def load(p):
    try:
        return {"ok": True, "contract": contract.load(p.get("name", ""))}, 200
    except Exception as e:
        return {"ok": False, "error": str(e)}, 200


def list_(p):
    return {"ok": True, "saved": contract.list_saved()}, 200


def status(p):
    return {"ok": True, "scheduler": contract.scheduler_status(),
            "loop_log": contract.loop_log(), "armed": contract.current().get("armed", False)}, 200


def loop_log(p):
    return {"ok": True, "loop_log": contract.loop_log()}, 200


def scheduler(p):
    op = p.get("op")
    if op == "start":
        return {"ok": True, **contract.scheduler_start()}, 200
    if op == "stop":
        return {"ok": True, **contract.scheduler_stop()}, 200
    return {"ok": True, "scheduler": contract.scheduler_status()}, 200


ACTIONS = {"get": get, "set": set_, "build_from_log": build_from_log,
           "build_from_csv": build_from_csv, "plan": plan,
           "export": export, "run_now": run_now, "arm": arm, "disarm": disarm,
           "save": save, "load": load, "list": list_, "status": status,
           "loop_log": loop_log, "scheduler": scheduler}
