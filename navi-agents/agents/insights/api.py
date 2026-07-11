"""'Bet You Didn't Know This' — aggregate insights (read-only)."""
from core import insights


def run(p):
    try:
        return {"ok": True, "result": insights.compute()}, 200
    except Exception as e:
        return {"ok": False, "error": str(e)}, 200


ACTIONS = {"run": run}
