"""Sphinx — On the Scent. The estate brain: posture across every Hound, blind
spots (unknown-unknowns), cross-Hound surprises, and a hand-off to Nemesis."""
from core import insights


def board(p):
    """The Scent Board — estate posture + blind spots + convergence + Nemesis lead-in."""
    try:
        return {"ok": True, "result": insights.scent_board()}, 200
    except Exception as e:
        return {"ok": False, "error": str(e)}, 200


def run(p):
    """Legacy single-signal rollup (certs timeline, tiles) — still available."""
    try:
        return {"ok": True, "result": insights.compute()}, 200
    except Exception as e:
        return {"ok": False, "error": str(e)}, 200


ACTIONS = {"board": board, "run": run}
