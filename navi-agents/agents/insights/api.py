"""Sphinx — On the Scent. The estate brain, built from Release the Hounds.

scent — the page's read. A compact digest (~20 KB) of every hound's RELEASED result: the
        page-cache entries Release saved (core/pagecache.py) + the Nemesis / Atlas / Sköll
        snapshots. Reads caches only — never navi.db, never re-runs a hound.
          {peek:true}   the stored digest (+ `outdated`, live coverage) or {state:"none"};
                        never builds — this is all opening the page does
          {}            stored digest if its inputs are unchanged, else build it (inline when
                        the cached inputs are ≤ 4 MB gz, else on the job queue →
                        {building:{job_id}}; poll /api/jobs/<id>, then peek)
          {force:true}  ↻ Rebuild from cache
        Release the Hounds runs this LAST (core/release_recipes.json, kind "snapshot").
board — legacy live roll-up (computes from navi.db; kept for MCP / other callers — the page
        no longer uses it).
run   — legacy single-signal roll-up (same).
"""
from core import insights, jobq


def _submit(fn):
    return jobq.submit(fn, {"agent": "insights", "action": "scent", "label": "On the Scent summary"})


def scent(p):
    try:
        return {"ok": True, "result": insights.scent(p or {}, submit=_submit)}, 200
    except Exception as e:
        return {"ok": False, "error": "%s: %s" % (type(e).__name__, e)}, 200


def board(p):
    """Legacy: the live Scent Board roll-up (queries navi.db). The page uses `scent`."""
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


ACTIONS = {"scent": scent, "board": board, "run": run}
