"""Parity guardrail for the Hounds MCP.

Two checks, run against whatever NAVI_DB_PATH points at (default: bundled sample):
  1. PARITY — each tool wrapper returns EXACTLY what the underlying core engine returns.
     (If someone ever adds a transform in a tool, this fails.)
  2. SHAPE  — each payload still carries the keys the Executive artifact renders.
     (If an engine change drops a field the artifact needs, this fails — that's the
     "don't lose functionality" tripwire.)

Usage:  NAVI_DB_PATH=./sample_navi.db python hounds_mcp_selftest.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from core import fused_score, insights
import hounds_mcp as H

# keys the Executive artifact depends on — the contract it renders against
EXPOSURE_KEYS = {"ok", "kpi", "factors", "assets", "total", "worst", "convergence"}
KPI_KEYS = {"assets", "critical", "high", "estate", "avg", "factor_totals"}
SCENT_KEYS = {"ok", "nemesis", "bands", "risk_by_hound", "radar", "funnel",
              "reduction", "champion", "posture", "blind", "convergence"}


def _check(name, ok, detail=""):
    print(("  ok  " if ok else " FAIL ") + name + ((" — " + detail) if detail else ""))
    return ok


def main():
    db = os.environ.get("NAVI_DB_PATH", "(default)")
    print("Hounds MCP self-test · NAVI_DB_PATH=%s\n" % db)
    passed = True

    ov_tool = H._exposure_overview()
    ov_core = fused_score.overview()
    passed &= _check("exposure_overview parity (tool == core)", ov_tool == ov_core)
    missing = EXPOSURE_KEYS - set(ov_tool)
    passed &= _check("exposure_overview shape", not missing, "missing " + ", ".join(sorted(missing)) if missing else "")
    kmiss = KPI_KEYS - set(ov_tool.get("kpi", {}))
    passed &= _check("exposure_overview kpi shape", not kmiss, "missing " + ", ".join(sorted(kmiss)) if kmiss else "")
    passed &= _check("exposure_overview factor weights sum to 100",
                     sum(f["max"] for f in ov_tool.get("factors", [])) == 100,
                     "sum=%s" % sum(f["max"] for f in ov_tool.get("factors", [])))

    sb_tool = H._scent_board()
    sb_core = insights.scent_board()
    passed &= _check("scent_board parity (tool == core)", sb_tool == sb_core)
    smiss = SCENT_KEYS - set(sb_tool)
    passed &= _check("scent_board shape", not smiss, "missing " + ", ".join(sorted(smiss)) if smiss else "")
    passed &= _check("scent_board radar has axes", bool(sb_tool.get("radar")))
    passed &= _check("scent_board risk_by_hound non-empty", bool(sb_tool.get("risk_by_hound")))

    # confirm the two tools actually registered (API differs across SDKs)
    names = set()
    try:
        import anyio
        for getter in ("get_tools", "list_tools"):
            fn = getattr(H.mcp, getter, None)
            if fn is None:
                continue
            res = anyio.run(fn)
            names = set(res.keys()) if isinstance(res, dict) else {getattr(t, "name", t) for t in res}
            break
    except Exception as e:
        print("  (tool-registration check via API failed: %s)" % e)
    if names:
        passed &= _check("both tools registered", {"hounds_exposure_overview", "hounds_scent_board"} <= names,
                         "got " + ", ".join(sorted(names)))
    else:
        print("  (skip tool-registration check — no list API found)")

    print("\n" + ("ALL PASSED" if passed else "FAILURES ABOVE"))
    sys.exit(0 if passed else 1)


if __name__ == "__main__":
    main()
