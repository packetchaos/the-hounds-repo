"""The Hounds MCP server — the shim that lets thin, persona-focused artifacts feed
off the SAME engines the repo already runs.

Design contract (why this exists and how it stays honest):
  • This file adds NOTHING to the core. Every tool is a 3-line wrapper that calls the
    exact `core/*.py` function the HTTP API already calls, and returns its payload
    verbatim. There is ZERO logic here — so an artifact rendering these tools can never
    drift from the repo. Change an engine once, every surface updates.
  • All tools are READ-ONLY. Writes (tag / ACR / push) stay behind the navi MCP's own
    gates and are NOT exposed here. This server cannot mutate navi.db.
  • Data source is env-driven: point NAVI_DB_PATH at a real navi.db (or the bundled
    sample). No db path is accepted as a tool argument.

Run (local / stdio):
    pip install -r requirements-mcp.txt
    NAVI_DB_PATH=/path/to/navi.db python hounds_mcp.py

This is PoC slice 1 (the Executive persona): two tools — the fused exposure score
(Nemesis) and the estate brain (Sphinx). More tools/personas layer on top additively.
"""
import os
import sys
from typing import Any, Dict, Optional

# make `from core import ...` work no matter where the process is launched from
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core import security                       # noqa: E402
security.harden_process()                        # umask 077: anything we create is owner-only

from core import fused_score, insights          # noqa: E402  (the engines — untouched)

FastMCP = None
for _imp in ("fastmcp", "mcp.server.fastmcp"):   # standalone fastmcp, or the official SDK
    try:
        FastMCP = __import__(_imp, fromlist=["FastMCP"]).FastMCP
        break
    except Exception:
        continue
if FastMCP is None:                              # pragma: no cover
    sys.stderr.write("The Hounds MCP needs FastMCP — run `pip install -r requirements-mcp.txt`\n")
    raise SystemExit(1)

mcp = FastMCP("hounds")

# startup sanity — the #1 "why is everything empty" cause is a missing/wrong DB path
_db = os.environ.get("NAVI_DB_PATH")
if not _db:
    sys.stderr.write("[hounds-mcp] NAVI_DB_PATH is not set — tools will report 'no assets table'. "
                     "Set it in your MCP config's env block.\n")
elif not os.path.exists(_db):
    sys.stderr.write("[hounds-mcp] NAVI_DB_PATH=%s does not exist.\n" % _db)

# read-only annotation, attached best-effort (the class lives in different places
# across SDKs; if we can't find it, the tools still register, just without the hint)
_RO = {}
for _imp in ("fastmcp.tools.tool", "mcp.types"):
    try:
        _RO = {"annotations": __import__(_imp, fromlist=["ToolAnnotations"]).ToolAnnotations(
            readOnlyHint=True, openWorldHint=False)}
        break
    except Exception:
        continue


# --------------------------------------------------------------------------- #
#  Plain callables — the single source of truth for both the tool and the test #
# --------------------------------------------------------------------------- #
def _exposure_overview(limit: int = 500, offset: int = 0,
                       weights: Optional[Dict[str, float]] = None) -> Dict[str, Any]:
    return fused_score.overview(limit=limit, offset=offset, weights=weights)


def _scent_board() -> Dict[str, Any]:
    return insights.scent_board()


def _budgeted(fn, *a, **kw):
    """Run one tool call under the request budget the HTTP API gives a ▶ Run (core/db
    budget_scope "run": NAVI_RUN_BUDGET_S, 2 h; HOUNDS_MCP_BUDGET=open|run|job|<seconds>
    overrides) — so an MCP client never waits on an unbounded scan of a huge navi.db. A stopped
    query answers {ok:false, budget:true, message} (db.budget_payload), not an exception."""
    from core import db
    b = (os.environ.get("HOUNDS_MCP_BUDGET") or "run").strip()
    try:
        b = float(b)
    except ValueError:
        pass
    try:
        with db.budget_scope(b):
            return fn(*a, **kw)
    except (db.QueryTimeout, db.TooManyRows) as e:
        return db.budget_payload(e)


# --------------------------------------------------------------------------- #
#  Tools (Executive persona)                                                    #
# --------------------------------------------------------------------------- #
@mcp.tool(**_RO)
def hounds_exposure_overview(limit: int = 500, offset: int = 0,
                             weights: Optional[Dict[str, float]] = None) -> Dict[str, Any]:
    """Nemesis — the fused exposure score rolled up across the whole estate.

    Returns per-asset fused scores (worst-N), estate KPIs, the 16 factor weights, the
    per-factor estate totals, worst-from-each-Hound, and cross-Hound convergence. Pass
    an optional `weights` map (factor id -> relative weight) to re-rank to a priority;
    it re-normalises to 100 so the score stays 0–100. Read-only.
    """
    try:
        return _budgeted(_exposure_overview, limit=limit, offset=offset, weights=weights)
    except Exception as e:                       # pragma: no cover
        return {"ok": False, "error": "exposure_overview failed: %s" % e}


@mcp.tool(**_RO)
def hounds_scent_board() -> Dict[str, Any]:
    """Sphinx — the estate brain ('On the Scent'). One read that returns everything the
    Executive view needs: the exposure distribution bands, risk attributed to each Hound,
    the pack-detection radar, the coverage funnel, the CVE→Plugin→App→Path reduction with
    its champion fix, the per-domain posture tiles, blind spots, and cross-Hound
    surprises. Read-only.
    """
    try:
        return _budgeted(_scent_board)
    except Exception as e:                       # pragma: no cover
        return {"ok": False, "error": "scent_board failed: %s" % e}


if __name__ == "__main__":
    # stdio (default) works in Claude Desktop + Claude Code. For Cowork / web / mobile,
    # the persona artifacts need a REMOTE connector — run over HTTP and add it as a custom
    # connector:  HOUNDS_MCP_HTTP=1 NAVI_DB_PATH=... python hounds_mcp.py
    if os.environ.get("HOUNDS_MCP_HTTP"):
        host = os.environ.get("HOUNDS_MCP_HOST", "127.0.0.1")
        port = int(os.environ.get("HOUNDS_MCP_PORT", "8790"))
        if not security.is_loopback_bind(host):
            if (os.environ.get("HOUNDS_MCP_ALLOW_REMOTE") or "").strip() != "1":
                sys.stderr.write("[hounds-mcp] REFUSING to listen on %s: the HTTP transport has no "
                                 "authentication, so anyone who can reach the port can read your "
                                 "estate's exposure data. Use 127.0.0.1 (+ an SSH tunnel / an "
                                 "authenticating reverse proxy), or set HOUNDS_MCP_ALLOW_REMOTE=1 "
                                 "to accept the risk.\n" % host)
                raise SystemExit(2)
            sys.stderr.write("!" * 72 + "\n[hounds-mcp] WARNING: HOUNDS_MCP_ALLOW_REMOTE=1 — the "
                             "UNAUTHENTICATED MCP endpoint on %s:%s is reachable from other hosts.\n"
                             % (host, port) + "!" * 72 + "\n")
        sys.stderr.write("[hounds-mcp] HTTP transport on http://%s:%s (remote-connector mode)\n" % (host, port))
        mcp.run(transport="http", host=host, port=port)
    else:
        mcp.run()
