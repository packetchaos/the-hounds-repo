"""MCP compare — Tenable MCP vs navi MCP (reference + navi-side snapshot).

The capability matrix and handoff notes are static reference content rendered in
the page. This backend provides a navi-side snapshot (tag categories, asset count,
and navi's own identity) so the operator can sanity-check what navi is pointed at.
The full cross-tool "same account" check lives in the desktop console, which has
the Tenable MCP available; a standalone repo only has navi.
"""
from core import db, navi_cli
from core.agents.base import Agent


def snapshot(db_path=None) -> dict:
    cats = []
    try:
        cats = [r["tag_key"] for r in db.query(
            "SELECT DISTINCT tag_key FROM tags ORDER BY tag_key;", path=db_path)
            if r.get("tag_key")]
    except Exception:
        cats = []
    assets = None
    try:
        assets = db.scalar("SELECT COUNT(*) FROM assets;", path=db_path)
    except Exception:
        assets = None
    db_fresh = None
    try:
        db_fresh = db.scalar("SELECT MAX(last_found) FROM vulns;", path=db_path)
    except Exception:
        db_fresh = None
    identity = ""
    try:
        r = navi_cli.explore_info("auth")
        identity = "\n".join(
            l.strip() for l in (r.get("stdout", "") or "").splitlines()
            if l.strip() and "Level up" not in l and set(l.strip()) != {"-"}
        )[:400]
    except Exception:
        identity = ""
    return {"navi_categories": cats, "navi_category_count": len(cats),
            "asset_total": assets, "navi_identity": identity, "db_fresh": db_fresh,
            "navi_available": navi_cli.navi_available()}


class McpCompareAgent(Agent):
    id = "mcpcmp"
    name = "MCP Compare"
    icon = "⚖"
    description = ("Tenable MCP vs navi MCP — capability/routing matrix, limits & "
                  "handoffs, and a navi-side snapshot to sanity-check the connection.")

    def summary(self):
        if not self.result:
            return {}
        return {"navi_categories": self.result.get("navi_category_count"),
                "assets": self.result.get("asset_total")}

    def _run(self, db_path=None, **kwargs):
        return snapshot(db_path)
