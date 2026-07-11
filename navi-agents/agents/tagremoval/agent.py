"""Garmr — the tag-removal agent.

Lists every tag in the tenant (live `navi explore info tags`, enriched with the
per-tag asset counts from navi.db) so the operator can pick which to strip. The
api removes the chosen tags through the same background queue every other agent
uses, so removals appear in the Tagging log as `op=remove`.
"""
from core import navi_cli
from core.agents.base import Agent

try:
    from core import db
except Exception:                                    # pragma: no cover
    db = None


class TagRemovalAgent(Agent):
    id = "tagremoval"
    name = "Tag Removal"
    icon = "🗑️"
    description = ("Garmr — lists every tag in the tenant and removes the ones you "
                  "pick (visible in the Tagging log). Choices can feed the AI "
                  "Contract, which removes them first, pauses, runs navi update, "
                  "then re-runs the tagging workflow.")

    def summary(self):
        if not self.result:
            return {}
        return {"tags": len(self.result.get("tags", []))}

    def _run(self, db_path=None, **kwargs):
        live = navi_cli.list_tags()
        tags = live.get("tags", []) or []
        counts = {}
        if db is not None:
            try:
                for r in db.query("SELECT tag_key AS k, tag_value AS v, "
                                  "COUNT(DISTINCT asset_uuid) AS n FROM tags "
                                  "GROUP BY tag_key, tag_value", path=db_path):
                    counts[(r.get("k"), r.get("v"))] = r.get("n")
            except Exception:
                counts = {}
        merged, have = [], set()
        for t in tags:
            cat, val = t.get("category"), t.get("value")
            merged.append({"category": cat, "value": val, "assets": counts.get((cat, val))})
            have.add((cat, val))
        # surface navi.db tags not in the live list (e.g. not yet synced upstream)
        for (k, v), n in counts.items():
            if (k, v) not in have:
                merged.append({"category": k, "value": v, "assets": n})
        merged.sort(key=lambda x: ((x["category"] or "").lower(), (x["value"] or "").lower()))
        return {"ok": live.get("ok", True),
                "source": live.get("source", "navi explore info tags"),
                "tags": merged, "count": len(merged),
                "message": live.get("message", "")}
