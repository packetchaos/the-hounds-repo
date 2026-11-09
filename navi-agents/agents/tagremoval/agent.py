"""Garmr — the tag-removal agent.

Lists the tags navi can actually remove — the ones in navi.db's `tags` table, with
the number of navi.db assets carrying each. `navi enrich tag ... -remove` strips a tag
from the assets navi.db says carry it, so a tag that exists only in Tenable (on assets
outside navi's pull window, or no longer licensed) can't be removed from here; those
are shown separately by the Tenable ⇄ navi.db compare, never offered for selection.
The api removes the chosen tags through the same background queue every other agent
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
        """navi.db's tags table only (build 452) — the live Tenable list is the compare's job."""
        if db is None:
            return {"ok": False, "tags": [], "count": 0, "source": "navi.db tags table",
                    "message": "navi.db is not available"}
        try:
            rows = db.query("SELECT tag_key AS k, tag_value AS v, COUNT(DISTINCT asset_uuid) AS n "
                            "FROM tags WHERE TRIM(COALESCE(tag_key,''))<>'' "
                            "GROUP BY tag_key, tag_value", path=db_path)
        except Exception as e:
            msg = str(e)
            return {"ok": False, "tags": [], "count": 0, "source": "navi.db tags table",
                    "message": ("navi.db has no tags table — run an assets sync (navi config update assets)"
                                if "no such table" in msg else msg)}
        tags = [{"category": r.get("k"), "value": r.get("v"), "assets": r.get("n") or 0} for r in rows]
        tags.sort(key=lambda x: ((x["category"] or "").lower(), (x["value"] or "").lower()))
        return {"ok": True, "source": "navi.db tags table", "tags": tags, "count": len(tags),
                "message": "" if tags else "navi.db's tags table is empty — run an assets sync"}
