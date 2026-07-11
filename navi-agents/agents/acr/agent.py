"""ACR Calibration Agent.

Lists tags from the **live `navi explore info tags`** command (not the local
tags table), so the operator can adjust the Asset Criticality Rating for the
assets carrying any tag — set to an absolute value, or nudge it up/down by a
delta (so an asset at 3 dec-1 becomes 2; an asset at 9 dec-1 becomes 8) — with
a required business justification.

The agent's run() just fetches the tag list. The ACR write itself is a gated
human-in-the-loop action handled by the service layer (navi_cli.acr).
"""
from core import navi_cli
from core.agents.base import Agent


class ACRCalibrationAgent(Agent):
    id = "acr"
    name = "ACR Calibration Agent"
    icon = "🎯"
    description = ("Adjusts Asset Criticality Rating per tag (set / +N / −N) with a "
                   "business justification, so Tenable One's AES reflects reality.")

    def summary(self) -> dict:
        if not self.result:
            return {}
        return {"tags": len(self.result.get("tags", [])),
                "source": self.result.get("source", "")}

    def _run(self, db_path=None, **kwargs) -> dict:
        res = navi_cli.list_tags()
        # group by category for the UI
        cats = {}
        for t in res.get("tags", []):
            cats.setdefault(t["category"], []).append(t)
        return {"ok": res.get("ok", False),
                "source": res.get("source", "navi explore info tags"),
                "message": res.get("message"),
                "tags": res.get("tags", []),
                "by_category": cats,
                "reasons": ["business", "compliance", "mitigation", "development"],
                "tier_hint": {"Prod+PII": 10, "Internet-facing": 9, "Production": 8,
                              "Staging": 6, "Dev/Test": 3, "Isolated": 2}}
