"""Asset Ownership — Terminus Hound.

The asset-side complement to Atlas (Exposure Routes). Atlas maps ROUTES/PATHS to
owners; Terminus rolls that up to the ASSET and adds two layers on top:
a business-leader layer (``Business Owner``) and a single complete-owner layer
(``Asset Owner`` — one owner for an asset's every route & path, or the remainder).
See core/asset_ownership.py for the engine.
"""
from core import asset_ownership as engine
from core.agents.base import Agent


class AssetOwnershipAgent(Agent):
    id = "asset_ownership"
    name = "Asset Ownership"
    icon = "📌"
    description = ("Ownership from the asset's point of view — business leaders, technology "
                   "owners, and single complete asset owners; crown jewels, blind spots, and "
                   "plain-English owner assignment that reads each asset's tags. Gated writes.")

    def summary(self):
        if not self.result:
            return {}
        k = (self.result or {}).get("kpi", {})
        return {"assets": k.get("assets"), "unclaimed": k.get("unclaimed"),
                "crown": k.get("crown"), "crown_unclaimed": k.get("crown_unclaimed")}

    def _run(self, db_path=None, **kwargs):
        return engine.overview(db_path)
