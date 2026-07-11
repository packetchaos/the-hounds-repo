"""Argos — the asset deep-dive agent.

Odysseus's faithful hound, the only one who knew his master's true identity after
twenty years. Give Argos a single asset (UUID *or* IP) and it recognizes it across
every table in navi.db — assembling one dossier: risk band, the pack's tags
*deciphered* (what each means + which Hound raised it), a severity breakdown, top
CVEs, software and certificates. Read-only; the live `navi explore uuid` views are
an optional CLI passthrough.
"""
from core.agents.base import Agent


class ArgosAgent(Agent):
    id = "argos"
    name = "Asset Deep-Dive"
    icon = "🔦"
    description = ("Argos — recognizes one asset by UUID or IP and tells its whole "
                   "story: risk, the pack's tags deciphered, CVEs, software and certs.")

    def summary(self):
        if not self.result:
            return {}
        return {"hint": self.result.get("hint", "")}

    def _run(self, db_path=None, **kwargs):
        # The hub's generic "Execute" has no target; the real work is the `lookup`
        # action (api.py), driven from the page with a UUID or IP.
        return {"hint": "Enter an asset UUID or IP on the Argos page to build its dossier.",
                "ready": True}
