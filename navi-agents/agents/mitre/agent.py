"""MITRE ATT&CK Tagging agent.

Thin orchestrator over the navi-enrich skill recipe: it fetches the live
ATT&CK->CVE mapping (core.mitre) and produces the asset-tagging plan (CVE = selector). The actual
writes use navi's own tag-by-CVE function via core.navi_cli — nothing is baked in.
"""
from core import mitre
from core.agents.base import Agent


class MitreAgent(Agent):
    id = "mitre"
    name = "MITRE ATT&CK Tagging"
    icon = "🎯"
    description = ("Fetches the live ATT&CK->CVE mapping and tags the assets whose "
                  "findings cite each mapped CVE with its Primary/Secondary Impact + "
                  "Exploit Technique, using navi's tag-by-CVE selector.")

    def summary(self):
        if not self.result:
            return {}
        return {"matched_cves": self.result.get("matched_cves"),
                "tag_actions": len(self.result.get("actions", []))}

    def _run(self, db_path=None, scope="navidb"):
        return mitre.build_plan(db_path, scope=scope)
