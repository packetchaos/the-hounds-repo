"""Identity Inventory agent.

Identity discovery (NHI + human + service accounts) that can TAG the
hosting assets like the other agents — per identity, by class, or from a plain-English
instruction. Read-only discovery; tag writes are gated.
"""
from core import identity
from core.agents.base import Agent


class IdentityAgent(Agent):
    id = "identity"
    name = "Identity Inventory"
    icon = "🆔"
    description = ("Finds NHI and human identities from local-user enumeration plugins "
                  "and tags the hosting assets via navi tag-by-query.")

    def summary(self):
        if not self.result:
            return {}
        c = self.result.get("counts", {})
        return {"identities": c.get("total"), "human": c.get("human"),
                "service_nhi": (c.get("nhi", 0) + c.get("service", 0)),
                "machine": c.get("machine"), "flagged": c.get("flagged"),
                "blind_hosts": self.result.get("blind")}

    def _run(self, db_path=None):
        return identity.scan(db_path)
