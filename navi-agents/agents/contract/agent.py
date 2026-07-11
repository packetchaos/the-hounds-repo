"""AI Navi Contract agent (Covenant Hound).

Orchestrates every tagging agent under one autonomous workflow. The contract
captures the human's policy (per-agent logic, ACR rules, wait periods, schedule)
so the loop decides what to tag instead of the per-row HITL gate.
"""
from core import contract
from core.agents.base import Agent


class ContractAgent(Agent):
    id = "contract"
    name = "AI Navi Contract"
    icon = "📜"
    description = ("Turns the captured tag log + your policy into an autonomous, "
                   "scheduled workflow — plans first, executes when armed.")

    def summary(self):
        st = contract.scheduler_status()
        c = contract.current()
        enabled = sum(1 for a in c.get("agents", {}).values() if a.get("enabled"))
        return {"armed": c.get("armed", False), "agents": enabled,
                "every_h": c.get("schedule_hours", 4), "loop": st.get("running", False)}

    def _run(self, db_path=None, **kwargs):
        # "running" the contract = compute a plan (safe, no writes)
        return contract.plan(db_path=db_path)
