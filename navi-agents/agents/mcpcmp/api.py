"""MCP compare agent — self-contained HTTP actions."""
from .agent import McpCompareAgent

AGENT = McpCompareAgent()


def run(p):
    return {"ok": True, "agent": AGENT.meta(), "result": AGENT.run()}, 200


ACTIONS = {"run": run, "snapshot": run}
