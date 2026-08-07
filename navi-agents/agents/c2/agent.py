"""Command & Control — Amarok Hound.

The pack's remediation executor. Amarok drives ``navi action push`` — the single
highest-risk capability in navi: remote code execution over SSH to ONE Linux host —
to run a command, ship a file, or apply a patch derived from the vulns table.

Everything is TRIPLE-gated (writes + NAVI_REMOTE_CODE_EXECUTION + per-host confirm),
Linux-only, canary-first, stop-on-failure, and written to the Tagging ledger
(op=push). Planning / host discovery / precheck are read-only; only command/
push_file/campaign execute, and only when armed + confirmed. See core/navi_cli.py
for the gated push path (rce_enabled / scan_command / push).
"""
from core.agents.base import Agent


class C2Agent(Agent):
    id = "c2"
    name = "Command & Control"
    icon = "🐺"
    description = ("Amarok — the pack's remediation executor. Runs a command, ships a file, or "
                   "applies a vuln-derived patch to a Linux host via navi action push. Triple-gated "
                   "remote code execution, Linux-only, canary-first armed campaigns, full ledger.")

    def summary(self):
        if not self.result:
            return {}
        return {"linux_hosts": self.result.get("linux_hosts"),
                "rce_enabled": self.result.get("rce_enabled", False)}

    def _run(self, db_path=None, **kwargs):
        from core import navi_cli
        n = None
        try:
            from . import api
            n = len(api._linux_hosts(db_path))
        except Exception:
            n = None
        return {"ready": True, "linux_hosts": n,
                "rce_enabled": navi_cli.rce_enabled(),
                "hint": "Pick a Linux host, precheck, then arm & run. Remote execution needs "
                        "NAVI_ALLOW_WRITES=1 + NAVI_REMOTE_CODE_EXECUTION=1 + confirm."}
