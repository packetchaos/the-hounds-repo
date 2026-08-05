"""Draco — the Custom Audit authoring agent.

Named for the lawgiver who set down the first written code: Draco turns a policy
requirement into a written, enforceable Tenable Nessus .audit file you can drop
into a compliance scan. Two producers — a natural-language box (Claude drafts the
checks) and a guided builder over the platform catalog — both render through
core.custom_audit and are syntax-validated before download. Read-only; no navi
writes. Scope v1: Windows (config) and Unix/Linux/macOS.
"""
from core import custom_audit as _ca
from core.agents.base import Agent


class DracoAgent(Agent):
    id = "custom_audit"
    name = "Custom Audit"
    icon = "📜"
    description = ("Draco — author a custom .audit file from plain English or a guided builder; "
                   "live preview, syntax validation, and auto-mapped framework references; "
                   "download a scan-ready .audit or a single check.")

    def summary(self):
        r = self.result or {}
        plats = r.get("platforms") or []
        return {"platforms": len(plats),
                "check_types": sum(len(p.get("types") or []) for p in plats)}

    def _run(self, db_path=None, **kwargs):
        return _ca.platforms()
