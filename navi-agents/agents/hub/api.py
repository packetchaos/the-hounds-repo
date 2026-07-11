"""Hub orchestration — powers the "Release the Hounds" page.

Two cross-agent actions, both built on the Covenant contract engine
(core.contract), so there is ONE place that knows how to run every agent and
apply its tags:

  run_all — run discovery for every tagging agent (plan only; NO writes).
  trust   — "I trust you": run every tagging agent AND apply the proposed tags
            live (gated). ACR is never run; Ownership Assignment (exproute) and
            Software need human input, so they are skipped — matching the
            artifact's autopilot exactly.
"""
from core import contract, navi_cli

# Agents the pack autopilot will NOT run automatically (need human input).
# ACR is not in contract.TAGGERS at all, so it is never auto-run either.
SKIP = {"exproute"}


def _pack_contract():
    """A one-shot contract: all taggers enabled EXCEPT the human-input ones,
    no ACR rules, no inter-agent wait."""
    c = contract.default_contract()
    for aid in SKIP:
        if aid in c.get("agents", {}):
            c["agents"][aid]["enabled"] = False
    c["acr"] = []
    c["wait_minutes"] = 0
    return c


def roster(p):
    """Which agents the pack orchestration will run, for the UI to badge cards."""
    tg = [a for a in contract.TAGGERS if a not in SKIP]
    return {"ok": True, "taggers": tg, "skipped": sorted(SKIP),
            "writes_enabled": navi_cli.writes_enabled()}, 200


def run_all(p):
    """Run all ready — discovery for every tagging agent (plan only, no writes)."""
    pl = contract.plan(_pack_contract())
    total = sum(b.get("selected", 0) for b in pl.get("agents", []))
    return {"ok": True, "plan": pl, "total_selected": total,
            "writes_enabled": navi_cli.writes_enabled()}, 200


def trust(p):
    """I trust you — run every tagging agent and APPLY the proposed tags (gated)."""
    if not p.get("confirm"):
        return {"ok": False, "error": "confirm=true required — this applies tags live"}, 400
    c = _pack_contract()
    c["armed"] = True                        # execute() only writes when armed
    out = contract.execute(c)
    return {"ok": True, "queued_tags": out.get("queued_tags", 0),
            "plan": out.get("plan", {}), "skipped": sorted(SKIP),
            "writes_enabled": navi_cli.writes_enabled()}, 200


ACTIONS = {"roster": roster, "run_all": run_all, "trust": trust}
