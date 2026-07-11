"""Garmr / Tag Removal — self-contained HTTP actions.

`run`             — list every tag (live `navi explore info tags` + navi.db asset counts).
`remove`          — gated; queue a `-remove` for each chosen tag (shows in the Tagging
                    log as op=remove). Each removal strips the category:value from the
                    assets that currently carry it in navi.db.
`add_to_contract` — merge the chosen tags into the AI Contract's removal phase (the
                    contract removes them first, pauses, runs navi update, then re-tags).
"""
from core import navi_cli

AGENT = None


def _agent():
    global AGENT
    if AGENT is None:
        from .agent import TagRemovalAgent
        AGENT = TagRemovalAgent()
    return AGENT


def run(p):
    return {"ok": True, "agent": _agent().meta(), "result": _agent().run()}, 200


def remove(p):
    if not p.get("confirm"):
        return {"ok": False, "error": "confirm=true required to remove tags"}, 400
    tags = p.get("tags") or []
    if not tags:
        return {"ok": False, "error": "no tags selected"}, 400
    results = []
    for t in tags:
        cat = (t.get("category") or "").strip()
        val = (t.get("value") or "").strip()
        if not cat or not val:
            continue
        # Strip the tag off every asset that carries it, keeping the tag itself (UUID
        # intact). No selector — just `navi enrich tag --c <cat> --v <val> -remove`.
        r = navi_cli.tag(cat, val, remove=True, op="remove", agent="tagremoval")
        results.append({"category": cat, "value": val, **r})
    return {"ok": True, "queued": len(results), "results": results,
            "writes_enabled": navi_cli.writes_enabled()}, 200


def add_to_contract(p):
    tags = p.get("tags") or []
    if not tags:
        return {"ok": False, "error": "no tags selected"}, 400
    from core import contract
    out = contract.add_removals([{"category": t.get("category"), "value": t.get("value")}
                                 for t in tags])
    return {"ok": True, **out}, 200


ACTIONS = {"run": run, "remove": remove, "add_to_contract": add_to_contract}
