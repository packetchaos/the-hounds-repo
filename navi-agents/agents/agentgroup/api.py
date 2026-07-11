"""Sirius / Agent Group tagging — self-contained HTTP actions.

`run`     — list Tenable agent groups (live, navi explore info agent-groups).
`tag`     — gated; tag a supplied list of group names (the NL-list & widget paths
            both resolve to a list of names). One navi --group write per group.
`tag_all` — gated; tag EVERY agent group (the classic script behaviour).
"""
from core import navi_cli
from .agent import AgentGroupAgent, groups, tag_group

AGENT = AgentGroupAgent()


def run(p):
    return {"ok": True, "agent": AGENT.meta(), "result": AGENT.run()}, 200


def _tag_names(names):
    results = []
    for n in names:
        n = (n or "").strip()
        if not n:
            continue
        results.append({"group": n, **tag_group(n)})
    return results


def tag(p):
    if not p.get("confirm"):
        return {"ok": False, "error": "confirm=true required to write tags"}, 400
    names = p.get("groups") or []
    if not names:
        return {"ok": False, "error": "no agent groups supplied"}, 400
    results = _tag_names(names)
    return {"ok": True, "queued": len(results), "results": results,
            "writes_enabled": navi_cli.writes_enabled()}, 200


def tag_all(p):
    if not p.get("confirm"):
        return {"ok": False, "error": "confirm=true required to write tags"}, 400
    names = [g["name"] for g in groups()]
    if not names:
        return {"ok": False, "error": "no agent groups found (is navi on PATH?)"}, 400
    results = _tag_names(names)
    return {"ok": True, "queued": len(results), "total_groups": len(names), "results": results,
            "writes_enabled": navi_cli.writes_enabled()}, 200


ACTIONS = {"run": run, "tag": tag, "tag_all": tag_all}
