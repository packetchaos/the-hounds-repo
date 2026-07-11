"""Fenrir / Attack Path Analysis — self-contained HTTP actions.

  run         — correlate signals and return entries, crown-jewel targets, and
                the reachable paths between them (read-only).
  tag_entry   — tag every exploitable / weak-auth entry point Attack Path:Entry Point
  tag_target  — tag every reachable crown-jewel target       Attack Path:Target
Both writes are gated (confirm + NAVI_ALLOW_WRITES).
"""
from core import navi_cli
from .agent import AttackPathAgent, ENTRY_CAT

AGENT = AttackPathAgent()


def run(p):
    return {"ok": True, "agent": AGENT.meta(), "result": AGENT.run()}, 200


def _tag(uuids, value, p):
    if not p.get("confirm"):
        return {"ok": False, "error": "confirm=true required to write tags"}, 400
    uu = [u for u in uuids if u]
    if not uu:
        return {"ok": False, "error": "nothing to tag — map attack paths first"}, 400
    inlist = ",".join("'" + str(u).replace("'", "''") + "'" for u in uu)
    q = "SELECT uuid AS asset_uuid FROM assets WHERE uuid IN (" + inlist + ")"
    r = navi_cli.tag(ENTRY_CAT, value, query=q, remove=False, agent="attackpath")
    return {"ok": True, "value": value, "count": len(uu), "result": r,
            "writes_enabled": navi_cli.writes_enabled()}, 200


def tag_entry(p):
    res = AGENT.result or AGENT.run()
    return _tag([e["uuid"] for e in res.get("entries", [])], "Entry Point", p)


def tag_target(p):
    res = AGENT.result or AGENT.run()
    seen, order = set(), []
    for pa in res.get("paths", []):
        u = pa["target"]["uuid"]
        if u not in seen:
            seen.add(u)
            order.append(u)
    return _tag(order, "Target", p)


def tag(p):
    """Tag an explicit list of asset UUIDs under Attack Path:<value> (per-row use)."""
    return _tag(p.get("uuids", []), p.get("value", "Target"), p)


ACTIONS = {"run": run, "tag_entry": tag_entry, "tag_target": tag_target, "tag": tag}
