"""Fenrir / Attack Path Analysis — self-contained HTTP actions.

  run         — build the attack graph from navi.db (vulns, compliance, identities) and return
                ranked paths to the crown jewels, entry points, choke-point fixes, the
                remediation bundle, the map, and metrics (read-only). {crown_acr?}
  tag         — gated; tag an explicit asset list Attack Path : <value>
                (Entry Point | Target | Pivot | Choke Point)
  tag_entry   — gated; tag every entry point that reaches a crown jewel   Attack Path : Entry Point
  tag_target  — gated; tag every reachable crown jewel                    Attack Path : Target
Writes are gated (confirm + NAVI_ALLOW_WRITES) and recorded in the Tagging log.
"""
from core import navi_cli
from .agent import AttackPathAgent, ENTRY_CAT
from core.gates import confirmed

AGENT = AttackPathAgent()
VALUES = {"Entry Point", "Target", "Pivot", "Choke Point"}


def run(p):
    try:
        acr = float(p.get("crown_acr") or 7)
    except (TypeError, ValueError):
        acr = 7.0
    acr = min(10.0, max(1.0, acr))
    res = AGENT.run(crown_acr=acr)
    return {"ok": True, "agent": AGENT.meta(), "result": res}, 200


def _tag(uuids, value, p):
    if not confirmed(p):
        return {"ok": False, "error": "confirm=true required to write tags"}, 400
    if value not in VALUES:
        return {"ok": False, "error": f"value must be one of {sorted(VALUES)}"}, 400
    uu = sorted({u for u in uuids if u})
    if not uu:
        return {"ok": False, "error": "nothing to tag — run the analysis first"}, 400
    inlist = ",".join("'" + str(u).replace("'", "''") + "'" for u in uu)
    q = "SELECT uuid AS asset_uuid FROM assets WHERE uuid IN (" + inlist + ")"
    r = navi_cli.tag(ENTRY_CAT, value, query=q, remove=False, agent="attackpath")
    return {"ok": r.get("ok", True) is not False, "value": value, "count": len(uu), "result": r,
            "error": r.get("message") if r.get("ok") is False else None,
            "writes_enabled": navi_cli.writes_enabled()}, 200


def _res():
    return AGENT.result or AGENT.run()


def tag_entry(p):
    return _tag([e["uuid"] for e in _res().get("entries", []) if e.get("reaches_any")], "Entry Point", p)


def tag_target(p):
    r = _res()
    return _tag(r.get("reachable") or [x["target"]["uuid"] for x in r.get("paths", [])], "Target", p)


def tag(p):
    return _tag(p.get("uuids", []), p.get("value", "Target"), p)


ACTIONS = {"run": run, "tag_entry": tag_entry, "tag_target": tag_target, "tag": tag}
