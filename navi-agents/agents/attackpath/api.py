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
    # attack-graph roles are computed in Python → ≤1,999-UUID batches (add-only)
    sm = navi_cli.jobs_summary(navi_cli.tag_uuids_batched(ENTRY_CAT, value, uu, agent="attackpath"))
    r = sm["result"]
    return {"ok": r.get("ok", True) is not False, "value": value, "count": len(uu), "result": r,
            "jobs": sm["jobs"], "job_ids": sm["job_ids"],
            "error": r.get("message") if r.get("ok") is False else None,
            "writes_enabled": navi_cli.writes_enabled()}, 200


def _res():
    return AGENT.result or AGENT.run()


def tag_entry(p):
    return _tag([e["uuid"] for e in _res().get("entries", []) if e.get("reaches_any")], "Entry Point", p)


def tag_target(p):
    r = _res()
    return _tag(r.get("reachable") or [x["target"]["uuid"] for x in r.get("paths", [])], "Target", p)


_UUID_RE = __import__("re").compile(r"^[0-9a-f-]{20,}$", __import__("re").I)


def _key_set(key):
    """(value, uuids) for a page key, rebuilt from the server's own last analysis — the page
    never posts a UUID list. entry | target | pivot | fix:<fix>."""
    r = _res()
    if key == "entry":
        return "Entry Point", [e["uuid"] for e in r.get("entries", []) if e.get("reaches_any")]
    if key == "target":
        return "Target", r.get("reachable") or [x["target"]["uuid"] for x in r.get("paths", []) if x.get("target")]
    if key == "pivot":                       # = the page's pivot rule (intermediate hosts on a path)
        piv = set()
        for pth in r.get("paths", []):
            tu, eu = (pth.get("target") or {}).get("uuid"), (pth.get("entry") or {}).get("uuid")
            for st in (pth.get("steps") or [])[:-1]:
                u = str(st.get("to") or "").split(":")[0]
                if _UUID_RE.match(u) and u not in (tu, eu):
                    piv.add(u)
        return "Pivot", sorted(piv)
    if key.startswith("fix:"):
        f = next((x for x in r.get("fixes", []) if x.get("fix") == key[4:]), None)
        return "Choke Point", (f or {}).get("uuids") or []
    return None, []


def tag(p):
    """Gated: {key} (entry | target | pivot | fix:<fix>) — the set is rebuilt server-side.
    A bare {value, uuids} list from a client is no longer accepted."""
    value, uu = _key_set(str(p.get("key") or ""))
    if value is None:
        return {"ok": False, "error": "key must be entry, target, pivot or fix:<fix>"}, 400
    return _tag(uu, value, p)


ACTIONS = {"run": run, "tag_entry": tag_entry, "tag_target": tag_target, "tag": tag}
