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
from core import navi_cli, payload
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
    runid = _publish(res)
    first, _c = payload.drill("attackpath", {"run": runid, "section": "entries", "limit": 50}, SECTIONS)
    return {"ok": True, "agent": AGENT.meta(), "result": _slim(res),
            "drill": {"action": "drill", "run": runid, "section": "entries"}, "first": first}, 200


# ── payload contract (build 464) ──────────────────────────────────────────────────────────────
# The full analysis stays on the server (AGENT.result — what every tag key rebuilds from); the
# page gets the paths, map, metrics and the fix / control tables WITHOUT their asset-uuid lists,
# and the ways-in table pages from the result store (10k+ entry points was 4.5 MB, the control
# and fix uuid lists 5 MB more at 150k assets).
SECTIONS = {"entries": {"sorts": {}, "flags": {"reach"}}}
UNREACHED_SHOWN = 40
C2_TARGETS = 256


def _publish(res):
    W = payload.STORE.begin("attackpath")
    W.section("entries")
    try:
        for e in res.get("entries") or []:
            W.add("entries", e, uid=e.get("uuid"), rk=e.get("uuid"), flags=["reach"] if e.get("reaches_any") else [],
                  text=" ".join(str(e.get(k) or "") for k in ("host", "ip", "os", "subnet")) + " "
                  + " ".join(str(h) for h in (e.get("how") or [])) + " " + " ".join(str(h) for h in (e.get("crown_hosts") or [])))
    except BaseException:
        W.close(ok=False)
        raise
    W.close()
    return W.run


def _slim(res):
    """The page payload: everything but per-asset lists (counts + the C2 hand-off targets kept)."""
    nodes = {n.get("id"): n for n in ((res.get("graph") or {}).get("nodes") or []) if n.get("kind") == "asset" and n.get("ip")}

    def fix(x):
        out = {k: v for k, v in x.items() if k != "uuids"}
        out["c2_targets"] = [{"ip": nodes[u]["ip"], "uuid": u, "hostname": nodes[u].get("label") or ""}
                             for u in (x.get("uuids") or []) if u in nodes][:C2_TARGETS]
        return out
    small = {k: v for k, v in res.items() if k not in ("entries", "reachable", "unreached", "fixes", "bundle", "controls")}
    ent = res.get("entries") or []
    small["entries_n"] = len(ent)
    small["entries_reach_n"] = sum(1 for e in ent if e.get("reaches_any"))
    reach = res.get("reachable") or [x["target"]["uuid"] for x in res.get("paths", []) if x.get("target")]
    small["reachable_n"] = len(set(reach))
    un = res.get("unreached") or []
    small["unreached"] = un[:UNREACHED_SHOWN]
    small["unreached_n"] = len(un)
    small["fixes"] = [fix(x) for x in res.get("fixes") or []]
    small["bundle"] = [fix(x) for x in res.get("bundle") or []]
    small["controls"] = [{k: v for k, v in x.items() if k != "uuids"} for x in res.get("controls") or []]
    return small


def drill(p):
    return payload.drill("attackpath", p, SECTIONS)


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


ACTIONS = {"run": run, "drill": drill, "tag_entry": tag_entry, "tag_target": tag_target, "tag": tag}
