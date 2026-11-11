"""Identity Inventory — self-contained HTTP actions.

`run`       — discover NHI/human/service identities (read-only) + asset_uuids + URLs.
`tag`       — gated; tag the hosting assets via navi tag-by-query. Accepts either a
              single {category,value,asset_uuids} or a list of such under `items`.
`interpret` — natural-language tagging: turn an instruction + the discovered
              identities into per-identity {category,value} assignments (LLM).
"""
import re

from core import identity, navi_cli
from core.gates import confirmed

try:
    from core import llm
except Exception:
    llm = None

AGENT = None


def _agent():
    global AGENT
    if AGENT is None:
        from .agent import IdentityAgent
        AGENT = IdentityAgent()
    return AGENT


CROWN_ACR = 7
RISK = ("privileged", "non-expiring pw", "ssh password auth", "weak pw policy", "guest enabled",
        "default/blank cred", "AD attack path", "default secret", "write (private)")


def _enrich(res):
    """Page metrics: crown-jewel exposure (max ACR of the hosts behind each identity),
    credential coverage, and per-signal counts. Read-only; best-effort."""
    from core import db
    accts = res.get("accounts") or []
    uu = sorted({u for a in accts for u in (a.get("asset_uuids") or [])})
    acr = {}
    if uu:
        try:
            for part in navi_cli.uuid_batches(uu, size=900):    # bounded SQL per statement
                for r in db.query("SELECT uuid, acr FROM assets WHERE uuid IN (" + ",".join("?" * len(part)) + ")",
                                  tuple(part)):
                    try:
                        acr[r["uuid"]] = float(r.get("acr") or 0)
                    except (TypeError, ValueError):
                        pass
        except Exception:
            pass
    try:
        total = db.scalar("SELECT COUNT(*) FROM assets") or 0
    except Exception:
        total = 0
    for a in accts:
        vals = [acr.get(u, 0) for u in a.get("asset_uuids") or []]
        a["max_acr"] = max(vals) if vals else None
        a["crown_hosts"] = sum(1 for v in vals if v >= CROWN_ACR)
        a["reused"] = max([int(re.search(r"×(\d+)", f).group(1)) for f in a.get("flags", [])
                           if f.startswith("account reuse ×")] or [0])
        a["risky"] = [f for f in a.get("flags", []) if f != "scan credential"]
    has = lambda a, f: f in (a.get("flags") or [])
    people = [a for a in accts if a.get("klass") != "machine"]
    c = res.get("counts") or {}
    cred, blind = res.get("credentialed") or 0, res.get("blind") or 0
    res["metrics"] = {
        "estate": total,
        "identity_hosts": res.get("identity_hosts") or 0,
        "credentialed": cred, "blind": blind,
        "coverage_pct": round(100.0 * cred / (cred + blind), 1) if (cred + blind) else None,
        "privileged": sum(1 for a in accts if has(a, "privileged")),
        "privileged_hosts": len({u for a in accts if has(a, "privileged") for u in a["asset_uuids"]}),
        "nonexpiring": sum(1 for a in accts if has(a, "non-expiring pw")),
        "reused": c.get("reused", 0), "reused_hosts": c.get("reused_hosts", 0),
        "max_reuse": max([a["reused"] for a in accts] or [0]),
        "on_kev": sum(1 for a in people if has(a, "on KEV host")),
        "on_crit": sum(1 for a in people if has(a, "on critical host")),
        "crown_ids": sum(1 for a in people if a["crown_hosts"]),
        "crown_priv": sum(1 for a in people if a["crown_hosts"] and has(a, "privileged")),
        "priv_exploitable": sum(1 for a in people if has(a, "privileged")
                                and (has(a, "on KEV host") or has(a, "on critical host"))),
        "scan_creds": len(res.get("scan_creds") or []),
        "signals": {k: len(v) for k, v in (res.get("host_sets") or {}).items()},
    }
    return res


def run(p):
    try:
        res = identity.scan()
    except Exception as e:
        return {"ok": False, "error": f"identity scan failed: {e}"}, 200
    try:
        res = _enrich(res)
    except Exception as e:
        res["metrics_error"] = f"metrics failed: {e}"
    return {"ok": True, "agent": _agent().meta(),
            "result": res, "llm_available": bool(llm and llm.available())}, 200


def _tag_one(category, value, asset_uuids):
    """Identity → host mapping is computed in Python (accounts parsed from plugin output), so
    the set goes as ≤1,999-UUID batches (core.navi_cli.tag_uuids_batched, add-only)."""
    uu = [u for u in (asset_uuids or []) if u]
    if not uu:
        return {"ok": False, "message": "no asset_uuids for this identity"}
    jobs = navi_cli.tag_uuids_batched(category or "Identity", value, uu, agent="identity")
    sm = navi_cli.jobs_summary(jobs)
    return {**(sm["result"] or {}), "jobs": sm["jobs"], "job_ids": sm["job_ids"]}


def tag(p):
    if not confirmed(p):
        return {"ok": False, "error": "confirm=true required to write tags"}, 400
    items = p.get("items")
    if items:
        results = []
        for it in items:
            r = _tag_one(it.get("category", "Identity"), it.get("value", ""), it.get("asset_uuids"))
            results.append({"value": it.get("value"), "category": it.get("category", "Identity"), **r})
        ok = sum(1 for r in results if r.get("ok", r.get("job_id") is not None))
        return {"ok": ok > 0, "applied": ok, "error": None if ok else "no tags queued",
                "total": len(results), "results": results,
                "writes_enabled": navi_cli.writes_enabled()}, 200
    value = (p.get("value") or "").strip()
    if not value:
        return {"ok": False, "error": "value required"}, 400
    r = _tag_one(p.get("category", "Identity"), value, p.get("asset_uuids"))
    return {"ok": r.get("ok", True) is not False, "result": r, "count": len(p.get("asset_uuids") or []),
            "error": r.get("message") if r.get("ok") is False else None,
            "writes_enabled": navi_cli.writes_enabled()}, 200


def interpret(p):
    prompt = (p.get("prompt") or "").strip()
    accounts = p.get("accounts") or []
    if not prompt:
        return {"ok": False, "error": "prompt required"}, 200
    if llm is None or not llm.available():
        return {"ok": False, "needs_key": True,
                "error": "natural-language tagging needs the model (set ANTHROPIC_API_KEY); "
                         "use the per-row Tag buttons instead"}, 200
    out = llm.identity_plan(prompt, accounts)
    if not out.get("ok"):
        return {"ok": False, "error": out.get("message", "LLM failed")}, 200
    return {"ok": True, "assignments": out.get("assignments", [])}, 200


ACTIONS = {"run": run, "tag": tag, "interpret": interpret}
