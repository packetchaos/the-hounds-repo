"""Identity Inventory — self-contained HTTP actions.

`run`       — discover NHI/human/service identities (read-only) + asset_uuids + URLs.
`tag`       — gated; tag the hosting assets via navi tag-by-query. Accepts either a
              single {category,value,asset_uuids} or a list of such under `items`.
`interpret` — natural-language tagging: turn an instruction + the discovered
              identities into per-identity {category,value} assignments (LLM).
"""
from core import identity, navi_cli

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


def run(p):
    try:
        res = identity.scan()
    except Exception as e:
        return {"ok": False, "error": f"identity scan failed: {e}"}, 200
    return {"ok": True, "agent": _agent().meta(),
            "result": res, "llm_available": bool(llm and llm.available())}, 200


def _tag_one(category, value, asset_uuids):
    q = identity.selector_for(asset_uuids)
    if not q:
        return {"ok": False, "message": "no asset_uuids for this identity"}
    return navi_cli.tag(category or "Identity", value, query=q, remove=False)


def tag(p):
    if not p.get("confirm"):
        return {"ok": False, "error": "confirm=true required to write tags"}, 400
    items = p.get("items")
    if items:
        results = []
        for it in items:
            r = _tag_one(it.get("category", "Identity"), it.get("value", ""), it.get("asset_uuids"))
            results.append({"value": it.get("value"), "category": it.get("category", "Identity"), **r})
        return {"ok": True, "applied": sum(1 for r in results if r.get("ok")),
                "total": len(results), "results": results,
                "writes_enabled": navi_cli.writes_enabled()}, 200
    value = (p.get("value") or "").strip()
    if not value:
        return {"ok": False, "error": "value required"}, 400
    r = _tag_one(p.get("category", "Identity"), value, p.get("asset_uuids"))
    return {"ok": True, "result": r, "writes_enabled": navi_cli.writes_enabled()}, 200


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
