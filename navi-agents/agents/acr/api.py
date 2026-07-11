"""ACR Calibration agent — self-contained HTTP actions."""
from core import navi_cli, llm
from .agent import ACRCalibrationAgent

AGENT = ACRCalibrationAgent()
REASONS = {"business", "compliance", "mitigation", "development"}


def run(p):
    return {"ok": True, "agent": AGENT.meta(), "result": AGENT.run()}, 200


def apply(p):
    if not p.get("confirm"):
        return {"ok": False, "error": "confirm=true required to change ACR"}, 400
    cat, val, mod = p.get("category", ""), p.get("value", ""), p.get("mod", "set")
    note = p.get("note", "")
    if not cat or not val:
        return {"ok": False, "error": "category and value are required"}, 400
    try:
        score = float(p.get("score"))
    except (TypeError, ValueError):
        return {"ok": False, "error": "score must be a number 1–10"}, 400
    if not (1 <= score <= 10):
        return {"ok": False, "error": "score must be between 1 and 10"}, 400
    if mod in ("inc", "dec") and not note:
        return {"ok": False, "error": "a business justification is required"}, 400
    res = navi_cli.acr(cat, val, score, mod=mod, note=note, reasons=p.get("reasons", []))
    return {"ok": res.get("ok", False), **res, "writes_enabled": navi_cli.writes_enabled()}, 200


def bulk_apply(p):
    if not p.get("confirm"):
        return {"ok": False, "error": "confirm=true required to change ACR"}, 400
    changes = p.get("changes", [])
    if not changes:
        return {"ok": False, "error": "no changes supplied"}, 400
    results = []
    for ch in changes:
        try:
            score = float(ch.get("score"))
        except (TypeError, ValueError):
            results.append({**ch, "ok": False, "message": "invalid score"}); continue
        if not (1 <= score <= 10):
            results.append({**ch, "ok": False, "message": "score must be 1–10"}); continue
        r = navi_cli.acr(ch.get("category", ""), ch.get("value", ""), score,
                         mod=ch.get("mod", "set"), note=ch.get("note"), reasons=ch.get("reasons", []))
        results.append({"category": ch.get("category"), "value": ch.get("value"),
                        "mod": ch.get("mod"), "score": score, **r})
    return {"ok": True, "applied": sum(1 for r in results if r.get("ok")),
            "total": len(results), "results": results,
            "writes_enabled": navi_cli.writes_enabled()}, 200


def interpret(p):
    prompt, tags = p.get("prompt", ""), p.get("tags", [])
    if not prompt.strip():
        return {"ok": False, "error": "empty instruction"}, 400
    if not tags:
        return {"ok": False, "error": "no tags loaded — run the agent first"}, 400
    out = llm.interpret(prompt, tags)
    if not out.get("ok"):
        return {"ok": False, "fallback": out.get("fallback", True),
                "message": out.get("message", "LLM unavailable"), "llm_available": llm.available()}, 200
    index = {(t["category"], t["value"]) for t in tags}
    valid, rejected = [], []
    for c in out.get("changes", []):
        cat, val, mod = c.get("category"), c.get("value"), c.get("mod")
        try:
            score = int(c.get("score"))
        except (TypeError, ValueError):
            rejected.append({**c, "why_rejected": "bad score"}); continue
        reason = c.get("reason") if c.get("reason") in REASONS else "business"
        if (cat, val) not in index:
            rejected.append({**c, "why_rejected": "tag not in current list"}); continue
        if mod not in ("set", "inc", "dec"):
            rejected.append({**c, "why_rejected": "bad mod"}); continue
        if not (1 <= score <= 10):
            rejected.append({**c, "why_rejected": "score out of 1–10"}); continue
        valid.append({"category": cat, "value": val, "mod": mod, "score": score,
                      "reasons": [reason], "why": (c.get("why") or "")[:80]})
    return {"ok": True, "changes": valid, "rejected": rejected,
            "model": out.get("model"), "llm_available": True}, 200


ACTIONS = {"run": run, "apply": apply, "bulk_apply": bulk_apply, "interpret": interpret}
