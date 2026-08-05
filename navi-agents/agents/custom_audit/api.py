"""Draco — Custom Audit HTTP actions.

platforms — the check-type catalog (Windows + Unix) for the guided builder + a hint
            for the NL box.
draft     — natural language -> Claude-drafted checks (via core.llm.audit_plan),
            rendered to a .audit + validated. Falls back cleanly with no API key.
render    — structured checks (from builder or edited drafts) -> full .audit + validation.
validate  — validate a pasted/edited .audit text.

All read-only: nothing is written to navi. The scan-ready .audit is downloaded by
the page (client-side).
"""
AGENT = None


def _agent():
    global AGENT
    if AGENT is None:
        from .agent import DracoAgent
        AGENT = DracoAgent()
    return AGENT


def platforms(p):
    from core import custom_audit as _ca
    return {"ok": True, "result": _ca.platforms()}, 200


def draft(p):
    """NL requirement -> drafted checks + rendered .audit. If the model isn't
    configured, returns fallback:true so the page steers the user to the builder."""
    from core import custom_audit as _ca, llm
    prompt = (p.get("prompt") or "").strip()
    platform = (p.get("platform") or "Unix").strip()
    if platform not in _ca.CATALOG:
        return {"ok": False, "error": "unknown platform '%s'" % platform}, 400
    if not prompt:
        return {"ok": False, "error": "describe the audit check or file you need"}, 400
    plan = llm.audit_plan(prompt, platform, _ca.vocab_text(platform))
    if not plan.get("ok"):
        return {"ok": False, "fallback": bool(plan.get("fallback")),
                "error": plan.get("message") or "draft failed"}, 200
    checks = plan.get("checks") or []
    # Backfill framework refs the model may have skipped, from the rule-based map.
    for c in checks:
        if not c.get("references"):
            c["references"] = _ca.suggest_refs((c.get("description") or "") + " " + (c.get("info") or ""))
    title = plan.get("title") or "Custom Audit"
    audit = _ca.render_file({"platform": platform, "title": title}, checks)
    return {"ok": True, "platform": platform, "title": title, "checks": checks,
            "notes": plan.get("notes") or "", "audit": audit,
            "validation": _ca.validate(audit), "model": plan.get("model")}, 200


def render(p):
    """Structured checks -> full .audit + validation (the builder's live preview /
    download source of truth). Accepts an optional preserved `wrapper` + `group`
    (from an uploaded file) and a custom/empty platform."""
    from core import custom_audit as _ca
    platform = (p.get("platform") or "").strip()
    wrapper = p.get("wrapper")
    if platform and platform not in _ca.CATALOG:
        return {"ok": False, "error": "unknown platform '%s'" % platform}, 400
    title = (p.get("title") or "Custom Audit").strip()
    checks = p.get("checks") or []
    meta = {"platform": platform or None, "title": title, "wrapper": wrapper, "group": p.get("group")}
    audit = _ca.render_file(meta, checks)
    return {"ok": True, "platform": platform, "title": title,
            "audit": audit, "validation": _ca.validate(audit)}, 200


def parse(p):
    """Upload -> editable checks. Preserves each <custom_item> verbatim so the user
    can quickly remove checks or add new ones and re-download a faithful file."""
    from core import custom_audit as _ca
    text = p.get("text") or ""
    if not text.strip():
        return {"ok": False, "error": "no file content"}, 400
    r = _ca.parse(text)
    if not r.get("ok"):
        return {"ok": False, "error": r.get("error") or "could not parse"}, 200
    return {"ok": True, "result": r, "validation": _ca.validate(text)}, 200


def validate(p):
    from core import custom_audit as _ca
    return {"ok": True, "result": _ca.validate(p.get("text") or "")}, 200


def suggest(p):
    """Rule-based framework references for a check description (builder helper)."""
    from core import custom_audit as _ca
    return {"ok": True, "references": _ca.suggest_refs(p.get("text") or "")}, 200


ACTIONS = {"platforms": platforms, "draft": draft, "render": render,
           "validate": validate, "suggest": suggest, "parse": parse}
