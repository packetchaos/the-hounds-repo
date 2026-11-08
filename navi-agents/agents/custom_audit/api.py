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
import os

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
    """NL requirement -> drafted checks + rendered .audit. If the prompt names a CIS
    benchmark in the library (core.benchmarks), draft the whole benchmark grounded on its
    control index and apply any per-control adjustments; otherwise draft ad-hoc checks.
    Falls back cleanly (a scaffold, or the guided builder) when no model key is set."""
    from core import custom_audit as _ca, llm, benchmarks as _bm
    prompt = (p.get("prompt") or "").strip()
    platform = (p.get("platform") or "Unix").strip()
    if platform not in _ca.CATALOG:
        return {"ok": False, "error": "unknown platform '%s'" % platform}, 400
    if not prompt:
        return {"ok": False, "error": "describe the audit check or file you need"}, 400

    # Benchmark path — "create a CIS Docker benchmark and tighten 5.3 ..."
    bench = None
    if not p.get("no_benchmark"):
        bid = (p.get("benchmark") or "").strip()
        bench = _bm.get(bid) if bid else _bm.match(prompt)
    if bench:
        return _draft_benchmark(bench, prompt, p)

    # Ad-hoc single/few-check path.
    plan = llm.audit_plan(prompt, platform, _ca.vocab_text(platform))
    if not plan.get("ok"):
        return {"ok": False, "fallback": bool(plan.get("fallback")),
                "error": plan.get("message") or "draft failed"}, 200
    checks = plan.get("checks") or []
    for c in checks:
        if not c.get("references"):
            c["references"] = _ca.suggest_refs((c.get("description") or "") + " " + (c.get("info") or ""))
    title = plan.get("title") or "Custom Audit"
    audit = _ca.render_file({"platform": platform, "title": title}, checks)
    return {"ok": True, "platform": platform, "title": title, "checks": checks,
            "notes": plan.get("notes") or "", "audit": audit,
            "validation": _ca.validate(audit), "model": plan.get("model")}, 200


_BENCH_MAX = int(os.environ.get("NAVI_BENCH_MAX_CONTROLS", "45"))


def benchmarks(p):
    """List the CIS benchmark control-index library (no control bodies)."""
    from core import benchmarks as _bm
    return {"ok": True, "benchmarks": _bm.catalog()}, 200


def _scaffold_type(hint):
    """Best-effort check type + starter fields from a control's one-line hint.
    Honest placeholder: required fields the author must complete are marked TODO."""
    h = (hint or "").strip()
    hl = h.lower()
    if hl.startswith("cmd_exec") or "auditctl" in hl or "sysctl" in hl or "findmnt" in hl \
            or "getenforce" in hl or "modprobe" in hl or hl.startswith("rpm ") \
            or "dpkg -" in hl or "awk " in hl or "grep" in hl:
        cmd = h.split(":", 1)[1].strip() if ":" in h else h
        return "CMD_EXEC", {"cmd": cmd or "TODO: command", "expect": ".+"}
    if "file_content_check" in hl:
        return "FILE_CONTENT_CHECK", {"file": "TODO: /path", "regex": ".*", "expect": ".*"}
    if "file_check" in hl:
        return "FILE_CHECK", {"file": "TODO: /path"}
    return "CMD_EXEC", {"cmd": (h or "TODO: command"), "expect": ".+"}


def _scaffold_from_index(bench, controls):
    """Deterministic, key-free fallback: turn the control index into editable scaffold
    checks so the file is a real starting point even with no model configured."""
    from core import custom_audit as _ca
    out = []
    for c in controls:
        num = c.get("num", ""); title = c.get("title", "")
        typ, fields = _scaffold_type(c.get("hint"))
        refs = c.get("refs") or _ca.suggest_refs(title + " " + (c.get("topic") or ""))
        out.append({"type": typ, "description": ("%s %s" % (num, title)).strip(),
                    "info": "%s %s (scaffold — complete the check logic; set "
                            "ANTHROPIC_API_KEY to auto-draft)" % (bench.get("name", ""), num),
                    "fields": fields, "solution": "", "references": refs})
    return out


def _draft_benchmark(bench, prompt, p):
    from core import custom_audit as _ca, llm, benchmarks as _bm
    platform = bench.get("platform") or "Unix"
    if platform not in _ca.CATALOG:
        platform = "Unix"
    controls_all = _bm.section_filter(bench, prompt)
    total = len(controls_all)
    try:
        cap = max(1, int(p.get("max_controls") or _BENCH_MAX))
    except (TypeError, ValueError):
        cap = _BENCH_MAX
    controls = controls_all[:cap]
    truncated = total > len(controls)
    plan = llm.benchmark_plan(prompt, bench, controls, _ca.vocab_text(platform))
    used_model = bool(plan.get("ok"))
    if used_model:
        checks = plan.get("checks") or []
        notes = plan.get("notes") or ""
        applied = plan.get("applied") or []
    else:
        checks = _scaffold_from_index(bench, controls)
        notes = plan.get("message") or ""
        applied = []
    for c in checks:
        if not c.get("references"):
            c["references"] = _ca.suggest_refs((c.get("description") or "") + " " + (c.get("info") or ""))
    title = plan.get("title") or bench.get("name") or "Custom Audit"
    audit = _ca.render_file({"platform": platform, "title": title}, checks)
    if truncated:
        notes = (notes + " · " if notes else "") + (
            "drafted the first %d of %d controls (cap %d) — raise Max controls, or narrow by "
            "section (e.g. \"%s section 5\")." % (len(controls), total, cap, bench.get("name", "")))
    return {"ok": True, "platform": platform, "title": title, "checks": checks,
            "notes": notes, "applied": applied, "audit": audit,
            "validation": _ca.validate(audit),
            "benchmark": {"id": bench["id"], "name": bench.get("name"),
                          "version": bench.get("version"),
                          "total_controls": total, "drafted": len(checks),
                          "truncated": truncated, "scaffold": not used_model,
                          "note": bench.get("note", "")},
            "model": plan.get("model")}, 200


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


ACTIONS = {"platforms": platforms, "benchmarks": benchmarks, "draft": draft,
           "render": render, "validate": validate, "suggest": suggest, "parse": parse}
