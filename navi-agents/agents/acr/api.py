"""ACR Calibration agent — self-contained HTTP actions.

ACR protection (NO : UPDATE) and the ACR log: see core/acr_protect.py + core/acrlog.py.
Reads: preview, metrics, log, log_export. Gated writes: apply, bulk_apply (optional
protect_after), protect (tag NO : UPDATE — never a removal; removal is Garmr's)."""
from core import acr_protect, acrlog, navi_cli, llm
from .agent import ACRCalibrationAgent
from core.gates import confirmed

AGENT = ACRCalibrationAgent()
REASONS = {"business", "compliance", "mitigation", "development"}


def run(p):
    return {"ok": True, "agent": AGENT.meta(), "result": AGENT.run()}, 200


def apply(p):
    if not confirmed(p):
        return {"ok": False, "error": "confirm=true required to change ACR"}, 400
    cat, val, mod = p.get("category", ""), p.get("value", ""), p.get("mod", "set")
    note = p.get("note", "")
    if not cat or not val:
        return {"ok": False, "error": "category and value are required"}, 400
    score, err = _score(p.get("score"))
    if err:
        return {"ok": False, "error": err}, 400
    if mod in ("inc", "dec") and not note:
        return {"ok": False, "error": "a business justification is required"}, 400
    refuse = acr_protect.preview(cat, val, score, mod).get("refuse") or acr_protect.refuse_reason(cat, val, score, mod)
    if refuse:                     # navi would change nothing / crash part-way — don't send it
        return {"ok": False, "error": refuse, "refused": True}, 400
    res = navi_cli.acr(cat, val, score, mod=mod, note=note, reasons=p.get("reasons", []), agent="acr")
    out = {"ok": res.get("ok", False), **res, "writes_enabled": navi_cli.writes_enabled()}
    if p.get("protect_after"):
        out["protection"] = _protect_after(res)
    return out, 200


def _score(v):
    """(score, error): a WHOLE number 1–10 — navi does int(score), so 9.5 would crash it."""
    try:
        f = float(v)
    except (TypeError, ValueError):
        return None, "score must be a whole number 1–10"
    if f != f or f != int(f):
        return None, "score must be a whole number 1–10 (navi rejects %s)" % v
    if not (1 <= f <= 10):
        return None, "score must be between 1 and 10"
    return int(f), ""


def _protect_after(res):
    """Queue NO : UPDATE for exactly the assets this change APPLIED to (ACR log batch)."""
    if not res.get("ok") or res.get("blocked"):
        return {"ok": False, "queued_jobs": 0, "assets": 0, "note": "the ACR change was not applied — nothing to protect"}
    batch = (res.get("acr_log") or {}).get("batch")
    if not batch:
        return {"ok": False, "queued_jobs": 0, "assets": 0, "note": "no ACR log batch"}
    return acr_protect.protect_batch(batch, agent="acr", business_case=res.get("business_case", ""))


def bulk_apply(p):
    if not confirmed(p):
        return {"ok": False, "error": "confirm=true required to change ACR"}, 400
    changes = p.get("changes", [])
    if not changes:
        return {"ok": False, "error": "no changes supplied"}, 400
    results = []
    for ch in changes:
        score, err = _score(ch.get("score"))
        if err:
            results.append({**ch, "ok": False, "message": err}); continue
        refuse = acr_protect.refuse_reason(ch.get("category", ""), ch.get("value", ""), score, ch.get("mod", "set")) \
            or acr_protect.preview(ch.get("category", ""), ch.get("value", ""), score, ch.get("mod", "set")).get("refuse")
        if refuse:
            results.append({**ch, "ok": False, "refused": True, "message": refuse}); continue
        r = navi_cli.acr(ch.get("category", ""), ch.get("value", ""), score,
                         mod=ch.get("mod", "set"), note=ch.get("note"), reasons=ch.get("reasons", []),
                         agent="acr")
        if p.get("protect_after"):
            r["protection"] = _protect_after(r)
        results.append({"category": ch.get("category"), "value": ch.get("value"),
                        "mod": ch.get("mod"), "score": score, **r})
    out = {"ok": True, "applied": sum(1 for r in results if r.get("ok")),
           "total": len(results), "results": results,
           "writes_enabled": navi_cli.writes_enabled()}
    if p.get("protect_after"):
        out["protected_assets"] = sum((r.get("protection") or {}).get("assets", 0) for r in results)
    return out, 200


def preview(p):
    """Read: what navi WILL do for one or more ACR changes — per change, how many assets change,
    are protected (NO : UPDATE) and are skipped for having no ACR. Mirrors navi's selection.
    payload: {category, value, score, mod} or {changes:[…]}."""
    chs = p.get("changes") if isinstance(p.get("changes"), list) else [p]
    out, tot = [], {"change": 0, "unchanged": 0, "protected": 0, "no_acr": 0, "bad_acr": 0, "total": 0}
    for ch in chs[:500]:
        pv = acr_protect.preview(str(ch.get("category") or ""), str(ch.get("value") or ""),
                                 ch.get("score"), ch.get("mod") or "set")
        out.append(acr_protect.summary(pv, sample=int(p.get("sample") or 0)))
        for k in tot:
            tot[k] += (pv.get("counts") or {}).get(k, 0)
    return {"ok": True, "previews": out, "totals": tot}, 200


def metrics(p):
    """Read: At-a-glance numbers + the Protection list (navi.db NO : UPDATE × the ACR log)."""
    show = str(p.get("show") or "all")
    if show not in ("all", "protected", "unprotected", "pending"):
        show = "all"
    return {"ok": True, **acr_protect.metrics(show=show, limit=p.get("limit") or 2000),
            "writes_enabled": navi_cli.writes_enabled()}, 200


def _filters(p):
    return {k: p.get(k) for k in ("agent", "result", "business_case", "batch", "since", "until", "q",
                                   "category", "value")}


def log(p):
    """Read: the ACR log (newest first), filtered; plus filter facets."""
    r = acrlog.rows(_filters(p), limit=p.get("limit") or 5000)
    return {"ok": True, **r, "facets": acrlog.facets()}, 200


def log_export(p):
    """Read: the ACR log as CSV (same filters as `log`, no row limit)."""
    return {"ok": True, **acrlog.export_csv(_filters(p))}, 200


def protect(p):
    """Gated: tag NO : UPDATE on assets the Hounds changed and that are not protected yet.
    payload: {confirm:true, uuids:[…]} or {confirm:true, all_unprotected:true}. The tag is
    always exactly NO : UPDATE (exempt from Settings → Test run). Each job carries the business
    case of the asset's last Hound ACR change. Protection counts for navi after the next
    navi.db sync. Removing it is a tag removal → Tag Removal (Garmr) only."""
    if not confirmed(p):
        return {"ok": False, "error": "confirm=true required to tag NO : UPDATE"}, 400
    changed = acrlog.applied_assets()
    prot = acr_protect.protected_uuids()
    pend = acr_protect.pending_uuids(prot)            # queued already, waiting for the navi.db sync
    if p.get("all_unprotected"):
        want = [u for u in changed if u not in prot and u not in pend]
    else:
        want = [str(u) for u in (p.get("uuids") or []) if isinstance(u, str)]
        unknown = [u for u in want if u not in changed]
        if unknown:
            return {"ok": False, "error": "%d asset(s) were not changed by the Hounds — protect only assets in "
                    "the ACR log (or tag NO : UPDATE from another tagging Hound)" % len(unknown)}, 400
        want = [u for u in want if u not in prot and u not in pend]
    if not want:
        return {"ok": True, "queued_jobs": 0, "assets": 0,
                "note": "nothing to protect — already protected or waiting for the navi.db sync",
                "writes_enabled": navi_cli.writes_enabled()}, 200
    groups = {}
    for u in want:
        groups.setdefault(changed[u]["business_case"] or "", []).append(u)
    r = acr_protect.protect(groups, agent="acr")
    return {**r, "writes_enabled": navi_cli.writes_enabled(), "write_gate_reason": navi_cli.write_gate_reason()}, 200


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


ACTIONS = {"run": run, "apply": apply, "bulk_apply": bulk_apply, "interpret": interpret,
           "preview": preview, "metrics": metrics, "log": log, "log_export": log_export, "protect": protect}
