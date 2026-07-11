"""Certificate agent — self-contained HTTP actions.

`run`    — deterministic discovery (ground truth: certs failing in 12 months).
`reason` — the agentic step: a static (editable) system prompt drives an LLM to
           triage those candidates, assign priority, and explain the risk in
           plain language. Validated against the real candidate set; falls back
           to "tag everything" when no API key is configured.
`tags_apply` — the gated write (unchanged).
"""
from core import navi_cli, llm, db
from .agent import CertificateAgent, DEFAULT_PROMPT

AGENT = CertificateAgent()


def _candidates():
    """Compact view of the taggable certs (expired + failing-in-12mo) for the
    model + the valid value set. Expired certs come first (highest risk)."""
    res = AGENT.result or AGENT.run()
    cands, seen = [], set()
    for r in res.get("expired", []) + res.get("twelve_month", []):
        v = r["tag_value"]
        if v in seen:
            continue
        seen.add(v)
        cands.append({"value": v, "status": r.get("status", "failing"),
                      "ip": r["ip_address"], "host": r.get("hostname", ""),
                      "common_name": r["common_name"],
                      "expiry": r["not_valid_after"], "days_left": r["days_left"],
                      "signature": r.get("signature_algorithm", ""),
                      "key_length": r.get("key_length", "")})
    return res, cands, {c["value"] for c in cands}


def run(p):
    res = AGENT.run()
    # Ground truth for "applied": which of our tags ACTUALLY exist in navi.db right
    # now. The UI derives status from this instead of a sticky client-side flag, so
    # deleting a tag in Tenable/navi.db makes it show as pending again after a sync.
    return {"ok": True, "agent": AGENT.meta(), "result": res,
            "default_prompt": DEFAULT_PROMPT, "llm_available": llm.available(),
            "tags_present": db.tags_present(["Cert failure", "Cert Issue"])}, 200


def reason(p):
    """Run discovery, then have the agent reason over the candidates with the
    (possibly edited) static prompt. Returns an assessment + per-candidate plan."""
    res, cands, valid = _candidates()
    prompt = (p.get("prompt") or DEFAULT_PROMPT).strip()
    if not cands:
        rows = res.get("cert_rows", 0)
        if not rows:
            msg = ("No rows in the navi.db `certs` table, so there are no certificates "
                   "to reason over. Populate it with navi's certificate sync "
                   "(`navi update certs`, or the certs/SSL plugins via a scan), then "
                   "Refresh navi.db and run again.")
        else:
            msg = (f"The certs table has {rows} certificate(s), but none are expired or "
                   "expiring within 12 months (their not_valid_after dates may be far "
                   "in the future, or unparseable). Nothing to tag right now.")
        return {"ok": True, "result": res, "assessment": msg,
                "plan": [], "llm_used": False, "default_prompt": DEFAULT_PROMPT}, 200
    out = llm.cert_plan(prompt, cands)
    plan = []
    if out.get("ok"):
        tagged = {t.get("value"): t for t in out.get("tag", []) if t.get("value") in valid}
        skipped = {s.get("value"): s for s in out.get("skip", []) if s.get("value") in valid}
        for c in cands:
            if c["value"] in tagged:
                t = tagged[c["value"]]
                plan.append({"value": c["value"], "decision": "tag",
                             "priority": (t.get("priority") or "med"), "why": (t.get("why") or "")[:120]})
            elif c["value"] in skipped:
                plan.append({"value": c["value"], "decision": "skip", "priority": "—",
                             "why": (skipped[c["value"]].get("why") or "")[:120]})
            else:  # model didn't mention it → default to tag (per the prompt policy)
                plan.append({"value": c["value"], "decision": "tag", "priority": "med",
                             "why": "default (not explicitly assessed)"})
        return {"ok": True, "result": res, "assessment": out.get("assessment", ""),
                "plan": plan, "llm_used": True, "model": out.get("model"),
                "default_prompt": DEFAULT_PROMPT}, 200
    # fallback: no/failed LLM — deterministic. Honor a simple "expired only" intent
    # so the operator's instruction still does something useful without a model.
    pl = prompt.lower()
    expired_only = ("expired" in pl or "have expired" in pl or "already expired" in pl) \
        and not any(w in pl for w in ("failing", "expiring", "next 12", "all cert", "everything"))
    for c in sorted(cands, key=lambda x: x["days_left"]):
        is_expired = c.get("status") == "expired" or c["days_left"] < 0
        if expired_only and not is_expired:
            plan.append({"value": c["value"], "decision": "skip", "priority": "—",
                         "why": "not expired (prompt: expired only)"})
            continue
        d = c["days_left"]
        why = (f"expired {abs(d)} days ago" if is_expired else f"expires in {d} days")
        plan.append({"value": c["value"], "decision": "tag",
                     "priority": "high" if is_expired or d <= 30 else "med", "why": why})
    n_tag = sum(1 for x in plan if x["decision"] == "tag")
    scope = "already-expired certificate(s)" if expired_only else "certificate(s)"
    note = ("Deterministic (no working model key — set ANTHROPIC_API_KEY to use the "
            "editable reasoning prompt). " if not llm.available() or "fail" in out.get("message", "").lower()
            else "")
    return {"ok": True, "result": res,
            "assessment": f"{note}{n_tag} {scope} selected for tagging"
                          + (" by expiry urgency." if not expired_only else "."),
            "plan": plan, "llm_used": False, "default_prompt": DEFAULT_PROMPT}, 200


def tags_apply(p):
    if AGENT.result is None:
        return {"ok": False, "error": "run the agent first"}, 400
    if not p.get("confirm"):
        return {"ok": False, "error": "confirm=true required to apply tags"}, 400
    actions = {a["value"]: a for a in AGENT.result.get("tag_actions", [])}
    results = []
    for v in p.get("values", []):
        a = actions.get(v)
        if not a:
            results.append({"value": v, "ok": False, "message": "no matching tag action"})
            continue
        results.append({"value": v, **navi_cli.tag(a["category"], a["value"], a["query"], remove=False)})
    return {"ok": True, "results": results, "writes_enabled": navi_cli.writes_enabled(),
            "allow_writes_flag": navi_cli.allow_writes(), "navi_available": navi_cli.navi_available(),
            "write_gate_reason": navi_cli.write_gate_reason()}, 200


def tags_issues(p):
    """Tag the selected cert-issue plugins from Heat map 2 — each becomes
    Cert Issue : <plugin_name>, scoped to the assets the plugin fired on
    (navi --plugin <id>). Persistent (remove=False) — it categorises the assets
    carrying that certificate weakness. Gated."""
    if not p.get("confirm"):
        return {"ok": False, "error": "confirm=true required to apply tags"}, 400
    results = []
    for it in p.get("issues", []):
        pid = str(it.get("plugin_id") or "").strip()
        nm = (it.get("plugin_name") or "").strip()
        if not pid or not nm:
            results.append({"plugin_id": pid, "ok": False, "message": "missing plugin id/name"})
            continue
        results.append({"plugin_id": pid, "value": nm,
                        **navi_cli.tag("Cert Issue", nm, plugin=pid, remove=False,
                                       agent="certificate")})
    return {"ok": True, "results": results, "writes_enabled": navi_cli.writes_enabled(),
            "allow_writes_flag": navi_cli.allow_writes(), "navi_available": navi_cli.navi_available(),
            "write_gate_reason": navi_cli.write_gate_reason()}, 200


ACTIONS = {"run": run, "reason": reason, "tags_apply": tags_apply,
           "tags_issues": tags_issues}
