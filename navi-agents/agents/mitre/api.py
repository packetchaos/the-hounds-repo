"""MITRE ATT&CK Tagging — self-contained HTTP actions.

`run`   — fetch the live ATT&CK->CVE mapping and build the per-CVE tag plan
          (scope='navidb' by default: only CVEs present in navi.db).
`apply` — gated; tags each selected CVE via navi's tag-by-CVE function
          (navi enrich tag --cve), exactly as the navi skill recipe prescribes.
"""
from core import mitre, navi_cli
try:
    from core import llm
except Exception:
    llm = None

AGENT = None


def source(p):
    """Human-approval step: describe the external download + an LLM assessment of
    the source, so the operator can approve before anything is fetched."""
    note = ("Center for Threat-Informed Defense (MITRE Engenuity) attack_to_cve — "
            "the official ATT&CK→CVE mapping. Read-only download; tags are still "
            "gated and approved before any write.")
    llm_used = False
    if llm is not None and getattr(llm, "available", lambda: False)():
        try:
            note = llm._messages(
                "You are a security assistant. Answer in 2-3 sentences.",
                f"A Tenable agent will download this CSV to drive MITRE ATT&CK tagging: {mitre.CSV_URL}. "
                "Assess whether it is an official/trustworthy source, what it contains, and any caution "
                "before approving the download.")
            llm_used = True
        except Exception:
            pass
    return {"ok": True, "url": mitre.CSV_URL, "assessment": note,
            "llm_used": llm_used, "llm_available": bool(llm and llm.available())}, 200


def _agent():
    global AGENT
    if AGENT is None:
        from .agent import MitreAgent
        AGENT = MitreAgent()
    return AGENT


def run(p):
    scope = p.get("scope", "navidb")
    csv_text = p.get("csv_text", "")   # optional user-supplied CSV
    try:
        res = mitre.build_plan(scope=scope, csv_text=csv_text)
    except Exception as e:
        return {"ok": False, "error": f"could not build ATT&CK->CVE plan: {e}"}, 200
    return {"ok": True, "agent": _agent().meta(), "result": res,
            "download_url": mitre.CSV_URL}, 200


def apply(p):
    if not p.get("confirm"):
        return {"ok": False, "error": "confirm=true required to write tags"}, 400
    actions = p.get("actions") or []
    if not actions:
        return {"ok": False, "error": "no tag actions supplied"}, 400
    # MITRE tagging is STRICTLY CVE-based: every asset is tagged through navi's
    # native tag-by-CVE selector (navi enrich tag --cve), one call per CVE. navi
    # resolves the affected assets server-side and pages internally, so there is
    # no UUID cap to dodge and no SQL --query is used at all — the CVE is the
    # built-in. Group by (category, value) → union of CVEs → one --cve call each.
    groups = {}
    for a in actions:
        cve, cat, val = (a.get("cve", "") or "").upper(), a.get("category", "Mitre"), a.get("value", "")
        if not cve or not val:
            continue
        groups.setdefault((cat, val), set()).add(cve)
    if not groups:
        return {"ok": False, "error": "no cve/value pairs supplied"}, 400
    results = []
    for (cat, val), cves in groups.items():
        job_ids = []
        for c in sorted(cves):
            j = navi_cli.tag(cat, val, cve=c, remove=False, agent="mitre")
            if j.get("job_id") is not None:
                job_ids.append(j.get("job_id"))
        results.append({"value": val, "cves": len(cves), "commands": len(job_ids),
                        "mode": "cve", "job_ids": job_ids,
                        "job_id": (job_ids[0] if job_ids else None), "ok": True,
                        "queued": bool(job_ids), "writes_enabled": navi_cli.writes_enabled(),
                        "write_gate_reason": navi_cli.write_gate_reason()})
    return {"ok": True, "applied": sum(1 for r in results if r.get("ok")),
            "total": len(results), "results": results,
            "writes_enabled": navi_cli.writes_enabled()}, 200


ACTIONS = {"source": source, "run": run, "apply": apply}
