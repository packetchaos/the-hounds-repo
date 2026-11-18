"""MITRE ATT&CK Tagging — self-contained HTTP actions.

`run`   — fetch the live ATT&CK->CVE mapping and build the asset-tagging plan
          (scope='navidb' by default: only CVEs present in navi.db), with metrics
          and the ATT&CK technique/tactic view.
`apply` — gated; tags the ASSETS affected by each selected CVE via navi's
          tag-by-CVE selector (navi enrich tag --cve), exactly as the navi skill
          recipe prescribes — the CVE picks the assets, the tag lands on them.
"""
from core import downloads, mitre, navi_cli, tagscope
from core.gates import confirmed
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
            "llm_used": llm_used, "llm_available": bool(llm and llm.available()),
            "source_id": mitre.SOURCE_ID, "auto_approved": downloads.auto_approve()}, 200


def _agent():
    global AGENT
    if AGENT is None:
        from .agent import MitreAgent
        AGENT = MitreAgent()
    return AGENT


_LAST = {"csv": ""}   # the CSV the PAGE last uploaded — apply() re-validates against it


def run(p):
    scope = p.get("scope", "navidb")
    csv_text = p.get("csv_text", "")   # optional user-supplied CSV
    # live download only when approved: by the human (approved:true) or Settings → Auto-approve
    live, by = downloads.allowed(p)
    # only a page run (it always sends csv_text / approved) updates the remembered upload —
    # the Contract's discovery runs this with {} and must not wipe it
    if "csv_text" in p or "approved" in p:
        _LAST["csv"] = csv_text or ""
    tk, tv = tagscope.parse(p)          # build 489: (None, None) = the whole estate, as before
    try:
        if tk:
            res = mitre.build_plan(scope=scope, csv_text=csv_text, allow_live=live, tag_key=tk, tag_value=tv)
        else:
            res = mitre.build_plan(scope=scope, csv_text=csv_text, allow_live=live)
    except Exception as e:
        return {"ok": False, "error": f"could not build ATT&CK->CVE plan: {e}"}, 200
    out = {"ok": True, "agent": _agent().meta(), "result": res,
           "download_url": mitre.CSV_URL, "approved_by": by}
    if tk:
        out["scope"] = res.get("tag_scope") or tagscope.describe(tk, tv)
    return out, 200


def apply(p):
    if not confirmed(p):
        return {"ok": False, "error": "confirm=true required to write tags"}, 400
    actions = p.get("actions") or []
    if not actions:
        return {"ok": False, "error": "no tag actions supplied"}, 400
    # MITRE tagging is STRICTLY CVE-based: every asset is tagged through navi's
    # native tag-by-CVE selector (navi enrich tag --cve), one call per CVE. navi
    # resolves the affected assets server-side and pages internally, so there is
    # no UUID cap to dodge and no SQL --query is used at all — the CVE is the
    # built-in. Group by (category, value) → union of CVEs → one --cve call each.
    # Re-build the plan on the server and accept only (cve, value) pairs that are in it AND have
    # assets in navi.db; the category is always Mitre. A crafted request can't pick another
    # category, and "approve all" in full-mapping scope doesn't queue jobs for absent CVEs.
    tk, tv = tagscope.parse(p)
    if tk:
        return _apply_scoped(p, actions, tk, tv)
    try:
        # live vs snapshot decided by THIS request's approval (the page sends approved with
        # apply, as with run) — not a process-wide flag another caller can overwrite
        plan = mitre.build_plan(scope="navidb", csv_text=_LAST["csv"], allow_live=downloads.allowed(p)[0])
    except Exception as e:
        return {"ok": False, "error": f"could not rebuild the plan: {e}"}, 200
    valid = {(a["cve"], a["value"]) for a in plan.get("actions", []) if a.get("assets")}
    groups, skipped = {}, 0
    for a in actions:
        cve, val = (a.get("cve", "") or "").upper(), a.get("value", "")
        if (cve, val) not in valid:
            skipped += 1
            continue
        groups.setdefault(("Mitre", val), set()).add(cve)
    if not groups:
        return {"ok": False, "error": "none of those CVE / value pairs are in the plan with assets in navi.db"}, 400
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
    return {"ok": True, "applied": sum(1 for r in results if r.get("ok")), "skipped": skipped,
            "total": len(results), "results": results,
            "writes_enabled": navi_cli.writes_enabled()}, 200


def _apply_scoped(p, actions, tk, tv):
    """apply() from a tag view (build 489): the tag lands ONLY on the tag's assets.

    navi's tag-by-CVE selector (--cve) would tag every asset in the estate that has the CVE, so
    a tag view cannot use it. Instead the server rebuilds the plan over the tag (re-read from
    navi.db, never from the browser), keeps only (CVE, value) pairs that have assets in the tag,
    and for each Mitre value tags the union of the tag's assets citing its CVEs through
    navi_cli.tag_set — ≤ 1,999-UUID pages, a tag series above that, add-only (remove=False)."""
    try:
        plan = mitre.build_plan(scope="navidb", csv_text=_LAST["csv"], allow_live=downloads.allowed(p)[0],
                                tag_key=tk, tag_value=tv)
    except Exception as e:
        return {"ok": False, "error": f"could not rebuild the plan: {e}"}, 200
    valid = {(a["cve"], a["value"]) for a in plan.get("actions", []) if a.get("assets")}
    groups, skipped = {}, 0
    for a in actions:
        cve, val = (a.get("cve", "") or "").upper(), a.get("value", "")
        if (cve, val) not in valid:
            skipped += 1
            continue
        groups.setdefault(val, set()).add(cve)
    scope = tagscope.describe(tk, tv)
    if not groups:
        return {"ok": False, "error": f"none of those CVE / value pairs have assets tagged {tk} : {tv}",
                "scope": scope}, 400
    # the tag's assets per CVE, from navi.db (SQL-scoped), for just the CVEs being written
    ca = mitre.cve_assets(only=set().union(*groups.values()), tag_key=tk, tag_value=tv)
    results = []
    for val, cves in groups.items():
        uu = sorted(set().union(*(ca.get(c, set()) for c in cves)))
        jobs = navi_cli.tag_set("Mitre", val, uuids=uu, agent="mitre") if uu else []
        job_ids = [j.get("job_id") for j in jobs if isinstance(j, dict) and j.get("job_id") is not None]
        bad = [j for j in jobs if isinstance(j, dict) and j.get("ok") is False]
        results.append({"value": val, "cves": len(cves), "assets": len(uu), "commands": len(jobs),
                        "mode": "uuids-in-tag", "job_ids": job_ids,
                        "job_id": (job_ids[0] if job_ids else None), "ok": bool(jobs) and not bad,
                        "queued": bool(job_ids), "error": (bad[0].get("message") if bad else None),
                        "writes_enabled": navi_cli.writes_enabled(),
                        "write_gate_reason": navi_cli.write_gate_reason()})
    return {"ok": True, "applied": sum(1 for r in results if r.get("ok")), "skipped": skipped,
            "total": len(results), "results": results, "scope": scope,
            "writes_enabled": navi_cli.writes_enabled()}, 200


ACTIONS = {"source": source, "run": run, "apply": apply}
