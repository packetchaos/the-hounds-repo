"""Laelaps / CISA KEV — self-contained HTTP actions.

`source`         — human-approval step for the CISA KEV catalog download.
`run`            — KEV exposure from navi.db joined to CISA's catalog by CVE: due dates,
                   overdue / due-soon, ransomware use, crown jewels, vendors, plus the
                   dateAdded list from Tenable's CISA-KNOWN-EXPLOITED xref.
`tag_vulnerable` — gated; tag every KEV asset CISA KEV:Vulnerable (navi --xrefs).
`tag_dates`      — gated; tag KEV assets per chosen dateAdded (navi --xrefs --xid).
`tag_due`        — gated; tag the assets behind each KEV CVE with its CISA remediation
                   due date: CISA KEV Due:<YYYY-MM-DD> (navi tag-by-CVE).
`tag_ransomware` — gated; tag the assets behind ransomware-linked KEVs CISA KEV:Ransomware.
`nl`             — NL → one read-only SELECT to hunt KEV in navi.db / tags.
"""
from core import downloads, navi_cli, llm, kev
from .agent import CisaKevAgent, kev_dates, summary as _xref_summary
from .agent import tag_vulnerable as _tag_vuln, tag_date as _tag_date
from core.gates import confirmed

AGENT = CisaKevAgent()
DUE_CATEGORY = "CISA KEV Due"


def source(p):
    """Human-approval step: what will be downloaded, and (when a model is set) an assessment."""
    note = ("CISA's Known Exploited Vulnerabilities catalog (JSON feed) — the authoritative list "
            "of CVEs exploited in the wild, with the federal remediation due date for each. "
            "Read-only download; falls back to CISA's GitHub mirror, then a bundled snapshot. "
            "Tags are still gated and approved before any write.")
    llm_used = False
    if llm.available():
        try:
            note = llm._messages("You are a security assistant. Answer in 2-3 sentences.",
                                 f"A Tenable agent will download {kev.FEED_URLS[0]} (fallback {kev.FEED_URLS[1]}) "
                                 "to add CISA KEV due dates and ransomware flags to its findings. Assess whether "
                                 "it is an official/trustworthy source, what it contains, and any caution before approving.")
            llm_used = True
        except Exception:
            pass
    return {"ok": True, "url": kev.FEED_URLS[0], "mirror": kev.FEED_URLS[1], "assessment": note,
            "llm_used": llm_used, "source_id": kev.SOURCE_ID,
            "auto_approved": downloads.auto_approve()}, 200


_UPLOAD = {"text": ""}   # the catalog the PAGE last uploaded, so tag actions use the SAME due dates


def run(p):
    base = AGENT.run()                                     # xref summary + dateAdded list
    # only a page run (it always sends json_text / approved) updates the remembered upload —
    # the Contract's discovery runs this with {} and must not wipe it
    if "json_text" in p or "approved" in p:
        _UPLOAD["text"] = p.get("json_text", "") or ""
    # live download only when approved: by the human (approved:true) or Settings → Auto-approve
    live, by = downloads.allowed(p)
    try:
        a = kev.analyze(json_text=_UPLOAD["text"], force=bool(p.get("refresh_catalog")), allow_live=live)
    except Exception as e:
        a = {"ok": False, "error": f"could not read the CISA KEV catalog: {e}"}
    return {"ok": True, "agent": AGENT.meta(), "result": {**base, "kev": a}, "approved_by": by}, 200


def _cves_for(pred, p):
    # live vs snapshot decided by THIS request's approval (the page sends approved with each
    # tag action, as with run) — not a process-wide flag another caller can overwrite
    a = kev.analyze(json_text=_UPLOAD["text"], keep_uuids=True,
                    allow_live=downloads.allowed(p)[0])          # catalog is cached — cheap
    return [c for c in a.get("cves", []) if pred(c)]


def _tag_rows(category, value, rows):
    """Tag the assets with an OPEN finding for these KEV CVEs (navi --cve would also match
    FIXED findings and longer ids by LIKE). The set is core.kev.cve_tag_query — the analysis'
    own rule as SQL — computed here (streamed) and paged: ≤1,999 per navi job, a series above."""
    rows = [r for r in rows or [] if r.get("uuids")]
    q = kev.cve_tag_query(rows)
    if not q:
        return []
    return navi_cli.tag_set(category, value, sql=q, agent="cisakev")


def tag_due(p):
    """Tag assets by their KEV due date: one navi tag-by-CVE job per CVE, value = due date."""
    if not confirmed(p):
        return {"ok": False, "error": "confirm=true required to write tags"}, 400
    want = {d for d in (p.get("dues") or []) if (d or "").strip()}
    if not want:
        return {"ok": False, "error": "no due dates supplied"}, 400
    rows = _cves_for(lambda c: c.get("due_date") in want, p)
    if not rows:
        return {"ok": False, "error": "none of those due dates have KEV CVEs on assets in navi.db"}, 400
    results = []
    for due in sorted(want):
        jobs = _tag_rows(DUE_CATEGORY, due, [r for r in rows if r["due_date"] == due])
        ids = [j["job_id"] for j in jobs if j.get("job_id") is not None]
        results.append({"due_date": due, "cves": sum(1 for r in rows if r["due_date"] == due),
                        "jobs": len(ids), "queued": bool(ids)})
    return {"ok": True, "queued": sum(r["jobs"] for r in results), "results": results,
            "writes_enabled": navi_cli.writes_enabled()}, 200


def tag_ransomware(p):
    if not confirmed(p):
        return {"ok": False, "error": "confirm=true required to write tags"}, 400
    rows = _cves_for(lambda c: c.get("ransomware"), p)
    if not rows:
        return {"ok": False, "error": "no ransomware-linked KEV CVEs on assets in navi.db"}, 400
    ids = [j["job_id"] for j in _tag_rows("CISA KEV", "Ransomware", rows)
           if j.get("job_id") is not None]
    return {"ok": True, "queued": len(ids), "cves": len(rows), "writes_enabled": navi_cli.writes_enabled()}, 200


def tag_vulnerable(p):
    if not confirmed(p):
        return {"ok": False, "error": "confirm=true required to write tags"}, 400
    r = _tag_vuln()
    return {"ok": r.get("ok", False), **r, "writes_enabled": navi_cli.writes_enabled()}, 200


def tag_dates(p):
    if not confirmed(p):
        return {"ok": False, "error": "confirm=true required to write tags"}, 400
    dates = p.get("dates")
    known = [d["kev_date"] for d in kev_dates()]
    if dates is None:                       # default: every catalog date present
        dates = known
    if not isinstance(dates, list):
        return {"ok": False, "error": "dates must be a list"}, 400
    ks = set(known)
    dates = [d for d in dates if isinstance(d, str) and d.strip() in ks]   # only KEV dates in navi.db
    if not dates:
        return {"ok": False, "error": "no KEV dates supplied / found"}, 400
    results = [{"kev_date": d, **_tag_date(d)} for d in dates]
    return {"ok": True, "queued": len(results), "results": results,
            "writes_enabled": navi_cli.writes_enabled()}, 200


_SCHEMA = ("vulns(asset_uuid, plugin_id, plugin_name, cves, xrefs, severity, state, url) — "
           "CISA KEV findings have xrefs LIKE '%CISA-KNOWN-EXPLOITED%'; the KEV dateAdded is "
           "the xref id (YYYY/MM/DD) inside xrefs\n"
           "assets(uuid, hostname, ip_address, operating_system, acr, url)\n"
           "tags(asset_uuid, tag_key, tag_value) — applied CISA KEV tags use tag_key='CISA KEV' "
           "(tag_value 'Vulnerable' or 'Mon - DD - YYYY')")
_JOINS = "assets.uuid = vulns.asset_uuid ; assets.uuid = tags.asset_uuid"
_HINT = ("\nKEV findings: vulns.xrefs LIKE '%CISA-KNOWN-EXPLOITED%'. Applied KEV tags: "
         "tags.tag_key='CISA KEV'. Filter one KEV date with xrefs LIKE "
         "'%CISA-KNOWN-EXPLOITED'', ''id'': ''2025/02/13%'.")


def nl(p):
    prompt = (p.get("prompt") or "").strip()
    if not prompt:
        return {"ok": False, "error": "ask a question first"}, 400
    from core import tagname
    keys = tagname.names("CISA KEV")           # 'CISA KEV' + its test-run name ('Hounds-CISA KEV')
    hint = _HINT + ("\nKEV tags may also be test-run tags: match tags.tag_key IN (%s)." %
                    ", ".join("'%s'" % k.replace("'", "''") for k in keys) if len(keys) > 1 else "")
    out = llm.advanced_query(prompt, _SCHEMA, _JOINS, value_hint=hint)
    if not out.get("ok"):
        return {"ok": False, "fallback": out.get("fallback", True),
                "message": out.get("message", "LLM unavailable"), "llm_available": llm.available()}, 200
    return {"ok": True, "sql": out.get("sql"), "model": out.get("model"), "llm_available": True}, 200


ACTIONS = {"source": source, "run": run, "tag_vulnerable": tag_vulnerable, "tag_dates": tag_dates,
           "tag_due": tag_due, "tag_ransomware": tag_ransomware, "nl": nl}
