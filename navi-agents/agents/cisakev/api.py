"""Laelaps / CISA KEV — self-contained HTTP actions.

`run`            — KEV summary + the distinct catalog dates (from navi.db xrefs).
`tag_vulnerable` — gated; tag every KEV asset CISA KEV:Vulnerable (navi --xrefs).
`tag_dates`      — gated; tag KEV assets per chosen dateAdded (navi --xrefs --xid).
`nl`             — NL → one read-only SELECT to hunt KEV in navi.db / tags.
"""
from core import navi_cli, llm
from .agent import CisaKevAgent, kev_dates
from .agent import tag_vulnerable as _tag_vuln, tag_date as _tag_date

AGENT = CisaKevAgent()


def run(p):
    return {"ok": True, "agent": AGENT.meta(), "result": AGENT.run()}, 200


def tag_vulnerable(p):
    if not p.get("confirm"):
        return {"ok": False, "error": "confirm=true required to write tags"}, 400
    r = _tag_vuln()
    return {"ok": r.get("ok", False), **r, "writes_enabled": navi_cli.writes_enabled()}, 200


def tag_dates(p):
    if not p.get("confirm"):
        return {"ok": False, "error": "confirm=true required to write tags"}, 400
    dates = p.get("dates")
    if dates is None:                       # default: every catalog date present
        dates = [d["kev_date"] for d in kev_dates()]
    dates = [d for d in dates if (d or "").strip()]
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
    out = llm.advanced_query(prompt, _SCHEMA, _JOINS, value_hint=_HINT)
    if not out.get("ok"):
        return {"ok": False, "fallback": out.get("fallback", True),
                "message": out.get("message", "LLM unavailable"), "llm_available": llm.available()}, 200
    return {"ok": True, "sql": out.get("sql"), "model": out.get("model"), "llm_available": True}, 200


ACTIONS = {"run": run, "tag_vulnerable": tag_vulnerable, "tag_dates": tag_dates, "nl": nl}
