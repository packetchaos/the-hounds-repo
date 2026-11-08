"""Certificate agent — self-contained HTTP actions. Deterministic; no free-form LLM
reasoning (ad-hoc certificate questions go through the MCP).

`run`         — expired certs by month (last 12 months + older), certs failing in the
                next 12 months, the expiry timeline, metrics, crown jewels, cert-issue
                plugins and the IoT/app cache.
`tags_apply`  — gated; tags the ASSETS behind each chosen expiry date
                Cert failure : <Mon>-<DD>-<YYYY>. Jobs go to the Tagging log.
`tags_issues` — gated; tags the assets a cert-issue plugin fired on
                Cert Issue : <plugin name> (navi --plugin <id>).
"""
from core import navi_cli, db, tagname
from .agent import CertificateAgent
from core.gates import confirmed

AGENT = CertificateAgent()
CATEGORIES = ["Cert failure", "Cert Issue"]


def _gate():
    return {"writes_enabled": navi_cli.writes_enabled(), "write_gate_reason": navi_cli.write_gate_reason()}


def run(p):
    res = AGENT.run()
    # "applied" ground truth: which of our tags exist in navi.db right now
    return {"ok": True, "agent": AGENT.meta(), "result": res,
            # plain + Settings → Test run names; `base` lets the page match either
            "tags_present": [dict(t, base=tagname.base(t.get("tag_key")))
                             for t in db.tags_present(tagname.names(*CATEGORIES))]}, 200


def tags_apply(p):
    """Tag the assets behind each selected expiry date. Returns a compact summary —
    per-job detail lives in the Tagging log."""
    if not confirmed(p):
        return {"ok": False, "error": "confirm=true required to apply tags"}, 400
    want = [v for v in (p.get("values") or []) if v]
    if not want:
        return {"ok": False, "error": "no expiry dates selected"}, 400
    res = AGENT.result or AGENT.run()                  # recompute server-side if the cache is cold
    actions = {a["value"]: a for a in res.get("tag_actions", [])}
    queued, missing = 0, []
    for v in want:
        a = actions.get(v)
        if not a:
            missing.append(v)
            continue
        j = navi_cli.tag(a["category"], a["value"], a["query"], remove=False, agent="certificate")
        if j.get("job_id") is not None or j.get("ok"):
            queued += 1
    return {"ok": queued > 0, "queued": queued, "requested": len(want), "missing": missing,
            "error": None if queued else "none of those dates match a certificate in navi.db", **_gate()}, 200


def tags_issues(p):
    """Tag the assets each selected cert-issue plugin fired on: Cert Issue : <plugin name>."""
    if not confirmed(p):
        return {"ok": False, "error": "confirm=true required to apply tags"}, 400
    res = AGENT.result or AGENT.run()
    known = {str(m.get("plugin_id")): m.get("plugin_name") for m in res.get("cert_issue_matrix", [])}
    queued, bad = 0, 0
    for it in p.get("issues", []):
        pid = str(it.get("plugin_id") or "").strip()
        nm = (known.get(pid) or "").strip()          # only certificate plugins, named by the server
        if not pid or not nm:
            bad += 1
            continue
        j = navi_cli.tag("Cert Issue", nm, plugin=pid, remove=False, agent="certificate")
        if j.get("job_id") is not None or j.get("ok"):
            queued += 1
    return {"ok": queued > 0, "queued": queued, "skipped": bad,
            "error": None if queued else "no valid plugins selected", **_gate()}, 200


ACTIONS = {"run": run, "tags_apply": tags_apply, "tags_issues": tags_issues}
