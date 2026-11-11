"""Certificate agent — self-contained HTTP actions. Deterministic; no free-form LLM
reasoning (ad-hoc certificate questions go through the MCP).

`run`         — expired certs by month (last 12 months + older), certs failing in the
                next 12 months, the expiry timeline, metrics, crown jewels, cert-issue
                plugins and the IoT/app cache.
`tags_apply`  — gated; tags the ASSETS behind each chosen expiry date
                Cert failure : <Mon>-<DD>-<YYYY>. Jobs go to the Tagging log.
`tags_issues` — gated; tags the assets a cert-issue plugin fired on
                Cert Issue : <plugin name> (navi --plugin <id>).
`drill`       — read; pages / searches / filters the run's certificate, crown-jewel and
                IoT/app lists (core.payload — the page never receives the full lists).
`dates`       — read; the expiry dates (tag values) in a filtered view and how many
                certificates / assets a set of dates covers — what "Select shown" and the
                selection counter use instead of the full certificate list.

Payload contract (build 455): `run` returns the decision data — every metric, the
timeline, the cert-issue matrix, the top crown jewels, IoT counts and the first page
of certificates — plus `drill` (the run id) for everything else; no UUID arrays.
"""
from core import navi_cli, db, payload, tagname
from .agent import CertificateAgent
from core.gates import confirmed

AGENT = CertificateAgent()
CATEGORIES = ["Cert failure", "Cert Issue"]


def _gate():
    return {"writes_enabled": navi_cli.writes_enabled(), "write_gate_reason": navi_cli.write_gate_reason()}


# drill sections: sorts are (ascending) store key columns; flags are the filter tokens
_MONTH = lambda f: f.startswith("m:") and (f == "m:older" or (len(f) == 9 and f[2:6].isdigit() and f[7:].isdigit()))
_CERT_FLAGS = {"expired", "failing", "last12", "older", "due30", "due90", "crown", "weak", "self"}
SECTIONS = {
    "certs": {"sorts": {"near": ("s1", "s2")}, "flags": lambda f: f in _CERT_FLAGS or _MONTH(f)},
    "crown": {"sorts": {}, "flags": set()},
    "iot": {"sorts": {"type": ("s1", "s2")}, "flags": {"t:IoT", "t:Application", "t:Unknown"}},
}


def run(p):
    res = AGENT.run()
    runid = res.get("run")
    first, nxt = [], None
    if runid:
        b, _c = payload.drill("certificate", {"run": runid, "section": "certs", "sort": "near", "limit": 50}, SECTIONS)
        first, nxt = b.get("top") or [], (b.get("page") or {}).get("next")
    m = res.get("metrics") or {}
    small = {k: v for k, v in res.items() if k != "tag_actions"}       # tag_actions stay server-side
    # "applied" ground truth: which of our tags exist in navi.db right now
    return payload.response(
        summary=m, top=first,
        total_=payload.total((m.get("expired") or 0) + (m.get("failing") or 0)),
        page={"next": nxt, "start": 0, "limit": 50},
        drill={"action": "drill", "run": runid, "section": "certs", "sections": sorted(SECTIONS)},
        tag={"key": "dates", "count": len(res.get("tag_actions") or [])},
        agent=AGENT.meta(), result=small,
        # plain + Settings → Test run names; `base` lets the page match either
        tags_present=[dict(t, base=tagname.base(t.get("tag_key")))
                      for t in db.tags_present(tagname.names(*CATEGORIES))]), 200


def drill(p):
    return payload.drill("certificate", p, SECTIONS)


def dates(p):
    """Read: the tag values (expiry dates) of a filtered certificate view ({run, filter, q}) —
    capped at 5,000 dates — or, for {run, values}, how many certificates and assets those
    dates cover. Dates are strings, never asset uuids."""
    run = (p or {}).get("run")
    if not payload.STORE.run_info(run, "certificate"):
        return {"ok": False, "expired": True, "error": "this run is gone — press ▶ Run again"}, 200
    vals = p.get("values")
    if isinstance(vals, list):
        vals = [str(v) for v in vals if isinstance(v, str) and len(v) < 40][:5000]
        n, assets = payload.STORE.count_any(run, "certs", ["v:" + v for v in vals])
        return {"ok": True, "values": len(vals), "certs": n, "assets": assets}, 200
    flt = p.get("filter") or []
    if isinstance(flt, str):
        flt = [flt]
    ok = SECTIONS["certs"]["flags"]
    if not isinstance(flt, list) or not all(isinstance(f, str) and ok(f) for f in flt):
        return {"ok": False, "error": "unknown filter"}, 400
    q = p.get("q") if isinstance(p.get("q"), str) else ""
    out = payload.STORE.distinct_keys(run, "certs", flt, q[:200].strip(), cap=5000)
    return {"ok": True, "values": out["keys"], "truncated": out["truncated"]}, 200


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
        # the date's set (raw not_valid_after strings → assets), computed here and paged
        js = navi_cli.tag_set(a["category"], a["value"], sql=a["query"].rstrip(";"), agent="certificate")
        if any(j.get("job_id") is not None or j.get("ok") for j in js):
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


ACTIONS = {"run": run, "drill": drill, "dates": dates, "tags_apply": tags_apply, "tags_issues": tags_issues}
