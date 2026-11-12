"""Asset Classification — HTTP actions.

run   — classify every asset; return the per-class summary + a drill handle (build 464:
        the asset list stays on the server — core.payload's result store).
drill — read; page / search one class's assets on the server (filter cls:<class>).
assets— drill one class → its assets (capped list; kept for server-side callers).
tag   — GATED write of Class:<type[ - subtype]> tags for a class (same navi path as
        every other agent). Closes the loop: a classified asset becomes an ownable one.
"""
import re

from core import navi_cli, payload, classify as _classify, topology as _topology
from .agent import ClassifyAgent
from core.gates import confirmed

AGENT = ClassifyAgent()

# OS-family words the prompt parser recognizes → canonical family
_FAMILY_ALIASES = {
    "windows": "Windows", "win": "Windows",
    "linux": "Linux", "ubuntu": "Linux", "debian": "Linux", "centos": "Linux",
    "redhat": "Linux", "red hat": "Linux", "rhel": "Linux", "fedora": "Linux",
    "rocky": "Linux", "alma": "Linux", "suse": "Linux", "oracle linux": "Linux",
    "amazon linux": "Linux",
    "mac": "macOS", "macos": "macOS", "osx": "macOS", "os x": "macOS", "apple": "macOS",
}


def _parse_os_prompt(prompt):
    """Pull the tagging intent out of a plain-English prompt — no model needed:
      • confidence floor  ('over 75%', 'at least 80', '>=90', '90%+', 'high confidence')
      • OS-family filter   (mentions of windows / linux / mac restrict the cohorts)
      • grouping           ('by family' collapses to Windows/Linux/macOS; otherwise the
                            specific OS label like 'Windows Server 2016' / 'Ubuntu')."""
    s = (prompt or "").lower()
    thr = None
    m = (re.search(r"(?:>=|≥|>|over|above|greater than|at least|no less than|"
                   r"minimum(?:\s+of)?|min)\s*(\d{1,3})\s*%?", s)
         or re.search(r"(\d{1,3})\s*%?\s*(?:\+|or\s+(?:higher|more|greater|above|better))", s)
         or re.search(r"confidence\D{0,12}(\d{1,3})", s))
    if m:
        thr = max(0, min(100, int(m.group(1))))
    elif "high confidence" in s:
        thr = 80
    elif "medium confidence" in s:
        thr = 50
    fams = set()
    for alias, fam in _FAMILY_ALIASES.items():
        if re.search(r"\b" + re.escape(alias) + r"\b", s):
            fams.add(fam)
    group = "family" if re.search(r"\bfamil(?:y|ies)\b", s) else "detailed"
    if re.search(r"\b(?:exact|detailed|version|versions|specific|granular)\b", s):
        group = "detailed"
    return {"threshold": thr, "families": sorted(fams), "group": group}


def os_plan(p):
    """Interpret an OS-tagging prompt (e.g. 'tag all my assets by OS with a confidence over
    75%') into taggable cohorts, sourced from plugin 11936 (OS Identification → OS + a
    confidence %). No model key required — the intent is parsed locally. Returns the proposed
    plan for preview; applying it reuses the existing gated `tag` action (facet 'OS')."""
    p = p or {}
    prompt = (p.get("prompt") or "").strip()
    parsed = _parse_os_prompt(prompt)
    thr = parsed["threshold"]
    if thr is None:
        thr = int(p["threshold"]) if str(p.get("threshold") or "").isdigit() else 0
    pf = p.get("families")
    fams = set(parsed["families"]) or set(f for f in (pf if isinstance(pf, list) else []) if isinstance(f, str))
    group = p.get("group") or parsed["group"]
    rows = _classify.os_confidence()
    kept = [r for r in rows if r["confidence"] >= thr and (not fams or r["family"] in fams)]
    cohorts = {}
    for r in kept:
        val = r["family"] if group == "family" else r["os_label"]
        c = cohorts.setdefault(val, {"value": val, "facet": "OS", "family": r["family"],
                                     "uuids": [], "confs": []})
        c["uuids"].append(r["uuid"])
        c["confs"].append(r["confidence"])
    out = [{"value": v, "facet": "OS", "family": c["family"], "count": len(c["uuids"]),
            "uuids": c["uuids"], "conf_min": min(c["confs"]), "conf_max": max(c["confs"])}
           for v, c in cohorts.items()]
    out.sort(key=lambda x: -x["count"])
    if p.get("_with_uuids") is not True:
        # build 464: counts only — a cohort is tagged by KEY {plan:{…the same inputs…, value}}
        # and the server rebuilds its uuids (_plan_uuids); no uuid arrays reach the page
        out = [{k: v for k, v in c.items() if k != "uuids"} for c in out]
    return {"ok": True, "prompt": prompt, "threshold": thr, "families": sorted(fams),
            "group": group, "scanned": len(rows),
            "with_confidence": sum(1 for r in rows if r["confidence"] > 0),
            "matched": len(kept), "cohorts": out,
            "note": ("No OS-fingerprinted assets meet that confidence floor — lower the "
                     "threshold or run an OS-identification scan." if not out else None)}, 200


def tree(p):
    """The zoomable-sunburst topology tree — Class/Subnet → Sub → Software/Docker →
    Version, sized by asset count, plus the virtualization narrative."""
    by = (p or {}).get("by") or "class"
    return {"ok": True, "result": _topology.tree(by=by if by in ("class", "subnet") else "class")}, 200


def members(p):
    """Lazy asset list at any sunburst node (leaf → Argos)."""
    p = p or {}
    return {"ok": True, **_topology.members(cls=p.get("cls"), sub=p.get("sub"),
                                            software=p.get("software"), version=p.get("version"),
                                            subnet=p.get("subnet"))}, 200


DRILL_MAX = 5000      # rows a class drill-down ships (≈1.5 MB); the class tag covers the whole class


def _cls_flag_ok(f):
    return f.split(":", 1)[0] in ("cls", "sub") and len(f) < 160


SECTIONS = {"assets": {"sorts": {}, "flags": _cls_flag_ok}}


def _risk_key(r):
    return (not r.get("kev"), not r.get("critical"), str(r.get("hostname") or "~").lower(), str(r.get("uuid") or ""))


def _publish(rows):
    """Every classified asset → the result store (one section), riskiest first within each
    class; flags cls:<class> / sub:<sub-type>; search over host, IP, sub-type, evidence."""
    W = payload.STORE.begin("classify")
    W.section("assets")
    try:
        for r in sorted(rows, key=_risk_key):
            sub = r.get("sub") or r.get("reason") or "—"
            W.add("assets", r, uid=r.get("uuid"), rk=r.get("uuid"),
                  flags=["cls:" + str(r.get("cls")), "sub:" + str(sub)],
                  text=" ".join(str(v or "") for v in (r.get("hostname"), r.get("ip"), r.get("sub"),
                                                         r.get("reason"), r.get("method"), r.get("uuid"))))
    except BaseException:
        W.close(ok=False)
        raise
    W.close()
    return W.run


def run(p):
    """Payload contract (build 464): the run ships the classes, glance and stats plus a drill
    handle — never the per-asset list (150k assets was a 49 MB answer). The drill-down pages
    and searches one class on the server (`drill`); "select all" tags by key {run, cls, q}."""
    res = AGENT.run()
    small = {k: v for k, v in res.items() if k != "assets"}
    small["assets_total"] = len(res.get("assets") or [])
    try:
        small["drill"] = {"action": "drill", "run": _publish(res.get("assets") or []), "section": "assets"}
    except Exception as e:                 # the summary still works; the drill-down falls back to `assets`
        small["drill_error"] = str(e)
    return {"ok": True, "agent": AGENT.meta(), "result": small,
            "writes_enabled": navi_cli.writes_enabled()}, 200


def drill(p):
    return payload.drill("classify", p, SECTIONS)


def _run_uuids(key):
    """{run, cls, q?} → the exact asset set of that class (and search) in the stored run."""
    if not isinstance(key, dict) or not isinstance(key.get("cls"), str) or not key.get("cls"):
        return None
    if not payload.STORE.run_info(key.get("run"), "classify"):
        return None
    q = key.get("q") if isinstance(key.get("q"), str) else ""
    return payload.STORE.uids(key["run"], "assets", ["cls:" + key["cls"]], q.strip()[:200])


def assets(p):
    p = p or {}
    res = AGENT.result or AGENT.run()
    cls = (p.get("cls") or "").strip()
    sub = (p.get("sub") or "").strip()
    rows = res.get("assets", [])
    if cls:
        rows = [r for r in rows if r["cls"] == cls]
    if sub:
        rows = [r for r in rows if (r.get("sub") or r.get("reason") or "—") == sub]
    count = len(rows)
    try:
        lim = max(1, min(int(p.get("limit") or DRILL_MAX), DRILL_MAX))
    except (TypeError, ValueError):
        lim = DRILL_MAX
    if count > lim:
        # the riskiest first (KEV, then critical), so what's shipped is what matters
        rows = sorted(rows, key=lambda r: (not r.get("kev"), not r.get("critical")))[:lim]
    return {"ok": True, "cls": cls, "sub": sub, "assets": rows, "count": count,
            "shown": len(rows), "truncated": count > len(rows)}, 200


def signals(p):
    """OS Signals — detected classification suggestions (the untagged assets), grouped
    into taggable cohorts. Mirrors the IoT squad's detect → tag flow. Build 464: counts and
    samples only — a cohort is tagged by KEY {sig:{facet, value, all?}} (_sig_uuids)."""
    only = (p or {}).get("all") is not True
    res = dict(_classify.os_signals(only_untagged=only))
    res["cohorts"] = [{k: v for k, v in c.items() if k != "uuids"} for c in (res.get("cohorts") or [])]
    return {"ok": True, "result": res}, 200


def _sig_uuids(key):
    """The asset set behind an OS Signals cohort (its DETECTED facet + value), rebuilt server-side."""
    if not isinstance(key, dict) or not isinstance(key.get("facet"), str) or not isinstance(key.get("value"), str):
        return None
    res = _classify.os_signals(only_untagged=key.get("all") is not True)
    for c in res.get("cohorts") or []:
        if c.get("facet") == key["facet"] and c.get("value") == key["value"]:
            return list(c.get("uuids") or [])
    return []


def _plan_uuids(key):
    """The asset set behind one cohort of an OS plan — os_plan re-run with the same inputs."""
    if not isinstance(key, dict) or not isinstance(key.get("value"), str):
        return None
    q = {k: key.get(k) for k in ("prompt", "threshold", "families", "group") if key.get(k) is not None}
    q["_with_uuids"] = True
    o, _st = os_plan(q)
    for c in o.get("cohorts") or []:
        if c.get("value") == key["value"]:
            return list(c.get("uuids") or [])
    return []


def os_breakdown(p):
    """OS families → versions for the two-pie OS explorer (untagged assets)."""
    only = (p or {}).get("all") is not True
    res = _classify.os_breakdown(only_untagged=only)
    # build 464: counts only — no uuid arrays (138k uuids, twice, was 11 MB). A tag sends the
    # KEY {os:{family, version?, all?}} and the server rebuilds the exact set (_os_uuids).
    out = dict(res)
    out["families"] = [{**{k: v for k, v in f.items() if k != "uuids"},
                        "versions": [{k: v for k, v in x.items() if k != "uuids"} for x in (f.get("versions") or [])]}
                       for f in (res.get("families") or [])]
    return {"ok": True, "result": out}, 200


def _os_uuids(key):
    """The asset set behind an OS explorer node, rebuilt server-side from the same breakdown."""
    if not isinstance(key, dict) or not isinstance(key.get("family"), str):
        return None
    res = _classify.os_breakdown(only_untagged=key.get("all") is not True)
    for f in res.get("families") or []:
        if f.get("family") != key["family"]:
            continue
        if key.get("version") is None:
            return list(f.get("uuids") or [])
        for v in f.get("versions") or []:
            if v.get("name") == key.get("version"):
                return list(v.get("uuids") or [])
    return []


def tag(p):
    """Gated write of the unified inventory scheme (scheme A): category
    'Asset Inventory', value '<Facet>: <Value>' (Class / OS / Device Type / App / Cloud).
    Targets a cohort by explicit `uuids` (OS Signals) OR by the path (cls/sub/…)."""
    p = p or {}
    if not confirmed(p):
        return {"ok": False, "error": "confirm=true required to write tags"}, 400
    facet = (p.get("facet") or "Class").strip()
    value = (p.get("value") or p.get("cls") or "").strip()
    if not value:
        return {"ok": False, "error": "value required"}, 400
    if p.get("uuids") is not None and not isinstance(p.get("uuids"), list):
        return {"ok": False, "error": "uuids must be a list"}, 400
    if p.get("sig") is not None or p.get("plan") is not None:
        uuids = _sig_uuids(p["sig"]) if p.get("sig") is not None else _plan_uuids(p["plan"])
        if uuids is None:
            return {"ok": False, "error": "malformed cohort key"}, 400
    elif p.get("set") is not None:
        uuids = _run_uuids(p.get("set"))
        if uuids is None:
            return {"ok": False, "expired": True,
                    "error": "that run's rows are no longer on the server — press ▶ Run again"}, 400
    elif p.get("os") is not None:
        uuids = _os_uuids(p.get("os"))
        if uuids is None:
            return {"ok": False, "error": "os must be {family, version?}"}, 400
    elif p.get("uuids"):
        uuids = [str(u) for u in p["uuids"] if u and isinstance(u, str)]
    else:
        m = _topology.members(cls=p.get("cls"), sub=p.get("sub"), software=p.get("software"),
                              version=p.get("version"), subnet=p.get("subnet"), cap=None)   # unbounded (build 464)
        uuids = [a["uuid"] for a in m.get("assets", []) if a.get("uuid")]
    if not uuids:
        return {"ok": False, "error": "no assets for that cohort"}, 400
    tag_value = f"{facet}: {value}"

    # The classification is computed in Python (core.classify); the cohort is paged by
    # core.navi_cli.tag_set: ≤1,999 UUIDs per navi job (a tag series above), add-only.
    jobs = navi_cli.tag_set("Asset Inventory", tag_value, uuids=uuids, col="asset_uuid", table="vulns",
                            agent="classify")
    chunks = jobs
    job_ids = [j.get("job_id") for j in jobs if j.get("job_id") is not None]
    first = jobs[0] if jobs else {}
    ok = all(j.get("ok") or j.get("queued") for j in jobs) if jobs else False
    return {"ok": ok, "queued": any(j.get("queued") for j in jobs),
            "job_id": job_ids[0] if job_ids else first.get("job_id"),
            "job_ids": job_ids, "chunks": len(chunks),
            "message": (f"queued {len(chunks)} batch(es) for {len(uuids)} assets"
                        if len(chunks) > 1 else first.get("message")),
            "value": "Asset Inventory : " + tag_value, "asset_count": len(uuids),
            "writes_enabled": navi_cli.writes_enabled(),
            "write_gate_reason": navi_cli.write_gate_reason()}, 200


ACTIONS = {"run": run, "drill": drill, "assets": assets, "tag": tag, "tree": tree, "members": members,
           "signals": signals, "os_breakdown": os_breakdown, "os_plan": os_plan}
