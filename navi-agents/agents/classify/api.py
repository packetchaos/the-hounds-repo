"""Asset Classification — HTTP actions.

run   — classify every asset; return per-class summary + the full asset list.
assets— drill one class → its assets.
tag   — GATED write of Class:<type[ - subtype]> tags for a class (same navi path as
        every other agent). Closes the loop: a classified asset becomes an ownable one.
"""
import re

from core import navi_cli, classify as _classify, topology as _topology
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


def run(p):
    return {"ok": True, "agent": AGENT.meta(), "result": AGENT.run(),
            "writes_enabled": navi_cli.writes_enabled()}, 200


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
    return {"ok": True, "cls": cls, "sub": sub, "assets": rows, "count": len(rows)}, 200


def signals(p):
    """OS Signals — detected classification suggestions (the untagged assets), grouped
    into taggable cohorts. Mirrors the IoT squad's detect → tag flow."""
    only = (p or {}).get("all") is not True
    return {"ok": True, "result": _classify.os_signals(only_untagged=only)}, 200


def os_breakdown(p):
    """OS families → versions for the two-pie OS explorer (untagged assets)."""
    only = (p or {}).get("all") is not True
    return {"ok": True, "result": _classify.os_breakdown(only_untagged=only)}, 200


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
    if p.get("uuids"):
        uuids = [str(u) for u in p["uuids"] if u and isinstance(u, str)]
    else:
        m = _topology.members(cls=p.get("cls"), sub=p.get("sub"), software=p.get("software"),
                              version=p.get("version"), subnet=p.get("subnet"), cap=100000)
        uuids = [a["uuid"] for a in m.get("assets", []) if a.get("uuid")]
    if not uuids:
        return {"ok": False, "error": "no assets for that cohort"}, 400
    tag_value = f"{facet}: {value}"

    def _q(chunk):
        return ("SELECT DISTINCT asset_uuid FROM vulns WHERE asset_uuid IN ("
                + ",".join("'" + str(u).replace("'", "''") + "'" for u in chunk) + ")")

    # navi's tag endpoint caps at ~1999 UUIDs per call and a single huge IN(...) query
    # can overflow the arg-length limit (the query gets truncated → unclosed bracket →
    # the write fails). So chunk the UUIDs into cap-sized batches, one navi job each.
    cap = navi_cli.UUID_CAP
    chunks = [uuids[i:i + cap] for i in range(0, len(uuids), cap)]
    jobs = [navi_cli.tag("Asset Inventory", tag_value, query=_q(c), remove=False, agent="classify")
            for c in chunks]
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


ACTIONS = {"run": run, "assets": assets, "tag": tag, "tree": tree, "members": members,
           "signals": signals, "os_breakdown": os_breakdown, "os_plan": os_plan}
