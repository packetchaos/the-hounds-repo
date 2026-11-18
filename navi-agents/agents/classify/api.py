"""Asset Classification — HTTP actions.

run   — classify every asset; return the per-class summary + a drill handle (build 464:
        the asset list stays on the server — core.payload's result store).
drill — read; page / search one class's assets on the server (filter cls:<class>).
assets— drill one class → its assets (capped list; kept for server-side callers).
tag   — GATED write of Class:<type[ - subtype]> tags for a class (same navi path as
        every other agent). Closes the loop: a classified asset becomes an ownable one.

Tag filter (build 489): every action takes the page's {tag_scope:{key, value}} and works over
only that tag's assets (core/tagscope). Each asset's class / sub / owned / KEV / critical is the
same as in the whole estate; only the population changes. A tag run's rows live in their own
result-store hound (classify_t_<hash>, the newest TAG_RUNS tags kept), so tag runs never evict
the estate's run, and a drill / "select all" can't mix the two. A write from a tag view re-reads
the tag's assets from navi.db and never touches an asset outside it.
"""
import hashlib
import re

from core import navi_cli, payload, tagscope, classify as _classify, topology as _topology
from .agent import ClassifyAgent
from core.gates import confirmed

AGENT = ClassifyAgent()
TAG_RUNS = tagscope.MAX_TAGS          # tag views whose drillable rows stay on the server
_TAG_PREFIX = "classify_t_"


def _scope(p):
    """(key, value) of the request's tag scope, or None for the whole estate."""
    k, v = tagscope.parse(p or {})
    return (k, v) if k else None


def _hound(scope):
    """The result-store hound a run of this scope is filed under — the estate keeps 'classify'
    (unchanged); each tag gets its own, so tag runs never prune the estate's (or each other's)."""
    if not scope:
        return "classify"
    h = hashlib.sha1((scope[0] + "\x00" + scope[1]).encode("utf-8")).hexdigest()[:12]
    return _TAG_PREFIX + h


def _prune_tag_runs(keep=None, store=None):
    """Keep the newest `keep` tag scopes' runs (like the page cache's 5 tag views)."""
    keep = TAG_RUNS if keep is None else keep
    store = store or payload.STORE
    con = store._connect()
    try:
        rows = con.execute("SELECT hound, MAX(built_at) b FROM runs WHERE substr(hound,1,?)=? "
                           "GROUP BY hound ORDER BY b DESC", (len(_TAG_PREFIX), _TAG_PREFIX)).fetchall()
        old = [r[0] for r in rows[keep:]]
        runs = [r[0] for h in old for r in con.execute("SELECT run FROM runs WHERE hound=?", (h,))]
    finally:
        con.close()
    for r in runs:
        store.drop(r)


def _in_scope(uuids, scope):
    """A write's asset set, cut to the tag's assets re-read from navi.db (never the browser's)."""
    if not scope:
        return uuids
    keep = tagscope.uuids(scope[0], scope[1])
    return [u for u in uuids if u in keep]


def _scoped(res, scope):
    """Add "scope" to a scoped result (the whole estate's result is left exactly as it was)."""
    if scope:
        res["scope"] = tagscope.describe(scope[0], scope[1])
    return res

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
    scope = _scope(p)
    rows = _classify.os_confidence(scope=scope) if scope else _classify.os_confidence()
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
    return _scoped({"ok": True, "prompt": prompt, "threshold": thr, "families": sorted(fams),
            "group": group, "scanned": len(rows),
            "with_confidence": sum(1 for r in rows if r["confidence"] > 0),
            "matched": len(kept), "cohorts": out,
            "note": ("No OS-fingerprinted assets meet that confidence floor — lower the "
                     "threshold or run an OS-identification scan." if not out else None)}, scope), 200


def tree(p):
    """The zoomable-sunburst topology tree — Class/Subnet → Sub → Software/Docker →
    Version, sized by asset count, plus the virtualization narrative."""
    by = (p or {}).get("by") or "class"
    by = by if by in ("class", "subnet") else "class"
    scope = _scope(p)
    if not scope:
        return {"ok": True, "result": _topology.tree(by=by)}, 200
    return {"ok": True, "result": _scoped(_topology.tree(by=by, scope=scope), scope)}, 200


def members(p):
    """Lazy asset list at any sunburst node (leaf → Argos)."""
    p = p or {}
    scope = _scope(p)
    kw = {"scope": scope} if scope else {}
    return _scoped({"ok": True, **_topology.members(cls=p.get("cls"), sub=p.get("sub"),
                                                    software=p.get("software"), version=p.get("version"),
                                                    subnet=p.get("subnet"), **kw)}, scope), 200


DRILL_MAX = 5000      # rows a class drill-down ships (≈1.5 MB); the class tag covers the whole class


def _cls_flag_ok(f):
    return f.split(":", 1)[0] in ("cls", "sub") and len(f) < 160


SECTIONS = {"assets": {"sorts": {}, "flags": _cls_flag_ok}}


def _risk_key(r):
    return (not r.get("kev"), not r.get("critical"), str(r.get("hostname") or "~").lower(), str(r.get("uuid") or ""))


def _publish(rows, scope=None):
    """Every classified asset → the result store (one section), riskiest first within each
    class; flags cls:<class> / sub:<sub-type>; search over host, IP, sub-type, evidence.
    A tag run goes under its own hound (_hound) with its scope in the run's meta."""
    W = payload.STORE.begin(_hound(scope))
    if scope:
        W.meta["scope"] = {"key": scope[0], "value": scope[1]}
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
    if scope:
        _prune_tag_runs()
    return W.run


def run(p):
    """Payload contract (build 464): the run ships the classes, glance and stats plus a drill
    handle — never the per-asset list (150k assets was a 49 MB answer). The drill-down pages
    and searches one class on the server (`drill`); "select all" tags by key {run, cls, q}."""
    scope = _scope(p)
    if scope:
        # a tag view: computed directly — AGENT.result stays the whole estate's (the `assets`
        # action and the status card read it)
        if not tagscope.count(scope[0], scope[1]):
            return {"ok": False, "error": f"no assets carry the tag {scope[0]} : {scope[1]} in navi.db — "
                                          "check the name, or run navi update assets"}, 200
        res = _classify.classify(None, glance=True, scope=scope)
    else:
        res = AGENT.run()
    small = {k: v for k, v in res.items() if k != "assets"}
    small["assets_total"] = len(res.get("assets") or [])
    small["device_types"] = _classify.DEVICE_TYPE_LABELS
    try:
        small["drill"] = {"action": "drill", "run": _publish(res.get("assets") or [], scope), "section": "assets"}
    except Exception as e:                 # the summary still works; the drill-down falls back to `assets`
        small["drill_error"] = str(e)
    return {"ok": True, "agent": AGENT.meta(), "result": _scoped(small, scope),
            "writes_enabled": navi_cli.writes_enabled()}, 200


def drill(p):
    """Pages a stored run — of the request's own scope only (a tag run under the estate, or the
    estate's under a tag, is "no longer on the server")."""
    return payload.drill(_hound(_scope(p)), p, SECTIONS)


def _run_uuids(key, scope=None):
    """{run, cls, q?} → the exact asset set of that class (and search) in the stored run —
    which must be a run of the same scope as the request."""
    if not isinstance(key, dict) or not isinstance(key.get("cls"), str) or not key.get("cls"):
        return None
    if not payload.STORE.run_info(key.get("run"), _hound(scope)):
        return None
    q = key.get("q") if isinstance(key.get("q"), str) else ""
    return payload.STORE.uids(key["run"], "assets", ["cls:" + key["cls"]], q.strip()[:200])


def assets(p):
    p = p or {}
    scope = _scope(p)
    res = _classify.classify(None, scope=scope) if scope else (AGENT.result or AGENT.run())
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
    return _scoped({"ok": True, "cls": cls, "sub": sub, "assets": rows, "count": count,
                    "shown": len(rows), "truncated": count > len(rows)}, scope), 200


def signals(p):
    """OS Signals — detected classification suggestions (the untagged assets), grouped
    into taggable cohorts. Mirrors the IoT squad's detect → tag flow. Build 464: counts and
    samples only — a cohort is tagged by KEY {sig:{facet, value, all?}} (_sig_uuids)."""
    only = (p or {}).get("all") is not True
    scope = _scope(p)
    kw = {"scope": scope} if scope else {}
    res = dict(_classify.os_signals(only_untagged=only, **kw))
    res["cohorts"] = [{k: v for k, v in c.items() if k != "uuids"} for c in (res.get("cohorts") or [])]
    res["device_types"] = _classify.DEVICE_TYPE_LABELS
    return {"ok": True, "result": _scoped(res, scope)}, 200


def _sig_uuids(key, scope=None):
    """The asset set behind an OS Signals cohort (its DETECTED facet + value), rebuilt server-side."""
    if not isinstance(key, dict) or not isinstance(key.get("facet"), str) or not isinstance(key.get("value"), str):
        return None
    kw = {"scope": scope} if scope else {}
    res = _classify.os_signals(only_untagged=key.get("all") is not True, **kw)
    for c in res.get("cohorts") or []:
        if c.get("facet") == key["facet"] and c.get("value") == key["value"]:
            return list(c.get("uuids") or [])
    return []


def _plan_uuids(key, scope=None):
    """The asset set behind one cohort of an OS plan — os_plan re-run with the same inputs."""
    if not isinstance(key, dict) or not isinstance(key.get("value"), str):
        return None
    q = {k: key.get(k) for k in ("prompt", "threshold", "families", "group") if key.get(k) is not None}
    q["_with_uuids"] = True
    if scope:
        q["tag_scope"] = {"key": scope[0], "value": scope[1]}
    o, _st = os_plan(q)
    for c in o.get("cohorts") or []:
        if c.get("value") == key["value"]:
            return list(c.get("uuids") or [])
    return []


def os_breakdown(p):
    """OS families → versions for the two-pie OS explorer (untagged assets)."""
    only = (p or {}).get("all") is not True
    scope = _scope(p)
    res = _classify.os_breakdown(only_untagged=only, scope=scope) if scope else _classify.os_breakdown(only_untagged=only)
    # build 464: counts only — no uuid arrays (138k uuids, twice, was 11 MB). A tag sends the
    # KEY {os:{family, version?, all?}} and the server rebuilds the exact set (_os_uuids).
    out = dict(res)
    out["families"] = [{**{k: v for k, v in f.items() if k != "uuids"},
                        "versions": [{k: v for k, v in x.items() if k != "uuids"} for x in (f.get("versions") or [])]}
                       for f in (res.get("families") or [])]
    return {"ok": True, "result": _scoped(out, scope)}, 200


def _os_uuids(key, scope=None):
    """The asset set behind an OS explorer node, rebuilt server-side from the same breakdown."""
    if not isinstance(key, dict) or not isinstance(key.get("family"), str):
        return None
    kw = {"scope": scope} if scope else {}
    res = _classify.os_breakdown(only_untagged=key.get("all") is not True, **kw)
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
    Targets a cohort by explicit `uuids` (OS Signals) OR by the path (cls/sub/…).
    From a tag view (tag_scope) every cohort is rebuilt over that tag's assets and the final set
    is cut to the tag's assets re-read from navi.db — a write never leaves the tag."""
    p = p or {}
    scope = _scope(p)
    if not confirmed(p):
        return {"ok": False, "error": "confirm=true required to write tags"}, 400
    facet = (p.get("facet") or "Class").strip()
    value = (p.get("value") or p.get("cls") or "").strip()
    if not value:
        return {"ok": False, "error": "value required"}, 400
    if p.get("uuids") is not None and not isinstance(p.get("uuids"), list):
        return {"ok": False, "error": "uuids must be a list"}, 400
    if p.get("sig") is not None or p.get("plan") is not None:
        uuids = _sig_uuids(p["sig"], scope) if p.get("sig") is not None else _plan_uuids(p["plan"], scope)
        if uuids is None:
            return {"ok": False, "error": "malformed cohort key"}, 400
    elif p.get("set") is not None:
        uuids = _run_uuids(p.get("set"), scope)
        if uuids is None:
            return {"ok": False, "expired": True,
                    "error": "that run's rows are no longer on the server — press ▶ Run again"}, 400
    elif p.get("os") is not None:
        uuids = _os_uuids(p.get("os"), scope)
        if uuids is None:
            return {"ok": False, "error": "os must be {family, version?}"}, 400
    elif p.get("uuids"):
        uuids = [str(u) for u in p["uuids"] if u and isinstance(u, str)]
    else:
        kw = {"scope": scope} if scope else {}
        m = _topology.members(cls=p.get("cls"), sub=p.get("sub"), software=p.get("software"),
                              version=p.get("version"), subnet=p.get("subnet"), cap=None, **kw)   # unbounded (build 464)
        uuids = [a["uuid"] for a in m.get("assets", []) if a.get("uuid")]
    uuids = _in_scope(uuids, scope)
    if not uuids:
        return {"ok": False, "error": "no assets for that cohort" + (
            f" among the assets tagged {scope[0]} : {scope[1]}" if scope else "")}, 400
    tag_value = f"{facet}: {value}"

    # The classification is computed in Python (core.classify); the cohort is paged by
    # core.navi_cli.tag_set: ≤1,999 UUIDs per navi job (a tag series above), add-only.
    # over assets.uuid (tag_set's default): a --query over vulns.asset_uuid silently drops every
    # asset with no findings (a cloud-connector asset, a freshly discovered host)
    jobs = navi_cli.tag_set("Asset Inventory", tag_value, uuids=uuids, agent="classify")
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
            "write_gate_reason": navi_cli.write_gate_reason(),
            **({"scope": tagscope.describe(scope[0], scope[1])} if scope else {})}, 200


ACTIONS = {"run": run, "drill": drill, "assets": assets, "tag": tag, "tree": tree, "members": members,
           "signals": signals, "os_breakdown": os_breakdown, "os_plan": os_plan}
