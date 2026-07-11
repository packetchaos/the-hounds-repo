"""AI Navi Contract — turn the captured Tagging log + human policy into an
autonomous workflow.

A Contract captures the human's *needs* (per-agent plain-English policy, ACR
rules, wait periods, a schedule) so the loop can decide what to tag instead of
the per-row HITL gate. Each cycle:

  1. (optional) kick `navi update assets` + `navi update vulns` in the background
     and DON'T wait on them,
  2. compute a PLAN — for every enabled agent, run discovery, apply the human's
     policy (or a risk-weighted top-N when no policy is given), and list the tags
     + ACR changes it would make,
  3. if the contract is ARMED (and NAVI_ALLOW_WRITES is set) execute the plan via
     the background tag queue, honoring wait periods,
  4. run a light QA check (did tags land / any errors) and append to the loop log.

Storage is session-memory plus optional JSON files under ./contracts (save/load).
Writes still pass through the same NAVI_ALLOW_WRITES gate as everything else.
"""
import json
import os
import subprocess
import threading
import time
from importlib import import_module

from core import navi_cli, tagq

try:
    from core import llm
except Exception:                                    # pragma: no cover
    llm = None

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONTRACT_DIR = os.environ.get("CONTRACT_DIR", os.path.join(HERE, "contracts"))

# agents the contract can orchestrate (id -> default category + human label)
TAGGERS = ["iot_squad", "customapp", "exproute", "eol", "software", "ai", "identity",
           "mitre", "scan_eval", "certificate",
           "cisakev", "postquantum", "agentgroup"]

_LOCK = threading.Lock()
_LOOP_LOG = []                                        # cycle history (session-only)
_OPTIMIZED = False                                    # `navi config optimize` fired this run?
_SCHED = {"thread": None, "stop": False, "next_run": None}


# --------------------------------------------------------------------------- #
#  contract document
# --------------------------------------------------------------------------- #
def default_contract() -> dict:
    return {
        "name": "navi-contract",
        "created": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "armed": False,
        "schedule_hours": 4,
        "wait_minutes": 0,
        "navi_update": True,                          # kick navi update assets/vulns each cycle
        "optimize": True,                             # run `navi config optimize` once (fast tagging)
        "defaults": {"top_n": 50, "rank": "risk"},
        "acr": [],                                    # [{category,value,score,mod,reasons,note}]
        # Garmr / tag-removal phase: chosen tags are removed at the TOP of a cycle,
        # then a forced pause + navi update, then the tagging workflow re-runs.
        "removal": {"enabled": False, "tags": [],     # [{category,value}]
                    "pause_minutes": 30, "navi_update": True},
        "agents": {a: {"enabled": True, "logic": ""} for a in TAGGERS},
    }


_CURRENT = default_contract()


def current() -> dict:
    return _CURRENT


def set_contract(doc: dict) -> dict:
    global _CURRENT
    base = default_contract()
    base.update({k: v for k, v in (doc or {}).items() if k in base})
    # merge agent map so missing agents keep defaults
    ag = base.get("agents", {})
    for a in TAGGERS:
        ag.setdefault(a, {"enabled": True, "logic": ""})
    base["agents"] = ag
    rem = base.get("removal") or {}
    rem.setdefault("enabled", False); rem.setdefault("tags", [])
    rem.setdefault("pause_minutes", 30); rem.setdefault("navi_update", True)
    base["removal"] = rem
    _CURRENT = base
    return _CURRENT


def add_removals(tags) -> dict:
    """Merge a list of {category,value} tags into the contract's removal list and
    enable the removal phase. Used by the Garmr tag-removal agent's 'add to contract'."""
    rem = _CURRENT.setdefault("removal", {"enabled": False, "tags": [],
                                          "pause_minutes": 30, "navi_update": True})
    have = {(t.get("category"), t.get("value")) for t in rem.get("tags", [])}
    added = 0
    for t in (tags or []):
        key = (t.get("category"), t.get("value"))
        if key[0] and key[1] and key not in have:
            rem["tags"].append({"category": t.get("category"), "value": t.get("value")})
            have.add(key); added += 1
    if rem["tags"]:
        rem["enabled"] = True
    return {"ok": True, "added": added, "total": len(rem["tags"]), "removal": rem}


def build_from_log(jobs=None) -> dict:
    """Seed a contract from the captured Tagging log — which agents the human used
    and the ACR changes they made become the starting policy.

    `jobs` defaults to the live in-memory tagging queue. Pass a list of job-like
    dicts (e.g. parsed from an exported tag-log CSV: agent/category/value/detail)
    to build the contract from a portable record that survives server restarts.
    """
    doc = default_contract()
    if jobs is None:
        jobs = tagq.list_jobs()
    used = {j.get("agent") for j in jobs if j.get("agent")}
    for a in TAGGERS:
        doc["agents"][a]["enabled"] = (a in used) or not used  # if nothing logged, enable all
    # carry forward ACR changes seen in the log as explicit ACR rules
    seen = set()
    for j in jobs:
        if j.get("agent") == "acr" and j.get("value"):
            key = (j.get("category"), j.get("value"))
            if key in seen:
                continue
            seen.add(key)
            # detail looks like "score=8 (set)"
            score, mod = 8, "set"
            d = j.get("detail", "")
            try:
                if "score=" in d:
                    score = float(d.split("score=")[1].split(" ")[0])
                if "(" in d:
                    mod = d.split("(")[1].split(")")[0]
            except Exception:
                pass
            doc["acr"].append({"category": j.get("category", "Business Tier"),
                               "value": j.get("value"), "score": score, "mod": mod,
                               "reasons": ["business"], "note": "from tagging log"})
    return set_contract(doc)


# --------------------------------------------------------------------------- #
#  persistence
# --------------------------------------------------------------------------- #
def save(name=None) -> dict:
    name = (name or _CURRENT.get("name") or "navi-contract").replace("/", "_")
    os.makedirs(CONTRACT_DIR, exist_ok=True)
    _CURRENT["name"] = name
    path = os.path.join(CONTRACT_DIR, name + ".json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(_CURRENT, f, indent=2)
    return {"ok": True, "path": path, "name": name}


def load(name) -> dict:
    path = os.path.join(CONTRACT_DIR, name.replace("/", "_") + ".json")
    with open(path, encoding="utf-8") as f:
        return set_contract(json.load(f))


def list_saved() -> list:
    try:
        return sorted(f[:-5] for f in os.listdir(CONTRACT_DIR) if f.endswith(".json"))
    except Exception:
        return []


# --------------------------------------------------------------------------- #
#  per-agent adapters — run discovery -> normalized candidates with tag specs
# --------------------------------------------------------------------------- #
def _agent_run(aid):
    m = import_module(f"agents.{aid}.api")
    fn = m.ACTIONS.get("run") or m.ACTIONS.get("load")
    out = fn({})
    out = out[0] if isinstance(out, tuple) else out
    return (out or {}).get("result", out) if isinstance(out, dict) else {}


def _idcat(klass):
    return {"nhi": "NHI", "service": "Service Account"}.get(klass, "Identity")


def _candidates(aid, db_path=None):
    """Return [{label, rank, spec}] for an agent (spec = navi_cli.tag kwargs)."""
    try:
        res = _agent_run(aid)
    except Exception as e:
        return [], f"discovery failed: {e}"
    out = []
    if aid == "iot_squad":
        for a in res.get("tag_actions", []):
            # one candidate per navi BUILT-IN selector (--plugin/--output/--name);
            # --query only for signal-fusion groups with no plugin signature.
            sels = a.get("selectors") or ([{"query": a.get("query", "")}] if a.get("query") else [])
            for s in sels:
                spec = {"category": "IoT", "value": a.get("value", ""), "remove": False}
                if s.get("plugin"):
                    spec["plugin"] = str(s["plugin"])
                    if s.get("output"):
                        spec["output"] = s["output"]
                elif s.get("name"):
                    spec["plugin_name"] = s["name"]
                else:
                    spec["query"] = s.get("query", "")
                out.append({"label": a.get("value", ""), "rank": a.get("asset_count", 0), "spec": spec})
    elif aid == "customapp":
        for c in res.get("candidates", []):
            kw = (c.get("keyword") or c.get("name") or "").replace("'", "''")
            out.append({"label": f"{c.get('name','')} ({c.get('source','')})",
                        "rank": c.get("evidence", 0),
                        "spec": {"category": "Custom App", "value": c.get("name", ""),
                                 "query": f"SELECT DISTINCT asset_uuid FROM vuln_paths "
                                          f"WHERE path LIKE '%{kw}%'", "remove": False}})
    elif aid == "eol":
        for g in res.get("groups", []):
            pats = g.get("patterns") or []
            where = " OR ".join("plugin_name LIKE '%" + p.replace("'", "''") + "%'" for p in pats)
            q = f"SELECT asset_uuid FROM vulns WHERE ({where})" if where else ""
            out.append({"label": g.get("label", ""), "rank": g.get("asset_count", 0),
                        "spec": {"category": g.get("category", "Lifecycle"),
                                 "value": g.get("label", ""), "query": q, "remove": False}})
    elif aid == "software":
        from core import software as _sw
        # one candidate per product, ranked by asset footprint; tag Software:<name> on the
        # product's assets via a UUID --query (navi loops past the cap). Cap the candidate
        # list — _select risk-ranks and keeps top-N anyway.
        for pr in sorted(res.get("products", []) or [],
                         key=lambda x: -(x.get("nasset") or 0))[:100]:
            uu = [u for u in (pr.get("assets") or []) if u]
            if not uu:
                continue
            nver = pr.get("nver", 0)
            out.append({"label": f"{pr.get('name','')} · {nver} version(s) · {len(uu)} asset(s)",
                        "rank": pr.get("nasset", 0),
                        "spec": {"category": "Software", "value": pr.get("name", ""),
                                 "query": _sw.tag_query_for_assets(uu), "remove": False}})
    elif aid == "ai":
        out.append({"label": "Artificial Intelligence", "rank": res.get("asset_count", 0),
                    "spec": {"category": "AI", "value": "Artificial Intelligence",
                             "query": "SELECT DISTINCT asset_uuid FROM vulns "
                                      "WHERE plugin_family LIKE '%Artificial Intelligence%'",
                             "remove": False}})
    elif aid == "identity":
        from core import identity
        for a in res.get("accounts", []):
            uu = a.get("asset_uuids") or []
            q = identity.selector_for(uu) if hasattr(identity, "selector_for") else ""
            if not q:
                continue
            out.append({"label": f"{a.get('user','')} ({a.get('klass','')})",
                        "rank": len(uu),
                        "spec": {"category": _idcat(a.get("klass")), "value": a.get("user", ""),
                                 "query": q, "remove": False}})
    elif aid == "mitre":
        # group by value → union of CVEs → tag-by-query (cached mapping, offline-safe;
        # avoids navi's tag-by-CVE recipe that downloads the ATT&CK CSV at write time)
        groups = {}
        for a in res.get("actions", []):
            cve = (a.get("cve", "") or "").upper()
            val = a.get("value", "")
            if cve and val:
                groups.setdefault((a.get("category", "Mitre"), val), set()).add(cve)
        for (cat, val), cves in groups.items():
            clause = " OR ".join("cves LIKE '%" + c.replace("'", "''") + "%'" for c in sorted(cves))
            out.append({"label": val, "rank": len(cves),
                        "spec": {"category": cat, "value": val, "remove": False,
                                 "query": "SELECT asset_uuid FROM vulns WHERE " + clause}})
    elif aid == "scan_eval":
        cred = res.get("cred") or res.get("cred_failures") or []
        n = len(cred) if isinstance(cred, list) else (cred or 0)
        if n:
            out.append({"label": "Cred Failure", "rank": n,
                        "spec": {"category": "Scan Health", "value": "Cred Failure",
                                 "plugin": "104410", "remove": False}})
    elif aid == "certificate":
        byval = {}
        for t in res.get("twelve", []):
            v = t.get("tag_value") or ("Cert failure:" + (t.get("expiry_iso") or ""))
            byval.setdefault(v, []).append(t.get("asset_uuid"))
        for v, uu in byval.items():
            uu = [u for u in uu if u]
            inlist = ",".join("'" + u.replace("'", "''") + "'" for u in uu)
            out.append({"label": v, "rank": len(uu),
                        "spec": {"category": "Cert failure", "value": v, "remove": False,
                                 "query": f"SELECT asset_uuid FROM certs WHERE asset_uuid IN ({inlist})"}})
    elif aid == "exproute":
        import json as _json
        for r in res.get("routes", []):
            # tag by the route's plugin set (fast asset_uuid query), NOT --route_id,
            # which resolves assets via the Tenable API at write time and can time out.
            pl = r.get("plugin_list")
            try:
                ids = [str(x) for x in _json.loads(str(pl or "[]").replace("'", '"'))]
            except Exception:
                ids = [s for s in __import__("re").sub(r"[\[\]'\s]", "", str(pl or "")).split(",") if s]
            if not ids:
                continue
            inlist = ",".join("'" + i.replace("'", "''") + "'" for i in ids)
            out.append({"label": r.get("app_name", ""), "rank": r.get("total_vulns", 0),
                        "spec": {"category": "Route", "value": r.get("app_name", ""),
                                 "query": "SELECT DISTINCT asset_uuid FROM vulns WHERE plugin_id IN ("
                                          + inlist + ")", "remove": False}})
    elif aid == "cisakev":
        # tag every asset with a CISA Known-Exploited vuln (by xref), persistent
        s = res.get("summary") or {}
        n = s.get("kev_assets", 0)
        if n:
            out.append({"label": "Vulnerable (CISA KEV)", "rank": n,
                        "spec": {"category": "CISA KEV", "value": "Vulnerable",
                                 "xrefs": "CISA-KNOWN-EXPLOITED", "remove": False}})
    elif aid == "postquantum":
        # tag assets on the Post-Quantum cipher-analysis plugins, persistent
        ids = [str(p.get("plugin_id")) for p in res.get("plugins", []) if p.get("plugin_id")]
        if ids:
            inlist = ",".join("'" + i.replace("'", "''") + "'" for i in ids)
            out.append({"label": "Cipher Analysis", "rank": res.get("assets", 0),
                        "spec": {"category": "Post-Quantum", "value": "Cipher Analysis",
                                 "query": "SELECT asset_uuid FROM vulns WHERE plugin_id IN ("
                                          + inlist + ")", "remove": False}})
    elif aid == "agentgroup":
        # one tag per Tenable agent group: Agent Group:<name> via navi --group
        for g in res.get("groups", []):
            nm = (g.get("name") or "").strip()
            if not nm:
                continue
            out.append({"label": nm, "rank": g.get("count", 1) or 1,
                        "spec": {"category": "Agent Group", "value": nm,
                                 "group": nm, "remove": False}})
    return out, None


def _select(aid, items, logic, top_n):
    """Risk-rank then apply policy (LLM) or fall back to top-N."""
    items = sorted(items, key=lambda x: -(x.get("rank") or 0))
    for i, it in enumerate(items):
        it["i"] = i
    note = ""
    if logic and llm is not None:
        sel = llm.contract_select(aid, logic,
                                  [{"i": it["i"], "label": it["label"], "rank": it["rank"]}
                                   for it in items], top_n=top_n)
        if sel.get("ok"):
            keep = set(sel.get("keep", []))
            chosen = [it for it in items if it["i"] in keep][:top_n]
            return chosen, sel.get("note", "policy applied")
        note = "policy needs the model — used risk-ranked top-%d" % top_n
    return items[:top_n], note or ("risk-ranked top-%d" % top_n)


# --------------------------------------------------------------------------- #
#  plan / execute
# --------------------------------------------------------------------------- #
def plan(contract=None, db_path=None) -> dict:
    c = contract or _CURRENT
    top_n = int(c.get("defaults", {}).get("top_n", 50))
    agents_out = []
    for aid in TAGGERS:
        cfg = c.get("agents", {}).get(aid, {})
        if not cfg.get("enabled", True):
            continue
        items, err = _candidates(aid, db_path)
        if err:
            agents_out.append({"agent": aid, "error": err, "candidates": 0, "selected": 0, "items": []})
            continue
        chosen, note = _select(aid, items, (cfg.get("logic") or "").strip(), top_n)
        agents_out.append({"agent": aid, "candidates": len(items), "selected": len(chosen),
                           "note": note,
                           "items": [{"label": x["label"], "rank": x["rank"], "spec": x["spec"]}
                                     for x in chosen]})
    return {"ok": True, "agents": agents_out, "acr": c.get("acr", []),
            "removal": c.get("removal", {"enabled": False, "tags": []}),
            "wait_minutes": c.get("wait_minutes", 0), "armed": c.get("armed", False),
            "writes_enabled": navi_cli.writes_enabled()}


def _remove_tags(contract=None) -> int:
    """Queue '-remove' jobs for every tag in the contract's removal list (these show
    up in the Tagging log with op=remove). Returns the number of jobs queued."""
    c = contract or _CURRENT
    rem = (c.get("removal") or {}).get("tags") or []
    n = 0
    for t in rem:
        cat, val = (t.get("category") or "").strip(), (t.get("value") or "").strip()
        if not cat or not val:
            continue
        # Strip the tag off all its assets but KEEP the tag (UUID intact so dashboards/
        # access-groups that reference it don't break). No selector — just
        # `navi enrich tag --c <cat> --v <val> -remove`. The re-tag phase re-populates it.
        navi_cli.tag(cat, val, remove=True, op="remove", agent="tagremoval")
        n += 1
    return n


def _sh(s):
    return '"' + str("" if s is None else s).replace('"', '\\"') + '"'


def _cmd_for_spec(spec, force_remove=None):
    """Render one `navi enrich tag` command. force_remove overrides the spec's own
    remove flag (True → append -remove, False → never) so the exporter can emit a
    remove pass and an add pass from the same specs."""
    a = spec or {}
    rem = a.get("remove") if force_remove is None else force_remove
    rf = " -remove" if rem else ""
    cmd = "navi enrich tag --c " + _sh(a.get("category")) + " --v " + _sh(a.get("value"))
    if a.get("cve"):
        cmd += " --cve " + _sh(a["cve"]) + rf
    elif a.get("plugin_name") or a.get("name"):
        cmd += " --name " + _sh(a.get("plugin_name") or a.get("name")) + rf
    elif str(a.get("scanid", "")):
        cmd += " --scanid " + str(a["scanid"]) + rf
    elif str(a.get("plugin", "")):
        cmd += " --plugin " + str(a["plugin"]) + (" --output " + _sh(a["output"]) if a.get("output") else "") + rf
    elif str(a.get("route_id", "")):
        cmd += " --route_id " + str(a["route_id"]) + rf
    elif str(a.get("group", "")):
        cmd += " --group " + _sh(a["group"]) + rf
    elif str(a.get("xrefs", "")):
        cmd += " --xrefs " + _sh(a["xrefs"]) + (" --xid " + _sh(a["xid"]) if a.get("xid") else "") + rf
    else:
        cmd += " --query " + _sh(a.get("query")) + rf
    return cmd


def export_script(contract=None, db_path=None) -> str:
    """Render the contract's plan as a runnable `navi` script — the escape hatch
    for when MCP writes are blocked (run it where navi can write).

    Uses the ephemeral-tag refresh pattern: REMOVE every tag first (clears stale
    membership while preserving each tag's UUID), wait 30s for navi to propagate,
    then RE-APPLY so only current members remain. ACR rules run once at the end.
    """
    c = contract or _CURRENT
    p = plan(c, db_path)
    specs = [it["spec"] for blk in p["agents"] for it in (blk.get("items") or [])]
    acr = c.get("acr", []) or []
    lines = ["#!/usr/bin/env bash",
             "# Generated by The Hounds — AI Navi Contract plan",
             "# Ephemeral-tag refresh: REMOVE each tag first (clears stale members, keeps the tag",
             "# UUID), wait 30s for navi to propagate, then RE-APPLY so only current members remain.",
             "# Run where navi can write (navi on PATH, API keys configured).",
             "set -e", ""]
    if specs:
        lines.append('echo "① Removing %d tag(s) to clear stale membership…"' % len(specs))
        # -remove is tolerant: a tag that does not exist yet must not abort the run.
        for s in specs:
            lines.append(_cmd_for_spec(s, force_remove=True) + " || true")
        lines += ["",
                  'echo "⏳ Waiting 30s for navi to propagate the removals…"',
                  "sleep 30", "",
                  'echo "② Re-applying %d tag(s)…"' % len(specs)]
        for s in specs:
            lines.append(_cmd_for_spec(s, force_remove=False))
    if acr:
        lines += ["", 'echo "③ Applying %d ACR rule(s)…"' % len(acr)]
        for r in acr:
            reasons = [x for x in (r.get("reasons") or ["business"])]
            lines.append("navi enrich acr --c %s --v %s --score %s --mod %s %s%s" % (
                _sh(r.get("category")), _sh(r.get("value")), r.get("score", 0), r.get("mod", "set"),
                " ".join("-" + x for x in reasons),
                (" --note " + _sh(r.get("note"))) if r.get("note") else ""))
    lines += ["", 'echo "✓ Done."']
    return "\n".join(lines) + "\n"


def execute(contract=None, db_path=None) -> dict:
    c = contract or _CURRENT
    p = plan(c, db_path)
    if not c.get("armed"):
        return {"ok": False, "skipped": "contract not armed — plan only", "plan": p}
    wait = max(0, int(c.get("wait_minutes", 0))) * 60
    queued, acr_done = 0, 0
    for blk in p["agents"]:
        for it in blk["items"]:
            spec = dict(it["spec"])
            navi_cli.tag(agent=blk["agent"], **spec)     # -> background tag queue
            queued += 1
        if wait and blk["items"]:
            time.sleep(wait)
    for rule in c.get("acr", []):
        try:
            navi_cli.acr(rule.get("category", ""), rule.get("value", ""),
                         float(rule.get("score", 0)), mod=rule.get("mod", "set"),
                         note=rule.get("note"), reasons=rule.get("reasons") or ["business"])
            acr_done += 1
        except Exception:
            pass
    return {"ok": True, "queued_tags": queued, "acr_applied": acr_done, "plan": p}


# --------------------------------------------------------------------------- #
#  background navi update (fire-and-forget) + QA + cycle + scheduler
# --------------------------------------------------------------------------- #
def _navi_update_bg(kinds=("assets", "vulns")):
    if not navi_cli.navi_available():
        return {"started": [], "skipped": "navi not on PATH"}
    started = []
    for k in kinds:
        try:
            subprocess.Popen([navi_cli.NAVI_BIN, "update", k],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                             start_new_session=True)               # don't wait / don't track
            started.append(k)
        except Exception:
            pass
    return {"started": started}


def _qa(before):
    from core import db
    try:
        after = db.scalar("SELECT COUNT(*) FROM tags;")
    except Exception:
        after = None
    jobs = tagq.list_jobs()
    errs = sum(1 for j in jobs if j.get("status") == "error")
    return {"tags_before": before, "tags_after": after,
            "tag_delta": (after - before) if (after is not None and before is not None) else None,
            "queue_errors": errs,
            "verdict": ("ok" if (after is None or before is None or after >= before) and errs == 0
                        else "review")}


def run_cycle(contract=None, enforce_pause=True) -> dict:
    global _OPTIMIZED
    c = contract or _CURRENT
    from core import db
    started = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    # build SQL indexes once per run so contract tagging is fast on big datasets
    opt = {"skipped": "disabled"}
    if c.get("optimize", True) and not _OPTIMIZED:
        opt = navi_cli.optimize_async(); _OPTIMIZED = True
    elif c.get("optimize", True):
        opt = {"skipped": "already optimized this run"}
    # ── Garmr removal phase ──────────────────────────────────────────────────
    # When armed with a removal list: strip those tags FIRST (queued → tag log),
    # force a pause so Tenable applies the removals, then navi update so navi.db
    # reflects the cleared state, THEN run the tagging workflow below.
    rem_cfg = c.get("removal") or {}
    removal_info = {"skipped": "disabled"}
    if rem_cfg.get("enabled") and rem_cfg.get("tags") and c.get("armed"):
        removed = _remove_tags(c)
        pause = max(0, int(rem_cfg.get("pause_minutes", 30)))
        removal_info = {"removed_jobs": removed, "pause_minutes": pause,
                        "paused": bool(pause > 0 and enforce_pause)}
        if pause > 0 and enforce_pause:
            time.sleep(pause * 60)                       # autonomous loop only (not manual run_now)
        upd = _navi_update_bg() if rem_cfg.get("navi_update", True) else {"skipped": "disabled"}
        removal_info["navi_update"] = upd
    else:
        upd = _navi_update_bg() if c.get("navi_update") else {"skipped": "disabled"}
    try:
        before = db.scalar("SELECT COUNT(*) FROM tags;")
    except Exception:
        before = None
    ex = execute(c)
    qa = _qa(before)
    entry = {"started": started, "finished": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
             "armed": c.get("armed", False), "navi_update": upd, "optimize": opt,
             "removal": removal_info,
             "queued_tags": ex.get("queued_tags", 0), "acr_applied": ex.get("acr_applied", 0),
             "skipped": ex.get("skipped"), "qa": qa,
             "plan_counts": {b["agent"]: b.get("selected", 0) for b in ex.get("plan", {}).get("agents", [])}}
    with _LOCK:
        _LOOP_LOG.append(entry)
    return entry


def loop_log():
    with _LOCK:
        return list(reversed(_LOOP_LOG))


def _sched_loop():
    while not _SCHED["stop"]:
        c = _CURRENT
        hrs = max(1, int(c.get("schedule_hours", 4)))
        _SCHED["next_run"] = time.time() + hrs * 3600
        # sleep in 5s slices so stop/disarm is responsive
        while time.time() < _SCHED["next_run"] and not _SCHED["stop"]:
            time.sleep(5)
        if _SCHED["stop"]:
            break
        try:
            run_cycle(_CURRENT)
        except Exception:
            pass


def scheduler_start() -> dict:
    if _SCHED["thread"] and _SCHED["thread"].is_alive():
        return {"ok": True, "running": True, "next_run": _SCHED["next_run"]}
    _SCHED["stop"] = False
    t = threading.Thread(target=_sched_loop, name="contract-scheduler", daemon=True)
    _SCHED["thread"] = t
    t.start()
    return {"ok": True, "running": True}


def scheduler_stop() -> dict:
    _SCHED["stop"] = True
    return {"ok": True, "running": False}


def scheduler_status() -> dict:
    running = bool(_SCHED["thread"] and _SCHED["thread"].is_alive())
    return {"running": running, "next_run": _SCHED["next_run"],
            "armed": _CURRENT.get("armed", False),
            "schedule_hours": _CURRENT.get("schedule_hours", 4)}
