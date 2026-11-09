"""AI Navi Contract — turn the captured Tagging log + human policy into an
autonomous workflow.

A Contract captures the human's *needs* (per-agent plain-English policy, ACR
rules, wait periods, a schedule) so the loop can decide what to tag instead of
the per-row HITL gate. Each cycle:

  1. (optional) kick `navi config update assets` → `vulns` in the background (one after the other)
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
import re
import shlex
import subprocess
import threading
import time
from importlib import import_module

from core import navi_cli, tagname, tagq
from core.security import private_open as _popen

try:
    from core import llm
except Exception:                                    # pragma: no cover
    llm = None

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONTRACT_DIR = os.environ.get("CONTRACT_DIR", os.path.join(HERE, "contracts"))

# Every agent that applies tags. Each one has an adapter in _ADAPTERS below that mirrors
# the agent's OWN tag action (same category/value scheme, same server-side target set),
# so a contract tag is identical to what a human would apply from that agent's page.
# Deliberately NOT here (see AGENT_EXCLUDED): acr (ACR, not tags — contract `acr` rules),
# tagremoval (removal — the contract's Garmr phase), compliance_asset / ex_paths /
# ex_routes / iot_squad.tag_candidate (one-off, per-asset or free-text tags a human picks).
TAGGERS = ["iot_squad", "customapp", "exproute", "eol", "software", "ai", "identity",
           "mitre", "scan_eval", "certificate",
           "cisakev", "postquantum", "agentgroup",
           "classify", "attackpath", "was", "fused_score", "compliance", "asset_ownership"]

# Human labels + one-line descriptions for the Covenant page's per-agent policy list.
AGENT_INFO = {
    "iot_squad": ("IoT squad", "Asset Inventory : <Facet>: <device> via navi built-in selectors (--plugin/--output/--name)."),
    "customapp": ("Custom apps", "Custom App : <name> on matching filesystem paths (--query) and app routes (--route_id)."),
    "exproute": ("Ownership (Atlas)", "Owner : <route/path>: <owner>. Needs an owner mapping in the policy box, e.g. \"payment routes → VM Team; ignore the ICMP route\"."),
    "eol": ("EOL / unsupported", "Lifecycle : <group> by plugin name (--name), plus Lifecycle EOL : <date> on the exact assets."),
    "software": ("Software (Mimir)", "Software : <product> on its assets (built-in --plugin/--output -regex over the cap)."),
    "ai": ("AI inventory (Pythia)", "AI : Present, AI Role : <role>, AI Exposed, AI Priority : KEV-exposed and AI ATLAS techniques/tactics."),
    "identity": ("Identity (Janus)", "Identity / NHI / Machine ID : <account>, Identity Risk : Account Reuse + auth signals, Identity Coverage : No Credentials."),
    "mitre": ("MITRE ATT&CK", "Mitre : <technique> via navi tag-by-CVE (--cve), only CVEs with assets in navi.db."),
    "scan_eval": ("Scan health (Chronos)", "Scan Health : Cred Failure / Insufficient Privilege / Stale Scan / Never Scanned / Crown Jewel Blind Spot …"),
    "certificate": ("Certificates", "Cert failure : <expiry> on the exact assets, plus Cert Issue : <plugin> (--plugin)."),
    "cisakev": ("CISA KEV (Laelaps)", "CISA KEV : Vulnerable / <date added> (--xrefs), CISA KEV : Ransomware and CISA KEV Due : <due date>."),
    "postquantum": ("Post-Quantum (Heimdall)", "Post-Quantum : Cipher Analysis on the quantum-vulnerable cert set and each PQC plugin."),
    "agentgroup": ("Agent Groups (Sirius)", "Agent Group : <group> via navi --group."),
    "classify": ("Asset Classification (Linnaeus)", "Asset Inventory : <Facet>: <value> for untagged assets with an OS / device signal."),
    "attackpath": ("Attack Paths (Fenrir)", "Attack Path : Entry Point (entries that reach a crown jewel) and Attack Path : Target."),
    "was": ("Web apps (Arachne)", "WAS OWASP / WAS Severity / WAS Technology cohorts on each web app's Tenable asset."),
    "fused_score": ("Exposure Score (Nemesis)", "Priority : P1 on every asset scoring ≥ 80 (or the worst 10 when none does)."),
    "compliance": ("Compliance owner (Minos)", "Audit Owner : <owner> on assets FAILING each control. Needs an owner name below."),
    "asset_ownership": ("Asset Ownership (Terminus)", "Business Owner / Asset Owner from a plain-English instruction in the policy box, e.g. \"assign Jane Smith to production\"."),
}

# Tagging agents the contract does not orchestrate, and why (shown on the page / in docs).
AGENT_EXCLUDED = {
    "acr": "sets Asset Criticality Ratings, not tags — use the contract's ACR rules",
    "tagremoval": "removes tags — that is the contract's Garmr removal phase",
    "compliance_asset": "Audit-Vuln Link is a per-asset tag whose topic a human picks in the deep-dive",
    "ex_paths": "explorer: tags a path a human searched for, with a free-text value",
    "ex_routes": "explorer: tags a route a human searched for, with a free-text value",
}

# Per-agent defaults. Agents that need human input before they can tag anything are OFF
# by default so a fresh (or older, saved) contract never plans tags nobody asked for.
_AGENT_DEFAULT = {"enabled": True, "logic": ""}
AGENT_DEFAULTS = {
    "exproute": {"enabled": False, "logic": ""},          # needs an owner mapping (policy)
    "asset_ownership": {"enabled": False, "logic": ""},   # needs an owner instruction (policy)
    "compliance": {"enabled": False, "logic": "", "owner": "", "checks": []},  # needs an owner
}
NEEDS_INPUT = frozenset(AGENT_DEFAULTS)
# Agents whose policy text IS the adapter's input (an owner mapping), not a selection filter.
PROMPT_DRIVEN = frozenset({"exproute", "asset_ownership"})

# A --query is ONE argv element; the OS caps a single argument at 128 KB. 1,500 quoted
# UUIDs ≈ 60 KB, so chunk any inlined UUID list at this size (one candidate per chunk).
CHUNK_UUIDS = 1500
CUSTOMAPP_MAX = 50              # candidates looked up per plan (ranked by evidence)
CUSTOMAPP_MAX_ROUTES = 10       # route selectors per custom app
MAX_QUERY_BYTES = 100_000


def agent_default(aid) -> dict:
    return json.loads(json.dumps(AGENT_DEFAULTS.get(aid, _AGENT_DEFAULT)))


def taggers_info() -> list:
    """[{id,label,desc,needs_input,prompt_driven}] for the page's per-agent list."""
    return [{"id": a, "label": AGENT_INFO.get(a, (a, ""))[0], "desc": AGENT_INFO.get(a, (a, ""))[1],
             "needs_input": a in NEEDS_INPUT, "prompt_driven": a in PROMPT_DRIVEN} for a in TAGGERS]

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
        # after the ACR rules, tag NO : UPDATE on exactly the assets they changed, so navi
        # (and every later cycle) leaves those ACRs alone — core/acr_protect.py. Off by default.
        "protect_acr": False,
        # Garmr / tag-removal phase: chosen tags are removed at the TOP of a cycle,
        # then a forced pause + navi update, then the tagging workflow re-runs.
        "removal": {"enabled": False, "tags": [],     # [{category,value}]
                    "pause_minutes": 30, "navi_update": True},
        # Gabriel run-summary email each cycle. On by default; flip enabled off to stop
        # getting an email every run. Blank `to` → NAVI_ALERT_EMAIL / NAVI_EMAIL_TO. Send
        # is still gated by NAVI_EMAIL, so a disabled inbox just records what would go out.
        "notify": {"enabled": True, "to": ""},
        "agents": {a: agent_default(a) for a in TAGGERS},
    }


_CURRENT = default_contract()


def current() -> dict:
    return _CURRENT


def _num(v, default, lo, hi, kind):
    """A number from a contract field (strings from the form allowed), clamped; junk → default."""
    try:
        x = kind(float(v))
    except (TypeError, ValueError):
        return default
    if x != x:                                   # NaN
        return default
    return max(lo, min(hi, x))


def _flag(v) -> bool:
    """A strict on/off: True / 1 / 'true' / 'yes' / 'on' only — so a stray 'false' string
    can never switch a write-adding option on."""
    if isinstance(v, bool):
        return v
    if isinstance(v, (int, float)):
        return v == 1
    return str(v or "").strip().lower() in ("1", "true", "yes", "on")


_ACR_MODS = ("set", "inc", "dec")
_ACR_REASONS = ("business", "compliance", "mitigation", "development")


def _acr_rule(r):
    rs = [x for x in (r.get("reasons") or []) if x in _ACR_REASONS] if isinstance(r.get("reasons"), list) else []
    return {"category": str(r.get("category") or ""), "value": str(r.get("value") or ""),
            "score": _num(r.get("score"), 8, 0, 10, int),
            "mod": r.get("mod") if r.get("mod") in _ACR_MODS else "set",
            "reasons": rs or ["business"], "note": str(r.get("note") or "")}


def acr_rule_errors(doc) -> str:
    """'' or a clear message for an ACR rule navi can't run: a numeric score that is not a whole
    number 1–10 (navi does int(score)). Junk / missing scores keep the old default (8)."""
    for i, r in enumerate((doc or {}).get("acr") or [], 1):
        if not isinstance(r, dict) or r.get("score") in (None, ""):
            continue
        try:
            f = float(r.get("score"))
        except (TypeError, ValueError):
            continue
        if f != f or f != int(f) or not 1 <= f <= 10:
            return ("ACR rule %d (%s : %s): the score must be a whole number 1–10 — got %s"
                    % (i, r.get("category") or "?", r.get("value") or "?", r.get("score")))
    return ""


def set_contract(doc: dict) -> dict:
    global _CURRENT
    base = default_contract()
    base.update({k: v for k, v in (doc or {}).items() if k in base})
    # merge agent map so missing agents (e.g. ones added after the contract was saved)
    # get their defaults, and missing per-agent keys (owner, checks …) are filled in
    ag = base.get("agents") if isinstance(base.get("agents"), dict) else {}
    for a in TAGGERS:
        cur = ag.get(a) if isinstance(ag.get(a), dict) else {}
        merged = {**agent_default(a), **cur}
        merged["enabled"] = bool(merged.get("enabled"))
        merged["logic"] = str(merged.get("logic") or "")
        if "owner" in merged:
            merged["owner"] = str(merged.get("owner") or "")
        if "checks" in merged:
            merged["checks"] = [str(x) for x in merged["checks"]] if isinstance(merged["checks"], list) else []
        ag[a] = merged
    base["agents"] = ag
    rem = base.get("removal") if isinstance(base.get("removal"), dict) else {}
    tags = rem.get("tags") if isinstance(rem.get("tags"), list) else []
    rem = {"enabled": bool(rem.get("enabled", False)),
           "tags": [{"category": str(t.get("category") or ""), "value": str(t.get("value") or "")}
                    for t in tags if isinstance(t, dict)],
           "pause_minutes": _num(rem.get("pause_minutes"), 30, 0, 1440, int),
           "navi_update": bool(rem.get("navi_update", True))}
    base["removal"] = rem
    nt = base.get("notify") if isinstance(base.get("notify"), dict) else {}
    base["notify"] = {"enabled": bool(nt.get("enabled", True)), "to": str(nt.get("to") or "")}
    dfl = base.get("defaults") if isinstance(base.get("defaults"), dict) else {}
    base["defaults"] = {"top_n": _num(dfl.get("top_n"), 50, 1, 5000, int),
                        "rank": str(dfl.get("rank") or "risk")}
    base["schedule_hours"] = _num(base.get("schedule_hours"), 4, 0.25, 24 * 30, float)
    base["wait_minutes"] = _num(base.get("wait_minutes"), 0, 0, 1440, int)
    for k in ("armed", "navi_update", "optimize"):
        base[k] = bool(base.get(k))
    base["protect_acr"] = _flag(base.get("protect_acr"))
    base["name"] = str(base.get("name") or "navi-contract")
    acr = base.get("acr") if isinstance(base.get("acr"), list) else []
    base["acr"] = [_acr_rule(r) for r in acr if isinstance(r, dict)]
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


def _reasons_from_log(j):
    """(reasons, note) of a logged ACR change: the retained spec when there is one, else the
    business case text ('Business Critical, Dev Only — note'); else the old defaults."""
    spec = j.get("spec") if isinstance(j.get("spec"), dict) else {}
    rs = [r for r in (spec.get("reasons") or []) if r in _ACR_REASONS]
    if rs:
        return rs, str(spec.get("note") or "") or "from tagging log"
    bc = str(j.get("business_case") or "").strip()
    if bc:
        from core import acr_protect
        lbl, _, note = bc.partition(" — ")
        names = [x.strip() for x in lbl.split(",")]
        rs = [k for k, l in acr_protect.REASON_LABELS if l in names]
        if rs:
            return rs, note.strip() or "from tagging log"
        return ["business"], bc                         # a note-only business case
    return ["business"], "from tagging log"


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
        # if nothing logged, enable all — except agents that need human input first
        doc["agents"][a]["enabled"] = (a in used) or (not used and a not in NEEDS_INPUT)
    # carry forward ACR changes seen in the log as explicit ACR rules
    seen = set()
    for j in jobs:
        sel = str(j.get("selector") or "").strip()
        # an ACR change — not the NO : UPDATE protection tag the ACR agent also logs (agent 'acr',
        # selector 'query'); a selector-less row is an old CSV export (pre-protection: all ACR)
        if (j.get("agent") == "acr" and j.get("value") and j.get("category") != "NO"
                and (not sel or sel.startswith("acr"))):
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
            reasons, note = _reasons_from_log(j)
            doc["acr"].append({"category": j.get("category", "Business Tier"),
                               "value": j.get("value"), "score": score, "mod": mod,
                               "reasons": reasons, "note": note})
    return set_contract(doc)


# --------------------------------------------------------------------------- #
#  persistence
# --------------------------------------------------------------------------- #
def safe_name(name) -> str:
    """A contract name safe to use as a file name on every OS: only [A-Za-z0-9 _.-]
    (everything else → '_', so 'a/b' and 'a\\b' and '..' can't climb out), no leading
    dots, at most 80 characters."""
    n = re.sub(r"[^A-Za-z0-9 _.-]", "_", str(name or "")).strip().lstrip(".").strip()
    return n[:80] or "navi-contract"


def _contract_path(name) -> str:
    base = os.path.realpath(CONTRACT_DIR)
    p = os.path.realpath(os.path.join(base, safe_name(name) + ".json"))
    if os.path.dirname(p) != base:
        raise ValueError("contract name escapes the contracts folder")
    return p


def save(name=None) -> dict:
    name = safe_name(name or _CURRENT.get("name") or "navi-contract")
    os.makedirs(CONTRACT_DIR, mode=0o700, exist_ok=True)
    _CURRENT["name"] = name
    path = _contract_path(name)
    with _popen(path, "w", encoding="utf-8") as f:
        json.dump(_CURRENT, f, indent=2)
    return {"ok": True, "path": path, "name": name}


def load(name) -> dict:
    name = (name or "").strip()
    if not name:
        raise ValueError("no contract name given")
    path = _contract_path(name)
    if not os.path.exists(path):
        raise FileNotFoundError(f"no saved contract named '{name}'")
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
    # discovery must not replace the result a human last ran on that hound's page
    ag = getattr(m, "AGENT", None)
    had = hasattr(ag, "result") if ag is not None else False
    saved = getattr(ag, "result", None)
    try:
        out = fn({})
    finally:
        if ag is not None and had:
            try:
                ag.result = saved
            except Exception:
                pass
    out = out[0] if isinstance(out, tuple) else out
    return (out or {}).get("result", out) if isinstance(out, dict) else {}


class NeedsInput(Exception):
    """An adapter can't plan anything until a human supplies input (an owner name, an
    owner mapping …). Shown as a note on the plan, not as a discovery failure."""


def _q(s):
    return "'" + str(s).replace("'", "''") + "'"


def _uuid_specs(category, value, uuids, prefix="SELECT uuid AS asset_uuid FROM assets WHERE uuid IN (",
                suffix=")"):
    """Tag specs for an explicit asset set, chunked at CHUNK_UUIDS so no single --query
    argument passes the OS 128 KB per-argument limit. Same SELECT shape as the agent's own."""
    uu = sorted({str(u) for u in (uuids or []) if u})
    out = []
    for i in range(0, len(uu), CHUNK_UUIDS):
        part = uu[i:i + CHUNK_UUIDS]
        out.append({"category": category, "value": value, "remove": False,
                    "query": prefix + ",".join(_q(u) for u in part) + suffix})
    return out


def _items(label, rank, specs, unit=None):
    """One candidate per spec; all chunks/selectors of one tag share a `unit` so policy
    selection keeps or drops them together."""
    specs = [s for s in specs if s]
    unit = unit or (specs[0]["category"] + " : " + str(specs[0]["value"]) if specs else label)
    return [{"label": label + (f" [{i + 1}/{len(specs)}]" if len(specs) > 1 else ""),
             "rank": rank or 0, "spec": s, "unit": unit} for i, s in enumerate(specs)]


_IN_RE = re.compile(r"^(.*?\bIN\s*\()((?:'(?:[^']|'')*'\s*,\s*)*'(?:[^']|'')*')(\).*)$", re.S)


def _enforce_size(items):
    """Safety net: split any --query whose inlined IN (...) list would pass the argument
    limit into several candidates (same unit). Queries without a splittable list are kept."""
    out = []
    for it in items:
        q = (it.get("spec") or {}).get("query") or ""
        if len(q.encode("utf-8")) <= MAX_QUERY_BYTES:
            out.append(it)
            continue
        m = _IN_RE.match(q)
        if not m:
            out.append(it)
            continue
        vals = re.findall(r"'(?:[^']|'')*'", m.group(2))
        for i in range(0, len(vals), CHUNK_UUIDS):
            sp = dict(it["spec"])
            sp["query"] = m.group(1) + ",".join(vals[i:i + CHUNK_UUIDS]) + m.group(3)
            out.append({**it, "spec": sp, "label": it["label"] + f" [{i // CHUNK_UUIDS + 1}]"})
    return out


def _idcat(klass):
    # same mapping as the Identity page's idCat(): service accounts stay under Identity
    return {"nhi": "NHI", "machine": "Machine ID"}.get(klass, "Identity")


# ---------------------------------------------------------------- per-agent adapters
def _ad_iot_squad(cfg):
    res = _agent_run("iot_squad")
    out = []
    for a in res.get("tag_actions", []):
        v = a.get("value", "")
        # tags_apply: category 'Asset Inventory', value '<Facet>: <device>'; one navi
        # BUILT-IN selector per command (--plugin/--output/--name), --query only for
        # signal-fusion groups with no plugin signature.
        facet = (a.get("facet") or "Device Type").strip()
        tv = f"{facet}: {v}"
        sels = a.get("selectors") or ([{"query": a.get("query", "")}] if a.get("query") else [])
        specs = []
        for s in sels:
            spec = {"category": "Asset Inventory", "value": tv, "remove": False}
            if s.get("plugin"):
                spec["plugin"] = str(s["plugin"])
                if s.get("output"):
                    spec["output"] = s["output"]
            elif s.get("name"):
                spec["plugin_name"] = s["name"]
            else:
                spec["query"] = s.get("query", "")
            specs.append(spec)
        out += _items(tv, a.get("asset_count", 0), specs)
    return out


def _ad_customapp(cfg):
    from agents.customapp.agent import search_paths, search_routes, tag_query_for
    res = _agent_run("customapp")
    out = []
    # search_paths/search_routes are full scans per keyword — on a large navi.db every
    # candidate costs seconds, so look up only the strongest candidates (by evidence)
    cands = sorted((res.get("candidates") or []), key=lambda c: -(c.get("evidence") or 0))[:CUSTOMAPP_MAX]
    for c in cands:
        name, kw = c.get("name") or "", c.get("keyword") or c.get("name") or ""
        if not name or not kw:
            continue
        specs = []
        # customapp.tag: paths via --query, every matching route via --route_id
        if search_paths(kw):
            specs.append({"category": "Custom App", "value": name, "query": tag_query_for(kw),
                          "remove": False})
        for rt in (search_routes(kw) or [])[:CUSTOMAPP_MAX_ROUTES]:
            if rt.get("route_id") is not None:
                specs.append({"category": "Custom App", "value": name,
                              "route_id": str(rt["route_id"]), "remove": False})
        out += _items(f"{name} ({c.get('source', '')})", c.get("evidence", 0), specs)
    return out


def _ad_exproute(cfg):
    """Atlas: Owner : '<route/path>: <owner>' from the owner mapping in the policy box —
    the agent's own interpret() (dispositions parsed locally, owners by the model and
    resolved to real navi users/groups), then tag_owner()'s selectors."""
    from core import db
    logic = (cfg.get("logic") or "").strip()
    if not logic:
        raise NeedsInput("needs an owner mapping in the policy box (e.g. \"payment routes → VM Team\")")
    m = import_module("agents.exproute.api")
    r = m.ACTIONS["interpret"]({"prompt": logic})
    r = r[0] if isinstance(r, tuple) else r
    if not r.get("ok"):
        raise NeedsInput(r.get("message") or r.get("error") or "could not interpret the owner mapping")
    out = []
    for mp in r.get("mappings", []):
        owner = (mp.get("owner") or "").strip()
        if not owner:
            continue
        if mp.get("kind") == "path" or mp.get("path"):
            path = mp.get("path") or mp.get("match") or ""
            name = mp.get("match") or path
            q = "SELECT asset_uuid FROM vuln_paths WHERE path=" + _q(path)
            out += _items(f"{name} → {owner}", 1, [{"category": "Owner", "value": f"{name}: {owner}",
                                                     "query": q, "remove": False}])
            continue
        if mp.get("route_id") not in (None, ""):
            rows = db.query("SELECT route_id, app_name, total_vulns FROM vuln_route WHERE route_id=?",
                            (mp["route_id"],))
        else:
            rows = db.query("SELECT route_id, app_name, total_vulns FROM vuln_route "
                            "WHERE app_name=? COLLATE NOCASE LIMIT 1", (mp.get("match") or "",))
        if not rows:
            continue
        app = rows[0].get("app_name") or mp.get("match") or ""
        name = mp.get("match") or app
        # every route_id sharing the app name (the map merges them by name)
        rids = [x["route_id"] for x in db.query(
            "SELECT route_id FROM vuln_route WHERE app_name=? COLLATE NOCASE ORDER BY route_id", (app,))
            if x.get("route_id") not in (None, "")] or [rows[0]["route_id"]]
        out += _items(f"{name} → {owner}", rows[0].get("total_vulns") or 1,
                      [{"category": "Owner", "value": f"{name}: {owner}", "route_id": str(x),
                        "remove": False} for x in rids])
    return out


def _ad_eol(cfg):
    from core import eol as _eol
    res = _agent_run("eol")
    known = dict(_eol.DEFAULT_GROUPS)
    out = []
    # apply(): Lifecycle : <group> via tag-by-plugin-name, one --name per pattern
    for g in res.get("groups", []):
        val = g.get("label", "")
        pats = known.get(val) or g.get("patterns") or []
        if not g.get("asset_count") or not pats:
            continue
        out += _items(val, g.get("asset_count", 0),
                      [{"category": "Lifecycle", "value": val, "plugin_name": p, "remove": False}
                       for p in pats])
    # tag_eol_date(): Lifecycle EOL : <YYYY-MM-DD> on the exact assets
    for dg in (res.get("view") or {}).get("date_groups", []) or []:
        uu = dg.get("uuids") or []
        if uu:
            out += _items("EOL " + dg["eol_date"], len(uu), _uuid_specs("Lifecycle EOL", dg["eol_date"], uu))
    return out


def _has_table(name):
    from core import db
    try:
        return bool(db.scalar("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)))
    except Exception:
        return True                      # can't tell — let discovery try


def _ad_software(cfg):
    sw_api = import_module("agents.software.api")
    from core import software as _sw
    if not _has_table("software"):
        raise NeedsInput("no software table in navi.db — run navi update assets first")
    res = _agent_run("software")
    out = []
    for pr in sorted(res.get("products", []) or [], key=lambda x: -(x.get("nasset") or 0))[:100]:
        uu = sorted({u for u in (pr.get("assets") or []) if u})
        name = pr.get("name", "")
        if not uu or not name:
            continue
        label = f"{name} · {pr.get('nver', 0)} version(s) · {len(uu)} asset(s)"
        fb = sw_api._software_fallbacks(name)
        if len(uu) > navi_cli.UUID_CAP and fb:
            # software.tag over the cap: navi built-ins (--plugin <enum> --output <name> -regex)
            specs = [{"category": "Software", "value": name, "plugin": str(f["plugin"]),
                      "output": f["output"], "regex": True, "remove": False} for f in fb]
        else:
            specs = [{"category": "Software", "value": name, "remove": False,
                      "query": _sw.tag_query_for_assets(uu)}]
        out += _items(label, pr.get("nasset", 0), specs)
    return out


def _ad_ai(cfg):
    from core import ai_assets
    res = _agent_run("ai")
    assets = res.get("assets") or []
    out = []
    allu = [x.get("asset_uuid") for x in assets]
    if any(allu):
        out += _items("AI : Present", len(allu), _uuid_specs("AI", "Present", allu))
    by_role = {}
    for x in assets:
        if x.get("role"):
            by_role.setdefault(x["role"], []).append(x.get("asset_uuid"))
    for role, uu in by_role.items():
        out += _items("AI Role : " + role, len(uu), _uuid_specs("AI Role", role, uu))
    ex = [x.get("asset_uuid") for x in assets if x.get("exposed")]
    if ex:
        out += _items("AI Exposed : Endpoint", len(ex), _uuid_specs("AI Exposed", "Endpoint", ex))
    kv = [x.get("asset_uuid") for x in assets if (x.get("risk") or {}).get("kev")]
    if kv:
        out += _items("AI Priority : KEV-exposed", len(kv), _uuid_specs("AI Priority", "KEV-exposed", kv))
    # tag_atlas(): only known techniques / tactics, recomputed from the scan
    sets = ai_assets.atlas_sets(assets)
    for tid, uu in sorted(sets["tech"].items()):
        if tid in ai_assets.ATLAS_TECH and uu:
            out += _items("AI ATLAS : " + tid, len(uu), _uuid_specs("AI ATLAS", tid, uu))
    for tac, uu in sorted(sets["tactic"].items()):
        if tac in ai_assets.ATLAS_TACTIC_ORDER and uu:
            out += _items("AI ATLAS : Tactic : " + tac, len(uu), _uuid_specs("AI ATLAS", "Tactic : " + tac, uu))
    return out


_ID_SIGNALS = {"ssh password auth": "SSH Password Auth", "weak pw policy": "Weak Password Policy",
               "default/blank cred": "Default Credentials", "AD attack path": "AD Attack Path",
               "on KEV host": "KEV Host"}     # = the Identity page's SIGNALS table


def _ad_identity(cfg):
    res = _agent_run("identity")
    accts = res.get("accounts", []) or []
    out = []
    for a in accts:
        uu = a.get("asset_uuids") or []
        if not uu or not a.get("user"):
            continue
        out += _items(f"{a.get('user', '')} ({a.get('klass', '')})", len(uu),
                      _uuid_specs(_idcat(a.get("klass")), a["user"], uu))
    # account reuse (the ONLY reuse signal — password reuse is never inferred)
    reuse = sorted({u for a in accts if any(str(f).startswith("account reuse") for f in a.get("flags") or [])
                    for u in (a.get("reuse_uuids") or [])})
    if reuse:
        out += _items("Identity Risk : Account Reuse", len(reuse),
                      _uuid_specs("Identity Risk", "Account Reuse", reuse))
    hs = res.get("host_sets") or {}
    for key, val in _ID_SIGNALS.items():
        if hs.get(key):
            out += _items("Identity Risk : " + val, len(hs[key]), _uuid_specs("Identity Risk", val, hs[key]))
    if hs.get("uncredentialed"):
        out += _items("Identity Coverage : No Credentials", len(hs["uncredentialed"]),
                      _uuid_specs("Identity Coverage", "No Credentials", hs["uncredentialed"]))
    return out


def _ad_mitre(cfg):
    """mitre.apply(): the plan rebuilt server-side; only CVEs with assets in navi.db;
    one navi tag-by-CVE (--cve) per CVE, grouped by value; category always Mitre."""
    from core import downloads, mitre as _mitre
    api = import_module("agents.mitre.api")
    plan_ = _mitre.build_plan(scope="navidb", csv_text=api._LAST.get("csv", ""),
                              allow_live=downloads.allowed({})[0])
    groups = {}
    for a in plan_.get("actions", []):
        cve, val = (a.get("cve") or "").upper(), a.get("value", "")
        if cve and val and a.get("assets"):
            groups.setdefault(val, set()).add(cve)
    out = []
    for val, cves in groups.items():
        out += _items(val, len(cves), [{"category": "Mitre", "value": val, "cve": c, "remove": False}
                                       for c in sorted(cves)])
    return out


def _ad_scan_eval(cfg):
    """scan_eval.tag: the same evaluation with keep_uuids, one Scan Health cohort per key."""
    from core import scan_eval as _se
    api = import_module("agents.scan_eval.api")
    ev = _se.evaluate(keep_uuids=True)
    sets = ev.get("_sets") or {}
    out = []
    for key, value in api.VALUES.items():
        uu = sorted(u for u in (sets.get(key) or ()) if u)
        if uu:
            out += _items(value, len(uu), _uuid_specs(api.CATEGORY, value, uu))
    return out


def _ad_certificate(cfg):
    if not _has_table("certs"):
        raise NeedsInput("no certs table in navi.db — run navi config certificates first")
    res = _agent_run("certificate")
    out = []
    # tags_apply(): Cert failure : <expiry> with the agent's exact-asset query
    seen = set()
    for a in res.get("tag_actions", []):
        v = a.get("value")
        if not v or v in seen or not a.get("assets"):
            continue
        seen.add(v)
        out += _items(v, a.get("assets", 0), [{"category": a.get("category", "Cert failure"), "value": v,
                                               "query": a.get("query", ""), "remove": False}])
    # tags_issues(): Cert Issue : <plugin name> via --plugin
    for mx in res.get("cert_issue_matrix", []) or []:
        pid, nm = str(mx.get("plugin_id") or "").strip(), (mx.get("plugin_name") or "").strip()
        if pid and nm:
            out += _items("Cert Issue : " + nm, mx.get("asset_count") or 1,
                          [{"category": "Cert Issue", "value": nm, "plugin": pid, "remove": False}])
    return out


def _ad_cisakev(cfg):
    from agents.cisakev.agent import XREF, kev_dates, summary
    api = import_module("agents.cisakev.api")
    out = []
    n = (summary() or {}).get("kev_assets", 0)
    if n:   # tag_vulnerable(): every KEV asset by xref
        out += _items("CISA KEV : Vulnerable", n, [{"category": "CISA KEV", "value": "Vulnerable",
                                                    "xrefs": XREF, "remove": False}])
    for d in kev_dates():   # tag_dates(): one --xrefs --xid per catalog dateAdded
        kd = d.get("kev_date")
        if kd:
            out += _items("CISA KEV : " + d.get("value", kd), d.get("assets", 0),
                          [{"category": "CISA KEV", "value": d.get("value", kd), "xrefs": XREF,
                            "xid": kd, "remove": False}])
    try:    # tag_ransomware() / tag_due(): the CISA catalog joined by CVE (cached download)
        rows = api._cves_for(lambda c: True, {})
    except Exception:
        rows = []
    rw = sorted({u for r in rows if r.get("ransomware") for u in r.get("uuids", []) if u})
    if rw:
        out += _items("CISA KEV : Ransomware", len(rw), _uuid_specs("CISA KEV", "Ransomware", rw))
    dues = {}
    for r in rows:
        if r.get("due_date"):
            dues.setdefault(r["due_date"], set()).update(u for u in r.get("uuids", []) if u)
    for due, uu in sorted(dues.items()):
        if uu:
            out += _items("CISA KEV Due : " + due, len(uu), _uuid_specs(api.DUE_CATEGORY, due, uu))
    return out


def _ad_postquantum(cfg):
    """tag_all(): Post-Quantum : Cipher Analysis on the cert set (query) AND each PQC
    plugin that has findings (--plugin)."""
    from core import db
    from agents.postquantum import agent as pq
    specs = []
    try:
        if pq._has_table("certs") and pq._uuid_set(pq._CERT_TAG_QUERY):
            specs.append({"category": pq.CATEGORY, "value": pq.VALUE, "query": pq._CERT_TAG_QUERY,
                          "remove": False})
    except Exception:
        pass
    for pid, _n, _r in pq.PLUGINS:
        if db.scalar("SELECT COUNT(*) FROM vulns WHERE plugin_id=?", (pid,)) or 0:
            specs.append({"category": pq.CATEGORY, "value": pq.VALUE, "plugin": str(pid), "remove": False})
    try:
        n = len(pq._uuid_set("SELECT DISTINCT asset_uuid FROM vulns WHERE plugin_id IN ("
                             + ",".join(_q(p) for p, _a, _b in pq.PLUGINS) + ")"))
    except Exception:
        n = len(specs)
    return _items("Cipher Analysis", n, specs)


def _ad_agentgroup(cfg):
    res = _agent_run("agentgroup")
    out = []
    for g in res.get("groups", []):
        nm = (g.get("name") or "").strip()
        if nm:
            out += _items(nm, g.get("count", 1) or 1, [{"category": "Agent Group", "value": nm,
                                                       "group": nm, "remove": False}])
    return out


def _ad_classify(cfg):
    """Linnaeus OS Signals: every UNTAGGED asset with a classification signal, grouped into
    cohorts → Asset Inventory : '<Facet>: <value>' (classify.tag's scheme and query)."""
    from core import classify as _cl
    sig = _cl.os_signals(only_untagged=True)
    out = []
    for c in sig.get("cohorts", []) or []:
        tv = f"{c.get('facet')}: {c.get('value')}"
        uu = c.get("uuids") or []
        if uu:
            out += _items(tv, c.get("count", len(uu)),
                          _uuid_specs("Asset Inventory", tv, uu,
                                      prefix="SELECT DISTINCT asset_uuid FROM vulns WHERE asset_uuid IN ("))
    return out


def _ad_attackpath(cfg):
    from agents.attackpath.agent import ENTRY_CAT
    res = _agent_run("attackpath")
    ent = [e.get("uuid") for e in res.get("entries", []) if e.get("reaches_any")]
    tgt = res.get("reachable") or [x["target"]["uuid"] for x in res.get("paths", []) if x.get("target")]
    out = []
    if any(ent):
        out += _items("Attack Path : Entry Point", len(set(ent)), _uuid_specs(ENTRY_CAT, "Entry Point", ent))
    if tgt:
        out += _items("Attack Path : Target", len(set(tgt)), _uuid_specs(ENTRY_CAT, "Target", tgt))
    return out


def _ad_was(cfg):
    """Arachne: every tag_plan cohort, targets as was.tag_targets resolves them."""
    from core import was as _was
    plan_ = _was.tag_plan()
    if not plan_.get("available"):
        return []
    out = []
    for dim in ("owasp", "severity", "technology"):
        for c in plan_.get(dim, []) or []:
            uu = c.get("uuids") or []
            if uu:
                out += _items(f"{c['category']} : {c['value']}", c.get("apps", len(uu)),
                              _uuid_specs(c["category"], c["value"], uu,
                                          prefix="SELECT DISTINCT asset_uuid FROM apps WHERE asset_uuid IN ("))
    return out


def _ad_fused_score(cfg):
    """Nemesis: Priority : P1 on the act-now set recomputed server-side (select_uuids at the
    page's default threshold of 80 — the worst 10 when nothing scores that high)."""
    from core import fused_score as _fs
    uu = _fs.select_uuids(threshold=80)
    return _items("Priority : P1 (score ≥ 80)", len(uu), _uuid_specs("Priority", "P1", uu))


def _ad_compliance(cfg):
    """Minos: Audit Owner : <owner> on the assets FAILING each control. The owner is a human
    name the contract carries (agents.compliance.owner); without it nothing is planned."""
    from core import compliance as _c, db
    owner = (cfg.get("owner") or "").strip()
    if not owner:
        raise NeedsInput("needs an Audit Owner name — set it in the Compliance owner row")
    if not _c._table_exists("compliance"):
        return []
    want = {str(x) for x in (cfg.get("checks") or []) if str(x).strip()}
    out = []
    for r in db.query(_c._CTRL_AGG + " ORDER BY failed DESC"):
        cid = r.get("check_id")
        if not cid or not int(r.get("failed_assets") or 0) or (want and str(cid) not in want):
            continue
        # control_targets(failed_only=True) as SQL — no inlined UUIDs, no size limit
        q = ("SELECT DISTINCT asset_uuid FROM compliance WHERE check_id=" + _q(cid)
             + " AND upper(status) LIKE 'FAIL%'")
        out += _items(f"{r.get('check_name') or cid} → {owner}", int(r.get("failed_assets") or 0),
                      [{"category": _c.TAG_OWNER_CATEGORY, "value": owner, "query": q, "remove": False}],
                      unit="check:" + str(cid))
    return out


def _ad_asset_ownership(cfg):
    """Terminus: each line of the policy box is one plain-English owner instruction, run
    through the agent's own plan(). Business layer → Business Owner : <owner>; asset layer →
    the same tags assign_asset_owner() cascades (Owner : '<route/path>: <owner>' + Asset
    Owner : '<owner> · <mode>'), aggregated per tag value. The asset layer is capped at
    2,000 assets, as apply(); the business layer tags every matched asset."""
    from core import asset_ownership as eng
    lines = [x.strip() for x in (cfg.get("logic") or "").splitlines() if x.strip()]
    if not lines:
        raise NeedsInput("needs an owner instruction in the policy box (e.g. \"assign Jane Smith to production\")")
    out, notes = [], []
    for ln in lines:
        p = eng.plan(ln)
        if not p.get("ok"):
            notes.append(p.get("error") or "could not read " + ln)
            continue
        owner, uu = p.get("owner") or "", list(p.get("uuids") or [])
        if not owner or not uu:
            continue
        if p.get("layer") == "asset":
            uu = uu[:2000]                       # the per-asset cascade is capped, as apply()
        if p.get("layer") != "asset":
            out += _items(f"Business Owner : {owner} ({len(uu)} assets)", len(uu),
                          _uuid_specs(eng.BUSINESS_OWNER_KEY, owner, uu))
            continue
        mode = "remainder" if str(p.get("mode") or "").lower().startswith("rem") else "complete"
        cascade = {}
        for u in uu:
            routes, paths = eng._asset_routes_paths(u)
            owned = set()
            for r in eng._q("SELECT tag_value FROM tags WHERE asset_uuid=? AND " + tagname.sql_lit("tag_key", "Owner") + " "
                            "AND tag_value IS NOT NULL", (u,)):
                val = (r.get("tag_value") or "").strip()
                if ": " in val:
                    nm, user = val.rsplit(": ", 1)
                    if user.strip() and not eng._disp_of(user):
                        owned.add(eng._nk(nm))
            for nm in routes + paths:
                if mode == "remainder" and eng._nk(nm) in owned:
                    continue
                cascade.setdefault(f"{nm}: {owner}", set()).add(u)
        for val, s in sorted(cascade.items()):
            out += _items("Owner : " + val, len(s), _uuid_specs("Owner", val, s))
        out += _items(f"Asset Owner : {owner} · {mode}", len(uu),
                      _uuid_specs(eng.ASSET_OWNER_KEY, f"{owner} · {mode}", uu))
    if not out and notes:
        raise NeedsInput("; ".join(notes))
    return out


_ADAPTERS = {
    "iot_squad": _ad_iot_squad, "customapp": _ad_customapp, "exproute": _ad_exproute,
    "eol": _ad_eol, "software": _ad_software, "ai": _ad_ai, "identity": _ad_identity,
    "mitre": _ad_mitre, "scan_eval": _ad_scan_eval, "certificate": _ad_certificate,
    "cisakev": _ad_cisakev, "postquantum": _ad_postquantum, "agentgroup": _ad_agentgroup,
    "classify": _ad_classify, "attackpath": _ad_attackpath, "was": _ad_was,
    "fused_score": _ad_fused_score, "compliance": _ad_compliance,
    "asset_ownership": _ad_asset_ownership,
}


def _candidates_ex(aid, db_path=None, cfg=None):
    """(items, error, note) for an agent. items = [{label, rank, spec, unit}] where spec is
    navi_cli.tag kwargs (category, value, ONE selector, remove=False)."""
    fn = _ADAPTERS.get(aid)
    if fn is None:
        return [], f"no contract adapter for '{aid}'", None
    try:
        out = fn(dict(cfg or (_CURRENT.get("agents", {}).get(aid)) or agent_default(aid)))
    except NeedsInput as e:
        return [], None, str(e)
    except Exception as e:
        return [], f"discovery failed: {e}", None
    out = _enforce_size([it for it in out if it.get("spec")])
    for it in out:
        it["spec"]["remove"] = False        # adapters never remove — only the Garmr phase does
    return out, None, None


def _candidates(aid, db_path=None, cfg=None):
    """Return ([{label, rank, spec, unit}], error) for an agent (spec = navi_cli.tag kwargs)."""
    out, err, note = _candidates_ex(aid, db_path, cfg)
    return out, err


def _select(aid, items, logic, top_n):
    """Risk-rank then apply policy (LLM) or fall back to top-N. Selection works on UNITS
    (one tag = all its chunks / selectors) so a tag is never half-applied."""
    units, order = {}, []
    for it in items:
        k = it.get("unit") or it.get("label")
        if k not in units:
            units[k] = {"label": it.get("unit") or it["label"], "rank": 0, "items": []}
            order.append(k)
        u = units[k]
        u["items"].append(it)
        u["rank"] = max(u["rank"], it.get("rank") or 0)
    ul = sorted((units[k] for k in order), key=lambda u: -(u["rank"] or 0))
    for i, u in enumerate(ul):
        u["i"] = i

    def flat(us):
        return [it for u in us for it in u["items"]]
    note = ""
    if logic and aid not in PROMPT_DRIVEN and llm is not None:
        sel = llm.contract_select(aid, logic,
                                  [{"i": u["i"], "label": u["label"], "rank": u["rank"]} for u in ul],
                                  top_n=top_n)
        if sel.get("ok"):
            keep = set(sel.get("keep", []))
            return flat([u for u in ul if u["i"] in keep][:top_n]), sel.get("note", "policy applied")
        note = "policy needs the model — used risk-ranked top-%d" % top_n
    if aid in PROMPT_DRIVEN:
        # the policy IS the owner mapping — every tag it produces is wanted, not a top-N pick
        return flat(ul), "owner mapping from the policy"
    return flat(ul[:top_n]), note or ("risk-ranked top-%d" % top_n)


# --------------------------------------------------------------------------- #
#  plan / execute
# --------------------------------------------------------------------------- #
def plan(contract=None, db_path=None) -> dict:
    c = contract or _CURRENT
    top_n = _num((c.get("defaults") or {}).get("top_n"), 50, 1, 5000, int)
    agents_out = []
    for aid in TAGGERS:
        raw = (c.get("agents") or {}).get(aid)
        cfg = {**agent_default(aid), **(raw if isinstance(raw, dict) else {})}
        if not cfg.get("enabled", True):
            continue
        items, err, need = _candidates_ex(aid, db_path, cfg)
        if err:
            agents_out.append({"agent": aid, "error": err, "candidates": 0, "selected": 0, "items": []})
            continue
        if need:
            agents_out.append({"agent": aid, "needs_input": need, "note": "needs input — nothing planned",
                               "candidates": 0, "selected": 0, "items": []})
            continue
        chosen, note = _select(aid, items, (cfg.get("logic") or "").strip(), top_n)
        agents_out.append({"agent": aid, "candidates": len({x.get("unit") or x["label"] for x in items}),
                           "selected": len({x.get("unit") or x["label"] for x in chosen}),
                           "commands": len(chosen),
                           "note": note,
                           "items": [_test_run_item(x) for x in chosen]})
    out = {"ok": True, "agents": agents_out, "acr": c.get("acr", []),
           "acr_preview": _acr_preview(c), "protect_acr": _flag(c.get("protect_acr")),
           "removal": c.get("removal", {"enabled": False, "tags": []}),
           "wait_minutes": c.get("wait_minutes", 0), "armed": c.get("armed", False),
           "writes_enabled": navi_cli.writes_enabled()}
    if tagname.enabled():
        out["tag_prefix"] = tagname.prefix()      # the page says every planned tag carries it
    return out


def _acr_preview(c) -> list:
    """Per ACR rule: what navi will do right now (core.acr_protect.preview mirrors navi) —
    how many assets change, are protected by NO : UPDATE (navi skips them) or have no ACR."""
    from core import acr_protect
    out = []
    for r in c.get("acr", []) or []:
        if not isinstance(r, dict):
            continue
        r = _acr_rule(r)
        pv = acr_protect.preview(r["category"], r["value"], r["score"], r["mod"])
        n = pv.get("counts") or {}
        out.append({"category": r["category"], "value": r["value"], "mod": r["mod"], "score": r["score"],
                    "business_case": acr_protect.business_case(r["reasons"], r["note"]),
                    "change": n.get("change", 0), "unchanged": n.get("unchanged", 0),
                    "protected": n.get("protected", 0), "no_acr": n.get("no_acr", 0),
                    "bad_acr": n.get("bad_acr", 0), "total": n.get("total", 0),
                    "refused": n.get("refused", 0),
                    "refuse": pv.get("refuse") or acr_protect.refuse_reason(r["category"], r["value"], r["score"], r["mod"]),
                    "valid_score": pv.get("valid_score", True), "error": pv.get("error")})
    return out


def _test_run_item(x):
    """A plan item as it will be WRITTEN: with Settings → Test run on, an add spec's category
    (and the label that names it) carry the prefix; removals stay exact. Off → unchanged."""
    spec, label = x["spec"], x["label"]
    if tagname.enabled() and not spec.get("remove"):
        cat = spec.get("category")
        eff = tagname.effective(cat)
        if eff != cat:
            spec = {**spec, "category": eff}
            if cat and label.startswith(cat + " :"):
                label = eff + label[len(cat):]
    return {"label": label, "rank": x["rank"], "spec": spec}


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
    """One shell word — single-quoted, so $(…), backticks, $VAR and quotes stay literal."""
    return shlex.quote(str("" if s is None else s))


def _cmd_for_spec(spec, force_remove=None):
    """Render one `navi enrich tag` command. force_remove overrides the spec's own
    remove flag (True → append -remove, False → never) so the exporter can emit a
    remove pass and an add pass from the same specs."""
    a = spec or {}
    rem = a.get("remove") if force_remove is None else force_remove
    rf = " -remove" if rem else ""
    # The category is rendered EXACTLY as the spec gives it: plan() already carries the
    # Settings → Test run prefix on its add specs, removals are exact, and the Tagging-log
    # export replays the name each job really wrote (core.tagname).
    cmd = "navi enrich tag --c " + _sh(a.get("category")) + " --v " + _sh(a.get("value"))
    if a.get("cve"):
        cmd += " --cve " + _sh(a["cve"]) + rf
    elif a.get("plugin_name") or a.get("name"):
        cmd += " --name " + _sh(a.get("plugin_name") or a.get("name")) + rf
    elif str(a.get("scanid", "")):
        cmd += " --scanid " + _sh(a["scanid"]) + rf
    elif str(a.get("plugin", "")):
        cmd += (" --plugin " + _sh(a["plugin"]) + (" --output " + _sh(a["output"]) if a.get("output") else "")
                + (" -regex" if a.get("output") and a.get("regex") else "") + rf)
    elif str(a.get("route_id", "")):
        cmd += " --route_id " + _sh(a["route_id"]) + rf
    elif str(a.get("group", "")):
        cmd += " --group " + _sh(a["group"]) + rf
    elif str(a.get("xrefs", "")):
        cmd += " --xrefs " + _sh(a["xrefs"]) + (" --xid " + _sh(a["xid"]) if a.get("xid") else "") + rf
    elif a.get("query") or not rem:
        cmd += " --query " + _sh(a.get("query")) + rf
    else:
        cmd += rf                    # pure removal: strip the tag from all its assets (navi_cli.tag)
    return cmd


def export_script(contract=None, db_path=None) -> str:
    """Render the contract's plan as a runnable `navi` script — the escape hatch
    for when MCP writes are blocked (run it where navi can write).

    Mirrors a cycle: ① strip ONLY the tags on the contract's removal list (the Garmr
    phase — tag UUIDs are kept), wait for navi to propagate, ② apply the planned tags
    (add-only: a planned tag is never removed), ③ ACR rules. Every value is shell-quoted.
    """
    c = contract or _CURRENT
    p = plan(c, db_path)
    specs = [it["spec"] for blk in p["agents"] for it in (blk.get("items") or [])]
    acr = c.get("acr", []) or []
    rem_cfg = c.get("removal") or {}
    rem = [t for t in (rem_cfg.get("tags") or []) if (t.get("category") or "").strip() and (t.get("value") or "").strip()] \
        if rem_cfg.get("enabled") else []
    lines = ["#!/usr/bin/env bash",
             "# Generated by The Hounds — AI Navi Contract plan",
             "# ① removal list (if any) → wait → ② add the planned tags → ③ ACR rules.",
             "# Run where navi can write (navi on PATH, API keys configured).",
             "set -e", ""]
    if rem:
        pause = int(_num(rem_cfg.get("pause_minutes"), 30, 0, 1440, int))
        lines.append('echo "① Removing %d tag(s) on the contract\'s removal list…"' % len(rem))
        for t in rem:
            # -remove is tolerant: a tag that no longer exists must not abort the run.
            lines.append(_cmd_for_spec({"category": t["category"].strip(), "value": t["value"].strip()},
                                       force_remove=True) + " || true")
        lines += ["", 'echo "⏳ Waiting %d min for Tenable to apply the removals…"' % pause,
                  "sleep %d" % (pause * 60), "navi update assets || true", ""]
    if specs:
        lines.append('echo "② Applying %d tag command(s)…"' % len(specs))
        for s_ in specs:
            lines.append(_cmd_for_spec(s_, force_remove=False))
    if acr:
        lines += ["", 'echo "③ Applying %d ACR rule(s)…"' % len(acr),
                  "# navi enrich acr skips every asset tagged NO : UPDATE (and any asset with no ACR"
                  " in navi.db) — those keep their ACR."]
        protect_ids = []
        from core import acr_protect
        for r in acr:
            r = _acr_rule(r)
            pv = acr_protect.preview(r["category"], r["value"], r["score"], r["mod"])
            why = pv.get("refuse") or acr_protect.refuse_reason(r["category"], r["value"], r["score"], r["mod"])
            line = "navi enrich acr --c %s --v %s --score %s --mod %s %s%s" % (
                _sh(r["category"]), _sh(r["value"]), _sh(r["score"]), _sh(r["mod"]),
                " ".join("-" + x for x in r["reasons"]),
                (" --note " + _sh(r["note"])) if r["note"] else "")
            if why:          # the Hounds refuse this rule (navi would change nothing / crash part-way)
                lines.append("# SKIPPED — %s" % " ".join(why.split()))
                lines.append("# " + line)
                continue
            lines.append(line)
            if _flag(c.get("protect_acr")):
                protect_ids += [a["uuid"] for a in pv.get("assets") or []
                                if a.get("status") in ("change", "unchanged") and a["uuid"] not in protect_ids]
        if _flag(c.get("protect_acr")):
            from core import acr_protect
            lines += ["", "# ④ Protect ACR after applying: tag NO : UPDATE on the %d asset(s) the rules above change"
                      " (as of this export) — navi leaves their ACR alone after the next navi update assets."
                      % len(protect_ids)]
            if not protect_ids:
                lines.append("# (no assets to protect)")
            for i in range(0, len(protect_ids), acr_protect.CHUNK):
                lines.append("navi enrich tag --c %s --v %s --query %s" % (
                    _sh(acr_protect.PROTECT_CATEGORY), _sh(acr_protect.PROTECT_VALUE),
                    _sh(acr_protect._query_for(protect_ids[i:i + acr_protect.CHUNK]))))
    lines += ["", 'echo "✓ Done."']
    return "\n".join(lines) + "\n"


def execute(contract=None, db_path=None, enforce_pause=True, skip_tags=None, apply=False) -> dict:
    """Queue the plan's tag commands, then the ACR rules. wait_minutes between agents is
    an autonomous-loop pacing — a manual run (enforce_pause=False) doesn't sleep.
    skip_tags = {(category, value)} not to re-apply this cycle (removed without a pause).
    apply=True: an explicit, confirmed manual run ("Execute one cycle now") writes even when
    the autonomous loop isn't armed — `armed` governs the loop, not a run the user asked for."""
    c = contract or _CURRENT
    p = plan(c, db_path)
    if not (c.get("armed") or apply):
        return {"ok": False, "skipped": "contract not armed — plan only", "plan": p}
    wait = (_num(c.get("wait_minutes"), 0, 0, 1440, int) * 60) if enforce_pause else 0
    skip = {(str(a).strip(), str(b).strip()) for a, b in (skip_tags or ())}
    queued, held, acr_done = 0, 0, 0
    for blk in p["agents"]:
        for it in blk["items"]:
            spec = dict(it["spec"])
            if (str(spec.get("category") or "").strip(), str(spec.get("value") or "").strip()) in skip:
                held += 1
                continue
            navi_cli.tag(agent=blk["agent"], **spec)     # -> background tag queue
            queued += 1
        if wait and blk["items"]:
            time.sleep(wait)
    applied = []                      # (batch, business case) of ACR rules that went through
    for rule in c.get("acr", []):
        try:
            r = navi_cli.acr(rule.get("category", ""), rule.get("value", ""),
                             float(rule.get("score", 0)), mod=rule.get("mod", "set"),
                             note=rule.get("note"), reasons=rule.get("reasons") or ["business"],
                             agent="contract")
            acr_done += 1
            if isinstance(r, dict) and r.get("ok") and not r.get("blocked") and (r.get("acr_log") or {}).get("batch"):
                applied.append((r["acr_log"]["batch"], r.get("business_case") or ""))
        except Exception:
            pass
    out = {"ok": True, "queued_tags": queued, "acr_applied": acr_done, "plan": p}
    if _flag(c.get("protect_acr")):
        # after ALL the rules (a later rule may hit the same asset this cycle): NO : UPDATE on
        # exactly the assets they applied to, each job carrying its rule's business case
        try:
            from core import acr_protect, acrlog
            groups = {}
            for batch, bc in applied:
                groups.setdefault(bc, []).extend(acrlog.batch_uuids(batch, "applied"))
            pr = acr_protect.protect(groups, agent="contract") if groups else {"assets": 0, "queued_jobs": 0}
            out["acr_protected"] = pr.get("assets", 0)
            out["acr_protect_jobs"] = pr.get("queued_jobs", 0)
        except Exception as e:
            out["acr_protected"] = 0
            out["acr_protect_error"] = str(e)
    if held:
        out["held_tags"] = held
    return out


# --------------------------------------------------------------------------- #
#  background navi update (fire-and-forget) + QA + cycle + scheduler
# --------------------------------------------------------------------------- #
def _navi_update_bg(kinds=("assets", "vulns")):
    """Refresh navi.db in the background: `navi config update assets`, then `... vulns`, one
    after the other (two syncs at once lock navi.db). Runs through core.cli_jobs, so it uses the
    resolved navi binary, runs in the folder that holds the console's navi.db, and its output is
    visible in the console's navi jobs window. (Before build 450 this ran `navi update <kind>` —
    not a navi 8.x command — from the server's cwd with its output discarded, so navi.db was
    never refreshed and removed tags kept showing as present.)"""
    if not navi_cli.navi_available():
        return {"started": [], "skipped": "navi not on PATH"}
    from core import cli_jobs
    kinds = [k for k in kinds if k in cli_jobs.COMMANDS]

    def _chain():
        for k in kinds:
            try:
                r = cli_jobs.start_update(k)
                jid = (r.get("job") or {}).get("id")
                if not r.get("ok") or jid is None:
                    continue
                t0 = time.time()
                while time.time() - t0 < 6 * 3600:        # a big tenant's vulns sync can take hours
                    j = cli_jobs.poll(jid, since=10 ** 9) or {}   # status only, no lines
                    if (j.get("job") or j).get("status") != "running":
                        break
                    time.sleep(5)
            except Exception:
                pass
    threading.Thread(target=_chain, daemon=True, name="contract-navi-update").start()
    return {"started": list(kinds), "commands": ["navi " + " ".join(cli_jobs.COMMANDS[k]) for k in kinds]}


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


def _notify_run(c, entry):
    """Email a Gabriel run-summary of this cycle — on by default, disabled via
    notify.enabled. Recipient = notify.to → NAVI_ALERT_EMAIL → NAVI_EMAIL_TO. Send is
    gated by NAVI_EMAIL; a disabled inbox just records what would have gone out."""
    nt = c.get("notify") or {}
    if not nt.get("enabled", True):
        return {"skipped": "disabled"}
    to = (nt.get("to") or os.environ.get("NAVI_ALERT_EMAIL") or os.environ.get("NAVI_EMAIL_TO") or "").strip()
    if not to:
        return {"skipped": "no recipient — set one in the AI Contract, or NAVI_ALERT_EMAIL"}
    if not navi_cli.email_enabled():
        return {"skipped": navi_cli.email_gate_reason()}
    al = entry.get("alerts") or {}
    nf = al.get("newly_fired") or []
    subj = "[Hounds] Contract cycle — %d tag(s) queued%s%s" % (
        entry.get("queued_tags", 0),
        (" · %d ACR" % entry["acr_applied"]) if entry.get("acr_applied") else "",
        (" · %d alert(s)" % len(nf)) if nf else "")
    lines = ["The Hounds · AI Contract (Covenant) cycle", "",
             "Finished: %s UTC" % entry.get("finished", ""),
             "Mode: %s" % {"armed": "ARMED — writes applied",
                           "manual": "MANUAL run — writes applied (autonomous loop not armed)"}.get(
                 entry.get("mode") or ("armed" if entry.get("armed") else "plan"), "disarmed — planned only"),
             "Tags queued: %d" % entry.get("queued_tags", 0),
             "ACR applied: %d" % entry.get("acr_applied", 0)]
    rem = entry.get("removal") or {}
    if rem.get("removed_jobs"):
        lines.append("Tags removed: %s job(s)" % rem.get("removed_jobs"))
    pc = entry.get("plan_counts") or {}
    if pc:
        lines.append("Per agent: " + ", ".join("%s %d" % (k, v) for k, v in pc.items() if v))
    qa = entry.get("qa") or {}
    if isinstance(qa, dict) and qa:
        lines.append("QA: " + ", ".join("%s %s" % (k, v) for k, v in qa.items()))
    if nf:
        lines += ["", "🚨 Alerts newly fired (Alert Raven): " + ", ".join(nf)]
    lines += ["", "— The Hounds · Covenant. Turn these run emails off in the AI Contract page (Notify)."]
    try:
        r = navi_cli.mail(to=to, subject=subj, message="\n".join(lines), agent="contract")
        return {"sent": bool(r.get("ok")), "to": to, "reason": r.get("message") or r.get("error")}
    except Exception as e:
        return {"error": str(e), "to": to}


def run_cycle(contract=None, enforce_pause=True, apply=False) -> dict:
    """One contract cycle. apply=True is the confirmed manual run: it writes (removal list,
    tags, ACR) even when the autonomous loop isn't armed, without arming it."""
    global _OPTIMIZED
    c = contract or _CURRENT
    live = bool(c.get("armed") or apply)
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
    skip = set()
    if rem_cfg.get("enabled") and rem_cfg.get("tags") and live:
        removed = _remove_tags(c)
        pause = _num(rem_cfg.get("pause_minutes"), 30, 0, 1440, int)
        removal_info = {"removed_jobs": removed, "pause_minutes": pause,
                        "paused": bool(pause > 0 and enforce_pause)}
        if pause > 0 and enforce_pause:
            time.sleep(pause * 60)                       # autonomous loop only (not manual run_now)
        else:
            # No pause: the removals are still queued, so re-adding the same tag now would
            # race them (the add can land first and then be stripped). Hold those tags
            # until the next cycle; everything else is tagged as usual.
            skip = {((t.get("category") or "").strip(), (t.get("value") or "").strip())
                    for t in rem_cfg.get("tags") or []}
            removal_info["held_until_next_cycle"] = len(skip)
        upd = _navi_update_bg() if rem_cfg.get("navi_update", True) else {"skipped": "disabled"}
        removal_info["navi_update"] = upd
    else:
        upd = _navi_update_bg() if c.get("navi_update") else {"skipped": "disabled"}
    try:
        before = db.scalar("SELECT COUNT(*) FROM tags;")
    except Exception:
        before = None
    ex = execute(c, enforce_pause=enforce_pause, skip_tags=skip, apply=live)
    qa = _qa(before)
    # ── Alert Raven alert sweep ──────────────────────────────────────────────
    # Every cycle, evaluate the enabled alerts against the (freshly-updated) navi.db
    # and email a digest of anything that NEWLY fired. Read-only detection; the send
    # is gated by NAVI_EMAIL, so a disabled inbox just records what would have gone out.
    alerts_info = {"skipped": "no alerts engine"}
    try:
        from core import alerts as _alerts
        _ar = _alerts.evaluate_all(send=True, source="contract")
        alerts_info = {"evaluated": len(_ar.get("evaluated", [])),
                       "newly_fired": [r["name"] for r in _ar.get("newly_fired", [])],
                       "sent": bool(_ar.get("sent") and _ar["sent"].get("ok"))}
    except Exception as e:
        alerts_info = {"error": str(e)}
    entry = {"started": started, "finished": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
             "armed": c.get("armed", False), "applied": live,
             "mode": "armed" if c.get("armed") else ("manual" if live else "plan"),
             "navi_update": upd, "optimize": opt,
             "removal": removal_info, "alerts": alerts_info,
             "queued_tags": ex.get("queued_tags", 0), "acr_applied": ex.get("acr_applied", 0),
             "acr_protected": ex.get("acr_protected", 0),
             "skipped": ex.get("skipped"), "qa": qa,
             "plan_counts": {b["agent"]: b.get("selected", 0) for b in ex.get("plan", {}).get("agents", [])}}
    entry["notify"] = _notify_run(c, entry)     # Gabriel run-summary email (on by default, toggleable)
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
