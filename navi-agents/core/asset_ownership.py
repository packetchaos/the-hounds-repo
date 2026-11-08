"""Asset Ownership — the asset-perspective ownership engine (Terminus).

Atlas (exproute) answers "who owns each ROUTE / PATH?" — a route/path can carry
many owners. Terminus flips it to the ASSET: for every asset, *who owns it, how
much of it is claimed, what's left blind, and — for the crown jewels — what do
the rest of the Hounds already know?*

Three ownership layers, read off tags:

  * ``Owner``          — Atlas's per-route/path technology owners
                         (value scheme ``<app/path>: <user>``; may be several per asset).
  * ``Business Owner`` — a business leader accountable for a group of assets / apps
                         (value = the owner). The accountability layer.
  * ``Asset Owner``    — a SINGLE owner who owns the WHOLE asset — every route & path
                         (value ``<owner> · complete`` or ``<owner> · remainder``).
                         Setting it *closes* the asset: 100% claimed. Written by the
                         "one owner owns everything / the rest" toggle.

Crown jewels = ``assets.acr >= CROWN_ACR`` (9) or an explicit crown-jewel business
tag. All reads are read-only; every write goes through the gated navi tag path.
"""
from core import db, navi_cli, tagname

CROWN_ACR = 9
_CROWN_TAG_VALUES = {"crown jewel", "crown-jewel", "mission critical", "mission-critical",
                     "tier 1", "tier-1", "tier1"}
BUSINESS_OWNER_KEY = "Business Owner"
ASSET_OWNER_KEY = "Asset Owner"
DISPOSITIONS = ("Ignored", "Accepted", "Mitigated")

# tag keys that are ownership bookkeeping, not a Hound "signal"
_OWNER_KEYS = {"Owner", BUSINESS_OWNER_KEY, ASSET_OWNER_KEY}

# asset↔route membership: an asset is "on" a route when it carries a vuln whose
# plugin id is in that route's plugin_list (stored like ['51192','187315']).
_RA = ("WITH ra AS (SELECT DISTINCT r.app_name app, v.asset_uuid au "
       "FROM vuln_route r JOIN vulns v ON r.plugin_list LIKE '%''' || v.plugin_id || '''%') ")


def _q(sql, args=(), path=None):
    try:
        return list(db.query(sql, args, path=path)) if args else list(db.query(sql, path=path))
    except Exception:
        return []


def _has_table(name, path=None):
    return bool(_q("SELECT name FROM sqlite_master WHERE type='table' AND name=?", (name,), path))


def _fnum(x):
    try:
        v = float(x)
        return v if v == v else None
    except (TypeError, ValueError):
        return None


def _disp_of(user):
    u = (user or "").strip().lower()
    for d in DISPOSITIONS:
        if u == d.lower():
            return d
    return None


# --------------------------------------------------------------------------- #
#  Raw asset + tag + membership loaders                                        #
# --------------------------------------------------------------------------- #
def _asset_cols(path=None):
    return {r["name"] for r in _q("PRAGMA table_info(assets)", path=path)}


def assets_with_tags(db_path=None) -> list[dict]:
    """Every asset with its attributes AND all its tags — the object the NL
    processor reasons over (it can filter on any tag key/value or attribute)."""
    if not _has_table("assets", db_path):
        return []
    cols = _asset_cols(db_path)
    acr = "acr" if "acr" in cols else "NULL AS acr"
    aes = "aes" if "aes" in cols else "NULL AS aes"
    url = "url" if "url" in cols else "NULL AS url"
    rows = _q(f"SELECT uuid, hostname, ip_address ip, {acr}, {aes}, {url} FROM assets", path=db_path)
    by = {}
    cloud_cols = [c for c in ("aws_id", "azure_vm_id", "gcp_instance_id") if c in cols]
    for r in rows:
        u = r.get("uuid")
        if not u:
            continue
        by[u] = {"uuid": u, "hostname": r.get("hostname"), "ip": r.get("ip"),
                 "acr": _fnum(r.get("acr")), "aes": _fnum(r.get("aes")), "url": r.get("url"),
                 "tags": [], "_tagmap": {}}
    if cloud_cols:
        cc = ", ".join(cloud_cols)
        for r in _q(f"SELECT uuid, {cc} FROM assets", path=db_path):
            u = r.get("uuid")
            if u in by and any(r.get(c) for c in cloud_cols):
                by[u]["cloud"] = True
    for r in _q("SELECT asset_uuid, tag_key, tag_value FROM tags WHERE asset_uuid IS NOT NULL", path=db_path):
        e = by.get(r.get("asset_uuid"))
        if not e:
            continue
        k, v = (r.get("tag_key") or "").strip(), (r.get("tag_value") or "").strip()
        if not k:
            continue
        e["tags"].append({"key": k, "value": v})          # the real name (shown as is)
        e["_tagmap"].setdefault(k.lower(), []).append(v)
        bk = tagname.base(k)                              # a test-run 'Hounds-Owner' also
        if bk != k:                                       # counts as 'Owner' (core.tagname)
            e["_tagmap"].setdefault(bk.lower(), []).append(v)
    return list(by.values())


def _route_members(db_path=None) -> dict:
    """uuid -> set(route app_name) it sits on."""
    out = {}
    if not _has_table("vuln_route", db_path):
        return out
    for r in _q(_RA + "SELECT app, au FROM ra", path=db_path):
        if r.get("au") and r.get("app"):
            out.setdefault(r["au"], set()).add(r["app"])
    return out


def _path_members(db_path=None) -> dict:
    out = {}
    if not _has_table("vuln_paths", db_path):
        return out
    for r in _q("SELECT DISTINCT asset_uuid au, path FROM vuln_paths WHERE path IS NOT NULL", path=db_path):
        if r.get("au"):
            out.setdefault(r["au"], set()).add(r["path"])
    return out


def _vuln_risk(db_path=None) -> dict:
    """uuid -> (open critical findings, has an open CISA-KEV finding). Read-only; tolerant
    of a missing vulns table or columns (navi.db shapes vary). Fixed findings are skipped
    when navi recorded a state."""
    if not _has_table("vulns", db_path):
        return {}
    vc = {r["name"] for r in _q("PRAGMA table_info(vulns)", path=db_path)}
    if "asset_uuid" not in vc:
        return {}
    sev = "lower(severity) IN ('critical','4')" if "severity" in vc else "0"
    kev = "xrefs LIKE '%CISA-KNOWN-EXPLOITED%'" if "xrefs" in vc else "0"
    where = ("WHERE lower(COALESCE(state,'open')) IN ('open','reopened')" if "state" in vc else "")
    out = {}
    for r in _q(f"SELECT asset_uuid u, SUM(CASE WHEN {sev} THEN 1 ELSE 0 END) c, "
                f"MAX(CASE WHEN {kev} THEN 1 ELSE 0 END) k FROM vulns {where} GROUP BY asset_uuid",
                path=db_path):
        if r.get("u"):
            out[r["u"]] = (int(r.get("c") or 0), bool(r.get("k")))
    return out


def _nk(s):
    return " ".join((s or "").strip().lower().split())


# --------------------------------------------------------------------------- #
#  Per-asset ownership rollup                                                  #
# --------------------------------------------------------------------------- #
def _is_crown(a):
    if a.get("acr") is not None and a["acr"] >= CROWN_ACR:
        return True
    for v in a.get("_tagmap", {}).get("business tier", []):
        if _nk(v) in _CROWN_TAG_VALUES:
            return True
    return any(_nk(v) in _CROWN_TAG_VALUES for vs in a.get("_tagmap", {}).values() for v in vs)


def _asset_ownership(a, routes_on, paths_on):
    """Compute the ownership picture for ONE asset from its tags + route/path surface."""
    tm = a.get("_tagmap", {})
    # ---- layer 1: Asset Owner (single, complete) ----
    asset_owner, ao_mode = None, None
    for v in tm.get(ASSET_OWNER_KEY.lower(), []):
        val = (v or "").strip()
        if not val:
            continue
        if " · " in val:
            nm, mode = val.rsplit(" · ", 1)
            asset_owner, ao_mode = nm.strip(), mode.strip().lower()
        else:
            asset_owner, ao_mode = val, "complete"
        break
    # ---- layer 2: Business Owner ----
    biz = sorted({v.strip() for v in tm.get(BUSINESS_OWNER_KEY.lower(), []) if v.strip()})
    # ---- layer 3: Owner (per route/path technology owners + dispositions) ----
    tech, disp_names = set(), set()
    owned_names = set()          # route/path names this asset carries an owner tag for
    for v in tm.get("owner", []):
        val = (v or "").strip()
        if ": " not in val:
            # a bare ``Owner: <team>`` (navi's classic asset-level owner tag) names an
            # owner for the asset without claiming any one route/path — it still makes the
            # asset owned, exactly as Exposure Score (core/fused_score._row_signals) reads it
            if val and not _disp_of(val):
                tech.add(val)
            continue
        nm, user = val.rsplit(": ", 1)
        nm, user = nm.strip(), user.strip()
        d = _disp_of(user)
        if d:
            disp_names.add((_nk(nm), d))
        elif user:
            tech.add(user)
            owned_names.add(_nk(nm))
    surface_items = {("route", _nk(r)) for r in routes_on} | {("path", _nk(p)) for p in paths_on}
    surface = len(surface_items)
    # which surface items are owned / dispositioned
    owned = sum(1 for _, nm in surface_items if nm in owned_names)
    disp_map = {}
    for nm, d in disp_names:
        disp_map[nm] = d
    dispositioned = sum(1 for _, nm in surface_items if nm in disp_map)
    # claimed: asset owner closes everything; else owned + dispositioned handled items.
    # An item can carry both an owner tag and a disposition — count it once, so the
    # claimed share can never exceed 100%.
    handled_items = sum(1 for _, nm in surface_items if nm in owned_names or nm in disp_map)
    if asset_owner:
        claimed_pct = 100.0
        handled = surface
    elif surface:
        handled = handled_items
        claimed_pct = round(100.0 * handled / surface, 1)
    else:
        handled = 0
        claimed_pct = 100.0 if (asset_owner or biz) else None   # None = no exposure surface
    has_any_owner = bool(asset_owner or tech or biz)
    # disposition rollup for this asset (share of surface)
    mit = sum(1 for _, nm in surface_items if disp_map.get(nm) == "Mitigated")
    acc = sum(1 for _, nm in surface_items if disp_map.get(nm) == "Accepted")
    ign = sum(1 for _, nm in surface_items if disp_map.get(nm) == "Ignored")
    return {
        "asset_owner": asset_owner, "asset_owner_mode": ao_mode,
        "business_owners": biz, "tech_owners": sorted(tech),
        "surface": surface, "owned": owned, "dispositioned": dispositioned, "handled": handled,
        "claimed_pct": claimed_pct, "has_owner": has_any_owner,
        "mitigated": mit, "accepted": acc, "ignored": ign,
        "unclaimed": (surface > 0 and not has_any_owner and handled == 0),
    }


def _hound_signals(a):
    """What the Hounds already know about this asset — its non-ownership tags,
    grouped by key (KEV, Lifecycle/EOL, Post-Quantum, AI, IoT, Class, NHI, Attack
    Path, Cert failure, Scan Health, Mitre, Software…)."""
    sig = {}
    for t in a.get("tags", []):
        k = t["key"]
        if tagname.base(k) in _OWNER_KEYS:
            continue
        sig.setdefault(k, [])
        if t["value"] and t["value"] not in sig[k]:
            sig[k].append(t["value"])
    return sig


def overview(db_path=None) -> dict:
    """The Asset Ownership dashboard payload — per-asset rollup + KPIs + crown
    jewels (what the Hounds know) + blind spots. Read-only."""
    if not _has_table("assets", db_path):
        return {"ok": False, "error": "no assets table in navi.db — run `navi config update assets`"}
    assets = assets_with_tags(db_path)
    routes_by = _route_members(db_path)
    paths_by = _path_members(db_path)
    risk_by = _vuln_risk(db_path)

    rows, crown, blind = [], [], []
    owners = {}                       # name -> {assets, crown, business, asset, tech}
    surf_owned = surf_disp = surf_handled = 0
    kev_count = 0
    for a in assets:
        ro = routes_by.get(a["uuid"], set())
        pa = paths_by.get(a["uuid"], set())
        own = _asset_ownership(a, ro, pa)
        sig = _hound_signals(a)
        is_crown = _is_crown(a)
        primary_owner = (own["asset_owner"] or (own["tech_owners"][0] if own["tech_owners"] else None)
                         or (own["business_owners"][0] if own["business_owners"] else None))
        row = {
            "uuid": a["uuid"], "hostname": a.get("hostname"), "ip": a.get("ip"),
            "acr": a.get("acr"), "crown": is_crown, "cloud": a.get("cloud", False),
            "routes": len(ro), "paths": len(pa),
            "asset_owner": own["asset_owner"], "asset_owner_mode": own["asset_owner_mode"],
            "business_owners": own["business_owners"], "tech_owners": own["tech_owners"],
            "primary_owner": primary_owner,
            "claimed_pct": own["claimed_pct"], "surface": own["surface"],
            "unclaimed": own["unclaimed"], "has_owner": own["has_owner"],
            "mitigated": own["mitigated"], "accepted": own["accepted"], "ignored": own["ignored"],
            "signals": sig, "signal_count": len(sig),
            "crit": risk_by.get(a["uuid"], (0, False))[0],
            "kev": risk_by.get(a["uuid"], (0, False))[1],
        }
        rows.append(row)
        surf_owned += own["owned"]
        surf_disp += own["dispositioned"]
        surf_handled += own["handled"]
        layers = ([("asset", own["asset_owner"])] if own["asset_owner"] else []) \
            + [("business", b) for b in own["business_owners"]] + [("tech", t) for t in own["tech_owners"]]
        seen = set()
        for layer, name in layers:
            o = owners.setdefault(name, {"name": name, "assets": 0, "crown": 0,
                                         "business": 0, "asset": 0, "tech": 0})
            o[layer] += 1
            if name not in seen:
                seen.add(name)
                o["assets"] += 1
                o["crown"] += 1 if is_crown else 0
        if any(_nk(k) == "cisa kev" or "kev" in _nk(k) for k in sig):
            kev_count += 1
        if is_crown:
            crown.append(row)
        # blind spots — unclaimed crown jewels, unclaimed high-ACR, or exposed-but-no-signal
        if own["unclaimed"] and (is_crown or (a.get("acr") or 0) >= 7):
            blind.append(row)

    # ---- KPIs ----
    n = len(rows)
    with_surface = [r for r in rows if r["surface"] > 0]
    unclaimed = [r for r in with_surface if r["unclaimed"]]
    fully = [r for r in with_surface if r["claimed_pct"] == 100.0]
    biz_owned = [r for r in rows if r["business_owners"]]
    asset_owned = [r for r in rows if r["asset_owner"]]
    tech_owned = [r for r in rows if r["tech_owners"]]
    claimed_vals = [r["claimed_pct"] for r in with_surface if r["claimed_pct"] is not None]
    avg_claimed = round(sum(claimed_vals) / len(claimed_vals), 1) if claimed_vals else 0.0
    # surface-level disposition tally (routes+paths handled by a disposition)
    surf_total = sum(r["surface"] for r in with_surface) or 1
    mit = sum(r["mitigated"] for r in rows)
    acc = sum(r["accepted"] for r in rows)
    ign = sum(r["ignored"] for r in rows)

    def pct(a, b):
        return round(100.0 * a / b, 1) if b else 0.0

    owned_rows = [r for r in rows if r["has_owner"]]
    _tu = max((r for r in rows if not r["has_owner"]),
              key=lambda r: (r["acr"] or 0, r["crit"], r["surface"]), default=None)
    top_unowned = ({"uuid": _tu["uuid"], "hostname": _tu["hostname"], "ip": _tu["ip"],
                    "acr": _tu["acr"], "crit": _tu["crit"]} if _tu else None)
    crown_owned = [r for r in crown if r["has_owner"]]
    crown_unclaimed = [r for r in crown if r["surface"] > 0 and not r["has_owner"]]
    crown_biz = [r for r in crown if r["business_owners"]]

    # blind by category
    blind_no_signal = [r for r in rows if r["signal_count"] == 0]
    cred_fail = [r for r in rows if any("cred failure" in _nk(k) + " " + _nk(str(v))
                                        for k, vs in r["signals"].items() for v in (vs or [""]))]

    kpi = {
        "assets": n, "with_surface": len(with_surface),
        "fully_claimed": len(fully), "fully_claimed_pct": pct(len(fully), len(with_surface)),
        "unclaimed": len(unclaimed), "unclaimed_pct": pct(len(unclaimed), len(with_surface)),
        "avg_claimed_pct": avg_claimed,
        "business_owned": len(biz_owned), "business_owned_pct": pct(len(biz_owned), n),
        "asset_owned": len(asset_owned), "tech_owned": len(tech_owned),
        "mitigated": mit, "mitigated_pct": pct(mit, surf_total),
        "accepted": acc, "accepted_pct": pct(acc, surf_total),
        "ignored": ign, "ignored_pct": pct(ign, surf_total),
        "crown": len(crown), "crown_owned": len(crown_owned),
        "crown_unclaimed": len(crown_unclaimed), "crown_owned_pct": pct(len(crown_owned), len(crown)),
        "crown_business_owned": len(crown_biz),
        "kev_assets": kev_count, "blind": len(blind),
        "blind_no_signal": len(blind_no_signal), "cred_fail": len(cred_fail),
        "crown_acr": CROWN_ACR,
        # --- "At a glance" (build 441) — all derived from the rollup above ---
        "owned": len(owned_rows), "owned_pct": pct(len(owned_rows), n),
        "no_owner": n - len(owned_rows), "no_owner_pct": pct(n - len(owned_rows), n),
        "no_business": n - len(biz_owned), "no_business_pct": pct(n - len(biz_owned), n),
        "asset_owned_complete": sum(1 for r in asset_owned if r["asset_owner_mode"] != "remainder"),
        "asset_owned_remainder": sum(1 for r in asset_owned if r["asset_owner_mode"] == "remainder"),
        "owners_distinct": len(owners),
        "surface_items": sum(r["surface"] for r in rows), "surface_owned": surf_owned,
        "surface_dispositioned": surf_disp, "surface_handled": surf_handled,
        "surface_handled_pct": pct(surf_handled, sum(r["surface"] for r in rows)),
        "crown_no_owner": len([r for r in crown if not r["has_owner"]]),
        "has_vulns": bool(risk_by),
        "crit_assets": sum(1 for r in rows if r["crit"]),
        "kev_finding_assets": sum(1 for r in rows if r["kev"]),
        "unowned_crit": sum(1 for r in rows if r["crit"] and not r["has_owner"]),
        "unowned_crit_findings": sum(r["crit"] for r in rows if not r["has_owner"]),
        "unowned_kev": sum(1 for r in rows if r["kev"] and not r["has_owner"]),
        "top_unowned": top_unowned,
    }
    rows.sort(key=lambda r: (-(r["acr"] or 0), r["claimed_pct"] if r["claimed_pct"] is not None else 999))
    crown.sort(key=lambda r: (0 if not r["has_owner"] else 1, -(r["acr"] or 0)))
    blind.sort(key=lambda r: -(r["acr"] or 0))
    ol = sorted(owners.values(), key=lambda o: (-o["assets"], o["name"].lower()))
    return {"ok": True, "kpi": kpi, "assets": rows, "crown_jewels": crown,
            "blind_spots": blind[:200], "owners": ol[:100], "owners_total": len(ol)}


# --------------------------------------------------------------------------- #
#  Natural-language ownership planner (tag-aware)                              #
# --------------------------------------------------------------------------- #
def tag_schema(db_path=None) -> dict:
    """Distinct tag keys -> their distinct values — the vocabulary the NL processor
    (and the operator) can filter on. Ownership keys are excluded (you assign those)."""
    out = {}
    for r in _q("SELECT tag_key k, tag_value v, COUNT(DISTINCT asset_uuid) n FROM tags "
                "GROUP BY tag_key, tag_value", path=db_path):
        k = (r.get("k") or "").strip()
        if not k or tagname.base(k) in _OWNER_KEYS:
            continue
        out.setdefault(k, []).append({"value": (r.get("v") or "").strip(), "assets": r.get("n") or 0})
    return out


def _match_asset(a, filt):
    """Evaluate a structured filter against one asset (attributes + tags)."""
    tm = a.get("_tagmap", {})
    if filt.get("crown") and not _is_crown(a):
        return False
    acr = a.get("acr")
    if filt.get("acr_min") is not None and (acr is None or acr < filt["acr_min"]):
        return False
    if filt.get("acr_max") is not None and (acr is None or acr > filt["acr_max"]):
        return False
    if filt.get("cloud") and not a.get("cloud"):
        return False
    for cond in filt.get("tags", []):
        k = (cond.get("key") or "").strip().lower()
        v = _nk(cond.get("value"))
        vals = [_nk(x) for x in tm.get(k, [])]
        if v:
            if not any(v in x or x in v for x in vals):
                return False
        else:
            if not vals:      # key must be present
                return False
    for term in filt.get("host_like", []):
        t = _nk(term)
        if t and t not in _nk(a.get("hostname")) and t not in _nk(a.get("ip")):
            return False
    return True


def _rule_plan(prompt, schema):
    """Key-free fallback parser: pull an owner, a layer, a mode, and tag/acr/crown
    conditions out of plain English — no model needed for the common phrasings."""
    import re
    p = " " + (prompt or "").strip() + " "
    pl = p.lower()
    filt = {"tags": [], "host_like": []}
    # The SINGLE Asset-Owner layer is only meant when the prompt explicitly signals
    # complete/whole-asset ownership; a plain assignment to a tag-group is a Business Owner.
    asset_signal = re.search(
        r"\b(asset owner|single owner|sole owner|complete|entire asset|whole asset|everything|"
        r"every route|every path|all routes|all paths|owns the rest|the rest|remaining|remainder)\b", pl)
    remainder = re.search(r"\b(the rest|remaining|remainder|leftover|not (?:yet )?owned|unowned)\b", pl)
    force_biz = re.search(r"\bbusiness\b", pl)
    layer = "asset" if (asset_signal and not force_biz) else "business"
    mode = ("remainder" if remainder else "complete") if layer == "asset" else None
    # crown / acr
    if re.search(r"\bcrown\s*jewel", pl) or re.search(r"\bcrown\b", pl):
        filt["crown"] = True
    m = re.search(r"acr\s*(>=|>|=|≥)?\s*(\d+)", pl)
    if m:
        filt["acr_min"] = int(m.group(2))
    # tag key:value matches from the live schema (e.g. "production" -> Environment/Business Tier)
    for k, vals in (schema or {}).items():
        for entry in vals:
            v = (entry.get("value") or "").strip()
            if v and re.search(r"\b" + re.escape(v.lower()) + r"\b", pl):
                filt["tags"].append({"key": k, "value": v})
    owner = _extract_owner(pl, schema)
    return {"owner": owner, "layer": layer, "mode": mode, "filter": filt}


_OWNER_STOP = {"the", "a", "an", "all", "every", "rest", "remaining", "remainder", "leftover",
               "owner", "owners", "owns", "own", "owned", "route", "routes", "path", "paths",
               "asset", "assets", "vuln", "vulns", "vulnerability", "vulnerabilities", "everything",
               "complete", "completely", "single", "sole", "whole", "entire", "of", "on", "for",
               "as", "to", "and", "by", "crown", "jewel", "jewels", "cloud", "acr", "business",
               "tier", "assign", "assigned", "give", "given", "make", "set", "accountable",
               "is", "are", "be", "that", "this", "with", "who", "them", "their", "please",
               "control", "ownership", "responsible", "responsibility"}


def _extract_owner(pl, schema):
    """Pull the owner name out of a prompt: try the strong markers, then strip filler
    and any live tag-value words (so 'production'/'crown' can't be read as the owner)."""
    import re
    stop = set(_OWNER_STOP) | {_nk(e["value"]) for vs in (schema or {}).values() for e in vs}
    spans = []
    for pat in (r"owned by ([a-z0-9 ._@'&/-]+)",
                r"\bassign(?:ed)?\s+([a-z0-9 ._@'&/-]+?)\s+(?:to|as|the|for|ownership)\b",
                r"\bgive\s+([a-z0-9 ._@'&/-]+?)\s+(?:the|all|every|ownership|complete|control|of|responsibility)\b",
                r"\bmake\s+([a-z0-9 ._@'&/-]+?)\s+(?:the\s+)?(?:complete\s+|single\s+|sole\s+)?owner",
                r"([a-z0-9 ._@'&/-]+?)\s+is\s+(?:the\s+)?(?:complete\s+|single\s+|sole\s+)?owner",
                r"([a-z0-9 ._@'&/-]+?)\s+owns?\b",
                r"\bowner\s*(?:is|=|:)\s*([a-z0-9 ._@'&/-]+)"):
        for m in re.finditer(pat, pl):
            spans.append(m.group(1))
    for s in spans:
        toks = [t for t in re.split(r"[^a-z0-9._@'&/-]+", s) if t and t not in stop
                and not t.isdigit()]
        if toks:
            return " ".join(toks[:3])
    return None


def plan(prompt, db_path=None) -> dict:
    """Turn a plain-English instruction into a preview: which owner, which layer
    (business vs single asset owner), and the matched assets — considering each
    asset's attributes AND its existing tags. Nothing is written."""
    prompt = (prompt or "").strip()
    if not prompt:
        return {"ok": False, "error": "describe who owns which assets"}
    schema = tag_schema(db_path)
    assets = assets_with_tags(db_path)
    owner_names = []
    try:
        from agents.exproute.agent import owners as _owners
        owner_names = [{"name": o["name"], "type": o["type"], "alt": o.get("detail", "")}
                       for o in _owners()]
    except Exception:
        owner_names = []

    parsed, used_llm = None, False
    try:
        from core import llm
        if llm.available():
            out = llm.asset_owner_plan(prompt, schema, owner_names,
                                       [a["hostname"] for a in assets[:40] if a.get("hostname")])
            if out.get("ok") and out.get("owner"):
                parsed = {"owner": out.get("owner"), "layer": out.get("layer") or "business",
                          "mode": out.get("mode"), "filter": out.get("filter") or {}}
                used_llm = True
    except Exception:
        parsed = None
    if not parsed:
        parsed = _rule_plan(prompt, schema)
    if not parsed.get("owner"):
        return {"ok": False, "error": "couldn't find an owner in that — try “assign <name> to …”",
                "llm_available": used_llm}

    filt = parsed.get("filter") if isinstance(parsed.get("filter"), dict) else {}
    # a model-built filter may be loosely shaped — keep only well-formed conditions
    filt["tags"] = [c for c in (filt.get("tags") or []) if isinstance(c, dict) and (c.get("key") or "").strip()]
    filt["host_like"] = [h for h in (filt.get("host_like") or []) if isinstance(h, str) and h.strip()]
    matched = [a for a in assets if _match_asset(a, filt)]
    # resolve owner to a canonical navi user/group when possible (business leaders are
    # often NOT in the directory — accept the literal name, but flag it).
    resolved, resolved_note = parsed["owner"], None
    try:
        from agents.exproute.agent import resolve_owner
        entry, err = resolve_owner(parsed["owner"])
        if entry:
            resolved = entry["name"]
        else:
            resolved_note = f"“{parsed['owner']}” isn't a navi user/group — will tag as a free-text owner."
    except Exception:
        pass

    layer = "asset" if parsed.get("layer") == "asset" else "business"
    mode = (parsed.get("mode") or ("complete" if layer == "asset" else None))
    # describe the filter for the UI
    desc = []
    if filt.get("crown"):
        desc.append("crown jewels")
    if filt.get("acr_min") is not None:
        desc.append(f"ACR ≥ {filt['acr_min']}")
    if filt.get("cloud"):
        desc.append("cloud")
    for c in filt.get("tags", []):
        desc.append(f"{c['key']}: {c['value']}" if c.get("value") else c["key"])
    for h in filt.get("host_like", []):
        desc.append(f"host~{h}")
    preview = [{"uuid": a["uuid"], "hostname": a.get("hostname"), "ip": a.get("ip"),
                "acr": a.get("acr"), "crown": _is_crown(a),
                "tags": [f"{t['key']}: {t['value']}" if t["value"] else t["key"] for t in a["tags"]][:8]}
               for a in matched[:500]]
    return {"ok": True, "owner": resolved, "owner_raw": parsed["owner"], "owner_note": resolved_note,
            "layer": layer, "mode": mode, "filter": filt, "filter_desc": desc or ["all assets"],
            "matched": preview, "match_count": len(matched), "llm_available": used_llm,
            "uuids": [a["uuid"] for a in matched]}


# --------------------------------------------------------------------------- #
#  Writes (gated)                                                              #
# --------------------------------------------------------------------------- #
def _uuid_query(uuids):
    inlist = ",".join("'" + str(u).replace("'", "''") + "'" for u in uuids if u)
    return "SELECT uuid AS asset_uuid FROM assets WHERE uuid IN (" + inlist + ")"


def apply_business_owner(owner, uuids, db_path=None) -> dict:
    """Tag ``Business Owner: <owner>`` on a set of assets (gated, persistent)."""
    if not owner or not uuids:
        return {"ok": False, "message": "owner and assets required"}
    return navi_cli.tag(BUSINESS_OWNER_KEY, owner, query=_uuid_query(uuids),
                        remove=False, agent="asset_ownership")


def _asset_routes_paths(uuid, db_path=None):
    routes = [r["app"] for r in _q(_RA + "SELECT DISTINCT app FROM ra WHERE au=?", (uuid,), db_path) if r.get("app")]
    if not routes:  # some sqlite builds dislike WHERE on the CTE alias; fall back to a filter
        routes = [r["app"] for r in _q(_RA + "SELECT app, au FROM ra", path=db_path)
                  if r.get("au") == uuid and r.get("app")]
    paths = [r["path"] for r in _q("SELECT DISTINCT path FROM vuln_paths WHERE asset_uuid=? AND path IS NOT NULL",
                                    (uuid,), db_path) if r.get("path")]
    return sorted(set(routes)), sorted(set(paths))


def assign_asset_owner(uuid, owner, mode="complete", db_path=None) -> dict:
    """Give ONE asset a single complete owner. mode='complete' → the owner owns
    EVERY route & path on the asset; mode='remainder' → only the routes/paths that
    don't already have an owner. Writes the ``Asset Owner`` tag and cascades ``Owner``
    tags for the covered routes/paths so both this view and Atlas close the asset."""
    if not uuid or not owner:
        return {"ok": False, "message": "asset and owner required"}
    mode = "remainder" if str(mode).lower().startswith("rem") else "complete"
    routes, paths = _asset_routes_paths(uuid, db_path)
    # what's already owned on this asset (route/path names)?
    owned = set()
    for r in _q("SELECT tag_value FROM tags WHERE asset_uuid=? AND " + tagname.sql_lit("tag_key", "Owner")
                + " AND tag_value IS NOT NULL",
                (uuid,), db_path):
        val = (r.get("tag_value") or "").strip()
        if ": " in val:
            nm, user = val.rsplit(": ", 1)
            if user.strip() and not _disp_of(user):
                owned.add(_nk(nm))
    q1 = _uuid_query([uuid])
    jobs, targets = [], []
    for nm in routes + paths:
        if mode == "remainder" and _nk(nm) in owned:
            continue
        targets.append(nm)
        r = navi_cli.tag("Owner", f"{nm}: {owner}", query=q1, remove=False, agent="asset_ownership")
        jobs.append({"name": nm, "ok": r.get("ok", True)})
    # the single-owner marker (Terminus honors this directly = 100% claimed)
    ao = navi_cli.tag(ASSET_OWNER_KEY, f"{owner} · {mode}", query=q1, remove=False, agent="asset_ownership")
    return {"ok": ao.get("ok", True), "asset": uuid, "owner": owner, "mode": mode,
            "closed_routes": len([t for t in targets if t in routes]),
            "closed_paths": len([t for t in targets if t in paths]),
            "cascaded": len(targets), "asset_owner_tag": ao,
            "writes_enabled": navi_cli.writes_enabled()}
