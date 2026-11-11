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
import re

from core import db, hx_summary, navi_cli, tagname

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
    """uuid -> set(route app_name) it sits on.

    Build 455: the old form joined vuln_route to EVERY vulns row with a LIKE on the quoted
    plugin_list (``plugin_list LIKE '%<q>' || plugin_id || '<q>%'``) — O(routes × findings),
    50 s at 600k assets and unbounded at 420 M findings. A route's plugin_list is a quoted list
    ("['51192', '35291']"), so the same membership is "the finding's plugin id is one of the
    quoted ids": one ``plugin_id IN (…)`` probe per route through the covering
    (plugin_id, asset_uuid) index when ⚡ Optimize built it (hx_v_plugin)."""
    out = {}
    if not _has_table("vuln_route", db_path):
        return out
    hv = db.indexed_by("hx_v_plugin", db_path)
    for r in _q("SELECT app_name, plugin_list FROM vuln_route", path=db_path):
        app = r.get("app_name")
        pids = sorted(set(re.findall(r"'([^']*)'", str(r.get("plugin_list") or ""))))
        if not app or not pids:
            continue
        for i in range(0, len(pids), 500):
            part = pids[i:i + 500]
            try:
                for (u,) in db.iter("SELECT DISTINCT asset_uuid FROM vulns%s WHERE plugin_id IN (%s)"
                                    % (hv, ",".join("?" * len(part))), tuple(part), path=db_path,
                                    tuples=True, budget="job"):
                    if u:
                        out.setdefault(u, set()).add(app)
            except Exception:
                continue
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
    try:
        hx = hx_summary.usable(db_path)
    except Exception:
        hx = False
    if hx:
        # ⚡ Optimize's per-asset summary: hx_asset.crit = open findings with severity
        # critical/'4' (per finding, exact), .kev = an open finding of a CISA-KEV plugin;
        # n_open > 0 keeps exactly the assets the GROUP BY over open findings returned
        out = {}
        for r in _q("SELECT asset_uuid u, crit c, kev k FROM hx_asset WHERE n_open > 0", path=db_path):
            if r.get("u"):
                out[r["u"]] = (int(r.get("c") or 0), bool(r.get("k")))
        return out
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


def _iter_assets_with_tags(db_path=None):
    """assets_with_tags(), STREAMED (build 455): assets ordered by uuid merge-joined with their
    tags ordered by (asset_uuid, rowid) — the covering tags(asset_uuid, …) index when present —
    so each asset's tags keep the table's order, as before. Each asset carries `_rid` (its
    rowid) so callers break ties in the old (table) order. Memory: one asset at a time."""
    if not _has_table("assets", db_path):
        return
    cols = _asset_cols(db_path)
    acr = "acr" if "acr" in cols else "NULL AS acr"
    aes = "aes" if "aes" in cols else "NULL AS aes"
    url = "url" if "url" in cols else "NULL AS url"
    cloud_cols = [c for c in ("aws_id", "azure_vm_id", "gcp_instance_id") if c in cols]
    cc = "".join(", " + c for c in cloud_cols)
    arows = db.iter(f"SELECT rowid AS _rid, uuid, hostname, ip_address ip, {acr}, {aes}, {url}{cc} FROM assets "
                    "WHERE uuid IS NOT NULL AND uuid<>'' ORDER BY uuid, rowid", path=db_path, budget="job")
    trows = iter(())
    if _has_table("tags", db_path):
        try:
            trows = db.iter("SELECT asset_uuid, tag_key, tag_value FROM tags WHERE asset_uuid IS NOT NULL "
                            "ORDER BY asset_uuid, rowid", path=db_path, budget="job", tuples=True)
        except Exception:
            trows = iter(())
    tnext = next(trows, None)
    cur = None
    for r in arows:
        u = r.get("uuid")
        if cur is not None and cur["uuid"] == u:          # duplicate asset rows: the last row's attributes win
            cur.update(hostname=r.get("hostname"), ip=r.get("ip"), acr=_fnum(r.get("acr")),
                       aes=_fnum(r.get("aes")), url=r.get("url"))
            if cloud_cols and any(r.get(c) for c in cloud_cols):
                cur["cloud"] = True
            continue
        if cur is not None:
            yield cur
        cur = {"uuid": u, "hostname": r.get("hostname"), "ip": r.get("ip"), "acr": _fnum(r.get("acr")),
               "aes": _fnum(r.get("aes")), "url": r.get("url"), "tags": [], "_tagmap": {}, "_rid": r.get("_rid")}
        if cloud_cols and any(r.get(c) for c in cloud_cols):
            cur["cloud"] = True
        while tnext is not None and (tnext[0] or "") < u:
            tnext = next(trows, None)
        while tnext is not None and tnext[0] == u:
            k, v = (tnext[1] or "").strip(), (tnext[2] or "").strip()
            if k:
                cur["tags"].append({"key": k, "value": v})
                cur["_tagmap"].setdefault(k.lower(), []).append(v)
                bk = tagname.base(k)
                if bk != k:
                    cur["_tagmap"].setdefault(bk.lower(), []).append(v)
            tnext = next(trows, None)
    if cur is not None:
        yield cur


def _rollup(db_path, emit):
    """THE ownership rollup, one asset at a time (build 455). For every asset it builds the
    per-asset row exactly as before and calls emit(row, rid, is_crown, is_blind); the KPIs are
    accumulated as counters (no per-asset lists). Returns (kpi, owners list); raises LookupError
    when navi.db has no assets table."""
    if not _has_table("assets", db_path):
        raise LookupError("no assets table in navi.db — run `navi config update assets`")
    routes_by = _route_members(db_path)
    paths_by = _path_members(db_path)
    risk_by = _vuln_risk(db_path)
    owners = {}                       # name -> {assets, crown, business, asset, tech}
    K = dict(n=0, with_surface=0, unclaimed=0, fully=0, biz=0, asset=0, tech=0, claimed_sum=0.0, claimed_n=0,
             surf_total=0, mit=0, acc=0, ign=0, owned=0, crown=0, crown_owned=0, crown_unclaimed=0, crown_biz=0,
             crown_no_owner=0, kev=0, blind=0, no_signal=0, cred_fail=0, surf_owned=0, surf_disp=0, surf_handled=0,
             surface_items=0, ao_complete=0, ao_remainder=0, crit_assets=0, kev_findings=0, unowned_crit=0,
             unowned_crit_findings=0, unowned_kev=0)
    tu, tu_key = None, None
    for a in _iter_assets_with_tags(db_path):
        ro = routes_by.get(a["uuid"], set())
        pa = paths_by.get(a["uuid"], set())
        own = _asset_ownership(a, ro, pa)
        sig = _hound_signals(a)
        is_crown = _is_crown(a)
        primary_owner = (own["asset_owner"] or (own["tech_owners"][0] if own["tech_owners"] else None)
                         or (own["business_owners"][0] if own["business_owners"] else None))
        crit, kevf = risk_by.get(a["uuid"], (0, False))
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
            "crit": crit, "kev": kevf,
        }
        K["n"] += 1
        K["surf_owned"] += own["owned"]
        K["surf_disp"] += own["dispositioned"]
        K["surf_handled"] += own["handled"]
        K["surface_items"] += row["surface"]
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
            K["kev"] += 1
        # blind spots — unclaimed crown jewels or unclaimed high-ACR assets
        is_blind = bool(own["unclaimed"] and (is_crown or (a.get("acr") or 0) >= 7))
        if row["surface"] > 0:
            K["with_surface"] += 1
            K["surf_total"] += row["surface"]
            K["unclaimed"] += 1 if row["unclaimed"] else 0
            K["fully"] += 1 if row["claimed_pct"] == 100.0 else 0
            if row["claimed_pct"] is not None:
                K["claimed_sum"] += row["claimed_pct"]
                K["claimed_n"] += 1
        K["biz"] += 1 if row["business_owners"] else 0
        if row["asset_owner"]:
            K["asset"] += 1
            K["ao_remainder" if row["asset_owner_mode"] == "remainder" else "ao_complete"] += 1
        K["tech"] += 1 if row["tech_owners"] else 0
        K["mit"] += row["mitigated"]
        K["acc"] += row["accepted"]
        K["ign"] += row["ignored"]
        K["owned"] += 1 if row["has_owner"] else 0
        if is_crown:
            K["crown"] += 1
            K["crown_owned"] += 1 if row["has_owner"] else 0
            K["crown_unclaimed"] += 1 if (row["surface"] > 0 and not row["has_owner"]) else 0
            K["crown_biz"] += 1 if row["business_owners"] else 0
            K["crown_no_owner"] += 0 if row["has_owner"] else 1
        K["blind"] += 1 if is_blind else 0
        K["no_signal"] += 1 if row["signal_count"] == 0 else 0
        if any("cred failure" in _nk(k) + " " + _nk(str(v)) for k, vs in sig.items() for v in (vs or [""])):
            K["cred_fail"] += 1
        if crit:
            K["crit_assets"] += 1
        if kevf:
            K["kev_findings"] += 1
        if not row["has_owner"]:
            if crit:
                K["unowned_crit"] += 1
            K["unowned_crit_findings"] += crit
            if kevf:
                K["unowned_kev"] += 1
            key = (row["acr"] or 0, crit, row["surface"], -(a.get("_rid") or 0))   # max(): first in table order on a tie
            if tu_key is None or key > tu_key:
                tu_key, tu = key, row
        emit(row, a.get("_rid") or 0, is_crown, is_blind)

    def pct(x, y):
        return round(100.0 * x / y, 1) if y else 0.0
    n = K["n"]
    surf_total = K["surf_total"] or 1
    top_unowned = ({"uuid": tu["uuid"], "hostname": tu["hostname"], "ip": tu["ip"],
                    "acr": tu["acr"], "crit": tu["crit"]} if tu else None)
    kpi = {
        "assets": n, "with_surface": K["with_surface"],
        "fully_claimed": K["fully"], "fully_claimed_pct": pct(K["fully"], K["with_surface"]),
        "unclaimed": K["unclaimed"], "unclaimed_pct": pct(K["unclaimed"], K["with_surface"]),
        "avg_claimed_pct": round(K["claimed_sum"] / K["claimed_n"], 1) if K["claimed_n"] else 0.0,
        "business_owned": K["biz"], "business_owned_pct": pct(K["biz"], n),
        "asset_owned": K["asset"], "tech_owned": K["tech"],
        "mitigated": K["mit"], "mitigated_pct": pct(K["mit"], surf_total),
        "accepted": K["acc"], "accepted_pct": pct(K["acc"], surf_total),
        "ignored": K["ign"], "ignored_pct": pct(K["ign"], surf_total),
        "crown": K["crown"], "crown_owned": K["crown_owned"],
        "crown_unclaimed": K["crown_unclaimed"], "crown_owned_pct": pct(K["crown_owned"], K["crown"]),
        "crown_business_owned": K["crown_biz"],
        "kev_assets": K["kev"], "blind": K["blind"],
        "blind_no_signal": K["no_signal"], "cred_fail": K["cred_fail"],
        "crown_acr": CROWN_ACR,
        # --- "At a glance" (build 441) — all derived from the rollup above ---
        "owned": K["owned"], "owned_pct": pct(K["owned"], n),
        "no_owner": n - K["owned"], "no_owner_pct": pct(n - K["owned"], n),
        "no_business": n - K["biz"], "no_business_pct": pct(n - K["biz"], n),
        "asset_owned_complete": K["ao_complete"],
        "asset_owned_remainder": K["ao_remainder"],
        "owners_distinct": len(owners),
        "surface_items": K["surface_items"], "surface_owned": K["surf_owned"],
        "surface_dispositioned": K["surf_disp"], "surface_handled": K["surf_handled"],
        "surface_handled_pct": pct(K["surf_handled"], K["surface_items"]),
        "crown_no_owner": K["crown_no_owner"],
        "has_vulns": bool(risk_by),
        "crit_assets": K["crit_assets"],
        "kev_finding_assets": K["kev_findings"],
        "unowned_crit": K["unowned_crit"],
        "unowned_crit_findings": K["unowned_crit_findings"],
        "unowned_kev": K["unowned_kev"],
        "top_unowned": top_unowned,
    }
    ol = sorted(owners.values(), key=lambda o: (-o["assets"], o["name"].lower()))
    return kpi, ol


def _claimed_key(r):
    return r["claimed_pct"] if r["claimed_pct"] is not None else 999


def overview(db_path=None) -> dict:
    """The Asset Ownership dashboard payload — per-asset rollup + KPIs + crown jewels (what the
    Hounds know) + blind spots. Read-only. The FULL result, for server-side callers and tests;
    the page reads overview_store() (summary + top lists + server-paged rows)."""
    rows, crown, blind = [], [], []

    def emit(row, rid, is_crown, is_blind):
        rows.append((rid, row))
        if is_crown:
            crown.append((rid, row))
        if is_blind:
            blind.append((rid, row))
    try:
        kpi, ol = _rollup(db_path, emit)
    except LookupError as e:
        return {"ok": False, "error": str(e)}
    rows.sort(key=lambda t: (-(t[1]["acr"] or 0), _claimed_key(t[1]), t[0]))
    crown.sort(key=lambda t: (0 if not t[1]["has_owner"] else 1, -(t[1]["acr"] or 0), t[0]))
    blind.sort(key=lambda t: (-(t[1]["acr"] or 0), t[0]))
    return {"ok": True, "kpi": kpi, "assets": [r for _i, r in rows], "crown_jewels": [r for _i, r in crown],
            "blind_spots": [r for _i, r in blind][:200], "owners": ol[:100], "owners_total": len(ol)}


SCOPE_FLAGS = ("unclaimed", "crown", "owned", "noowner", "full", "biz", "nobiz", "asset", "complete", "remainder",
               "tech", "crownnone", "ucrit", "ukev", "nosig")


def _row_flags(r):
    """The page's table scopes as stored filter flags (agents/asset_ownership/page.html SCOPES)."""
    f = {"unclaimed": r["unclaimed"], "crown": r["crown"], "owned": r["has_owner"], "noowner": not r["has_owner"],
         "full": r["surface"] > 0 and r["claimed_pct"] == 100, "biz": bool(r["business_owners"]),
         "nobiz": not r["business_owners"], "asset": bool(r["asset_owner"]),
         "complete": bool(r["asset_owner"]) and r["asset_owner_mode"] != "remainder",
         "remainder": bool(r["asset_owner"]) and r["asset_owner_mode"] == "remainder",
         "tech": bool(r["tech_owners"]), "crownnone": r["crown"] and not r["has_owner"],
         "ucrit": (not r["has_owner"]) and r["crit"] > 0, "ukev": (not r["has_owner"]) and bool(r["kev"]),
         "nosig": not r["signal_count"]}
    return [k for k, v in f.items() if v]


def overview_store(db_path=None):
    """▶ Run for the page (build 455): the same rollup, STREAMED into the result store
    (core.payload) — every asset row once (sort keys ACR ↓ / claimed ↑ / table order, the
    scope flags, host/IP/owner search text), plus the crown jewels and blind spots as their own
    sections. Python keeps only the KPI counters and the owners. Returns
    {ok, run, kpi, owners (top 100), owners_total, signal_keys}."""
    from core import payload
    W = payload.STORE.begin("asset_ownership")
    for sec in ("assets", "crown", "blind"):
        W.section(sec)

    def emit(row, rid, is_crown, is_blind):
        neg_acr, cl = -(row["acr"] or 0), _claimed_key(row)
        text = " ".join(str(x or "") for x in [row["hostname"], row["ip"], row["asset_owner"], row["uuid"]]
                        + list(row["tech_owners"]) + list(row["business_owners"]))
        W.add("assets", row, uid=row["uuid"], flags=_row_flags(row), keys=(neg_acr, cl, rid), text=text)
        if is_crown:
            W.add("crown", row, uid=row["uuid"], keys=(0 if not row["has_owner"] else 1, neg_acr, rid))
        if is_blind:
            W.add("blind", row, uid=row["uuid"], keys=(neg_acr, rid))
    try:
        kpi, ol = _rollup(db_path, emit)
        W.meta = {"owners_total": len(ol)}
    except LookupError as e:
        W.close(ok=False)
        return {"ok": False, "error": str(e)}
    except BaseException:
        W.close(ok=False)
        raise
    W.close()
    # the ✨ Ask hints: the first tag keys in the table's own order (ACR ↓, claimed ↑)
    keys, after = [], None
    for _ in range(10):
        rows, after, _n, _e = payload.STORE.page(W.run, "assets", sort=("s1", "s2", "s3"), limit=200, after=after,
                                                 count=False)
        for r in rows:
            for k in (r.get("signals") or {}):
                if k not in keys:
                    keys.append(k)
        if len(keys) >= 6 or not after:
            break
    return {"ok": True, "run": W.run, "kpi": kpi, "owners": ol[:100], "owners_total": len(ol),
            "signal_keys": keys[:6]}


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


def clean_filter(filt) -> dict:
    """A plan filter as _match_asset reads it — a model-built (or page-echoed) filter may be
    loosely shaped, so keep only well-formed conditions."""
    filt = dict(filt) if isinstance(filt, dict) else {}
    filt["tags"] = [c for c in (filt.get("tags") or []) if isinstance(c, dict) and (str(c.get("key") or "")).strip()]
    filt["host_like"] = [h for h in (filt.get("host_like") or []) if isinstance(h, str) and h.strip()]
    for k in ("acr_min", "acr_max"):
        if filt.get(k) is not None:
            try:
                filt[k] = float(filt[k])
            except (TypeError, ValueError):
                filt.pop(k, None)
    return filt


def match_filter(filt, db_path=None) -> list:
    """The assets a plan's filter selects, re-evaluated HERE (apply never trusts a UUID list
    from the page; it sends the plan's filter and the server rebuilds the set)."""
    filt = clean_filter(filt)
    return [a["uuid"] for a in assets_with_tags(db_path) if a.get("uuid") and _match_asset(a, filt)]


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

    filt = clean_filter(parsed.get("filter"))
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
    return navi_cli.uuids_query([u for u in uuids if u])       # one asset (assign_asset_owner)


def apply_business_owner(owner, uuids, db_path=None) -> dict:
    """Tag ``Business Owner: <owner>`` on a set of assets (gated, persistent). The set comes
    from a Python filter over assets + tags, so it goes as ≤1,999-UUID batches
    (core.navi_cli.tag_uuids_batched, add-only) — any size."""
    if not owner or not uuids:
        return {"ok": False, "message": "owner and assets required"}
    sm = navi_cli.jobs_summary(navi_cli.tag_uuids_batched(BUSINESS_OWNER_KEY, owner, uuids,
                                                          agent="asset_ownership"))
    return {**(sm["result"] or {}), "jobs": sm["jobs"], "job_ids": sm["job_ids"]}


def _asset_routes_paths(uuid, db_path=None):
    """The routes and paths ONE asset sits on. Build 455: the asset's plugin ids (an index probe
    on vulns(asset_uuid, plugin_id) — hx_v_asset when present) matched against each route's
    quoted plugin_list — the same membership the old LIKE join over every finding computed."""
    routes = []
    if _has_table("vuln_route", db_path):
        hv = db.indexed_by("hx_v_asset", db_path)
        mine = {str(r.get("plugin_id")) for r in _q("SELECT DISTINCT plugin_id FROM vulns%s WHERE asset_uuid=?" % hv,
                                                    (uuid,), db_path) if r.get("plugin_id") is not None}
        if mine:
            for r in _q("SELECT app_name, plugin_list FROM vuln_route", path=db_path):
                if r.get("app_name") and mine & set(re.findall(r"'([^']*)'", str(r.get("plugin_list") or ""))):
                    routes.append(r["app_name"])
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
