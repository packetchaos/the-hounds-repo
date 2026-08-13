"""Fused Exposure Score — the pack's convergence engine (Nemesis).

One number per asset, assembled from every Hound. The direct signals (KEV via
``vulns.xrefs``, EPSS via the ``epss`` table, VPR via ``vulns.score``, ACR, EOL via
unsupported-product plugins, weak/expiring crypto via ``certs``, compliance failures,
WAS severity, SLA aging) are computed straight from navi.db; the rest (attack path,
identity, AI, ATT&CK, ownership) are read off the tags the other Hounds apply.

Score design: fifteen factors sum to 100 (so a score reads as "% of the maximum
danger one asset can carry"), then a disposition discount applies and scan coverage
(Chronos) sets confidence. 0–100 is a RANK, not a count — ordering is identical at
any scale.

Scaling: every source table is aggregated PER ASSET in SQL (GROUP BY), the joined
result is STREAMED row-by-row (never fetched whole), and only the worst N rows are
returned to the UI while KPIs are counted over the entire estate. Memory is O(N),
so it holds up on million-asset estates. EPSS refinement (a per-CVE join that can't
be indexed) is applied only up to ``epss_cap`` assets; above that KEV drives
exploitability and the response says so.
"""
import heapq
import re
import sqlite3

from core import db

CROWN_ACR = 9

# factor metadata for the UI: id, label, Hound, max points. Sum(max) == 100.
FACTORS = [
    {"id": "expl",  "label": "Exploitability",        "hound": "Laelaps · KEV / EPSS",     "max": 20},
    {"id": "aes",   "label": "Tenable AES",           "hound": "Tenable One · Asset Exposure", "max": 8},
    {"id": "sev",   "label": "Severity (VPR)",        "hound": "Tenable VPR",              "max": 8},
    {"id": "crit",  "label": "Business criticality",  "hound": "Anubis · ACR",             "max": 8},
    {"id": "path",  "label": "Attack path",           "hound": "Fenrir",                   "max": 8},
    {"id": "ident", "label": "Identity exposure",     "hound": "Janus · NHI / reuse",      "max": 7},
    {"id": "comp",  "label": "Compliance failure",    "hound": "Minos · audit controls",   "max": 6},
    {"id": "was",   "label": "Web-app exposure",      "hound": "Arachne · WAS",            "max": 5},
    {"id": "eol",   "label": "EOL / unsupported",     "hound": "Charon",                   "max": 5},
    {"id": "exp",   "label": "Internet exposure",     "hound": "Cerberus / exposed",       "max": 4},
    {"id": "ai",    "label": "AI risk",               "hound": "Pythia · shadow/exposed",  "max": 4},
    {"id": "cry",   "label": "Weak / expiring crypto","hound": "Certania + Heimdall",      "max": 4},
    {"id": "sla",   "label": "SLA breach (aging)",    "hound": "Sköll · overdue",          "max": 4},
    {"id": "vol",   "label": "Finding volume",        "hound": "open crit / KEV density",  "max": 4},
    {"id": "own",   "label": "Ownership gap",         "hound": "Terminus",                 "max": 3},
    {"id": "mit",   "label": "ATT&CK technique",      "hound": "Orthrus",                  "max": 2},
]
_CRED_PLUGINS = ("104410", "21745", "110723", "117885")   # credentialed-scan failures (Chronos)
_EPSS_CAP = 250000                                        # above this, EPSS refinement is skipped


def _q(sql, args=(), path=None):
    try:
        return list(db.query(sql, args, path=path)) if args else list(db.query(sql, path=path))
    except Exception:
        return []


def _has(t, path=None):
    return bool(_q("SELECT name FROM sqlite_master WHERE type='table' AND name=?", (t,), path))


def _cols(t, path=None):
    return {r["name"] for r in _q(f"PRAGMA table_info({t})", path=path)}


def _fnum(x):
    try:
        v = float(x)
        return v if v == v else None
    except (TypeError, ValueError):
        return None


def _cves(s):
    return set(re.findall(r"CVE-\d{4}-\d+", str(s or ""), re.I))


# --------------------------------------------------------------------------- #
#  Per-asset aggregate query — one row per asset, all heavy tables GROUP BY'd  #
#  in SQL so Python never touches the raw vuln / tag rows.                     #
# --------------------------------------------------------------------------- #
def _build_query(db_path):
    ac = _cols("assets", db_path)
    host = "a.hostname" if "hostname" in ac else "a.uuid"
    ip = "a.ip_address" if "ip_address" in ac else "NULL"
    acr = "CAST(a.acr AS REAL)" if "acr" in ac else "NULL"
    aes = "CAST(a.aes AS REAL)" if "aes" in ac else "NULL"
    ctes, joins, cols = [], [], []

    if _has("vulns", db_path):
        vc = _cols("vulns", db_path)
        sev = "severity" if "severity" in vc else "''"
        sc = "score" if "score" in vc else ("vpr" if "vpr" in vc else "0")
        xr = "xrefs" if "xrefs" in vc else "''"
        pid = "plugin_id" if "plugin_id" in vc else "''"
        pn = "plugin_name" if "plugin_name" in vc else "''"
        lf = "last_found" if "last_found" in vc else None
        eol_like = (f"(lower({pn}) LIKE '%unsupported%' OR lower({pn}) LIKE '%end of life%' OR "
                    f"lower({pn}) LIKE '%end-of-life%' OR lower({pn}) LIKE '%no longer supported%')")
        sla_expr = ("0" if not lf else
                    f"MAX(CASE WHEN lower({sev}) IN ('critical','4') AND julianday('now')-julianday({lf})>15 THEN 1 "
                    f"WHEN lower({sev}) IN ('high','3') AND julianday('now')-julianday({lf})>30 THEN 1 ELSE 0 END)")
        creds = ",".join("'%s'" % p for p in _CRED_PLUGINS)
        ctes.append(f"""v AS (SELECT asset_uuid u,
          MAX(CASE WHEN {xr} LIKE '%CISA-KNOWN-EXPLOITED%' THEN 1 ELSE 0 END) kev,
          MAX(CAST({sc} AS REAL)) vpr,
          MAX(CASE WHEN {eol_like} THEN 1 ELSE 0 END) veol,
          SUM(CASE WHEN lower({sev}) IN ('critical','4') OR {xr} LIKE '%CISA-KNOWN-EXPLOITED%' THEN 1 ELSE 0 END) vol,
          {sla_expr} slabr,
          MAX(CASE WHEN CAST({pid} AS TEXT) IN ({creds}) THEN 1 ELSE 0 END) blind
          FROM vulns GROUP BY asset_uuid)""")
        joins.append("LEFT JOIN v ON v.u=a.uuid")
        cols += ["COALESCE(v.kev,0) kev", "v.vpr vpr", "COALESCE(v.veol,0) veol",
                 "COALESCE(v.vol,0) vol", "COALESCE(v.slabr,0) slabr", "COALESCE(v.blind,0) blind"]
    else:
        cols += ["0 kev", "NULL vpr", "0 veol", "0 vol", "0 slabr", "0 blind"]

    if _has("tags", db_path):
        ctes.append("""t AS (SELECT asset_uuid u,
          MAX(CASE WHEN lower(tag_key) LIKE 'attack path%' AND lower(tag_key||' '||tag_value) LIKE '%target%' THEN 2
                   WHEN lower(tag_key) LIKE 'attack path%' THEN 1 ELSE 0 END) path,
          MAX(CASE WHEN lower(tag_key) IN ('nhi','identity') AND (lower(tag_value) LIKE '%reuse%' OR lower(tag_value) LIKE '%shared%') THEN 2
                   WHEN lower(tag_key) IN ('nhi','identity') THEN 1 ELSE 0 END) ident,
          MAX(CASE WHEN (lower(tag_key)='ai' OR lower(tag_key) LIKE 'ai %') AND lower(tag_key||' '||tag_value) LIKE '%expose%' THEN 3
                   WHEN (lower(tag_key)='ai' OR lower(tag_key) LIKE 'ai %') AND (lower(tag_value) LIKE '%shadow%' OR lower(tag_value) LIKE '%priority%') THEN 2
                   WHEN (lower(tag_key)='ai' OR lower(tag_key) LIKE 'ai %') THEN 1 ELSE 0 END) ai,
          MAX(CASE WHEN lower(tag_key)='iot' THEN 1 ELSE 0 END) iot,
          MAX(CASE WHEN lower(tag_key)='mitre' THEN 1 ELSE 0 END) mitre,
          MAX(CASE WHEN lower(tag_key)='lifecycle' THEN 1 ELSE 0 END) eoltag,
          MAX(CASE WHEN lower(tag_key) IN ('post-quantum','post quantum') THEN 1 ELSE 0 END) pq,
          MAX(CASE WHEN lower(tag_key)='cert failure' THEN 1 ELSE 0 END) certfail
          FROM tags GROUP BY asset_uuid)""")
        ctes.append("""o AS (SELECT asset_uuid u, GROUP_CONCAT(tag_value,'||') ov FROM tags "
                    "WHERE lower(tag_key) IN ('owner','business owner','asset owner') GROUP BY asset_uuid)""")
        joins += ["LEFT JOIN t ON t.u=a.uuid", "LEFT JOIN o ON o.u=a.uuid"]
        cols += ["COALESCE(t.path,0) path", "COALESCE(t.ident,0) ident", "COALESCE(t.ai,0) ai",
                 "COALESCE(t.iot,0) iot", "COALESCE(t.mitre,0) mitre", "COALESCE(t.eoltag,0) eoltag",
                 "COALESCE(t.pq,0) pq", "COALESCE(t.certfail,0) certfail", "o.ov ov"]
    else:
        cols += ["0 path", "0 ident", "0 ai", "0 iot", "0 mitre", "0 eoltag", "0 pq", "0 certfail", "NULL ov"]

    if _has("compliance", db_path):
        ctes.append("c AS (SELECT asset_uuid u, SUM(CASE WHEN upper(status) LIKE 'FAIL%' THEN 1 ELSE 0 END) cfail "
                    "FROM compliance GROUP BY asset_uuid)")
        joins.append("LEFT JOIN c ON c.u=a.uuid")
        cols.append("COALESCE(c.cfail,0) cfail")
    else:
        cols.append("0 cfail")

    if _has("certs", db_path):
        cc = _cols("certs", db_path)
        sig = "signature_algorithm" if "signature_algorithm" in cc else None
        kl = "key_length" if "key_length" in cc else None
        exp = "not_valid_after" if "not_valid_after" in cc else None
        weak = ("(lower(COALESCE(%s,'')) LIKE '%%sha1%%' OR lower(COALESCE(%s,'')) LIKE '%%md5%%'" % (sig or "''", sig or "''")
                + (f" OR (CAST({kl} AS INTEGER) BETWEEN 1 AND 2047)" if kl else "") + ")")
        expiring = (f"({exp} IS NOT NULL AND substr({exp},1,10) <= date('now','+365 day'))" if exp else "0")
        ctes.append(f"cr AS (SELECT asset_uuid u, MAX(CASE WHEN {weak} THEN 1 ELSE 0 END) weak, "
                    f"MAX(CASE WHEN {expiring} THEN 1 ELSE 0 END) expiring FROM certs GROUP BY asset_uuid)")
        joins.append("LEFT JOIN cr ON cr.u=a.uuid")
        cols += ["COALESCE(cr.weak,0) weak", "COALESCE(cr.expiring,0) expiring"]
    else:
        cols += ["0 weak", "0 expiring"]

    was_tbl = next((tb for tb in ("findings", "apps", "was_findings")
                    if _has(tb, db_path) and {"asset_uuid", "severity"} <= _cols(tb, db_path)), None)
    if was_tbl:
        ctes.append(f"w AS (SELECT asset_uuid u, MAX(CASE WHEN lower(severity) IN ('critical','4') THEN 2 "
                    f"WHEN lower(severity) IN ('high','3') THEN 1 ELSE 0 END) was FROM {was_tbl} GROUP BY asset_uuid)")
        joins.append("LEFT JOIN w ON w.u=a.uuid")
        cols.append("COALESCE(w.was,0) was")
    else:
        cols.append("0 was")

    head = ("WITH " + ",\n".join(ctes) + "\n") if ctes else ""
    return (head + f"SELECT a.uuid uuid, {host} host, {ip} ip, {acr} acr, {aes} aes, " + ", ".join(cols)
            + " FROM assets a " + " ".join(joins))


def _epss_map(db_path, cap):
    """asset_uuid -> max EPSS, streamed. Skipped above `cap` assets (can't index a
    CVE-list join). Returns (map, used)."""
    if not (_has("epss", db_path) and _has("vulns", db_path)):
        return {}, False
    total = 0
    try:
        total = int(db.scalar("SELECT COUNT(*) FROM assets", path=db_path, budget=0) or 0)
    except Exception:
        total = 0
    if not total or total > cap:
        return {}, False
    con = db.connect(db_path)
    try:
        emap = {}
        for cve, v in con.execute("SELECT cve, epss_value FROM epss"):
            ev = _fnum(v)
            if cve and ev is not None:
                emap[str(cve).upper()] = ev
        if not emap:
            return {}, True
        out = {}
        for u, cves in con.execute("SELECT asset_uuid, cves FROM vulns WHERE cves LIKE '%CVE-%'"):
            best = out.get(u, 0.0)
            for c in _cves(cves):
                e = emap.get(c.upper())
                if e and e > best:
                    best = e
            if best:
                out[u] = best
        return out, True
    finally:
        con.close()


# --------------------------------------------------------------------------- #
#  Scoring                                                                      #
# --------------------------------------------------------------------------- #
def _disp_mul(s):
    return 0.3 if s.get("disp") == "Mitigated" else 0.55 if s.get("disp") == "Accepted" else 1.0


def _factor_frac(s):
    """Each factor's INTENSITY on this asset, normalised to 0..1 and independent of
    its weight. Points = intensity × weight, so the weights are fully tunable without
    touching the detection logic. With the default weights (FACTORS max) this
    reproduces the original point scheme exactly."""
    vol = s["vol"]
    return {
        "expl": 1.0 if s["kev"] else s["epss"],
        "aes":  min(1.0, (s["aes"] or 0) / 1000.0),   # Tenable One Asset Exposure Score, 0–1000
        "sev":  min(1.0, (s["vpr"] or 0) / 10),
        "crit": 1.0 if s["crown"] else min(s["acr"] or 0, 9) / 9,
        "path": 1.0 if s["path"] == "target" else 0.625 if s["path"] == "entry" else 0.0,
        "ident": 1.0 if s["ident"] >= 2 else (4 / 7) if s["ident"] == 1 else 0.0,
        "comp": min(1.0, (s["comp"] or 0) / 3),
        "was": 1.0 if s["was"] >= 2 else 0.6 if s["was"] == 1 else 0.0,
        "eol": 1.0 if s["eol"] else 0.0,
        "exp": 1.0 if s["exposed"] else 0.0,
        "ai": 1.0 if s["ai"] == "exposed" else 0.75 if s["ai"] == "shadow" else 0.5 if s["ai"] == "present" else 0.0,
        "cry": 1.0 if s["crypto"] == "pq" else 0.75 if s["crypto"] == "certfail" else 0.0,
        "sla": 1.0 if s["sla"] else 0.0,
        "vol": 1.0 if vol >= 20 else 0.75 if vol >= 8 else 0.5 if vol >= 3 else 0.25 if vol >= 1 else 0.0,
        "own": 1.0 if s["unowned"] else 0.0,
        "mit": 1.0 if s["mitre"] else 0.0,
    }


def _factor_pts(s, weights):
    frac = _factor_frac(s)
    return {fid: round(frac[fid] * weights.get(fid, 0)) for fid in frac}


def _resolve_weights(weights):
    """Return (weight_map, is_custom). A caller may pass any relative weights; they're
    clamped to >=0 and re-normalised to sum 100 so the 0–100 score meaning holds."""
    base = {f["id"]: float(f["max"]) for f in FACTORS}
    if not weights:
        return base, False
    clean = {}
    for f in FACTORS:
        try:
            clean[f["id"]] = max(0.0, float(weights.get(f["id"], base[f["id"]])))
        except (TypeError, ValueError):
            clean[f["id"]] = base[f["id"]]
    tot = sum(clean.values())
    if tot <= 0:
        return base, False
    scaled = {k: v / tot * 100.0 for k, v in clean.items()}
    custom = any(abs(scaled[k] - base[k]) > 0.05 for k in base)
    return scaled, custom


def _band(sc):
    return "CRITICAL" if sc >= 80 else "HIGH" if sc >= 60 else "ELEVATED" if sc >= 40 else "LOW"


def _row_signals(r, epss_map):
    """Turn one aggregate DB row into the signal dict _factor_pts expects."""
    acr = _fnum(r["acr"])
    ai_raw = int(r["ai"] or 0)
    path_raw = int(r["path"] or 0)
    owned, disp = False, None
    for v in (r["ov"] or "").split("||"):
        v = v.strip()
        if not v:
            continue
        user = v.rsplit(": ", 1)[-1].strip()
        lab = next((d for d in ("Mitigated", "Accepted", "Ignored") if user.lower() == d.lower()), None)
        if lab:
            disp = disp or lab
        else:
            owned = True
    crypto = ("pq" if (int(r["pq"] or 0) or int(r["weak"] or 0))
              else "certfail" if (int(r["certfail"] or 0) or int(r["expiring"] or 0)) else None)
    return {
        "uuid": r["uuid"], "host": (r["host"] or r["ip"] or r["uuid"]), "ip": r["ip"],
        "acr": acr, "aes": _fnum(r["aes"]), "crown": bool(acr is not None and acr >= CROWN_ACR),
        "kev": int(r["kev"] or 0), "vpr": _fnum(r["vpr"]) or 0.0, "epss": epss_map.get(r["uuid"], 0.0),
        "eol": 1 if (int(r["veol"] or 0) or int(r["eoltag"] or 0)) else 0,
        "vol": int(r["vol"] or 0), "sla": int(r["slabr"] or 0), "blind": int(r["blind"] or 0),
        "path": "target" if path_raw == 2 else "entry" if path_raw == 1 else None,
        "ident": int(r["ident"] or 0),
        "ai": "exposed" if ai_raw == 3 else "shadow" if ai_raw == 2 else "present" if ai_raw == 1 else None,
        "exposed": 1 if (int(r["iot"] or 0) or ai_raw == 3) else 0,
        "mitre": bool(int(r["mitre"] or 0)), "crypto": crypto,
        "comp": int(r["cfail"] or 0), "was": int(r["was"] or 0),
        "unowned": 0 if owned else 1, "disp": (disp if not owned else None),
    }


def _silent(s, pts):
    """No Hound has found anything on this asset (structural crit/own don't count)."""
    return not (s["kev"] or s["comp"] or s["was"] or s["sla"] or s["path"] or s["ident"]
                or s["ai"] or s["eol"] or s["crypto"] or s["mitre"] or s["blind"])


def overview(db_path=None, limit=500, offset=0, epss_cap=_EPSS_CAP, weights=None) -> dict:
    if not _has("assets", db_path):
        return {"ok": False, "error": "no assets table in navi.db — run `navi config update assets`"}
    p = db_path or db.db_path()
    wmap, wcustom = _resolve_weights(weights)
    epss_map, epss_used = _epss_map(p, epss_cap)
    keep = max(1, offset + max(1, limit))

    # accumulators (whole-estate) + a bounded top-N heap (memory O(keep))
    kpi = {k: 0 for k in ("assets", "critical", "high", "elevated", "low", "clean",
                          "kev", "crown", "crown_kev", "crown_unowned",
                          "crown_blind", "unowned", "unowned_crit", "kev_unowned", "kev_exposed",
                          "eol_crown", "path_unowned", "identreuse_kev", "blind", "no_signal",
                          "path", "ident", "ai", "ai_shadow", "eol", "crypto", "exposed",
                          "comp_fail", "was_exposed", "sla_breach")}
    factor_totals = {f["id"]: 0 for f in FACTORS}   # estate-wide sum of each factor's points
    estate = 0
    heap = []                        # (sortkey_tuple, seq, row)
    seq = 0
    worst = {f["id"]: (0, None) for f in FACTORS}

    con = db.connect(p)
    con.row_factory = sqlite3.Row
    try:
        cur = con.execute(_build_query(p))
        while True:
            batch = cur.fetchmany(5000)
            if not batch:
                break
            for r in batch:
                s = _row_signals(r, epss_map)
                pts = _factor_pts(s, wmap)
                raw = sum(pts.values())
                fscore = raw * _disp_mul(s)
                score = min(100, round(fscore))
                # ---- estate KPIs ----
                kpi["assets"] += 1
                estate += score
                if score >= 80:
                    kpi["critical"] += 1
                    if s["unowned"]:
                        kpi["unowned_crit"] += 1
                if score >= 60:
                    kpi["high"] += 1
                # exclusive bands for the distribution chart
                if score < 40:
                    kpi["clean" if score <= 0 else "low"] += 1
                elif score < 60:
                    kpi["elevated"] += 1
                if s["kev"]:
                    kpi["kev"] += 1
                if s["crown"]:
                    kpi["crown"] += 1
                    if s["kev"]:
                        kpi["crown_kev"] += 1
                    if s["unowned"]:
                        kpi["crown_unowned"] += 1
                if s["unowned"]:
                    kpi["unowned"] += 1
                if s["blind"]:
                    kpi["blind"] += 1
                if s["path"]:
                    kpi["path"] += 1
                if s["ident"]:
                    kpi["ident"] += 1
                if s["ai"]:
                    kpi["ai"] += 1
                    if s["ai"] == "shadow":
                        kpi["ai_shadow"] += 1
                if s["eol"]:
                    kpi["eol"] += 1
                if s["crypto"]:
                    kpi["crypto"] += 1
                if s["exposed"]:
                    kpi["exposed"] += 1
                if s["comp"]:
                    kpi["comp_fail"] += 1
                if s["was"]:
                    kpi["was_exposed"] += 1
                if s["sla"]:
                    kpi["sla_breach"] += 1
                if _silent(s, pts):
                    kpi["no_signal"] += 1
                # ---- cross-Hound convergence intersections (whole estate) ----
                if s["crown"] and s["blind"]:
                    kpi["crown_blind"] += 1
                if s["kev"] and s["unowned"]:
                    kpi["kev_unowned"] += 1
                if s["kev"] and s["exposed"]:
                    kpi["kev_exposed"] += 1
                if s["eol"] and s["crown"]:
                    kpi["eol_crown"] += 1
                if s["path"] == "target" and s["unowned"]:
                    kpi["path_unowned"] += 1
                if s["ident"] >= 2 and s["kev"]:
                    kpi["identreuse_kev"] += 1
                # ---- worst-from-each-Hound ----
                for fid, v in pts.items():
                    factor_totals[fid] += v
                    if v > worst[fid][0]:
                        worst[fid] = (v, {"host": s["host"], "uuid": s["uuid"]})
                # ---- bounded top-N (worst scores; deterministic tiebreak) ----
                key = (fscore, s["kev"], s["vpr"] or 0, s["vol"])
                row = {"uuid": s["uuid"], "host": s["host"], "ip": s["ip"], "acr": s["acr"],
                       "aes": (round(s["aes"]) if s["aes"] is not None else None),
                       "crown": s["crown"], "score": score, "band": _band(score), "factors": pts,
                       "disp": s["disp"], "blind": bool(s["blind"]),
                       "applies": {"patch": bool(s["kev"] or (s["vpr"] or 0) >= 7), "eol": bool(s["eol"]),
                                   "crypto": bool(s["crypto"]), "segment": bool(s["exposed"] or s["ai"]),
                                   "own": bool(s["unowned"]), "comply": bool(s["comp"])},
                       "kev": s["kev"], "epss": round(s["epss"], 2), "vpr": round(s["vpr"] or 0, 1),
                       "path": s["path"], "ident": s["ident"], "exposed": bool(s["exposed"]), "ai": s["ai"],
                       "eol": bool(s["eol"]), "crypto": s["crypto"], "mitre": s["mitre"],
                       "unowned": bool(s["unowned"]), "comp": s["comp"], "was": s["was"],
                       "sla": bool(s["sla"]), "vol": s["vol"], "_k": key}
                seq += 1
                if len(heap) < keep:
                    heapq.heappush(heap, (key, seq, row))
                elif key > heap[0][0]:
                    heapq.heapreplace(heap, (key, seq, row))
    finally:
        con.close()

    n = kpi["assets"]
    kpi["total"] = n
    kpi["estate"] = estate
    kpi["avg"] = round(estate / n, 1) if n else 0
    kpi["factor_totals"] = factor_totals
    ranked = [t[2] for t in sorted(heap, key=lambda x: (x[0], x[1]), reverse=True)]
    page = ranked[offset:offset + limit]
    for row in page:
        row.pop("_k", None)

    worst_list = [{"id": f["id"], "label": f["label"], "hound": f["hound"],
                   "host": worst[f["id"]][1]["host"], "uuid": worst[f["id"]][1]["uuid"],
                   "pts": worst[f["id"]][0]}
                  for f in FACTORS if worst[f["id"]][1] and worst[f["id"]][0] > 0]
    host_hits = {}
    for w in worst_list:
        host_hits[w["host"]] = host_hits.get(w["host"], 0) + 1
    convergence = sorted(([{"host": h, "tops": c} for h, c in host_hits.items() if c >= 2]),
                         key=lambda x: -x["tops"])

    factors_meta = [{"id": f["id"], "label": f["label"], "hound": f["hound"],
                     "max": round(wmap[f["id"]]), "default": f["max"],
                     "weight": round(wmap[f["id"]], 1)} for f in FACTORS]
    return {"ok": True, "kpi": kpi, "factors": factors_meta, "assets": page,
            "total": n, "returned": len(page), "offset": offset, "limit": limit,
            "truncated": n > len(page), "epss_used": epss_used,
            "weights_custom": wcustom, "worst": worst_list, "convergence": convergence}
