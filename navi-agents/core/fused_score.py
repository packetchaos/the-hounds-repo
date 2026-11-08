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
import datetime
import heapq
import math
import re
import sqlite3

from core import db, tagname

CROWN_ACR = 9

# factor metadata for the UI: id, label, Hound, max points. Sum(max) == 100.
FACTORS = [
    {"id": "expl",  "label": "Exploitability",        "hound": "Laelaps · KEV / EPSS",     "max": 20},
    {"id": "aes",   "label": "Tenable AES",           "hound": "Tenable One · Asset Exposure", "max": 8},
    {"id": "sev",   "label": "Severity (VPR)",        "hound": "Tenable VPR",              "max": 8},
    {"id": "crit",  "label": "Business criticality",  "hound": "Anubis · ACR",             "max": 8},
    {"id": "path",  "label": "Attack path",           "hound": "Fenrir",                   "max": 8},
    {"id": "ident", "label": "Identity exposure",     "hound": "Janus · NHI / account reuse",      "max": 7},
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
# Heimdall: 277650 = remote services NOT using post-quantum ciphers. The "Post-Quantum" tag also
# lands on PQC-READY assets (277653), so the score reads the plugin, not the tag.
_PQ_EXPOSED = "277650"
_CERT_WARN_DAYS = 30                                      # cert expired or expiring within this many days
_MAX_WEIGHT = 1000.0
LIMIT_MAX = 5000


def _cert_days(v):
    """Days until a certificate's not_valid_after (negative = expired); None if unparseable."""
    try:
        from core.certdates import parse_cert_date
        d = parse_cert_date(v)
    except Exception:
        return None
    return (d - datetime.date.today()).days if d else None


def _r(x):
    """Round half UP (x >= 0) — Python's round() is half-to-even and the page's Math.round
    is half-up, so a 4.5 used to be 4 here and 5 in the browser."""
    return int(math.floor(x + 0.5))


def rank_key(fscore, s):
    """One ordering for the board, the act-now list and the tag set: worst first, ties broken
    by KEV, VPR, volume, then uuid — deterministic, and identical everywhere."""
    return (fscore, s["kev"], s["vpr"] or 0, s["vol"], str(s["uuid"]))


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
def _build_query(db_path, only=None):
    # `only`: one asset uuid — every per-asset aggregate is filtered to it (Argos' single score)
    lit = ("'" + str(only).replace("'", "''") + "'") if only else None
    wh = (lambda cond="": (" WHERE " + (cond + " AND " if cond else "") + "asset_uuid=" + lit) if lit
          else ((" WHERE " + cond) if cond else ""))
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
        # SLA age = how long an OPEN finding has been open → first_found (last_found is the
        # last time a scan saw it, i.e. almost always "recently", so it never breached)
        ff = "first_found" if "first_found" in vc else None
        # only OPEN findings are exposure — fixed ones used to count toward KEV / VPR / volume
        # / EOL / SLA (navi keeps fixed rows in vulns with state='fixed')
        open_where = wh("lower(COALESCE(state,'open')) IN ('open','reopened')" if "state" in vc else "")
        th = _sla_days(db_path)
        eol_like = (f"(lower({pn}) LIKE '%unsupported%' OR lower({pn}) LIKE '%end of life%' OR "
                    f"lower({pn}) LIKE '%end-of-life%' OR lower({pn}) LIKE '%no longer supported%')")
        age = (f"(julianday('now')-julianday(substr(replace(replace({ff},'T',' '),'Z',''),1,19)))" if ff else None)
        sla_expr = ("0" if not age else
                    "MAX(CASE " + " ".join(
                        f"WHEN lower({sev}) IN ('{name}','{num}') AND {age}>{float(th[name])} THEN 1"
                        for name, num in (("critical", "4"), ("high", "3"), ("medium", "2"), ("low", "1"))
                        if th.get(name) is not None) + " ELSE 0 END)")
        creds = ",".join("'%s'" % p for p in _CRED_PLUGINS)
        ctes.append(f"""v AS (SELECT asset_uuid u,
          MAX(CASE WHEN {xr} LIKE '%CISA-KNOWN-EXPLOITED%' THEN 1 ELSE 0 END) kev,
          MAX(CAST({sc} AS REAL)) vpr,
          MAX(CASE WHEN {eol_like} THEN 1 ELSE 0 END) veol,
          SUM(CASE WHEN lower({sev}) IN ('critical','4') OR {xr} LIKE '%CISA-KNOWN-EXPLOITED%' THEN 1 ELSE 0 END) vol,
          {sla_expr} slabr,
          MAX(CASE WHEN CAST({pid} AS TEXT) IN ({creds}) THEN 1 ELSE 0 END) blind,
          MAX(CASE WHEN CAST({pid} AS TEXT)='{_PQ_EXPOSED}' THEN 1 ELSE 0 END) pqv
          FROM vulns {open_where} GROUP BY asset_uuid)""")
        joins.append("LEFT JOIN v ON v.u=a.uuid")
        cols += ["COALESCE(v.kev,0) kev", "v.vpr vpr", "COALESCE(v.veol,0) veol",
                 "COALESCE(v.vol,0) vol", "COALESCE(v.slabr,0) slabr", "COALESCE(v.blind,0) blind",
                 "COALESCE(v.pqv,0) pq"]
    else:
        cols += ["0 kev", "NULL vpr", "0 veol", "0 vol", "0 slabr", "0 blind", "0 pq"]

    if _has("tags", db_path):
        # tag keys compared by their BASE name: a Settings → Test run tag ('Hounds-Attack Path')
        # is the same signal as 'Attack Path' (core.tagname)
        _TK = tagname.sql_base("tag_key")
        ctes.append(f"""t AS (SELECT asset_uuid u,
          MAX(CASE WHEN lower({_TK}) LIKE 'attack path%' AND lower(tag_key||' '||tag_value) LIKE '%target%' THEN 2
                   WHEN lower({_TK}) LIKE 'attack path%' THEN 1 ELSE 0 END) path,
          MAX(CASE WHEN lower({_TK}) IN ('nhi','identity','identity risk') AND lower(tag_value) LIKE '%reuse%' THEN 2
                   WHEN lower({_TK}) IN ('nhi','identity','identity risk') THEN 1 ELSE 0 END) ident,
          MAX(CASE WHEN (lower({_TK})='ai' OR lower({_TK}) LIKE 'ai %') AND lower(tag_key||' '||tag_value) LIKE '%expose%' THEN 3
                   WHEN (lower({_TK})='ai' OR lower({_TK}) LIKE 'ai %') AND (lower(tag_value) LIKE '%shadow%' OR lower(tag_value) LIKE '%priority%') THEN 2
                   WHEN (lower({_TK})='ai' OR lower({_TK}) LIKE 'ai %') THEN 1 ELSE 0 END) ai,
          MAX(CASE WHEN lower({_TK})='iot' THEN 1 ELSE 0 END) iot,
          MAX(CASE WHEN lower({_TK})='mitre' THEN 1 ELSE 0 END) mitre,
          MAX(CASE WHEN lower({_TK}) IN ('lifecycle','lifecycle eol') THEN 1 ELSE 0 END) eoltag,
          MAX(CASE WHEN lower({_TK}) IN ('cert failure','cert issue') THEN 1 ELSE 0 END) certfail
          FROM tags""" + wh() + """ GROUP BY asset_uuid)""")
        ctes.append("o AS (SELECT asset_uuid u, GROUP_CONCAT(tag_value,'||') ov FROM tags"
                    + wh("lower(" + _TK + ") IN ('owner','business owner','asset owner')") + " GROUP BY asset_uuid)")
        joins += ["LEFT JOIN t ON t.u=a.uuid", "LEFT JOIN o ON o.u=a.uuid"]
        cols += ["COALESCE(t.path,0) path", "COALESCE(t.ident,0) ident", "COALESCE(t.ai,0) ai",
                 "COALESCE(t.iot,0) iot", "COALESCE(t.mitre,0) mitre", "COALESCE(t.eoltag,0) eoltag",
                 "COALESCE(t.certfail,0) certfail", "o.ov ov"]
    else:
        cols += ["0 path", "0 ident", "0 ai", "0 iot", "0 mitre", "0 eoltag", "0 certfail", "NULL ov"]

    if _has("compliance", db_path):
        ctes.append("c AS (SELECT asset_uuid u, SUM(CASE WHEN upper(status) LIKE 'FAIL%' THEN 1 ELSE 0 END) cfail "
                    "FROM compliance" + wh() + " GROUP BY asset_uuid)")
        joins.append("LEFT JOIN c ON c.u=a.uuid")
        cols.append("COALESCE(c.cfail,0) cfail")
    else:
        cols.append("0 cfail")

    if _has("certs", db_path):
        cc = _cols("certs", db_path)
        sig = "signature_algorithm" if "signature_algorithm" in cc else None
        kl = "key_length" if "key_length" in cc else None
        exp = "not_valid_after" if "not_valid_after" in cc else None
        sg = f"lower(COALESCE({sig},''))" if sig else "''"
        alg = "algorithm" if "algorithm" in cc else None
        kalg = f"lower(COALESCE({alg},{sig or 'NULL'},''))" if alg else sg
        # SHA-1 / MD5 signatures ("SHA-1 With RSA Encryption"); short keys only for RSA — a 256-bit
        # ECDSA key is strong
        weak = (f"({sg} LIKE '%sha1%' OR {sg} LIKE '%sha-1%' OR {sg} LIKE '%md5%'"
                + (f" OR ({kalg} LIKE '%rsa%' AND {kalg} NOT LIKE '%ecdsa%' AND CAST({kl} AS INTEGER) BETWEEN 1 AND 2047)"
                   if kl else "") + ")")
        # expired or expiring within 30 days; navi stores 'Dec 12 20:57:22 2023 GMT' (parsed in Python)
        expiring = (f"(_cert_days({exp}) IS NOT NULL AND _cert_days({exp}) <= {_CERT_WARN_DAYS})" if exp else "0")
        ctes.append(f"cr AS (SELECT asset_uuid u, MAX(CASE WHEN {weak} THEN 1 ELSE 0 END) weak, "
                    f"MAX(CASE WHEN {expiring} THEN 1 ELSE 0 END) expiring FROM certs{wh()} GROUP BY asset_uuid)")
        joins.append("LEFT JOIN cr ON cr.u=a.uuid")
        cols += ["COALESCE(cr.weak,0) weak", "COALESCE(cr.expiring,0) expiring"]
    else:
        cols += ["0 weak", "0 expiring"]

    was_tbl = next((tb for tb in ("findings", "apps", "was_findings")
                    if _has(tb, db_path) and {"asset_uuid", "severity"} <= _cols(tb, db_path)), None)
    if was_tbl:
        ctes.append(f"w AS (SELECT asset_uuid u, MAX(CASE WHEN lower(severity) IN ('critical','4') THEN 2 "
                    f"WHEN lower(severity) IN ('high','3') THEN 1 ELSE 0 END) was FROM {was_tbl}{wh()} GROUP BY asset_uuid)")
        joins.append("LEFT JOIN w ON w.u=a.uuid")
        cols.append("COALESCE(w.was,0) was")
    else:
        cols.append("0 was")

    head = ("WITH " + ",\n".join(ctes) + "\n") if ctes else ""
    return (head + f"SELECT a.uuid uuid, {host} host, {ip} ip, {acr} acr, {aes} aes, " + ", ".join(cols)
            + " FROM assets a " + " ".join(joins) + (" WHERE a.uuid=" + lit if lit else ""))


def _sla_days(db_path):
    """SLA days per severity from navi.db's `sla` table (Sköll's thresholds); the old
    hard-coded 15 / 30 days for critical / high when none are configured."""
    try:
        from core import sla as _sla
        th = _sla.thresholds(db_path) or {}
    except Exception:
        th = {}
    th = {k: v for k, v in th.items() if v is not None and v > 0}   # 0 / blank = no window
    return th or {"critical": 15, "high": 30}


def _epss_map(db_path, cap):
    """asset_uuid -> max EPSS, streamed. Skipped above `cap` assets (can't index a
    CVE-list join). Returns (map, used)."""
    if not (_has("epss", db_path) and _has("vulns", db_path) and "cves" in _cols("vulns", db_path)):
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
        st = ("AND lower(COALESCE(state,'open')) IN ('open','reopened')" if "state" in _cols("vulns", db_path) else "")
        for u, cves in con.execute(f"SELECT asset_uuid, cves FROM vulns WHERE cves LIKE '%CVE-%' {st}"):
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
    return {fid: _r(frac[fid] * weights.get(fid, 0)) for fid in frac}


def _resolve_weights(weights):
    """Return (weight_map, is_custom). A caller may pass any relative weights; they're
    clamped to >=0 and re-normalised to sum 100 so the 0–100 score meaning holds."""
    base = {f["id"]: float(f["max"]) for f in FACTORS}
    if not weights:
        return base, False
    clean = {}
    for f in FACTORS:
        try:
            v = weights.get(f["id"], base[f["id"]])
            v = float(v) if not isinstance(v, bool) else base[f["id"]]
            if not math.isfinite(v):
                v = base[f["id"]]
            clean[f["id"]] = min(_MAX_WEIGHT, max(0.0, v))
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
        "uuid": r["uuid"], "host": (str(r["host"] or "").strip() or str(r["ip"] or "").strip() or r["uuid"]), "ip": r["ip"],
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
                or s["ai"] or s["eol"] or s["crypto"] or s["mitre"] or s["blind"] or s["exposed"])


ACT_THRESHOLDS = (80, 60, 40)


def _scored(p, wmap, epss_map, only=None):
    """Stream (signals, factor points, unrounded score, score) for every asset (or `only` one)."""
    con = db.connect(p)
    con.row_factory = sqlite3.Row
    con.create_function("_cert_days", 1, _cert_days, deterministic=True)
    try:
        cur = con.execute(_build_query(p, only))
        while True:
            batch = cur.fetchmany(5000)
            if not batch:
                break
            for r in batch:
                s = _row_signals(r, epss_map)
                pts = _factor_pts(s, wmap)
                fscore = sum(pts.values()) * _disp_mul(s)
                yield s, pts, fscore, min(100, _r(fscore))
    finally:
        con.close()


def asset_score(uuid, db_path=None, weights=None, epss_cap=_EPSS_CAP):
    """One asset's fused score with the same factors and weights as the estate view
    (EPSS included only under the same asset-count cap as overview/select_uuids) —
    every aggregate filtered to that asset. navi.db has no index on vulns.asset_uuid, so
    each aggregate is still a table scan; ~0.1 s at 600k findings, linear in vulns rows.
    {score, band, factors, signals} or None."""
    p = db_path or db.db_path()
    if not uuid or not _has("assets", p):
        return None
    wmap, _ = _resolve_weights(weights)
    emap = {}
    try:
        n_assets = int(db.scalar("SELECT COUNT(*) FROM assets", path=p, budget=0) or 0)
    except Exception:
        n_assets = 0
    if n_assets and n_assets <= epss_cap and _has("epss", p) and _has("vulns", p) and "cves" in _cols("vulns", p):
        st = ("AND lower(COALESCE(state,'open')) IN ('open','reopened')" if "state" in _cols("vulns", p) else "")
        cves = set()
        for r in _q(f"SELECT cves FROM vulns WHERE asset_uuid=? AND cves LIKE '%CVE-%' {st}", (uuid,), p):
            cves |= {c.upper() for c in _cves(r["cves"])}
        vals = []
        cl = sorted(cves)
        for i in range(0, len(cl), 900):           # stay under SQLite's 999-parameter limit
            part = cl[i:i + 900]
            ph = ",".join("?" * len(part))
            vals += [_fnum(r["epss_value"]) for r in _q(f"SELECT epss_value FROM epss WHERE upper(cve) IN ({ph})",
                                                         tuple(part), p)]
        vals = [v for v in vals if v is not None]
        if vals:
            emap[uuid] = max(vals)
    for s, pts, fscore, score in _scored(p, wmap, emap, only=uuid):
        return {"score": score, "band": _band(score), "factors": pts,
                "kev": bool(s["kev"]), "sla": bool(s["sla"]), "unowned": bool(s["unowned"])}
    return None


def select_uuids(db_path=None, weights=None, threshold=80, uuid=None, fallback=10, epss_cap=_EPSS_CAP):
    """The asset set a Priority tag is applied to, recomputed from navi.db — never taken
    from the browser. ``threshold``: every asset scoring >= it (or the worst ``fallback``
    when none does — the same rule the page shows). ``uuid``: just that asset, if it exists."""
    p = db_path or db.db_path()
    if uuid is not None:
        uuid = str(uuid).strip()
        r = _q("SELECT uuid FROM assets WHERE uuid=?", (uuid,), p) if uuid else []
        return [r[0]["uuid"]] if r else []
    if not _has("assets", p):
        return []
    wmap, _ = _resolve_weights(weights)
    epss_map, _ = _epss_map(p, epss_cap)
    hit, top = [], []
    for s, _pts, fscore, score in _scored(p, wmap, epss_map):
        if score >= threshold:
            hit.append(s["uuid"])
        elif not hit:
            k = rank_key(fscore, s)
            if len(top) < fallback:
                heapq.heappush(top, (k, s["uuid"]))
            elif k > top[0][0]:
                heapq.heapreplace(top, (k, s["uuid"]))
    return hit or [u for _, u in sorted(top, reverse=True)]


# The per-asset signals On the Scent (Sphinx) stacks and overlaps — one hound each. Counted
# over ALL assets here (kpi.stack / kpi.cooccur), since the snapshot keeps only the worst N rows.
SIGNALS = (("kev", "KEV"), ("crown", "Crown"), ("eol", "EOL"), ("crypto", "Crypto"), ("comp", "Compliance"),
           ("sla", "SLA"), ("blind", "Blind"), ("unowned", "Unowned"), ("ai", "AI"), ("ident", "Identity"),
           ("path", "Path"))
STACK_MAX = 7                      # histogram buckets 0..6 and "7+"


def _signals_on(s):
    """Indexes into SIGNALS that fire on one scored asset."""
    return [i for i, (k, _) in enumerate(SIGNALS) if s.get(k)]


def overview(db_path=None, limit=500, offset=0, epss_cap=_EPSS_CAP, weights=None) -> dict:
    if not _has("assets", db_path):
        return {"ok": False, "error": "no assets table in navi.db — run `navi config update assets`"}
    p = db_path or db.db_path()
    wmap, wcustom = _resolve_weights(weights)
    epss_map, epss_used = _epss_map(p, epss_cap)
    limit = min(LIMIT_MAX, max(1, int(limit)))
    offset = max(0, int(offset))
    keep = offset + limit

    # accumulators (whole-estate) + a bounded top-N heap (memory O(keep))
    kpi = {k: 0 for k in ("assets", "critical", "high", "elevated", "low", "clean",
                          "kev", "crown", "crown_kev", "crown_unowned",
                          "crown_blind", "unowned", "unowned_crit", "kev_unowned", "kev_exposed",
                          "eol_crown", "path_unowned", "identreuse_kev", "blind", "no_signal",
                          "path", "ident", "ai", "ai_shadow", "eol", "crypto", "exposed",
                          "comp_fail", "was_exposed", "sla_breach")}
    factor_totals = {f["id"]: 0 for f in FACTORS}   # estate-wide sum of each factor's points
    estate = 0
    act = {t: {"n": 0, "unowned": 0, "owned": 0, "crown_kev": 0, "blind": 0} for t in ACT_THRESHOLDS}
    heap = []                        # (sortkey_tuple, seq, row)
    seq = 0
    worst = {f["id"]: (0, None) for f in FACTORS}
    nsig = len(SIGNALS)
    cooc = [[0] * nsig for _ in range(nsig)]    # assets carrying signal i AND j (diagonal = i alone)
    stack = [0] * (STACK_MAX + 1)               # assets by how many signals fire on them

    for s, pts, fscore, score in _scored(p, wmap, epss_map):
        # ---- estate KPIs ----
        kpi["assets"] += 1
        for t, a in act.items():           # act-now set at each threshold, whole estate
            if score >= t:
                a["n"] += 1
                a["unowned"] += 1 if s["unowned"] else 0
                a["crown_kev"] += 1 if (s["crown"] and s["kev"]) else 0
                a["blind"] += 1 if s["blind"] else 0
                a["owned"] += 0 if s["unowned"] else 1
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
        on = _signals_on(s)
        stack[min(len(on), STACK_MAX)] += 1
        for x, i in enumerate(on):
            ri = cooc[i]
            for j in on[x:]:
                ri[j] += 1
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
        key = rank_key(fscore, s)
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

    n = kpi["assets"]
    kpi["total"] = n
    kpi["estate"] = estate
    kpi["avg"] = round(estate / n, 1) if n else 0
    kpi["factor_totals"] = factor_totals
    kpi["act"] = {str(t): v for t, v in act.items()}
    for i in range(nsig):                       # mirror the upper triangle
        for j in range(i):
            cooc[i][j] = cooc[j][i]
    kpi["stack"] = stack
    kpi["cooccur"] = {"signals": [{"id": k, "label": lb} for k, lb in SIGNALS], "matrix": cooc}
    ranked = [t[2] for t in sorted(heap, key=lambda x: (x[0], x[1]), reverse=True)]
    page = ranked[offset:offset + limit]
    for row in page:
        row.pop("_k", None)

    worst_list = [{"id": f["id"], "label": f["label"], "hound": f["hound"],
                   "host": worst[f["id"]][1]["host"], "uuid": worst[f["id"]][1]["uuid"],
                   "pts": worst[f["id"]][0]}
                  for f in FACTORS if worst[f["id"]][1] and worst[f["id"]][0] > 0]
    hits = {}                                   # by asset, not hostname (names repeat / blank)
    for w in worst_list:
        h = hits.setdefault(w["uuid"], {"host": w["host"], "uuid": w["uuid"], "tops": 0})
        h["tops"] += 1
    convergence = sorted((h for h in hits.values() if h["tops"] >= 2), key=lambda x: -x["tops"])

    factors_meta = [{"id": f["id"], "label": f["label"], "hound": f["hound"],
                     "max": round(wmap[f["id"]]), "default": f["max"],
                     "weight": round(wmap[f["id"]], 1)} for f in FACTORS]
    return {"ok": True, "kpi": kpi, "factors": factors_meta, "assets": page,
            "total": n, "returned": len(page), "offset": offset, "limit": limit,
            "truncated": n > len(page), "epss_used": epss_used,
            "weights_custom": wcustom, "worst": worst_list, "convergence": convergence,
            "sla_days": _sla_days(p)}
