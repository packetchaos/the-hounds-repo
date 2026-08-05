"""Fused Exposure Score — the pack's convergence engine (Nemesis Hound).

One number per asset, assembled from every Hound. The direct signals (KEV via
``vulns.xrefs``, EPSS via the ``epss`` table, VPR via ``vulns.score``, ACR, EOL via
unsupported-product plugins, weak/expiring crypto via ``certs``) are always
computed; the rest (attack path, identity, AI, ATT&CK, ownership) are read off the
tags the other Hounds apply — so the score is honest before the whole pack has run
and gets richer as it does.

Eleven factors sum to 100, then a disposition discount applies and scan coverage
(Chronos) sets confidence. Read-only. The page does the projected-reduction math
from the per-factor contributions this returns.
"""
import re
from core import db

CROWN_ACR = 9

# factor metadata for the UI: id, label, Hound, colour hint, max points.
FACTORS = [
    {"id": "expl",  "label": "Exploitability",        "hound": "Laelaps · KEV / EPSS",     "max": 25},
    {"id": "sev",   "label": "Severity (VPR)",        "hound": "Tenable VPR",              "max": 15},
    {"id": "crit",  "label": "Business criticality",  "hound": "Anubis · ACR",             "max": 15},
    {"id": "path",  "label": "Attack path",           "hound": "Fenrir",                   "max": 8},
    {"id": "ident", "label": "Identity exposure",     "hound": "Janus · NHI / reuse",      "max": 8},
    {"id": "exp",   "label": "Internet exposure",     "hound": "Cerberus / exposed",       "max": 5},
    {"id": "ai",    "label": "AI risk",               "hound": "Pythia · shadow/exposed",  "max": 5},
    {"id": "eol",   "label": "EOL / unsupported",     "hound": "Charon",                   "max": 6},
    {"id": "cry",   "label": "Weak / expiring crypto","hound": "Certania + Heimdall",      "max": 5},
    {"id": "mit",   "label": "ATT&CK technique",      "hound": "Orthrus",                  "max": 3},
    {"id": "own",   "label": "Ownership gap",         "hound": "Terminus",                 "max": 5},
]
# ATT&CK techniques that matter most (impact / lateral movement / credential access)
_HOT_TECH = {"t1210", "t1486", "t1190", "t1003", "t1021", "t1078", "t1550", "t1570", "t1489", "t1491"}
_CRED_PLUGINS = {"104410", "21745", "110723", "117885"}   # credentialed-scan failures (Chronos)


def _q(sql, args=(), path=None):
    try:
        return list(db.query(sql, args, path=path)) if args else list(db.query(sql, path=path))
    except Exception:
        return []


def _has(t, path=None):
    return bool(_q("SELECT name FROM sqlite_master WHERE type='table' AND name=?", (t,), path))


def _fnum(x):
    try:
        v = float(x); return v if v == v else None
    except (TypeError, ValueError):
        return None


def _cols(t, path=None):
    return {r["name"] for r in _q(f"PRAGMA table_info({t})", path=path)}


def _cves(s):
    return set(re.findall(r"CVE-\d{4}-\d+", str(s or ""), re.I))


def _nk(s):
    return " ".join((s or "").strip().lower().split())


# --------------------------------------------------------------------------- #
#  Per-asset signal gathering                                                  #
# --------------------------------------------------------------------------- #
def _signals(db_path=None) -> dict:
    if not _has("assets", db_path):
        return {}
    acols = _cols("assets", db_path)
    acr = "acr" if "acr" in acols else "NULL acr"
    S = {}
    for r in _q(f"SELECT uuid, hostname, ip_address ip, {acr} FROM assets", path=db_path):
        u = r.get("uuid")
        if not u:
            continue
        av = _fnum(r.get("acr"))
        host = (r.get("hostname") or "").strip() or (r.get("ip") or "").strip() or u
        S[u] = {"uuid": u, "host": host, "ip": r.get("ip"),
                "acr": av, "crown": bool(av is not None and av >= CROWN_ACR),
                "kev": 0, "epss": 0.0, "vpr": 0.0, "eol": 0, "crypto": None,
                "path": None, "ident": 0, "ai": None, "mitre": None, "mitre_hot": 0,
                "exposed": 0, "unowned": 0, "blind": 0, "disp": None, "techniques": []}

    # ---- vulns: KEV, VPR, EOL(plugin), cred-fail(blind), CVE set for EPSS ----
    if _has("vulns", db_path):
        vc = _cols("vulns", db_path)
        sev = "severity" if "severity" in vc else "''"
        sc = "score" if "score" in vc else ("vpr" if "vpr" in vc else "0")
        xr = "xrefs" if "xrefs" in vc else "''"
        cv = "cves" if "cves" in vc else "''"
        eol_like = ("lower(plugin_name) LIKE '%unsupported%' OR lower(plugin_name) LIKE '%end of life%' "
                    "OR lower(plugin_name) LIKE '%end-of-life%' OR lower(plugin_name) LIKE '%no longer supported%'")
        for r in _q(f"SELECT asset_uuid u, "
                    f"MAX(CASE WHEN {xr} LIKE '%CISA-KNOWN-EXPLOITED%' THEN 1 ELSE 0 END) kev, "
                    f"MAX(CAST({sc} AS REAL)) vpr, "
                    f"MAX(CASE WHEN {eol_like} THEN 1 ELSE 0 END) eol "
                    f"FROM vulns GROUP BY asset_uuid", path=db_path):
            s = S.get(r.get("u"))
            if s:
                s["kev"] = int(r.get("kev") or 0)
                s["vpr"] = _fnum(r.get("vpr")) or 0.0
                s["eol"] = int(r.get("eol") or 0)
        # blind (Chronos): credentialed-scan failure plugins
        for r in _q("SELECT DISTINCT asset_uuid u, plugin_id p FROM vulns", path=db_path):
            if str(r.get("p")) in _CRED_PLUGINS and r.get("u") in S:
                S[r["u"]]["blind"] = 1
        # EPSS: max epss_value over the asset's CVEs
        if _has("epss", db_path):
            emap = {}
            for r in _q("SELECT cve, epss_value v FROM epss", path=db_path):
                ev = _fnum(r.get("v"))
                if r.get("cve") and ev is not None:
                    emap[str(r["cve"]).upper()] = ev
            if emap:
                for r in _q(f"SELECT asset_uuid u, {cv} cves FROM vulns WHERE {cv} LIKE '%CVE-%'", path=db_path):
                    s = S.get(r.get("u"))
                    if not s:
                        continue
                    for c in _cves(r.get("cves")):
                        e = emap.get(c.upper())
                        if e and e > s["epss"]:
                            s["epss"] = e

    # ---- certs: weak / expiring crypto (Certania + Heimdall, direct) ----
    if _has("certs", db_path):
        cc = _cols("certs", db_path)
        exp = "not_valid_after" if "not_valid_after" in cc else None
        sig = "signature_algorithm" if "signature_algorithm" in cc else None
        kl = "key_length" if "key_length" in cc else None
        sel = "asset_uuid u" + (f", {exp} exp" if exp else "") + (f", {sig} sig" if sig else "") + (f", {kl} kl" if kl else "")
        import datetime
        soon = (datetime.date.today() + datetime.timedelta(days=365)).isoformat()
        for r in _q(f"SELECT {sel} FROM certs", path=db_path):
            s = S.get(r.get("u"))
            if not s:
                continue
            sigv = _nk(r.get("sig"))
            klv = _fnum(r.get("kl"))
            weak = ("sha1" in sigv or "md5" in sigv or (klv is not None and klv < 2048))
            expiring = bool(exp and r.get("exp") and str(r.get("exp"))[:10] <= soon)
            if weak and s["crypto"] != "pq":
                s["crypto"] = "pq"
            elif expiring and not s["crypto"]:
                s["crypto"] = "certfail"

    # ---- tags: the Hound-produced factors (path / identity / AI / Mitre / EOL / PQ / ownership / disposition) ----
    if _has("tags", db_path):
        owner_family = {"owner", "business owner", "asset owner"}
        for r in _q("SELECT asset_uuid u, tag_key k, tag_value v FROM tags WHERE asset_uuid IS NOT NULL", path=db_path):
            s = S.get(r.get("u"))
            if not s:
                continue
            k, v = _nk(r.get("k")), (r.get("v") or "").strip()
            vl = _nk(v)
            if k.startswith("attack path") or k == "attack path":
                if "target" in (k + " " + vl):
                    s["path"] = "target"
                elif s["path"] != "target":
                    s["path"] = "entry"
            elif k in ("nhi", "identity"):
                s["ident"] = max(s["ident"], 2 if ("reuse" in vl or "shared" in vl) else 1)
            elif k == "ai" or k.startswith("ai "):
                if "expose" in (k + " " + vl):
                    s["ai"] = "exposed"
                elif "shadow" in (k + " " + vl) or "priority" in vl:
                    s["ai"] = s["ai"] or "shadow"
                else:
                    s["ai"] = s["ai"] or "present"
            elif k == "iot":
                s["exposed"] = 1
            elif k == "mitre":
                s["mitre"] = v or s["mitre"]
                tid = re.search(r"[Tt]\d{4}", v or "")
                if tid and tid.group(0).lower() in _HOT_TECH:
                    s["mitre_hot"] = 1
                if v:
                    s["techniques"].append(v)
            elif k == "lifecycle":
                s["eol"] = 1
            elif k in ("post-quantum", "post quantum"):
                s["crypto"] = "pq"
            elif k == "cert failure" and not s["crypto"]:
                s["crypto"] = "certfail"
        # ownership + disposition from Owner-family tags
        owned, disp = {}, {}
        for r in _q("SELECT asset_uuid u, tag_key k, tag_value v FROM tags "
                    "WHERE lower(tag_key) IN ('owner','business owner','asset owner')", path=db_path):
            u = r.get("u"); v = (r.get("v") or "").strip()
            user = v.rsplit(": ", 1)[1].strip() if ": " in v else v
            lab = next((d for d in ("Ignored", "Accepted", "Mitigated") if user.lower() == d.lower()), None)
            if lab:
                disp[u] = lab
            else:
                owned[u] = True
        for u, s in S.items():
            if u not in owned:
                s["unowned"] = 1
            if u in disp and u not in owned:
                s["disp"] = disp[u]
        # AI exposure fallback: exposed AI implies internet exposure
        for s in S.values():
            if s["ai"] == "exposed":
                s["exposed"] = 1
    return S


# --------------------------------------------------------------------------- #
#  Scoring                                                                      #
# --------------------------------------------------------------------------- #
def _disp_mul(s):
    return 0.3 if s.get("disp") == "Mitigated" else 0.55 if s.get("disp") == "Accepted" else 1.0


def _factor_pts(s):
    return {
        "expl": 25 if s["kev"] else round(s["epss"] * 25),
        "sev":  round((s["vpr"] or 0) / 10 * 15),
        "crit": 15 if s["crown"] else round(min(s["acr"] or 0, 9) / 9 * 15),
        "path": 8 if s["path"] == "target" else 5 if s["path"] == "entry" else 0,
        "ident": 8 if s["ident"] >= 2 else 4 if s["ident"] == 1 else 0,
        "exp": 5 if s["exposed"] else 0,
        "ai": 5 if s["ai"] == "exposed" else 4 if s["ai"] == "shadow" else 2 if s["ai"] == "present" else 0,
        "eol": 6 if s["eol"] else 0,
        "cry": 5 if s["crypto"] == "pq" else 3 if s["crypto"] == "certfail" else 0,
        "mit": (3 if s["mitre_hot"] else 2) if s["mitre"] else 0,
        "own": 5 if s["unowned"] else 0,
    }


def _band(sc):
    return "CRITICAL" if sc >= 80 else "HIGH" if sc >= 60 else "ELEVATED" if sc >= 40 else "LOW"


def overview(db_path=None) -> dict:
    if not _has("assets", db_path):
        return {"ok": False, "error": "no assets table in navi.db — run `navi config update assets`"}
    S = _signals(db_path)
    rows = []
    for s in S.values():
        pts = _factor_pts(s)
        raw = sum(pts.values())
        score = min(100, round(raw * _disp_mul(s)))
        # which remediation plays apply to this asset (drives the projected-reduction math on the page)
        applies = {
            "patch": bool(s["kev"] or (s["vpr"] or 0) >= 7),
            "eol": bool(s["eol"]),
            "crypto": bool(s["crypto"]),
            "segment": bool(s["exposed"] or s["ai"]),
            "own": bool(s["unowned"]),
        }
        rows.append({
            "uuid": s["uuid"], "host": s["host"], "ip": s["ip"], "acr": s["acr"], "crown": s["crown"],
            "score": score, "band": _band(score), "factors": pts,
            "disp": s["disp"], "blind": bool(s["blind"]), "applies": applies,
            # signal payload for chips
            "kev": s["kev"], "epss": round(s["epss"], 2), "vpr": round(s["vpr"] or 0, 1),
            "path": s["path"], "ident": s["ident"], "exposed": bool(s["exposed"]), "ai": s["ai"],
            "eol": bool(s["eol"]), "crypto": s["crypto"], "mitre": s["mitre"], "unowned": bool(s["unowned"]),
            "techniques": s["techniques"][:8],
        })
    rows.sort(key=lambda r: -r["score"])

    n = len(rows)
    crit = [r for r in rows if r["score"] >= 80]
    high = [r for r in rows if r["score"] >= 60]
    estate = sum(r["score"] for r in rows)
    kpi = {
        "assets": n, "estate": estate, "avg": round(estate / n, 1) if n else 0,
        "critical": len(crit), "high": len(high),
        "kev": sum(1 for r in rows if r["kev"]), "crown": sum(1 for r in rows if r["crown"]),
        "unowned_crit": sum(1 for r in crit if r["unowned"]),
        "crown_kev": sum(1 for r in rows if r["crown"] and r["kev"]),
        "blind": sum(1 for r in rows if r["blind"]),
    }
    # worst-from-each-Hound + convergence
    worst, host_hits = [], {}
    for f in FACTORS:
        best, bv = None, 0
        for r in rows:
            v = r["factors"].get(f["id"], 0)
            if v > bv:
                bv, best = v, r
        if best and bv > 0:
            worst.append({"id": f["id"], "label": f["label"], "hound": f["hound"],
                          "host": best["host"], "uuid": best["uuid"], "pts": bv})
            host_hits[best["host"]] = host_hits.get(best["host"], 0) + 1
    convergence = sorted(([{"host": h, "tops": c} for h, c in host_hits.items() if c >= 2]),
                         key=lambda x: -x["tops"])
    return {"ok": True, "kpi": kpi, "factors": FACTORS, "assets": rows,
            "worst": worst, "convergence": convergence}
