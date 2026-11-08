"""'Bet you didn't know this' — aggregate the unknown-unknowns from navi.db.

Cheap, resilient roll-up used by the insights landing page: certificates failing
soon, assets with no software inventory, IoT devices, identities, MITRE techniques
on high-ACR assets, and custom apps. Each figure links to the agent that owns it.
"""
import datetime
import re

from core import db, signals, tagname
from core.certdates import parse_cert_date

_CVE = re.compile(r"CVE-\d{4}-\d{3,}", re.I)


def _date(s):
    # robust multi-format cert-date parse (OpenSSL / ISO / epoch / …)
    return parse_cert_date(s)


def compute(db_path=None):
    def sc(sql):
        try:
            return db.scalar(sql, path=db_path) or 0
        except Exception:
            return 0

    today = datetime.date.today()
    try:
        end = today.replace(year=today.year + 1)
    except ValueError:                       # Feb 29 → Feb 28 next year
        end = today.replace(year=today.year + 1, day=28)
    certs = 0            # failing = valid today, expires within the next 12 months
    certs_expired = 0    # already failed = expiry date is in the past
    # 13 forward month buckets (current month first) — the SAME shape Certania's
    # dashboard renders as `heatmap_months`, so Sphinx's graph and certdash agree.
    cert_months = []
    _y, _m = today.year, today.month
    for _ in range(13):
        cert_months.append({"key": f"{_y:04d}-{_m:02d}",
                            "label": datetime.date(_y, _m, 1).strftime("%b %Y"), "count": 0})
        _m += 1
        if _m > 12:
            _m, _y = 1, _y + 1
    _bmap = {b["key"]: b for b in cert_months}
    try:
        try:
            crows = list(db.query("SELECT asset_uuid, not_valid_after FROM certs", path=db_path))
        except Exception:                    # older navi.db with no asset_uuid on certs
            crows = list(db.query("SELECT not_valid_after FROM certs", path=db_path))
        seen = set()
        for i, r in enumerate(crows):
            d = _date(r.get("not_valid_after"))
            if not d:
                continue
            # Certania counts one cert per (asset, expiry date) — dedupe identically,
            # or this board's numbers drift from the certificate dashboard's.
            key = (r.get("asset_uuid", i), d.isoformat())
            if key in seen:
                continue
            seen.add(key)
            if today <= d <= end:
                certs += 1
                b = _bmap.get(d.isoformat()[:7])
                if b:
                    b["count"] += 1
            elif d < today:
                certs_expired += 1
    except Exception:
        pass

    total = sc("SELECT COUNT(uuid) FROM assets")
    # intersect with assets — software may carry orphan asset_uuids not in the assets table,
    # so a bare COUNT(DISTINCT asset_uuid) can exceed total and yield >100% coverage.
    inv = sc("SELECT COUNT(DISTINCT s.asset_uuid) FROM software s JOIN assets a ON a.uuid=s.asset_uuid")
    shadow = max(0, total - inv)

    try:
        iot = len(signals._iot(db_path).get("devices", []))
    except Exception:
        iot = 0
    try:
        ident = len(signals._identity(db_path).get("accounts", []))
    except Exception:
        ident = 0
    if not ident:
        ident = sc("SELECT COUNT(DISTINCT asset_uuid) FROM vulns WHERE plugin_id IN "
                   "('95928','10860','83303','10785')")

    mitre_high = 0
    try:
        from core import downloads, mitre
        # live only when Settings → Auto-approve downloads is ON (no approval card here); else the snapshot
        rows, _ = mitre.fetch_mapping(allow_live=downloads.auto_approve())
        cset = {r["cve"] for r in rows}
        hits = set()
        for r in db.query("SELECT v.asset_uuid, v.cves FROM vulns v LEFT JOIN assets a "
                          "ON a.uuid=v.asset_uuid WHERE CAST(a.acr AS REAL)>7 "
                          "AND TRIM(COALESCE(v.cves,''))<>''", path=db_path):
            for c in _CVE.findall(r.get("cves") or ""):
                if c.upper() in cset:
                    hits.add(r["asset_uuid"]); break
        mitre_high = len(hits)
    except Exception:
        pass

    custom = sc("SELECT COUNT(*) FROM vuln_route")

    # Docker hosts / containers — plugin 93561 (output lists running containers)
    docker = sc("SELECT COUNT(DISTINCT asset_uuid) FROM vulns WHERE plugin_id='93561' "
                "OR plugin_name LIKE '%Docker%'")
    # Web applications — Web Servers / CGI plugin families
    web = sc("SELECT COUNT(DISTINCT asset_uuid) FROM vulns WHERE plugin_family IN "
             "('Web Servers','CGI abuses')")
    # Cloud assets — any AWS / GCP / Azure provenance on the asset record
    acols = set()
    try:
        acols = {r["name"] for r in db.query("PRAGMA table_info(\"assets\");", path=db_path)}
    except Exception:
        pass
    cloud = 0
    cc = [c for c in ("aws_id", "gcp_instance_id", "azure_vm_id", "azure_resource_id") if c in acols]
    if cc:
        where = " OR ".join(f"COALESCE({c},'')<>''" for c in cc)
        cloud = sc(f"SELECT COUNT(uuid) FROM assets WHERE {where}")
    # AI — Tenable's Artificial Intelligence plugin family
    ai = sc("SELECT COUNT(DISTINCT asset_uuid) FROM vulns WHERE plugin_family "
            "LIKE '%Artificial Intelligence%'")

    # ===== graphical stories — the unknowns, visualized (charts on the page) =====
    def rows(sql):
        try:
            return list(db.query(sql, path=db_path))
        except Exception:
            return []
    has_plugins = bool(rows("SELECT name FROM sqlite_master WHERE type='table' AND name='plugins'"))
    sev = []
    sr = rows("SELECT p.severity sev, COUNT(*) c FROM vulns v JOIN plugins p ON p.plugin_id=v.plugin_id GROUP BY p.severity") if has_plugins else []
    if not sr:
        sr = rows("SELECT severity sev, COUNT(*) c FROM vulns GROUP BY severity")
    for r in sr:
        if r.get("sev") is not None:
            sev.append({"sev": r.get("sev"), "count": int(r.get("c") or 0)})
    kev = sc("SELECT COUNT(DISTINCT asset_uuid) FROM vulns WHERE xrefs LIKE '%CISA-KNOWN-EXPLOITED%'")
    acr_bands = {}
    for r in rows("SELECT CASE WHEN CAST(acr AS REAL)>=9 THEN 'crit' WHEN CAST(acr AS REAL)>=7 THEN 'high' "
                  "WHEN CAST(acr AS REAL)>=4 THEN 'med' WHEN CAST(acr AS REAL)>=1 THEN 'low' ELSE 'unrated' END b, "
                  "COUNT(*) c FROM assets GROUP BY b"):
        acr_bands[r.get("b")] = int(r.get("c") or 0)
    owned = sc("SELECT COUNT(DISTINCT asset_uuid) FROM tags WHERE " + tagname.sql_lit("tag_key", "Owner"))
    credfail = sc("SELECT COUNT(DISTINCT asset_uuid) FROM vulns WHERE plugin_id IN "
                  "('104410','21745','110385','117885','84239')")
    top_routes = [{"app": (r.get("app_name") or "").strip(), "vulns": int(r.get("total_vulns") or 0)}
                  for r in rows("SELECT app_name, total_vulns FROM vuln_route WHERE total_vulns IS NOT NULL "
                                "ORDER BY total_vulns DESC LIMIT 8")]
    funnel, champion = {}, None
    if has_plugins:
        fr = rows("WITH present AS (SELECT DISTINCT plugin_id FROM vulns) SELECT (SELECT COUNT(*) FROM vulns) findings,"
                  "(SELECT COUNT(*) FROM present) plugins,(SELECT COUNT(DISTINCT app_name) FROM vuln_route) routes,"
                  "(SELECT SUM((length(p.cves)-length(replace(p.cves,'CVE-','')))/4) FROM plugins p "
                  "JOIN present ON present.plugin_id=p.plugin_id WHERE p.cves IS NOT NULL AND p.cves NOT IN ('','[]','None')) cves")
        if fr:
            x = fr[0]
            funnel = {"cves": int(x.get("cves") or 0), "findings": int(x.get("findings") or 0),
                      "plugins": int(x.get("plugins") or 0), "routes": int(x.get("routes") or 0),
                      "paths": int(sc("SELECT COUNT(*) FROM vuln_paths") or 0)}
        cr = rows("WITH present AS (SELECT DISTINCT plugin_id FROM vulns) SELECT p.name nm, p.plugin_id pid,"
                  "(length(p.cves)-length(replace(p.cves,'CVE-','')))/4 n,"
                  "(SELECT COUNT(DISTINCT asset_uuid) FROM vulns v WHERE v.plugin_id=p.plugin_id) a "
                  "FROM plugins p JOIN present ON present.plugin_id=p.plugin_id "
                  "WHERE p.cves IS NOT NULL AND p.cves NOT IN ('','[]','None') ORDER BY n DESC LIMIT 1")
        if cr:
            x = cr[0]
            champion = {"name": x.get("nm"), "plugin_id": x.get("pid"),
                        "cve_count": int(x.get("n") or 0), "assets": int(x.get("a") or 0)}
    pq_vuln = pq_safe = 0
    for r in rows("SELECT signature_algorithm a, COUNT(*) c FROM certs GROUP BY signature_algorithm"):
        a = str(r.get("a") or "").lower(); n = int(r.get("c") or 0)
        if any(k in a for k in ("ml-dsa", "dilithium", "sphincs", "falcon", "kyber", "ml-kem")):
            pq_safe += n
        else:
            pq_vuln += n
    stories = {"severity": sev, "kev": kev, "acr_bands": acr_bands, "owned": owned,
               "inventory": inv, "credfail": credfail, "top_routes": top_routes,
               "funnel": funnel, "champion": champion, "pq": {"vuln": pq_vuln, "safe": pq_safe}}

    return {"certs_failing": certs, "certs_expired": certs_expired,
            "cert_months": cert_months,
            "shadow_assets": shadow, "iot_devices": iot,
            "identities": ident, "mitre_high_acr": mitre_high, "custom_apps": custom,
            "docker_hosts": docker, "web_apps": web, "cloud_assets": cloud,
            "ai_assets": ai, "asset_total": total, "stories": stories}


# --------------------------------------------------------------------------- #
#  The Scent Board — Sphinx's estate brain (redesign)                          #
#                                                                              #
#  Nemesis scores each ASSET; Sphinx rolls that same fusion up to the ESTATE:  #
#  where every Hound's domain stands, what you're BLIND to, the cross-Hound    #
#  surprises no single agent sees, and a hand-off to Nemesis to act. Read-only.#
# --------------------------------------------------------------------------- #
def _sc(sql, db_path=None):
    try:
        return db.scalar(sql, path=db_path) or 0
    except Exception:
        return 0


def scent_board(db_path=None):
    from core import fused_score
    fo = {}
    try:
        fo = fused_score.overview(db_path)
    except Exception:
        fo = {}
    rows = fo.get("assets", []) if fo.get("ok") else []
    fk = fo.get("kpi", {}) if fo.get("ok") else {}
    total = fk.get("assets") or _sc("SELECT COUNT(uuid) FROM assets", db_path)

    # Whole-estate counts come from the fused-score KPI block (computed over ALL
    # assets in SQL) — `rows` is only the worst-N slice, so never count off it.
    kev = fk.get("kev", 0)
    crown = fk.get("crown", 0)
    eol = fk.get("eol", 0)
    crypto = fk.get("crypto", 0)
    path = fk.get("path", 0)
    ident = fk.get("ident", 0)
    ai = fk.get("ai", 0)
    exposed = fk.get("exposed", 0)
    unowned = fk.get("unowned", 0)
    blind = fk.get("blind", 0)
    no_signal = fk.get("no_signal", 0)
    crown_unowned = fk.get("crown_unowned", 0)
    ai_shadow = fk.get("ai_shadow", 0)

    def pct(a, b):
        return round(100.0 * a / b, 1) if b else 0.0

    # ---- classic single-signal rollup (certs / iot / etc.) reused from compute() ----
    try:
        c = compute(db_path)
    except Exception:
        c = {}

    # ---- estate posture — one tile per domain (Hound). status: ok|warn|crit|off ----
    def tile(id, domain, hound, icon, value, sub, status, href):
        return {"id": id, "domain": domain, "hound": hound, "icon": icon,
                "value": value, "sub": sub, "status": status, "href": href}

    crit_assets = fk.get("critical", 0)
    posture = [
        tile("exposure", "Exposure score", "Nemesis", "🎯", crit_assets,
             f"{crit_assets} critical · estate {fk.get('estate', 0)}", "crit" if crit_assets else "ok",
             "/agents/fused_score/page.html"),
        tile("kev", "CISA KEV", "Laelaps", "🔥", kev, "actively exploited", "crit" if kev else "ok",
             "/agents/cisakev/page.html"),
        tile("crown", "Crown jewels", "Anubis", "👑", crown,
             f"{crown_unowned} unowned", "warn" if crown else "off",
             "/agents/acr/page.html"),
        tile("cert", "Certificates", "Certania", "🔐", c.get("certs_failing", 0),
             f"{c.get('certs_expired', 0)} already expired", "warn" if c.get("certs_failing") else "ok",
             "/agents/certificate/page.html"),
        tile("eol", "EOL / crypto decay", "Charon+Heimdall", "🔩", eol + crypto,
             f"{eol} EOL · {crypto} weak crypto", "warn" if (eol + crypto) else "ok",
             "/agents/eol/page.html"),
        tile("ident", "Identity exposure", "Janus", "🪪", ident, "NHI / account reuse",
             "warn" if ident else "off", "/agents/identity/page.html"),
        tile("path", "Attack paths", "Fenrir", "🕸", path, "foothold → crown jewel",
             "crit" if path else "off", "/agents/attackpath/page.html"),
        tile("ai", "AI exposure", "Pythia", "🧠", ai, f"{ai_shadow} shadow",
             "warn" if ai else "off", "/agents/ai/page.html"),
        tile("iot", "IoT / OT", "Cerberus", "🐾", c.get("iot_devices", 0), "unmanageable devices",
             "warn" if c.get("iot_devices") else "off", "/agents/iot_squad/page.html"),
        tile("own", "Ownership coverage", "Terminus", "📌", f"{pct(total - unowned, total)}%",
             f"{unowned} unclaimed", "crit" if pct(unowned, total) > 50 else "warn" if unowned else "ok",
             "/agents/asset_ownership/page.html"),
    ]
    # ---- domains that come from their own engines (may be 'not run' on this navi.db) ----
    try:
        from core import compliance as _comp
        co = _comp.overview(db_path)
        # compliance.overview() returns assets / assets_rows / pass_pct — NOT the
        # assets_total / assets_failing keys this tile once guessed at (that mismatch
        # made the tile read "no audit data yet" even with a populated table).
        if co.get("available") and (co.get("assets_total") or co.get("assets")):
            fails = co.get("assets_failing", co.get("failing"))
            if fails is None:   # assets with ≥1 FAILED check, from the per-asset scorecards
                fails = sum(1 for a in (co.get("assets_rows") or [])
                            if (a.get("failed") or 0) > 0)
            posture.append(tile("compliance", "Compliance", "Minos", "⚖️",
                                 f"{co.get('pass_pct', co.get('compliant_pct', 0)) or 0}%",
                                 f"{fails} failing", "crit" if fails else "ok", "/agents/compliance/page.html"))
        else:
            posture.append(tile("compliance", "Compliance", "Minos", "⚖️", "—", "no audit data yet", "off", "/agents/compliance/page.html"))
    except Exception:
        pass
    try:
        from core import sla as _sla
        so = _sla.readiness(db_path)
        if so.get("sla_set"):
            posture.append(tile("sla", "SLA adherence", "Sköll", "⏱", "set", "SLA thresholds active", "warn", "/agents/sla/page.html"))
        else:
            posture.append(tile("sla", "SLA adherence", "Sköll", "⏱", "—", "no SLA set", "off", "/agents/sla/page.html"))
    except Exception:
        pass
    try:
        from core import was as _was
        wo = _was.overview(db_path)
        if wo.get("available") and wo.get("apps"):
            posture.append(tile("was", "Web apps (WAS)", "Arachne", "🕸️", wo.get("findings", wo.get("apps", 0)),
                                 f"{wo.get('apps', 0)} apps", "warn", "/agents/was/page.html"))
        else:
            posture.append(tile("was", "Web apps (WAS)", "Arachne", "🕸️", "—", "no WAS data yet", "off", "/agents/was/page.html"))
    except Exception:
        pass
    # ---- Command & Control (Amarok) — remediation executed on hosts, from the tag ledger ----
    try:
        from core import tagq as _tq
        _jobs = _tq.list_jobs()
        pushes = sum(1 for j in _jobs if j.get("op") == "push")
        done = sum(1 for j in _jobs if j.get("op") == "push" and j.get("status") == "done")
        if pushes:
            posture.append(tile("c2", "Remediation", "Amarok", "🐺", done,
                                 f"{pushes} pushes · {done} verified on hosts", "warn", "/agents/c2/page.html"))
        else:
            posture.append(tile("c2", "Remediation", "Amarok", "🐺", "—",
                                 "no pushes yet — arm Amarok to fix at the source", "off", "/agents/c2/page.html"))
    except Exception:
        pass

    # ---- blind spots — the dark matter Sphinx is named for (risk by ABSENCE) ----
    # Classification MUST come from Linnaeus' own engine, not a re-implemented SQL
    # rule. The old query counted `tags.tag_key='Class'`, a key nothing ever writes
    # (Linnaeus tags Asset Inventory / 'Class: <x>', accepts 5 other categories, and
    # treats cloud metadata as ground truth) — so this tile was pinned at 100%
    # unclassified while the Linnaeus page reported 0. One definition, one number.
    unclassified = None
    try:
        from core import classify as _classify
        _cl = _classify.classify(db_path)
        if _cl.get("ok"):
            unclassified = int(_cl.get("unclassified") or 0)
            total = total or _cl.get("total") or 0
    except Exception:
        unclassified = None
    if unclassified is None:                      # engine unavailable — best-effort SQL
        unclassified = _sc(
            "SELECT COUNT(a.uuid) FROM assets a WHERE NOT EXISTS ("
            "SELECT 1 FROM tags t WHERE t.asset_uuid=a.uuid AND TRIM(COALESCE(t.tag_value,''))<>'' "
            "AND lower(" + tagname.sql_base("t.tag_key") + ") IN ('asset inventory','os','operating system','iot','device type','class'))",
            db_path)
    # Business criticality in the pack is ACR (Anubis) — plus any tier tag if one
    # exists. 'Business Tier' alone is not a key navi ever writes.
    no_tier = _sc(
        "SELECT COUNT(a.uuid) FROM assets a WHERE (TRIM(COALESCE(a.acr,''))='' OR CAST(a.acr AS REAL)<=0) "
        "AND NOT EXISTS (SELECT 1 FROM tags t WHERE t.asset_uuid=a.uuid "
        "AND TRIM(COALESCE(t.tag_value,''))<>'' AND ("
        "lower(" + tagname.sql_base("t.tag_key") + ") IN ('business tier','tier','criticality') OR "
        "(lower(" + tagname.sql_base("t.tag_key") + ")='asset inventory' AND ("
        "lower(t.tag_value) LIKE 'tier:%' OR lower(t.tag_value) LIKE 'business tier:%' "
        "OR lower(t.tag_value) LIKE 'criticality:%'))))", db_path)
    blind_spots = [
        {"label": "No Hound signal", "count": no_signal, "sub": "the pack found nothing — truly dark", "sev": "crit"},
        {"label": "Uncredentialed / blind", "count": blind, "sub": "Chronos — scan can't see inside", "sev": "crit"},
        {"label": "Unclassified", "count": unclassified, "sub": "Linnaeus — type unknown", "sev": "warn"},
        {"label": "Unowned", "count": unowned, "sub": "Terminus — nobody accountable", "sev": "warn"},
        {"label": "No business tier", "count": no_tier, "sub": "Anubis — criticality unrated (no ACR / tier tag)", "sev": "warn"},
        {"label": "Shadow AI", "count": ai_shadow, "sub": "Pythia — AI off the sanctioned list", "sev": "warn"},
    ]

    # ---- convergence — the cross-Hound surprises no single agent sees ----
    def conv(text, n, sev):
        return {"text": text, "count": n, "sev": sev, "href": "/agents/fused_score/page.html"}
    convergence = [c for c in [
        conv("crown jewels with no owner", crown_unowned, "crit"),
        conv("crown jewels the scan can't see (blind)", fk.get("crown_blind", 0), "crit"),
        conv("KEV-exploitable assets nobody owns", fk.get("kev_unowned", 0), "crit"),
        conv("KEV-exploitable AND internet-exposed", fk.get("kev_exposed", 0), "crit"),
        conv("EOL software on a crown jewel", fk.get("eol_crown", 0), "warn"),
        conv("attack-path targets nobody owns", fk.get("path_unowned", 0), "warn"),
        conv("account-reuse hosts that are KEV-exploitable", fk.get("identreuse_kev", 0), "crit"),
    ] if c["count"] > 0]
    convergence.sort(key=lambda x: (-{"crit": 2, "warn": 1}.get(x["sev"], 0), -x["count"]))

    # ---- POWER GRAPHS — chart-ready series so the board tells a story, not just counts ----
    # 1) Exposure distribution: mutually exclusive score bands across the whole estate.
    crit_b = fk.get("critical", 0)
    high_b = max(0, fk.get("high", 0) - crit_b)          # 60–79 (kpi 'high' is cumulative ≥60)
    bands = [
        {"label": "Critical", "sub": "≥ 80", "count": crit_b, "sev": "crit"},
        {"label": "High", "sub": "60–79", "count": high_b, "sev": "high"},
        {"label": "Elevated", "sub": "40–59", "count": fk.get("elevated", 0), "sev": "med"},
        {"label": "Low", "sub": "1–39", "count": fk.get("low", 0), "sev": "low"},
        {"label": "Clean", "sub": "0", "count": fk.get("clean", 0), "sev": "ok"},
    ]

    # 2) Where the estate's risk comes from — each Hound's share of total fused exposure,
    #    and how saturated that factor is on average (0–100). This is the differentiator:
    #    competitors show a vuln count; the pack attributes fused risk to a detection domain.
    ftot = fk.get("factor_totals", {}) or {}
    fsum = sum(ftot.values()) or 1
    risk_by_hound, radar = [], []
    for f in fused_score.FACTORS:
        tv = ftot.get(f["id"], 0)
        sat = round(100.0 * tv / ((f["max"] or 1) * (total or 1)), 1)   # avg intensity of this factor
        risk_by_hound.append({"id": f["id"], "label": f["label"], "hound": f["hound"],
                              "total": tv, "pct": round(100.0 * tv / fsum, 1), "sat": sat})
        radar.append({"axis": f["label"], "hound": f["hound"], "value": sat})
    risk_by_hound_sorted = sorted(risk_by_hound, key=lambda x: -x["total"])

    # 3) Coverage funnel — what the pack can actually SEE, stage by stage (drop-offs = blind spots).
    funnel = [
        {"label": "All assets", "count": total, "note": "the whole estate"},
        {"label": "Seen by a Hound", "count": max(0, total - no_signal), "note": f"{no_signal} truly dark"},
        {"label": "Credentialed", "count": max(0, total - blind), "note": f"{blind} blind / uncredentialed"},
        {"label": "Classified", "count": max(0, total - unclassified), "note": f"{unclassified} unclassified"},
        {"label": "Owned", "count": max(0, total - unowned), "note": f"{unowned} unowned"},
        {"label": "Business-tiered", "count": max(0, total - no_tier), "note": f"{no_tier} untiered"},
    ]

    return {"ok": True, "asset_total": total,
            "nemesis": {"critical": crit_assets, "high": fk.get("high", 0),
                        "estate": fk.get("estate", 0), "avg": fk.get("avg", 0),
                        "top": [{"host": r["host"], "score": r["score"]} for r in rows[:5]]},
            "bands": bands, "risk_by_hound": risk_by_hound_sorted, "radar": radar, "funnel": funnel,
            # 12-month certificate expiry series — each bucket deep-links into
            # Certania's dashboard scoped to that month (web/certdash.html?month=…).
            "certs": {"months": c.get("cert_months") or [],
                      "failing": c.get("certs_failing", 0),
                      "expired": c.get("certs_expired", 0)},
            "reduction": (c.get("stories") or {}).get("funnel") or {},
            "champion": (c.get("stories") or {}).get("champion"),
            "posture": posture, "blind": blind_spots, "convergence": convergence,
            "classic": c}


# =========================================================================== #
#  On the Scent — the Release digest (Sphinx's page)                          #
#                                                                             #
#  Built ONLY from what Release the Hounds left behind: each hound's page-    #
#  cache entry (core/pagecache.py) and the Nemesis / Atlas / Sköll snapshots. #
#  It never queries navi.db and never re-runs a hound — every number is the   #
#  owning hound's own, and links back to it. Release runs it LAST (recipe     #
#  kind "snapshot", action "scent"); opening the page only peeks it.          #
#  The answer is compact (~20 KB, every list capped) whatever the estate size.#
# =========================================================================== #
import gzip as _gzip
import hashlib as _hashlib
import json as _json
import os as _os
import time as _time

from core import pagecache as _pc, snapcache as _snapcache

SCENT = _snapcache.Snapshots("scent", version=1)
INLINE_MAX_GZ = int(_os.environ.get("NAVI_SCENT_INLINE_MAX", str(4 * 1024 * 1024)))   # cached inputs above this (gz) → job queue
SNAP_AGENTS = ("fused_score", "exproute", "sla")
_ROOT = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
_MAN = None

# Nemesis factor → the hound that detects it (treemap tiles link there)
FACTOR_AGENT = {"expl": "cisakev", "aes": "fused_score", "sev": "fused_score", "crit": "acr", "path": "attackpath",
                "ident": "identity", "comp": "compliance", "was": "was", "eol": "eol", "exp": "iot_squad", "ai": "ai",
                "cry": "certificate", "sla": "sla", "vol": "fused_score", "own": "asset_ownership", "mit": "mitre"}
# Crown-jewel rules differ between hounds — every crown number is labelled with its owner's rule.
CROWN_RULE = {"fused_score": "ACR ≥ 9", "asset_ownership": "ACR ≥ 9", "postquantum": "ACR ≥ 7", "ai": "ACR ≥ 7",
              "certificate": "ACR > 7", "eol": "ACR > 7", "attackpath": "ACR ≥ 7", "scan_eval": "ACR ≥ 7",
              "cisakev": "ACR > 7"}


def _P(a, sec=""):
    return "/agents/%s/page.html%s" % (a, ("#" + sec) if sec else "")


def _manifests():
    global _MAN
    if _MAN is None:
        out = {}
        try:
            for a in _os.listdir(_os.path.join(_ROOT, "agents")):
                try:
                    with open(_os.path.join(_ROOT, "agents", a, "manifest.json"), encoding="utf-8") as f:
                        m = _json.load(f)
                    out[m.get("id") or a] = m
                except Exception:
                    pass
        except OSError:
            pass
        _MAN = out
    return _MAN


def _name(a):
    m = _manifests().get(a) or {}
    return (m.get("codename") or m.get("name") or a).replace(" Hound", "")


def _icon(a):
    return (_manifests().get(a) or {}).get("icon") or ""


def _recipe_pages():
    from core import release
    return [r for r in release.recipes()["pages"] if r["agent"] != "insights"]


def _release_record(db_path=None):
    try:
        from core import release
        return release.record(db_path)
    except Exception:
        return None


def _entry_metas(db_path=None):
    """{agent: listing row} for the recipe hounds' page-cache entries (small .meta files only)."""
    out = {}
    for m in _pc.listing(db_path):
        k = str(m.get("key") or "")
        if k.startswith("/agents/") and k.endswith("/page.html") and k.count("/") == 3:
            out.setdefault(k.split("/")[2], m)
    return out


def _cache_file(name):
    return _os.path.join(_snapcache.CACHE_DIR, name)


def _stat(name):
    try:
        st = _os.stat(_cache_file(name))
        return [st.st_mtime_ns, st.st_size]
    except OSError:
        return None


def _read_gz(path):
    try:
        with _gzip.open(path, "rt", encoding="utf-8") as f:
            return _json.load(f)
    except Exception:
        return None


def _snap_refs(rec, prev):
    """Which snapshot file each snapshot hound left: the release's record of it, else the one
    the previous digest used. Cheap (no file reads)."""
    items = {i.get("agent"): i for i in (rec or {}).get("items") or []}
    pin = ((prev or {}).get("_inputs") or {}).get("snaps") or {}
    out = {}
    for a in SNAP_AGENTS:
        f = ((items.get(a) or {}).get("snap") or {}).get("file") or (pin.get(a) or {}).get("file")
        if f and _stat(f):
            out[a] = f
    return out


def _scan_snaps(missing, db_path, cur):
    """Build-time fallback when no release recorded a snapshot: Atlas / Sköll snapshots say
    which navi.db they're for; Nemesis' is matched on the current navi.db signature."""
    from core import release
    me = _snapcache.db_file(db_path)
    out = {}
    try:
        names = _os.listdir(_snapcache.CACHE_DIR)
    except OSError:
        return out
    for a in missing:
        pre = release.SNAP_PREFIX.get(a)
        best = None
        for n in names:
            if not (n.startswith(pre + "_") and n.endswith(".json.gz")):
                continue
            s = _read_gz(_cache_file(n)) or {}
            m = s.get("meta") or {}
            if a == "fused_score":
                ok = m.get("sig") == cur
            else:
                ok = m.get("db") == me and not (a == "sla" and (m.get("view") or {}).get("tag_key"))
            if ok:
                t = _os.path.getmtime(_cache_file(n))
                if not best or t > best[0]:
                    best = (t, n)
        if best:
            out[a] = best[1]
    return out


def _fingerprint(metas, snap_stats, cur, rec_id):
    """What the digest was built from. `at`+`released` (not size: replaying a page can add a
    missed read to its entry without it being a new run)."""
    pages = {r["agent"] for r in _recipe_pages()}
    rows = sorted([a, m.get("at"), (m.get("released") or {}).get("id"), (m.get("released") or {}).get("sig")]
                  for a, m in metas.items() if a in pages)
    raw = _json.dumps([rows, sorted((a, s) for a, s in snap_stats.items()), cur, rec_id], default=str)
    return _hashlib.sha1(raw.encode()).hexdigest()[:16]


def _iso_ms(s):
    try:
        import datetime
        return int(datetime.datetime.fromisoformat(str(s)).timestamp() * 1000)
    except Exception:
        return None


_LIVE_NOTE = "loads its live list on open"


def _coverage(metas, snap_info, rec, cur):
    """One row per recipe hound (On the Scent itself excluded — it's the reader)."""
    items = {i.get("agent"): i for i in (rec or {}).get("items") or []}
    rid = (rec or {}).get("id")
    out = []
    for r in _recipe_pages():
        a, it = r["agent"], items.get(r["agent"]) or {}
        row = {"agent": a, "label": r["label"], "codename": _name(a), "icon": _icon(a), "kind": r["kind"],
               "href": _P(a), "status": "missing", "at": None, "kb": None, "note": None}
        if r["kind"] == "live":
            row.update(status="live", note=_LIVE_NOTE)
        elif r["kind"] == "snapshot":
            si = snap_info.get(a)
            if si:
                row.update(status="fresh" if si.get("sig") == cur else ("user" if si.get("user") else "stale"),
                           at=si.get("at"), kb=si.get("kb"))
                if si.get("user"):
                    row["note"] = "rebuilt since this summary"
        else:
            m = metas.get(a)
            if m:
                rel = m.get("released") or None
                st = "user" if not rel else ("fresh" if rel.get("sig") == cur else "stale")
                row.update(status=st, at=m.get("at"), kb=round((m.get("size") or 0) / 1024.0, 1))
                if st == "user":
                    row["note"] = "your own run on this page"
                elif rel.get("id") == rid and it.get("note"):
                    row["note"] = it.get("note")
        if row["status"] == "missing" and it:
            if it.get("status") in ("error", "skipped"):
                row.update(status=it["status"], note=it.get("note"))
            elif it.get("status") == "cancelled":
                row["note"] = "the release was cancelled before this hound"
        if row["status"] == "stale" and not row["note"]:
            row["note"] = "navi.db changed since"
        out.append(row)
    return out


def _counts(cov):
    tot = [c for c in cov if c["kind"] != "live"]
    present = [c for c in tot if c["status"] in ("fresh", "user", "stale")]
    stale = [c for c in present if c["status"] == "stale"]
    return len(tot), len(present), len(stale)


def _page_state(cov, running):
    total, present, stale = _counts(cov)
    fused = next((c for c in cov if c["agent"] == "fused_score"), {})
    if running:
        return "building"
    if not present:
        return "none"
    if stale * 2 > present:
        return "stale"
    if present < total or fused.get("status") not in ("fresh", "user", "stale"):
        return "partial"
    return "ready"


def _stored(db_path=None):
    s = _read_gz(SCENT._path(SCENT.key(db_path)))
    return (s or {}).get("result") if isinstance(s, dict) else None


def _hist_est():
    """Release time estimate from the last release's measured times (no navi.db read)."""
    try:
        from core import release
        h = release._history()
        secs = [v.get("sec") or 0 for k, v in h.items() if isinstance(v, dict)]
        return round(sum(secs), 1) if secs else None
    except Exception:
        return None


def _live(db_path=None, stored=None):
    """Cheap view of the inputs right now: page-cache metadata, snapshot file stats, the
    release record, navi.db's signature (os.stat). No navi.db query, no entry reads."""
    cur = _snapcache.db_signature(db_path)
    rec = _release_record(db_path)
    metas = _entry_metas(db_path)
    refs = _snap_refs(rec, stored)
    stats = {a: _stat(f) for a, f in refs.items()}
    pin = ((stored or {}).get("_inputs") or {}).get("snaps") or {}
    snap_info = {}
    for a, f in refs.items():
        p = pin.get(a) or {}
        if p.get("file") == f and p.get("st") == stats[a]:
            snap_info[a] = {"sig": p.get("sig"), "at": p.get("at"), "kb": p.get("kb")}
        else:                                # a different / rebuilt snapshot than the digest read
            snap_info[a] = {"sig": None, "user": True, "kb": round(stats[a][1] / 1024.0, 1)}
    return {"cur": cur, "rec": rec, "metas": metas, "refs": refs, "stats": stats, "snap_info": snap_info,
            "fp": _fingerprint(metas, stats, cur, (rec or {}).get("id"))}


def _release_info(rec):
    r = rec or {}
    fin = r.get("finished")
    return {"id": r.get("id"), "status": r.get("status"),
            "at": int(float(fin) * 1000) if fin else None,
            "started": int(float(r["started"]) * 1000) if r.get("started") else None}


# ------------------------------------------------------------------ the build
def scent_digest(db_path=None):
    """Summarise the pack's released results into the On the Scent digest. Reads the page
    cache entries + snapshot files only — never navi.db."""
    from core import release
    t0 = _time.time()
    prev = _stored(db_path)
    lv = _live(db_path, prev)
    cur, rec, metas = lv["cur"], lv["rec"], lv["metas"]
    refs = dict(lv["refs"])
    refs.update(_scan_snaps([a for a in SNAP_AGENTS if a not in refs], db_path, cur))
    recipes = {r["agent"]: r for r in _recipe_pages()}

    # ---- page entries (the heavy part: whole gz entries)
    E = {}
    for a, r in recipes.items():
        if r["kind"] == "page" and a in metas:
            E[a] = _pc.get("/agents/%s/page.html" % a, db_path)

    def R(agent, action, nth=0):
        """The owning hound's cached answer to `action` (the release's own request when present)."""
        e = E.get(agent) or {}
        resp = e.get("resp") or {}
        r = recipes.get(agent) or {}
        reqs = [q for q in r.get("requests") or [] if q["agent"] == agent and q["action"] == action]
        hit = None
        if len(reqs) > nth:
            # the recipe names this exact request: its answer or nothing — never another
            # request's answer (a failed software query must not borrow the EOL query's rows)
            hit = resp.get(release.req_key(agent, action, reqs[nth].get("body") or {}, r.get("key_ignore") or ()))
        elif not reqs:
            hs = [v for k, v in resp.items() if k.startswith("POST /api/%s/%s " % (agent, action))]
            hit = hs[nth] if len(hs) > nth else None
        b = (hit or {}).get("body")
        if not isinstance(b, dict):
            return None
        return b.get("result", b) if isinstance(b.get("result", b), dict) else None

    # ---- snapshots
    S, snap_pin = {}, {}
    for a, f in refs.items():
        s = _read_gz(_cache_file(f))
        if not isinstance(s, dict):
            continue
        S[a] = s
        m = s.get("meta") or {}
        st = _stat(f)
        snap_pin[a] = {"file": f, "st": st, "sig": m.get("sig"), "at": _iso_ms(m.get("built_at")),
                       "kb": round((st or [0, 0])[1] / 1024.0, 1)}
    fused = (S.get("fused_score") or {}).get("result") or {}
    fk = fused.get("kpi") or {}
    expr = S.get("exproute") or {}
    sla = (S.get("sla") or {}).get("result") or {}
    have = {a: bool(E.get(a)) for a in recipes}
    have.update({"fused_score": bool(fk), "exproute": bool(expr.get("map")), "sla": bool(sla)})

    stats = {a: (snap_pin.get(a) or {}).get("st") for a in refs if a in snap_pin}
    fp = _fingerprint(metas, stats, cur, (rec or {}).get("id"))
    cov = _coverage(metas, snap_pin, rec, cur)
    total = fk.get("assets") or 0

    def g(d, *path, default=None):
        for p in path:
            if not isinstance(d, dict):
                return default
            d = d.get(p)
        return default if d is None else d

    cert_r, eol_r, pq_r, ai_r = R("certificate", "run") or {}, R("eol", "run") or {}, R("postquantum", "run") or {}, R("ai", "run") or {}
    id_r, kev_r, mit_r, ap_r = R("identity", "run") or {}, R("cisakev", "run") or {}, R("mitre", "run") or {}, R("attackpath", "run") or {}
    comp, se_r, cl, own_r = R("compliance", "overview") or {}, R("scan_eval", "run") or {}, R("classify", "run") or {}, R("asset_ownership", "overview") or {}
    iot, capp_r, was = R("iot_squad", "run") or {}, R("customapp", "run") or {}, R("was", "overview") or {}
    cert, eolm, pq, ai = cert_r.get("metrics") or {}, g(eol_r, "view", "metrics", default={}), pq_r.get("metrics") or {}, ai_r.get("metrics") or {}
    idm, kevs, mit, apm = id_r.get("metrics") or {}, kev_r.get("summary") or {}, mit_r.get("metrics") or {}, ap_r.get("metrics") or {}
    se, own, capp = se_r.get("metrics") or {}, own_r.get("kpi") or {}, capp_r.get("metrics") or {}
    if not total:
        total = se.get("assets") or cl.get("total") or own.get("assets") or idm.get("estate") or 0

    def n_or_none(agent, v):
        return v if have.get(agent) else None

    # ---- at a glance
    def card(agent, v, l, href, sev=None, u=None):
        if not have.get(agent):
            return {"v": None, "l": l, "u": "not in this release →", "href": _P(agent), "sev": None, "zero": True,
                    "agent": agent}
        u = u or "%s %s →" % (_icon(agent), _name(agent))
        return {"v": v, "l": l, "u": u, "href": href, "sev": sev, "zero": not v, "agent": agent}

    sw = R("software", "run_sql", 0) or {}
    sw_inv = len({r.get("asset_uuid") for r in (sw.get("rows") or []) if isinstance(r, dict) and r.get("asset_uuid")})
    comp_fail_assets = sum(1 for x in comp.get("assets_rows") or [] if (x.get("failed") or 0) > 0)
    det = g(iot, "discovery", "detected", default=[]) or []
    iot_n = len({d.get("asset_uuid") for d in det if isinstance(d, dict) and d.get("asset_uuid")})
    cred_ok = g(se, "status", "ok", default=0)
    stack_raw = fk.get("stack")
    A = fused.get("assets") or []
    from core import fused_score as _fs
    if not stack_raw and A:                    # older snapshot: count the rows it kept
        stack_raw = [0] * (_fs.STACK_MAX + 1)
        for a in A:
            stack_raw[min(len(_fs._signals_on(a)), _fs.STACK_MAX)] += 1
    lit4 = sum((stack_raw or [])[4:]) if stack_raw else 0

    glance = [
        {"group": "How exposed", "cards": [
            card("fused_score", fk.get("avg", 0), "avg exposure score / 100", _P("fused_score", "sec-lb")),
            card("fused_score", fk.get("high", 0), "assets scored ≥ 60", _P("fused_score", "sec-act"), "crit",
                 "🎯 Nemesis · act now →"),
            card("cisakev", kevs.get("kev_assets", 0), "KEV-exploitable assets", _P("cisakev", "secCves"), "crit"),
            card("compliance", comp.get("pass_pct", 0), "% audit checks passing", _P("compliance", "secStatus"), "warn")
            if comp.get("available", True) else
            {"v": None, "l": "% audit checks passing", "u": "no audit data in navi.db →", "href": _P("compliance"),
             "sev": None, "zero": True, "agent": "compliance"}]},
        {"group": "Where it concentrates", "cards": [
            card("fused_score", fk.get("crown", 0), "crown jewels (ACR ≥ 9)", _P("acr"), None, "🎯 Anubis · ACR →"),
            card("eol", eolm.get("eol_assets", 0), "assets on EOL software", _P("eol", "secProd"), "warn"),
            card("certificate", cert.get("expired_assets", 0), "assets with expired certs", _P("certificate", "secCerts"), "warn"),
            card("postquantum", pq.get("exposed", 0), "quantum-vulnerable assets", _P("postquantum", "secRoad"))]},
        {"group": "Converging", "cards": [
            card("fused_score", fk.get("crown_kev", 0), "crown jewels (ACR ≥ 9) with KEV", "#secConverge", "crit", "🔗 Convergence →"),
            card("fused_score", fk.get("crown_blind", 0), "crown jewels (ACR ≥ 9) blind", "#secConverge", "crit", "🔗 Convergence →"),
            card("fused_score", lit4, "assets lit by ≥ 4 hounds", "#secConverge", "warn", "🔗 Signal stack →")]},
        {"group": "Blind spots", "cards": [
            card("scan_eval", max(0, (se.get("assets") or total) - cred_ok), "not credential-scanned OK",
                 _P("scan_eval", "secAssets"), "crit"),
            card("classify", cl.get("unclassified", 0), "unclassified", _P("classify"), "warn"),
            card("asset_ownership", own.get("unclaimed", 0), "unclaimed by any owner", _P("asset_ownership"), "warn")]},
    ]

    # ---- how exposed
    crit = fk.get("critical", 0)
    bands = [
        {"id": "critical", "label": "Critical", "range": "≥80", "count": crit},
        {"id": "high", "label": "High", "range": "60–79", "count": max(0, fk.get("high", 0) - crit)},
        {"id": "elevated", "label": "Elevated", "range": "40–59", "count": fk.get("elevated", 0)},
        {"id": "low", "label": "Low", "range": "1–39", "count": fk.get("low", 0)},
        {"id": "clean", "label": "Clean", "range": "0", "count": fk.get("clean", 0)},
    ] if fk else []
    ft = fk.get("factor_totals") or {}
    fsum = sum(ft.values()) or 1
    factors = sorted([{"id": f["id"], "label": f["label"], "hound": str(f.get("hound") or "").split(" · ")[0],
                       "agent": FACTOR_AGENT.get(f["id"], "fused_score"), "total": ft.get(f["id"], 0),
                       "pct": round(100.0 * ft.get(f["id"], 0) / fsum, 1)}
                      for f in fused.get("factors") or []], key=lambda x: -x["total"])
    exposure = {"assets": total, "avg": fk.get("avg"), "estate": fk.get("estate"), "bands": bands, "factors": factors,
                "available": bool(fk)}

    # ---- footprint: assets each hound flags (its own number) + crown jewels by ITS rule
    def fpr(agent, label, n, crown, sec, crown_rule=None):
        return {"agent": agent, "label": label, "n": n, "crown": crown,
                "crown_rule": crown_rule or (CROWN_RULE.get(agent) if crown is not None else None),
                "href": _P(agent, sec), "codename": _name(agent), "icon": _icon(agent)}
    footprint = []
    if have["certificate"]:
        footprint.append(fpr("certificate", "Expired certs", cert.get("expired_assets", 0), cert.get("crown_expired_assets"), "secCerts"))
    if have["postquantum"]:
        footprint.append(fpr("postquantum", "Quantum-vulnerable crypto", pq.get("exposed", 0), pq.get("crown"), "secRoad"))
    if have["eol"]:
        footprint.append(fpr("eol", "EOL / unsupported", eolm.get("eol_assets", 0), eolm.get("crown_assets"), "secProd"))
    if have["compliance"] and comp.get("available", True):
        footprint.append(fpr("compliance", "Failing audit controls", comp_fail_assets, None, "secCtrl"))
    if have["identity"]:
        footprint.append(fpr("identity", "Identity exposure", idm.get("identity_hosts", 0), None, "secIds"))
    if have["ai"]:
        footprint.append(fpr("ai", "AI workloads", ai_r.get("asset_count", 0), ai.get("crown"), "secAssets"))
    if have["cisakev"]:
        footprint.append(fpr("cisakev", "CISA KEV exploitable", kevs.get("kev_assets", 0),
                             fk.get("crown_kev") if fk else None, "secCves", "ACR ≥ 9 (Nemesis)"))
    if have["iot_squad"]:
        footprint.append(fpr("iot_squad", "IoT / OT devices", iot_n, None, ""))
    if have["mitre"]:
        footprint.append(fpr("mitre", "ATT&CK-mapped CVEs", mit.get("assets_affected", 0), None, "secMatrix"))
    if have["attackpath"]:
        footprint.append(fpr("attackpath", "Crown jewels reachable", apm.get("crown_reachable", 0),
                             apm.get("crown_reachable", 0), "secPaths",
                             "ACR ≥ %g" % float(ap_r.get("crown_acr") or 7)))
    if have["was"] and was.get("available") and was.get("apps"):
        footprint.append(fpr("was", "Web apps (WAS)", was.get("apps", 0), None, ""))
    quiet = [f["label"] for f in footprint if not f["n"]]          # hounds that flag nothing here
    footprint = sorted((f for f in footprint if f["n"]), key=lambda x: -(x["n"] or 0))[:12]

    # ---- worst assets × hound points
    worst = [{"host": a.get("host") or a.get("ip") or a.get("uuid"), "uuid": a.get("uuid"), "score": a.get("score"),
              "crown": bool(a.get("crown")),
              "factors": {k: v for k, v in (a.get("factors") or {}).items() if v}} for a in A[:8]]

    # ---- converging: signal stack + overlap map (whole estate when the snapshot has it)
    stack = [{"signals": k, "label": ("%d+" % k if k == _fs.STACK_MAX else str(k)),
              "assets": (stack_raw or [0] * 8)[k] if stack_raw else 0} for k in range(_fs.STACK_MAX + 1)] if stack_raw else []
    co = fk.get("cooccur")
    if co and co.get("matrix"):
        sig_l, M = co["signals"], co["matrix"]
        basis = "all %s assets" % format(total, ",")
    elif A:
        sig_l = [{"id": k, "label": lb} for k, lb in _fs.SIGNALS]
        n = len(sig_l)
        M = [[0] * n for _ in range(n)]
        for a in A:
            on = _fs._signals_on(a)
            for i in on:
                for j in on:
                    M[i][j] += 1
        basis = ("worst %s of %s assets" % (format(len(A), ","), format(total, ","))) if fused.get("truncated") \
            else "all %s assets" % format(len(A), ",")
    else:
        sig_l, M, basis = [], [], ""
    keep = [i for i in range(len(sig_l)) if M[i][i] > 0]
    cooccur = {"signals": [{"id": sig_l[i]["id"], "label": sig_l[i]["label"], "n": M[i][i]} for i in keep],
               "matrix": [[M[i][j] for j in keep] for i in keep], "basis": basis}

    def cv(text, n, sev, owner_sec, fix_agent, fix_sec, b="acr"):
        return {"text": text, "n": n, "sev": sev, "a": fix_agent, "b": b,
                "rule": "ACR ≥ 9 · Nemesis" if "rown" in text else "Nemesis",
                "href": _P("fused_score", owner_sec), "fix_href": _P(fix_agent, fix_sec)}
    convergence = [c for c in [
        cv("Crown jewels with a KEV-exploitable finding", fk.get("crown_kev", 0), "crit", "sec-act", "cisakev", "secCrown"),
        cv("Crown jewels the scan can't see inside", fk.get("crown_blind", 0), "crit", "sec-lb", "scan_eval", "secAssets"),
        cv("Crown jewels with no owner", fk.get("crown_unowned", 0), "crit", "sec-lb", "asset_ownership", ""),
        cv("KEV-exploitable AND internet-exposed", fk.get("kev_exposed", 0), "crit", "sec-act", "cisakev", "secCves", "iot_squad"),
        cv("KEV-exploitable assets nobody owns", fk.get("kev_unowned", 0), "crit", "sec-act", "asset_ownership", "", "cisakev"),
        cv("Account-reuse hosts that are KEV-exploitable", fk.get("identreuse_kev", 0), "crit", "sec-lb", "identity", "secReuse", "cisakev"),
        cv("EOL software on a crown jewel", fk.get("eol_crown", 0), "warn", "sec-lb", "eol", "secCrown"),
        cv("Attack-path targets nobody owns", fk.get("path_unowned", 0), "warn", "sec-lb", "attackpath", "secPaths", "asset_ownership"),
    ] if c["n"] and c["n"] > 0]
    convergence.sort(key=lambda x: (0 if x["sev"] == "crit" else 1, -x["n"]))
    for c in convergence:
        c["pair"] = "%s %s × %s %s" % (_icon(c["a"]), _name(c["a"]), _icon(c["b"]), _name(c["b"]))

    # ---- on the clock
    months = [{"key": m.get("key"), "label": m.get("label"), "count": m.get("count") or 0}
              for m in (cert_r.get("heatmap_months") or [])[:13] if isinstance(m, dict)]
    clock = {
        "certs": {"have": have["certificate"], "expired": cert.get("expired", 0), "due30": cert.get("due30", 0),
                  "due90": cert.get("due90", 0), "months": months},
        "eol": {"have": have["eol"], "median_years": eolm.get("median_years_past"),
                "max_years": eolm.get("max_years_past"), "products_5y": eolm.get("products_5y")},
        "pq": {"have": have["postquantum"], "past2030_assets": pq.get("past2030_assets"), "harvest_5y": pq.get("harvest_5y")},
        "kev_dates": [{"kev_date": d.get("kev_date"), "assets": d.get("assets"), "findings": d.get("findings")}
                      for d in (kev_r.get("dates") or [])[:12] if isinstance(d, dict)],
        "kev_have": have["cisakev"],
        "sla": {"have": have["sla"], "set": bool(g(sla, "readiness", "sla_set", default=False)),
                "breached": g(sla, "metrics", "totals", "breached")},
    }

    # ---- blind spots
    def step(label, n, agent, gap, gap_label, sec=""):
        if not have.get(agent):
            return {"label": label, "n": None, "agent": agent, "gap": None, "gap_label": "not in this release",
                    "href": _P(agent, sec), "codename": _name(agent)}
        return {"label": label, "n": n, "agent": agent, "gap": gap, "gap_label": gap_label, "href": _P(agent, sec),
                "codename": _name(agent)}
    funnel = [
        step("Seen by a hound", max(0, total - fk.get("no_signal", 0)), "fused_score", fk.get("no_signal", 0), "truly dark", "sec-lb"),
        step("Credentialed scan OK", cred_ok, "scan_eval", max(0, total - cred_ok), "uncredentialed or failed", "secAssets"),
        step("Classified", cl.get("classified", 0), "classify", cl.get("unclassified", 0), "type unknown"),
        step("Owned (any surface)", max(0, total - own.get("unclaimed", 0)), "asset_ownership", own.get("unclaimed", 0), "unclaimed"),
        step("Software inventory", min(sw_inv, total) if total else sw_inv, "software", max(0, total - sw_inv), "no inventory", "swCard"),
    ]

    def tile(label, n, agent, sec="", note=None):
        return {"label": label, "n": n if have.get(agent) else None, "agent": agent, "href": _P(agent, sec),
                "codename": _name(agent), "note": note if have.get(agent) else "not in this release"}
    tiles = [
        tile("Scans stale > 30 d", se.get("stale_30"), "scan_eval", "secAssets"),
        tile("Crown jewels blind (ACR ≥ 7)", se.get("crown_blind"), "scan_eval", "secAssets"),
        tile("Identity hosts uncredentialed", idm.get("blind"), "identity", "secCov"),
        tile("Shadow AI destinations", ai.get("shadow_dests"), "ai", "secEgress"),
        tile("Unnamed custom apps", capp.get("unnamed"), "customapp", "secCand"),
        tile("WAS apps", was.get("apps") if was.get("available") else None, "was", "",
             None if was.get("available") else (was.get("reason") or "no WAS data")),
    ]
    blind = {"assets": total, "funnel": funnel, "tiles": tiles}

    # ---- next moves (ranked: crit first, then by n; n=0 dropped)
    act = g(fk, "act", "40", default={}) or {}
    fix = (ap_r.get("fixes") or [{}])[0] or {}
    eolp = (g(eol_r, "view", "products", default=[]) or [{}])[0] or {}
    mp = expr.get("map") or {}
    champ = mp.get("champion") or {}

    def nx(agent, verb, n, unit, detail, href, sev):
        return {"agent": agent, "verb": verb, "n": n, "unit": unit, "detail": detail, "href": href, "sev": sev,
                "codename": _name(agent), "icon": _icon(agent)}
    nxt = []
    if fk:
        nxt.append(nx("fused_score", "Act on the act-now set", act.get("n", 0), "assets ≥ 40",
                      "%d crown jewels (ACR ≥ 9) with KEV · %d blind" % (act.get("crown_kev", 0), act.get("blind", 0)),
                      _P("fused_score", "sec-act"), "crit"))
    if have["attackpath"] and fix:
        nxt.append(nx("attackpath", "Break the attack path", fix.get("cuts", 0), "fix",
                      "%s cuts %s%% of crown-jewel paths" % (fix.get("label", ""), fix.get("exposure_cut_pct", 0)),
                      _P("attackpath", "secFix"), "crit"))
    if champ.get("plugin_id"):
        nxt.append(nx("exproute", "Patch the champion plugin", champ.get("cve_count", 0), "CVEs in one fix",
                      champ.get("name", ""), "/web/vuln.html?plugin=%s" % champ.get("plugin_id"), "warn"))
    if have["eol"] and eolp.get("product"):
        nxt.append(nx("eol", "Replace the biggest EOL product", eolp.get("assets", 0), "assets",
                      "%s — %s years past EOL" % (eolp.get("product", ""), eolp.get("years_past", "?")),
                      _P("eol", "secProd"), "warn"))
    if have["asset_ownership"]:
        nxt.append(nx("asset_ownership", "Claim unowned crown jewels", own.get("crown_unclaimed", 0), "crown jewels (ACR ≥ 9)",
                      "%s%% of the estate is unclaimed" % own.get("unclaimed_pct", 0), _P("asset_ownership"), "warn"))
    if have["scan_eval"]:
        nxt.append(nx("scan_eval", "Fix failing scan credentials", g(se, "status", "failed", default=0), "assets",
                      "credentialed OK on only %s%% of the estate" % (se.get("cred_ok_pct") or 0),
                      _P("scan_eval", "secAssets"), "warn"))
    if have["certificate"]:
        nxt.append(nx("certificate", "Renew certs due ≤ 30 days", cert.get("due30", 0), "certs",
                      "%s already expired on %s assets" % (cert.get("expired", 0), cert.get("expired_assets", 0)),
                      _P("certificate", "secCerts"), "warn"))
    nxt = [x for x in nxt if x["n"]]
    nxt.sort(key=lambda x: (0 if x["sev"] == "crit" else 1, -(x["n"] or 0)))
    nxt = nxt[:8]
    fun = mp.get("funnel") or {}
    reduction = {k: fun.get(k) for k in ("cves", "findings", "plugins", "routes", "paths")} if fun else {}
    if reduction:
        reduction["champion"] = {k: champ.get(k) for k in ("plugin_id", "name", "cve_count", "assets")} if champ else None

    # ---- the story sentence (every number links to its owner)
    story = []
    if fk:
        story += [{"t": "%s assets average " % format(total, ",")},
                  {"t": "%s / 100" % fk.get("avg", 0), "href": _P("fused_score", "sec-lb")}, {"t": " exposure. "}]
    if have["cisakev"] and not kevs.get("kev_assets"):
        story += [{"t": "None are KEV-exploitable", "href": _P("cisakev", "secCves")}, {"t": ". "}]
    elif have["cisakev"]:
        story += [{"t": "%s are KEV-exploitable" % format(kevs.get("kev_assets", 0), ","), "href": _P("cisakev", "secCves"),
                   "sev": "crit"}]
        if fk:
            story += [{"t": ", and "}, {"t": "%s crown jewels (ACR ≥ 9)" % fk.get("crown_kev", 0),
                                         "href": _P("fused_score", "sec-act"), "sev": "crit"}, {"t": " carry one. "}]
        else:
            story += [{"t": ". "}]
    if footprint and footprint[0]["n"]:
        f0 = footprint[0]
        story += [{"t": "The pack sees risk concentrated in "}, {"t": f0["label"].lower(), "href": f0["href"], "sev": "warn"},
                  {"t": " (%s assets)" % format(f0["n"], ",")}]
        story += [{"t": " — and "} if have["scan_eval"] else {"t": ". "}]
    if have["scan_eval"]:
        gap = max(0, total - cred_ok)
        story += [{"t": "%s assets" % format(gap, ","), "href": _P("scan_eval", "secAssets"), "sev": "warn"},
                  {"t": " aren't credential-scanned OK, so the real picture is likely worse." if gap else
                   " are credential-scanned OK."}]

    tot, pres, _st = _counts(cov)
    digest = {
        "ok": True, "fp": fp,
        "release": dict(_release_info(rec), db=_os.path.basename(_snapcache.db_file(db_path)), assets=total,
                        vuln_rows=(rec or {}).get("vuln_rows"), hounds_total=tot, hounds_present=pres,
                        built_sec=round(_time.time() - t0, 2), built_at=int(_time.time() * 1000)),
        "story": story, "glance": glance, "exposure": exposure, "footprint": footprint, "footprint_quiet": quiet,
        "worst": worst,
        "stack": stack, "cooccur": cooccur, "convergence": convergence, "clock": clock, "blind": blind,
        "next": nxt, "reduction": reduction, "coverage": cov,
        "_inputs": {"snaps": snap_pin, "release": (rec or {}).get("id")},
    }
    return digest


# ------------------------------------------------------------------ the API
def _job_running(db_path=None):
    try:
        return SCENT.state(db_path)["building"]
    except Exception:
        return None


def _release_running(rec):
    return bool(rec and rec.get("status") == "running")


def _present(digest, lv, db_path=None):
    """The stored digest with today's view of its inputs laid over it (cheap)."""
    rec = lv["rec"]
    cov = _coverage(lv["metas"], lv["snap_info"], rec, lv["cur"])
    bld = _job_running(db_path)
    running = _release_running(rec)
    tot, pres, st = _counts(cov)
    out = {k: v for k, v in (digest or {}).items() if k != "_inputs"}
    rel = dict(out.get("release") or {})
    if rec and rec.get("id") == rel.get("id"):
        rel.update(_release_info(rec))
    rel.update(hounds_total=tot, hounds_present=pres, sig_match=not st, stale=st)
    built = (digest or {}).get("release", {}).get("built_at") or 0
    changed = [{"agent": c["agent"], "label": c["label"], "href": c["href"],
                "by": "release" if c["status"] in ("fresh", "stale") else "you"} for c in cov
               if c.get("note") == "rebuilt since this summary"
               or (c.get("at") and c["at"] > built and c["status"] in ("fresh", "user", "stale"))]
    out.update(coverage=cov, release=rel, building=bld, running=running, changed=changed[:8],
               outdated=bool(digest) and digest.get("fp") != lv["fp"],
               state=_page_state(cov, running or bool(bld)))
    if running:
        out["progress"] = {"id": rec.get("id"), "items": [{"agent": i.get("agent"), "label": i.get("label"),
                                                           "status": i.get("status")} for i in rec.get("items") or []]}
    return out


def _none(lv, db_path=None):
    cov = _coverage(lv["metas"], lv["snap_info"], lv["rec"], lv["cur"])
    tot, pres, _st = _counts(cov)
    running = _release_running(lv["rec"])
    return {"ok": True, "state": "building" if running or _job_running(db_path) else "none",
            "building": _job_running(db_path), "running": running, "outdated": False,
            "cached_hounds": pres, "hounds_total": tot, "est_s": _hist_est(), "coverage": cov,
            "release": dict(_release_info(lv["rec"]), hounds_total=tot, hounds_present=pres)}


def scent(p, submit=None, db_path=None):
    """POST /api/insights/scent  {peek?, force?}. Reads caches only — never navi.db.
      peek:true   the stored digest (+ `outdated`) or {state:"none"}; never builds
      {}          the stored digest if its inputs are unchanged, else build it (inline when the
                  cached inputs are ≤ 4 MB gz, else on the job queue → {building:{job_id}})
      force:true  rebuild from the caches"""
    p = p or {}
    stored = _stored(db_path)
    lv = _live(db_path, stored)
    if p.get("peek"):
        return _present(stored, lv, db_path) if stored else _none(lv, db_path)
    if stored and not p.get("force") and stored.get("fp") == lv["fp"]:
        return dict(_present(stored, lv, db_path), cached=True)
    bld = _job_running(db_path)
    if bld:
        return dict(_present(stored, lv, db_path) if stored else _none(lv, db_path), building=bld)
    pages = {r["agent"] for r in _recipe_pages()}
    size = sum((m.get("size") or 0) for a, m in lv["metas"].items() if a in pages) + \
        sum((s or [0, 0])[1] for s in lv["stats"].values())
    if not any(a in pages for a in lv["metas"]) and not lv["refs"]:
        _scan = _scan_snaps(list(SNAP_AGENTS), db_path, lv["cur"])
        if not _scan:
            return _none(lv, db_path)               # nothing cached for this navi.db — nothing to summarise
    if size > INLINE_MAX_GZ and submit is not None:
        b = SCENT.start(submit, lambda: scent_digest(db_path), db_path=db_path, label="On the Scent")
        return dict(_present(stored, lv, db_path) if stored else _none(lv, db_path), building=b, state="building")
    SCENT.build(lambda: scent_digest(db_path), db_path=db_path)
    stored = _stored(db_path)
    return _present(stored, _live(db_path, stored), db_path)
