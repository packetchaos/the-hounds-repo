"""'Bet you didn't know this' — aggregate the unknown-unknowns from navi.db.

Cheap, resilient roll-up used by the insights landing page: certificates failing
soon, assets with no software inventory, IoT devices, identities, MITRE techniques
on high-ACR assets, and custom apps. Each figure links to the agent that owns it.
"""
import datetime
import re

from core import db, signals
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
    try:
        for r in db.query("SELECT not_valid_after FROM certs", path=db_path):
            d = _date(r.get("not_valid_after"))
            if not d:
                continue
            if today <= d <= end:
                certs += 1
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
        from core import mitre
        rows, _ = mitre.fetch_mapping()           # live → bundled snapshot fallback
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
    owned = sc("SELECT COUNT(DISTINCT asset_uuid) FROM tags WHERE tag_key='Owner'")
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
                      "plugins": int(x.get("plugins") or 0), "routes": int(x.get("routes") or 0)}
        cr = rows("WITH present AS (SELECT DISTINCT plugin_id FROM vulns) SELECT p.name nm,"
                  "(length(p.cves)-length(replace(p.cves,'CVE-','')))/4 n,"
                  "(SELECT COUNT(DISTINCT asset_uuid) FROM vulns v WHERE v.plugin_id=p.plugin_id) a "
                  "FROM plugins p JOIN present ON present.plugin_id=p.plugin_id "
                  "WHERE p.cves IS NOT NULL AND p.cves NOT IN ('','[]','None') ORDER BY n DESC LIMIT 1")
        if cr:
            x = cr[0]
            champion = {"name": x.get("nm"), "cve_count": int(x.get("n") or 0), "assets": int(x.get("a") or 0)}
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

    def cnt(pred):
        return sum(1 for r in rows if pred(r))

    def _hound_silent(r):
        # the pack found NOTHING on it — no KEV and no hound-derived factor fired
        f = r.get("factors", {})
        return (not r.get("kev")) and all(not f.get(k) for k in ("path", "ident", "ai", "eol", "cry", "mit"))

    kev = cnt(lambda r: r.get("kev"))
    crown = cnt(lambda r: r.get("crown"))
    eol = cnt(lambda r: r.get("eol"))
    crypto = cnt(lambda r: r.get("crypto"))
    path = cnt(lambda r: r.get("path"))
    ident = cnt(lambda r: r.get("ident"))
    ai = cnt(lambda r: r.get("ai"))
    exposed = cnt(lambda r: r.get("exposed"))
    unowned = cnt(lambda r: r.get("unowned"))
    blind = cnt(lambda r: r.get("blind"))
    no_signal = cnt(_hound_silent)

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
             f"{cnt(lambda r: r.get('crown') and r.get('unowned'))} unowned", "warn" if crown else "off",
             "/agents/acr/page.html"),
        tile("cert", "Certificates", "Certania", "🔐", c.get("certs_failing", 0),
             f"{c.get('certs_expired', 0)} already expired", "warn" if c.get("certs_failing") else "ok",
             "/agents/certificate/page.html"),
        tile("eol", "EOL / crypto decay", "Charon+Heimdall", "🔩", eol + crypto,
             f"{eol} EOL · {crypto} weak crypto", "warn" if (eol + crypto) else "ok",
             "/agents/eol/page.html"),
        tile("ident", "Identity exposure", "Janus", "🪪", ident, "NHI / credential reuse",
             "warn" if ident else "off", "/agents/identity/page.html"),
        tile("path", "Attack paths", "Fenrir", "🕸", path, "foothold → crown jewel",
             "crit" if path else "off", "/agents/attackpath/page.html"),
        tile("ai", "AI exposure", "Pythia", "🧠", ai, f"{cnt(lambda r: r.get('ai') == 'shadow')} shadow",
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
        if co.get("available") and co.get("assets_total"):
            fails = co.get("assets_failing", co.get("failing", 0))
            posture.append(tile("compliance", "Compliance", "Minos", "⚖️",
                                 f"{co.get('pass_pct', co.get('compliant_pct', 0))}%",
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
            posture.append(tile("was", "Web apps (WAS)", "Xolotl", "🕸️", wo.get("findings", wo.get("apps", 0)),
                                 f"{wo.get('apps', 0)} apps", "warn", "/agents/was/page.html"))
        else:
            posture.append(tile("was", "Web apps (WAS)", "Xolotl", "🕸️", "—", "no WAS data yet", "off", "/agents/was/page.html"))
    except Exception:
        pass

    # ---- blind spots — the dark matter Sphinx is named for (risk by ABSENCE) ----
    unclassified = _sc("SELECT COUNT(uuid) FROM assets WHERE uuid NOT IN "
                       "(SELECT DISTINCT asset_uuid FROM tags WHERE tag_key='Class')", db_path)
    no_tier = _sc("SELECT COUNT(uuid) FROM assets WHERE uuid NOT IN "
                  "(SELECT DISTINCT asset_uuid FROM tags WHERE tag_key='Business Tier')", db_path)
    blind_spots = [
        {"label": "No Hound signal", "count": no_signal, "sub": "the pack found nothing — truly dark", "sev": "crit"},
        {"label": "Uncredentialed / blind", "count": blind, "sub": "Chronos — scan can't see inside", "sev": "crit"},
        {"label": "Unclassified", "count": unclassified, "sub": "Linnaeus — type unknown", "sev": "warn"},
        {"label": "Unowned", "count": unowned, "sub": "Terminus — nobody accountable", "sev": "warn"},
        {"label": "No business tier", "count": no_tier, "sub": "criticality unrated", "sev": "warn"},
        {"label": "Shadow AI", "count": cnt(lambda r: r.get("ai") == "shadow"), "sub": "Pythia — AI off the sanctioned list", "sev": "warn"},
    ]

    # ---- convergence — the cross-Hound surprises no single agent sees ----
    def conv(text, n, sev):
        return {"text": text, "count": n, "sev": sev, "href": "/agents/fused_score/page.html"}
    convergence = [c for c in [
        conv("crown jewels with no owner", cnt(lambda r: r.get("crown") and r.get("unowned")), "crit"),
        conv("crown jewels the scan can't see (blind)", cnt(lambda r: r.get("crown") and r.get("blind")), "crit"),
        conv("KEV-exploitable assets nobody owns", cnt(lambda r: r.get("kev") and r.get("unowned")), "crit"),
        conv("KEV-exploitable AND internet-exposed", cnt(lambda r: r.get("kev") and r.get("exposed")), "crit"),
        conv("EOL software on a crown jewel", cnt(lambda r: r.get("eol") and r.get("crown")), "warn"),
        conv("attack-path targets nobody owns", cnt(lambda r: r.get("path") == "target" and r.get("unowned")), "warn"),
        conv("credential-reuse hosts that are KEV-exploitable", cnt(lambda r: r.get("ident", 0) >= 2 and r.get("kev")), "crit"),
    ] if c["count"] > 0]
    convergence.sort(key=lambda x: (-{"crit": 2, "warn": 1}.get(x["sev"], 0), -x["count"]))

    return {"ok": True, "asset_total": total,
            "nemesis": {"critical": crit_assets, "high": fk.get("high", 0),
                        "estate": fk.get("estate", 0), "avg": fk.get("avg", 0),
                        "top": [{"host": r["host"], "score": r["score"]} for r in rows[:5]]},
            "posture": posture, "blind": blind_spots, "convergence": convergence,
            "classic": c}
