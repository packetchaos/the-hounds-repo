"""Heimdall — Post-Quantum Cipher Analysis tagging agent.

Tenable's Post-Quantum Cipher Analysis plugins identify where your estate still
leans on quantum-vulnerable cryptography (RSA / ECC) so you can prioritise the
migration to post-quantum ciphers:

  * 277650 — Remote Services NOT Using Post-Quantum Ciphers (the quantum-vulnerable surface)
  * 277652 — Target Cipher Inventory (every cipher/algorithm seen during the scan)
  * 277653 — Remote Services Using Post-Quantum Ciphers (your PQC-ready surface)

The agent tags the assets these plugins fired on, all under one tag —
``Post-Quantum : Cipher Analysis`` — via navi's tag-by-plugin-id.

Beyond the simple plugin tag, ``roadmap()`` correlates three quantum-risk
signals straight out of navi.db into a crown-jewel migration roadmap:

  * cert crypto   — the ``certs`` table: RSA / ECC / DSA signature algorithms are
                    broken by Shor's algorithm; long-lived broken certs are the
                    "harvest-now-decrypt-later" surface.
  * transport     — TLS/SSH plugins that flag classical-only key exchange, no PQ
                    cipher suites, SHA-1 MACs, or deprecated protocol versions.
  * crypto-agility — OpenSSH / OpenSSL versions (from vulns + software) tiered
                    PQC-ready / Upgradable / Legacy.

Each asset's crypto risk is weighted by its ACR and CISA-KEV status so the
highest-value, most-exposed assets rise to the top of the migration queue.
"""
import re
from datetime import datetime, timezone

from core import db, navi_cli
from core.agents.base import Agent

PLUGINS = [
    ("277650", "Remote Services NOT Using Post-Quantum Ciphers",
     "Services that do NOT offer post-quantum ciphers — the quantum-vulnerable surface (RSA/ECC) to modernise first."),
    ("277652", "Target Cipher Inventory",
     "Collects every cipher / algorithm discovered during the scan (machine-parsable JSON) for deeper analysis."),
    ("277653", "Remote Services Using Post-Quantum Ciphers",
     "Services that already offer post-quantum ciphers, enumerated — your PQC-ready surface."),
]
CATEGORY, VALUE = "Post-Quantum", "Cipher Analysis"
_IDS = [p[0] for p in PLUGINS]

# Quantum-vulnerable certificate signature algorithms (RSA / ECC / DSA / DH — all broken
# by Shor). Case-insensitive so it matches navi.db's human-readable form
# ("SHA-256 With RSA Encryption", "ECDSA With SHA-256", …). PQC families are excluded.
_VULN_CERT_WHERE = (
    "(upper(signature_algorithm) LIKE '%RSA%' OR upper(signature_algorithm) LIKE '%ECDSA%' "
    "OR upper(signature_algorithm) LIKE '%ECDH%' OR upper(signature_algorithm) LIKE '%ED25519%' "
    "OR upper(signature_algorithm) LIKE '%ED448%' OR upper(signature_algorithm) LIKE '%EDDSA%' "
    "OR upper(signature_algorithm) LIKE '%ELLIPTIC%' OR upper(signature_algorithm) LIKE '%DSA%' "
    "OR upper(signature_algorithm) LIKE '%DIFFIE%') "
    "AND upper(signature_algorithm) NOT LIKE '%ML-KEM%' AND upper(signature_algorithm) NOT LIKE '%ML-DSA%' "
    "AND upper(signature_algorithm) NOT LIKE '%SLH-DSA%' AND upper(signature_algorithm) NOT LIKE '%DILITHIUM%' "
    "AND upper(signature_algorithm) NOT LIKE '%KYBER%' AND upper(signature_algorithm) NOT LIKE '%FALCON%' "
    "AND upper(signature_algorithm) NOT LIKE '%SPHINCS%'")
_CERT_TAG_QUERY = "SELECT DISTINCT asset_uuid FROM certs WHERE " + _VULN_CERT_WHERE


def _uuid_set(sql, db_path=None) -> set:
    try:
        return {r.get("asset_uuid") for r in db.query(sql, path=db_path) if r.get("asset_uuid")}
    except Exception:
        return set()


def _has_table(name, db_path=None) -> bool:
    try:
        return bool(db.query("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
                             (name,), path=db_path))
    except Exception:
        return False


def discover(db_path=None) -> dict:
    """The quantum-vulnerable surface. Sources, in order of what tenants actually have:
      1. Certificates — RSA/ECC/DSA signature algorithms (broken by Shor). Present on almost
         every scan, so this is the reliable floor.
      2. Transport crypto — TLS/SSH classical-only KEX, SHA-1 MACs, deprecated TLS.
      3. Tenable's newer Post-Quantum Cipher Analysis plugins (277650/277652/277653) — only
         on tenants that have run them.
    The headline count is the UNION across all three, so 'Load' reflects real exposure even
    when the 277650 plugins aren't in the scan yet (the original blind spot)."""
    out, all_uuids = [], set()

    # 1. certificates (the reliable floor)
    cert_set = _uuid_set(_CERT_TAG_QUERY, db_path) if _has_table("certs", db_path) else set()
    if cert_set:
        out.append({"plugin_id": "certs", "plugin_name": "Quantum-vulnerable certificates (RSA / ECC / DSA)",
                    "role": "Certificate signature algorithms broken by Shor — key length is irrelevant. "
                            "The cert crypto to migrate first.", "assets": len(cert_set), "kind": "cert"})
        all_uuids |= cert_set

    # 2. transport crypto signals
    trans_set = set()
    for s in PQT_SIGNALS:
        trans_set |= _uuid_set(s["sql"], db_path)
    if trans_set:
        out.append({"plugin_id": "transport", "plugin_name": "Quantum-weak transport crypto (TLS / SSH)",
                    "role": "Classical-only key exchange, no PQ cipher suites, SHA-1 MACs or deprecated "
                            "TLS on the wire.", "assets": len(trans_set), "kind": "transport"})
        all_uuids |= trans_set

    # 3. the Tenable PQC plugins (present only where they've been run)
    for pid, name, role in PLUGINS:
        s = _uuid_set("SELECT DISTINCT asset_uuid FROM vulns WHERE plugin_id='" + pid + "'", db_path)
        out.append({"plugin_id": pid, "plugin_name": name, "role": role, "assets": len(s), "kind": "plugin"})
        if pid == "277650":   # 277652 is inventory, 277653 = USING PQ ciphers — neither is exposure
            all_uuids |= s

    plugin_assets = _uuid_set("SELECT DISTINCT asset_uuid FROM vulns WHERE plugin_id IN ('"
                              + "','".join(_IDS) + "')", db_path)
    note = ("" if plugin_assets else
            "Tenable's Post-Quantum Cipher Analysis plugins (277650/277652/277653) aren't in this "
            "navi.db yet — so exposure is derived from certificate + transport crypto instead. Run "
            "those plugins in a scan for the richest signal.")
    return {"plugins": out, "assets": len(all_uuids),
            "cert_assets": len(cert_set), "transport_assets": len(trans_set),
            "pqc_plugin_assets": len(plugin_assets), "note": note}


def tag_all() -> list:
    """Tag the quantum-vulnerable surface under Post-Quantum:Cipher Analysis — the cert set
    (via query) AND each PQC plugin (harmless no-op where a plugin has no assets)."""
    jobs = []
    if _has_table("certs"):
        cert_set = _uuid_set(_CERT_TAG_QUERY)
        if cert_set:
            jobs.append({"source": "certs",
                         **navi_cli.tag(CATEGORY, VALUE, query=_CERT_TAG_QUERY, remove=False, agent="postquantum")})
    jobs += [{"plugin_id": pid, **navi_cli.tag(CATEGORY, VALUE, plugin=pid, remove=False, agent="postquantum")}
             for pid, _n, _r in PLUGINS
             if (db.scalar("SELECT COUNT(*) FROM vulns WHERE plugin_id=?", (pid,)) or 0)]
    return jobs


# ---------------------------------------------------------------------------
# Crown-jewel crypto correlation + migration roadmap
# (repo-native port of the live console's pqc / pqt / pqr analysis)
# ---------------------------------------------------------------------------

ROADMAP_CAT = "PQC Priority"

# TLS/SSH transport-crypto signals — same set the live console reads.
PQT_SIGNALS = [
    {"key": "TLS no post-quantum ciphers", "sev": "high",
     "note": "Tenable flags the TLS service offers no PQ cipher suites (plugin 277650)",
     "sql": "SELECT DISTINCT asset_uuid FROM vulns WHERE plugin_id='277650'"},
    {"key": "TLS classical-only key exchange", "sev": "high",
     "note": "TLS supported groups are all classical ECDH/DH — broken by Shor (plugin 277654, no ML-KEM/Kyber group)",
     "sql": ("SELECT DISTINCT asset_uuid FROM vulns WHERE plugin_id='277654' "
             "AND lower(output) NOT LIKE '%mlkem%' AND lower(output) NOT LIKE '%kyber%' "
             "AND lower(output) NOT LIKE '%sntrup%'")},
    {"key": "SSH classical-only key exchange", "sev": "high",
     "note": "SSH offers no PQ hybrid KEX (sntrup761x25519 / ML-KEM) — plugin 70657",
     "sql": ("SELECT DISTINCT asset_uuid FROM vulns WHERE plugin_id='70657' "
             "AND lower(output) NOT LIKE '%sntrup%' AND lower(output) NOT LIKE '%mlkem%' "
             "AND lower(output) NOT LIKE '%kyber%'")},
    {"key": "SSH SHA-1 HMAC enabled", "sev": "med",
     "note": "Legacy SHA-1 MAC still enabled (plugin 153588 / hmac-sha1 in 70657)",
     "sql": ("SELECT DISTINCT asset_uuid FROM vulns WHERE plugin_id='153588' "
             "OR (plugin_id='70657' AND lower(output) LIKE '%hmac-sha1%')")},
    {"key": "TLS deprecated version (1.0/1.1)", "sev": "med",
     "note": "Deprecated TLS protocol still supported (plugin 56984)",
     "sql": ("SELECT DISTINCT asset_uuid FROM vulns WHERE plugin_id='56984' "
             "AND (output LIKE '%TLSv1.0%' OR output LIKE '%TLSv1.1%' "
             "OR output LIKE '%TLS 1.0%' OR output LIKE '%TLS 1.1%')")},
]

_MONTHS = {"jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6,
           "jul": 7, "aug": 8, "sep": 9, "oct": 10, "nov": 11, "dec": 12}


def _cols(table, db_path=None):
    try:
        return {r["name"] for r in db.query('PRAGMA table_info("%s");' % table, path=db_path)}
    except Exception:
        return set()


def pqc_classify(algo):
    """Classify a certificate signature algorithm as quantum-safe / broken."""
    s = str(algo or "").lower()
    if re.search(r"ml-kem|ml-dsa|slh-dsa|dilithium|kyber|sphincs|falcon|xmss|\blms\b|frodo|\bbike\b|\bhqc\b", s):
        return {"fam": "PQC", "verdict": "safe", "note": "NIST post-quantum algorithm — quantum-safe"}
    if re.search(r"ecdsa|ecdh|ed25519|ed448|eddsa|elliptic|(^|[^a-z])ec([^a-z]|$)", s):
        return {"fam": "ECC", "verdict": "broken", "note": "Elliptic-curve — broken by Shor's algorithm"}
    if "rsa" in s:
        return {"fam": "RSA", "verdict": "broken", "note": "RSA — broken by Shor's algorithm; key length is irrelevant post-quantum"}
    if re.search(r"(^|[^a-z])dsa([^a-z]|$)", s):
        return {"fam": "DSA", "verdict": "broken", "note": "DSA — broken by Shor's algorithm"}
    return {"fam": "Other", "verdict": "unknown", "note": "Unclassified signature — review manually"}


def pqc_expiry_years(not_valid_after):
    """Years-until-expiry from an OpenSSL-style 'Mon DD HH:MM:SS YYYY' string."""
    m = re.search(r"([A-Za-z]{3})\s+(\d{1,2})\s+[\d:]+\s+(\d{4})", str(not_valid_after or ""))
    if not m:
        return None
    mo = _MONTHS.get(m.group(1).lower())
    if not mo:
        return None
    try:
        dt = datetime(int(m.group(3)), mo, int(m.group(2)), tzinfo=timezone.utc)
    except ValueError:
        return None
    return (dt - datetime.now(timezone.utc)).total_seconds() / 31557600.0


def _ssh_ver(o):
    m = re.search(r"OpenSSH[_/ ]?(\d+)\.(\d+)", str(o or ""), re.I)
    return {"maj": int(m.group(1)), "min": int(m.group(2)),
            "str": "OpenSSH %s.%s" % (m.group(1), m.group(2))} if m else None


def _ssl_ver(o):
    best = None
    for mm in re.finditer(r"(?:openssl[^0-9]{0,6}|version\s*:\s*)(\d+)\.(\d+)\.(\d+)", str(o or ""), re.I):
        v = {"maj": int(mm.group(1)), "min": int(mm.group(2)), "pat": int(mm.group(3))}
        if best is None or v["maj"] > best["maj"] or (v["maj"] == best["maj"] and v["min"] > best["min"]):
            best = v
    if best:
        best["str"] = "OpenSSL %d.%d.%d" % (best["maj"], best["min"], best["pat"])
    return best


def _ag_tier(ssh, ssl):
    ready = (ssh and ssh["maj"] >= 9) or (ssl and (ssl["maj"] > 3 or (ssl["maj"] == 3 and ssl["min"] >= 2)))
    if ready:
        return "PQC-ready"
    upg = (ssh and ssh["maj"] == 8 and ssh["min"] >= 5) or (ssl and ssl["maj"] == 3)
    if upg:
        return "Upgradable"
    if ssh or ssl:
        return "Legacy"
    return None


def _uuids_in(s):
    return re.findall(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", str(s or ""))


def _rows(sql, db_path=None):
    try:
        return list(db.query(sql, path=db_path))
    except Exception:
        return []


def _amap(db_path=None):
    """asset_uuid -> {host, ip, acr, url}."""
    acols = _cols("assets", db_path)
    sel = ["uuid", "hostname", "ip_address", "acr"] + (["url"] if "url" in acols else [])
    out = {}
    for a in _rows("SELECT " + ",".join(sel) + " FROM assets", db_path):
        u = a.get("uuid")
        if not u:
            continue
        try:
            acr = float(str(a.get("acr") or "").strip() or 0)
        except ValueError:
            acr = 0.0
        out[u] = {"host": (a.get("hostname") or a.get("ip_address") or "").strip() or "(none)",
                  "ip": a.get("ip_address") or "", "acr": acr, "url": a.get("url") or ""}
    return out


# ---- #1 certificate crypto inventory + #2 harvest-now hit-list --------------
CERT_CAT = "PQC Risk"
HARVEST_CAT = "PQC Harvest-Now"


def cert_analysis(db_path=None) -> dict:
    """Classify every cert signature algorithm by quantum risk, group into an algorithm
    inventory, and rank the harvest-now-decrypt-later hit-list (long-lived broken certs on
    high-ACR assets). Read-only."""
    if not _rows("SELECT 1 FROM certs LIMIT 1", db_path):
        return {"ok": True, "inventory": [], "harvest_now": [],
                "kpi": {"certs": 0, "vulnerable": 0, "safe": 0, "assets": 0, "harvest_now": 0},
                "note": "No certs table / rows in navi.db — run a scan that collects certificates."}
    amap = _amap(db_path)
    ccols = _cols("certs", db_path)
    sel = ["asset_uuid", "signature_algorithm", "not_valid_after"]
    for c in ("key_length", "common_name"):
        if c in ccols:
            sel.append(c)
    rows = _rows("SELECT " + ", ".join(sel) + " FROM certs", db_path)
    inv, harvest = {}, []
    total_certs, safe_certs, vuln_assets = 0, 0, set()
    for c in rows:
        total_certs += 1
        algo = c.get("signature_algorithm") or "(unknown)"
        cls = pqc_classify(algo)
        u = c.get("asset_uuid")
        I = inv.setdefault(algo, {"algo": algo, "fam": cls["fam"], "verdict": cls["verdict"],
                                  "note": cls["note"], "keys": set(), "certs": 0, "assets": set()})
        I["certs"] += 1
        if c.get("key_length"):
            I["keys"].add(str(c.get("key_length")))
        if u:
            I["assets"].add(u)
        if cls["verdict"] == "safe":
            safe_certs += 1
        elif cls["verdict"] == "broken" and u:
            vuln_assets.add(u)
            yrs = pqc_expiry_years(c.get("not_valid_after"))
            if yrs and yrs > 0:
                a = amap.get(u, {})
                harvest.append({"uuid": u, "host": a.get("host", "(none)"), "ip": a.get("ip", ""),
                                "url": a.get("url", ""), "cn": c.get("common_name") or "",
                                "algo": algo, "fam": cls["fam"], "key": c.get("key_length") or "",
                                "expiry": c.get("not_valid_after") or "", "years": round(yrs, 1),
                                "exp_year": int(re.search(r"(\d{4})", str(c.get("not_valid_after"))).group(1))
                                            if re.search(r"(\d{4})", str(c.get("not_valid_after") or "")) else None,
                                "acr": a.get("acr", 0.0),
                                "urgency": round(yrs * max(a.get("acr", 0.0), 1))})
    inventory = []
    _vord = {"broken": 0, "unknown": 1, "safe": 2}
    for algo, I in inv.items():
        inventory.append({"algo": I["algo"], "fam": I["fam"], "verdict": I["verdict"], "note": I["note"],
                          "keys": sorted(I["keys"]), "certs": I["certs"], "assets": len(I["assets"]),
                          "uuids": sorted(I["assets"])})
    inventory.sort(key=lambda x: (_vord.get(x["verdict"], 9), -x["certs"]))
    harvest.sort(key=lambda h: -h["urgency"])
    return {"ok": True, "inventory": inventory, "harvest_now": harvest,
            "kpi": {"certs": total_certs, "vulnerable": len(vuln_assets), "safe": safe_certs,
                    "assets": len(amap), "harvest_now": len(harvest)}}


# ---- #3 transport signals + #4 crypto-agility -------------------------------
TRANSPORT_CAT = "PQC Transport"
AGILITY_CAT = "PQC Agility"


def transport_analysis(db_path=None) -> dict:
    """The on-the-wire quantum-weak transport signals (TLS/SSH KEX, SHA-1 MAC, deprecated
    TLS) + per-host crypto-agility tier from OpenSSH/OpenSSL versions. Read-only."""
    amap = _amap(db_path)
    signals = []
    for s in PQT_SIGNALS:
        uu = sorted({r.get("asset_uuid") for r in _rows(s["sql"], db_path) if r.get("asset_uuid")})
        signals.append({"key": s["key"], "sev": s["sev"], "note": s["note"],
                        "assets": len(uu), "uuids": uu})
    # crypto-agility from OpenSSH (10267/181418) + OpenSSL (168149) versions
    ag = {}
    for r in _rows("SELECT asset_uuid, output FROM vulns WHERE plugin_id IN ('10267','181418')", db_path):
        u, v = r.get("asset_uuid"), _ssh_ver(r.get("output"))
        if u and v:
            a = ag.setdefault(u, {})
            if not a.get("ssh") or v["maj"] > a["ssh"]["maj"] or (v["maj"] == a["ssh"]["maj"] and v["min"] > a["ssh"]["min"]):
                a["ssh"] = v
    for r in _rows("SELECT asset_uuid, output FROM vulns WHERE plugin_id='168149'", db_path):
        u, v = r.get("asset_uuid"), _ssl_ver(r.get("output"))
        if u and v:
            a = ag.setdefault(u, {})
            if not a.get("ssl") or v["maj"] > a["ssl"]["maj"] or (v["maj"] == a["ssl"]["maj"] and v["min"] > a["ssl"]["min"]):
                a["ssl"] = v
    if "software_string" in _cols("software", db_path):
        for r in _rows("SELECT asset_uuid, software_string FROM software "
                       "WHERE lower(software_string) LIKE '%openssl%'", db_path):
            v = _ssl_ver(r.get("software_string"))
            if not v:
                continue
            for u in (_uuids_in(r.get("asset_uuid")) or ([r["asset_uuid"]] if r.get("asset_uuid") else [])):
                a = ag.setdefault(u, {})
                if not a.get("ssl") or v["maj"] > a["ssl"]["maj"] or (v["maj"] == a["ssl"]["maj"] and v["min"] > a["ssl"]["min"]):
                    a["ssl"] = v
    hosts, tiers = [], {"PQC-ready": 0, "Upgradable": 0, "Legacy": 0}
    for u, a in ag.items():
        tier = _ag_tier(a.get("ssh"), a.get("ssl"))
        if not tier:
            continue
        tiers[tier] = tiers.get(tier, 0) + 1
        m = amap.get(u, {})
        hosts.append({"uuid": u, "host": m.get("host", "(none)"), "url": m.get("url", ""),
                      "ssh": (a.get("ssh") or {}).get("str", ""), "ssl": (a.get("ssl") or {}).get("str", ""),
                      "tier": tier})
    _tord = {"Legacy": 0, "Upgradable": 1, "PQC-ready": 2}
    hosts.sort(key=lambda h: (_tord.get(h["tier"], 9), h["host"]))
    high = sum(s["assets"] for s in signals if s["sev"] == "high")
    return {"ok": True, "signals": signals, "agility": {"tiers": tiers, "hosts": hosts},
            "kpi": {"signals": sum(1 for s in signals if s["assets"]),
                    "high_assets": high, "legacy": tiers.get("Legacy", 0),
                    "ready": tiers.get("PQC-ready", 0)}}


def _years_until(year):
    return (datetime(year, 1, 1, tzinfo=timezone.utc) - datetime.now(timezone.utc)).total_seconds() / 31557600.0


# CNSA 2.0 milestones the lifetime view lines certificates up against
CNSA = [(2027, "PQC preferred for software / firmware signing"),
        (2030, "PQC required for signing; hybrid / PQ key exchange by default"),
        (2033, "CNSA 2.0 exclusive — classical RSA / ECC deprecated")]


def overview(db_path=None) -> dict:
    """One pass for the page: the surface (discover), certificate crypto, transport +
    agility, the roadmap, and the headline metrics that tie them together. Read-only."""
    surf = discover(db_path)
    cert = cert_analysis(db_path)
    trans = transport_analysis(db_path)
    road = roadmap(db_path)
    amap = _amap(db_path)
    total = len(amap)

    fam = {}
    broken_certs = 0
    for r in cert.get("inventory", []):
        f = fam.setdefault(r["fam"], {"fam": r["fam"], "verdict": r["verdict"], "certs": 0, "assets": set()})
        f["certs"] += r["certs"]
        f["assets"] |= set(r.get("uuids") or [])
        if r["verdict"] == "broken":
            broken_certs += r["certs"]
    families = sorted(({**f, "assets": len(f["assets"])} for f in fam.values()),
                      key=lambda f: ({"broken": 0, "unknown": 1, "safe": 2}.get(f["verdict"], 9), -f["certs"]))
    safe_cert_assets = set().union(*[set(r.get("uuids") or []) for r in cert.get("inventory", [])
                                     if r["verdict"] == "safe"]) if cert.get("inventory") else set()

    # broken certs still valid at each CNSA 2.0 milestone
    hn = cert.get("harvest_now", [])
    this_year = datetime.now(timezone.utc).year
    life = [{"key": "expired", "label": "Already expired", "certs": broken_certs - len(hn), "assets": None}]
    edges = [(None, 2027, f"Expire in {this_year}" if this_year == 2026 else "Expire before 2027"),
             (2027, 2030, "Expire 2027–2029"), (2030, 2033, "Expire 2030–2032"), (2033, None, "Valid into 2033+")]
    for lo, hi, label in edges:
        rows = [h for h in hn if h.get("exp_year") and (lo is None or h["exp_year"] >= lo) and (hi is None or h["exp_year"] < hi)]
        life.append({"key": f"{lo or ''}-{hi or ''}", "label": label, "certs": len(rows),
                     "assets": len({h["uuid"] for h in rows})})
    past = lambda y: [h for h in hn if h.get("exp_year") and h["exp_year"] >= y]

    plugin_ready = _uuid_set("SELECT DISTINCT asset_uuid FROM vulns WHERE plugin_id='277653'", db_path)
    ag = trans.get("agility", {})
    ready_stack = {h["uuid"] for h in ag.get("hosts", []) if h["tier"] == "PQC-ready"}
    sig = {s["key"]: s for s in trans.get("signals", [])}
    kex = set(sig.get("TLS classical-only key exchange", {}).get("uuids", [])) | \
        set(sig.get("SSH classical-only key exchange", {}).get("uuids", [])) | \
        set(sig.get("TLS no post-quantum ciphers", {}).get("uuids", []))
    rows = road.get("rows", [])
    m = {
        "assets_total": total,
        "exposed": surf.get("assets", 0),
        "exposed_pct": round(100.0 * surf.get("assets", 0) / total, 1) if total else None,
        "cert_assets": surf.get("cert_assets", 0), "transport_assets": surf.get("transport_assets", 0),
        "pqc_plugin_assets": surf.get("pqc_plugin_assets", 0),
        "ready_assets": len(plugin_ready | ready_stack | safe_cert_assets),
        "ready_plugin": len(plugin_ready), "ready_stack": len(ready_stack), "ready_cert": len(safe_cert_assets),
        "certs": cert.get("kpi", {}).get("certs", 0), "broken_certs": broken_certs,
        "broken_pct": round(100.0 * broken_certs / cert["kpi"]["certs"], 1) if cert.get("kpi", {}).get("certs") else None,
        "safe_certs": cert.get("kpi", {}).get("safe", 0),
        "harvest_5y": sum(1 for h in hn if h["years"] >= 5),
        "past2030_certs": len(past(2030)), "past2030_assets": len({h["uuid"] for h in past(2030)}),
        "past2033_certs": len(past(2033)), "past2033_assets": len({h["uuid"] for h in past(2033)}),
        "kex_assets": len(kex), "kex_uuids": sorted(kex),
        "weak_assets": len(set(sig.get("SSH SHA-1 HMAC enabled", {}).get("uuids", [])) |
                           set(sig.get("TLS deprecated version (1.0/1.1)", {}).get("uuids", []))),
        "sha1_assets": sig.get("SSH SHA-1 HMAC enabled", {}).get("assets", 0),
        "oldtls_assets": sig.get("TLS deprecated version (1.0/1.1)", {}).get("assets", 0),
        "legacy": ag.get("tiers", {}).get("Legacy", 0), "upgradable": ag.get("tiers", {}).get("Upgradable", 0),
        "ready": ag.get("tiers", {}).get("PQC-ready", 0),
        "crown": sum(1 for p in rows if p["acr"] >= 7),
        "crown_past2030": sum(1 for p in rows if p["acr"] >= 7 and p.get("past2030")),
        "kev": sum(1 for p in rows if p["kev"]),
        "legacy_crown": sum(1 for p in rows if p["acr"] >= 7 and p["agility"] == "Legacy"),
        "top_score": rows[0]["score"] if rows else None,
    }
    return {"ok": True, "surface": surf, "cert": cert, "transport": trans, "roadmap": road,
            "families": families, "lifetime": life, "cnsa": [{"year": y, "milestone": t} for y, t in CNSA],
            "metrics": m}


def roadmap(db_path=None) -> dict:
    """Correlate cert crypto + transport + agility, weighted by ACR + KEV, into a
    ranked crown-jewel migration roadmap. Pure read from navi.db."""
    acols = _cols("assets", db_path)
    sel = ["uuid", "hostname", "ip_address", "acr"]
    if "url" in acols:
        sel.append("url")
    amap = {}
    for a in _rows("SELECT " + ",".join(sel) + " FROM assets", db_path):
        u = a.get("uuid")
        if not u:
            continue
        try:
            acr = float(str(a.get("acr") or "").strip() or 0)
        except ValueError:
            acr = 0.0
        amap[u] = {"host": (a.get("hostname") or a.get("ip_address") or "").strip() or "(none)",
                   "ip": a.get("ip_address") or "", "acr": acr, "url": a.get("url") or ""}

    kev = {r["asset_uuid"] for r in _rows(
        "SELECT DISTINCT asset_uuid FROM vulns WHERE xrefs LIKE '%CISA-KNOWN-EXPLOITED%'", db_path)
        if r.get("asset_uuid")}

    def _mk(u):
        a = amap.get(u, {})
        return {"uuid": u, "host": a.get("host", "(none)"), "ip": a.get("ip", ""),
                "acr": a.get("acr", 0.0), "url": a.get("url", ""),
                "algos": set(), "brokenCerts": 0, "maxYears": 0.0,
                "transport": [], "transportHigh": 0, "agility": "", "kev": u in kev}

    prof = {}

    # --- cert crypto -------------------------------------------------------
    inv, safe_certs, total_certs = {}, 0, 0
    if "certs" in _cols("certs", db_path) or _rows("SELECT 1 FROM certs LIMIT 1", db_path):
        for c in _rows("SELECT c.asset_uuid, c.signature_algorithm, c.not_valid_after "
                       "FROM certs c", db_path):
            u = c.get("asset_uuid")
            total_certs += 1
            cls = pqc_classify(c.get("signature_algorithm"))
            algo = c.get("signature_algorithm") or "(unknown)"
            I = inv.setdefault(algo, {"algo": algo, "cls": cls, "certs": 0, "assets": set()})
            I["certs"] += 1
            if u:
                I["assets"].add(u)
            if cls["verdict"] == "safe":
                safe_certs += 1
            if cls["verdict"] == "broken" and u:
                p = prof.setdefault(u, _mk(u))
                p["brokenCerts"] += 1
                p["algos"].add(cls["fam"])
                yrs = pqc_expiry_years(c.get("not_valid_after"))
                if yrs and yrs > p["maxYears"]:
                    p["maxYears"] = yrs

    # --- transport signals -------------------------------------------------
    for s in PQT_SIGNALS:
        for r in _rows(s["sql"], db_path):
            u = r.get("asset_uuid")
            if not u:
                continue
            p = prof.setdefault(u, _mk(u))
            p["transport"].append(s["key"])
            if s["sev"] == "high":
                p["transportHigh"] += 1

    # --- crypto-agility (OpenSSH / OpenSSL) --------------------------------
    ag = {}
    for r in _rows("SELECT asset_uuid, output FROM vulns WHERE plugin_id IN ('10267','181418')", db_path):
        u = r.get("asset_uuid")
        v = _ssh_ver(r.get("output"))
        if u and v:
            a = ag.setdefault(u, {})
            if not a.get("ssh") or v["maj"] > a["ssh"]["maj"] or (v["maj"] == a["ssh"]["maj"] and v["min"] > a["ssh"]["min"]):
                a["ssh"] = v
    for r in _rows("SELECT asset_uuid, output FROM vulns WHERE plugin_id='168149'", db_path):
        u = r.get("asset_uuid")
        v = _ssl_ver(r.get("output"))
        if u and v:
            a = ag.setdefault(u, {})
            if not a.get("ssl") or v["maj"] > a["ssl"]["maj"] or (v["maj"] == a["ssl"]["maj"] and v["min"] > a["ssl"]["min"]):
                a["ssl"] = v
    if "software_string" in _cols("software", db_path):
        for r in _rows("SELECT asset_uuid, software_string FROM software "
                       "WHERE lower(software_string) LIKE '%openssl%'", db_path):
            v = _ssl_ver(r.get("software_string"))
            if not v:
                continue
            for u in (_uuids_in(r.get("asset_uuid")) or ([r["asset_uuid"]] if r.get("asset_uuid") else [])):
                a = ag.setdefault(u, {})
                if not a.get("ssl") or v["maj"] > a["ssl"]["maj"] or (v["maj"] == a["ssl"]["maj"] and v["min"] > a["ssl"]["min"]):
                    a["ssl"] = v
    for u, a in ag.items():
        tier = _ag_tier(a.get("ssh"), a.get("ssl"))
        if tier:
            prof.setdefault(u, _mk(u))["agility"] = tier

    # --- correlate + score -------------------------------------------------
    rows = []
    for u, p in prof.items():
        p["algoList"] = sorted(p["algos"])
        p["score"] = round(p["acr"] * 2 + p["brokenCerts"] + p["maxYears"] / 5
                           + p["transportHigh"] * 2 + len(p["transport"])
                           + (3 if p["agility"] == "Legacy" else 0) + (4 if p["kev"] else 0))
        if p["brokenCerts"] or p["transport"] or p["agility"] == "Legacy":
            p.pop("algos", None)
            p["past2030"] = p["maxYears"] >= _years_until(2030)
            p["past2033"] = p["maxYears"] >= _years_until(2033)
            p["maxYears"] = round(p["maxYears"], 1)
            rows.append(p)
    rows.sort(key=lambda p: p["score"], reverse=True)

    cj = [p for p in rows if p["acr"] >= 7]
    hn = [p for p in cj if p["maxYears"] >= 5]
    leg = [p for p in rows if p["agility"] == "Legacy" and p["acr"] >= 7]
    kv = [p for p in rows if p["kev"]]

    return {"ok": True, "rows": rows,
            "kpi": {"exposed": len(rows), "crown_jewels": len(cj),
                    "harvest_now": len(hn), "legacy_cj": len(leg), "kev": len(kv)},
            "certs": {"total": total_certs, "safe": safe_certs}}


class PostQuantumAgent(Agent):
    id = "postquantum"
    name = "Post-Quantum Cipher Analysis"
    icon = "⚛️"
    description = ("Heimdall — finds assets in Tenable's Post-Quantum Cipher Analysis "
                  "plugins (277650 / 277652 / 277653) and tags them Post-Quantum:Cipher Analysis.")

    def summary(self):
        return {"assets": self.result.get("assets")} if self.result else {}

    def _run(self, db_path=None, **kwargs):
        d = discover(db_path)
        d["ok"] = True
        return d
