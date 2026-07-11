"""Signal-fusion data — compute the six discovery lenses straight from navi.db.

Every figure traces to navi.db. Every figure here traces to a
read-only query against navi.db (the same DB navi syncs from Tenable). When a
lens's source plugins/tables aren't present the lens degrades gracefully to
empty rather than failing, so the dashboards always reflect *this* environment.

Shapes returned by compute_all() match exactly what the discovery-lens renderers
expect (IOT / CERTS / IDENTITY / SHADOW / ROUTES / PATHS).
"""
import re
from collections import defaultdict

from core import db

_MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
     "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}


def _q(sql, path, params=()):
    try:
        return db.query(sql, params, path=path)
    except Exception:
        return []


def _scalar(sql, path, params=()):
    try:
        return db.scalar(sql, params, path=path)
    except Exception:
        return None


# ----------------------------------------------------------------- 01 IoT
_DEVTYPE = re.compile(r"\b(embedded|hypervisor|switch|router|firewall|printer|"
                      r"webcam|general-purpose|unknown)\b", re.I)
_VIRTUAL = ("vmware", "virtual", "qemu", "xen", "microsoft corporation")
_VENDOR_CLASS = [
    ("network", ("ubiquiti", "netgear", "cisco", "tp-link", "mikrotik", "aruba")),
    ("sbc", ("raspberry",)),
    ("consumer", ("google", "samsung", "amazon", "apple", "aura", "sonos", "nest", "roku")),
    ("storage", ("buffalo", "synology", "qnap", "western digital")),
    ("ot", ("eac", "siemens", "rockwell", "schneider", "automation")),
    ("server", ("dell", "intel", "hewlett", "hpe", "supermicro", "lenovo")),
]


def _vendor_class(v):
    low = (v or "").lower()
    if any(k in low for k in _VIRTUAL):
        return "virtual"
    for cls, keys in _VENDOR_CLASS:
        if any(k in low for k in keys):
            return cls
    return "other"


def _iot(path):
    sig = [("54615", "Device Type"), ("86420", "Ethernet MAC Addresses"),
           ("35716", "Ethernet Card Manufacturer (OUI)"), ("24260", "HTTP Information"),
           ("66717", "mDNS Detection (Local Network)"), ("33276", "Enumerate MAC via SSH")]
    coverage = []
    for pid, name in sig:
        n = _scalar("SELECT COUNT(DISTINCT asset_uuid) FROM vulns WHERE plugin_id=?", path, (pid,)) or 0
        if n:
            coverage.append({"plugin": int(pid), "name": name, "assets": n})

    # device type per asset from plugin 54615 output
    devtype, dt_counts = {}, defaultdict(int)
    for r in _q("SELECT asset_uuid, output FROM vulns WHERE plugin_id='54615'", path):
        m = _DEVTYPE.search(r.get("output") or "")
        k = (m.group(1).lower() if m else "unknown")
        devtype[r["asset_uuid"]] = k
        dt_counts[k] += 1

    # OUI vendor per asset from plugin 35716 output (last "... : Vendor" line)
    vendor = {}
    vr = defaultdict(int)
    for r in _q("SELECT asset_uuid, output FROM vulns WHERE plugin_id='35716'", path):
        out = (r.get("output") or "").strip()
        if not out:
            continue
        line = out.splitlines()[-1]
        v = line.split(":")[-1].strip() if ":" in line else line.strip()
        if v:
            vendor[r["asset_uuid"]] = v
            vr[v] += 1
    vendor_rollup = [{"vendor": v, "count": c, "class": _vendor_class(v)}
                     for v, c in sorted(vr.items(), key=lambda x: -x[1])]

    mdns = {r["asset_uuid"] for r in _q("SELECT DISTINCT asset_uuid FROM vulns WHERE plugin_id='66717'", path)}

    # cert-fingerprinted IoT (Chromecast / Buffalo / pfSense / Samsung / Ubiquiti ...)
    cert_iot = {}
    for r in _q("SELECT asset_uuid, common_name, organization, organization_unit FROM certs", path):
        text = f"{r.get('common_name','')} {r.get('organization','')} {r.get('organization_unit','')}".lower()
        for key, label in (("chromecast", "Chromecast / Nest"), ("buffalo", "NAS (TeraStation)"),
                           ("terastation", "NAS (TeraStation)"), ("pfsense", "Firewall / appliance"),
                           ("samsung", "Smart device"), ("smartviewsdk", "Smart device"),
                           ("ubnt", "Camera / Ubiquiti"), ("ubiquiti", "Camera / Ubiquiti")):
            if key in text:
                cert_iot[r["asset_uuid"]] = label
                break

    # candidate device set = any IoT/OT signal
    cand = set(mdns) | set(cert_iot) | {u for u, t in devtype.items() if t not in ("general-purpose",)} \
        | {u for u, v in vendor.items() if _vendor_class(v) not in ("virtual", "server", "other")}
    amap = {a["uuid"]: a for a in _q("SELECT uuid, hostname, ip_address FROM assets", path)}
    devices = []
    for u in cand:
        a = amap.get(u, {})
        sigs = []
        if u in vendor:
            sigs.append("OUI:" + vendor[u].split()[0])
        if u in devtype and devtype[u] != "general-purpose":
            sigs.append("DevType:" + devtype[u])
        if u in mdns:
            sigs.append("mDNS")
        if u in cert_iot:
            sigs.append("cert")
        conf = "High" if len(sigs) >= 2 else "Medium"
        devices.append({"asset_uuid": u, "ip": a.get("ip_address", ""), "host": (a.get("hostname") or "").strip() or a.get("ip_address", ""),
                        "vendor": vendor.get(u, "—"), "type": devtype.get(u, "unknown"),
                        "klass": cert_iot.get(u, "Embedded / candidate"),
                        "signals": sigs or ["candidate"], "conf": conf})
    devices.sort(key=lambda d: (d["conf"] != "High", d["host"]))
    return {"deviceTypeCounts": dict(dt_counts), "signalCoverage": coverage,
            "vendorRollup": vendor_rollup, "devices": devices}


# ----------------------------------------------------------------- 02 Certs
def _cert_state(iso, today):
    if not iso:
        return "ok"
    if iso < today:
        return "expired"
    # within ~6 months
    return "soon" if iso <= _add_days(today, 180) else "ok"


def _add_days(iso, days):
    import datetime
    y, m, d = (int(x) for x in iso.split("-"))
    return (datetime.date(y, m, d) + datetime.timedelta(days=days)).isoformat()


def _parse_after(s):
    m = re.match(r"([A-Z][a-z]{2})\s+(\d{1,2})\s+[\d:]+\s+(\d{4})", s or "")
    if not m:
        return None, None
    iso = f"{int(m.group(3)):04d}-{_MONTHS[m.group(1)]:02d}-{int(m.group(2)):02d}"
    pretty = f"{m.group(1)} {int(m.group(2)):02d} {m.group(3)}"
    return iso, pretty


def _algo(sig, keylen):
    sig = (sig or "")
    kl = re.search(r"(\d{3,4})", keylen or "")
    bits = kl.group(1) if kl else ""
    if "ECDSA" in sig.upper() or "EC" == (sig[:2].upper()):
        return "ECDSA P-256"
    fam = "RSA" if "RSA" in sig.upper() else (sig.split()[0] if sig else "RSA")
    return f"{fam} {bits}".strip()


def _sig(sig):
    s = (sig or "").upper()
    for tag in ("MD5", "SHA-1", "SHA1", "SHA-256", "SHA256", "SHA-512", "SHA512"):
        if tag in s:
            return tag.replace("SHA1", "SHA-1").replace("SHA256", "SHA-256").replace("SHA512", "SHA-512")
    if "ECDSA" in s:
        return "ECDSA-SHA256"
    return sig or ""


def _certs(path):
    import datetime
    today = datetime.date.today().isoformat()
    fail = _q("SELECT plugin_id, plugin_name, COUNT(DISTINCT asset_uuid) AS assets FROM vulns "
              "WHERE plugin_name LIKE '%SSL%' OR plugin_name LIKE '%TLS%' OR plugin_name LIKE '%Certificate%' "
              "GROUP BY plugin_id, plugin_name ORDER BY assets DESC", path)
    failure = []
    for r in fail:
        nm = r.get("plugin_name", "")
        sev = "crit" if re.search(r"SSL Version 2|DROWN|POODLE|Heartbleed", nm, re.I) else "med"
        failure.append({"plugin": int(r["plugin_id"]) if str(r["plugin_id"]).isdigit() else r["plugin_id"],
                        "name": nm, "sev": sev, "assets": r["assets"]})
    if not failure:
        failure = [{"plugin": 0, "name": "(no certificate findings in navi.db)", "sev": "med", "assets": 0}]

    rows = _q("SELECT c.common_name, a.hostname, a.ip_address, c.signature_algorithm, c.key_length, c.not_valid_after "
              "FROM certs c LEFT JOIN assets a ON a.uuid=c.asset_uuid", path)
    certs = []
    for r in rows:
        iso, pretty = _parse_after(r.get("not_valid_after"))
        certs.append({"cn": r.get("common_name", ""),
                      "host": (r.get("hostname") or "").strip() or r.get("ip_address", ""),
                      "algo": _algo(r.get("signature_algorithm"), r.get("key_length")),
                      "sig": _sig(r.get("signature_algorithm")),
                      "expVal": pretty or "—", "exp": (iso or "")[:7],
                      "state": _cert_state(iso, today)})
    pqc = _scalar("SELECT COUNT(DISTINCT asset_uuid) FROM certs", path) or 0
    return {"failurePlugins": failure, "certs": certs, "pqcServicesNoPQ": pqc}


# ----------------------------------------------------------------- 03 Identity
def _identity(path):
    enum_ids = [("95928", "Linux User List Enumeration"), ("83303", "Local Users — Passwords Never Expire"),
                ("10860", "SMB Enumerate Local Users"), ("10785", "SMB NativeLanManager Disclosure"),
                ("10914", "Local Users — Never Changed Password"), ("10915", "Local Users — Never Logged In")]
    enum = []
    for pid, name in enum_ids:
        n = _scalar("SELECT COUNT(DISTINCT asset_uuid) FROM vulns WHERE plugin_id=?", path, (pid,)) or 0
        if n:
            enum.append({"plugin": int(pid), "name": name, "assets": n})
    # parse usernames from enumeration output (best-effort)
    acct = {}
    amap = {a["uuid"]: (a.get("hostname") or a.get("ip_address") or "") for a in _q("SELECT uuid, hostname, ip_address FROM assets", path)}
    for r in _q("SELECT asset_uuid, output FROM vulns WHERE plugin_id IN ('95928','10860')", path):
        host = (amap.get(r["asset_uuid"]) or "").strip() or "host"
        for line in (r.get("output") or "").splitlines():
            m = re.search(r"(?:User(?:name)?\s*[:\-]\s*|^-\s*|^\s{2,})([a-z_][a-z0-9_\-]{1,31})\b", line)
            if not m:
                continue
            u = m.group(1)
            if u in ("the", "this", "list", "users", "note", "plugin"):
                continue
            a = acct.setdefault(u, {"user": u, "klass": "system", "shell": "", "hosts": [], "note": "", "risk": "info"})
            if host not in a["hosts"]:
                a["hosts"].append(host)
    # classify by well-known names
    NHI = {"jenkins", "dockerroot", "pihole", "lighttpd", "www-data", "lxd", "cockpit-ws", "gitlab-runner"}
    SVC = {"tns", "postfix", "tcpdump", "chrony", "tss", "pcp", "pollinate", "usbmux", "mysql", "postgres"}
    HUM = {"root", "admin", "administrator"}
    for u, a in acct.items():
        if u in NHI:
            a["klass"], a["risk"], a["note"] = "nhi", "med", "application / non-human identity"
        elif u in SVC:
            a["klass"], a["risk"], a["note"] = "service", "low", "service account"
        elif u in HUM:
            a["klass"], a["risk"], a["note"] = "human", "high", "interactive / privileged"
    return {"enumPlugins": enum, "accounts": list(acct.values())}


# ----------------------------------------------------------------- 04 Shadow
_BANNER_PLUGINS = ("10107", "48243", "106375", "10719", "194915", "48204", "24260", "174788")


def _shadow(path):
    total = _scalar("SELECT COUNT(uuid) FROM assets", path) or 0
    inv = _scalar("SELECT COUNT(DISTINCT asset_uuid) FROM software", path) or 0
    inv_set = {r["asset_uuid"] for r in _q("SELECT DISTINCT asset_uuid FROM software", path)}
    amap = {a["uuid"]: a for a in _q("SELECT uuid, hostname, ip_address FROM assets", path)}
    ph = ",".join("'" + p + "'" for p in _BANNER_PLUGINS)
    apps = []
    for r in _q("SELECT asset_uuid, plugin_id, plugin_name, output FROM vulns WHERE plugin_id IN (" + ph + ")", path):
        if r["asset_uuid"] in inv_set:
            continue  # has inventory → not shadow
        out = (r.get("output") or "").strip()
        sw = out.splitlines()[0][:60] if out else (r.get("plugin_name") or "service")
        a = amap.get(r["asset_uuid"], {})
        apps.append({"sw": sw or "service", "detail": out[:160],
                     "host": (a.get("hostname") or "").strip() or a.get("ip_address", ""),
                     "plugin": int(r["plugin_id"]) if str(r["plugin_id"]).isdigit() else r["plugin_id"],
                     "age": "", "risk": "med"})
    fam = []
    for label, like in (("Web Servers", "%HTTP%"), ("Service detection", "%Service Detection%"),
                        ("Databases", "%SQL%"), ("DNS", "%DNS%")):
        n = _scalar("SELECT COUNT(DISTINCT asset_uuid) FROM vulns WHERE plugin_name LIKE ?", path, (like,)) or 0
        if n:
            fam.append({"family": label, "seen": n, "label": like.strip("%")})
    return {"invAssets": inv, "totalAssets": total, "blindAssets": max(0, total - inv),
            "apps": apps, "coverageByFamily": fam}


# ----------------------------------------------------------------- 05 Routes
def _routes(path):
    rows = _q("SELECT app_name, vuln_type, total_vulns, plugin_list FROM vuln_route", path)
    routes = []
    for r in rows:
        pl = r.get("plugin_list") or ""
        plugins = len([x for x in pl.split(",") if x.strip()]) if pl else 0
        routes.append({"app": r.get("app_name", ""), "vulns": r.get("total_vulns", 0) or 0,
                       "type": r.get("vuln_type", ""), "plugins": plugins})
    routes.sort(key=lambda x: -x["vulns"])
    return {"routes": routes, "totalVulns": sum(x["vulns"] for x in routes)}


# ----------------------------------------------------------------- 06 Paths
_OWNER_TOKENS = ["jenkins", "nessus", "docker", "spring", "apache", "nginx", "python", "urllib3",
                 "tomcat", "java", "navi"]


def _owner(p):
    low = p.lower()
    for t in _OWNER_TOKENS:
        if t in low:
            return {"urllib3": "PYTHON", "spring": "DOCKER / JAVA", "nessus": "TENABLE NESSUS"}.get(t, t.upper())
    parts = [x for x in p.split("/") if x]
    return (parts[1].upper() if len(parts) > 1 else (parts[0].upper() if parts else "OTHER"))


def _paths(path):
    rows = _q("SELECT path, plugin_id FROM vuln_paths WHERE path IS NOT NULL AND path<>''", path)
    raw = len(rows)
    by_path = defaultdict(set)
    for r in rows:
        by_path[r["path"]].add(str(r["plugin_id"]))
    locations = [{"path": p, "plugins": len(pl), "owner": _owner(p)} for p, pl in by_path.items()]
    locations.sort(key=lambda x: -x["plugins"])
    distinct = len(by_path)
    # density bands
    bands = {"1 plugin": 0, "2 plugins": 0, "3–5 plugins": 0, "6+ plugins": 0}
    for loc in locations:
        n = loc["plugins"]
        bands["1 plugin" if n == 1 else "2 plugins" if n == 2 else "3–5 plugins" if n <= 5 else "6+ plugins"] += 1
    density = [{"band": b, "paths": c} for b, c in bands.items() if c]
    # raw vs distinct per owner
    own_raw, own_dist = defaultdict(int), defaultdict(set)
    for r in rows:
        o = _owner(r["path"])
        own_raw[o] += 1
        own_dist[o].add(r["path"])
    by_owner = [{"owner": o, "raw": own_raw[o], "distinct": len(own_dist[o])}
                for o in sorted(own_raw, key=lambda x: -own_raw[x])]
    pct = round((1 - distinct / raw) * 100) if raw else 0
    return {"rawEntries": raw, "distinctLocations": distinct, "reductionPct": pct,
            "locations": locations[:14], "density": density, "byOwner": by_owner}


# ----------------------------------------------------------------- all
def compute_all(db_path=None):
    out = {"ok": True, "live": True}
    for key, fn in (("iot", _iot), ("certs", _certs), ("identity", _identity),
                    ("shadow", _shadow), ("routes", _routes), ("paths", _paths)):
        try:
            out[key] = fn(db_path)
        except Exception as e:  # never let one lens break the rest
            out[key] = {"error": f"{type(e).__name__}: {e}"}
    return out
