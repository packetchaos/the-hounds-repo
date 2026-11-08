"""Shared constants + helpers for the IoT agent squad.

The squad grounds every discovery in real navi.db findings:

- Agent 1 confirms devices from the registry's known detections.
- Agent 2 (host-scoped) harvests CARRIER PLUGINS from each confirmed host's OWN
  findings — plugins whose name/output carry the device term. Carrier plugins
  can also be supplied out-of-band (IOT_CARRIER_PLUGINS_PATH) so you can hunt on
  a rich db without waiting for a device to light up.
- Agent 3 sweeps each carrier plugin for the whole term VOCABULARY across the
  entire population; a term that shows up inside a carrier plugin on enough
  assets becomes a (plugin -> term -> device) detection proposal.

Guardrails are still computed, but on (plugin + term) co-occurrence — NOT the
plugin alone — so a broad "banner" carrier plugin isn't wrongly dropped. They
are surfaced as WARNINGS (Agent 4 coverage ledger) rather than silent filters.
"""
import csv
import json
import math
import os

from . import db

# Enumeration/info plugins that mention many vendors. Still flagged (as a
# warning) if one slips into a kept list, but never silently dropped.
GENERIC_PLUGIN_DENYLIST = {
    "10863",  # SSL Certificate Information
    "11936",  # OS Identification
    "54615",  # Device Type
    "35716",  # Ethernet Card Manufacturer Detection
    "19506",  # Nessus Scan Information
    "21643",  # SSL Cipher Suites Supported
    "45590",  # Common Platform Enumeration (CPE)
    "10180",  # Ping the remote host
    "10287",  # Traceroute Information
    "25220",  # TCP/IP Timestamps Supported
    "56468",  # Time of Last System Startup
    "11219",  # Nessus SYN scanner
    "22964",  # Service Detection
}

PREVALENCE_MAX = 0.50        # (plugin+term) firing on >50% of assets → warn (not drop)
MIN_NAME_LEN = 3             # term shorter than this is too ambiguous to search
CLUSTER_MIN = 2              # "over 1" — a tiny env still needs ≥2 confirming assets
# Significance scales SUB-LINEARLY with population (like statistical significance
# with sample size), so 2 matches is a strong signal in a 5k-asset shop but noise
# in a 5M-asset one. floor = max(2, round(2 * sqrt(assets / ANCHOR))): stays at 2
# below the anchor, then grows by √ — doubling every 4× growth (5k→2, 50k→7,
# 500k→20, 5M→63). Tune the whole curve with the single anchor knob.
FLOOR_ANCHOR = max(1, int(os.environ.get("NAVI_IOT_FLOOR_ANCHOR", "5000")))

NAME_STOPLIST = {
    "cast", "camera", "server", "linux", "windows", "device", "router",
    "switch", "phone", "print", "host", "network", "unknown",
    "generic", "ssl", "http", "https", "tls", "agent", "scan", "default",
}

# ---------------------------------------------------------------------------
# Known IoT term pack (OPTIONAL, opt-in per run).
#
# A curated embedded / OT / consumer-IoT / network-appliance vendor + product
# vocabulary. Terms are matched case-insensitively inside a plugin's NAME or
# OUTPUT. Deliberately excludes mega-vendors whose footprint is mostly NOT IoT
# (apple/google/amazon/microsoft/dell/intel) to keep the signal clean — supply
# those yourself via IOT_TERM_PACK_PATH if you really want them.
#
# For an AUTHORITATIVE, much larger vocabulary, point IOT_TERM_PACK_PATH at a
# CSV (`term,device`) or JSON ({term: device}) — e.g. an IEEE-OUI-derived vendor
# list. That file is MERGED on top of this built-in pack.
# ---------------------------------------------------------------------------
_BUILTIN_TERM_PACK = {
    # network / security appliances
    "ubiquiti": "Ubiquiti", "unifi": "Ubiquiti", "ubnt": "Ubiquiti",
    "mikrotik": "MikroTik", "netgear": "Netgear", "tp-link": "TP-Link",
    "aruba": "Aruba", "fortinet": "Fortinet", "fortigate": "Fortinet",
    "pfsense": "pfSense", "opnsense": "OPNsense", "sonicwall": "SonicWall",
    "meraki": "Cisco Meraki", "zyxel": "Zyxel", "ruckus": "Ruckus",
    "juniper": "Juniper", "watchguard": "WatchGuard", "draytek": "DrayTek",
    "ubee": "Ubee", "sagemcom": "Sagemcom",
    # cameras / surveillance
    "hikvision": "Hikvision", "dahua": "Dahua", "axis communications": "Axis",
    "hanwha": "Hanwha", "vivotek": "Vivotek", "reolink": "Reolink",
    "amcrest": "Amcrest", "wyze": "Wyze", "lorex": "Lorex", "geovision": "GeoVision",
    "mobotix": "Mobotix", "flir": "FLIR",
    # SBC / maker / modules
    "raspberry": "Raspberry Pi", "beaglebone": "BeagleBone", "arduino": "Arduino",
    "espressif": "Espressif", "esp32": "Espressif", "esp8266": "Espressif",
    "particle.io": "Particle",
    # NAS / storage appliances
    "synology": "Synology", "qnap": "QNAP", "terastation": "Buffalo TeraStation",
    "buffalo inc": "Buffalo", "western digital": "WD", "netapp": "NetApp",
    "drobo": "Drobo", "iomega": "Iomega",
    # consumer / smart home / media
    "sonos": "Sonos", "roku": "Roku", "chromecast": "Chromecast",
    "smartviewsdk": "Samsung SmartTV", "lifx": "LIFX", "shelly": "Shelly",
    "tuya": "Tuya", "tp-link kasa": "Kasa", "wemo": "Belkin Wemo",
    "philips hue": "Philips Hue", "hue bridge": "Philips Hue", "ecobee": "ecobee",
    "sonoff": "Sonoff", "harmony hub": "Logitech Harmony",
    # VoIP / conferencing
    "yealink": "Yealink", "polycom": "Polycom", "grandstream": "Grandstream",
    "snom": "Snom", "avaya": "Avaya", "mitel": "Mitel", "cisco spa": "Cisco IP Phone",
    # printers / MFP
    "lexmark": "Lexmark", "zebra": "Zebra", "xerox": "Xerox", "ricoh": "Ricoh",
    "kyocera": "Kyocera", "konica minolta": "Konica Minolta", "brother industries": "Brother",
    # building automation / physical
    "crestron": "Crestron", "lutron": "Lutron", "axis a1001": "Axis Access",
    "hid global": "HID", "honeywell": "Honeywell", "johnson controls": "Johnson Controls",
    "lenel": "Lenel", "bosch security": "Bosch", "tridium": "Tridium",
    "niagara": "Tridium Niagara", "kmc controls": "KMC",
    # industrial / OT / PLC
    "siemens": "Siemens", "simatic": "Siemens SIMATIC", "rockwell": "Rockwell",
    "allen-bradley": "Allen-Bradley", "schneider": "Schneider Electric",
    "modicon": "Schneider Modicon", "emerson": "Emerson", "moxa": "Moxa",
    "beckhoff": "Beckhoff", "wago": "WAGO", "phoenix contact": "Phoenix Contact",
    "abb ": "ABB", "mitsubishi electric": "Mitsubishi", "omron": "Omron",
    "yokogawa": "Yokogawa", "ge fanuc": "GE Fanuc", "codesys": "CODESYS",
    "hirschmann": "Hirschmann", "red lion": "Red Lion", "advantech": "Advantech",
    # medical / lab
    "draeger": "Draeger", "ge healthcare": "GE Healthcare", "philips medical": "Philips Medical",
    # UPS / power
    "eaton": "Eaton", "vertiv": "Vertiv", "apc ": "APC", "tripp lite": "Tripp Lite",
    "cyberpower": "CyberPower",
}

# distinctive tokens too generic to be a device NAME but still worth matching
# only when they appear alongside a device context (kept in the pack values).


def _load_term_file(path):
    """Merge a BYO term file (CSV `term,device` or JSON {term:device} / [term,…])."""
    out = {}
    try:
        with open(path, encoding="utf-8") as f:
            if path.lower().endswith(".json"):
                data = json.load(f)
                if isinstance(data, dict):
                    out = {str(k).strip().lower(): str(v).strip() for k, v in data.items()}
                elif isinstance(data, list):
                    for t in data:
                        t = str(t).strip()
                        if t:
                            out[t.lower()] = t
            else:                                   # csv / tsv
                for row in csv.reader(f):
                    if not row:
                        continue
                    term = str(row[0]).strip()
                    if not term or term.lower() in ("term", "vendor", "oui"):
                        continue
                    name = str(row[1]).strip() if len(row) > 1 and row[1].strip() else term
                    out[term.lower()] = name
    except Exception:
        return {}
    return out


def term_pack():
    """The active term pack: built-in curated + optional BYO file (merged)."""
    pack = dict(_BUILTIN_TERM_PACK)
    p = os.environ.get("IOT_TERM_PACK_PATH")
    if p and os.path.exists(p):
        pack.update(_load_term_file(p))
    return pack


def byo_carrier_plugins():
    """Optional operator-supplied carrier plugin IDs (IOT_CARRIER_PLUGINS_PATH).
    One id per line, or CSV/JSON list. Empty when not configured."""
    p = os.environ.get("IOT_CARRIER_PLUGINS_PATH")
    if not p or not os.path.exists(p):
        return []
    ids = []
    try:
        with open(p, encoding="utf-8") as f:
            if p.lower().endswith(".json"):
                data = json.load(f)
                seq = data if isinstance(data, list) else data.get("plugins", [])
                ids = [str(x).strip() for x in seq]
            else:
                for line in f:
                    for tok in line.replace(",", " ").split():
                        tok = tok.strip()
                        if tok.isdigit():
                            ids.append(tok)
    except Exception:
        return []
    seen, out = set(), []
    for i in ids:
        if i and i not in seen:
            seen.add(i)
            out.append(i)
    return out


# ---------------------------------------------------------------------------
def asset_total(db_path=None) -> int:
    return db.scalar("SELECT count(uuid) FROM assets;", path=db_path) or 0


def cluster_floor(total: int) -> int:
    """Min assets a term must appear on (inside a carrier plugin) to be proposed.
    Sub-linear: floor = max(2, round(2 * sqrt(assets / ANCHOR))). Stays at 2 below
    the anchor (default 5,000), then grows by √ so 2 hits is significant in a small
    shop but not in a 5M-asset one — the noise-reduction knob."""
    return max(CLUSTER_MIN, round(CLUSTER_MIN * math.sqrt(max(0, total) / FLOOR_ANCHOR)))


def floor_explainer(total: int) -> str:
    """One-line, human note explaining why the floor is what it is (for the UI)."""
    fl = cluster_floor(total)
    return (f"Signal floor = {fl}: a term must appear inside a carrier plugin on "
            f"≥{fl} of your {total:,} assets to be proposed. It scales with the "
            f"square root of population (anchored at {FLOOR_ANCHOR:,} → 2), so 2 hits "
            f"is significant in a small environment but filtered as noise in a large "
            f"one. Lower NAVI_IOT_FLOOR_ANCHOR to loosen, raise it to tighten.")


def valid_term(term: str) -> bool:
    t = (term or "").strip()
    if len(t) < MIN_NAME_LEN:
        return False
    if t.lower() in NAME_STOPLIST:
        return False
    return True


# keep the old public name as an alias (used elsewhere / tests)
def valid_iot_name(name: str) -> bool:
    return valid_term(name)


def _like(col, term):
    return f"{col} LIKE '%{term.replace(chr(39), chr(39)*2)}%'"


def detection_terms(det: dict) -> list:
    """All searchable terms for a detection: its name_contains + output_contains
    (its iot_name too, as a fallback if it has no explicit terms)."""
    terms = list(det.get("name_contains") or []) + list(det.get("output_contains") or [])
    if not terms and det.get("iot_name"):
        terms = [det["iot_name"]]
    seen, out = set(), []
    for t in terms:
        k = (t or "").strip().lower()
        if k and k not in seen:
            seen.add(k)
            out.append(t)
    return out


# Plugins whose OUTPUT legitimately carries DEVICE IDENTITY (certs, banners, MAC/OUI,
# mDNS, embedded web, service detection). An output-string match is only trusted inside
# these — NEVER in software-enumeration / program-history / autoruns plugins, which is
# how "Ubiquiti" tagged 62 Windows boxes (the UniFi *app* in MUICache) and "samsung"
# tagged a printer *driver*. This mirrors the human hunt: MAC → mDNS → cert → 24260 →
# plugin name, then output only as a corroborating signal. Override per-detection with
# a "signal_plugins" list on the detection; extend this default as you find more.
SIGNAL_PLUGINS = ("10863", "66717", "24260", "19689", "35716", "86420", "54615",
                  "10107", "22964", "11219", "43111")


# The strongest "NOT-IoT" signal: you CANNOT pull a software inventory off an
# embedded/IoT device, so any asset that yields SOFTWARE ENUMERATION is a general-
# purpose host, not IoT. Same for a general-purpose desktop/server OS fingerprint.
# This single subtractive filter is what kills the false positives (the UniFi *app*
# on 62 Windows boxes, the Samsung *printer driver*) — they all have software enum.
SOFTWARE_ENUM_PLUGINS = ("22869", "20811", "70329", "83991", "216040")
# OS exclusion is DELIBERATELY minimal — only never-IoT desktop/server OSes. We do NOT
# exclude Linux/BSD: IoT is very often embedded Linux (cameras, NAS, routers, PLCs), so
# the software-enum filter (above) — not the OS — is what separates a credentialed Linux
# SERVER (has software enum → out) from an embedded Linux DEVICE (no software enum → in).
_GEN_OS = ("windows", "mac os", "macos")


def _assets_cols(db_path=None):
    try:
        return {r["name"] for r in db.query('PRAGMA table_info("assets")', path=db_path)}
    except Exception:
        return set()


def candidate_filter(db_path=None, v="v", a="a"):
    """SQL predicate keeping only IoT/embedded CANDIDATES — no software enumeration
    and no general-purpose OS. Embedded/appliance OSes (FreeBSD-appliance, Nutanix,
    VxWorks) and unknown/empty OS are NOT excluded. Tune the lists above as needed."""
    sig = ",".join("'" + p + "'" for p in SOFTWARE_ENUM_PLUGINS)
    cond = f"{v}.asset_uuid NOT IN (SELECT asset_uuid FROM vulns WHERE plugin_id IN ({sig}))"
    if "operating_system" in _assets_cols(db_path):
        os_excl = " OR ".join(f"lower(COALESCE({a}.operating_system,'')) LIKE '%{k}%'" for k in _GEN_OS)
        cond += f" AND NOT ({os_excl})"
    return cond


def _detection_where(det: dict, db_path=None):
    """The shared WHERE for a detection: (device plugin id OR device plugin NAME OR
    an identity string in a SIGNAL plugin's output) AND the IoT-candidate filter
    (no software enum / no general-purpose OS). None when the detection has no match
    clause. Used by BOTH discovery and the single-query tag selector so they agree."""
    sig = ",".join("'" + p + "'" for p in (det.get("signal_plugins") or SIGNAL_PLUGINS))
    clauses = []
    pids = [str(p) for p in (det.get("plugins") or []) if str(p).strip()]
    if pids:
        clauses.append("v.plugin_id IN (" + ",".join("'" + p + "'" for p in pids) + ")")
    for t in det.get("name_contains", []):          # match the PLUGIN NAME (device-specific)
        if t:
            clauses.append(_like("v.plugin_name", t))
    for t in det.get("output_contains", []):        # match OUTPUT only inside signal plugins
        if len(str(t)) >= 4:
            clauses.append(f"(v.plugin_id IN ({sig}) AND {_like('v.output', t)})")
    if not clauses:
        return None
    keep = "(" + " OR ".join(clauses) + ")"
    if not det.get("include_general_hosts"):        # default: candidates only
        keep += " AND " + candidate_filter(db_path, "v", "a")
    return keep


def assets_for_detection(det: dict, db_path=None) -> list[dict]:
    """Agent 1 discovery — the detected asset rows + the plugin that matched."""
    where = _detection_where(det, db_path)
    if not where:
        return []
    sql = (f"SELECT DISTINCT v.asset_uuid, a.hostname, a.ip_address, "
           f"v.plugin_id, v.plugin_name FROM vulns v "
           f"LEFT JOIN assets a ON a.uuid = v.asset_uuid WHERE {where};")
    return db.query(sql, path=db_path)


def detection_query(det: dict, db_path=None) -> str:
    """The ONE broad tag selector for a device: a single SELECT of the detected
    asset_uuids (same match + candidate filter as discovery). Tagging via one
    `navi enrich tag --query <this>` replaces the 20× --plugin/--output spam and
    never over-tags, because the candidate filter is baked in."""
    where = _detection_where(det, db_path)
    if not where:
        return ""
    return ("SELECT DISTINCT v.asset_uuid FROM vulns v "
            "LEFT JOIN assets a ON a.uuid = v.asset_uuid WHERE " + where)


def carrier_plugins_on_assets(asset_uuids, terms, db_path=None) -> list[dict]:
    """Agent 2 (host-scoped) — plugins ON the given confirmed assets whose NAME or
    OUTPUT carries any of the device terms. These are 'carrier plugins': plugins
    that leak device-identity strings. Returns one row per (plugin, term)."""
    uuids = [u for u in (asset_uuids or []) if u]
    good = [t for t in (terms or []) if valid_term(t)]
    if not uuids or not good:
        return []
    inlist = ",".join("'" + u.replace("'", "''") + "'" for u in uuids)
    out = []
    for t in good:
        cond = f"({_like('plugin_name', t)} OR {_like('output', t)})"
        sql = (f"SELECT plugin_id, plugin_name, COUNT(DISTINCT asset_uuid) AS host_count "
               f"FROM vulns WHERE asset_uuid IN ({inlist}) AND {cond} "
               f"GROUP BY plugin_id, plugin_name;")
        for r in db.query(sql, path=db_path):
            out.append({"plugin_id": str(r["plugin_id"]),
                        "plugin_name": r.get("plugin_name") or "",
                        "term": t, "host_count": r.get("host_count") or 0})
    return out


def plugin_carries_term(plugin_id, term, db_path=None, total=None) -> dict:
    """Agent 3 — across the WHOLE population, how many assets have this plugin
    with the term inside its name/output, plus a sample of those asset UUIDs.
    prevalence is (plugin+term)/total — the guardrail denominator. Pass `total`
    to avoid re-counting assets on every call (a hunt makes many calls)."""
    if not valid_term(term):
        return {"count": 0, "prevalence": 0.0, "asset_uuids": []}
    total = max(1, total if total is not None else asset_total(db_path))
    pid = str(plugin_id).replace("'", "''")
    cond = f"({_like('plugin_name', term)} OR {_like('output', term)})"
    rows = db.query(f"SELECT DISTINCT asset_uuid FROM vulns "
                    f"WHERE plugin_id='{pid}' AND {cond};", path=db_path)
    uuids = [r["asset_uuid"] for r in rows if r.get("asset_uuid")]
    n = len(uuids)
    return {"count": n, "prevalence": round(n / total, 4), "asset_uuids": uuids}


# ---- page metrics (read-only) ----------------------------------------------
# The identity signals a scan must collect for IoT discovery to see anything. When a
# tenant is all credentialed agent/SSH scans of VMs these are absent and the squad is
# empty by design (scan coverage, not a bug) — the page shows "N of 7 present".
IDENTITY_SIGNALS = (("54615", "Device Type"), ("35716", "Ethernet OUI"),
                    ("66717", "mDNS (local network)"), ("10863", "SSL certificate info"),
                    ("22964", "Service Detection"), ("24260", "HTTP Information"),
                    ("86420", "Ethernet MAC addresses"))


def table_cols(table, db_path=None) -> set:
    """Column names of a navi.db table — empty set when the table is missing."""
    try:
        return {r["name"] for r in db.query(f'PRAGMA table_info("{table}")', path=db_path)}
    except Exception:
        return set()


def identity_signal_coverage(db_path=None) -> list[dict]:
    """Assets carrying each IoT identity-signal plugin (0 when absent). One GROUP BY."""
    ids = ",".join("'" + p + "'" for p, _ in IDENTITY_SIGNALS)
    try:
        rows = db.query(f"SELECT plugin_id, COUNT(DISTINCT asset_uuid) AS n FROM vulns "
                        f"WHERE plugin_id IN ({ids}) GROUP BY plugin_id;", path=db_path)
    except Exception:
        rows = []
    got = {str(r["plugin_id"]): r.get("n") or 0 for r in rows}
    return [{"plugin_id": p, "name": nm, "assets": got.get(p, 0)} for p, nm in IDENTITY_SIGNALS]


def device_exposure(asset_uuids, db_path=None, chunk=500) -> dict:
    """Per discovered device: open findings by severity, CISA KEV hits, and the asset's
    ACR / AES (when navi.db carries them). Read-only; tolerant of older schemas."""
    uuids = list(dict.fromkeys(u for u in (asset_uuids or []) if u))
    vcols, acols = table_cols("vulns", db_path), table_cols("assets", db_path)
    per = {u: {"asset_uuid": u, "critical": 0, "high": 0, "medium": 0, "low": 0,
               "kev": 0, "acr": None, "aes": None} for u in uuids}
    if uuids and "severity" in vcols:
        kev = ("MAX(CASE WHEN xrefs LIKE '%CISA-KNOWN-EXPLOITED%' THEN 1 ELSE 0 END)"
               if "xrefs" in vcols else "0")
        # navi keeps fixed rows in vulns with state='fixed' — count OPEN findings only
        st = (" AND lower(COALESCE(state,'open')) IN ('open','reopened')" if "state" in vcols else "")
        for i in range(0, len(uuids), chunk):
            part = uuids[i:i + chunk]
            ph = ",".join("?" * len(part))
            for r in db.query(f"SELECT asset_uuid, lower(COALESCE(severity,'')) AS sev, "
                              f"COUNT(*) AS n, {kev} AS kev FROM vulns WHERE asset_uuid IN ({ph}){st} "
                              f"GROUP BY asset_uuid, sev;", tuple(part), path=db_path):
                d = per.get(r["asset_uuid"])
                if not d:
                    continue
                # navi stores severity as text or as Tenable's number (4 critical … 1 low)
                sv = {"4": "critical", "3": "high", "2": "medium", "1": "low"}.get(r["sev"], r["sev"])
                if sv in ("critical", "high", "medium", "low"):
                    d[sv] += r["n"] or 0
                if r.get("kev"):
                    d["kev"] = 1
    want = [c for c in ("acr", "aes") if c in acols]
    if uuids and want and "uuid" in acols:
        for i in range(0, len(uuids), chunk):
            part = uuids[i:i + chunk]
            ph = ",".join("?" * len(part))
            for r in db.query(f"SELECT uuid, {', '.join(want)} FROM assets WHERE uuid IN ({ph});",
                              tuple(part), path=db_path):
                d = per.get(r["uuid"])
                for c in want:
                    try:
                        d[c] = None if r.get(c) in (None, "") else int(float(r[c]))
                    except (TypeError, ValueError):
                        d[c] = None
    rows = list(per.values())
    scored = [d for d in rows if d["aes"] is not None]
    top = max(scored, key=lambda d: d["aes"]) if scored else None
    acrs = [d["acr"] for d in rows if d["acr"] is not None]
    summary = {
        "devices": len(rows),
        "with_critical": sum(1 for d in rows if d["critical"]),
        "with_high": sum(1 for d in rows if d["high"]),
        "with_kev": sum(1 for d in rows if d["kev"]),
        "critical_findings": sum(d["critical"] for d in rows),
        "high_findings": sum(d["high"] for d in rows),
        "aes_high": sum(1 for d in scored if d["aes"] >= 650),
        "max_aes": top["aes"] if top else None,
        "max_aes_uuid": top["asset_uuid"] if top else None,
        "avg_acr": round(sum(acrs) / len(acrs), 1) if acrs else None,
        "has_kev_column": "xrefs" in vcols, "has_scores": bool(want),
    }
    return {"assets": rows, "summary": summary}


# ---- retained for backward-compat (older callers/tests) --------------------
def plugins_mentioning(name: str, db_path=None) -> list[dict]:
    """Whole-db plugins whose NAME or OUTPUT mentions a term, with guardrail
    flags. Retained for compatibility; the squad now uses the host-scoped
    carrier harvest + population cross-term sweep above."""
    total = max(1, asset_total(db_path))
    safe = name.replace("'", "''")
    sql = (f"SELECT plugin_id, plugin_name, COUNT(DISTINCT asset_uuid) AS asset_count "
           f"FROM vulns WHERE plugin_name LIKE '%{safe}%' OR output LIKE '%{safe}%' "
           f"GROUP BY plugin_id, plugin_name ORDER BY asset_count DESC;")
    out = []
    for r in db.query(sql, path=db_path):
        pid = str(r["plugin_id"])
        prevalence = (r["asset_count"] or 0) / total
        generic = pid in GENERIC_PLUGIN_DENYLIST
        dropped = generic or prevalence > PREVALENCE_MAX
        out.append({**r, "plugin_id": pid, "prevalence": round(prevalence, 3),
                    "kept": not dropped,
                    "drop_reason": ("generic-denylist" if generic else
                                    "too-prevalent" if prevalence > PREVALENCE_MAX else None)})
    return out


def assets_with_plugins(plugin_ids: list[str], exclude_uuids: set, db_path=None) -> list[dict]:
    """Assets (not excluded) firing ANY of the given plugins, with the count of
    distinct matching plugins as evidence. Used to tag newly-confirmed hosts."""
    if not plugin_ids:
        return []
    inlist = ",".join("'" + str(p).replace("'", "''") + "'" for p in plugin_ids)
    sql = (f"SELECT v.asset_uuid, a.hostname, a.ip_address, "
           f"COUNT(DISTINCT v.plugin_id) AS evidence, "
           f"GROUP_CONCAT(DISTINCT v.plugin_id) AS pids "
           f"FROM vulns v LEFT JOIN assets a ON a.uuid = v.asset_uuid "
           f"WHERE v.plugin_id IN ({inlist}) GROUP BY v.asset_uuid;")
    rows = db.query(sql, path=db_path)
    return [r for r in rows if r["asset_uuid"] not in exclude_uuids and (r["evidence"] or 0) >= 1]
