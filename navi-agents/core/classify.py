"""Asset Classification (Linnaeus).

Two distinct layers — the same split the IoT squad uses (detect → HITL tag → truth):

1. classify()  — GROUND TRUTH from TAGS ONLY. An asset's class/sub come solely from the
   tagging taxonomy other agents + this one write. No tags → Unclassified (blank), and the
   UI tells you to tag. Accepted schemes (first hit wins), so we honor the whole pack:
       'Asset Inventory' = 'Class: X' | 'OS: X' | 'Device Type: X' | 'App: X'   (this agent)
       'IoT'             = '<device>'                                            (IoT squad)
       'Device Type'     = '<type>'
       'OS' / 'Operating System' = '<os>'

2. os_signals() — DETECTION. The old signal logic (OS fingerprint, software-enum rule,
   device signals) reframed as suggestions: "Windows Server 2022 — 40 assets [Tag]".
   You approve, it writes the scheme tags (gated), and classify() then reflects them.
"""
import re

from core import db, software as _sw
from core.iot_common import SOFTWARE_ENUM_PLUGINS

# --- signal keyword sets (for os_signals detection) ------------------------------
_OT_NAME = ("rockwell", "factorytalk", "rslinx", "siemens", " s7", "simatic", "modbus",
            "dnp3", "bacnet", "scada", "wonderware", "iconics", "schneider", "modicon",
            "tridium", "niagara", "codesys", "profinet", "opc ", "omron", "mitsubishi electric")
_OT_HOST = ("plant", "scada", "-plc", "plc-", "hmi", "-rtu", "historian", "-ics", "-ot-", "ot-")
_HYPER = ("esxi", "vsphere", "vcenter", "nutanix", "proxmox", "hyper-v", "xenserver", "ovirt")
_NET = ("pfsense", "opnsense", "fortigate", "fortios", "fortinet", "pan-os", "palo alto",
        "sonicwall", "mikrotik", "routeros", "cisco ios", "cisco asa", "cisco nx-os", "nexus",
        "catalyst", "meraki", "junos", "juniper", "big-ip", "f5 networks", "netscaler", "citrix adc",
        "watchguard", "check point", "gaia", "vyos", "arista eos", "aruba", "arubaos", "procurve",
        "ruckus", "extreme networks", "extremexos", "brocade", "dell os10", "force10", "huawei",
        "vrp", "h3c", "zyxel", "netgear", "ubiquiti", "unifi", "edgeos", "edgerouter", "sophos xg",
        "sophos sfos", "barracuda", "adtran", "alcatel", "nokia sr", "allied telesis", "d-link", "tp-link")
# hostname tokens that imply network gear (used as a secondary signal)
_NET_HOST = ("-sw", "sw-", "-rtr", "rtr-", "-fw", "fw-", "-gw", "gw-", "router", "switch", "firewall")
# cloud provenance columns navi syncs → provider. First populated column wins.
_CLOUD_COLS = (("aws_id", "AWS"), ("aws_ec2_name", "AWS"), ("aws_ec2_region", "AWS"),
               ("azure_vm_id", "Azure"), ("azure_resource_id", "Azure"), ("azure_subscription_id", "Azure"),
               ("gcp_instance_id", "GCP"), ("gcp_project_id", "GCP"))
_IOT_TYPES = [
    ("Camera", ("camera", "ipcam", "hikvision", "dahua", "axis communications", "vivotek", "reolink", "amcrest", "onvif", "nvr", "dvr")),
    ("NAS", ("synology", "diskstation", "qnap", "terastation", "truenas", "freenas", "netapp", "drobo", "readynas")),
    ("Printer", ("printer", "jetdirect", "laserjet", "officejet", "ipp", "print server", "lexmark", "kyocera", "ricoh", "xerox", "brother ")),
    ("Media", ("chromecast", "roku", "sonos", "apple tv", "smarttv", "smart tv", "plex")),
    ("UPS / Power", ("apc ", "eaton ups", "vertiv", "tripp lite", "cyberpower")),
    ("VoIP", ("yealink", "polycom", "grandstream", "cisco ip phone", "sip phone")),
]
_CREDFAIL = ("110723", "104410", "24786", "21745")
_GEN_OS = ("windows", "mac os", "macos")

# Uncredentialed OS-fingerprint plugins whose OUTPUT names the OS — the "OS plugin output"
# the operator classifies from. 11936 = OS Identification (the primary one).
_OS_PLUGINS = ("11936", "45590", "25203", "35351", "38689", "55472")
_OS_OUT_RE = re.compile(r"(?:remote operating system|operating system|\bos)\s*[:=]\s*(.+)", re.I)


def _os_from_plugins(db_path=None):
    """{uuid: os_string} parsed from OS-identification plugin OUTPUT (works uncredentialed).
    Lets classification work when navi's operating_system column is empty."""
    out = {}
    inlist = ",".join("'" + p + "'" for p in _OS_PLUGINS)
    try:
        rows = db.query(f"SELECT asset_uuid, output FROM vulns WHERE plugin_id IN ({inlist})", path=db_path)
    except Exception:
        return out
    for r in rows:
        u = r.get("asset_uuid")
        if not u or u in out:
            continue
        for ln in (r.get("output") or "").splitlines():
            m = _OS_OUT_RE.search(ln.strip())
            if m:
                val = m.group(1).strip().strip(".")
                low = val.lower()
                if val and "confidence" not in low and "method" not in low and len(val) < 120:
                    out[u] = val
                    break
    return out

# Plugin 11936 (OS Identification) is the ONE whose output carries a confidence %, e.g.
#   Remote operating system : Microsoft Windows Server 2016
#   Confidence level : 95
# We parse both so the operator can tag by OS gated on a confidence floor.
_OS_CONF_PLUGIN = "11936"
_OS_NAME_RE = re.compile(r"remote operating system\s*[:=]\s*(.+)", re.I)
_OS_CONF_RE = re.compile(r"confidence level\s*[:=]\s*(\d{1,3})", re.I)


def os_confidence(db_path=None):
    """Per-asset OS + confidence parsed from plugin 11936 (OS Identification) OUTPUT.

    Returns a list of dicts: ``uuid, os_raw, confidence (int 0-100), os_label, family``.
    ``os_label`` is a clean, specific tag value (e.g. 'Windows Server 2016', 'Ubuntu',
    'macOS') via the same helpers the classifier uses; ``family`` collapses to Windows /
    Linux / macOS / Other. An asset can fingerprint on several ports — we keep the HIGHEST
    confidence reading per asset."""
    try:
        rows = db.query("SELECT asset_uuid, output FROM vulns WHERE plugin_id=? "
                        "AND output IS NOT NULL AND output!=''", (_OS_CONF_PLUGIN,), path=db_path)
    except Exception:
        return []
    best = {}
    for r in rows:
        u = r.get("asset_uuid")
        out = r.get("output") or ""
        if not u:
            continue
        nm = _OS_NAME_RE.search(out)
        if not nm:
            continue
        os_raw = nm.group(1).strip().strip(".")
        if not os_raw or len(os_raw) > 120:
            continue
        cm = _OS_CONF_RE.search(out)
        conf = int(cm.group(1)) if cm else 0
        conf = max(0, min(100, conf))
        if u not in best or conf > best[u]["confidence"]:
            fam = _os_to_class(os_raw)
            if fam == "Windows":
                label = _win_version(os_raw)
            elif fam == "Linux":
                label = _linux_distro(os_raw)
            elif fam == "macOS":
                label = "macOS"
            else:
                label = os_raw
            best[u] = {"uuid": u, "os_raw": os_raw, "confidence": conf,
                       "os_label": label, "family": fam}
    return sorted(best.values(), key=lambda x: (-x["confidence"], x["family"], x["uuid"]))


# tag categories that carry classification meaning
_TAG_CATS = ("Asset Inventory", "OS", "Operating System", "IoT", "Device Type", "Class")


def _uuids(sql, db_path=None):
    try:
        return {r["asset_uuid"] for r in db.query(sql, path=db_path) if r.get("asset_uuid")}
    except Exception:
        return set()


def _asset_cols(db_path=None):
    try:
        return {r["name"] for r in db.query('PRAGMA table_info("assets")', path=db_path)}
    except Exception:
        return set()


def _win_version(os_str):
    m = re.search(r"Windows(?:\s+Server)?\s+(\d{4}(?:\s*R2)?|10|11|8\.1|8|7|XP|Vista)", os_str or "", re.I)
    if m:
        srv = "Server " if re.search(r"server", os_str or "", re.I) else ""
        return "Windows " + srv + m.group(1).upper()
    return "Windows"


def _linux_distro(os_str):
    s = (os_str or "").lower()
    for key, name in (("ubuntu", "Ubuntu"), ("debian", "Debian"), ("red hat", "RHEL"), ("rhel", "RHEL"),
                      ("centos", "CentOS"), ("rocky", "Rocky Linux"), ("alma", "AlmaLinux"),
                      ("fedora", "Fedora"), ("oracle", "Oracle Linux"), ("suse", "SUSE"), ("amazon linux", "Amazon Linux")):
        if key in s:
            return name
    return "Linux"


def _os_to_class(osv):
    o = (osv or "").lower()
    if "windows" in o:
        return "Windows"
    if any(d in o for d in ("linux", "ubuntu", "debian", "cent", "fedora", "rocky", "red hat", "rhel", "oracle", "suse", "alma", "amazon")):
        return "Linux"
    if "mac" in o:
        return "macOS"
    return "Other"


# ------------------------------------------------------------------ TAGS = truth
def _read_tags(db_path=None):
    """{uuid: {facet: value}} across every accepted scheme."""
    out = {}
    incat = ",".join("'" + c + "'" for c in _TAG_CATS)
    try:
        rows = db.query(f"SELECT asset_uuid, tag_key, tag_value FROM tags WHERE tag_key IN ({incat})", path=db_path)
    except Exception:
        return out
    for r in rows:
        u = r.get("asset_uuid"); k = (r.get("tag_key") or "").strip().lower(); v = (r.get("tag_value") or "").strip()
        if not u or not v:
            continue
        d = out.setdefault(u, {})
        if k == "asset inventory" and ":" in v:
            facet, _, fv = v.partition(":")
            if fv.strip():
                d.setdefault(facet.strip().lower(), fv.strip())
        elif k == "operating system":
            d.setdefault("os", v)
        elif k in ("os", "iot", "device type", "class"):
            d.setdefault(k, v)
    return out


# Asset Inventory facets that are pure DESCRIPTORS, never a classification on their own.
_DESCRIPTOR_FACETS = ("os", "operating system", "app", "application", "software", "version")


def _tag_class(th):
    """(cls, sub, method) from an asset's tags — None if it carries no classification tag.

    Precedence: the explicit Class facet, then the built-in facets (Cloud, Network, OT,
    IoT, Device Type, OS), then ANY other customer-defined facet the operator invented
    under the Asset Inventory scheme (its value becomes the class) — so the taxonomy
    accounts for whatever classification the customer tags."""
    if not th:
        return None
    if th.get("class"):
        p = th["class"].split(" - ", 1)
        return (p[0].strip(), (p[1].strip() if len(p) > 1 else th.get("os") or th.get("device type") or ""), "tag: Class")
    if th.get("cloud"):
        return ("Cloud", th["cloud"], "tag: Cloud")
    if th.get("network"):
        return ("Network", th["network"], "tag: Network")
    if th.get("ot"):
        return ("OT", th["ot"], "tag: OT")
    if th.get("iot"):
        return ("IoT", th["iot"], "tag: IoT")
    if th.get("device type"):
        dv = th["device type"]
        cls = "OT" if any(k in dv.lower() for k in ("plc", "hmi", "rtu", "scada")) else "IoT"
        return (cls, dv, "tag: Device Type")
    osv = th.get("os")
    if osv:
        return (_os_to_class(osv), osv, "tag: OS")
    # customer-defined classification: any remaining non-descriptor facet → its value is the class
    for facet in sorted(th):
        if facet in _DESCRIPTOR_FACETS:
            continue
        val = (th.get(facet) or "").strip()
        if val:
            return (val, "", "tag: " + facet.title())
    return None


def classify(db_path=None):
    """GROUND TRUTH from tags. Untagged assets → Unclassified."""
    acols = _asset_cols(db_path)
    if "uuid" not in acols:
        return {"ok": False, "error": "no assets table in navi.db"}
    os_sel = ", operating_system" if "operating_system" in acols else ""
    acr_sel = ", acr" if "acr" in acols else ""
    aes_sel = ", aes" if "aes" in acols else ""
    cloud_cols = [c for c, _ in _CLOUD_COLS if c in acols]
    cloud_sel = "".join(", " + c for c in cloud_cols)
    assets = db.query(f"SELECT uuid, hostname, ip_address{os_sel}{acr_sel}{aes_sel}{cloud_sel} FROM assets;", path=db_path)

    tags = _read_tags(db_path)
    owned = _uuids("SELECT DISTINCT asset_uuid FROM tags WHERE tag_key='Owner'", db_path)
    kev = _uuids("SELECT DISTINCT asset_uuid FROM vulns WHERE xrefs LIKE '%CISA-KNOWN-EXPLOITED%'", db_path)
    crit = _uuids("SELECT DISTINCT asset_uuid FROM vulns WHERE lower(severity)='critical'", db_path)

    def _cloud_of(a):
        for c, prov in _CLOUD_COLS:
            if a.get(c):
                return prov
        return ""

    out = []
    for a in assets:
        u = a.get("uuid")
        prov = _cloud_of(a)
        tc = _tag_class(tags.get(u))
        if tc:
            cls, sub, method = tc; conf, reason = "tagged", ""
        elif prov:
            # cloud provenance from navi's metadata is authoritative ground truth
            cls, sub, method, conf, reason = "Cloud", prov, "cloud metadata", "detected", ""
        else:
            cls, sub, method, conf, reason = "Unclassified", "", "", "n/a", "not tagged — classify from OS Signals"
        out.append({"uuid": u, "hostname": a.get("hostname") or "", "ip": a.get("ip_address") or "",
                    "cls": cls, "sub": sub, "method": method, "confidence": conf, "reason": reason,
                    "cloud": prov, "os": (a.get("operating_system") or "").strip(),
                    "acr": a.get("acr"), "aes": a.get("aes"),
                    "owned": u in owned, "kev": u in kev, "critical": u in crit})

    classes = {}
    for r in out:
        c = classes.setdefault(r["cls"], {"cls": r["cls"], "count": 0, "owned": 0, "unowned": 0,
                                          "kev": 0, "critical": 0, "cloud": 0, "subs": {}})
        c["count"] += 1
        c["owned" if r["owned"] else "unowned"] += 1
        c["kev"] += 1 if r["kev"] else 0
        c["critical"] += 1 if r["critical"] else 0
        c["cloud"] += 1 if r["cloud"] else 0
        key = r["sub"] or r["reason"] or "—"
        c["subs"][key] = c["subs"].get(key, 0) + 1
    order = ["Windows", "Linux", "macOS", "IoT", "OT", "Network", "Cloud", "Virtual Infrastructure", "Other", "Unclassified"]
    class_list = []
    for name in order + [k for k in classes if k not in order]:
        if name in classes:
            c = classes[name]
            c["subs"] = sorted([{"name": k, "count": v} for k, v in c["subs"].items()], key=lambda x: -x["count"])
            class_list.append(c)

    total = len(out)
    unclassified = sum(1 for r in out if r["cls"] == "Unclassified")
    classified = total - unclassified
    stats = {"total": total, "servers": 0, "workstations": 0, "iot": 0, "ot": 0,
             "network": 0, "cloud": 0, "virtual": 0, "unclassified": unclassified}
    for r in out:
        c = r["cls"]; sub = (r["sub"] or "").lower()
        if c == "IoT":
            stats["iot"] += 1
        elif c == "OT":
            stats["ot"] += 1
        elif c == "Network":
            stats["network"] += 1; stats["servers"] += 1
        elif c == "Cloud":
            stats["cloud"] += 1; stats["servers"] += 1
        elif c == "Virtual Infrastructure":
            stats["virtual"] += 1; stats["servers"] += 1
        elif c == "Windows":
            stats["servers" if "server" in sub else "workstations"] += 1
        elif c == "macOS":
            stats["workstations"] += 1
        elif c == "Linux":
            stats["servers"] += 1
    stats["unclassified_pct"] = round(100.0 * unclassified / total, 1) if total else 0.0
    return {"ok": True, "total": total, "classified": classified, "unclassified": unclassified,
            "coverage_pct": round(100.0 * classified / total, 1) if total else 0.0,
            "tagged_any": classified > 0, "stats": stats, "classes": class_list, "assets": out,
            "unclassified_reasons": [{"reason": "not tagged", "count": unclassified}] if unclassified else []}


# ------------------------------------------------------------------ SIGNALS = suggestions
def _gather_signals(db_path, keep):
    def like_name(terms):
        return " OR ".join("lower(v.plugin_name) LIKE '%" + t.replace("'", "''") + "%'" for t in terms)
    S = {}
    S["sw_win"] = _uuids("SELECT DISTINCT asset_uuid FROM vulns WHERE plugin_id='20811'", db_path)
    S["sw_nix"] = _uuids("SELECT DISTINCT asset_uuid FROM vulns WHERE plugin_id IN ("
                         + ",".join("'" + p + "'" for p in SOFTWARE_ENUM_PLUGINS if p != "20811") + ")", db_path)
    S["ot"] = _uuids(f"SELECT DISTINCT v.asset_uuid FROM vulns v WHERE {like_name(_OT_NAME)}", db_path)
    S["net"] = _uuids(f"SELECT DISTINCT v.asset_uuid FROM vulns v WHERE {like_name(_NET)}", db_path)
    S["hyper"] = _uuids(f"SELECT DISTINCT v.asset_uuid FROM vulns v WHERE {like_name(_HYPER)}", db_path)
    S["embed"] = _uuids("SELECT DISTINCT asset_uuid FROM vulns WHERE plugin_id IN ('19689','66717','10863','24260')", db_path)
    S["credfail"] = _uuids("SELECT DISTINCT asset_uuid FROM vulns WHERE plugin_id IN ("
                           + ",".join("'" + p + "'" for p in _CREDFAIL) + ")", db_path)
    S["iot_type"] = {}
    for label, terms in _IOT_TYPES:
        S["iot_type"][label] = _uuids(f"SELECT DISTINCT v.asset_uuid FROM vulns v WHERE {like_name(terms)}", db_path)
    return S


def _signal_class(a, S):
    """Signal-inferred (facet, value) suggestion for one asset, or None."""
    u = a.get("uuid"); os_ = (a.get("operating_system") or "").strip(); osl = os_.lower()
    host = (a.get("hostname") or "").strip().lower()
    sw = (u in S["sw_win"]) or (u in S["sw_nix"])
    if u in S["ot"] or any(k in host for k in _OT_HOST):
        return ("Device Type", "Engineering Workstation" if sw else "OT Device")
    if u in S["net"] or any(k in host for k in _NET_HOST):
        return ("Class", "Network")
    if u in S["hyper"] or "esxi" in osl:
        return ("Class", "Virtual Infrastructure")
    if "windows" in osl or u in S["sw_win"]:
        return ("OS", _win_version(os_) if os_ else "Windows")
    if ("linux" in osl or any(d in osl for d in ("ubuntu", "debian", "cent", "fedora", "rocky", "red hat", "oracle", "suse", "alma", "amazon"))) or u in S["sw_nix"]:
        return ("OS", _linux_distro(os_) if os_ else "Linux")
    if "mac os" in osl or "macos" in osl:
        return ("OS", "macOS")
    if (u in S["embed"] or os_) and not sw:
        for label, terms in _IOT_TYPES:
            if u in S["iot_type"][label] or any(t.strip() in host for t in terms):
                return ("Device Type", label)
        return ("Device Type", "Embedded")
    return None


def os_breakdown(db_path=None, only_untagged=True):
    """OS families (Windows/Linux/macOS) → their versions, for the two-pie OS explorer.

    Reuses _signal_class so it stays consistent with os_signals AND honors the
    'IoT is often Linux' caution — only true OS hosts (net/OT/embedded routed away
    by _signal_class) count. Each node carries uuids so a cohort can be tagged.
    """
    acols = _asset_cols(db_path)
    if "uuid" not in acols:
        return {"ok": False, "error": "no assets table"}
    os_sel = ", operating_system" if "operating_system" in acols else ""
    assets = db.query(f"SELECT uuid, hostname, ip_address{os_sel} FROM assets;", path=db_path)
    tags = _read_tags(db_path) if only_untagged else {}
    S = _gather_signals(db_path, {a["uuid"] for a in assets})
    plugin_os = _os_from_plugins(db_path)          # OS from uncredentialed OS-ID plugin output
    fam = {}
    for a in assets:
        u = a.get("uuid")
        if only_untagged and _tag_class(tags.get(u)):
            continue
        if not (a.get("operating_system") or "").strip():
            a["operating_system"] = plugin_os.get(u, "")
        sig = _signal_class(a, S)
        if not sig or sig[0] != "OS":
            continue
        version = sig[1]
        family = _os_to_class(version)
        f = fam.setdefault(family, {"family": family, "count": 0, "uuids": [], "versions": {}})
        f["count"] += 1
        f["uuids"].append(u)
        v = f["versions"].setdefault(version, {"name": version, "count": 0, "uuids": [], "sample": []})
        v["count"] += 1
        v["uuids"].append(u)
        if len(v["sample"]) < 3 and (a.get("hostname") or "").strip():
            v["sample"].append(a["hostname"].strip())
    families = []
    for fm in sorted(fam.values(), key=lambda x: -x["count"]):
        vers = sorted(fm["versions"].values(), key=lambda x: -x["count"])
        families.append({"family": fm["family"], "count": fm["count"], "uuids": fm["uuids"], "versions": vers})
    return {"ok": True, "families": families,
            "total_detected": sum(f["count"] for f in families)}


def os_signals(db_path=None, only_untagged=True):
    """Detected classification suggestions, grouped into taggable cohorts."""
    acols = _asset_cols(db_path)
    if "uuid" not in acols:
        return {"ok": False, "error": "no assets table"}
    os_sel = ", operating_system" if "operating_system" in acols else ""
    assets = db.query(f"SELECT uuid, hostname, ip_address{os_sel} FROM assets;", path=db_path)
    keep = {a["uuid"] for a in assets}
    tags = _read_tags(db_path) if only_untagged else {}
    S = _gather_signals(db_path, keep)
    plugin_os = _os_from_plugins(db_path)
    cohorts = {}
    uncovered = 0
    for a in assets:
        u = a.get("uuid")
        if only_untagged and _tag_class(tags.get(u)):
            continue                       # already classified by a tag
        if not (a.get("operating_system") or "").strip():
            a["operating_system"] = plugin_os.get(u, "")
        sig = _signal_class(a, S)
        if not sig:
            uncovered += 1
            continue
        facet, value = sig
        c = cohorts.setdefault((facet, value), {"facet": facet, "value": value, "count": 0,
                                                "uuids": [], "sample": []})
        c["count"] += 1
        if len(c["uuids"]) < 5000:
            c["uuids"].append(u)
        if len(c["sample"]) < 4 and (a.get("hostname") or "").strip():
            c["sample"].append(a["hostname"].strip())
    cl = sorted(cohorts.values(), key=lambda x: -x["count"])
    return {"ok": True, "cohorts": cl, "cohort_count": len(cl),
            "assets_with_signal": sum(c["count"] for c in cl), "no_signal": uncovered}
