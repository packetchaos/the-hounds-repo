"""Argos / Asset Deep-Dive — self-contained HTTP actions.

`run`    — small readiness stub (the hub's generic Execute).
`lookup` — the workhorse: payload {target} (a UUID *or* an IP) → one asset dossier
           read entirely from navi.db (read-only): identity, risk band + severity
           breakdown, the pack's tags DECIPHERED (meaning + which Hound raised each),
           top CVEs, software, and certificates.
`live`   — optional CLI passthrough: `navi explore uuid <target> [view]` for the
           flag-driven views (-software/-patches/…). Needs the navi CLI + keys; it's
           a read, so no write gate.
"""
import re

from core import db

AGENT = None


def _agent():
    global AGENT
    if AGENT is None:
        from .agent import ArgosAgent
        AGENT = ArgosAgent()
    return AGENT


def _cols(table):
    try:
        return {r["name"] for r in db.query(f'PRAGMA table_info("{table}");')}
    except Exception:
        return set()


# --------------------------------------------------------------------------- #
#  Tag intelligence — how Argos "deciphers" the pack's tags. Keyed by a lower-case
#  substring of the tag CATEGORY; first match wins. weight 0-5 drives the risk lens.
# --------------------------------------------------------------------------- #
_TAG_INTEL = [
    ("cisa kev", {"hound": "Laelaps", "agent": "cisakev", "weight": 5, "band": "critical",
                  "why": "A CISA Known-Exploited vulnerability is present — attackers are using this in the wild. Patch first."}),
    ("cisa", {"hound": "Laelaps", "agent": "cisakev", "weight": 5, "band": "critical",
              "why": "Flagged against CISA's Known-Exploited catalog — actively exploited."}),
    ("kev", {"hound": "Laelaps", "agent": "cisakev", "weight": 5, "band": "critical",
             "why": "Known-Exploited vulnerability — prioritize remediation."}),
    ("cert failure", {"hound": "Certania", "agent": "certificate", "weight": 3, "band": "high",
                      "why": "A certificate on this asset is failing or expiring — an outage or trust break is coming."}),
    ("certexpiry", {"hound": "Certania", "agent": "certificate", "weight": 3, "band": "high",
                    "why": "Certificate expiring soon — renew before it breaks a service."}),
    ("cert", {"hound": "Certania", "agent": "certificate", "weight": 3, "band": "high",
              "why": "Certificate condition flagged — check the chain of trust."}),
    ("post-quantum", {"hound": "Heimdall", "agent": "postquantum", "weight": 2, "band": "medium",
                      "why": "Quantum-vulnerable cryptography detected — on the harvest-now-decrypt-later roadmap."}),
    ("mitre", {"hound": "Orthrus", "agent": "mitre", "weight": 4, "band": "high",
               "why": "Maps to a MITRE ATT&CK technique — carries known adversary tradecraft."}),
    ("lifecycle", {"hound": "Charon", "agent": "eol", "weight": 4, "band": "high",
                   "why": "End-of-life / unsupported software — no more security patches will ship."}),
    ("eol", {"hound": "Charon", "agent": "eol", "weight": 4, "band": "high",
             "why": "End-of-life software — unpatchable by design."}),
    ("iot", {"hound": "Cerberus", "agent": "iot_squad", "weight": 3, "band": "medium",
             "why": "An IoT / embedded device at the edge — often unmanaged and hard to patch."}),
    ("scan health", {"hound": "Chronos", "agent": "scan_eval", "weight": 3, "band": "medium",
                     "why": "A scan-health problem (e.g. credential failure) — this asset may be a blind spot."}),
    ("ai", {"hound": "Pythia", "agent": "ai", "weight": 2, "band": "medium",
            "why": "Carries AI / ML software — a fast-moving, novel attack surface."}),
    ("software", {"hound": "Mimir", "agent": "software", "weight": 1, "band": "low",
                  "why": "Software-inventory classification from the product map."}),
    ("route", {"hound": "Atlas", "agent": "exproute", "weight": 1, "band": "info",
               "why": "Belongs to an exposure route — grouped for remediation ownership."}),
    ("owner", {"hound": "Atlas", "agent": "exproute", "weight": 0, "band": "good",
               "why": "Has an assigned owner — findings here route to a human. This is a good sign."}),
    ("custom app", {"hound": "Argus", "agent": "customapp", "weight": 1, "band": "info",
                    "why": "Identified as part of a custom application."}),
    ("agent group", {"hound": "Sirius", "agent": "agentgroup", "weight": 0, "band": "info",
                     "why": "Segmented into a Tenable agent group."}),
    ("nhi", {"hound": "Janus", "agent": "identity", "weight": 3, "band": "medium",
             "why": "A non-human / machine identity — often over-privileged and unrotated."}),
    ("service account", {"hound": "Janus", "agent": "identity", "weight": 3, "band": "medium",
                         "why": "A service account — a common lateral-movement stepping stone."}),
    ("identity", {"hound": "Janus", "agent": "identity", "weight": 2, "band": "medium",
                  "why": "An identity / account classification."}),
]


def _decipher(cat, val):
    c = (cat or "").lower()
    for key, meta in _TAG_INTEL:
        if key in c:
            return dict(meta, category=cat, value=val)
    return {"hound": "", "agent": "", "weight": 1, "band": "info", "category": cat,
            "value": val, "why": "A classification tag applied to this asset."}


# --------------------------------------------------------------------------- #
#  severity + cve helpers (navi.db columns vary; stay defensive)
# --------------------------------------------------------------------------- #
_SEV_NUM = {"4": "critical", "3": "high", "2": "medium", "1": "low", "0": "info"}
_SEV_ORDER = ["critical", "high", "medium", "low", "info"]
_CVE_RE = re.compile(r"CVE-\d{4}-\d{3,7}", re.I)


def _sev_name(raw):
    if raw is None:
        return None
    s = str(raw).strip().lower()
    if s in _SEV_ORDER:
        return s
    if s in _SEV_NUM:
        return _SEV_NUM[s]
    return {"informational": "info", "": None}.get(s, s or None)


def _resolve(target):
    """Find the asset by exact UUID, then exact IP, then IP LIKE. Returns (row, how)."""
    ac = _cols("assets")
    if not ac:
        return None, "no assets table"
    sel = ["uuid", "hostname", "ip_address"]
    for c in ("operating_system", "acr", "network", "fqdn", "aes", "exposure_score", "url", "last_seen"):
        if c in ac:
            sel.append(c)
    cols = ", ".join(sel)
    t = (target or "").strip()
    if not t:
        return None, "empty"
    r = db.query(f"SELECT {cols} FROM assets WHERE uuid=? LIMIT 1;", (t,))
    if r:
        return r[0], "uuid"
    if "ip_address" in ac:
        r = db.query(f"SELECT {cols} FROM assets WHERE ip_address=? LIMIT 1;", (t,))
        if r:
            return r[0], "ip"
        r = db.query(f"SELECT {cols} FROM assets WHERE ip_address LIKE ? ORDER BY ip_address LIMIT 1;", (f"%{t}%",))
        if r:
            return r[0], "ip~"
    if "hostname" in ac:
        r = db.query(f"SELECT {cols} FROM assets WHERE hostname LIKE ? ORDER BY hostname LIMIT 1;", (f"%{t}%",))
        if r:
            return r[0], "hostname~"
    return None, "not found"


def _vulns_for(uuid):
    vc = _cols("vulns")
    if not vc or "asset_uuid" not in vc:
        return []
    sel = ["plugin_id", "plugin_name"]
    for c in ("severity", "vpr", "cves", "plugin_family", "output", "last_found",
              "exploit_available", "exploitability_ease"):
        if c in vc:
            sel.append(c)
    cols = ", ".join(sel)
    try:
        return db.query(f"SELECT {cols} FROM vulns WHERE asset_uuid=?;", (uuid,))
    except Exception:
        return []


def _tags_for(uuid):
    tc = _cols("tags")
    if not tc or "asset_uuid" not in tc:
        return []
    try:
        return db.query("SELECT DISTINCT tag_key, tag_value FROM tags WHERE asset_uuid=? "
                        "AND tag_value IS NOT NULL;", (uuid,))
    except Exception:
        return []


def _software_for(uuid):
    sc = _cols("software")
    if not sc or "asset_uuid" not in sc or "software_string" not in sc:
        return []
    try:
        from core import software as _sw
    except Exception:
        _sw = None
    rows = db.query("SELECT DISTINCT software_string FROM software WHERE asset_uuid=?;", (uuid,))
    out = []
    for r in rows:
        s = r.get("software_string") or ""
        if _sw:
            name, ver = _sw.parse_nvr(s)
        else:
            name, ver = s, ""
        if name:
            out.append({"name": name, "version": ver, "raw": s})
    return out


def _certs_for(uuid):
    cc = _cols("certs")
    if not cc or "asset_uuid" not in cc:
        return []
    sel = [c for c in ("common_name", "not_valid_after", "signature_algorithm",
                       "key_length", "organization") if c in cc]
    if not sel:
        return []
    try:
        from core.certdates import parse_cert_date
    except Exception:
        parse_cert_date = lambda s: None
    rows = db.query(f"SELECT {', '.join(sel)} FROM certs WHERE asset_uuid=?;", (uuid,))
    for c in rows:
        d = parse_cert_date(c.get("not_valid_after")) if c.get("not_valid_after") else None
        c["expiry_iso"] = d.isoformat() if hasattr(d, "isoformat") else (d or None)
        sig = (c.get("signature_algorithm") or "").lower()
        kl = c.get("key_length")
        try:
            kl = int(kl) if kl not in (None, "") else None
        except Exception:
            kl = None
        c["weak"] = bool(("sha1" in sig or "md5" in sig) or (kl is not None and kl < 2048))
    return rows


def _band_for_score(score):
    if score >= 70:
        return "critical"
    if score >= 45:
        return "high"
    if score >= 20:
        return "medium"
    if score > 0:
        return "low"
    return "clear"


def _host_profile(uuid):
    try:
        from core import hostprofile
        return hostprofile.profile(uuid)
    except Exception:
        return {}


def lookup(p):
    target = (p.get("target") or p.get("uuid") or p.get("ip") or "").strip()
    if not target:
        return {"ok": False, "error": "target (UUID or IP) required"}, 400
    row, how = _resolve(target)
    if not row:
        return {"ok": True, "found": False, "target": target,
                "message": f"No asset in navi.db matches '{target}'. Try the exact UUID or IP, "
                           f"or refresh navi.db.", "resolved_by": how}, 200

    uuid = row.get("uuid")
    vulns = _vulns_for(uuid)
    tags_raw = _tags_for(uuid)
    software = _software_for(uuid)
    certs = _certs_for(uuid)

    # severity breakdown
    sev_counts = {k: 0 for k in _SEV_ORDER}
    cves, exploitable = set(), 0
    for v in vulns:
        sn = _sev_name(v.get("severity"))
        if sn in sev_counts:
            sev_counts[sn] += 1
        for m in _CVE_RE.findall(str(v.get("cves") or "")):
            cves.add(m.upper())
        ee = str(v.get("exploit_available") or v.get("exploitability_ease") or "").lower()
        if ee in ("true", "1", "yes", "exploits are available"):
            exploitable += 1

    # deciphered tags + tag weight
    tags = [_decipher(t.get("tag_key"), t.get("tag_value")) for t in tags_raw]
    tags.sort(key=lambda x: -x.get("weight", 0))
    kev = any(t["agent"] == "cisakev" for t in tags)
    tag_weight = sum(t.get("weight", 0) for t in tags)

    # risk score (0-100): severity-weighted + KEV/exploit boosts + tag intelligence
    score = (sev_counts["critical"] * 12 + sev_counts["high"] * 6 +
             sev_counts["medium"] * 2 + sev_counts["low"] * 0.5)
    score += 25 if kev else 0
    score += min(exploitable, 10) * 2
    score += min(tag_weight, 20) * 1.5
    score = int(min(round(score), 100))

    # ACR passthrough (string/number)
    acr = row.get("acr")
    try:
        acr = float(acr) if acr not in (None, "") else None
    except Exception:
        pass

    top_cves = sorted(cves)[:40]
    # sort: critical→info, then vpr desc
    def _vk(v):
        sn = _sev_name(v.get("severity"))
        si = _SEV_ORDER.index(sn) if sn in _SEV_ORDER else 99
        vpr = float(v.get("vpr")) if str(v.get("vpr") or "").replace(".", "", 1).isdigit() else 0
        return (si, -vpr)
    top_vulns = sorted(vulns, key=_vk)[:25]

    return {"ok": True, "found": True, "target": target, "resolved_by": how,
            "asset": {"uuid": uuid, "hostname": row.get("hostname"),
                      "ip_address": row.get("ip_address"),
                      "operating_system": row.get("operating_system"),
                      "network": row.get("network"), "fqdn": row.get("fqdn"),
                      "url": row.get("url"), "last_seen": row.get("last_seen")},
            "risk": {"score": score, "band": _band_for_score(score),
                     "severity": sev_counts, "total_vulns": len(vulns),
                     "cve_count": len(cves), "kev": kev, "exploitable": exploitable,
                     "acr": acr, "aes": row.get("aes"),
                     "exposure_score": row.get("exposure_score")},
            "tags": tags,
            "top_cves": top_cves,
            "top_vulns": [{"plugin_id": v.get("plugin_id"), "plugin_name": v.get("plugin_name"),
                           "severity": _sev_name(v.get("severity")), "vpr": v.get("vpr"),
                           "family": v.get("plugin_family"),
                           "cves": _CVE_RE.findall(str(v.get("cves") or ""))} for v in top_vulns],
            "software": software[:200],
            "certs": certs,
            "host": _host_profile(uuid),
            "counts": {"vulns": len(vulns), "tags": len(tags),
                       "software": len(software), "certs": len(certs)}}, 200


def live(p):
    """`navi explore uuid <target> [view]` passthrough — the flag-driven per-asset views."""
    from core import navi_cli
    target = (p.get("target") or "").strip()
    view = (p.get("view") or "").strip()
    if not target:
        return {"ok": False, "error": "target required"}, 400
    if not navi_cli.navi_available():
        return {"ok": False, "error": "navi CLI not found on this server — the live "
                "`navi explore uuid` views need navi on PATH (set NAVI_BIN)."}, 200
    out = navi_cli.explore_uuid(target, view)
    return {"ok": bool(out.get("ok")), **out}, 200


def run(p):
    return {"ok": True, "agent": _agent().meta(), "result": _agent().run()}, 200


ACTIONS = {"run": run, "lookup": lookup, "live": live}
