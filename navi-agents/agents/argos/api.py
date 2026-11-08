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

from core import db, identity as _identity, tagname

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
    ("custom app", {"hound": "Cavall", "agent": "customapp", "weight": 1, "band": "info",
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


# Unified inventory scheme: category 'Asset Inventory', value '<Facet>: <val>'. Map each
# facet to the Hound that owns it so the tag reads as e.g. 'Asset Inventory : IoT: …' → Cerberus.
_FACET_INTEL = {
    "iot": {"hound": "Cerberus", "agent": "iot_squad", "weight": 3, "band": "medium",
            "why": "An IoT / embedded device — often unmanaged and hard to patch."},
    "ot": {"hound": "Cerberus", "agent": "iot_squad", "weight": 4, "band": "high",
           "why": "Operational-technology device — fragile, safety-critical, rarely patchable."},
    "device type": {"hound": "Cerberus", "agent": "iot_squad", "weight": 3, "band": "medium",
                    "why": "Classified by device type — an IoT/OT signal."},
    "class": {"hound": "Linnaeus", "agent": "classify", "weight": 1, "band": "info",
              "why": "Asset-class classification — what this asset IS."},
    "os": {"hound": "Linnaeus", "agent": "classify", "weight": 1, "band": "info",
           "why": "Operating-system classification."},
    "app": {"hound": "Cavall", "agent": "customapp", "weight": 1, "band": "info",
            "why": "Part of a custom application."},
    "cloud": {"hound": "Linnaeus", "agent": "classify", "weight": 1, "band": "info",
              "why": "Cloud-hosted asset."},
}


def _decipher(cat, val):
    c = tagname.base(cat or "").lower()      # 'Hounds-Lifecycle' reads as 'lifecycle' (core.tagname)
    # Unified inventory scheme → split the facet out of the value and map it.
    if c == "asset inventory" and ": " in (val or ""):
        facet, sub = (val or "").split(": ", 1)
        fk = facet.strip().lower()
        meta = _FACET_INTEL.get(fk, {"hound": "Linnaeus", "agent": "classify", "weight": 1,
                                     "band": "info", "why": "Inventory classification (" + facet.strip() + ")."})
        return dict(meta, category=cat, value=val, facet=facet.strip(), subvalue=sub.strip())
    for key, meta in _TAG_INTEL:
        if key in c:
            return dict(meta, category=cat, value=val)
    return {"hound": "", "agent": "", "weight": 1, "band": "info", "category": cat,
            "value": val, "why": "A classification tag applied to this asset."}


_DISPOSITIONS = {"ignored", "accepted", "mitigated"}


def _ownership(tags_raw):
    """Owners assigned to this asset, from its Owner tags (scheme '<app/route>: <user>').
    Dispositions (Accepted/Ignored/Mitigated) are NOT owners and are excluded. Grouped by
    owner, so the Argos ownership pie shows WHO is accountable and for which apps/routes."""
    owners = {}
    for t in tags_raw:
        if tagname.base((t.get("tag_key") or "").strip()).lower() != "owner":     # Owner or Hounds-Owner
            continue
        v = (t.get("tag_value") or "").strip()
        if ": " in v:
            app, user = v.rsplit(": ", 1)
        else:
            app, user = v, ""
        app, user = app.strip(), user.strip()
        if not user or user.lower() in _DISPOSITIONS:
            continue
        e = owners.setdefault(user, {"owner": user, "apps": [], "count": 0})
        if app and app not in e["apps"]:
            e["apps"].append(app)
        e["count"] += 1
    return sorted(owners.values(), key=lambda x: (-x["count"], x["owner"].lower()))


def _coverage(tags):
    """Per-asset taxonomy completeness — is this asset OWNED and CLASSIFIED? Drives the Argos
    coverage strip so the deep-dive doubles as a 'what's missing' worklist across the pack."""
    agents = {t.get("agent") for t in tags}
    facets = {(t.get("facet") or "").lower() for t in tags if t.get("facet")}
    cats = {(t.get("category") or "").lower() for t in tags}
    owned = "owner" in cats
    classified = bool(facets & {"class", "os", "device type", "iot", "ot"}) or "class" in cats
    device_typed = bool(facets & {"device type", "iot", "ot"})
    return {"owned": owned, "classified": classified, "device_typed": device_typed,
            "os_known": "os" in facets or bool(agents)}


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
        return [], "none"          # callers unpack (rows, source) — a bare [] crashed the lookup
    try:
        from core import software as _sw
    except Exception:
        _sw = None
    # software.asset_uuid is a single uuid on some navi datasets and a STRINGIFIED
    # LIST of uuids on others ("['ec88…', 'd423…']") — match both shapes.
    rows = db.query("SELECT DISTINCT software_string FROM software "
                    "WHERE asset_uuid=? OR asset_uuid LIKE ?;", (uuid, f"%{uuid}%"))
    out = []
    for r in rows:
        s = r.get("software_string") or ""
        if _sw:
            name, ver = _sw.parse_software(s)
        else:
            name, ver = s, ""
        if name:
            out.append({"name": name, "version": ver, "raw": s})
    src = "table"
    if not out and _sw:
        # the software table doesn't cover every host — fall back to parsing the
        # enumeration plugins' stored output (22869 / 20811 / 83991) directly.
        try:
            for s in _sw.enum_plugin_strings(uuid):
                name, ver = _sw.parse_software(s)
                if name:
                    out.append({"name": name, "version": ver, "raw": s})
        except Exception:
            pass
        if out:
            src = "plugins"
    return out, src


def _certs_for(uuid):
    cc = _cols("certs")
    if not cc or "asset_uuid" not in cc:
        return []
    sel = [c for c in ("common_name", "not_valid_after", "signature_algorithm",
                       "key_length", "organization", "algorithm") if c in cc]
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
        # navi stores key_length as text like '1024 bits'; only RSA keys under 2048 are weak
        # (a 256-bit ECDSA key is strong) — the same rule as the Exposure Score's crypto factor
        m = re.search(r"\d+", str(c.get("key_length") or ""))
        kl = int(m.group(0)) if m else None
        kalg = str(c.get("algorithm") or sig).lower()
        rsa = "rsa" in kalg and "ecdsa" not in kalg
        c["weak"] = bool(("sha1" in sig or "sha-1" in sig or "md5" in sig) or (rsa and kl is not None and kl < 2048))
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


# --------------------------------------------------------------------------- #
#  At a glance — the numbers that decide what to do with this asset, each owned by
#  another Hound. Every block is best-effort: a missing table leaves its card empty.
# --------------------------------------------------------------------------- #
_GLANCE_HOUNDS = None
_CERT_SOON = 30


def _days_since(text):
    """Days since a navi timestamp ('2024-01-15T10:00:00.000Z', '2026/4/9 20:40 EDT')."""
    import datetime
    m = re.search(r"(\d{4})[-/](\d{1,2})[-/](\d{1,2})", str(text or ""))
    if not m:
        return None
    try:
        d = datetime.date(int(m.group(1)), int(m.group(2)), int(m.group(3)))
    except ValueError:
        return None
    return (datetime.date.today() - d).days


def _iso_date(text):
    m = re.search(r"(\d{4})[-/](\d{1,2})[-/](\d{1,2})", str(text or ""))
    return "%s-%02d-%02d" % (m.group(1), int(m.group(2)), int(m.group(3))) if m else None


def _glance(uuid, tags):
    global _GLANCE_HOUNDS
    g = {}
    vc = _cols("vulns")
    opened = ("lower(COALESCE(state,'open')) IN ('open','reopened')" if "state" in vc else "1=1")
    # ---- Exposure Score (Nemesis): this asset's score now + its rank from the cached estate snapshot
    try:
        from core import fused_score as _fs
        a = _fs.asset_score(uuid)
        if a:
            g["nemesis"] = {"score": a["score"], "band": a["band"]}
            try:
                from agents.fused_score import api as _fapi
                snap = _fapi.SNAP.state(extra=_fapi._extra(None))["snap"]
                if snap:
                    res = snap.get("result") or {}
                    rows = res.get("assets") or []
                    idx = next((i for i, r in enumerate(rows) if r.get("uuid") == uuid), None)
                    g["nemesis"].update({"of": res.get("total"), "rank": (idx + 1) if idx is not None else None,
                                         "beyond": len(rows) if idx is None else None})
            except Exception:
                pass
    except Exception:
        pass
    # ---- open critical / high, KEV, past-SLA, oldest open critical (open findings only)
    if vc and "asset_uuid" in vc:
        sev = "severity" if "severity" in vc else "''"
        xr = "xrefs" if "xrefs" in vc else "''"
        ff = "first_found" if "first_found" in vc else None
        pidc = "plugin_id" if "plugin_id" in vc else "''"
        try:
            from core import sla as _sla
            agesql = _sla._age_days(ff) if ff else None
        except Exception:
            _sla, agesql = None, None
        try:
            # age in fractional days, in SQL, exactly as the SLA page measures it
            rows = db.query(f"SELECT {sev} AS sev, {xr} AS xr, {pidc} AS pid"
                            f"{', ' + ff + ' AS ff' if ff else ''}{', ' + agesql + ' AS age' if agesql else ''} "
                            f"FROM vulns WHERE asset_uuid=? AND {opened}", (uuid,))
        except Exception:
            rows = []
        # findings on a route/path the operator marked Accepted / Mitigated / Ignored don't
        # count against SLA (core.sla.dispositions — the SLA page's rule)
        disp = set()
        try:
            if _sla is not None and db.scalar(
                    "SELECT 1 FROM tags WHERE asset_uuid=? AND " + tagname.sql_in("tag_key", _sla.OWNER_KEY)[0]
                    + " AND (" + " OR ".join("tag_value LIKE ?" for _ in _sla.DISPOSITIONS) + ") LIMIT 1",
                    (uuid, *tagname.names(_sla.OWNER_KEY), *("%: " + d for d in _sla.DISPOSITIONS))):
                con = db.connect()
                try:
                    disp = _sla.dispositions(con).get(uuid, set())
                finally:
                    con.close()
        except Exception:
            disp = set()
        try:
            from core import fused_score as _fs
            th = _fs._sla_days(None)
        except Exception:
            th = {"critical": 15, "high": 30}
        crit = high = kev = past = 0
        oldest = None
        for r in rows:
            sn = _sev_name(r.get("sev"))
            crit += sn == "critical"
            high += sn == "high"
            kev += "CISA-KNOWN-EXPLOITED" in str(r.get("xr") or "").upper()
            age = r.get("age") if agesql else (_days_since(r.get("ff")) if ff else None)
            try:
                age = float(age) if age is not None else None
            except (TypeError, ValueError):
                age = None
            if age is not None and sn in th and float(th[sn]) > 0 and age > float(th[sn]) \
                    and str(r.get("pid")) not in disp:
                past += 1
            if sn == "critical" and age is not None and (oldest is None or age > oldest[0]):
                oldest = (age, str(r.get("ff"))[:10])
        g["findings"] = {"critical": crit, "high": high, "kev": kev}
        g["sla"] = {"past": past, "windows": th, "first_found": bool(ff),
                    "oldest_critical_days": int(oldest[0]) if oldest else None,
                    "oldest_critical_since": oldest[1] if oldest else None}
        # EOL / unsupported software findings (Charon's signal), plus a Lifecycle tag
        try:
            pn = "plugin_name" if "plugin_name" in vc else "''"
            n = db.scalar(f"SELECT COUNT(DISTINCT plugin_id) FROM vulns WHERE asset_uuid=? AND {opened} AND "
                          f"(lower({pn}) LIKE '%unsupported%' OR lower({pn}) LIKE '%end of life%' OR "
                          f"lower({pn}) LIKE '%end-of-life%' OR lower({pn}) LIKE '%no longer supported%')", (uuid,))
        except Exception:
            n = None
        g["eol"] = {"findings": int(n or 0),
                    "tagged": any(str(t.get("category") or "").lower().startswith("lifecycle") for t in tags)}
        # last scan + credentialed (plugin 19506 — the most recent scan's own report)
        try:
            out = db.query("SELECT output FROM vulns WHERE asset_uuid=? AND plugin_id='19506' "
                           "ORDER BY last_found DESC LIMIT 1" if "last_found" in vc else
                           "SELECT output FROM vulns WHERE asset_uuid=? AND plugin_id='19506' LIMIT 1", (uuid,))
        except Exception:
            out = []
        if out:
            o = str(out[0].get("output") or "")
            ms = re.search(r"Scan Start Date\s*:\s*([^\n]+)", o)
            mn = re.search(r"Scan name\s*:\s*([^\n]+)", o)
            mc = re.search(r"Credentialed checks\s*:\s*(\w+)", o, re.I)
            g["scan"] = {"days": _days_since(ms.group(1)) if ms else None,
                         "date": _iso_date(ms.group(1)) if ms else None,
                         "name": mn.group(1).strip()[:60] if mn else None,
                         "credentialed": (mc.group(1).lower() == "yes") if mc else None}
    # ---- compliance (Minos / Tiresias)
    if "asset_uuid" in _cols("compliance"):
        try:
            r = db.query("SELECT SUM(CASE WHEN upper(status) LIKE 'PASS%' THEN 1 ELSE 0 END) p, "
                         "SUM(CASE WHEN upper(status) LIKE 'FAIL%' THEN 1 ELSE 0 END) f, COUNT(*) n "
                         "FROM compliance WHERE asset_uuid=?", (uuid,))[0]
            p_, f_ = int(r.get("p") or 0), int(r.get("f") or 0)
            if r.get("n"):
                g["compliance"] = {"pass_pct": round(100.0 * p_ / (p_ + f_), 1) if (p_ + f_) else None,
                                   "failed": f_, "checks": int(r.get("n") or 0)}
        except Exception:
            pass
    # ---- certificates: expired / expiring soon (same parser as the Certificates card)
    certs = _certs_for(uuid)
    if certs:
        import datetime
        today = datetime.date.today()
        days = []
        for c in certs:
            try:
                days.append((datetime.date.fromisoformat(str(c.get("expiry_iso"))[:10]) - today).days)
            except Exception:
                pass
        soon = [d for d in days if 0 <= d <= _CERT_SOON]
        g["certs"] = {"total": len(certs), "expired": sum(1 for d in days if d < 0), "soon": len(soon),
                      "soonest_days": min(soon) if soon else None, "window": _CERT_SOON}
    # ---- the pack: how many tagging Hounds have said something about this asset
    if _GLANCE_HOUNDS is None:
        _GLANCE_HOUNDS = sorted({m["hound"] for _, m in _TAG_INTEL if m.get("hound")}
                                | {m["hound"] for m in _FACET_INTEL.values() if m.get("hound")})
    seen = sorted({t.get("hound") for t in tags if t.get("hound")})
    g["pack"] = {"hounds": seen, "of": len(_GLANCE_HOUNDS)}
    return g


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
    software, software_source = _software_for(uuid)
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
    # ALL findings, worst-first (soft 5000 cap for payload sanity) — the page
    # paginates + severity-filters client-side so nobody has to leave for Tenable.
    top_vulns = sorted(vulns, key=_vk)[:5000]

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
            "ownership": _ownership(tags_raw),
            "identities": _identity.host_identities(uuid),
            "coverage": _coverage(tags),
            "top_cves": top_cves,
            "top_vulns": [{"plugin_id": v.get("plugin_id"), "plugin_name": v.get("plugin_name"),
                           "severity": _sev_name(v.get("severity")), "vpr": v.get("vpr"),
                           "family": v.get("plugin_family"),
                           "cves": _CVE_RE.findall(str(v.get("cves") or ""))} for v in top_vulns],
            "software": software[:200],
            "software_source": software_source,
            "certs": certs,
            "host": _host_profile(uuid),
            # so the widgets can tell "no data for this asset" apart from "table not
            # synced yet" and name the exact command to build it.
            "tables": {"software": bool(_cols("software")), "certs": bool(_cols("certs"))},
            "counts": {"vulns": len(vulns), "tags": len(tags),
                       "software": len(software), "certs": len(certs)},
            "glance": _glance(uuid, tags)}, 200


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


def output(p):
    """Return the stored plugin OUTPUT for one finding on one asset, straight from navi.db
    (``vulns.output``) — no navi CLI needed. Web/HTTP plugins (e.g. 24260) carry long output
    that often contains HTML, so we hand back the raw stored string plus an ``is_html`` hint
    and the instance count (a plugin can fire on several ports); the page renders it."""
    target = (p.get("target") or p.get("uuid") or "").strip()
    pid = str(p.get("plugin_id") or p.get("plugin") or "").strip()
    if not target or not pid:
        return {"ok": False, "error": "target (UUID/IP) and plugin_id required"}, 400
    row, how = _resolve(target)
    if not row:
        return {"ok": True, "found": False, "message": f"No asset in navi.db matches '{target}'."}, 200
    uuid = row.get("uuid")
    vc = _cols("vulns")
    if not vc or "output" not in vc:
        return {"ok": True, "found": False, "plugin_id": pid,
                "message": "navi.db has no vulns.output column yet — run `navi update vulns` "
                           "to pull plugin output, then re-run Argos."}, 200
    # port/protocol columns are optional — include them only if present so we can label instances.
    extra = [c for c in ("port", "protocol") if c in vc]
    sel = ", ".join(["plugin_name", "output"] + extra)
    try:
        rows = db.query(f"SELECT {sel} FROM vulns WHERE asset_uuid=? AND plugin_id=?;", (uuid, pid))
    except Exception as e:
        return {"ok": False, "error": str(e)}, 200
    rows = [r for r in rows if (r.get("output") or "").strip()]
    if not rows:
        return {"ok": True, "found": False, "plugin_id": pid,
                "message": "No stored output for this plugin on this asset. Try the live "
                           "`navi explore uuid` views below (needs navi on the server)."}, 200
    blocks = []
    for r in rows:
        loc = ""
        if r.get("port") not in (None, "", 0, "0"):
            loc = f"port {r.get('port')}" + (f"/{r.get('protocol')}" if r.get("protocol") else "")
        blocks.append({"where": loc, "output": (r.get("output") or "").strip()})
    joined = "\n\n".join((f"[{b['where']}]\n" if b["where"] else "") + b["output"] for b in blocks)
    is_html = bool(re.search(r"</?(?:table|thead|tbody|tr|td|th|div|span|p|br|pre|ul|ol|li|"
                             r"b|i|em|strong|h[1-6]|a|code|hr)\b", joined, re.I))
    return {"ok": True, "found": True, "plugin_id": pid,
            "plugin_name": rows[0].get("plugin_name"), "instances": len(rows),
            "is_html": is_html, "output": joined, "blocks": blocks}, 200


_HTML_START = re.compile(r"<!doctype html|<html[\s>]|<head[\s>]|<body[\s>]|<title[\s>]", re.I)


def _extract_html(output):
    """Pull a captured HTML document out of a plugin's text output (it sits below the
    HTTP headers). Mirrors the old asset-detail page's extractor."""
    if not output:
        return None
    m = _HTML_START.search(output)
    if not m:
        return None
    html = output[m.start():]
    end = html.lower().rfind("</html>")
    if end >= 0:
        html = html[:end + 7]
    html = html.strip()
    return html if len(html) > 20 else None


def webpages(p):
    """Findings on this asset whose stored output contains a captured web page — plugin
    24260 & other HTTP plugins record the HTTP response, including the page HTML. Returns
    each page's HTML so the Argos page can render it back in a locked sandbox (no scripts,
    no network). Read-only, straight from navi.db."""
    target = (p.get("target") or p.get("uuid") or "").strip()
    if not target:
        return {"ok": False, "error": "target (UUID/IP) required"}, 400
    row, _ = _resolve(target)
    if not row:
        return {"ok": True, "found": False, "pages": [], "message": f"No asset in navi.db matches '{target}'."}, 200
    uuid = row.get("uuid")
    vc = _cols("vulns")
    if not vc or "output" not in vc:
        return {"ok": True, "found": False, "pages": [],
                "message": "navi.db has no vulns.output column yet — run `navi update vulns`."}, 200
    extra = [c for c in ("url", "port", "protocol") if c in vc]
    sel = ", ".join(["plugin_id", "plugin_name", "output"] + extra)
    try:
        rows = db.query(f"SELECT {sel} FROM vulns WHERE asset_uuid=? AND output LIKE '%<%';", (uuid,))
    except Exception as e:
        return {"ok": False, "error": str(e)}, 200
    pages, seen = [], set()
    for r in rows:
        html = _extract_html(r.get("output") or "")
        if not html:
            continue
        pid = str(r.get("plugin_id") or "")
        key = (pid, r.get("port"))
        if key in seen:
            continue
        seen.add(key)
        loc = ""
        if r.get("port") not in (None, "", 0, "0"):
            loc = f"port {r.get('port')}" + (f"/{r.get('protocol')}" if r.get("protocol") else "")
        pages.append({"plugin_id": pid, "plugin_name": r.get("plugin_name") or "",
                      "url": r.get("url") or "", "where": loc, "html": html})
    pages.sort(key=lambda x: (x["plugin_id"], x["where"]))
    return {"ok": True, "found": True, "pages": pages}, 200


def run(p):
    return {"ok": True, "agent": _agent().meta(), "result": _agent().run()}, 200


ACTIONS = {"run": run, "lookup": lookup, "live": live, "output": output, "webpages": webpages}
