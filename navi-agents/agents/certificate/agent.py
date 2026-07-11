"""Certificate Agent — three actions, all driven from live navi.db reads.

  1. Identify assets with certs failing in the next 12 months and produce the
     `Cert failure : <Mon>-<dd>-<yyyy>` tag actions (exact expiry date per cert).
  2. Build two heat maps: a 12-month failure timeline, and cert-issue plugins
     x distinct affected assets.
  3. Cache application names and IoT/appliance devices fingerprinted from certs.

Reads use core.db (read-only sqlite3). Tag writes are executed separately by
the service layer via core.navi_cli (gated).
"""
import datetime
import re

from core import db
from core.agents.base import Agent

# The agent's DEFAULT static reasoning prompt — shown (editable) in the HITL page.
DEFAULT_PROMPT = """You are the Certificate Lifecycle Agent for a Tenable / navi deployment.

You are given certificates that are ALREADY EXPIRED or will FAIL (expire) within the
next 12 months. Each is mapped to its asset, carries a "status" of "expired" or
"failing", and an exact-date tag value of the form "Cert failure:<Mon>-<DD>-<YYYY>".

Act like a security engineer triaging certificate risk. For each certificate, decide
whether to TAG it now and assign a priority (high / med / low), reasoning about:
  - status: already-expired certs are the highest priority (active outage/risk),
  - how soon a failing cert expires (sooner = higher priority),
  - weak crypto (MD5 / SHA-1 signatures, RSA keys < 2048 bits),
  - whether it looks internet-facing, and CA vs leaf certificate,
  - obvious irrelevance (lab / test hosts, certificates already rotated).

Default to tagging unless a certificate is clearly out of scope. Follow any extra
instruction the operator adds above (e.g. "only tag certs that have expired" should
TAG every status=="expired" cert and SKIP the rest).

Return ONLY JSON, no prose, in exactly this shape:
{"assessment":"<2-4 sentence triage summary for an operator>",
 "tag":[{"value":"<exact tag value from the list>","priority":"high|med|low","why":"<=12 words>"}],
 "skip":[{"value":"<exact tag value from the list>","why":"<=12 words>"}]}

Never invent a value that is not in the provided list."""

MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
     "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}
MABBR = list(MONTHS.keys())


def parse_not_after(s: str):
    """Parse a cert expiry in ANY of navi.db's formats (OpenSSL / ISO / epoch / …).
    'Apr 03 16:07:23 2027 GMT' -> date(2027,4,3); '2027-04-03T..' -> date(2027,4,3)."""
    from core.certdates import parse_cert_date
    return parse_cert_date(s)


def classify(cn: str, org: str, ou: str):
    text = f"{cn} {org} {ou}".lower()
    rules = [
        ("IoT", "Google", "Chromecast (media streamer)", ["chromecast", "google inc"]),
        ("IoT", "Buffalo", "TeraStation NAS", ["buffalo", "terastation"]),
        ("IoT", "Netgate/pfSense", "pfSense firewall appliance", ["pfsense"]),
        ("IoT", "Samsung", "Smart TV / Visual Display", ["smartviewsdk", "samsung", "visual display"]),
        ("IoT", "Ubiquiti", "UniFi/Ubiquiti camera", ["ubnt", "ubiquiti", "camera"]),
        ("Application", "Tenable", "Nessus / SecurityCenter", ["nessus", "tenable"]),
        ("Application", "Canonical", "Kubernetes / Ubuntu service", ["canonical", "10.152.183"]),
        ("Application", "VMware", "ESXi / vSphere", ["vmware", "esx"]),
        ("Application", "Apache Friends", "XAMPP / Apache", ["apache friends"]),
    ]
    for dtype, vendor, product, keys in rules:
        if any(k in text for k in keys):
            return dtype, vendor, product
    return "Unknown", "Unknown", cn or "(unknown)"


class CertificateAgent(Agent):
    id = "certificate"
    name = "Certificate Agent"
    icon = "🔐"
    description = ("Tags 12-month cert failures, builds two heat maps, and caches "
                   "IoT/app devices fingerprinted from certificates.")

    def summary(self) -> dict:
        if not self.result:
            return {"failing_12mo": None, "iot_devices": None}
        r = self.result
        return {"failing_12mo": len(r["twelve_month"]),
                "issue_types": len(r["cert_issue_matrix"]),
                "iot_devices": sum(1 for c in r["iot_app_cache"] if c["device_type"] == "IoT"),
                "cache_rows": len(r["iot_app_cache"])}

    def _run(self, db_path: str | None) -> dict:
        today = datetime.date.today()
        end = today.replace(year=today.year + 1)

        # --- meta ---
        asset_total = db.scalar("SELECT count(uuid) FROM assets;", path=db_path)
        try:
            fresh = db.scalar("SELECT MAX(last_found) FROM vulns;", path=db_path)
        except Exception:
            fresh = None

        # --- Action 1 + 3 source: certs joined to assets ---
        certs = db.query(
            "SELECT c.asset_uuid, a.hostname, a.ip_address, c.common_name, "
            "c.organization, c.organization_unit, c.not_valid_after, "
            "c.signature_algorithm, c.key_length "
            "FROM certs c LEFT JOIN assets a ON a.uuid = c.asset_uuid;", path=db_path)

        # --- Heat map 2 source ---
        matrix = db.query(
            "SELECT plugin_id, plugin_name, COUNT(DISTINCT asset_uuid) AS asset_count "
            "FROM vulns WHERE plugin_name LIKE '%Certificate%' "
            "GROUP BY plugin_id, plugin_name ORDER BY asset_count DESC;", path=db_path)

        # --- Action 1: failing in next 12 months ---
        twelve, expired, seen = [], [], set()
        for r in certs:
            d = parse_not_after(r["not_valid_after"])
            if not d:
                continue
            host = (r["hostname"] or "").strip() or "(none)"
            if today <= d <= end:
                key = (r["asset_uuid"], d.isoformat())
                if key in seen:
                    continue
                seen.add(key)
                twelve.append({**r, "hostname": host, "expiry_iso": d.isoformat(),
                               "status": "failing",
                               "tag_value": d.strftime("%b-%d-%Y"),
                               "days_left": (d - today).days})
            elif d < today:
                key = (r["asset_uuid"], d.isoformat())
                if key in seen:
                    continue
                seen.add(key)
                expired.append({**r, "hostname": host, "expiry_iso": d.isoformat(),
                                "status": "expired",
                                "tag_value": d.strftime("%b-%d-%Y"),
                                "days_left": (d - today).days})  # negative = days ago
        twelve.sort(key=lambda x: x["expiry_iso"])
        expired.sort(key=lambda x: x["expiry_iso"], reverse=True)  # most-recent expiry first

        # --- Heat map 1: 13 forward month buckets ---
        buckets = []
        y, m = today.year, today.month
        for _ in range(13):
            buckets.append({"key": f"{y:04d}-{m:02d}",
                            "label": datetime.date(y, m, 1).strftime("%b %Y"),
                            "count": 0, "assets": []})
            m += 1
            if m > 12:
                m = 1
                y += 1
        bmap = {b["key"]: b for b in buckets}
        for r in twelve:
            k = r["expiry_iso"][:7]
            if k in bmap:
                bmap[k]["count"] += 1
                bmap[k]["assets"].append({"ip": r["ip_address"], "cn": r["common_name"],
                                          "date": r["not_valid_after"], "tag": r["tag_value"],
                                          "asset_uuid": r["asset_uuid"], "hostname": r["hostname"],
                                          "days_left": r["days_left"]})

        # --- Action 3: IoT / application cache ---
        cache = {}
        for r in certs:
            dtype, vendor, product = classify(r["common_name"], r["organization"],
                                              r["organization_unit"])
            key = (r["ip_address"], vendor, product)
            if key not in cache:
                cache[key] = {"device_type": dtype, "vendor": vendor, "product": product,
                              "ip": r["ip_address"], "hostname": (r["hostname"] or "").strip() or "(none)",
                              "asset_uuid": r["asset_uuid"], "cert_cn": r["common_name"],
                              "cert_org": r["organization"], "cert_ou": r["organization_unit"],
                              "signature_algorithm": r["signature_algorithm"],
                              "key_length": r["key_length"], "source_plugin": "10863"}
        cache_list = sorted(cache.values(), key=lambda x: (x["device_type"], x["vendor"]))

        # --- tag actions (write manifest) — expired first (highest risk), then failing ---
        tag_actions = []
        seen_val = set()
        for r in expired + twelve:
            if r["tag_value"] in seen_val:
                continue
            seen_val.add(r["tag_value"])
            # Build the tag query to match this expiry DATE in whatever format
            # navi.db stores not_valid_after (OpenSSL / ISO / slashed), so tagging
            # works regardless of source format.
            raw = r["not_valid_after"] or ""
            _d = datetime.date.fromisoformat(r["expiry_iso"])
            if re.match(r"[A-Za-z]{3}\s", raw):                 # OpenSSL 'Jun 24 .. 2026'
                q = (f"SELECT asset_uuid FROM certs WHERE not_valid_after "
                     f"LIKE '{raw[:6]}%{r['expiry_iso'][:4]}%';")
            elif re.match(r"\d{4}-\d{1,2}-\d{1,2}", raw):        # ISO '2026-06-24..'
                q = (f"SELECT asset_uuid FROM certs WHERE not_valid_after "
                     f"LIKE '{_d.strftime('%Y-%m-%d')}%';")
            elif re.match(r"\d{4}/\d{1,2}/\d{1,2}", raw):        # '2026/06/24..'
                q = (f"SELECT asset_uuid FROM certs WHERE not_valid_after "
                     f"LIKE '{_d.strftime('%Y/%m/%d')}%';")
            else:                                               # unknown → exact match
                q = ("SELECT asset_uuid FROM certs WHERE not_valid_after = '"
                     + raw.replace("'", "''") + "';")
            tag_actions.append({
                "category": "Cert failure", "value": r["tag_value"],
                "status": r["status"],
                "asset_uuid": r["asset_uuid"], "ip": r["ip_address"],
                "hostname": r["hostname"], "common_name": r["common_name"],
                "expiry": r["not_valid_after"], "days_left": r["days_left"],
                "query": q,
                "tool_call": (f'navi enrich tag --c "Cert failure" --v "{r["tag_value"]}" '
                              f'--query "{q}"')})

        return {
            "generated": today.isoformat(),
            "window_start": today.isoformat(), "window_end": end.isoformat(),
            "asset_total": asset_total, "cert_rows": len(certs), "db_fresh": fresh,
            "twelve_month": twelve, "expired": expired,
            "failing_count": len(twelve), "expired_count": len(expired),
            "heatmap_months": buckets, "cert_issue_matrix": matrix,
            "iot_app_cache": cache_list, "tag_actions": tag_actions,
        }
