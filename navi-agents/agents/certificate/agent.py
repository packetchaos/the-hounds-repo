"""Certificate Agent — deterministic, driven from live navi.db reads.

  1. Find every certificate that has EXPIRED (bucketed by month over the last 12
     months, plus everything older than that) or will FAIL within the next 12 months,
     and produce the `Cert failure : <Mon>-<dd>-<yyyy>` tag actions (exact expiry date).
  2. Build the expiry timeline (older | 12 past months | 12 future months), metrics
     (crown jewels, weak crypto, self-signed, how long expired), and the cert-issue
     plugin matrix.
  3. Cache application names and IoT/appliance devices fingerprinted from certs.

No free-form LLM reasoning here — ad-hoc questions go through the MCP. Reads use
core.db (read-only sqlite3). Tag writes go through core.navi_cli (gated).
"""
import datetime
import re
import statistics

from core import db, tagname
from core.agents.base import Agent

CROWN_ACR = 7
_EC = re.compile(r"ecdsa|elliptic|\bec\b", re.I)
_WEAK_SIG = re.compile(r"md5|sha-?1(?!\d)", re.I)


def key_bits(v):
    m = re.search(r"\d+", str(v or ""))
    return int(m.group()) if m else 0


def is_weak(sig, key_length):
    kb = key_bits(key_length)
    return bool(_WEAK_SIG.search(sig or "")) or (0 < kb < 2048 and not _EC.search(sig or ""))


def is_self_signed(r):
    subj, iss = (r.get("subject_name") or "").strip(), (r.get("issuer_name") or "").strip()
    if subj and iss:
        return subj == iss
    cn = (r.get("common_name") or "").strip()
    return bool(cn and iss and ("CN=" + cn) in iss and iss.count("CN=") == 1 and cn in subj)


def _month_add(y, m, n):
    m0 = (y * 12 + (m - 1)) + n
    return m0 // 12, m0 % 12 + 1


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
    description = ("Finds expired certificates (by month, last 12 months, and older) and "
                   "those failing in the next 12 months, tags their assets by expiry date, "
                   "and caches IoT/app devices fingerprinted from certificates.")

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
        try:
            end = today.replace(year=today.year + 1)
        except ValueError:                       # Feb 29 → Feb 28 next year
            end = today.replace(year=today.year + 1, day=28)

        # --- meta ---
        asset_total = db.scalar("SELECT count(uuid) FROM assets;", path=db_path)
        try:
            fresh = db.scalar("SELECT MAX(last_found) FROM vulns;", path=db_path)
        except Exception:
            fresh = None

        # --- Action 1 + 3 source: certs joined to assets ---
        try:
            cc = {r["name"] for r in db.query('PRAGMA table_info("certs");', path=db_path)}
            ac = {r["name"] for r in db.query('PRAGMA table_info("assets");', path=db_path)}
        except Exception:
            cc, ac = set(), set()
        extra = "".join(f", c.{c}" for c in ("subject_name", "issuer_name", "not_valid_before") if c in cc)
        # older/leaner navi.db exports have no organization columns — select NULL instead of failing
        col = lambda c: ("c." + c) if c in cc else ("NULL AS " + c)
        certs = db.query(
            "SELECT c.asset_uuid, a.hostname, a.ip_address, " + col("common_name") + ", "
            + col("organization") + ", " + col("organization_unit") + ", " + col("not_valid_after") + ", "
            + col("signature_algorithm") + ", " + col("key_length") + extra
            + (", a.acr" if "acr" in ac else "") +
            " FROM certs c LEFT JOIN assets a ON a.uuid = c.asset_uuid;", path=db_path)

        # --- Heat map 2 source ---
        matrix = db.query(
            "SELECT plugin_id, plugin_name, COUNT(DISTINCT asset_uuid) AS asset_count "
            "FROM vulns WHERE plugin_name LIKE '%Certificate%' "
            "GROUP BY plugin_id, plugin_name ORDER BY asset_count DESC;", path=db_path)

        # --- Action 1: failing in next 12 months ---
        twelve, expired, seen, unparsed = [], [], set(), 0
        for r in certs:
            d = parse_not_after(r["not_valid_after"])
            if not d:
                unparsed += 1
                continue
            host = (r["hostname"] or "").strip() or "(none)"
            try:
                acr = float(r.get("acr") or 0)
            except (TypeError, ValueError):
                acr = 0.0
            r = {**r, "acr": acr or None, "crown": acr > CROWN_ACR,
                 "weak": is_weak(r.get("signature_algorithm"), r.get("key_length")),
                 "self_signed": is_self_signed(r)}
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

        # --- expiry timeline: older | last 12 months (expired) | next 12 months (failing) ---
        win0 = _month_add(today.year, today.month, -11)          # first month of the 12-month look-back
        win0_key = f"{win0[0]:04d}-{win0[1]:02d}"
        tl, tmap = [], {}
        older = {"key": "older", "label": "Older", "expired": 0, "failing": 0, "assets": set()}
        for n in range(-11, 13):
            yy, mm = _month_add(today.year, today.month, n)
            b = {"key": f"{yy:04d}-{mm:02d}", "label": datetime.date(yy, mm, 1).strftime("%b %Y"),
                 "expired": 0, "failing": 0, "assets": set(), "current": n == 0}
            tl.append(b); tmap[b["key"]] = b
        for r in expired + twelve:
            k = r["expiry_iso"][:7]
            b = tmap.get(k) or (older if k < win0_key else None)
            if b is None:
                continue
            b["expired" if r["status"] == "expired" else "failing"] += 1
            b["assets"].add(r["asset_uuid"])
        timeline = [{**older, "assets": len(older["assets"])}] + [{**b, "assets": len(b["assets"])} for b in tl]
        for r in expired:
            r["bucket"] = "older" if r["expiry_iso"][:7] < win0_key else "last12"

        # --- metrics ---
        inscope = expired + twelve
        A = lambda rows: len({x["asset_uuid"] for x in rows})
        exp12 = [r for r in expired if r["bucket"] == "last12"]
        expold = [r for r in expired if r["bucket"] == "older"]
        d30 = [r for r in twelve if r["days_left"] <= 30]
        d90 = [r for r in twelve if r["days_left"] <= 90]
        crown_rows = [r for r in inscope if r["crown"]]
        weak_all = [r for r in certs if is_weak(r.get("signature_algorithm"), r.get("key_length"))]
        self_all = [r for r in certs if is_self_signed(r)]
        ages = [-r["days_left"] for r in expired]
        metrics = {
            "cert_rows": len(certs), "cert_assets": len({r["asset_uuid"] for r in certs}),
            "unparsed": unparsed,
            "expired": len(expired), "expired_assets": A(expired),
            "expired_12": len(exp12), "expired_12_assets": A(exp12),
            "expired_older": len(expold), "expired_older_assets": A(expold),
            "max_days_expired": max(ages) if ages else None,
            "median_days_expired": int(statistics.median(ages)) if ages else None,
            "failing": len(twelve), "failing_assets": A(twelve),
            "due30": len(d30), "due30_assets": A(d30), "due90": len(d90), "due90_assets": A(d90),
            "crown": len(crown_rows), "crown_assets": A(crown_rows),
            "crown_expired_assets": A([r for r in crown_rows if r["status"] == "expired"]),
            "weak": len(weak_all), "weak_assets": len({r["asset_uuid"] for r in weak_all}),
            "weak_inscope": sum(1 for r in inscope if r["weak"]),
            "self_signed": len(self_all), "self_signed_assets": len({r["asset_uuid"] for r in self_all}),
            "self_signed_inscope": sum(1 for r in inscope if r["self_signed"]),
            "common_names": len({(r.get("common_name") or "").strip() for r in certs if r.get("common_name")}),
            "issue_plugins": len(matrix), "issue_assets": sum(m.get("asset_count") or 0 for m in matrix),
            "has_acr": "acr" in ac,
        }
        cr = {}
        for r in crown_rows:
            c = cr.setdefault(r["asset_uuid"], {"asset_uuid": r["asset_uuid"], "host": r["hostname"], "ip": r["ip_address"],
                                                "acr": r["acr"], "expired": 0, "failing": 0, "soonest": None, "cns": []})
            c[r["status"] if r["status"] == "expired" else "failing"] += 1
            if r["status"] != "expired" and (c["soonest"] is None or r["days_left"] < c["soonest"]):
                c["soonest"] = r["days_left"]
            if r["common_name"] and r["common_name"] not in c["cns"]:
                c["cns"].append(r["common_name"])
        crown = sorted(cr.values(), key=lambda c: (-(c["acr"] or 0), -c["expired"], c["soonest"] if c["soonest"] is not None else 1e9))

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
        # The query selects the EXACT assets the page lists for each date (by uuid), so every
        # raw date format navi.db stores (OpenSSL 'Nov  4 …', ISO, slashed) is covered.
        tag_actions = []
        by_val = {}
        for r in expired + twelve:
            if r.get("asset_uuid"):
                by_val.setdefault(r["tag_value"], set()).add(r["asset_uuid"])
        seen_val = set()
        for r in expired + twelve:
            if r["tag_value"] in seen_val:
                continue
            seen_val.add(r["tag_value"])
            inl = ",".join("'" + str(u).replace("'", "''") + "'" for u in sorted(by_val.get(r["tag_value"], ())))
            q = f"SELECT uuid AS asset_uuid FROM assets WHERE uuid IN ({inl});" if inl else \
                "SELECT uuid AS asset_uuid FROM assets WHERE 0;"
            tag_actions.append({
                "category": "Cert failure", "value": r["tag_value"],
                "status": r["status"],
                "asset_uuid": r["asset_uuid"], "ip": r["ip_address"],
                "hostname": r["hostname"], "common_name": r["common_name"],
                "expiry": r["not_valid_after"], "days_left": r["days_left"],
                "query": q, "assets": len(by_val.get(r["tag_value"], ())),
                "tool_call": (f'navi enrich tag --c "{tagname.effective("Cert failure")}" --v "{r["tag_value"]}" '
                              f'--query "{q}"')})

        return {
            "generated": today.isoformat(),
            "window_start": today.isoformat(), "window_end": end.isoformat(),
            "asset_total": asset_total, "cert_rows": len(certs), "db_fresh": fresh,
            "twelve_month": twelve, "expired": expired,
            "failing_count": len(twelve), "expired_count": len(expired),
            "heatmap_months": buckets, "cert_issue_matrix": matrix,
            "iot_app_cache": cache_list, "tag_actions": tag_actions,
            "timeline": timeline, "metrics": metrics, "crown": crown,
            "lookback_start": win0_key,
        }
