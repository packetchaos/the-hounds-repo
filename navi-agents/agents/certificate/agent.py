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
        iot = r.get("iot") or {}
        return {"failing_12mo": r.get("failing_count"),
                "issue_types": len(r.get("cert_issue_matrix") or []),
                "iot_devices": iot.get("IoT", 0),
                "cache_rows": iot.get("total", 0)}

    def _run(self, db_path: str | None) -> dict:
        """One STREAMED pass over certs ⋈ assets (build 455). Every number is computed exactly
        as before (same SQL, same row order, same per-(asset, expiry) dedupe), but the rows
        are written to the result store (core.payload) as they go instead of being kept in
        Python lists and shipped to the page: the page gets the decision data and pages the
        certificate / crown / IoT lists through the `drill` action. Memory: one dedupe key
        per in-scope (asset, date) pair + integer asset ids for the distinct counts."""
        from core import payload
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

        try:
            cc = {r["name"] for r in db.query('PRAGMA table_info("certs");', path=db_path)}
            ac = {r["name"] for r in db.query('PRAGMA table_info("assets");', path=db_path)}
        except Exception:
            cc, ac = set(), set()
        extra = "".join(f", c.{c}" for c in ("subject_name", "issuer_name", "not_valid_before") if c in cc)
        col = lambda c: ("c." + c) if c in cc else ("NULL AS " + c)
        cert_sql = ("SELECT c.asset_uuid, a.hostname, a.ip_address, " + col("common_name") + ", "
                    + col("organization") + ", " + col("organization_unit") + ", " + col("not_valid_after") + ", "
                    + col("signature_algorithm") + ", " + col("key_length") + extra
                    + (", a.acr" if "acr" in ac else "") +
                    " FROM certs c LEFT JOIN assets a ON a.uuid = c.asset_uuid;")

        # --- Heat map 2 source ---
        matrix = db.query(
            "SELECT plugin_id, plugin_name, COUNT(DISTINCT asset_uuid) AS asset_count "
            "FROM vulns WHERE plugin_name LIKE '%Certificate%' "
            "GROUP BY plugin_id, plugin_name ORDER BY asset_count DESC;", path=db_path)

        win0 = _month_add(today.year, today.month, -11)          # first month of the 12-month look-back
        win0_key = f"{win0[0]:04d}-{win0[1]:02d}"
        # timeline: older | last 12 months (expired) | next 12 months (failing)
        tl, tmap = [], {}
        older = {"key": "older", "label": "Older", "expired": 0, "failing": 0, "assets": set()}
        for n in range(-11, 13):
            yy, mm = _month_add(today.year, today.month, n)
            b = {"key": f"{yy:04d}-{mm:02d}", "label": datetime.date(yy, mm, 1).strftime("%b %Y"),
                 "expired": 0, "failing": 0, "assets": set(), "current": n == 0}
            tl.append(b); tmap[b["key"]] = b
        # heat map 1: 13 forward month buckets
        buckets = []
        y, m = today.year, today.month
        for _ in range(13):
            buckets.append({"key": f"{y:04d}-{m:02d}", "label": datetime.date(y, m, 1).strftime("%b %Y"),
                            "count": 0, "assets": 0})
            m += 1
            if m > 12:
                m = 1
                y += 1
        bmap = {b["key"]: b for b in buckets}

        ids = {}                                  # asset uuid -> small int (distinct counts)
        def aid(u):
            i = ids.get(u)
            if i is None:
                i = ids[u] = len(ids)
            return i
        S = {k: set() for k in ("all", "expired", "exp12", "expold", "failing", "d30", "d90", "crown",
                                "crown_exp", "weak", "self")}
        bucket_assets = {b["key"]: set() for b in buckets}
        C = dict(cert_rows=0, unparsed=0, expired=0, exp12=0, expold=0, failing=0, d30=0, d90=0, crown=0,
                 weak=0, self=0, weak_in=0, self_in=0)
        ages, cns = [], set()
        seen = set()
        cr = {}                                   # crown asset -> rollup (bounded by crown assets in scope)
        by_val = {}                               # tag value -> {first row, raws, assets(int set)}
        iot_seen, iot_n = set(), {"IoT": 0, "Application": 0, "Unknown": 0}
        W = payload.STORE.begin("certificate")
        W.section("certs"); W.section("crown"); W.section("iot")
        try:
            for r in db.iter(cert_sql, path=db_path, budget="job"):
                C["cert_rows"] += 1
                u = r.get("asset_uuid")
                S["all"].add(aid(u))
                weak = is_weak(r.get("signature_algorithm"), r.get("key_length"))
                selfs = is_self_signed(r)
                if weak:
                    C["weak"] += 1; S["weak"].add(aid(u))
                if selfs:
                    C["self"] += 1; S["self"].add(aid(u))
                if r.get("common_name"):
                    cns.add((r.get("common_name") or "").strip())
                # IoT / application cache (first row per (ip, vendor, product))
                dtype, vendor, product = classify(r["common_name"], r["organization"], r["organization_unit"])
                ik = (r["ip_address"], vendor, product)
                if ik not in iot_seen:
                    iot_seen.add(ik)
                    iot_n[dtype] = iot_n.get(dtype, 0) + 1
                    host = (r["hostname"] or "").strip() or "(none)"
                    W.add("iot", {"device_type": dtype, "vendor": vendor, "product": product,
                                  "ip": r["ip_address"], "hostname": host, "asset_uuid": u,
                                  "cert_cn": r["common_name"], "cert_org": r["organization"],
                                  "cert_ou": r["organization_unit"], "signature_algorithm": r["signature_algorithm"],
                                  "key_length": r["key_length"], "source_plugin": "10863"},
                          uid=u, flags=("t:" + dtype,), keys=(dtype, vendor),
                          text=" ".join(str(x or "") for x in (vendor, product, r["ip_address"], host, r["common_name"])))
                d = parse_not_after(r["not_valid_after"])
                if not d:
                    C["unparsed"] += 1
                    continue
                if not (d < today or today <= d <= end):
                    continue
                key = (u, d.toordinal())
                if key in seen:
                    continue
                seen.add(key)
                host = (r["hostname"] or "").strip() or "(none)"
                try:
                    acr = float(r.get("acr") or 0)
                except (TypeError, ValueError):
                    acr = 0.0
                crown = acr > CROWN_ACR
                iso = d.isoformat()
                days_left = (d - today).days
                status = "expired" if d < today else "failing"
                bucket = ("older" if iso[:7] < win0_key else "last12") if status == "expired" else None
                tv = d.strftime("%b-%d-%Y")
                row = {**r, "acr": acr or None, "crown": crown, "weak": weak, "self_signed": selfs,
                       "hostname": host, "expiry_iso": iso, "status": status, "tag_value": tv, "days_left": days_left}
                if bucket:
                    row["bucket"] = bucket
                ai = aid(u)
                if status == "expired":
                    C["expired"] += 1; S["expired"].add(ai); ages.append(-days_left)
                    if bucket == "last12":
                        C["exp12"] += 1; S["exp12"].add(ai)
                    else:
                        C["expold"] += 1; S["expold"].add(ai)
                else:
                    C["failing"] += 1; S["failing"].add(ai)
                    if days_left <= 30:
                        C["d30"] += 1; S["d30"].add(ai)
                    if days_left <= 90:
                        C["d90"] += 1; S["d90"].add(ai)
                    k = iso[:7]
                    if k in bmap:
                        bmap[k]["count"] += 1
                        bucket_assets[k].add(ai)
                if weak:
                    C["weak_in"] += 1
                if selfs:
                    C["self_in"] += 1
                b = tmap.get(iso[:7]) or (older if iso[:7] < win0_key else None)
                if b is not None:
                    b["expired" if status == "expired" else "failing"] += 1
                    b["assets"].add(ai)
                if crown:
                    C["crown"] += 1; S["crown"].add(ai)
                    if status == "expired":
                        S["crown_exp"].add(ai)
                    # position in the old `expired (newest first) + failing (soonest first)` list,
                    # so ties and the CN order come out exactly as before
                    pos = (0, _neg_iso(iso), C["cert_rows"]) if status == "expired" else (1, iso, C["cert_rows"])
                    c = cr.get(u)
                    if c is None or pos < c["_pos"]:
                        c = cr[u] = {"asset_uuid": u, "host": host, "ip": r["ip_address"], "acr": acr or None,
                                     "expired": 0, "failing": 0, "soonest": None, "_cns": [], "_pos": pos,
                                     **({k: c[k] for k in ("expired", "failing", "soonest", "_cns")} if c else {})}
                    c["expired" if status == "expired" else "failing"] += 1
                    if status != "expired" and (c["soonest"] is None or days_left < c["soonest"]):
                        c["soonest"] = days_left
                    if r["common_name"]:
                        c["_cns"].append((pos, r["common_name"]))
                v = by_val.get(tv)
                if v is None:
                    v = by_val[tv] = {"row": row, "raws": set(), "assets": set(), "order": len(by_val)}
                v["raws"].add(r["not_valid_after"])
                if u:
                    v["assets"].add(ai)
                flags = [status, bucket, "due30" if status == "failing" and days_left <= 30 else None,
                         "due90" if status == "failing" and days_left <= 90 else None,
                         "crown" if crown else None, "weak" if weak else None, "self" if selfs else None,
                         "m:" + iso[:7], "m:older" if bucket == "older" else None, "v:" + tv]
                # page order: closest to today first; expired before failing on a tie (stable)
                W.add("certs", row, uid=u, flags=flags, keys=(abs(days_left), 0 if status == "expired" else 1),
                      text=" ".join(str(x or "") for x in (host, r["ip_address"], r["common_name"], tv, iso)),
                      rk=tv)
            for c in cr.values():
                cn_l = []
                for _p, cn in sorted(c.pop("_cns")):
                    if cn not in cn_l:
                        cn_l.append(cn)
                c["cns"] = cn_l
            crown_l = sorted(sorted(cr.values(), key=lambda c: c["_pos"]),
                             key=lambda c: (-(c["acr"] or 0), -c["expired"],
                                            c["soonest"] if c["soonest"] is not None else 1e9))
            for c in crown_l:
                c.pop("_pos", None)
            for c in crown_l:
                W.add("crown", c, uid=c["asset_uuid"], text=" ".join(str(x or "") for x in (c["host"], c["ip"], " ".join(c["cns"]))))
            W.meta = {"window_end": end.isoformat()}
        except BaseException:
            W.close(ok=False)
            raise
        W.close()

        timeline = [{**older, "assets": len(older["assets"])}] + [{**b, "assets": len(b["assets"])} for b in tl]
        for b in buckets:
            b["assets"] = len(bucket_assets[b["key"]])
        metrics = {
            "cert_rows": C["cert_rows"], "cert_assets": len(S["all"]),
            "unparsed": C["unparsed"],
            "expired": C["expired"], "expired_assets": len(S["expired"]),
            "expired_12": C["exp12"], "expired_12_assets": len(S["exp12"]),
            "expired_older": C["expold"], "expired_older_assets": len(S["expold"]),
            "max_days_expired": max(ages) if ages else None,
            "median_days_expired": int(statistics.median(ages)) if ages else None,
            "failing": C["failing"], "failing_assets": len(S["failing"]),
            "due30": C["d30"], "due30_assets": len(S["d30"]), "due90": C["d90"], "due90_assets": len(S["d90"]),
            "crown": C["crown"], "crown_assets": len(S["crown"]),
            "crown_expired_assets": len(S["crown_exp"]),
            "weak": C["weak"], "weak_assets": len(S["weak"]),
            "weak_inscope": C["weak_in"],
            "self_signed": C["self"], "self_signed_assets": len(S["self"]),
            "self_signed_inscope": C["self_in"],
            "common_names": len(cns),
            "issue_plugins": len(matrix), "issue_assets": sum(m.get("asset_count") or 0 for m in matrix),
            "has_acr": "acr" in ac,
        }

        # --- tag actions (write manifest) — expired first (highest risk), then failing ---
        # The query DEFINES the set the page lists for each date: every certificate whose RAW
        # not_valid_after string parses to that date (each format navi.db stores — OpenSSL
        # 'Nov  4 …', ISO, slashed — listed verbatim), on an asset in navi.db. navi re-selects
        # the full set; the argument grows with distinct date strings, never with assets.
        vals = sorted(by_val.values(), key=lambda v: (0 if v["row"]["status"] == "expired" else 1,
                                                      _neg_iso(v["row"]["expiry_iso"]) if v["row"]["status"] == "expired"
                                                      else v["row"]["expiry_iso"], v["order"]))
        tag_actions = []
        for v in vals:
            r = v["row"]
            raws = sorted((x for x in v["raws"] if x is not None), key=str)
            inl = ",".join(repr(x) if isinstance(x, (int, float)) and not isinstance(x, bool)
                           else "'" + str(x).replace("'", "''") + "'" for x in raws)
            q = ("SELECT uuid AS asset_uuid FROM assets WHERE uuid IN (SELECT asset_uuid FROM certs "
                 f"WHERE not_valid_after IN ({inl}));") if inl else \
                "SELECT uuid AS asset_uuid FROM assets WHERE 0;"
            tag_actions.append({
                "category": "Cert failure", "value": r["tag_value"],
                "status": r["status"],
                "asset_uuid": r["asset_uuid"], "ip": r["ip_address"],
                "hostname": r["hostname"], "common_name": r["common_name"],
                "expiry": r["not_valid_after"], "days_left": r["days_left"],
                "query": q, "assets": len(v["assets"]),
                "tool_call": (f'navi enrich tag --c "{tagname.effective("Cert failure")}" --v "{r["tag_value"]}" '
                              f'--query "{q}"')})

        return {
            "generated": today.isoformat(),
            "window_start": today.isoformat(), "window_end": end.isoformat(),
            "asset_total": asset_total, "cert_rows": C["cert_rows"], "db_fresh": fresh,
            "failing_count": C["failing"], "expired_count": C["expired"],
            "heatmap_months": buckets, "cert_issue_matrix": matrix,
            "tag_actions": tag_actions,
            "timeline": timeline, "metrics": metrics,
            "crown": crown_l[:payload.TOP_MAX], "crown_total": len(crown_l),
            "iot": {"total": len(iot_seen), **iot_n},
            "lookback_start": win0_key,
            "run": W.run,
        }


def _neg_iso(iso):
    """Sort key that orders ISO dates descending inside an ascending sort."""
    return tuple(-ord(ch) for ch in iso)
