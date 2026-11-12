"""Scan Evaluations — reproduce `navi scan evaluate`, cleaned + interactive.

`navi scan evaluate` analyses plugin 19506 (Nessus Scan Information) from the local
navi.db and reports average scan time per asset by policy, by scanner, and by scan
name. This module computes the same breakdowns directly from navi.db (so it works in
the artifact too) and adds credential-failure coverage (plugin 104410).

Read-only. Tag writes go through navi (core.navi_cli):
  - problematic scanner IP  -> navi enrich tag --plugin 19506 --output "<ip>"
  - problematic scan policy  -> navi enrich tag --plugin 19506 --output "<policy>"
  - problematic scan (by id) -> navi enrich tag --scanid <id>
  - credential failures      -> navi enrich tag --plugin 104410
"""
import datetime
import re
import statistics

from core import db

SCAN_INFO_PLUGIN = "19506"
CRED_FAIL_PLUGIN = "104410"


def _field(text, label):
    m = re.search(r"(?im)^\s*" + re.escape(label) + r"\s*:\s*(.+?)\s*$", text or "")
    return m.group(1).strip() if m else ""


def _duration_sec(text):
    d = _field(text, "Scan duration")
    m = re.search(r"(\d+(?:\.\d+)?)\s*(sec|second|min|minute|hour|hr)?", d, re.I)
    if not m:
        return None
    v = float(m.group(1))
    u = (m.group(2) or "sec").lower()
    if u.startswith("min"):
        v *= 60
    elif u.startswith("hour") or u == "hr":
        v *= 3600
    return v


def _agg(buckets, overall_avg):
    """buckets: {key: {assets:set, durs:[]}} -> sorted list with flags."""
    out = []
    for key, b in buckets.items():
        if not key:
            continue
        durs = b["durs"]
        avg = statistics.mean(durs) if durs else 0
        out.append({"key": key, "assets": len(b["assets"]),
                    "avg_sec": round(avg, 1), "max_sec": round(max(durs), 1) if durs else 0,
                    "problematic": bool(durs) and overall_avg > 0 and avg > overall_avg * 1.5})
    out.sort(key=lambda x: (-x["avg_sec"], -x["assets"]))
    return out


# Credential-health plugins (Tenable "Target Credential Status/Issues" family + patch-assessment).
CRED_PLUGINS = {
    "104410": "failed",        # Target Credential Status – Failure for Provided Credentials
    "110385": "insufficient",  # Target Credential Issues – Insufficient Privilege
    "102094": "insufficient",  # SSH Commands Require Privilege Escalation
    "117885": "intermittent",  # Target Credential Issues – Intermittent Authentication Failure
    "110723": "nocreds",       # Target Credential Status – No Credentials Provided
    "141118": "ok",            # Target Credential Status – Valid Credentials Provided
    "110095": "ok",            # Target Credential Issues – No Issues Found
}
PATCH_PLUGINS = {"21745": "patch_failed",   # OS Security Patch Assessment Failed
                 "117886": "patch_na"}       # OS Security Patch Assessment Not Available
# worst first — an asset takes the worst state any plugin (or 19506) reports for it
STATUS_ORDER = ["failed", "insufficient", "intermittent", "uncredentialed", "ok", "unknown"]
FRESH_BUCKETS = [("0-7", 0, 7), ("8-30", 8, 30), ("31-90", 31, 90), ("90+", 91, 10 ** 6)]
SLOW_SEC = 3600            # an asset scan over an hour is "slow"
FEED_LAG_DAYS = 7          # scanner feed this far behind the newest feed seen = outdated
CROWN_ACR = 7
ROW_CAP = 20000            # asset rows returned to the page (metrics + tags always use every asset)


def _date(text):
    m = re.search(r"(\d{4})/(\d{1,2})/(\d{1,2})", text or "") or re.search(r"(\d{4})-(\d{1,2})-(\d{1,2})", text or "")
    if not m:
        return None
    try:
        return datetime.date(int(m.group(1)), int(m.group(2)), int(m.group(3)))
    except ValueError:
        return None


def _feed_date(text):
    m = re.match(r"(\d{4})(\d{2})(\d{2})", (text or "").strip())
    if not m:
        return None
    try:
        return datetime.date(int(m.group(1)), int(m.group(2)), int(m.group(3)))
    except ValueError:
        return None


def _yes(v):
    v = (v or "").strip().lower()
    return None if not v else v.startswith("yes")


def evaluate(db_path=None, keep_uuids=False, all_rows=False):
    today = datetime.date.today()
    vc = _cols("vulns", db_path)
    open_only = (" AND lower(COALESCE(v.state,'open')) IN ('open','reopened')" if "state" in vc else "")
    lf = ", v.last_found AS last_found" if "last_found" in vc else ""
    rows = db.query(
        f"SELECT v.asset_uuid, v.output{lf}, a.hostname, a.ip_address"
        + (", a.url AS url" if _has_col("assets", "url", db_path) else "")
        + f" FROM vulns v LEFT JOIN assets a ON a.uuid=v.asset_uuid "
        f"WHERE v.plugin_id='{SCAN_INFO_PLUGIN}' AND v.output IS NOT NULL AND v.output<>'';",
        path=db_path)
    by_scanner, by_policy, by_scan = {}, {}, {}
    all_durs = []
    latest = {}                                    # asset -> its most recent 19506 parse
    for i, r in enumerate(rows):
        if not i % 200:                            # the SQL budget can't stop Python parsing
            db.checkpoint("scan evaluation: 19506 parse")
        out = r.get("output") or ""
        u = r.get("asset_uuid")
        stype = _field(out, "Scan type")
        agent = "agent" in stype.lower()
        scanner = _field(out, "Scanner IP")
        if agent and scanner in ("127.0.0.1", "::1", ""):
            scanner = "Nessus Agent (on host)"
        policy = _field(out, "Scan policy used")
        scan = _field(out, "Scan name")
        dur = _duration_sec(out)
        cred = _yes(_field(out, "Credentialed checks"))
        start = _date(_field(out, "Scan Start Date")) or _date(str(r.get("last_found") or ""))
        rec = {"scanner": scanner, "policy": policy, "scan": scan, "dur": dur, "cred": cred, "start": start,
               "agent": agent, "type": stype or ("Agent" if agent else "Network"),
               "nessus": _field(out, "Nessus version"), "feed": _feed_date(_field(out, "Plugin feed version")),
               "safe": _yes(_field(out, "Safe checks")), "thorough": _yes(_field(out, "Thorough tests")),
               "host": (r.get("hostname") or "").strip() or r.get("ip_address") or "(none)",
               "ip": r.get("ip_address"), "url": r.get("url")}
        if dur is not None:
            all_durs.append(dur)
        for bucket, k in ((by_scanner, scanner), (by_policy, policy), (by_scan, scan)):
            if not k:
                continue
            b = bucket.setdefault(k, {"assets": set(), "durs": [], "cred": set(), "uncred": set(),
                                      "last": None, "versions": set(), "feed": None, "safe_off": set(),
                                      "thorough": set(), "agent": agent})
            if u:
                b["assets"].add(u)
                (b["cred"] if cred else b["uncred"] if cred is False else set()).add(u)
                if rec["safe"] is False:
                    b["safe_off"].add(u)
                if rec["thorough"]:
                    b["thorough"].add(u)
            if dur is not None:
                b["durs"].append(dur)
            if start and (b["last"] is None or start > b["last"]):
                b["last"] = start
            if rec["nessus"]:
                b["versions"].add(rec["nessus"])
            if rec["feed"] and (b["feed"] is None or rec["feed"] > b["feed"]):
                b["feed"] = rec["feed"]
        if u:
            cur = latest.get(u)
            if cur is None or (start and (cur["start"] is None or start > cur["start"])):
                latest[u] = rec
    overall_avg = statistics.mean(all_durs) if all_durs else 0
    newest_feed = max((b["feed"] for b in by_scanner.values() if b["feed"]), default=None)

    # credential coverage (kept for Alerts / Contract) — plugin 104410
    total_assets = db.scalar("SELECT COUNT(uuid) FROM assets", path=db_path) or 0
    a_url = (", v.url AS url" if _has_col("vulns", "url", db_path)
             else (", a.url AS url" if _has_col("assets", "url", db_path) else ""))
    cred = db.query(
        f"SELECT DISTINCT v.asset_uuid, a.hostname, a.ip_address{a_url} "
        f"FROM vulns v LEFT JOIN assets a ON a.uuid=v.asset_uuid "
        f"WHERE v.plugin_id='{CRED_FAIL_PLUGIN}'{open_only};", path=db_path)
    cred_assets = [{"asset_uuid": c.get("asset_uuid"),
                    "host": (c.get("hostname") or "").strip() or c.get("ip_address") or "(none)",
                    "ip": c.get("ip_address"), "url": c.get("url")} for c in cred if c.get("asset_uuid")]

    # ---- per-asset credential state from the credential-status plugin family
    pids = list(CRED_PLUGINS) + list(PATCH_PLUGINS)
    signals = {}
    try:
        for r in db.query("SELECT DISTINCT v.asset_uuid, v.plugin_id FROM vulns v WHERE v.plugin_id IN ("
                          + ",".join("'" + p + "'" for p in pids) + ")" + open_only, path=db_path):
            if r.get("asset_uuid"):
                signals.setdefault(r["asset_uuid"], set()).add(str(r["plugin_id"]))
    except Exception:
        pass
    amap = {}
    try:
        cols = _cols("assets", db_path)
        for a in db.query("SELECT uuid, hostname, ip_address" + (", acr" if "acr" in cols else "")
                          + (", url" if "url" in cols else "") + " FROM assets", path=db_path):
            amap[a["uuid"]] = a
    except Exception:
        pass

    universe = set(amap) | set(latest) | set(signals)
    assets = []
    for u in universe:
        rec = latest.get(u) or {}
        sig = signals.get(u, set())
        states = {CRED_PLUGINS[p] for p in sig if p in CRED_PLUGINS}
        if rec.get("cred") is True:
            states.add("ok")
        elif rec.get("cred") is False:
            states.add("uncredentialed")
        if "nocreds" in states:
            states.discard("nocreds"); states.add("uncredentialed")
        status = next((st for st in STATUS_ORDER if st in states), "unknown")
        if status == "uncredentialed" and "ok" in states and rec.get("cred") is not False:
            status = "ok"
        start = rec.get("start")
        age = (today - start).days if start else None
        fresh = "never" if not rec else ("unknown" if age is None else
                                          next(k for k, lo, hi in FRESH_BUCKETS if lo <= max(age, 0) <= hi))
        a = amap.get(u, {})
        try:
            acr = float(a.get("acr")) if a.get("acr") not in (None, "") else None
        except (TypeError, ValueError):
            acr = None
        assets.append({
            "asset_uuid": u,
            "host": (a.get("hostname") or "").strip() or a.get("ip_address") or rec.get("host") or "(none)",
            "ip": a.get("ip_address") or rec.get("ip"), "url": a.get("url") or rec.get("url"), "acr": acr,
            "status": status, "patch": ("failed" if "21745" in sig else "na" if "117886" in sig else ""),
            "fresh": fresh, "age_days": age, "last_scan": start.isoformat() if start else None,
            "scanner": rec.get("scanner") or "", "policy": rec.get("policy") or "", "scan": rec.get("scan") or "",
            "type": ("Agent" if rec.get("agent") else ("Network" if rec else "")),
            "dur": round(rec["dur"], 1) if rec.get("dur") is not None else None,
            "crown": acr is not None and acr >= CROWN_ACR})
    assets.sort(key=lambda x: (STATUS_ORDER.index(x["status"]), -(x["acr"] or 0), x["host"]))

    def ids(pred):
        return {x["asset_uuid"] for x in assets if pred(x)}
    sets = {
        "status:failed": ids(lambda x: x["status"] == "failed"),
        "status:insufficient": ids(lambda x: x["status"] == "insufficient"),
        "status:intermittent": ids(lambda x: x["status"] == "intermittent"),
        "status:uncredentialed": ids(lambda x: x["status"] == "uncredentialed"),
        "patch:failed": ids(lambda x: x["patch"] == "failed"),
        "fresh:31-90": ids(lambda x: x["fresh"] == "31-90"),
        "fresh:90+": ids(lambda x: x["fresh"] == "90+"),
        "fresh:never": ids(lambda x: x["fresh"] == "never"),
        "slow": ids(lambda x: (x["dur"] or 0) > SLOW_SEC),
        "crown:blind": ids(lambda x: x["crown"] and (x["status"] in ("failed", "insufficient", "intermittent", "uncredentialed")
                                                      or x["fresh"] in ("90+", "never"))),
    }
    st_n = {k: sum(1 for x in assets if x["status"] == k) for k in STATUS_ORDER}
    fr_n = {k: sum(1 for x in assets if x["fresh"] == k) for k in [b[0] for b in FRESH_BUCKETS] + ["never", "unknown"]}
    scanned = [x for x in assets if x["fresh"] != "never"]
    crown = [x for x in assets if x["crown"]]

    def dims(buckets, kind):
        out = _agg(buckets, overall_avg)
        tot = sum(len(b["assets"]) for b in buckets.values()) or 1
        for d in out:
            b = buckets[d["key"]]
            known = len(b["cred"]) + len(b["uncred"])
            d["share_pct"] = round(100.0 * len(b["assets"]) / tot, 1)
            d["cred_pct"] = round(100.0 * len(b["cred"]) / known, 1) if known else None
            d["last_scan"] = b["last"].isoformat() if b["last"] else None
            d["agent"] = b["agent"]
            if kind == "scanner":
                d["versions"] = sorted(b["versions"])
                d["feed"] = b["feed"].isoformat() if b["feed"] else None
                d["feed_lag_days"] = (newest_feed - b["feed"]).days if (newest_feed and b["feed"]) else None
                d["outdated"] = bool(d["feed_lag_days"] is not None and d["feed_lag_days"] > FEED_LAG_DAYS)
            if kind == "policy":
                d["safe_off"] = len(b["safe_off"]); d["thorough"] = len(b["thorough"])
        return out

    scanners, policies, scans = dims(by_scanner, "scanner"), dims(by_policy, "policy"), dims(by_scan, "scan")
    slowest = sorted((x for x in assets if x["dur"] is not None), key=lambda x: -x["dur"])[:50]
    metrics = {
        "assets": len(universe), "scanned": len(scanned), "never": fr_n["never"],
        "agent": sum(1 for x in scanned if x["type"] == "Agent"), "network": sum(1 for x in scanned if x["type"] == "Network"),
        "fresh": fr_n, "status": st_n,
        "cred_ok_pct": round(100.0 * st_n["ok"] / len(scanned), 1) if scanned else None,
        "blind": st_n["failed"] + st_n["insufficient"] + st_n["intermittent"] + st_n["uncredentialed"],
        "patch_failed": len(sets["patch:failed"]), "patch_na": sum(1 for x in assets if x["patch"] == "na"),
        "stale_30": fr_n["31-90"] + fr_n["90+"], "stale_90": fr_n["90+"],
        "crown": len(crown), "crown_blind": len(sets["crown:blind"]),
        "crown_uncred": sum(1 for x in crown if x["status"] in ("failed", "insufficient", "intermittent", "uncredentialed")),
        "crown_stale": sum(1 for x in crown if x["fresh"] in ("90+", "never")),
        "overall_avg_sec": round(overall_avg, 1), "slow": len(sets["slow"]),
        "slow_scanners": sum(1 for d in scanners if d["problematic"]),
        "slow_policies": sum(1 for d in policies if d["problematic"]),
        "slow_scans": sum(1 for d in scans if d["problematic"]),
        "scanner_count": sum(1 for d in scanners if not d["agent"]),
        "outdated_scanners": sum(1 for d in scanners if d.get("outdated")),
        "versions": len({v for d in scanners for v in d.get("versions", [])}),
        "newest_feed": newest_feed.isoformat() if newest_feed else None,
        "safe_off": len({u for b in by_policy.values() for u in b["safe_off"]}),
        "top_scanner_share": max((d["share_pct"] for d in scanners if not d["agent"]), default=None),
    }
    res = {
        "scanners": scanners, "policies": policies, "scans": scans,
        "overall_avg_sec": round(overall_avg, 1),
        "scan_info_assets": len({u for b in by_scanner.values() for u in b["assets"]}),
        "credential": {"total_assets": total_assets,
                       "cred_fail_assets": len(cred_assets),
                       "ok_assets": max(0, total_assets - len(cred_assets)),
                       "assets": cred_assets,
                       "plugin": CRED_FAIL_PLUGIN},
        "metrics": metrics, "assets": assets if all_rows else assets[:ROW_CAP],
        "assets_truncated": (not all_rows) and len(assets) > ROW_CAP,
        "slowest": slowest, "slow_sec": SLOW_SEC, "feed_lag_days": FEED_LAG_DAYS, "today": today.isoformat(),
    }
    if keep_uuids:
        res["_sets"] = sets
        res["_dim_uuids"] = {"scanner": {k: b["assets"] for k, b in by_scanner.items()},
                             "policy": {k: b["assets"] for k, b in by_policy.items()},
                             "scan": {k: b["assets"] for k, b in by_scan.items()}}
    return res


def _cols(table, db_path=None):
    try:
        return {r["name"] for r in db.query(f'PRAGMA table_info("{table}");', path=db_path)}
    except Exception:
        return set()


def _has_col(table, col, db_path=None):
    try:
        return any(r["name"] == col for r in db.query(f'PRAGMA table_info("{table}");', path=db_path))
    except Exception:
        return False
