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


def evaluate(db_path=None):
    rows = db.query(
        f"SELECT v.asset_uuid, v.output, a.hostname, a.ip_address"
        + (", a.url AS url" if _has_col("assets", "url", db_path) else "")
        + f" FROM vulns v LEFT JOIN assets a ON a.uuid=v.asset_uuid "
        f"WHERE v.plugin_id='{SCAN_INFO_PLUGIN}' AND v.output IS NOT NULL AND v.output<>'';",
        path=db_path)
    by_scanner, by_policy, by_scan = {}, {}, {}
    all_durs = []
    for r in rows:
        out = r.get("output") or ""
        u = r.get("asset_uuid")
        scanner = _field(out, "Scanner IP")
        policy = _field(out, "Scan policy used")
        scan = _field(out, "Scan name")
        dur = _duration_sec(out)
        if dur is not None:
            all_durs.append(dur)
        for bucket, k in ((by_scanner, scanner), (by_policy, policy), (by_scan, scan)):
            if not k:
                continue
            b = bucket.setdefault(k, {"assets": set(), "durs": []})
            if u:
                b["assets"].add(u)
            if dur is not None:
                b["durs"].append(dur)
    overall_avg = statistics.mean(all_durs) if all_durs else 0

    # credential coverage
    total_assets = db.scalar("SELECT COUNT(uuid) FROM assets", path=db_path) or 0
    # plugin 104410 involved → prefer the finding URL (vulns.url); fall back to assets.url
    a_url = (", v.url AS url" if _has_col("vulns", "url", db_path)
             else (", a.url AS url" if _has_col("assets", "url", db_path) else ""))
    cred = db.query(
        f"SELECT DISTINCT v.asset_uuid, a.hostname, a.ip_address{a_url} "
        f"FROM vulns v LEFT JOIN assets a ON a.uuid=v.asset_uuid "
        f"WHERE v.plugin_id='{CRED_FAIL_PLUGIN}';", path=db_path)
    cred_assets = [{"asset_uuid": c.get("asset_uuid"),
                    "host": (c.get("hostname") or "").strip() or c.get("ip_address") or "(none)",
                    "ip": c.get("ip_address"), "url": c.get("url")} for c in cred if c.get("asset_uuid")]

    return {
        "scanners": _agg(by_scanner, overall_avg),
        "policies": _agg(by_policy, overall_avg),
        "scans": _agg(by_scan, overall_avg),
        "overall_avg_sec": round(overall_avg, 1),
        "scan_info_assets": len({u for b in by_scanner.values() for u in b["assets"]}),
        "credential": {"total_assets": total_assets,
                       "cred_fail_assets": len(cred_assets),
                       "ok_assets": max(0, total_assets - len(cred_assets)),
                       "assets": cred_assets,
                       "plugin": CRED_FAIL_PLUGIN},
    }


def _has_col(table, col, db_path=None):
    try:
        return any(r["name"] == col for r in db.query(f'PRAGMA table_info("{table}");', path=db_path))
    except Exception:
        return False
