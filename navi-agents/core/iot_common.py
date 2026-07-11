"""Shared constants + helpers for the IoT agent squad.

Guardrails (conservative + false-positive control):
- GENERIC_PLUGIN_DENYLIST: enumeration/info plugins that mention many vendors;
  never promoted as IoT detectors.
- PREVALENCE_MAX: a plugin firing on more than this fraction of all assets is
  too generic to be an IoT signature.
- MIN_NAME_LEN / NAME_STOPLIST: reject short or ambiguous IoT names that would
  over-match in plugin name/output search.
"""
from . import db

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

PREVALENCE_MAX = 0.50        # drop plugins firing on >50% of assets
MIN_NAME_LEN = 5             # IoT names shorter than this are too ambiguous
MIN_XREF_PLUGINS = 1         # min expanded plugins an asset must share to be a candidate

NAME_STOPLIST = {
    "cast", "camera", "server", "linux", "windows", "device", "router",
    "switch", "phone", "print", "printer", "host", "network", "unknown",
    "generic", "ssl", "http", "https", "tls", "agent", "scan", "default",
}


def asset_total(db_path=None) -> int:
    return db.scalar("SELECT count(uuid) FROM assets;", path=db_path) or 0


def valid_iot_name(name: str) -> bool:
    n = (name or "").strip()
    if len(n) < MIN_NAME_LEN:
        return False
    if n.lower() in NAME_STOPLIST:
        return False
    return True


def _like(col, term):
    return f"{col} LIKE '%{term.replace(chr(39), chr(39)*2)}%'"


def assets_for_detection(det: dict, db_path=None) -> list[dict]:
    """Conservative match: asset has a vuln whose plugin_id is in det.plugins,
    OR plugin_name matches a name_contains term, OR output matches a
    (non-generic) output_contains term. Returns asset rows + trigger plugins."""
    clauses = []
    for pid in det.get("plugins", []):
        clauses.append(f"v.plugin_id = '{pid}'")
    for t in det.get("name_contains", []):
        clauses.append(_like("v.plugin_name", t))
    for t in det.get("output_contains", []):
        if len(t) >= 4:  # skip ultra-short output terms
            clauses.append(_like("v.output", t))
    if not clauses:
        return []
    where = " OR ".join(clauses)
    sql = (f"SELECT DISTINCT v.asset_uuid, a.hostname, a.ip_address, "
           f"v.plugin_id, v.plugin_name FROM vulns v "
           f"LEFT JOIN assets a ON a.uuid = v.asset_uuid WHERE {where};")
    return db.query(sql, path=db_path)


def plugins_mentioning(name: str, db_path=None) -> list[dict]:
    """All plugins whose NAME or OUTPUT mentions the IoT name, with the distinct
    asset count, after applying the generic/prevalence guardrails."""
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
    """Assets (not in exclude set) that fire ANY of the given plugins, with the
    count of distinct matching plugins as cross-reference evidence."""
    if not plugin_ids:
        return []
    inlist = ",".join("'" + p.replace("'", "''") + "'" for p in plugin_ids)
    sql = (f"SELECT v.asset_uuid, a.hostname, a.ip_address, "
           f"COUNT(DISTINCT v.plugin_id) AS evidence, "
           f"GROUP_CONCAT(DISTINCT v.plugin_id) AS pids "
           f"FROM vulns v LEFT JOIN assets a ON a.uuid = v.asset_uuid "
           f"WHERE v.plugin_id IN ({inlist}) GROUP BY v.asset_uuid;")
    rows = db.query(sql, path=db_path)
    return [r for r in rows if r["asset_uuid"] not in exclude_uuids
            and (r["evidence"] or 0) >= MIN_XREF_PLUGINS]
