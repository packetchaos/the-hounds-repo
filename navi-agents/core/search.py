"""navi.db search — powers the UI explorers (Assets, Vulns, Plugins, Routes, Paths).

All read-only (core.db). Paginated 500/page (DB-side LIMIT/OFFSET): each call fetches
PAGE+1 rows to know if there's a next page. Column-resilient: adapts to whichever
columns a given navi.db actually has. navi stores VPR in vulns.score.
"""
from core import db

PAGE = 500


def _cols(table):
    try:
        return {r["name"] for r in db.query(f'PRAGMA table_info("{table}");')}
    except Exception:
        return set()


def _page(rows, offset):
    has_next = len(rows) > PAGE
    return {"rows": rows[:PAGE], "count": min(len(rows), PAGE),
            "offset": offset, "has_next": has_next, "page": offset // PAGE + 1}


def assets(q="", offset=0):
    cols = _cols("assets")
    has = lambda c: c in cols
    sel = ["uuid", "hostname", "ip_address",
           "operating_system" if has("operating_system") else "'' AS operating_system",
           "acr" if has("acr") else "'' AS acr",
           "aes" if has("aes") else "'' AS aes",
           "url" if has("url") else "'' AS url"]
    where, params = "", []
    if q:
        tc = ["hostname", "ip_address"] + (["operating_system"] if has("operating_system") else []) + (["network"] if has("network") else [])
        where = "WHERE " + " OR ".join(f"{c} LIKE ?" for c in tc)
        params = [f"%{q}%"] * len(tc)
    rows = db.query(f"SELECT {', '.join(sel)} FROM assets {where} ORDER BY hostname "
                    f"LIMIT {PAGE+1} OFFSET {int(offset)};", tuple(params))
    return _page(rows, int(offset))


def vulns(q="", offset=0):
    """Per-FINDING rows from the vulns table (NOT grouped by plugin — that's the Plugin
    Explorer). Each row carries its finding_id and the Tenable platform url so the UI can
    deep-link. Degrades gracefully on the simplified sample schema (no finding_id /
    asset_hostname → falls back to a join on assets)."""
    cols = _cols("vulns")
    has = lambda c: c in cols
    sel = ["v.plugin_id",
           ("v.plugin_name AS name" if has("plugin_name") else "'' AS name"),
           ("v.severity AS severity" if has("severity") else "'' AS severity"),
           ("CAST(v.score AS REAL) AS vpr" if has("score") else "NULL AS vpr"),
           ("v.finding_id AS finding_id" if has("finding_id") else "NULL AS finding_id"),
           ("v.url AS url" if has("url") else "'' AS url"),
           "v.asset_uuid AS asset_uuid"]
    join = ""
    if has("asset_hostname"):
        sel.append("v.asset_hostname AS hostname")
    else:
        sel.append("COALESCE(a.hostname,'') AS hostname")
        join = "LEFT JOIN assets a ON a.uuid=v.asset_uuid"
    sel.append("v.asset_ip AS ip" if has("asset_ip") else "COALESCE(a.ip_address,'') AS ip")
    where, params = "", []
    if q:
        cs = ["v.plugin_name", "v.plugin_id"] + (["v.cves"] if has("cves") else []) \
            + (["v.severity"] if has("severity") else []) \
            + (["v.asset_hostname"] if has("asset_hostname") else []) \
            + (["v.finding_id"] if has("finding_id") else [])
        where = "WHERE " + " OR ".join(f"{c} LIKE ?" for c in cs)
        params = [f"%{q}%"] * len(cs)
    order = ("ORDER BY CASE lower(CAST(v.severity AS TEXT)) "
             "WHEN 'critical' THEN 4 WHEN '4' THEN 4 WHEN 'high' THEN 3 WHEN '3' THEN 3 "
             "WHEN 'medium' THEN 2 WHEN '2' THEN 2 WHEN 'low' THEN 1 WHEN '1' THEN 1 ELSE 0 END DESC, "
             "vpr DESC")
    rows = db.query(
        f"SELECT {', '.join(sel)} FROM vulns v {join} {where} {order} "
        f"LIMIT {PAGE+1} OFFSET {int(offset)};", tuple(params))
    return _page(rows, int(offset))


def plugins(q="", offset=0):
    cols = _cols("vulns")
    fam = "MAX(plugin_family)" if "plugin_family" in cols else "''"
    where, params = "", []
    if q:
        cs = ["plugin_name", "plugin_id"] + (["plugin_family"] if "plugin_family" in cols else [])
        where = "WHERE " + " OR ".join(f"{c} LIKE ?" for c in cs)
        params = [f"%{q}%"] * len(cs)
    rows = db.query(
        f"SELECT plugin_id, MAX(plugin_name) AS name, {fam} AS family, "
        f"COUNT(DISTINCT asset_uuid) AS assets FROM vulns {where} "
        f"GROUP BY plugin_id ORDER BY assets DESC LIMIT {PAGE+1} OFFSET {int(offset)};", tuple(params))
    return _page(rows, int(offset))


def routes(q="", offset=0):
    where, params = "", []
    if q:
        where = "WHERE app_name LIKE ? OR vuln_type LIKE ?"
        params = [f"%{q}%", f"%{q}%"]
    try:
        rows = db.query(
            f"SELECT app_name, vuln_type, total_vulns, plugin_list FROM vuln_route {where} "
            f"ORDER BY total_vulns DESC LIMIT {PAGE+1} OFFSET {int(offset)};", tuple(params))
    except Exception:
        rows = []
    return _page(rows, int(offset))


def paths(q="", offset=0):
    where, params = "", []
    if q:
        where = "WHERE p.path LIKE ?"
        params = [f"%{q}%"]
    try:
        rows = db.query(
            "SELECT p.path, p.plugin_id, p.asset_uuid, a.hostname, a.ip_address "
            "FROM vuln_paths p LEFT JOIN assets a ON a.uuid=p.asset_uuid "
            f"{where} ORDER BY p.path LIMIT {PAGE+1} OFFSET {int(offset)};", tuple(params))
    except Exception:
        rows = []
    return _page(rows, int(offset))
