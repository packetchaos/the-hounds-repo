"""navi.db search — powers the UI explorers (Assets, Vulns, Plugins, Routes, Paths, Tags).

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


def _lim(limit):
    """Page size: the UI asks for 10–50; other callers (MCP, scripts) keep the 500 default."""
    try:
        n = int(limit or PAGE)
    except (TypeError, ValueError):
        n = PAGE
    return max(1, min(PAGE, n))


def _page(rows, offset, n=PAGE):
    has_next = len(rows) > n
    return {"rows": rows[:n], "count": min(len(rows), n), "limit": n,
            "offset": offset, "has_next": has_next, "page": offset // n + 1}


def assets(q="", offset=0, limit=None):
    n = _lim(limit)
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
                    f"LIMIT {n+1} OFFSET {int(offset)};", tuple(params))
    return _page(rows, int(offset), n)


def vulns(q="", offset=0, limit=None):
    n = _lim(limit)
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
        f"LIMIT {n+1} OFFSET {int(offset)};", tuple(params))
    return _page(rows, int(offset), n)


def _hx_plugins(q, offset, n):
    """Plugin Explorer from hx_plugin (one row per plugin, built by ⚡ Optimize) — the same
    columns as the GROUP BY over vulns, without reading a single 5.5 KB vulns row. name/family
    come from one representative finding per plugin (they are plugin attributes); `assets` is
    COUNT(DISTINCT asset_uuid) over every state, as below."""
    where, params = "", []
    if q:
        where = "WHERE name LIKE ? OR plugin_id LIKE ? OR family LIKE ?"
        params = [f"%{q}%"] * 3
    rows = db.query(
        f"SELECT plugin_id, name, family, assets FROM hx_plugin {where} "
        f"ORDER BY assets DESC, plugin_id LIMIT {n+1} OFFSET {int(offset)};", tuple(params))
    return _page(rows, int(offset), n)


def plugins(q="", offset=0, limit=None):
    n = _lim(limit)
    from core import hx_summary
    if hx_summary.usable():
        return _hx_plugins(q, offset, n)
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
        f"GROUP BY plugin_id ORDER BY assets DESC LIMIT {n+1} OFFSET {int(offset)};", tuple(params))
    return _page(rows, int(offset), n)


def tags(q="", offset=0, limit=None):
    n = _lim(limit)
    """Grouped tag list — one row per tag (tag_key : tag_value) with a DISTINCT
    asset count, so you can see how big each tag is before drilling in."""
    cols = _cols("tags")
    if not cols:
        return _page([], int(offset), n)
    has = lambda c: c in cols
    dt = "tag_added_date" if has("tag_added_date") else None
    sel = ["tag_key", "tag_value",
           ("MAX(tag_uuid)" if has("tag_uuid") else "''") + " AS tag_uuid",
           "COUNT(DISTINCT asset_uuid) AS assets",
           (f"MIN({dt})" if dt else "''") + " AS first_added",
           (f"MAX({dt})" if dt else "''") + " AS last_added"]
    where, params = "", []
    if q:
        tc = ["tag_key", "tag_value"] + (["tag_uuid"] if has("tag_uuid") else [])
        where = "WHERE " + " OR ".join(f"{c} LIKE ?" for c in tc)
        params = [f"%{q}%"] * len(tc)
    rows = db.query(f"SELECT {', '.join(sel)} FROM tags {where} "
                    f"GROUP BY tag_key, tag_value ORDER BY assets DESC, tag_key, tag_value "
                    f"LIMIT {n+1} OFFSET {int(offset)};", tuple(params))
    return _page(rows, int(offset), n)


def tag_assets(key, value, q="", offset=0, limit=None):
    n = _lim(limit)
    """The assets carrying ONE tag — tags ⋈ assets, so each row shows the full
    asset (hostname, IP, OS, ACR/AES, platform url), not just a UUID. Falls back
    to the tags table's own asset_ip when the asset row isn't in navi.db."""
    tcols, acols = _cols("tags"), _cols("assets")
    th, ah = (lambda c: c in tcols), (lambda c: c in acols)
    ip = ("COALESCE(a.ip_address, t.asset_ip, '')" if th("asset_ip")
          else "COALESCE(a.ip_address, '')")
    sel = ["t.asset_uuid AS uuid",
           "COALESCE(a.hostname, '') AS hostname",
           ip + " AS ip_address",
           ("a.operating_system" if ah("operating_system") else "''") + " AS operating_system",
           ("a.acr" if ah("acr") else "''") + " AS acr",
           ("a.aes" if ah("aes") else "''") + " AS aes",
           ("a.url" if ah("url") else "''") + " AS url",
           ("MAX(t.tag_added_date)" if th("tag_added_date") else "''") + " AS tag_added"]
    where, params = ["t.tag_key = ?", "t.tag_value = ?"], [key, value]
    if q:
        tc = ["a.hostname", "t.asset_uuid", ip] \
            + (["a.operating_system"] if ah("operating_system") else [])
        where.append("(" + " OR ".join(f"{c} LIKE ?" for c in tc) + ")")
        params += [f"%{q}%"] * len(tc)
    rows = db.query(
        f"SELECT {', '.join(sel)} FROM tags t LEFT JOIN assets a ON a.uuid = t.asset_uuid "
        f"WHERE {' AND '.join(where)} GROUP BY t.asset_uuid "
        f"ORDER BY hostname, ip_address LIMIT {n+1} OFFSET {int(offset)};", tuple(params))
    return _page(rows, int(offset), n)


def routes(q="", offset=0, limit=None):
    n = _lim(limit)
    where, params = "", []
    if q:
        where = "WHERE app_name LIKE ? OR vuln_type LIKE ?"
        params = [f"%{q}%", f"%{q}%"]
    try:
        rows = db.query(
            f"SELECT route_id, app_name, vuln_type, total_vulns, plugin_list FROM vuln_route {where} "
            f"ORDER BY total_vulns DESC LIMIT {n+1} OFFSET {int(offset)};", tuple(params))
    except Exception:
        rows = []
    return _page(rows, int(offset), n)


def paths(q="", offset=0, limit=None):
    n = _lim(limit)
    where, params = "", []
    if q:
        where = "WHERE p.path LIKE ?"
        params = [f"%{q}%"]
    try:
        rows = db.query(
            "SELECT p.path, p.plugin_id, p.asset_uuid, a.hostname, a.ip_address "
            "FROM vuln_paths p LEFT JOIN assets a ON a.uuid=p.asset_uuid "
            f"{where} ORDER BY p.path LIMIT {n+1} OFFSET {int(offset)};", tuple(params))
    except Exception:
        rows = []
    return _page(rows, int(offset), n)
