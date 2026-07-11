"""Exposure Routes — owner-mapping agent (Atlas Hound).

Pulls users & groups from navi (`navi explore info users|user_groups|agent_groups`,
live Tenable API) and the application **routes** (`vuln_route`) and filesystem
**paths** (`vuln_paths`) from navi.db. A plain-English instruction then maps each
route/path to an owner; applying a mapping tags every asset on that route/path
with `Owner:<group-or-user>` via the gated navi tag path.
"""
import re

from core import db, navi_cli
from core.agents.base import Agent

_SPLIT = re.compile(r"\s{2,}")
_DIV = re.compile(r"^-{5,}$")


def _info_rows(stdout: str) -> list[list]:
    """Parse a `navi explore info` text table into rows of fields (everything
    after the dashed divider line)."""
    out, started = [], False
    for ln in (stdout or "").splitlines():
        if _DIV.match(ln.strip()):
            started = True
            continue
        if not started:
            continue
        t = ln.strip()
        if not t:
            continue
        out.append([c.strip() for c in _SPLIT.split(t)])
    return out


def owners() -> list[dict]:
    """Users + groups available to assign. navi primary; the Tenable MCP acts as a
    backup/validator in the UI layer."""
    out, seen = [], set()

    def add(name, typ, detail=""):
        name = (name or "").strip()
        if not name:
            return
        k = (typ, name.lower())
        if k in seen:
            return
        seen.add(k)
        out.append({"name": name, "type": typ, "detail": detail})

    for sub, typ in (("users", "user"), ("user_groups", "user group"),
                     ("agent_groups", "agent group")):
        r = navi_cli.explore_info(sub)
        for f in _info_rows(r.get("stdout", "")):
            if not f:
                continue
            if typ == "user":
                add(f[0], "user", f[1] if len(f) > 1 else "")
            elif typ == "user group":
                cnt = f[-1] if (f and f[-1].isdigit()) else ""
                add(f[0], "user group", (cnt + " users") if cnt else "")
            else:
                add(f[0], "agent group", " · ".join(f[1:]) if len(f) > 1 else "")
    return out


def routes(db_path=None) -> list[dict]:
    return db.query("SELECT route_id, app_name, vuln_type, total_vulns, plugin_list "
                    "FROM vuln_route ORDER BY total_vulns DESC LIMIT 1000;", path=db_path)


def _plugin_ids(pl) -> list[str]:
    """vuln_route.plugin_list is stored like ['51192', '187315'] — parse to ids."""
    import json
    try:
        return [str(x) for x in json.loads(str(pl or "[]").replace("'", '"'))]
    except Exception:
        return [s for s in re.sub(r"[\[\]'\s]", "", str(pl or "")).split(",") if s]


def paths(db_path=None) -> list[dict]:
    return db.query("SELECT path, MAX(plugin_id) plugin_id, "
                    "COUNT(DISTINCT asset_uuid) assets FROM vuln_paths "
                    "GROUP BY path ORDER BY assets DESC LIMIT 1000;", path=db_path)


def tag_owner(owner: str, route_id=None, path=None, app=None, db_path=None) -> dict:
    """Apply a persistent Owner tag (NO remove) to the assets on a route or path.

    Value scheme: ``<App/technology>: <owner>`` so the tag records WHAT is owned,
    not just by whom. Routes are tagged by their plugin set (a fast asset_uuid
    query) rather than ``--route_id`` — route_id resolves assets via the Tenable
    API at write time, which is slow and times out the MCP bridge.
    """
    if route_id not in (None, ""):
        rows = db.query("SELECT plugin_list, app_name FROM vuln_route WHERE route_id=?",
                        (route_id,), path=db_path)
        if not rows:
            return {"ok": False, "message": f"route_id {route_id} not found"}
        name = app or rows[0].get("app_name") or str(route_id)
        ids = _plugin_ids(rows[0].get("plugin_list"))
        if not ids:
            return {"ok": False, "message": "route has no plugins to tag"}
        inlist = ",".join("'" + i.replace("'", "''") + "'" for i in ids)
        q = "SELECT DISTINCT asset_uuid FROM vulns WHERE plugin_id IN (" + inlist + ")"
        return navi_cli.tag("Owner", f"{name}: {owner}", query=q, remove=False, agent="exproute")
    if path:
        name = app or path
        q = "SELECT asset_uuid FROM vuln_paths WHERE path='" + str(path).replace("'", "''") + "'"
        return navi_cli.tag("Owner", f"{name}: {owner}", query=q, remove=False, agent="exproute")
    return {"ok": False, "message": "no route_id or path supplied"}


# Route↔asset membership: an asset is "on" a route when it carries a vuln whose plugin id
# is in that route's plugin_list (stored like ['51192','187315']). We match the id wrapped
# in quotes ('%'<id>'%') so 519 doesn't match 51192.
_RA = ("WITH ra AS (SELECT DISTINCT r.app_name app, v.asset_uuid au "
       "FROM vuln_route r JOIN vulns v ON r.plugin_list LIKE '%''' || v.plugin_id || '''%') ")


def coverage(db_path=None) -> dict:
    """How much of the attack surface has an owner assigned. An asset is CLOSED only when
    EVERY route it sits on is owned (an Owner:'<app>: <user>' tag for each route). Read-only."""
    def sc(sql):
        try:
            return db.scalar(sql, path=db_path) or 0
        except Exception:
            return 0
    if not db.query("SELECT name FROM sqlite_master WHERE type='table' AND name='vuln_route'", path=db_path):
        return {"ok": True, "owned": 0, "assets_with_routes": 0, "avg_routes": 0.0,
                "closed": 0, "total_routes": 0, "total_paths": 0, "owned_paths": 0,
                "note": "No vuln_route table — run `navi config update route` + `navi config update paths`."}
    owned = sc("SELECT COUNT(DISTINCT asset_uuid) FROM tags WHERE tag_key='Owner'")
    assets_with_routes = sc(_RA + "SELECT COUNT(DISTINCT au) FROM ra")
    avg_routes = sc(_RA + "SELECT AVG(c) FROM (SELECT au, COUNT(DISTINCT app) c FROM ra GROUP BY au)")
    total_routes = sc("SELECT COUNT(*) FROM vuln_route")
    total_paths = sc("SELECT COUNT(DISTINCT path) FROM vuln_paths")
    # workload reduction: raw path findings (every asset×path row) collapse to distinct
    # paths you actually assign; sum of route vulns collapse to a handful of routes.
    path_findings = sc("SELECT COUNT(*) FROM vuln_paths")
    route_findings = sc("SELECT COALESCE(SUM(total_vulns),0) FROM vuln_route")
    closed, owned_paths = 0, 0
    if owned > 0:
        closed = sc(_RA + "SELECT COUNT(*) FROM (SELECT au FROM ra GROUP BY au HAVING "
                    "SUM(CASE WHEN EXISTS(SELECT 1 FROM tags t WHERE t.asset_uuid=ra.au "
                    "AND t.tag_key='Owner' AND t.tag_value LIKE ra.app || ': %') THEN 0 ELSE 1 END)=0)")
        # a path is OWNED only when an asset on it carries an Owner tag mapped to THAT path
        # (the tag_owner scheme Owner : '<path>: <user>') — not merely any Owner tag that
        # happens to be on the asset for some other route/path. Count distinct paths.
        owned_paths = sc("SELECT COUNT(DISTINCT vp.path) FROM vuln_paths vp "
                         "JOIN tags t ON t.asset_uuid=vp.asset_uuid AND t.tag_key='Owner' "
                         "AND t.tag_value LIKE vp.path || ': %'")
    return {"ok": True, "owned": int(owned), "assets_with_routes": int(assets_with_routes),
            "avg_routes": round(float(avg_routes or 0), 1), "closed": int(closed),
            "total_routes": int(total_routes), "total_paths": int(total_paths),
            "owned_paths": int(owned_paths), "path_findings": int(path_findings),
            "route_findings": int(route_findings)}


def ownership_map(db_path=None) -> dict:
    """The Ownership Map — every route/path with the owners assigned to it (the Owner
    tag scheme '<name>: <user>'), the assets behind it, and a coverage status:
      owned   — every asset on it carries that route/path's Owner tag
      partial — some but not all of its assets are owned (too few owners)
      unowned — no owner at all
    Plus per-owner workload (routes/paths/assets each owner carries) and the count of
    assets on the attack surface with no owner. Read-only; feeds the network-thread graph."""
    def q(sql, args=()):
        try:
            return list(db.query(sql, args, path=db_path)) if args else list(db.query(sql, path=db_path))
        except Exception:
            return []
    if not q("SELECT name FROM sqlite_master WHERE type='table' AND name='vuln_route'"):
        return {"ok": True, "routes": [], "paths": [], "owners": [], "owner_load": [],
                "kpi": {"routes": 0, "paths": 0, "owners": 0, "unowned_assets": 0},
                "note": "No vuln_route/vuln_paths tables — run `navi config update route` + `navi config update paths`."}

    # Owner tags -> map a route/path NAME to its owners + the assets carrying that tag
    name_owners, name_assets = {}, {}
    for r in q("SELECT asset_uuid, tag_value FROM tags WHERE tag_key='Owner' AND tag_value IS NOT NULL"):
        val = (r.get("tag_value") or "").strip()
        au = r.get("asset_uuid")
        if ": " in val:
            name, user = val.rsplit(": ", 1)
        else:
            name, user = val, ""
        name, user = name.strip(), user.strip()
        if user:
            name_owners.setdefault(name, set()).add(user)
        if au:
            name_assets.setdefault(name, set()).add(au)

    # route -> assets (via plugin_list membership) and path -> assets
    route_assets = {}
    for r in q(_RA + "SELECT app, au FROM ra"):
        if r.get("app"):
            route_assets.setdefault(r["app"], set()).add(r.get("au"))
    path_assets = {}
    for r in q("SELECT path, asset_uuid FROM vuln_paths WHERE path IS NOT NULL"):
        path_assets.setdefault(r["path"], set()).add(r.get("asset_uuid"))

    def _item(name, kind, assets):
        owners = sorted(name_owners.get(name, set()))
        owned = len((name_assets.get(name, set()) & assets))
        total = len(assets)
        status = ("unowned" if (not owners or owned == 0)
                  else "partial" if owned < total else "owned")
        return {"name": name, "type": kind, "owners": owners, "owner_count": len(owners),
                "assets": total, "owned_assets": owned, "status": status}

    routes = [_item(r["app_name"], "route", route_assets.get(r["app_name"], set()))
              for r in q("SELECT DISTINCT app_name FROM vuln_route WHERE app_name IS NOT NULL")]
    paths = [_item(p, "path", a) for p, a in path_assets.items()]
    # PLUGIN-MEDIATED route<->path link — the accurate relationship: a route's plugins
    # (plugin_list) found at a filesystem path (vuln_paths.plugin_id). One app/route can
    # cover MANY paths (e.g. a Jenkins route's plugins fire in many sub-dirs). This is the
    # true CVE→plugin→app→path chain, NOT the loose shared-asset proxy. Surfaces apps with
    # no filesystem-path detail and ORPHAN paths whose plugin belongs to no app.
    route_paths, path_routes = {}, {}
    for r in q("SELECT DISTINCT r.app_name app, vp.path path FROM vuln_route r "
               "JOIN vuln_paths vp ON r.plugin_list LIKE '%''' || vp.plugin_id || '''%'"):
        app, pth = r.get("app"), r.get("path")
        if app and pth:
            route_paths.setdefault(app, set()).add(pth)
            path_routes.setdefault(pth, set()).add(app)
    for it in routes:
        it["paths_on_route"] = len(route_paths.get(it["name"], set()))
    for it in paths:
        cov = path_routes.get(it["name"], set())
        it["routes"] = sorted(cov)                # which app(s) cover this path
        it["on_route"] = bool(cov)
    route_paths_list = {a: sorted(s) for a, s in route_paths.items()}
    orphan_paths = sorted(p["name"] for p in paths if not p["on_route"])

    routes.sort(key=lambda x: (-x["assets"], x["name"]))
    paths.sort(key=lambda x: (-x["assets"], x["name"]))

    # per-owner workload: routes, paths and distinct assets each owner carries
    load = {}
    for it in routes + paths:
        for o in it["owners"]:
            e = load.setdefault(o, {"owner": o, "routes": 0, "paths": 0, "assets": set()})
            e["routes" if it["type"] == "route" else "paths"] += 1
            e["assets"] |= (name_assets.get(it["name"], set()))
    owner_load = sorted(([{"owner": e["owner"], "routes": e["routes"], "paths": e["paths"],
                           "assets": len(e["assets"])} for e in load.values()]),
                        key=lambda x: -(x["routes"] + x["paths"]))

    all_assets = set()
    for s in route_assets.values():
        all_assets |= s
    for s in path_assets.values():
        all_assets |= s
    tagged = {r["asset_uuid"] for r in q("SELECT DISTINCT asset_uuid FROM tags WHERE tag_key='Owner'") if r.get("asset_uuid")}
    unowned_assets = len(all_assets - tagged)

    def kc(items, s):
        return sum(1 for i in items if i["status"] == s)

    # ===== Reduction funnel + champion plugin — the workload-reduction story:
    # CVE line-items -> findings -> plugins -> apps/routes. People chase CVEs (the most
    # duplicated work); owning apps collapses that. Champion = one fix clearing the most CVEs.
    funnel, champion = {}, None
    if q("SELECT name FROM sqlite_master WHERE type='table' AND name='plugins'"):
        fr = q("WITH present AS (SELECT DISTINCT plugin_id FROM vulns) "
               "SELECT (SELECT COUNT(*) FROM vulns) findings,(SELECT COUNT(*) FROM present) plugins,"
               "(SELECT COUNT(DISTINCT path) FROM vuln_paths) paths,(SELECT COUNT(DISTINCT app_name) FROM vuln_route) routes,"
               "(SELECT SUM((length(p.cves)-length(replace(p.cves,'CVE-','')))/4) FROM plugins p "
               "JOIN present ON present.plugin_id=p.plugin_id WHERE p.cves IS NOT NULL AND p.cves NOT IN ('','[]','None')) cves")
        if fr:
            row = fr[0]
            funnel = {"cves": int(row.get("cves") or 0), "findings": int(row.get("findings") or 0),
                      "plugins": int(row.get("plugins") or 0), "paths": int(row.get("paths") or 0),
                      "routes": int(row.get("routes") or 0)}
        cr = q("WITH present AS (SELECT DISTINCT plugin_id FROM vulns) "
               "SELECT p.plugin_id,p.name,(length(p.cves)-length(replace(p.cves,'CVE-','')))/4 cve_count,"
               "(SELECT COUNT(DISTINCT asset_uuid) FROM vulns v WHERE v.plugin_id=p.plugin_id) assets "
               "FROM plugins p JOIN present ON present.plugin_id=p.plugin_id "
               "WHERE p.cves IS NOT NULL AND p.cves NOT IN ('','[]','None') ORDER BY cve_count DESC LIMIT 1")
        if cr:
            c = cr[0]
            champion = {"plugin_id": c.get("plugin_id"), "name": c.get("name"),
                        "cve_count": int(c.get("cve_count") or 0), "assets": int(c.get("assets") or 0)}

    return {"ok": True, "routes": routes, "paths": paths,
            "owners": sorted({o for it in routes + paths for o in it["owners"]}),
            "owner_load": owner_load,
            "route_paths": route_paths_list, "orphan_paths": orphan_paths,
            "funnel": funnel, "champion": champion,
            "kpi": {"routes": len(routes), "routes_unowned": kc(routes, "unowned"),
                    "routes_partial": kc(routes, "partial"), "routes_owned": kc(routes, "owned"),
                    "paths": len(paths), "paths_unowned": kc(paths, "unowned"),
                    "paths_partial": kc(paths, "partial"), "paths_owned": kc(paths, "owned"),
                    "owners": len(owner_load), "unowned_assets": unowned_assets,
                    "asset_scope": len(all_assets),
                    "routes_no_paths": sum(1 for r in routes if r.get("paths_on_route", 0) == 0),
                    "routes_with_paths": sum(1 for r in routes if r.get("paths_on_route", 0) > 0),
                    "paths_orphan": len(orphan_paths),
                    "paths_covered": sum(1 for p in paths if p.get("on_route"))}}


def path_detail(path):
    """Drill-down for a single filesystem path (a newly-found gap): which assets carry it,
    their findings/plugins, and the owner(s) of the app(s) that cover it — so Gabriel can
    email the gap to the right person."""
    from core import db
    if not path:
        return {"ok": False, "error": "path required"}
    dbp = db.db_path()

    def q(sql, args=()):
        try:
            return list(db.query(sql, args, path=dbp))
        except Exception:
            return []

    rows = q("SELECT vp.asset_uuid au, vp.plugin_id pid, vp.finding_id fid, a.hostname host, "
             "a.ip_address ip, a.acr acr, a.url url FROM vuln_paths vp "
             "LEFT JOIN assets a ON a.uuid=vp.asset_uuid WHERE vp.path=?", (path,))
    by, findings, plugins = {}, set(), set()
    for r in rows:
        u = r.get("au")
        e = by.setdefault(u, {"uuid": u, "hostname": r.get("host"), "ip": r.get("ip"),
                              "acr": r.get("acr"), "url": r.get("url"), "plugins": set(), "findings": set()})
        if r.get("pid"):
            e["plugins"].add(str(r["pid"])); plugins.add(str(r["pid"]))
        if r.get("fid"):
            e["findings"].add(str(r["fid"])); findings.add(str(r["fid"]))
    assets = [{"uuid": e["uuid"], "hostname": e["hostname"], "ip": e["ip"], "acr": e["acr"],
               "url": e["url"], "plugins": len(e["plugins"]), "findings": sorted(e["findings"])}
              for e in by.values()]
    assets.sort(key=lambda x: -(float(x["acr"]) if x["acr"] else 0))
    apps = [r["app"] for r in q("SELECT DISTINCT r.app_name app FROM vuln_route r JOIN vuln_paths vp "
            "ON r.plugin_list LIKE '%''' || vp.plugin_id || '''%' WHERE vp.path=?", (path,)) if r.get("app")]
    owners = set()
    for r in q("SELECT DISTINCT tag_value FROM tags WHERE tag_key='Owner' AND tag_value IS NOT NULL"):
        val = (r.get("tag_value") or "").strip()
        if ": " in val:
            nm, us = val.rsplit(": ", 1)
            if nm.strip() in apps and us.strip():
                owners.add(us.strip())
    return {"ok": True, "path": path, "apps": sorted(apps), "owners": sorted(owners),
            "assets": assets, "plugins": sorted(plugins), "findings": sorted(findings),
            "asset_count": len(assets)}


class ExpRouteAgent(Agent):
    id = "exproute"
    name = "Exposure Routes"
    icon = "🧭"
    description = ("Pulls users & groups (navi, Tenable MCP backup) and maps exposure "
                  "routes & paths to owners from plain English; tags Owner:<group/user>.")

    def summary(self):
        if not self.result:
            return {}
        c = self.result.get("counts", {})
        return {"owners": c.get("owners"), "routes": c.get("routes"), "paths": c.get("paths")}

    def _run(self, db_path=None, **kwargs):
        ow, rt, pa = owners(), routes(db_path), paths(db_path)
        return {"owners": ow, "routes": rt, "paths": pa,
                "counts": {"owners": len(ow), "routes": len(rt), "paths": len(pa)}}
