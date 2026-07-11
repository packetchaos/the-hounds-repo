"""Custom Application Name Agent.

Finds software that Tenable's *software inventory* misses, by mining the
vulnerability **routes** (`vuln_route.app_name`) and filesystem **paths**
(`vuln_paths.path`) and comparing what it finds against the `software` table.
Apps that show up in routes/paths but not in the package inventory are surfaced
as candidate "custom apps" for the operator to name and tag.

Also powers the natural-language "tag my custom app <X>" flow: search the paths
table for a keyword, show the matching paths/assets, then (gated) tag
`Custom App:<name>`.
"""
import json
import os
import re

from core import db
from core.agents.base import Agent

# ---- persistent ignore list (false positives / web pages that look like apps) ----
IGNORE_PATH = os.environ.get(
    "CUSTOMAPP_IGNORE_PATH", os.path.join(os.path.dirname(__file__), "ignore.json"))


def load_ignore() -> list:
    try:
        with open(IGNORE_PATH, encoding="utf-8") as f:
            data = json.load(f)
        return sorted({str(t).strip().lower() for t in data if str(t).strip()})
    except Exception:
        return []


def save_ignore(terms: list) -> list:
    terms = sorted({str(t).strip().lower() for t in (terms or []) if str(t).strip()})
    try:
        with open(IGNORE_PATH, "w", encoding="utf-8") as f:
            json.dump(terms, f, indent=2)
    except Exception:
        pass
    return terms


def is_ignored(name: str, keyword: str, terms=None) -> bool:
    terms = load_ignore() if terms is None else terms
    n, k = str(name or "").lower(), str(keyword or "").lower()
    return any(t and (n == t or k == t or t in n or t in k) for t in terms)

STOP = {
    "var", "lib", "usr", "etc", "bin", "sbin", "local", "share", "snap", "tmp",
    "home", "srv", "run", "proc", "sys", "dev", "opt", "site", "packages",
    "site-packages", "dist", "info", "dist-info", "egg", "egg-info", "plugins",
    "plugin", "cgi", "cgi-bin", "overlay2", "diff", "app", "html", "entries",
    "server", "status", "printenv", "supported", "versions", "net", "www",
    "data", "conf", "config", "log", "logs", "cache", "tls", "http", "gif",
    "jpeg", "png", "pjpeg", "stable", "pkg", "pkg-info", "analyst", "home",
    "root", "users", "user", "admin", "administrator", "public", "temp",
}


def _clean(seg: str) -> str:
    seg = seg.lower()
    seg = re.split(r"[-_.]\d", seg)[0]   # strip version suffixes
    seg = seg.split(".")[0]              # strip extension
    return seg


def path_tokens(path: str) -> set:
    out = set()
    for seg in (path or "").split("/"):
        if not seg:
            continue
        t = _clean(seg)
        if len(t) < 3 or t in STOP:
            continue
        if t.replace(".", "").isdigit():
            continue
        if re.fullmatch(r"[0-9a-f]{12,}", t):   # container hashes
            continue
        out.add(t)
    return out


class CustomAppAgent(Agent):
    id = "customapp"
    name = "Custom App Name Agent"
    icon = "🧩"
    description = ("Finds software missing from the inventory by mining vuln routes "
                   "and filesystem paths; lets you name & tag custom apps in plain English.")

    def summary(self) -> dict:
        if not self.result:
            return {}
        return {"candidates": len(self.result.get("candidates", [])),
                "from_routes": sum(1 for c in self.result["candidates"] if c["source"] == "route")}

    # ---- discovery ----
    def _run(self, db_path=None, **kwargs) -> dict:
        # vuln_route / vuln_paths are populated by SEPARATE navi commands
        # (navi config update route / paths), NOT a normal full sync — so they are
        # often missing/empty. Degrade gracefully and report what needs populating
        # instead of crashing the whole run.
        routes = _safe_rows("SELECT app_name, vuln_type, total_vulns FROM vuln_route;", db_path)
        sw = [r["software_string"].lower() for r in
              _safe_rows("SELECT software_string FROM software;", db_path)
              if r.get("software_string")]
        paths = _safe_rows("SELECT path, asset_uuid FROM vuln_paths "
                           "WHERE path IS NOT NULL AND path<>'';", db_path)
        setup = routing_status(db_path)

        def in_inventory(term: str) -> bool:
            term = term.lower()
            return any(term in s for s in sw)

        candidates = []
        seen = set()

        # routes — these are named apps/components
        for r in routes:
            name = (r["app_name"] or "").strip()
            if not name:
                continue
            key = name.lower().split()[0]
            if in_inventory(key):
                continue
            k = ("route", name.lower())
            if k in seen:
                continue
            seen.add(k)
            candidates.append({"source": "route", "name": name,
                               "vuln_type": r["vuln_type"], "evidence": r["total_vulns"],
                               "example": f"route · {r['vuln_type']}", "in_inventory": False,
                               "keyword": key})

        # paths — tokenized folder/file names
        tok_assets, tok_example = {}, {}
        for p in paths:
            # sub-components of an app (e.g. /jenkins/plugins/*) are not standalone apps
            if "/plugins/" in (p["path"] or "").lower():
                continue
            for t in path_tokens(p["path"]):
                tok_assets.setdefault(t, set()).add(p["asset_uuid"])
                tok_example.setdefault(t, p["path"])
        route_keys = {c["keyword"] for c in candidates}
        for tok, assets in sorted(tok_assets.items(), key=lambda kv: -len(kv[1])):
            if tok in route_keys or in_inventory(tok):
                continue
            candidates.append({"source": "path", "name": tok,
                               "vuln_type": "path-derived", "evidence": len(assets),
                               "example": tok_example.get(tok, ""), "in_inventory": False,
                               "keyword": tok})

        candidates.sort(key=lambda c: (-(c["evidence"] or 0), c["name"]))
        terms = load_ignore()
        kept = [c for c in candidates if not is_ignored(c["name"], c.get("keyword"), terms)]
        hidden = len(candidates) - len(kept)
        return {"candidates": kept, "ignored": terms, "hidden": hidden,
                "setup": setup, "needs_setup": not (setup["vuln_route"] or setup["vuln_paths"]),
                "setup_hint": _SETUP_HINT,
                "counts": {"routes": len(routes), "software": len(sw),
                           "paths": len(paths), "candidates": len(kept), "hidden": hidden}}


# ---- helpers used by the service layer for the NL tag flow ----

# The routing/paths tables this agent depends on are populated by dedicated navi
# commands, separate from a normal `navi config update full`. Surface this so the
# operator knows why discovery/tagging is empty and exactly how to fix it.
_SETUP_HINT = ("Custom App discovery reads navi.db's vuln_route + vuln_paths tables. "
               "Populate them first: `navi config update route` then "
               "`navi config update paths` (they are NOT part of a normal full sync).")


def _safe_rows(sql, db_path=None):
    """Run a SELECT, returning [] if the table doesn't exist yet (missing routing
    tables must not crash discovery)."""
    try:
        return db.query(sql, path=db_path)
    except Exception:
        return []


def _table_has_rows(table, db_path=None):
    try:
        return (db.scalar(f"SELECT COUNT(*) FROM {table}", path=db_path) or 0) > 0
    except Exception:
        return False


def routing_status(db_path=None) -> dict:
    """Which routing/paths tables are actually populated in this navi.db."""
    return {"vuln_route": _table_has_rows("vuln_route", db_path),
            "vuln_paths": _table_has_rows("vuln_paths", db_path)}

def search_paths(keyword: str, db_path=None) -> list[dict]:
    """Filesystem-path matches (vuln_paths.path) — assets linked by asset_uuid."""
    kw = (keyword or "").strip().replace("'", "''")
    if not kw:
        return []
    sql = (f"SELECT p.path, p.plugin_id, a.hostname, a.ip_address, p.asset_uuid "
           f"FROM vuln_paths p LEFT JOIN assets a ON a.uuid=p.asset_uuid "
           f"WHERE p.path LIKE '%{kw}%' GROUP BY p.path;")
    return _safe_rows(sql, db_path)


def search_routes(keyword: str, db_path=None) -> list[dict]:
    """Application-route matches (vuln_route.app_name). vuln_route carries no
    asset_uuid, so navi tags these via --route_id rather than a SQL query."""
    kw = (keyword or "").strip().replace("'", "''")
    if not kw:
        return []
    sql = (f"SELECT route_id, app_name, vuln_type, total_vulns FROM vuln_route "
           f"WHERE app_name LIKE '%{kw}%' ORDER BY total_vulns DESC;")
    return _safe_rows(sql, db_path)


def search_app(keyword: str, db_path=None) -> dict:
    """Search BOTH vuln_route (app_name) and vuln_paths (path) for a custom app."""
    return {"paths": search_paths(keyword, db_path),
            "routes": search_routes(keyword, db_path)}


def tag_query_for(keyword: str) -> str:
    """Read-only SELECT of asset_uuids whose filesystem paths match the keyword."""
    kw = (keyword or "").strip().replace("'", "''")
    return f"SELECT DISTINCT asset_uuid FROM vuln_paths WHERE path LIKE '%{kw}%';"
