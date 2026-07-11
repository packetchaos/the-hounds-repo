"""End-of-Life / Unsupported software detection.

Finds assets whose findings include plugins whose NAME contains lifecycle
language ("Unsupported", "End of Life", "SEoL", …) and tags them via navi's
tag-by-plugin-name selector (`navi enrich tag --name "<text>"`). Because the
match is on the live plugin name, the tag set expands automatically as new
end-of-life/unsupported plugins appear — no rules to maintain per product.
"""
from core import db

# label -> substrings searched in plugin_name (navi --name matches each, substring)
DEFAULT_GROUPS = [
    ("Unsupported", ["Unsupported"]),
    ("End of Life", ["End of Life", "SEoL", "End-of-Life", "End of Support"]),
]


def _clause(pats):
    return " OR ".join("plugin_name LIKE '%" + p.replace("'", "''") + "%'" for p in pats)


def scan(db_path=None, groups=None):
    groups = groups or DEFAULT_GROUPS
    out = []
    for label, pats in groups:
        where = _clause(pats)
        plugins = db.query(
            "SELECT plugin_id, plugin_name, COUNT(DISTINCT asset_uuid) AS assets "
            "FROM vulns WHERE " + where + " GROUP BY plugin_id, plugin_name "
            "ORDER BY assets DESC", path=db_path)
        n = db.scalar("SELECT COUNT(DISTINCT asset_uuid) FROM vulns WHERE " + where, path=db_path) or 0
        out.append({"label": label, "patterns": pats, "category": "Lifecycle",
                    "plugins": plugins, "asset_count": n})
    return {"groups": out}
