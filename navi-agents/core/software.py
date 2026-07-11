"""Software analyzer — version sprawl over the `software` table.

Parses RPM/NVR-style `software_string` values (name-version-release) into a
product name + version, then aggregates across the estate to surface version
sprawl (one product at many versions), the most-deployed software, and rare
single-install software.
"""
import re

from core import db

_VER = re.compile(r"^\d")


def parse_nvr(s: str):
    """name-version-release -> (name, version). Name is everything before the
    first hyphen-delimited segment that starts with a digit."""
    parts = str(s or "").split("-")
    vi = -1
    for i in range(1, len(parts)):
        if _VER.match(parts[i]):
            vi = i
            break
    if vi < 0:
        return str(s or ""), ""
    return "-".join(parts[:vi]), parts[vi]


def _ver_key(v: str):
    out = []
    for x in re.split(r"[._\-]", str(v)):
        out.append((0, int(x)) if x.isdigit() else (1, x))
    return out


def analyze(db_path=None) -> dict:
    rows = db.query("SELECT asset_uuid, software_string FROM software "
                    "WHERE software_string IS NOT NULL AND software_string<>'';",
                    path=db_path)
    prod, assets = {}, set()
    for r in rows:
        assets.add(r["asset_uuid"])
        name, version = parse_nvr(r["software_string"])
        if not name:
            continue
        P = prod.setdefault(name, {"name": name, "versions": {},
                                   "assets": set(), "installs": 0})
        P["installs"] += 1
        P["assets"].add(r["asset_uuid"])
        P["versions"].setdefault(version, set()).add(r["asset_uuid"])

    products = []
    for P in prod.values():
        vers = sorted(P["versions"].items(), key=lambda kv: _ver_key(kv[0]), reverse=True)
        vlist = [{"v": v, "assets": len(a), "uuids": sorted(a)} for v, a in vers]
        products.append({"name": P["name"], "nver": len(vlist), "nasset": len(P["assets"]),
                         "installs": P["installs"], "versions": vlist,
                         "assets": sorted(P["assets"]),
                         "newest": vlist[0]["v"] if vlist else ""})
    products.sort(key=lambda p: (-p["nver"], -p["nasset"]))
    multi = sum(1 for p in products if p["nver"] > 1)
    single = sum(1 for p in products if p["nasset"] == 1)
    return {"products": products,
            "counts": {"records": len(rows), "products": len(products),
                       "pairs": sum(p["nver"] for p in products), "assets": len(assets),
                       "multi_version": multi, "single_install": single}}


def tag_query_for_assets(uuids: list) -> str:
    inl = ",".join("'" + str(u).replace("'", "''") + "'" for u in uuids if u)
    return f"SELECT DISTINCT asset_uuid FROM software WHERE asset_uuid IN ({inl})"
