"""Software analyzer — version sprawl over the `software` table.

Parses RPM/NVR-style `software_string` values (name-version-release) into a
product name + version, then aggregates across the estate to surface version
sprawl (one product at many versions), the most-deployed software, and rare
single-install software.
"""
import re

from core import db

_VER = re.compile(r"^\d")
_UUID_RE = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
_VTAG = re.compile(r"\[\s*version\s+([^\]]+?)\s*\]", re.I)


def row_assets(v):
    """software.asset_uuid holds ONE uuid in some navi datasets and a STRINGIFIED
    PYTHON LIST of uuids in others ("['ec88…', 'd423…']", from navi software
    generate). Return the real asset-uuid list either way."""
    v = str(v or "")
    found = _UUID_RE.findall(v)
    if found:
        return found
    v = v.strip()
    return [v] if v else []


def parse_software(s: str):
    """(name, version) for either software_string style: Windows-style
    "Name - 1.2.3  [version 1.2.3]" (the [version …] marker wins) or RPM NVR."""
    s = str(s or "").strip()
    m = _VTAG.search(s)
    if m:
        ver = m.group(1).strip()
        name = _VTAG.sub("", s)
        # drop other bracketed annotations too ("[installed on 2024/07/01]" etc.)
        name = re.sub(r"\[[^\]]*\]", "", name).strip()
        if ver and name.endswith(ver):
            name = name[: -len(ver)].rstrip().rstrip("-").rstrip()
        return (name or s), ver
    return parse_nvr(s)


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
        uus = row_assets(r["asset_uuid"])   # single uuid OR stringified list
        if not uus:
            continue
        name, version = parse_software(r["software_string"])
        if not name:
            continue
        P = prod.setdefault(name, {"name": name, "versions": {},
                                   "assets": set(), "installs": 0})
        P["installs"] += len(uus)           # one row can be N installs (list form)
        for u in uus:
            assets.add(u)
            P["assets"].add(u)
            P["versions"].setdefault(version, set()).add(u)

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


ENUM_PLUGINS = ("22869", "20811", "83991")   # SSH/Linux · Windows · macOS software enumeration
_SKIP_LINE = re.compile(r"^(here is|the following|list of|for your|note that)", re.I)


def enum_plugin_strings(asset_uuid, db_path=None, cap=2000):
    """Per-asset software raw strings parsed straight from the enumeration plugins'
    stored output — the fallback when the `software` table has no rows for an asset
    (navi software generate doesn't always cover every host).
    Shapes handled: 22869 RPM list "  <nvr>|<epoch>      <date>", 22869 Debian
    "ii  <pkg>  <ver> …", 20811/83991 "<name>  [version X] …" lines."""
    from core import db
    if not asset_uuid:
        return []
    ph = ",".join("'%s'" % p for p in ENUM_PLUGINS)
    try:
        rows = list(db.query(
            "SELECT plugin_id, output FROM vulns WHERE asset_uuid=? "
            "AND plugin_id IN (%s) AND output IS NOT NULL AND output<>''" % ph,
            (asset_uuid,), path=db_path))
    except Exception:
        return []
    out, seen = [], set()

    def add(s):
        k = s.lower()
        if s and k not in seen and len(out) < cap:
            seen.add(k)
            out.append(s)

    for r in rows:
        pid = str(r.get("plugin_id") or "")
        for raw in (r.get("output") or "").splitlines():
            s = raw.strip()
            if not s or s.endswith(":") or _SKIP_LINE.match(s):
                continue
            if pid == "22869":
                if "|" in s:                      # RPM: nvr|epoch      date
                    add(s.split("|")[0].strip())
                elif s.startswith("ii "):         # Debian: ii  pkg  ver  …
                    parts = s.split()
                    if len(parts) >= 3:
                        add(parts[1] + "-" + parts[2])
                elif re.match(r"[A-Za-z0-9][\w.+\-]*-\d", s.split()[0] if s.split() else ""):
                    add(s.split()[0])             # bare NVR token
            else:                                 # 20811 / 83991: name … [version X]
                if _VTAG.search(s):
                    add(s)
    out.sort(key=str.lower)
    return out


def tag_query_for_assets(uuids: list) -> str:
    # Select from ASSETS, not software: software.asset_uuid may be a stringified
    # LIST (see row_assets), so an IN() against it never matches on those datasets.
    inl = ",".join("'" + str(u).replace("'", "''") + "'" for u in uuids if u)
    return f"SELECT uuid AS asset_uuid FROM assets WHERE uuid IN ({inl})"
