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


# =========================================================================== build 455
# The Software page's analysis, server-side. It used to run in the BROWSER over every row of
# `software`, `cpes` and a per-(asset, plugin) vulns rollup pulled through run_sql (3.9 M rows /
# 525 MB at 150k assets; out of memory at 600k). These functions are a faithful port of the
# page's JS (parseNVR, cpeParse, verCmp, Object.keys order, eolSlug, crownRoleFor, the risk
# score) so the numbers are the ones the page showed; the page now receives the summary + one
# page of products and pages / filters the rest through the `drill` action (core.payload).
# Tags are requested by KEY (product / version / role) and the asset set is rebuilt here by
# re-streaming the inventory — never posted by the page.
import functools

from core.software_eol import EOL_ALIAS, EOL_SLUGS


def js_uuids(v):
    """The page's _swUuids: every UUID inside software.asset_uuid (single or stringified list)."""
    return _UUID_RE.findall(str(v or ""))


def parse_nvr_js(s):
    """The page's parseNVR (= parse_software, with the JS trailing-separator trim)."""
    s = str(s or "").strip()
    m = _VTAG.search(s)
    if m:
        ver = m.group(1).strip()
        name = re.sub(r"\[\s*version\s+[^\]]*\]", "", s, flags=re.I)
        name = re.sub(r"\[[^\]]*\]", "", name).strip()
        if ver and name.endswith(ver):
            name = re.sub(r"[\s\-]+$", "", name[: -len(ver)])
        return (name or s), ver
    parts = s.split("-")
    for i in range(1, len(parts)):
        if parts[i][:1] in "0123456789" and parts[i][:1]:
            return "-".join(parts[:i]), parts[i]
    return s, ""


_CPE_RE = re.compile(r"[a-z-]*cpe:/[^'\",\]]+", re.I)


def cpe_parse(s):
    """The page's cpeParse: [(name, version)] from one cpes.cpe_string."""
    out, seen = [], set()
    for entry in _CPE_RE.findall(str(s or "")):
        pkg = bool(re.match(r"^p-cpe", entry, re.I))
        parts = re.sub(r"^[a-z-]*cpe:/", "", entry, flags=re.I).split(":")
        if len(parts) < 3:
            continue
        if pkg and len(parts) > 3 and parts[3]:
            name = parts[3]
            ver = parts[4] if (len(parts) > 4 and parts[4] and re.search(r"\d", parts[4])) else ""
        else:
            name = parts[2]
            ver = parts[3] if (len(parts) > 3 and parts[3] and re.search(r"\d", parts[3])) else ""
        name = str(name or "").replace("_", " ").strip()
        if not name:
            continue
        k = (name, ver)
        if k not in seen:
            seen.add(k)
            out.append(k)
    return out


def _js_parse_int(x):
    m = re.match(r"^\s*([+-]?\d+)", x or "")
    return int(m.group(1)) if m else None


def ver_cmp(a, b):
    """The page's verCmp (JS semantics: parseInt per part; a number vs a string compares as
    Number(string), i.e. '' → 0 and anything else NaN, which compares false both ways)."""
    pa, pb = re.split(r"[._\-]", str(a)), re.split(r"[._\-]", str(b))
    for i in range(max(len(pa), len(pb))):
        xa = pa[i] if i < len(pa) else None
        xb = pb[i] if i < len(pb) else None
        na, nb = _js_parse_int(xa), _js_parse_int(xb)
        va = na if na is not None else (xa or "")
        vb = nb if nb is not None else (xb or "")
        if isinstance(va, str) and isinstance(vb, str):
            lt, gt = va < vb, va > vb
        else:
            fa = va if not isinstance(va, str) else (0 if va.strip() == "" else None)
            fb = vb if not isinstance(vb, str) else (0 if vb.strip() == "" else None)
            if fa is None or fb is None:
                lt = gt = False
            else:
                lt, gt = fa < fb, fa > fb
        if lt:
            return -1
        if gt:
            return 1
    return 0


def _js_key_order(keys):
    """Object.keys() order: canonical array-index keys ascending first, then insertion order."""
    idx = [k for k in keys if k.isdigit() and str(int(k)) == k and int(k) < 4294967295]
    si = set(idx)
    return sorted(idx, key=int) + [k for k in keys if k not in si]


def eol_slug(name):
    """The page's eolSlug: product name → endoflife.date slug, or None."""
    n = str(name or "").lower().strip()
    if not n:
        return None
    if n in EOL_ALIAS:
        return EOL_ALIAS[n]
    if n in EOL_SLUGS:
        return n
    nd = re.sub(r"[0-9._]+$", "", n)
    if nd and nd != n:
        if nd in EOL_ALIAS:
            return EOL_ALIAS[nd]
        if nd in EOL_SLUGS:
            return nd
    nb = re.sub(r"-(server|client|core|libs?|devel|common|tools|fpm|cli)$", "", n)
    if nb and nb != n:
        if nb in EOL_ALIAS:
            return EOL_ALIAS[nb]
        if nb in EOL_SLUGS:
            return nb
    return None


CROWN_ROLES = [
    ("Domain Controller / Directory", 10, ["active directory", "domain controller", "ntds", "389-ds-base", "opendj",
                                           "openldap-servers", "freeipa-server", "ipa-server", "samba", "krb5-server", "krb5kdc"]),
    ("PKI / Certificate Authority", 10, ["certificate authority", "ejbca", "step-ca", "adcs", "dogtag"]),
    ("Database", 9, ["oracle", "sql server", "mssql", "sqlserver", "mysql", "mariadb", "postgresql", "postgres", "mongodb",
                     "redis", "memcached", "cassandra", "couchbase", "elasticsearch", "influxdb", "cockroach", "db2",
                     "sybase", "neo4j", "clickhouse"]),
    ("Hypervisor / Virtualization", 9, ["esxi", "vcenter", "vsphere", "hyper-v", "hyperv", "qemu-kvm", "xen-hypervisor",
                                        "xenserver", "proxmox", "virtualbox", "libvirt-daemon"]),
    ("Backup / Recovery", 8, ["veeam", "commvault", "networker", "netbackup", "bacula", "borgbackup", "rubrik", "cohesity"]),
    ("Security Tooling", 8, ["splunk", "crowdstrike", "carbon black", "sentinelone", "defender", "clamav", "wazuh", "ossec",
                             "qradar", "nessus", "tenable", "snort", "suricata"]),
    ("Remote Access / Gateway", 8, ["openvpn", "wireguard", "strongswan", "citrix", "netscaler", "anyconnect",
                                    "globalprotect", "pulse secure", "teleport", "guacamole"]),
    ("Message Queue / Integration", 7, ["rabbitmq", "kafka", "activemq", "mulesoft"]),
    ("Web / App Server", 7, ["nginx", "httpd", "tomcat", "jboss", "wildfly", "websphere", "weblogic", "iis"]),
]
# client libraries, CLI tools and guest agents are on every host — they don't make the host the server
_CROWN_NOT = re.compile(r"(^|[-_ ])(libs?|client|clients|common|devel|utils|tools|doc|docs|headers|guest-agent|"
                        r"guest-tools|compat|connector|filesystem|python3?|perl)([-_ .]|$)|^(lib(?!virt-daemon)|python3?-|perl-)")


def crown_role(name):
    """The page's crownRoleFor: (role, acr) or None."""
    n = str(name or "").lower()
    if _CROWN_NOT.search(n):
        return None
    for role, acr, kws in CROWN_ROLES:
        for k in kws:
            if k in n:
                return role, acr
    return None


def _like_lit(s):
    return str(s).replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def product_sets(db_path=None, only=None):
    """Stream `software` + `cpes` (db.iter) and aggregate products exactly as the page did.
    Returns (prod, info): prod = {lower name: {name, versions{v: set(int)}, assets set(int),
    installs, soft, cpe}} with asset ids as small ints; info = {ids (uuid→int), records, cpe_rows,
    soft_assets, cpe_assets, all_assets}. `only` = product keys to keep (rows are pre-filtered
    in SQL by a LIKE on each name, then matched exactly after parsing)."""
    ids = {}

    def aid(u):
        i = ids.get(u)
        if i is None:
            i = ids[u] = len(ids)
        return i
    prod, soft_a, cpe_a, all_a = {}, set(), set(), set()
    recs = cpe_rows = 0
    where_s = where_c = ""
    args_s, args_c = [], []
    if only is not None:
        names = sorted(only)
        if not names:
            return prod, {"ids": ids, "records": 0, "cpe_rows": 0, "soft_assets": soft_a, "cpe_assets": cpe_a,
                          "all_assets": all_a}
        # pre-filter on each name's longest token: the parsed name isn't always a substring of
        # the raw string (parse_nvr_js drops middle "[…]" groups, collapses spaces), and SQLite
        # LIKE folds ASCII case only — so a non-ASCII name skips the pre-filter entirely. The
        # exact match after parsing still decides.
        toks = [max(re.split(r"\s+", n.strip()) or [n], key=len) for n in names]
        if len(names) <= 40 and all(t and t.isascii() for t in toks):
            where_s = " AND (" + " OR ".join(["software_string LIKE ? ESCAPE '\\'"] * len(names)) + ")"
            args_s = ["%" + _like_lit(t) + "%" for t in toks]
            where_c = " AND (" + " OR ".join(["cpe_string LIKE ? ESCAPE '\\'"] * len(names)) + ")"
            # cpe names are stored with '_' for ' ' — a '_' wildcard matches either
            args_c = ["%" + _like_lit(n).replace(" ", "_") + "%" for n in names]

    def P(name):
        k = str(name).lower()
        p = prod.get(k)
        if p is None:
            p = prod[k] = {"name": name, "versions": {}, "assets": set(), "installs": 0, "soft": False, "cpe": False}
        return p
    for asset, sstr in db.iter("SELECT asset_uuid, software_string FROM software WHERE software_string IS NOT NULL "
                               "AND software_string<>''" + where_s, tuple(args_s), path=db_path, tuples=True,
                               budget="job"):
        recs += 1
        uu = [aid(u) for u in js_uuids(asset)]
        if only is None:
            all_a.update(uu)
            soft_a.update(uu)
        name, ver = parse_nvr_js(sstr)
        if not name or (only is not None and str(name).lower() not in only):
            continue
        p = P(name)
        p["soft"] = True
        p["installs"] += 1
        vs = p["versions"].setdefault(ver, set())
        p["assets"].update(uu)
        vs.update(uu)
    try:
        has_cpes = bool(db.scalar("SELECT 1 FROM sqlite_master WHERE type='table' AND name='cpes'", path=db_path))
    except Exception:
        has_cpes = False
    if has_cpes:
        for asset, cstr in db.iter("SELECT asset_uuid, cpe_string FROM cpes WHERE cpe_string IS NOT NULL "
                                   "AND cpe_string<>''" + where_c, tuple(args_c), path=db_path, tuples=True,
                                   budget="job"):
            cpe_rows += 1
            if not asset:
                continue
            i = aid(asset)
            if only is None:
                all_a.add(i)
                cpe_a.add(i)
            for name, ver in cpe_parse(cstr):
                if only is not None and name.lower() not in only:
                    continue
                p = P(name)
                p["cpe"] = True
                p["installs"] += 1
                p["assets"].add(i)
                p["versions"].setdefault(ver or "", set()).add(i)
    return prod, {"ids": ids, "records": recs, "cpe_rows": cpe_rows, "soft_assets": soft_a, "cpe_assets": cpe_a,
                  "all_assets": all_a}


def sorted_versions(p):
    """[(version, asset set)] newest first — verCmp desc over Object.keys order (stable sort)."""
    keys = _js_key_order(list(p["versions"].keys()))
    keys = sorted(keys, key=functools.cmp_to_key(lambda a, b: ver_cmp(b, a)))
    return [(v, p["versions"][v]) for v in keys]


def _src(p):
    return "both" if (p["soft"] and p["cpe"]) else ("cpe" if p["cpe"] else "software")


_SRC_ORDER = {"cpe": 0, "software": 1, "both": 2}


def product_row(p):
    vers = sorted_versions(p)
    return {"name": p["name"], "nver": len(vers), "nasset": len(p["assets"]), "installs": p["installs"],
            "vers": [{"v": v, "assets": len(a)} for v, a in vers], "newest": vers[0][0] if vers else "",
            "src": _src(p)}


def product_flags(row, eol=None):
    f = ["multi" if row["nver"] > 1 else None, "single" if row["nasset"] == 1 else None,
         "delta" if row["src"] != "both" else None, "src:" + row["src"]]
    if eol and (eol.get("eolAssetCount") or 0) > 0:
        f.append("eol")
    return f


def product_keys(row, eol=None):
    """s1..s6 for the product views: sprawl (s1,s2) · common (s2,s3) · single/all (s4) ·
    eol (s5) · delta (s6,s2) — ascending, counts negated for 'most first'."""
    return (-row["nver"], -row["nasset"], -row["installs"], row["name"].lower(),
            -((eol or {}).get("eolAssetCount") or 0), _SRC_ORDER.get(row["src"], 3))


def inventory(db_path=None):
    """▶ Run: the inventory summary (the page's KPI row), every product written to the result
    store (one row each — versions with asset COUNTS, never uuids) and the crown-jewel roles.
    Returns {run, summary, crown}."""
    from core import payload
    prod, info = product_sets(db_path)
    keys = _js_key_order(list(prod.keys()))
    W = payload.STORE.begin("software")
    W.section("products")
    multi = single = only_soft = only_cpe = both = pairs = 0
    roles = {}
    try:
        for k in keys:
            p = prod[k]
            row = product_row(p)
            pairs += row["nver"]
            multi += row["nver"] > 1
            single += row["nasset"] == 1
            only_soft += row["src"] == "software"
            only_cpe += row["src"] == "cpe"
            both += row["src"] == "both"
            W.add("products", row, flags=product_flags(row), keys=product_keys(row), text=row["name"], rk=k)
            cr = crown_role(p["name"])
            if cr:
                b = roles.setdefault(cr[0], {"role": cr[0], "acr": cr[1], "products": [], "assets": set()})
                if p["name"] not in b["products"]:
                    b["products"].append(p["name"])
                b["assets"] |= p["assets"]
        role_l = sorted(roles.values(), key=lambda r: (-r["acr"], -len(r["assets"])))
        crown_assets = set()
        for r in role_l:
            crown_assets |= r["assets"]
        crown = {"roles": [{"role": r["role"], "acr": r["acr"], "products": r["products"][:12],
                            "nproducts": len(r["products"]), "assets": len(r["assets"])} for r in role_l],
                 "assets": len(crown_assets)}
        sa, ca = info["soft_assets"], info["cpe_assets"]
        summary = {"records": info["records"], "nprod": len(prod), "pairs": pairs, "multi": multi, "single": single,
                   "nasset": len(info["all_assets"]), "softAssets": len(sa), "cpeAssets": len(ca),
                   "onlySoft": only_soft, "onlyCpe": only_cpe, "both": both,
                   "cpeOnlyAssets": len(ca - sa), "softOnlyAssets": len(sa - ca), "haveCpe": info["cpe_rows"] > 0}
        W.meta = {"summary": summary, "crown": crown}
    except BaseException:
        W.close(ok=False)
        raise
    W.close()
    return {"run": W.run, "summary": summary, "crown": crown}


def assets_for(db_path=None, product=None, version=None, role=None, versions=None):
    """The asset uuids behind a software tag KEY — rebuilt from navi.db, never taken from the
    page: a product (optionally one version, or a list of versions), or a crown-jewel role."""
    if role:
        prod, info = product_sets(db_path)
        sel = set()
        for p in prod.values():
            cr = crown_role(p["name"])
            if cr and cr[0] == role:
                sel |= p["assets"]
    else:
        key = str(product or "").lower()
        if not key:
            return []
        prod, info = product_sets(db_path, only={key})
        p = prod.get(key)
        if not p:
            return []
        if version is not None:
            sel = set(p["versions"].get(str(version), set()))
        elif versions is not None:
            sel = set()
            for v in versions:
                sel |= p["versions"].get(str(v), set())
        else:
            sel = set(p["assets"])
    rev = {i: u for u, i in info["ids"].items()}
    return sorted(rev[i] for i in sel if i in rev)


_TEN_EOL_PATS = ("unsupported", "end of life", "end-of-life", "no longer supported", "obsolete", "seol")


def tenable_eol_assets(db_path=None):
    """Assets Tenable flags as running EOL / unsupported software (plugin NAME match — the
    page's own query; one vulns scan that returns only uuids, streamed)."""
    from core import hx_summary
    w = " OR ".join("lower(plugin_name) LIKE '%%%s%%'" % p for p in _TEN_EOL_PATS)
    q = "SELECT DISTINCT asset_uuid FROM vulns WHERE " + w
    if hx_summary.usable(db_path):
        # Phase 1: the same name rule on hx_plugin.lname, assets off covering hx_v_plugin ranges
        q = hx_summary.assets_with("(" + w.replace("lower(plugin_name)", "lname") + ")", path=db_path)
    out = set()
    for (u,) in db.iter(q, path=db_path, tuples=True, budget="job"):
        if u:
            out.add(u)
    return out


def eol_plan(run):
    """The products endoflife.date can answer for (slug-matched), with their version strings —
    what the browser looks up (one GET per slug, cached 7 days in the browser)."""
    from core import payload
    out = []
    for row in payload.STORE.iter_rows(run, "products"):
        slug = eol_slug(row.get("name"))
        if slug:
            out.append({"name": row["name"], "slug": slug, "newest": row.get("newest") or "",
                        "versions": [v["v"] for v in row.get("vers") or []][:400]})
    return out


def lifecycle(run, results, db_path=None):
    """Apply the browser's endoflife.date verdicts ([{name, slug, latest, eolVers, noData}]) to a
    stored inventory run: per product the assets on EOL versions and behind the latest release,
    unioned with Tenable's own EOL plugins. Updates the stored product rows (EOL view / column)
    and returns the run's EOL counts."""
    from core import payload
    want = {}
    for r in results or []:
        if isinstance(r, dict) and isinstance(r.get("name"), str):
            want[r["name"].lower()] = r
    prod, info = product_sets(db_path, only=set(want)) if want else ({}, {"ids": {}})
    rev = {i: u for u, i in info["ids"].items()}
    ten = tenable_eol_assets(db_path)
    ten_i = {info["ids"][u] for u in ten if u in info["ids"]}
    eol_assets, checked, eol_prod = set(), 0, 0
    for k, r in want.items():
        stored = payload.STORE.row(run, "products", k)
        if stored is None:
            continue
        p = prod.get(k)
        if r.get("noData") or not p:
            e = {"slug": r.get("slug"), "checked": True, "noData": True}
        else:
            checked += 1
            eol_vers = [str(v) for v in (r.get("eolVers") or []) if v is not None][:5000]
            latest = str(r.get("latest") or "")
            ev = set(eol_vers)
            eu, behind = set(), set()
            for v, a in p["versions"].items():
                if v in ev:
                    eu |= a
                elif latest and v and ver_cmp(v, latest) < 0:
                    behind |= a
            e = {"slug": r.get("slug"), "checked": True, "latest": latest, "eolVers": eol_vers,
                 "eolAssetCount": len(eu), "behindAssets": len(behind),
                 "behind": latest if (stored.get("newest") and latest and ver_cmp(stored["newest"], latest) < 0) else "",
                 "tenConfirmed": len(eu & ten_i) if eu else 0}
            if eu:
                eol_prod += 1
                eol_assets |= eu
        stored["eol"] = e
        payload.STORE.update_row(run, "products", k, row=stored, flags=product_flags(stored, e),
                                 keys={"s5": -(e.get("eolAssetCount") or 0)})
    combined = {rev[i] for i in eol_assets if i in rev} | ten
    eol = {"checkedProducts": checked, "eolProducts": eol_prod, "eolAssets": len(combined),
           "eolAssetsEndoflife": len(eol_assets), "tenEolAssets": len(ten)}
    payload.STORE.set_meta(run, eol=eol)
    return eol


def risk(run, db_path=None, top=40):
    """The risk leaderboard, server-side: per product, host-level exposure (KEV / critical
    findings / max VPR on the hosts that run it) and package-level exposure (findings whose
    plugin NAME contains the product). Instead of shipping every (asset, plugin) pair to the
    browser: one per-plugin catalog pass (GROUP BY plugin_id — tens of thousands of rows), a
    per-ASSET rollup joined to it inside SQLite (covered by hx_v_asset when present), and the
    (plugin, asset) pairs of the NAMED plugins only (covered by hx_v_plugin).
    Returns {rows (top N), total, named}."""
    from core import payload
    prod, info = product_sets(db_path)
    ids = info["ids"]
    eolc = {}
    for row in payload.STORE.iter_rows(run, "products", flags=["eol"]):
        eolc[row["name"].lower()] = (row.get("eol") or {}).get("eolAssetCount") or 0
    con = db.connect(db_path)
    # this private connection is opened mode=ro (navi.db itself can never be written); lifting
    # query_only lets it hold two TEMP tables (the plugin catalog + the named-plugin set)
    con.execute("PRAGMA query_only=0")
    try:
        from core import hx_summary
        if hx_summary.usable(db_path):
            # Phase 1: the per-plugin catalog IS hx_plugin (name / KEV xref / VPR are plugin attributes)
            cat = con.execute("SELECT plugin_id, lname, kev, vpr FROM hx_plugin").fetchall()
        else:
            vc = {r[1] for r in con.execute("PRAGMA table_info(vulns)")}
            kx = ("MAX(CASE WHEN xrefs LIKE '%CISA-KNOWN-EXPLOITED%' THEN 1 ELSE 0 END)"
                  if "xrefs" in vc else "0")             # older navi.db: no xrefs / score columns
            sx = "MAX(CAST(score AS REAL))" if "score" in vc else "0"
            cat = con.execute("SELECT plugin_id, lower(MAX(plugin_name)), %s, %s FROM vulns GROUP BY plugin_id"
                              % (kx, sx)).fetchall()
        con.execute("CREATE TEMP TABLE IF NOT EXISTS _cat(plugin_id TEXT PRIMARY KEY, kev INT, vpr REAL)")
        con.execute("DELETE FROM _cat")
        con.executemany("INSERT OR REPLACE INTO _cat VALUES(?,?,?)", [(c[0], c[2] or 0, c[3] or 0.0) for c in cat])
        hv = db.indexed_by("hx_v_asset", db_path)
        roll = {}
        for u, kev, crit, vpr, n in con.execute(
                "SELECT v.asset_uuid, MAX(c.kev), MAX(CASE WHEN lower(v.severity)='critical' OR v.severity='4' "
                "THEN 1 ELSE 0 END), MAX(c.vpr), COUNT(*) FROM vulns v%s LEFT JOIN _cat c ON c.plugin_id=v.plugin_id "
                "GROUP BY v.asset_uuid" % hv):
            i = ids.get(u)
            if i is not None:
                roll[i] = (kev or 0, crit or 0, vpr or 0.0, n or 0)
        names = [k for k in prod if len(k) >= 3]
        named_pids = {}
        for pid, pn, _kev, _vpr in cat:
            pn = pn or ""
            hit = [k for k in names if k in pn]
            if hit:
                named_pids[pid] = hit
        pk = {}          # product key -> {asset int: [kev, crit, findings, vpr]}
        if named_pids:
            hp = db.indexed_by("hx_v_plugin", db_path)
            kevp = {c[0]: (c[2] or 0, c[3] or 0.0) for c in cat}
            con.execute("CREATE TEMP TABLE IF NOT EXISTS _np(plugin_id TEXT PRIMARY KEY)")
            con.execute("DELETE FROM _np")
            con.executemany("INSERT OR IGNORE INTO _np VALUES(?)", [(x,) for x in named_pids])
            for pid, u, crit, n in con.execute(
                    "SELECT v.plugin_id, v.asset_uuid, MAX(CASE WHEN lower(v.severity)='critical' OR v.severity='4' "
                    "THEN 1 ELSE 0 END), COUNT(*) FROM vulns v%s WHERE v.plugin_id IN (SELECT plugin_id FROM _np) "
                    "GROUP BY v.plugin_id, v.asset_uuid" % hp):
                i = ids.get(u)
                if i is None:
                    continue
                kv, vp = kevp.get(pid, (0, 0.0))
                for k in named_pids.get(pid, ()):
                    if i not in prod[k]["assets"]:
                        continue
                    d = pk.setdefault(k, {}).setdefault(i, [0, 0, 0, 0.0])
                    d[0] = d[0] or kv
                    d[1] = d[1] or crit
                    d[2] += n
                    d[3] = max(d[3], vp)
    finally:
        con.close()
    rows = []
    for k in _js_key_order(list(prod.keys())):
        p = prod[k]
        kev = crit = find = 0
        vpr = 0.0
        for i in p["assets"]:
            r = roll.get(i)
            if not r:
                continue
            kev += 1 if r[0] else 0
            crit += 1 if r[1] else 0
            find += r[3]
            vpr = max(vpr, r[2])
        D = pk.get(k, {})
        pkv = sum(1 for d in D.values() if d[0])
        pc = sum(1 for d in D.values() if d[1])
        pf = sum(d[2] for d in D.values())
        pv = max([d[3] for d in D.values()] or [0.0])
        eol = eolc.get(k, 0)
        score = pkv * 1000 + pc * 200 + min(pf, 500) * 2 + pv * 10 + kev * 50 + crit * 10 + eol * 30 + min(find, 500) * 0.2
        if kev or crit or find or pf:
            rows.append({"name": p["name"], "nasset": len(p["assets"]), "kev": kev, "crit": crit, "find": find,
                         "vpr": vpr, "pk": pkv, "pc": pc, "pf": pf, "pv": pv, "eol": eol, "risk": score})
    rows.sort(key=lambda x: (-x["risk"], -x["pk"], -x["kev"], -x["eol"]))
    return {"rows": rows[:top], "total": len(rows), "named": sum(1 for x in rows if x["pf"])}
