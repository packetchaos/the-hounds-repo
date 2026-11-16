"""Software search — the engine behind the Software Explorer (Harrier).

Finds where a piece of software is installed across navi.db's `software` table (and `cpes`,
when navi has it), by product name or search term, optionally narrowed to one version or a
version RANGE ("is anything in the affected range of this new CVE?").

  search(q, product, version, ranges)  → products, KPIs, where-installed breakdowns, and the
                                          per-asset rows (status + versions), all computed over
                                          the WHOLE selection; the caller pages the rows.

Versions come from the same parser as Mimir (core.software.parse_nvr_js), so both hounds
agree on what a product and a version are. Matching is deterministic: a model never decides
whether an asset is affected.

Statuses (per asset, worst wins across the matched installs on that asset):
  affected   the version is inside the range
  check      inside the range, but it is a DISTRO BUILD (RHEL / Ubuntu / Debian / SUSE …) —
             distros back-port fixes without changing the upstream version, so confirm against
             the distro's own advisory before calling it vulnerable
  unknown    no version to compare (navi recorded the product without one)
  clear      outside the range
With no range every install is "match" (no verdict).

Range syntax (also what the zero-day lookup fills in): clauses separated by ';' or '||' are
OR'd; inside a clause, constraints separated by spaces or commas are AND'd. A constraint is
<, <=, >, >=, = (or ==) followed by a version; a bare version means exactly that version.
  "<2.4.60"      ">=2.0 <2.17.1; >=2.18 <2.18.2"      "3.0.2"
"""
import functools
import re

from core import db
from core import software as sw

# ── versions ──────────────────────────────────────────────────────────────────
_PRE = ("dev", "alpha", "a", "beta", "b", "pre", "preview", "c", "rc", "cr", "m")
_PRE_WORD = re.compile(r"(dev|alpha|beta|pre|preview|rc|cr)\w*$")
_TOK = re.compile(r"\d+|[a-zA-Z]+")


def _tokens(v):
    """Numbers as ints, words lower-case; a PRE-RELEASE word is marked '~word'. 'rc', 'beta',
    'alpha', 'dev', 'pre' always are; a lone a / b / c / m only when a number follows (1.2a1 is
    an alpha, but OpenSSL's 1.0.2a is a release after 1.0.2)."""
    v = str(v or "").strip()
    v = re.sub(r"^\d+:", "", v)                 # RPM / DEB epoch "1:2.3.4"
    v = re.sub(r"^[vV](?=\d)", "", v)           # "v1.2"
    raw = _TOK.findall(v)
    out = []
    for i, t in enumerate(raw):
        if t.isdigit():
            out.append(int(t))
            continue
        t = t.lower()
        nxt_num = i + 1 < len(raw) and raw[i + 1].isdigit()
        if _PRE_WORD.match(t) or (t in ("a", "b", "c", "m") and nxt_num):
            t = "~" + t
        out.append(t)
    return out


def _is_pre(t):
    return isinstance(t, str) and t.startswith("~")


def _pre_rank(t):
    w = t[1:]
    m = _PRE_WORD.match(w)
    w = m.group(1) if m else w
    return _PRE.index(w) if w in _PRE else 0


def vcmp(a, b) -> int:
    """Compare two version strings: -1 / 0 / 1. Numbers compare as numbers, letters as text,
    so 1.0.2k < 1.0.2u and 2.4.9 < 2.4.10. A pre-release tail (rc1, beta2, dev) sorts BEFORE
    the release (2.0rc1 < 2.0); any other extra tail sorts after (1.0.2 < 1.0.2a); where a
    number meets letters the number is newer (RPM's rule: 1.0.2a < 1.0.2.1)."""
    ta, tb = _tokens(a), _tokens(b)
    for i in range(max(len(ta), len(tb))):
        if i >= len(ta) or i >= len(tb):
            rest, sign = (tb[i:], -1) if i >= len(ta) else (ta[i:], 1)
            rest = [x for j, x in enumerate(rest) if not (x == 0 and all(y == 0 for y in rest[:j + 1]))]
            if not rest:                           # only zeros left: 2.0 == 2.0.0
                return 0
            first = rest[0]                        # first non-zero part: 2.0.0rc1 < 2.0
            if _is_pre(first):
                return -sign
            return sign
        x, y = ta[i], tb[i]
        if x == y:
            continue
        if isinstance(x, int) and isinstance(y, int):
            return -1 if x < y else 1
        if isinstance(x, str) and isinstance(y, str):
            px, py = _is_pre(x), _is_pre(y)
            if px and py:
                ox, oy = _pre_rank(x), _pre_rank(y)
                if ox != oy:
                    return -1 if ox < oy else 1
            elif px or py:
                return -1 if px else 1
            return -1 if x < y else 1
        # number vs letters: the number is newer (RPM's rule — 1.0.2a < 1.0.2.1)
        return -1 if isinstance(x, str) else 1
    return 0


_OPS = ("<=", ">=", "==", "<", ">", "=")
_CONSTRAINT = re.compile(r"(<=|>=|==|<|>|=)?\s*([0-9vV][^\s,;|<>=]*)")


def parse_ranges(text):
    """'>=2.0 <2.17.1; >=2.18 <2.18.2' → [[('>=','2.0'),('<','2.17.1')],[...]].
    Raises ValueError on text that isn't a range (so the page can say so)."""
    text = str(text or "").strip()
    if not text:
        return []
    out = []
    for clause in re.split(r"\|\||;", text):
        clause = clause.strip()
        if not clause:
            continue
        cons, pos = [], 0
        for m in _CONSTRAINT.finditer(clause):
            gap = clause[pos:m.start()].strip(" ,")
            if gap:
                raise ValueError("can't read %r in the range %r" % (gap, clause))
            cons.append((m.group(1) or "=", m.group(2)))
            pos = m.end()
        if clause[pos:].strip(" ,"):
            raise ValueError("can't read %r in the range %r" % (clause[pos:].strip(), clause))
        if not cons:
            raise ValueError("no version in %r" % clause)
        out.append(cons)
    return out


def ranges_text(ranges):
    """The inverse of parse_ranges (for display / the page's range box)."""
    return "; ".join(" ".join((op if op != "=" else "") + v for op, v in c) for c in ranges or [])


def in_ranges(version, ranges) -> bool:
    for clause in ranges:
        ok = True
        for op, v in clause:
            c = vcmp(version, v)
            if not ((op in ("=", "==") and c == 0) or (op == "<" and c < 0) or (op == "<=" and c <= 0)
                    or (op == ">" and c > 0) or (op == ">=" and c >= 0)):
                ok = False
                break
        if ok:
            return True
    return False


# a package built by a distro (upstream version + the distro's own release) — RPM / DEB / SUSE
_DISTRO = re.compile(r"(\.el\d|\.amzn\d|\.fc\d+|\.module[+_]|ubuntu|\bdeb\d|\+deb|debian|\.sles|\.suse|"
                     r"\.mga\d|\.oe\d|\.ol\d|\.al\d|\.photon|\.cm\d|\.azl\d)", re.I)


def distro_build(raw) -> bool:
    return bool(_DISTRO.search(str(raw or "")))


# ── search ────────────────────────────────────────────────────────────────────
STATUS_ORDER = {"affected": 0, "check": 1, "unknown": 2, "match": 3, "clear": 4}
_TOP = 12


def _like(s):
    return "%" + re.sub(r"([\\%_])", r"\\\1", s) + "%"


def _has(table, path=None):
    try:
        return bool(db.scalar("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,), path=path,
                              budget=0))
    except Exception:
        return False


def _cols(table, path=None):
    try:
        return {r["name"] for r in db.query('PRAGMA table_info("%s")' % table, path=path, budget=0)}
    except Exception:
        return set()


def _status(ver, raw, ranges):
    if not ranges:
        return "match"
    if not str(ver or "").strip():
        return "unknown"
    if in_ranges(ver, ranges):
        return "check" if distro_build(raw) else "affected"
    return "clear"


def _name_ok(name, q, product, exact):
    n = name.lower()
    if product:
        return n == product
    return n == q if exact else q in n


def search(q="", product="", version="", ranges=None, exact=False, path=None):
    """The whole selection for a term (substring of the product name) or one exact product,
    optionally narrowed by `version` (exact; 'x*' = prefix) and/or `ranges` (parse_ranges).
    Returns {products, kpi, breakdowns, rows, ranges} — rows is every matched asset, sorted
    affected → check → unknown → others, then ACR high → low (the caller pages it)."""
    q = str(q or "").strip().lower()
    product = str(product or "").strip().lower()
    version = str(version or "").strip()
    ranges = ranges or []
    term = product or q
    if len(term) < 2:
        raise ValueError("type at least 2 characters of a product name")
    vprefix = version.endswith("*")
    vwant = version.rstrip("*").strip()

    prods = {}         # lower name → {name, versions{v: set(uuid)}, assets set, src set}
    per_asset = {}     # uuid → {versions: {(product, ver)}, status}
    records = 0

    def add(uuid, name, ver, raw, src):
        if vwant and not (ver.startswith(vwant) if vprefix else vcmp(ver, vwant) == 0 and ver):
            return
        st = _status(ver, raw, ranges)
        k = name.lower()
        p = prods.get(k)
        if p is None:
            p = prods[k] = {"name": name, "versions": {}, "assets": set(), "src": set(), "st": {}}
        p["versions"].setdefault(ver, set()).add(uuid)
        p["assets"].add(uuid)
        p["src"].add(src)
        vk = (ver, st)
        p["st"][vk] = p["st"].get(vk, 0) + 1
        a = per_asset.get(uuid)
        if a is None:
            a = per_asset[uuid] = {"installs": {}, "status": st}
        ik = (name, ver)                        # one install per product+version (worst status wins),
        old = a["installs"].get(ik)             # so a range doesn't change the install count
        if old is None or STATUS_ORDER[st] < STATUS_ORDER[old]:
            a["installs"][ik] = st
        if STATUS_ORDER[st] < STATUS_ORDER[a["status"]]:
            a["status"] = st

    # SQLite LIKE folds ASCII case only — a non-ASCII term is matched after parsing instead
    pre = term.isascii()
    toks = [t for t in re.split(r"\s+", term) if t]
    key = max(toks, key=len) if toks else term
    if _has("software", path):
        sql = ("SELECT asset_uuid, software_string FROM software WHERE software_string IS NOT NULL "
               "AND software_string<>''" + (" AND software_string LIKE ? ESCAPE '\\'" if pre else ""))
        for au, s in db.iter(sql, (_like(key),) if pre else (), path=path, tuples=True, budget="job"):
            records += 1
            name, ver = sw.parse_nvr_js(s)
            if not name or not _name_ok(name, q, product, exact):
                continue
            for u in sw.js_uuids(au):
                add(u, name, ver, s, "software")
    if _has("cpes", path):
        sql = ("SELECT asset_uuid, cpe_string FROM cpes WHERE cpe_string IS NOT NULL AND cpe_string<>''"
               + (" AND cpe_string LIKE ? ESCAPE '\\'" if pre else ""))
        # cpe names are stored with '_' for ' ' — '_' is a LIKE wildcard, so either spelling hits
        arg = (_like(key).replace(" ", "_"),) if pre else ()
        for au, s in db.iter(sql, arg, path=path, tuples=True, budget="job"):
            records += 1
            if not au:
                continue
            for name, ver in sw.cpe_parse(s):
                if _name_ok(name, q, product, exact):
                    add(str(au), name, ver or "", "", "cpe")

    # assets: host / IP / OS / network / ACR for every matched uuid
    ac = _cols("assets", path)
    want = [c for c in ("uuid", "hostname", "ip_address", "operating_system", "network", "acr", "last_found")
            if c in ac]
    meta = {}
    if per_asset and "uuid" in ac:
        sel = ", ".join(want)
        uu = list(per_asset)
        if len(uu) <= 4000:
            for i in range(0, len(uu), 900):
                part = uu[i:i + 900]
                for r in db.query("SELECT %s FROM assets WHERE uuid IN (%s)" % (sel, ",".join("?" * len(part))),
                                  tuple(part), path=path, budget="job"):
                    meta[r["uuid"]] = r
        else:                                   # big selection: one pass over assets beats 900-uuid IN lists
            for r in db.iter("SELECT %s FROM assets" % sel, path=path, budget="job"):
                if r["uuid"] in per_asset:
                    meta[r["uuid"]] = r

    def acr(u):
        try:
            return float((meta.get(u) or {}).get("acr"))
        except (TypeError, ValueError):
            return None

    rows = []
    for u, a in per_asset.items():
        m = meta.get(u) or {}
        inst = sorted(((n, v, s) for (n, v), s in a["installs"].items()), key=lambda x: (STATUS_ORDER[x[2]], x[0].lower(), x[1]))
        rows.append({"asset_uuid": u, "hostname": m.get("hostname"), "ip_address": m.get("ip_address"),
                     "operating_system": m.get("operating_system"), "network": m.get("network"),
                     "acr": m.get("acr"), "last_found": m.get("last_found"), "status": a["status"],
                     "installs": [{"product": n, "version": v, "status": s} for n, v, s in inst],
                     "ninstalls": len(inst), "in_assets": bool(m)})
    rows.sort(key=lambda r: (STATUS_ORDER[r["status"]], -(acr(r["asset_uuid"]) or -1),
                             str(r["hostname"] or r["ip_address"] or r["asset_uuid"]).lower()))

    # products (newest version first)
    plist = []
    for p in prods.values():
        vers = sorted(p["versions"], key=functools.cmp_to_key(lambda a, b: vcmp(b, a)))
        aff = {s: set() for s in STATUS_ORDER}
        for v in vers:
            for u in p["versions"][v]:
                aff[_status_of(p, v)].add(u)
        plist.append({"name": p["name"], "assets": len(p["assets"]), "nver": len(vers),
                      "newest": vers[0] if vers else "", "oldest": vers[-1] if vers else "",
                      "src": "both" if len(p["src"]) > 1 else next(iter(p["src"])),
                      "affected": len(aff["affected"]), "check": len(aff["check"]),
                      "versions": [{"v": v, "assets": len(p["versions"][v]), "status": _status_of(p, v)}
                                   for v in vers[:60]]})
    plist.sort(key=lambda p: (-(p["affected"] + p["check"]), -p["assets"], p["name"].lower()))

    # KPIs + where-installed breakdowns, over the whole selection
    cnt = {s: 0 for s in STATUS_ORDER}
    for r in rows:
        cnt[r["status"]] += 1
    allv = {}
    for p in prods.values():
        for v, us in p["versions"].items():
            k = (p["name"], v)
            allv[k] = (len(us), _status_of(p, v))
    crown = sum(1 for r in rows if (acr(r["asset_uuid"]) or 0) >= 9)
    crown_hit = sum(1 for r in rows if (acr(r["asset_uuid"]) or 0) >= 9 and r["status"] in ("affected", "check"))
    kpi = {"assets": len(rows), "products": len(prods), "versions": len(allv),
           "installs": sum(len(r["installs"]) for r in rows), "records": records,
           "affected": cnt["affected"], "check": cnt["check"], "unknown": cnt["unknown"], "clear": cnt["clear"],
           "crown": crown, "crown_hit": crown_hit, "not_in_assets": sum(1 for r in rows if not r["in_assets"]),
           "ranged": bool(ranges)}

    def top(keyf, n=8):
        c = {}
        for r in rows:
            k = keyf(r)
            b = c.setdefault(k, {"label": k, "assets": 0, "aff": 0, "chk": 0})
            b["assets"] += 1
            b["aff"] += r["status"] == "affected"
            b["chk"] += r["status"] == "check"
        out = sorted(c.values(), key=lambda b: (-b["assets"], str(b["label"])))
        if len(out) > n:
            rest = out[n:]
            out = out[:n] + [{"label": "other (%d)" % len(rest), "assets": sum(b["assets"] for b in rest),
                              "aff": sum(b["aff"] for b in rest), "chk": sum(b["chk"] for b in rest), "other": True}]
        return out

    vtop = sorted(({"label": (k[1] or "(no version)"), "product": k[0], "assets": n, "status": s}
                   for k, (n, s) in allv.items()), key=lambda b: (-b["assets"], b["product"].lower()))
    breakdowns = {
        "versions": vtop[:_TOP], "versions_more": max(0, len(vtop) - _TOP),
        "os": top(lambda r: os_family(r.get("operating_system"))),
        "network": top(lambda r: (str(r.get("network") or "").strip() or "(no network)")),
        "acr": top(lambda r: acr_band(acr(r["asset_uuid"])), n=6),
    }
    return {"products": plist, "kpi": kpi, "breakdowns": breakdowns, "rows": rows,
            "ranges": ranges_text(ranges)}


def _status_of(p, v):
    """The status a product version carries (a version can be a distro build on one asset and
    upstream on another — the worse wins)."""
    best = None
    for (vv, s) in p["st"]:
        if vv == v and (best is None or STATUS_ORDER[s] < STATUS_ORDER[best]):
            best = s
    return best or "match"


def os_family(os_text):
    s = str(os_text or "").strip()
    if not s:
        return "(no OS)"
    s = s.split("\n")[0].strip()
    m = re.match(r"(Microsoft Windows (?:Server )?\d{2,4}(?: R2)?|Microsoft Windows \w+|"
                 r"(?:Red Hat Enterprise Linux|CentOS(?: Linux| Stream)?|Rocky Linux|AlmaLinux|Oracle Linux|"
                 r"Amazon Linux|SUSE Linux Enterprise Server|Debian(?: GNU/Linux)?|Fedora)\s*\d*|"
                 r"Ubuntu(?:\s+\d+\.\d+)?|"
                 r"macOS(?: \w+)?|Mac OS X(?: \d+)?|Cisco \w+|FreeBSD \d+)", s, re.I)
    return (m.group(1).strip() if m else s)[:60]


def acr_band(a):
    if a is None:
        return "ACR not set"
    if a >= 9:
        return "ACR 9–10 (crown)"
    if a >= 7:
        return "ACR 7–8"
    if a >= 4:
        return "ACR 4–6"
    return "ACR 1–3"


def multi_count(specs, path=None, max_terms=60):
    """The zero-day lookup's "do we have it?" for many products in ONE pass over software (+ cpes).
    specs = [{key, terms[], ranges(text)}] → {key: {assets, affected, check, unknown, clear,
    versions, products[{name, assets}], terms}}. A term matches a product whose name CONTAINS
    it (case-insensitive); terms shorter than 3 characters are skipped (too broad)."""
    work = []
    for sp in specs:
        try:
            rg = parse_ranges(sp.get("ranges") or "")
        except ValueError:
            rg = []
        ts = []
        for t in sp.get("terms") or []:
            t = str(t or "").strip().lower()
            if len(t) >= 3 and t not in ts:
                ts.append(t)
        work.append({"key": sp["key"], "terms": ts, "ranges": rg, "assets": {}, "names": {}, "vers": set()})
    allterms = sorted({t for w in work for t in w["terms"]})[:max_terms]
    allset = set(allterms)
    for w in work:
        w["terms"] = [t for t in w["terms"] if t in allset]

    def hit(uuid, name, ver, raw):
        n = name.lower()
        for w in work:
            if any(t in n for t in w["terms"]):
                st = _status(ver, raw, w["ranges"])
                cur = w["assets"].get(uuid)
                if cur is None or STATUS_ORDER[st] < STATUS_ORDER[cur]:
                    w["assets"][uuid] = st
                w["names"].setdefault(name, set()).add(uuid)
                w["vers"].add((name, ver))

    asc = [t for t in allterms if t.isascii()]
    if asc and len(asc) == len(allterms):
        where = " AND (" + " OR ".join(["software_string LIKE ? ESCAPE '\\'"] * len(asc)) + ")"
        wherec = " AND (" + " OR ".join(["cpe_string LIKE ? ESCAPE '\\'"] * len(asc)) + ")"
        args = tuple(_like(t) for t in asc)
        argc = tuple(_like(t).replace(" ", "_") for t in asc)
    else:
        where = wherec = ""
        args = argc = ()
    if allterms and _has("software", path):
        for au, s in db.iter("SELECT asset_uuid, software_string FROM software WHERE software_string IS NOT NULL "
                             "AND software_string<>''" + where, args, path=path, tuples=True, budget="job"):
            name, ver = sw.parse_nvr_js(s)
            if name:
                for u in sw.js_uuids(au):
                    hit(u, name, ver, s)
    if allterms and _has("cpes", path):
        for au, s in db.iter("SELECT asset_uuid, cpe_string FROM cpes WHERE cpe_string IS NOT NULL "
                             "AND cpe_string<>''" + wherec, argc, path=path, tuples=True, budget="job"):
            if au:
                for name, ver in sw.cpe_parse(s):
                    hit(str(au), name, ver or "", "")
    out = {}
    for w in work:
        c = {s: 0 for s in STATUS_ORDER}
        for st in w["assets"].values():
            c[st] += 1
        names = sorted(w["names"].items(), key=lambda x: (-len(x[1]), x[0].lower()))
        out[w["key"]] = {"assets": len(w["assets"]), "affected": c["affected"], "check": c["check"],
                         "unknown": c["unknown"], "clear": c["clear"], "versions": len(w["vers"]),
                         "products": [{"name": n, "assets": len(us)} for n, us in names[:6]],
                         "nproducts": len(names), "terms": w["terms"], "ranged": bool(w["ranges"])}
    return out
