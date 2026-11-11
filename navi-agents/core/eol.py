"""End-of-Life / Unsupported software detection.

Finds assets whose findings include plugins whose NAME contains lifecycle
language ("Unsupported", "End of Life", "SEoL", …) and tags THOSE ASSETS via navi's
tag-by-plugin-name selector (`navi enrich tag --name "<text>"`). Because the
match is on the live plugin name, the tag set expands automatically as new
end-of-life/unsupported plugins appear — no rules to maintain per product.

analyze() adds the product view: plugin names normalised to products (OS vs
application), the end-of-life date Tenable prints in the plugin output (SEoL
plugins: "Security End of Life : July 11, 2017"; older detections: "End of support
date : 2014/04/08", …), years past end of life, crown jewels, and the overlap with
CISA KEV / critical findings on the same assets. Read-only over navi.db.
"""
import datetime
import functools
import re

from core import db, hx_summary

# label -> substrings searched in plugin_name (navi --name matches each, substring)
DEFAULT_GROUPS = [
    ("Unsupported", ["Unsupported"]),
    ("End of Life", ["End of Life", "SEoL", "End-of-Life", "End of Support"]),
]


def _clause(pats, col="plugin_name"):
    return " OR ".join(col + " LIKE '%" + p.replace("'", "''") + "%'" for p in pats)


def _fast(db_path=None):
    """Phase 1: the hx_plugin / hx_asset summaries exist and match this navi.db."""
    return hx_summary.usable(db_path)


def _scan_fast(db_path, groups):
    """scan() over hx_plugin: the same name rule on hx_plugin.lname (LIKE is case-blind, so the
    patterns match exactly as on vulns.plugin_name), open_assets = assets with an OPEN finding of
    the plugin; the group's asset count is one covering hx_v_plugin range per plugin."""
    out = []
    for label, pats in groups:
        cond = "(" + _clause(pats, "lname") + ")"
        plugins = db.query(
            "SELECT plugin_id, name AS plugin_name, open_assets AS assets FROM hx_plugin "
            "WHERE " + cond + " AND open_assets > 0 ORDER BY assets DESC, plugin_id", path=db_path)
        n = db.scalar("SELECT COUNT(asset_uuid) FROM (" + hx_summary.assets_with(cond, open_only=True, path=db_path)
                      + ")", path=db_path) or 0
        out.append({"label": label, "patterns": pats, "category": "Lifecycle",
                    "plugins": plugins, "asset_count": n})
    return {"groups": out}


def scan(db_path=None, groups=None):
    groups = groups or DEFAULT_GROUPS
    if _fast(db_path):
        return _scan_fast(db_path, groups)
    out = []
    open_only = (" AND lower(COALESCE(state,'open')) IN ('open','reopened')"
                 if "state" in _cols("vulns", db_path) else "")
    for label, pats in groups:
        where = "(" + _clause(pats) + ")" + open_only
        plugins = db.query(
            "SELECT plugin_id, plugin_name, COUNT(DISTINCT asset_uuid) AS assets "
            "FROM vulns WHERE " + where + " GROUP BY plugin_id, plugin_name "
            "ORDER BY assets DESC", path=db_path)
        n = db.scalar("SELECT COUNT(DISTINCT asset_uuid) FROM vulns WHERE " + where, path=db_path) or 0
        out.append({"label": label, "patterns": pats, "category": "Lifecycle",
                    "plugins": plugins, "asset_count": n})
    return {"groups": out}


# ---------------------------------------------------------------- product view
_OS_WORDS = re.compile(r"\b(operating system|windows( server)?|esxi|ubuntu|debian|centos|red hat enterprise linux|rhel|"
                       r"suse|sles|oracle linux|amazon linux|fedora|freebsd|openbsd|solaris|aix|hp-ux|macos|mac os x|"
                       r"os x|ios|junos|fortios|pan-os|nx-os|ios xe|alma ?linux|rocky linux)\b", re.I)
_NOISE = re.compile(r"\s*(\(|-|:)?\s*\b(unsupported( version)?( detection)?|security end of life|end[- ]of[- ](life|support)|"
                    r"seol|eol|detection|version|installed)\b\)?", re.I)
_LABELS = (r"security end of life|end of security support|end of (?:life|support)(?: date)?|eol(?: date)?|"
           r"support (?:ended|end date|ends)(?: on)?|extended support (?:end(?:ed)?|end date)|end of extended support|"
           r"end of service(?: life)?|retirement date|end of maintenance")
_DATE_LINE = re.compile(r"(?:" + _LABELS + r")\s*(?:\(est\.?\))?\s*[:=]?\s*(?:on\s+)?([^\n\r;]{4,40})", re.I)
_FMTS = ("%Y-%m-%d", "%Y/%m/%d", "%B %d, %Y", "%b %d, %Y", "%d %B %Y", "%d %b %Y", "%B %Y", "%b %Y",
         "%m/%d/%Y", "%Y-%m", "%Y/%m", "%Y")


def parse_eol_date(text):
    """First end-of-life / end-of-support date stated in a plugin output, as 'YYYY-MM-DD'."""
    return parse_eol_match(text)[0]


def parse_eol_match(text):
    """(date 'YYYY-MM-DD', the exact output text that stated it) — or (None, None). The text
    is what date_tag_query() searches for, so navi re-selects the same rows by SQL."""
    for m in _DATE_LINE.finditer(text or ""):
        d = _raw_date(m.group(1))
        if d:
            return d, m.group(0)
    return None, None


@functools.lru_cache(maxsize=65536)
def _raw_date(raw):
    """The date one matched label line states (memoised: the same few phrasings repeat across
    hundreds of thousands of findings, and strptime dominated analyze() at scale)."""
    raw = re.sub(r"\s+", " ", raw).strip().rstrip(".").strip()
    raw = re.sub(r"(\d)(st|nd|rd|th)\b", r"\1", raw)
    for cand in (raw, raw.split(" (")[0], " ".join(raw.split()[:3]), " ".join(raw.split()[:2]), raw.split()[0] if raw else ""):
        for f in _FMTS:
            try:
                d = datetime.datetime.strptime(cand.strip().rstrip(","), f).date()
                if 1990 <= d.year <= 2100:
                    return d.isoformat()
            except ValueError:
                continue
    return None


def date_tag_query(group, db_path=None):
    """navi --query that DEFINES an EOL-date group's assets (analyze()['date_groups'][i]): an
    OPEN finding of one of the group's EOL plugins whose output states that date in the exact
    words analyze() parsed it from. Size grows with the date's plugins/phrasings, never with
    assets — navi re-selects the full set."""
    pids = sorted({str(x) for x in group.get("plugin_ids") or []})
    texts = sorted({t for t in group.get("match_texts") or [] if t})
    if not pids or not texts:
        return ""
    lit = lambda s: "'" + str(s).replace("'", "''") + "'"
    like = lambda t: ("output LIKE " + lit("%" + t.replace("\\", "\\\\").replace("%", "\\%")
                                           .replace("_", "\\_") + "%") + " ESCAPE '\\'")
    w = ["plugin_id IN (" + ",".join(lit(p) for p in pids) + ")"]
    if "state" in _cols("vulns", db_path):
        w.append("lower(COALESCE(state,'open')) IN ('open','reopened')")
    w.append("(" + " OR ".join(like(t) for t in texts) + ")")
    return "SELECT DISTINCT asset_uuid FROM vulns WHERE " + " AND ".join(w)


def product_name(plugin_name):
    """'Apache Tomcat SEoL (8.0.x)' → 'Apache Tomcat 8.0.x'; 'VMware ESXi Unsupported Version Detection' → 'VMware ESXi'."""
    n = plugin_name or ""
    ver = re.search(r"\(([^)]*\d[^)]*)\)", n)
    base = re.sub(r"\([^)]*\)", "", n)
    base = _NOISE.sub(" ", base)
    base = re.sub(r"\s{2,}", " ", base).strip(" -:")
    if ver and ver.group(1) not in base:
        base = f"{base} {ver.group(1).strip()}"
    return base or n


_APP_WORDS = re.compile(r"\b(adobe|reader|acrobat|\.net|framework|firefox|chrome|edge|office|java|jre|jdk|flash|"
                        r"silverlight|sql server|exchange|sharepoint|iis|internet explorer|visual|runtime|"
                        r"server \d{4} (?:sp|cu)|python|php|node|tomcat|apache|nginx|openssl|wordpress)\b", re.I)


def kind_of(plugin_name, family=""):
    """OS vs application from the plugin NAME only — families like 'Windows' or
    'MacOS X Local Security Checks' hold application plugins too. Bare 'Windows'/'macOS'/'iOS'
    count only at the start of the name and only when no application word follows."""
    n = (plugin_name or "").strip()
    if _APP_WORDS.search(n):
        return "Application"
    if re.match(r"(?i)(unsupported\s+)?(microsoft\s+|apple\s+|cisco\s+)?(windows|mac\s?os|os x|ios\b)", n) or \
            re.search(r"(?i)\b(windows|ios|mac\s?os)\s+(os|server|xe|xr|nx)\b", n):
        return "Operating system"
    core_os = re.sub(r"(?i)\b(windows( server)?|macos|mac os x|os x|ios)\b", "", n)
    return "Operating system" if (_OS_WORDS.search(core_os) or re.search(r"(?i)\boperating system\b", n)) else "Application"


def _cols(table, path=None):
    try:
        return {r["name"] for r in db.query(f'PRAGMA table_info("{table}");', path=path)}
    except Exception:
        return set()


CROWN_ACR = 7


def analyze(db_path=None, groups=None):
    groups = groups or DEFAULT_GROUPS
    pats = sorted({p for _, ps in groups for p in ps})
    where = _clause(pats)
    vc = _cols("vulns", db_path)
    has_state, has_first = "state" in vc, "first_found" in vc
    sel = ["asset_uuid", "plugin_id", "plugin_name", "output"] + (["plugin_family"] if "plugin_family" in vc else []) \
        + (["state"] if has_state else []) + (["first_found"] if has_first else [])
    w = f"({where})" + (" AND lower(COALESCE(state,'open')) IN ('open','reopened')" if has_state else "")
    fast = _fast(db_path)
    try:
        if fast:
            # Phase 1: resolve the name rule against hx_plugin (one row per plugin) and fetch only
            # those plugins' open findings by plugin_id (hx_v_plugin) — no full vulns scan. The
            # rows are put back in rowid order so every tie below breaks exactly as before.
            pw = hx_summary.plugins_where("(" + _clause(pats, "lname") + ")")
            rows = db.query(f"SELECT rowid AS _rid, {', '.join(sel)} FROM vulns WHERE {pw}"
                            " AND lower(COALESCE(state,'open')) IN ('open','reopened')", path=db_path)
            rows.sort(key=lambda r: r.pop("_rid"))
        else:
            rows = db.query(f"SELECT {', '.join(sel)} FROM vulns WHERE {w}", path=db_path)
    except Exception:
        rows = []
    today = datetime.date.today()

    plugins = {}
    for r in rows:
        pid = str(r.get("plugin_id"))
        p = plugins.setdefault(pid, {"plugin_id": pid, "plugin_name": r.get("plugin_name") or "", "family": r.get("plugin_family") or "",
                                     "assets": set(), "findings": 0, "dates": {}, "adates": {}, "first": None,
                                     "dtexts": {}})
        p["assets"].add(r.get("asset_uuid")); p["findings"] += 1
        d, dtext = parse_eol_match(r.get("output"))
        if d:
            p["dates"][d] = p["dates"].get(d, 0) + 1
            p["adates"].setdefault(r.get("asset_uuid"), set()).add(d)
            p["dtexts"].setdefault(d, set()).add(dtext)
        if has_first and r.get("first_found"):
            try:
                ff = datetime.date.fromisoformat(str(r["first_found"])[:10])
                p["first"] = ff if p["first"] is None or ff < p["first"] else p["first"]
            except ValueError:
                pass

    eol_assets = set().union(*[p["assets"] for p in plugins.values()]) if plugins else set()

    # asset context: ACR / host, and what else those assets carry (KEV xref, critical findings)
    acr, host, kev_a, crit_a = {}, {}, set(), {}
    if eol_assets:
        try:
            for a in db.query("SELECT uuid, hostname, ip_address, acr FROM assets", path=db_path):
                if a.get("uuid") in eol_assets:
                    try:
                        acr[a["uuid"]] = float(a.get("acr") or 0)
                    except (TypeError, ValueError):
                        acr[a["uuid"]] = 0.0
                    host[a["uuid"]] = (a.get("hostname") or "").strip() or a.get("ip_address") or a["uuid"]
        except Exception:
            pass
        try:
            sw = " AND lower(COALESCE(state,'open')) IN ('open','reopened')" if has_state else ""
            if fast:
                # hx_asset: kev = an OPEN finding of a KEV plugin, crit = OPEN critical findings
                # (per finding, exact). Only EOL assets are read back from it below.
                kq = "SELECT asset_uuid, kev, crit FROM hx_asset WHERE kev > 0 OR crit > 0"
            else:
                kq = None
            for r in (db.query(kq, path=db_path) if kq else db.query("SELECT asset_uuid, "
                              "MAX(CASE WHEN xrefs LIKE '%CISA-KNOWN-EXPLOITED%' THEN 1 ELSE 0 END) kev, "
                              "SUM(CASE WHEN lower(COALESCE(severity,''))='critical' THEN 1 ELSE 0 END) crit "
                              # NOT INDEXED (build 455): the EOL set is a large share of all assets, and
                              # with hx_v_asset the planner would fetch every finding of every EOL asset
                              # by random row reads (xrefs isn't in the index) — 41 s → 130 s at 16M rows.
                              # One sequential scan is cheaper. Phase 1's hx_asset summary replaces this.
                              f"FROM vulns NOT INDEXED WHERE asset_uuid IN (SELECT asset_uuid FROM vulns WHERE {where}){sw} "
                              "GROUP BY asset_uuid", path=db_path)):
                if kq and r.get("asset_uuid") not in eol_assets:
                    continue
                if r.get("kev"):
                    kev_a.add(r["asset_uuid"])
                if r.get("crit"):
                    crit_a[r["asset_uuid"]] = int(r["crit"])
        except Exception:
            pass
    crown = {u for u in eol_assets if acr.get(u, 0) > CROWN_ACR}

    # ---- products
    prods = {}
    for p in plugins.values():
        name = product_name(p["plugin_name"])
        x = prods.setdefault(name, {"product": name, "kind": kind_of(p["plugin_name"], p["family"]), "plugins": [],
                                    "assets": set(), "findings": 0, "dates": {}, "adates": {}, "first": None,
                                    "dtexts": {}})
        x["plugins"].append({"plugin_id": p["plugin_id"], "plugin_name": p["plugin_name"], "assets": len(p["assets"])})
        x["assets"] |= p["assets"]; x["findings"] += p["findings"]
        for d, n in p["dates"].items():
            x["dates"][d] = x["dates"].get(d, 0) + n
        for u, ds in p["adates"].items():
            x["adates"].setdefault(u, set()).update(ds)
        for d, ts in p["dtexts"].items():
            x["dtexts"].setdefault(d, set()).update(ts)
        if p["first"] and (x["first"] is None or p["first"] < x["first"]):
            x["first"] = p["first"]
    products = []
    for x in prods.values():
        eol = max(x["dates"], key=x["dates"].get) if x["dates"] else None
        days = (today - datetime.date.fromisoformat(eol)).days if eol else None
        products.append({"product": x["product"], "kind": x["kind"], "eol_date": eol,
                         "days_past": days, "years_past": round(days / 365.25, 1) if days is not None else None,
                         "plugins": sorted(x["plugins"], key=lambda q: -q["assets"]),
                         "plugin_ids": sorted({q["plugin_id"] for q in x["plugins"]}),
                         "assets": len(x["assets"]), "findings": x["findings"],
                         "crown_assets": len(x["assets"] & crown), "kev_assets": len(x["assets"] & kev_a),
                         "crit_assets": sum(1 for u in x["assets"] if u in crit_a),
                         "first_seen": x["first"].isoformat() if x["first"] else None,
                         "_assets": x["assets"], "_adates": x["adates"], "_dtexts": x["dtexts"],
                         "_one_date": len(x["dates"]) == 1})
    products.sort(key=lambda q: (-q["assets"], q["product"]))

    # ---- EOL-date groups (tag by date) and the year timeline
    # Each ASSET goes under the date its own plugin output states. An asset whose output has no
    # date stays undated: generic plugins (e.g. 33850 "Unix OS unsupported") cover many OS versions,
    # so borrowing another host's date would tag the wrong end-of-life date.
    dgroups = {}
    for q in products:
        for u in q["_assets"]:
            ds = q["_adates"].get(u) or set()
            for d in ds:
                g = dgroups.setdefault(d, {"eol_date": d, "days_past": (today - datetime.date.fromisoformat(d)).days,
                                           "products": set(), "plugin_ids": set(), "assets": set(), "crown": set(),
                                           "texts": set()})
                g["products"].add(q["product"]); g["plugin_ids"].update(q["plugin_ids"])
                g["texts"].update(q["_dtexts"].get(d) or ())
                g["assets"].add(u)
                if u in crown:
                    g["crown"].add(u)
    date_groups = sorted(({"eol_date": g["eol_date"], "days_past": g["days_past"], "products": sorted(g["products"]),
                           "plugin_ids": sorted(g["plugin_ids"]), "assets": len(g["assets"]),
                           "uuids": sorted(u for u in g["assets"] if u),
                           "match_texts": sorted(g["texts"]),
                           "crown_assets": len(g["crown"])} for g in dgroups.values()), key=lambda g: g["eol_date"])
    years = {}
    for q in products:
        if q["eol_date"]:
            y = years.setdefault(q["eol_date"][:4], {"year": q["eol_date"][:4], "os": set(), "app": set()})
            (y["os"] if q["kind"] == "Operating system" else y["app"]).update(q["_assets"])
    timeline = [{"year": y["year"], "os": len(y["os"]), "app": len(y["app"])} for y in sorted(years.values(), key=lambda y: y["year"])]

    # ---- crown jewels on EOL software
    by_asset = {}
    for q in products:
        for u in q["_assets"]:
            by_asset.setdefault(u, []).append(q)
    crown_rows = sorted(({"asset_uuid": u, "host": host.get(u, u), "acr": acr.get(u),
                          "products": [q["product"] for q in by_asset.get(u, [])][:8],
                          "os": any(q["kind"] == "Operating system" for q in by_asset.get(u, [])),
                          "kev": u in kev_a, "critical": crit_a.get(u, 0)} for u in crown),
                        key=lambda r: (-(r["acr"] or 0), -r["critical"]))

    os_assets = set().union(*[q["_assets"] for q in products if q["kind"] == "Operating system"]) if products else set()
    dated = [q for q in products if q["eol_date"]]
    past = sorted(q["days_past"] for q in dated if q["days_past"] is not None and q["days_past"] >= 0)
    for q in products:
        q.pop("_assets", None); q.pop("_adates", None); q.pop("_one_date", None); q.pop("_dtexts", None)
    metrics = {
        "eol_assets": len(eol_assets), "products": len(products), "plugins": len(plugins),
        "findings": sum(p["findings"] for p in plugins.values()),
        "os_assets": len(os_assets), "os_products": sum(1 for q in products if q["kind"] == "Operating system"),
        "app_assets": len(eol_assets - os_assets),
        "crown_assets": len(crown), "kev_assets": len(eol_assets & kev_a), "crit_assets": sum(1 for u in eol_assets if u in crit_a),
        "dated_products": len(dated), "max_years_past": round(past[-1] / 365.25, 1) if past else None,
        "median_years_past": round(past[len(past) // 2] / 365.25, 1) if past else None,
        "products_5y": sum(1 for d in past if d >= 5 * 365.25), "has_state": has_state,
    }
    return {"ok": True, "metrics": metrics, "products": products, "date_groups": date_groups,
            "timeline": timeline, "crown": crown_rows, "today": today.isoformat()}
