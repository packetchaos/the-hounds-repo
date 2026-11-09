"""CISA KEV engine — the catalog, due-date view and metrics behind Laelaps (cisakev).

Tenable marks KEV findings with an xref {'type':'CISA-KNOWN-EXPLOITED','id':'YYYY/MM/DD'}
whose id is only the catalog *dateAdded*. The remediation deadline (CISA's `dueDate`,
set under its binding operational directives), the ransomware flag, vendor/product
and the vulnerability name live only in CISA's KEV catalog. This module fetches that
catalog (human-approved, like Mitre's download — or auto-approved via Settings, see
core.downloads) and joins it to navi.db by CVE.

Catalog source priority: user upload → cisa.gov feed → CISA's official GitHub mirror
(cisagov/kev-data) → the bundled snapshot (agents/cisakev/kev_catalog.json).

Everything here is READ-ONLY over navi.db. Tagging stays in agents/cisakev (gated,
through core.navi_cli — tag-by-CVE: the CVE is the selector, the tag lands on the
assets that have it).
"""
import datetime
import json
import os
import re
import threading
import time
import urllib.request

from core import db, downloads

FEED_URLS = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json",
)
SOURCE_ID = "cisakev"
downloads.register(SOURCE_ID, "CISA KEV catalog", list(FEED_URLS), agent="cisakev",
                   purpose="CISA Known Exploited Vulnerabilities JSON feed — due dates, ransomware "
                           "use and vendor names for Laelaps (CISA KEV Tagging).",
                   fallback="CISA GitHub mirror, then bundled snapshot agents/cisakev/kev_catalog.json")
CATALOG_PAGE = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
BUNDLED = os.path.normpath(os.path.join(os.path.dirname(__file__), "..",
                                        "agents", "cisakev", "kev_catalog.json"))
XREF = "CISA-KNOWN-EXPLOITED"
_CVE = re.compile(r"CVE-\d{4}-\d{3,}", re.I)
_KEEP = ("cveID", "vendorProject", "product", "vulnerabilityName", "dateAdded", "dueDate",
         "knownRansomwareCampaignUse", "forensicTriage", "cwes")
OPEN_STATES = ("open", "reopened")
CROWN_ACR = 7          # ACR > 7 = crown jewel (same line the Mitre / Insights tiles use)

_CACHE = {"t": 0.0, "v": None}
_TTL = float(os.environ.get("NAVI_KEV_CACHE_S", "21600"))      # 6 h — CISA updates ~daily
_LOCK = threading.Lock()


# ---------------------------------------------------------------- catalog
def _slim(doc: dict) -> dict:
    vs = [{k: v.get(k) for k in _KEEP if k in v} for v in (doc.get("vulnerabilities") or [])]
    return {"catalogVersion": doc.get("catalogVersion"), "dateReleased": doc.get("dateReleased"),
            "count": len(vs), "vulnerabilities": vs}


def fetch_catalog(json_text: str = "", force: bool = False, timeout: int = 30,
                  allow_live: bool = True):
    """Return (catalog, source). Cached in-process for NAVI_KEV_CACHE_S.
    allow_live=False (download not approved — see core.downloads) never touches the
    network: it reuses a catalog already fetched this session, else the bundled snapshot."""
    if json_text and json_text.strip():
        return _slim(json.loads(json_text)), "upload"
    now = time.time()
    with _LOCK:
        if (not force or not allow_live) and _CACHE["v"] and now - _CACHE["t"] < _TTL:
            return _CACHE["v"]
    for i, url in enumerate(FEED_URLS if allow_live else ()):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "navi-agents-kev"})
            doc = json.loads(urllib.request.urlopen(req, timeout=timeout).read().decode("utf-8", "replace"))
            out = (_slim(doc), "live" if i == 0 else "mirror")
            with _LOCK:
                _CACHE["t"], _CACHE["v"] = now, out
            return out
        except Exception:
            continue
    try:
        with open(BUNDLED, encoding="utf-8") as f:
            out = (json.load(f), "bundled")
        if allow_live:
            with _LOCK:   # offline: don't retry both URLs (30 s timeouts) on every call — retry in 5 min
                _CACHE["t"], _CACHE["v"] = now - _TTL + 300, out
        return out
    except Exception:
        return {"vulnerabilities": [], "count": 0}, "unavailable"


# ---------------------------------------------------------------- helpers
def _cols(table, path=None):
    try:
        return {r["name"] for r in db.query(f'PRAGMA table_info("{table}");', path=path)}
    except Exception:
        return set()


def _date(s):
    try:
        return datetime.date.fromisoformat(str(s)[:10])
    except Exception:
        return None


def _day(s):
    """navi timestamps are ISO 8601 ('2025-03-04T10:11:12.000Z') → date."""
    return _date((s or "").replace("/", "-"))


def due_bucket(days_left):
    if days_left is None:
        return "no due date"
    if days_left < 0:
        return "overdue"
    if days_left <= 7:
        return "due ≤ 7 days"
    if days_left <= 30:
        return "due ≤ 30 days"
    return "later"


# ---------------------------------------------------------------- analysis
def analyze(db_path=None, json_text: str = "", force: bool = False, keep_uuids: bool = False,
            allow_live: bool = True) -> dict:
    cat, source = fetch_catalog(json_text, force=force, allow_live=allow_live)
    K = {v["cveID"].upper(): v for v in cat.get("vulnerabilities", []) if v.get("cveID")}
    today = datetime.date.today()

    vc = _cols("vulns", db_path)
    has_state, has_first = "state" in vc, "first_found" in vc
    sel = ["asset_uuid", "cves", "xrefs"] + (["state"] if has_state else []) + (["first_found"] if has_first else [])
    where = "TRIM(COALESCE(cves,''))<>''"
    if has_state:
        where += " AND lower(COALESCE(state,'open')) IN ('open','reopened')"

    per = {}            # cve → {assets:set, findings:int, xref:int, first:date}
    xref_only = set()   # assets with a KEV xref whose CVE isn't in the catalog (rare)
    try:
        rows = db.query(f"SELECT {', '.join(sel)} FROM vulns WHERE ({where}) OR xrefs LIKE '%{XREF}%'", path=db_path)
    except Exception:
        rows = []
    for r in rows:
        if has_state and (r.get("state") or "open").lower() not in OPEN_STATES:
            continue
        has_x = XREF in (r.get("xrefs") or "")
        hit = False
        for c in {c.upper() for c in _CVE.findall(r.get("cves") or "")}:
            if c not in K:
                continue
            hit = True
            p = per.setdefault(c, {"assets": set(), "findings": 0, "xref": 0, "first": None})
            p["assets"].add(r.get("asset_uuid")); p["findings"] += 1; p["xref"] += 1 if has_x else 0
            if has_first:
                d = _day(r.get("first_found"))
                if d and (p["first"] is None or d < p["first"]):
                    p["first"] = d
        if has_x and not hit:
            xref_only.add(r.get("asset_uuid"))

    # asset context (ACR, hostname) for the assets involved
    all_assets = set().union(*[p["assets"] for p in per.values()]) if per else set()
    acr, host = {}, {}
    if all_assets:
        try:
            for a in db.query("SELECT uuid, hostname, ip_address, acr FROM assets", path=db_path):
                if a.get("uuid") in all_assets:
                    try:
                        acr[a["uuid"]] = float(a.get("acr") or 0)
                    except (TypeError, ValueError):
                        acr[a["uuid"]] = 0.0
                    host[a["uuid"]] = (a.get("hostname") or "").strip() or a.get("ip_address") or a["uuid"]
        except Exception:
            pass
    crown = {u for u in all_assets if acr.get(u, 0) > CROWN_ACR}

    # ---- per-CVE rows
    cves = []
    for c, p in per.items():
        k = K[c]
        due, added = _date(k.get("dueDate")), _date(k.get("dateAdded"))
        left = (due - today).days if due else None
        cves.append({
            "cve": c, "vendor": k.get("vendorProject", ""), "product": k.get("product", ""),
            "name": k.get("vulnerabilityName", ""), "date_added": k.get("dateAdded"), "due_date": k.get("dueDate"),
            "days_left": left, "bucket": due_bucket(left),
            "ransomware": (k.get("knownRansomwareCampaignUse") or "").lower() == "known",
            "assets": len(p["assets"]), "findings": p["findings"], "crown_assets": len(p["assets"] & crown),
            "xref_findings": p["xref"], "first_seen": p["first"].isoformat() if p["first"] else None,
            "exposed_days": (today - p["first"]).days if p["first"] else None,
            "found_after_added": bool(p["first"] and added and p["first"] > added),
            **({"uuids": sorted(u for u in p["assets"] if u)} if keep_uuids else {}),
        })
    cves.sort(key=lambda x: (x["days_left"] if x["days_left"] is not None else 10**6, -x["assets"]))

    def assets_of(pred):
        s = set()
        for c in cves:
            if pred(c):
                s |= per[c["cve"]]["assets"]
        return s

    over = assets_of(lambda c: c["bucket"] == "overdue")
    due7 = assets_of(lambda c: c["bucket"] == "due ≤ 7 days")
    due30 = assets_of(lambda c: c["bucket"] in ("due ≤ 7 days", "due ≤ 30 days"))
    ransom = assets_of(lambda c: c["ransomware"])
    recent = assets_of(lambda c: _date(c["date_added"]) and (today - _date(c["date_added"])).days <= 30)
    no_xref = [c for c in cves if c["xref_findings"] == 0]
    overdue_days = sorted(-c["days_left"] for c in cves if c["bucket"] == "overdue")

    # ---- due-date groups (what the "tag by due date" table lists)
    groups = {}
    for c in cves:
        g = groups.setdefault(c["due_date"] or "", {"due_date": c["due_date"], "days_left": c["days_left"],
                                                    "bucket": c["bucket"], "cves": [], "assets": set(),
                                                    "findings": 0, "ransomware": 0, "crown": set()})
        g["cves"].append(c["cve"]); g["findings"] += c["findings"]; g["ransomware"] += 1 if c["ransomware"] else 0
        g["assets"] |= per[c["cve"]]["assets"]; g["crown"] |= per[c["cve"]]["assets"] & crown
    due_groups = sorted(({**{k: v for k, v in g.items() if k not in ("assets", "crown")},
                          "assets": len(g["assets"]), "crown_assets": len(g["crown"]),
                          "value": g["due_date"] or ""} for g in groups.values() if g["due_date"]),
                        key=lambda g: g["due_date"])

    # ---- timeline: assets by due month, past vs upcoming
    months = {}
    for c in cves:
        d = _date(c["due_date"])
        if not d:
            continue
        m = months.setdefault(d.strftime("%Y-%m"), {"month": d.strftime("%Y-%m"), "overdue": set(), "upcoming": set()})
        (m["overdue"] if c["bucket"] == "overdue" else m["upcoming"]).update(per[c["cve"]]["assets"])
    timeline = [{"month": m["month"], "overdue": len(m["overdue"]), "upcoming": len(m["upcoming"])}
                for m in sorted(months.values(), key=lambda m: m["month"])]

    # ---- vendors / products
    vend = {}
    for c in cves:
        v = vend.setdefault((c["vendor"], c["product"]), {"vendor": c["vendor"], "product": c["product"],
                                                         "cves": 0, "assets": set(), "overdue": 0, "ransomware": 0})
        v["cves"] += 1; v["assets"] |= per[c["cve"]]["assets"]
        v["overdue"] += 1 if c["bucket"] == "overdue" else 0; v["ransomware"] += 1 if c["ransomware"] else 0
    vendors = sorted(({**{k: x for k, x in v.items() if k != "assets"}, "assets": len(v["assets"])} for v in vend.values()),
                     key=lambda v: (-v["assets"], -v["cves"]))

    # ---- crown jewels (ACR > 7) carrying KEV
    crown_rows = []
    for u in crown:
        mine = [c for c in cves if u in per[c["cve"]]["assets"]]
        crown_rows.append({"asset_uuid": u, "host": host.get(u, u), "acr": acr.get(u),
                           "kev": len(mine), "overdue": sum(1 for c in mine if c["bucket"] == "overdue"),
                           "ransomware": sum(1 for c in mine if c["ransomware"]),
                           "cves": [c["cve"] for c in mine][:12]})
    crown_rows.sort(key=lambda r: (-(r["acr"] or 0), -r["overdue"], -r["kev"]))

    # ---- remediated KEV (navi's `fixed` table, when present)
    remediated = None
    fc = _cols("fixed", db_path)
    if {"cves", "last_fixed"} <= fc:
        n = on_time = 0
        try:
            for r in db.query("SELECT cves, last_fixed FROM fixed WHERE TRIM(COALESCE(cves,''))<>''", path=db_path):
                fixed_on = _day(r.get("last_fixed"))
                dues = [_date(K[c].get("dueDate")) for c in {c.upper() for c in _CVE.findall(r.get("cves") or "")} if c in K]
                if dues:
                    n += 1
                    due = min((d for d in dues if d), default=None)   # earliest deadline = the binding one
                    if fixed_on and due and fixed_on <= due:
                        on_time += 1
            remediated = {"findings": n, "on_time": on_time, "pct_on_time": round(100 * on_time / n, 1) if n else None}
        except Exception:
            remediated = None

    metrics = {
        "catalog_total": len(K), "catalog_version": cat.get("catalogVersion"), "catalog_released": cat.get("dateReleased"),
        "kev_cves": len(cves), "kev_assets": len(all_assets), "kev_findings": sum(c["findings"] for c in cves),
        "overdue_cves": sum(1 for c in cves if c["bucket"] == "overdue"), "overdue_assets": len(over),
        "due7_assets": len(due7), "due30_assets": len(due30),
        "due30_cves": sum(1 for c in cves if c["bucket"] in ("due ≤ 7 days", "due ≤ 30 days")),
        "ransomware_cves": sum(1 for c in cves if c["ransomware"]), "ransomware_assets": len(ransom),
        "crown_assets": len(crown), "crown_overdue_assets": len(over & crown),
        "recent_assets": len(recent), "recent_cves": sum(1 for c in cves if _date(c["date_added"]) and (today - _date(c["date_added"])).days <= 30),
        "max_days_overdue": overdue_days[-1] if overdue_days else 0,
        "median_days_overdue": overdue_days[len(overdue_days) // 2] if overdue_days else 0,
        "no_xref_cves": len(no_xref), "no_xref_assets": len(assets_of(lambda c: c["xref_findings"] == 0)),
        "xref_only_assets": len(xref_only), "has_state": has_state, "has_first_found": has_first,
        "found_after_added": sum(1 for c in cves if c["found_after_added"]),
        "remediated": remediated,
    }
    return {"ok": True, "source": source, "catalog_page": CATALOG_PAGE, "feed_url": FEED_URLS[0],
            "metrics": metrics, "cves": cves, "due_groups": due_groups, "timeline": timeline,
            "vendors": vendors[:200], "crown": crown_rows, "today": today.isoformat()}
