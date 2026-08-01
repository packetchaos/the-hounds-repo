"""WAS (Web Application Scanning) engine — the shared brain behind Xolotl (the two
WAS dashboards) and Vizsla (the Apps explorer).

Read-only over navi.db (core.db). Works the `apps` table (one row per completed WAS
scan config) and `findings` (per-finding detail). Two quirks of the real navi schema
this module hides from the pages:

  • apps.owasp is a STRINGIFIED PYTHON DICT — "{'A1': 3, 'A2': 5, … 'A10': 0}" —
    OWASP Top-10 category counts. apps.tech_list is a STRINGIFIED LIST — "['PHP', …]".
    Both are parsed here with ast.literal_eval and handed to the UI as real structures.
  • findings has NO `severity`/`config_id`; severity is `risk_factor`, and it joins to
    apps on  apps.uuid = findings.scan_uuid  (NOT config_id).

Counts (critical_count…info_count) are stored as TEXT — cast to int here.
scan_completed_time is ISO with a +00:00 offset; normalise for julianday.
"""
import ast
import re

from core import db

SEVERITIES = ("critical", "high", "medium", "low", "info")
_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "none": 4, "": 4}

# OWASP Top-10 (the A1–A10 codes navi stores in apps.owasp map to the 2017 list)
OWASP_LABELS = {
    "A1": "Injection", "A2": "Broken Authentication", "A3": "Sensitive Data Exposure",
    "A4": "XML External Entities (XXE)", "A5": "Broken Access Control",
    "A6": "Security Misconfiguration", "A7": "Cross-Site Scripting (XSS)",
    "A8": "Insecure Deserialization", "A9": "Using Components with Known Vulnerabilities",
    "A10": "Insufficient Logging & Monitoring",
}
OWASP_ORDER = ["A%d" % i for i in range(1, 11)]


def _table_exists(name, path=None):
    try:
        return bool(db.scalar("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
                              (name,), path=path, budget=0))
    except Exception:
        return False


def _int(v):
    try:
        return int(float(v))
    except (TypeError, ValueError):
        return 0


def parse_owasp(s):
    """'{'A1': 3, …}' -> {'A1': 3, …} (only non-negative ints kept). Robust to junk."""
    if not s or not str(s).strip():
        return {}
    try:
        d = ast.literal_eval(str(s))
        if isinstance(d, dict):
            return {str(k): _int(v) for k, v in d.items()}
    except (ValueError, SyntaxError):
        pass
    return {}


def parse_tech(s):
    """"['PHP','nginx']" -> ['PHP','nginx']; drops the 'Nothing Found' sentinel + blanks."""
    if not s or not str(s).strip():
        return []
    out = []
    try:
        v = ast.literal_eval(str(s))
        if isinstance(v, (list, tuple)):
            out = [str(x).strip() for x in v]
        elif isinstance(v, str):
            out = [v.strip()]
    except (ValueError, SyntaxError):
        out = [p.strip() for p in str(s).split(",")]
    return [t for t in out if t and t.lower() != "nothing found"]


def _owasp_list(counts):
    """A1..A10 in order with labels, from a {code:count} dict."""
    return [{"code": c, "label": OWASP_LABELS.get(c, c), "count": _int(counts.get(c, 0))}
            for c in OWASP_ORDER]


# normalise 'YYYY-MM-DDTHH:MM:SS.ssss+00:00' -> julianday-parseable 'YYYY-MM-DD HH:MM:SS'
_SCAN_AGE = ("(julianday('now') - julianday(substr(replace(scan_completed_time,'T',' '),1,19)))")

_APP_COLS = ("name, target, uuid, config_id, asset_uuid, scan_completed_time, "
             "pages_crawled, requests_made, critical_count, high_count, medium_count, "
             "low_count, info_count, owasp, tech_list, notes")


def status(path=None):
    exists = _table_exists("apps", path)
    apps = fnd = 0
    if exists:
        try:
            apps = int(db.scalar("SELECT count(*) FROM apps", path=path, budget=0) or 0)
        except Exception:
            apps = 0
        try:
            fnd = int(db.scalar("SELECT count(*) FROM findings", path=path, budget=0) or 0)
        except Exception:
            fnd = 0
    return {"exists": exists, "apps": apps, "findings": fnd, "ready": bool(exists and apps > 0)}


def _row_view(r):
    """Turn a raw apps row into a parsed, typed dict the UI can render directly."""
    sev = {s: _int(r.get(s + "_count")) for s in SEVERITIES}
    return {
        "uuid": r.get("uuid"), "name": r.get("name") or "(unnamed)",
        "target": r.get("target") or "", "asset_uuid": r.get("asset_uuid") or "",
        "config_id": r.get("config_id") or "",
        "scan_completed_time": r.get("scan_completed_time") or "",
        "pages_crawled": _int(r.get("pages_crawled")),
        "requests_made": _int(r.get("requests_made")),
        "notes": (r.get("notes") or "").strip(),
        **{k: sev[k] for k in SEVERITIES},
        "findings_total": sum(sev.values()),
        "tech": parse_tech(r.get("tech_list")),
        "owasp": parse_owasp(r.get("owasp")),
    }


# --------------------------------------------------------------------------- #
#  Dashboard 1 — consolidated overview across every app
# --------------------------------------------------------------------------- #
def overview(path=None, stale_days=30):
    st = status(path)
    if not st["ready"]:
        return {"available": False, "reason": "no WAS apps in navi.db — run navi config update was"}
    rows = [_row_view(r) for r in db.query("SELECT %s FROM apps" % _APP_COLS, path=path)]

    sev_tot = {s: sum(a[s] for a in rows) for s in SEVERITIES}
    owasp_tot = {c: 0 for c in OWASP_ORDER}
    tech_apps = {}
    for a in rows:
        for c, n in a["owasp"].items():
            if c in owasp_tot:
                owasp_tot[c] += n
        for t in set(a["tech"]):
            tech_apps[t] = tech_apps.get(t, 0) + 1

    # scan coverage / recency (SQL so we don't reparse timestamps in Python)
    try:
        cov = db.query(
            "SELECT COUNT(*) AS n, "
            " SUM(CASE WHEN %s <= ? THEN 1 ELSE 0 END) AS fresh, "
            " ROUND(AVG(CAST(pages_crawled AS INT)),0) AS avg_pages, "
            " ROUND(AVG(CAST(requests_made AS INT)),0) AS avg_requests, "
            " SUM(CAST(pages_crawled AS INT)) AS total_pages, "
            " SUM(CAST(requests_made AS INT)) AS total_requests, "
            " MIN(scan_completed_time) AS oldest, MAX(scan_completed_time) AS newest "
            "FROM apps" % _SCAN_AGE, (stale_days,), path=path)[0]
    except Exception:
        cov = {}
    fresh = _int(cov.get("fresh"))
    coverage = {"total_pages": _int(cov.get("total_pages")),
                "total_requests": _int(cov.get("total_requests")),
                "avg_pages": _int(cov.get("avg_pages")), "avg_requests": _int(cov.get("avg_requests")),
                "scanned_recent": fresh, "stale": len(rows) - fresh, "stale_days": stale_days,
                "oldest": cov.get("oldest") or "", "newest": cov.get("newest") or ""}

    rows.sort(key=lambda a: (a["critical"], a["high"], a["medium"], a["findings_total"]), reverse=True)
    return {
        "available": True, "apps": len(rows),
        "assets": len({a["asset_uuid"] for a in rows if a.get("asset_uuid")}),
        "total_findings": sum(sev_tot.values()),
        "severity": sev_tot,
        "apps_with_crit": sum(1 for a in rows if a["critical"] > 0),
        "apps_with_high": sum(1 for a in rows if a["high"] > 0),
        "clean_apps": sum(1 for a in rows if (a["critical"] + a["high"] + a["medium"] + a["low"]) == 0),
        "coverage": coverage,
        "owasp": _owasp_list(owasp_tot),
        "tech": sorted(({"tech": t, "apps": n} for t, n in tech_apps.items()),
                       key=lambda x: (-x["apps"], x["tech"]))[:25],
        "apps_rows": rows,
    }


def apps_list(path=None):
    """Lightweight list for the App Report selector (risk-sorted)."""
    st = status(path)
    if not st["ready"]:
        return []
    rows = [_row_view(r) for r in db.query(
        "SELECT name, target, uuid, critical_count, high_count, medium_count, low_count, info_count, "
        "config_id, asset_uuid, scan_completed_time, pages_crawled, requests_made, owasp, tech_list, notes "
        "FROM apps", path=path)]
    rows.sort(key=lambda a: (a["critical"], a["high"], a["findings_total"]), reverse=True)
    return [{"uuid": a["uuid"], "name": a["name"], "target": a["target"],
             "critical": a["critical"], "high": a["high"], "findings_total": a["findings_total"]}
            for a in rows]


# --------------------------------------------------------------------------- #
#  Dashboard 2 — per-app deep-dive (App Report)
# --------------------------------------------------------------------------- #
def app_report(path=None, app_uuid=None):
    st = status(path)
    if not st["ready"]:
        return {"available": False, "reason": "no WAS apps in navi.db"}
    app_uuid = (app_uuid or "").strip()
    where, args = ("WHERE uuid=?", (app_uuid,)) if app_uuid else ("", ())
    raw = db.query("SELECT %s FROM apps %s LIMIT 1" % (_APP_COLS, where), args, path=path)
    if not raw:                                   # fall back to the first (risk-sorted) app
        al = apps_list(path)
        if not al:
            return {"available": False, "reason": "app not found"}
        return app_report(path, al[0]["uuid"])
    app = _row_view(raw[0])
    app["owasp_list"] = _owasp_list(app["owasp"])

    findings = db.query(
        "SELECT name, family, risk_factor, owasp, plugin_id, solution, url "
        "FROM findings WHERE scan_uuid=? "
        "ORDER BY CASE lower(risk_factor) WHEN 'critical' THEN 0 WHEN 'high' THEN 1 "
        " WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, name",
        (app["uuid"],), path=path)
    frows = [dict(f) for f in findings]
    by_sev = {s: 0 for s in SEVERITIES}
    plugins = {}
    for f in frows:
        rf = (f.get("risk_factor") or "info").strip().lower()
        if rf not in by_sev:
            rf = "info"
        by_sev[rf] += 1
        # Top plugins = the ACTIONABLE ones only — informational and low-severity plugins
        # are excluded so the list surfaces what actually needs remediation.
        if rf in ("info", "low", "none"):
            continue
        pid = str(f.get("plugin_id") or "")
        p = plugins.setdefault(pid, {"plugin_id": pid, "name": f.get("name") or "",
                                     "family": f.get("family") or "", "risk_factor": rf, "count": 0})
        p["count"] += 1
    top_plugins = sorted(plugins.values(),
                         key=lambda p: (-p["count"], p["name"]))[:25]
    return {"available": True, "app": app, "findings": frows[:500],
            "findings_shown": min(len(frows), 500), "findings_count": len(frows),
            "by_severity": by_sev, "top_plugins": top_plugins}


# --------------------------------------------------------------------------- #
#  Dashboard 3 — Beagle: per-app RECON (WAS info plugins + raw plugin output)
# --------------------------------------------------------------------------- #
# The curated "recon" plugins: the informational WAS plugins that describe the web
# app itself — its sitemap, scan telemetry, target facts, screenshot, external links,
# cookies, methods. (plugin_id -> label, one-line blurb, icon). List order = UI order.
WAS_RECON = [
    ("98136", "Target Information", "domain, IP, status code, server response", "🎯"),
    ("98000", "Scan Information", "engine, plugins, requests, bandwidth, duration", "📊"),
    ("98009", "Web Application Sitemap", "every distinct URL the crawler discovered", "🗺️"),
    ("98138", "Screenshot", "captured screenshot of the landing page", "📸"),
    ("98154", "External URLs", "off-site / third-party links the app references", "🔗"),
    ("98772", "Fetch/XHR Detected", "AJAX / background endpoints observed", "⚡"),
    ("98061", "Cookies Collected", "cookies set during the scan", "🍪"),
    ("98047", "Allowed HTTP Methods", "HTTP verbs the server accepts", "🔧"),
    ("98072", "Common Directories Detection", "well-known paths that responded", "📁"),
    ("98077", "Private IP Address Disclosure", "internal IPs leaked in responses", "🕵️"),
    ("112616", "API Detected", "API surface identified on the target", "🧩"),
    ("114395", "WebSocket Detected", "real-time WebSocket endpoints", "🔌"),
    ("114503", "Virtual Hosts Detected", "additional vhosts on the same address", "🌐"),
    ("113393", "Performance Telemetry", "timing / performance metrics", "⏱️"),
]
# plugin_id -> (order, label, blurb, icon)
_RECON_INDEX = {pid: (i, label, blurb, icon)
                for i, (pid, label, blurb, icon) in enumerate(WAS_RECON)}

# HTML sniff for plugin output that carries a captured document/markup (screenshots &
# some HTTP plugins embed HTML) — the page renders those in a locked sandbox.
_HTML_RE = re.compile(r"</?(?:table|thead|tbody|tr|td|th|div|span|p|br|pre|ul|ol|li|"
                      r"b|i|em|strong|h[1-6]|a|code|hr|img|html|head|body|title)\b", re.I)


def _cols(table, path=None):
    try:
        return {r["name"] for r in db.query('PRAGMA table_info("%s");' % table, path=path)}
    except Exception:
        return set()


def _clean(v):
    """Trim + treat navi's 'None'/'N/A' sentinels as empty (findings store the string
    'None' in proof/headers when a plugin has none)."""
    if v is None:
        return ""
    s = str(v).strip()
    return "" if s.lower() in ("", "none", "n/a", "null") else s


def _resolve_app(path, app_uuid):
    """Resolve to one parsed app row. Accepts an app uuid OR an asset_uuid (so the WAS
    'asset' links resolve either way); falls back to the top-risk app when blank/unknown
    so the recon page always lands on something."""
    app_uuid = (app_uuid or "").strip()
    if app_uuid:
        raw = db.query("SELECT %s FROM apps WHERE uuid=? LIMIT 1" % _APP_COLS,
                       (app_uuid,), path=path)
        if not raw:
            raw = db.query("SELECT %s FROM apps WHERE asset_uuid=? LIMIT 1" % _APP_COLS,
                           (app_uuid,), path=path)
        if raw:
            return _row_view(raw[0])
    al = apps_list(path)
    if not al:
        return None
    raw = db.query("SELECT %s FROM apps WHERE uuid=? LIMIT 1" % _APP_COLS,
                   (al[0]["uuid"],), path=path)
    return _row_view(raw[0]) if raw else None


def app_info(path=None, app_uuid=None):
    """Beagle's per-app recon: the web app's identity plus its informational 'recon'
    plugins (sitemap, scan info, target info, screenshot, external URLs, cookies, …)
    drawn from findings. Every plugin is clickable → plugin_output() for the raw text."""
    st = status(path)
    if not st["ready"]:
        return {"available": False, "reason": "no WAS apps in navi.db"}
    app = _resolve_app(path, app_uuid)
    if not app:
        return {"available": False, "reason": "app not found"}
    app["owasp_list"] = _owasp_list(app["owasp"])

    has_out = "output" in _cols("findings", path)
    out_expr = ("MAX(CASE WHEN TRIM(COALESCE(output,''))<>'' THEN 1 ELSE 0 END) AS has_output, "
                "MAX(LENGTH(COALESCE(output,''))) AS out_len"
                if has_out else "0 AS has_output, 0 AS out_len")
    rows = db.query(
        "SELECT plugin_id, MAX(name) AS name, MAX(family) AS family, "
        " MAX(risk_factor) AS risk_factor, COUNT(*) AS n, " + out_expr +
        " FROM findings WHERE scan_uuid=? GROUP BY plugin_id",
        (app["uuid"],), path=path)

    by_pid, fam = {}, {}
    for r in rows:
        pid = str(r.get("plugin_id") or "")
        rf = (r.get("risk_factor") or "info").strip().lower()
        by_pid[pid] = {"plugin_id": pid, "name": r.get("name") or "",
                       "family": r.get("family") or "", "risk_factor": rf,
                       "count": _int(r.get("n")), "has_output": bool(_int(r.get("has_output"))),
                       "out_len": _int(r.get("out_len"))}
        f = r.get("family") or "Other"
        fam[f] = fam.get(f, 0) + _int(r.get("n"))

    # featured recon plugins, in curated order, that actually fired on this app
    recon = []
    for pid, (order, label, blurb, icon) in _RECON_INDEX.items():
        rec = by_pid.get(pid)
        if rec:
            recon.append({**rec, "label": label, "blurb": blurb, "icon": icon, "featured": True})
    recon.sort(key=lambda x: _RECON_INDEX[x["plugin_id"]][0])

    featured = set(_RECON_INDEX)
    other_info = sorted(
        [r for pid, r in by_pid.items()
         if pid not in featured and r["risk_factor"] in ("info", "none", "")],
        key=lambda x: (-x["count"], x["name"].lower()))
    security = sorted(
        [r for r in by_pid.values() if r["risk_factor"] not in ("info", "none", "")],
        key=lambda x: (_SEV_RANK.get(x["risk_factor"], 9), -x["count"]))
    families = sorted(({"family": k, "count": v} for k, v in fam.items()),
                      key=lambda x: (-x["count"], x["family"]))
    info_total = sum(1 for r in by_pid.values() if r["risk_factor"] in ("info", "none", ""))
    return {"available": True, "app": app, "recon": recon, "other_info": other_info,
            "security": security, "families": families, "info_total": info_total,
            "plugins_total": len(by_pid), "has_output": has_out}


def plugin_output(path=None, app_uuid=None, plugin_id=None):
    """The special SQL there is no navi primitive for: pull the RAW stored output for one
    plugin on one web app, straight from findings. WAS keeps the useful text in
    findings.output (sitemaps, scan info, target facts, cookie/URL lists …), plus proof
    and request/response headers on vuln findings. A plugin can fire on several URLs, so
    we return every instance. Read-only over navi.db."""
    st = status(path)
    if not st["ready"]:
        return {"ok": False, "found": False, "error": "no WAS apps in navi.db"}
    app = _resolve_app(path, app_uuid)
    if not app:
        return {"ok": False, "found": False, "error": "app not found"}
    pid = str(plugin_id or "").strip()
    if not pid:
        return {"ok": False, "found": False, "error": "plugin_id required"}
    fcols = _cols("findings", path)
    want = ["name", "family", "risk_factor", "url", "output", "proof", "request_headers",
            "response_headers", "description", "solution", "cves", "see_also", "xrefs", "owasp"]
    sel = [c for c in want if c in fcols]
    if not sel:
        return {"ok": True, "found": False, "plugin_id": pid,
                "message": "findings table has no output columns in this navi.db."}
    try:
        rows = db.query("SELECT %s FROM findings WHERE scan_uuid=? AND plugin_id=?"
                        % ", ".join(sel), (app["uuid"], pid), path=path)
    except Exception as e:
        return {"ok": False, "found": False, "error": str(e)}
    if not rows:
        return {"ok": True, "found": False, "plugin_id": pid,
                "message": "No findings recorded for this plugin on this app."}
    instances = [{"url": _clean(r.get("url")), "output": _clean(r.get("output")),
                  "proof": _clean(r.get("proof")),
                  "request_headers": _clean(r.get("request_headers")),
                  "response_headers": _clean(r.get("response_headers"))} for r in rows]
    first = rows[0]
    combined = "\n\n".join(i["output"] for i in instances if i["output"])
    return {"ok": True, "found": True, "plugin_id": pid,
            "app_uuid": app["uuid"], "app_name": app["name"],
            "name": first.get("name") or "", "family": first.get("family") or "",
            "risk_factor": (first.get("risk_factor") or "info").strip().lower(),
            "description": _clean(first.get("description")), "solution": _clean(first.get("solution")),
            "cves": _clean(first.get("cves")), "see_also": _clean(first.get("see_also")),
            "instances": instances, "count": len(instances),
            "is_html": bool(_HTML_RE.search(combined))}


# --------------------------------------------------------------------------- #
#  Bulk tagging — tag the web apps' Tenable ASSETS (by asset_uuid, same as VM
#  assets) via navi. This module only COMPUTES the cohorts (read-only); the write
#  goes through core.navi_cli.tag (gated) from the api layer.
# --------------------------------------------------------------------------- #
# One Tenable tag CATEGORY per dimension; the VALUE is the specific member.
TAG_CATEGORIES = {"owasp": "WAS OWASP", "severity": "WAS Severity", "technology": "WAS Technology"}
# Severities offered for tagging (info excluded — nearly every app has info findings,
# so an "info" cohort would tag everything and carry no signal).
_TAG_SEVERITIES = ("critical", "high", "medium", "low")


def _existing_tags(path=None):
    """Set of (tag_key, tag_value) already present in navi.db — so a cohort can show
    'tag exists' instead of a sticky client flag (reflects navi.db, like the pack)."""
    try:
        return {(t.get("tag_key"), t.get("tag_value")) for t in db.tags_present(path=path)}
    except Exception:
        return set()


def _cohort(value, apps, category, present):
    """Shape one taggable cohort: its value, matching apps, and the taggable asset
    UUIDs (apps missing an asset_uuid can't be tagged)."""
    uu = [a["asset_uuid"] for a in apps if a.get("asset_uuid")]
    return {"value": value, "category": category, "apps": len(apps),
            "taggable": len(uu), "uuids": uu,
            "no_asset": sum(1 for a in apps if not a.get("asset_uuid")),
            "applied": (category, value) in present}


def tag_plan(path=None):
    """Every taggable cohort across the three dimensions — OWASP category, severity, and
    detected technology — computed from `apps`. Each web app's Tenable asset (asset_uuid)
    is the tag target, exactly like a VM asset. Read-only; the apply is gated (api layer)."""
    st = status(path)
    if not st["ready"]:
        return {"available": False, "reason": "no WAS apps in navi.db"}
    rows = [_row_view(r) for r in db.query("SELECT %s FROM apps" % _APP_COLS, path=path)]
    present = _existing_tags(path)
    cat = TAG_CATEGORIES

    # OWASP: tag apps that carry ≥1 finding in a category (count > 0)
    owasp_apps = {}
    for a in rows:
        for code, n in a["owasp"].items():
            if n > 0 and code in OWASP_ORDER:
                owasp_apps.setdefault(code, []).append(a)
    owasp = []
    for code in OWASP_ORDER:
        apps = owasp_apps.get(code)
        if apps:
            value = "%s: %s" % (code, OWASP_LABELS.get(code, code))
            owasp.append({"key": code, "code": code, "label": OWASP_LABELS.get(code, code),
                          **_cohort(value, apps, cat["owasp"], present)})

    # Severity: tag apps that have ≥1 finding at a given severity
    severity = []
    for s in _TAG_SEVERITIES:
        apps = [a for a in rows if a.get(s, 0) > 0]
        if apps:
            value = s.capitalize()
            severity.append({"key": s, "label": value, **_cohort(value, apps, cat["severity"], present)})

    # Technology: tag apps where a technology was detected
    tech_apps = {}
    for a in rows:
        for t in set(a["tech"]):
            tech_apps.setdefault(t, []).append(a)
    technology = [{"key": t, "label": t, **_cohort(t, apps, cat["technology"], present)}
                  for t, apps in tech_apps.items()]
    technology.sort(key=lambda x: (-x["apps"], x["label"].lower()))

    return {"available": True, "apps": len(rows),
            "taggable_apps": sum(1 for a in rows if a.get("asset_uuid")),
            "untaggable_apps": sum(1 for a in rows if not a.get("asset_uuid")),
            "categories": cat, "owasp": owasp, "severity": severity, "technology": technology}


def tag_targets(path=None, dimension=None, key=None):
    """Resolve one cohort (dimension + key) → {category, value, uuids}. The api layer
    recomputes targets server-side from here rather than trusting client-supplied UUIDs."""
    dim = (dimension or "").strip().lower()
    if dim not in ("owasp", "severity", "technology"):
        return None
    plan = tag_plan(path)
    if not plan.get("available"):
        return None
    for c in plan.get(dim, []):
        if str(c.get("key")) == str(key):
            return {"category": c["category"], "value": c["value"], "uuids": c["uuids"],
                    "apps": c["apps"], "taggable": c["taggable"]}
    return None
