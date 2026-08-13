"""SLA adherence engine — the shared brain behind Sköll (the SLA Adherence agent),
the Settings SLA panel, and (coming next) the trending agent.

Read-only over navi.db via core.db. Three lenses, each robust to what's populated:

  • verdict     — navi's own Pass/Fail SLA verdict (the `fixed` table after
                  `navi config sla calculate`), across all SLA-tracked findings.
  • open aging  — OPEN vulns whose age (now − first_found) is measured against the
                  per-severity day-thresholds in the `sla` table. Needs only the
                  thresholds — works before `sla calculate` has ever run.
  • remediation — findings navi has CLOSED (`fixed`, state='FIXED'): were they fixed
                  within SLA (Pass/Fail) and how long did it take.

Every lens can be segmented by any tag_key (default 'Owner', Atlas's ownership tag).

Notes grounded in real navi data:
  • pass_fail is 'Pass' / 'Fail' / NULL (NULL = info severity, which has no SLA).
  • the `delta` column is TEXT with an ambiguous unit — never trust it for math;
    we compute ages/durations from the ISO timestamps ourselves.
  • first_found / last_fixed are ISO 8601 ('YYYY-MM-DDTHH:MM:SS.sssZ'); SQLite's
    julianday() won't parse the 'T'/'Z', so we normalise to 'YYYY-MM-DD HH:MM:SS'.
"""
from core import db

SEVERITIES = ("critical", "high", "medium", "low")
OPEN_STATES = ("open", "reopened")
OWNER_KEY = "Owner"
_SEV_IN = "('critical','high','medium','low')"


# --------------------------------------------------------------------------- #
#  small building blocks
# --------------------------------------------------------------------------- #
def _table_exists(name, path=None):
    try:
        return bool(db.scalar("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
                              (name,), path=path, budget=0))
    except Exception:
        return False


def _age_days(col):
    """Days between now and an ISO timestamp column (T/Z-normalised)."""
    return ("(julianday('now') - julianday(substr(replace(replace(%s,'T',' '),'Z',''),1,19)))"
            % col)


def _dur_days(a, b):
    """Days between two ISO timestamp columns b − a (e.g. first_found → last_fixed)."""
    n = "substr(replace(replace(%s,'T',' '),'Z',''),1,19)"
    return "(julianday(%s) - julianday(%s))" % (n % b, n % a)


def _thr_case(sevcol, th):
    """CASE mapping a severity column to its SLA day-threshold from `th`."""
    whens = " ".join("WHEN '%s' THEN %d" % (s, int(th[s]))
                     for s in SEVERITIES if th.get(s) is not None)
    return "(CASE lower(%s) %s ELSE NULL END)" % (sevcol, whens)


def _has_col(table, col, path=None):
    try:
        return any(r.get("name") == col for r in db.query('PRAGMA table_info("%s")' % table, path=path))
    except Exception:
        return False


# disposition words an operator applies to a route/path (stored as an Owner tag
# valued '<route|path name>: <disposition>'). Findings on a dispositioned route or
# path are formally handled risk — they must NOT count against the SLA clock.
DISPOSITIONS = ("Ignored", "Accepted", "Mitigated")


def _disp_exclude(prefix="", path=None, negate=True):
    """SQL fragment removing (or, with negate=False, KEEPING) findings that sit on a
    route or path the operator has Ignored / Accepted / Mitigated. Empty string when
    neither linkage table is present, or the finding table has no plugin_id to join on.

    A path disposition matches ``vuln_paths.path`` (→ its plugin_id on that asset); a
    route disposition matches ``vuln_route.app_name`` (→ every plugin in its
    plugin_list). Both are scoped to the SAME asset the Owner tag sits on."""
    au, pid = prefix + "asset_uuid", prefix + "plugin_id"
    disp_vals = lambda expr: "(" + ", ".join("%s||': %s'" % (expr, d) for d in DISPOSITIONS) + ")"
    frags = []
    if _table_exists("vuln_paths", path):
        frags.append(
            "EXISTS (SELECT 1 FROM tags td JOIN vuln_paths vp "
            "ON vp.asset_uuid=td.asset_uuid AND vp.plugin_id=%s "
            "AND td.tag_value IN %s "
            "WHERE td.tag_key='%s' AND td.asset_uuid=%s)" % (pid, disp_vals("vp.path"), OWNER_KEY, au))
    if _table_exists("vuln_route", path):
        frags.append(
            "EXISTS (SELECT 1 FROM tags td JOIN vuln_route vr "
            "ON vr.plugin_list LIKE '%%''' || %s || '''%%' "
            "AND td.tag_value IN %s "
            "WHERE td.tag_key='%s' AND td.asset_uuid=%s)" % (pid, disp_vals("vr.app_name"), OWNER_KEY, au))
    if not frags:
        return ""
    inner = " OR ".join(frags)
    return (" AND NOT (" + inner + ")") if negate else (" AND (" + inner + ")")


def _scope(tag_key, tag_value, col="asset_uuid"):
    """WHERE-fragment (+ params) that scopes a base population to the assets carrying
    tag_key:tag_value. Empty when no specific value is chosen (the dashboard stays
    global). This is what makes the Filter control move EVERY number, not just the
    per-owner breakdown — verdict / open-aging / remediation all restrict to the same
    asset set."""
    if tag_key and tag_value:
        return (" AND %s IN (SELECT asset_uuid FROM tags WHERE tag_key=? AND tag_value=?)" % col,
                (tag_key, tag_value))
    return ("", ())


# --------------------------------------------------------------------------- #
#  configuration / readiness
# --------------------------------------------------------------------------- #
def thresholds(path=None):
    """Per-severity SLA day-thresholds from the `sla` table, or None if unset."""
    if not _table_exists("sla", path):
        return None
    try:
        rows = db.query("SELECT critical, high, medium, low FROM sla", path=path)
    except Exception:
        return None
    if not rows:
        return None
    r = rows[0]

    def _i(v):
        try:
            return int(float(v))
        except (TypeError, ValueError):
            return None
    out = {s: _i(r.get(s)) for s in SEVERITIES}
    return out if any(v is not None for v in out.values()) else None


def fixed_status(path=None):
    """Is `fixed` present, populated, and stamped with `sla calculate` verdicts?"""
    exists = _table_exists("fixed", path)
    rows = verdicts = closed = 0
    if exists:
        try:
            rows = int(db.scalar("SELECT count(*) FROM fixed", path=path, budget=0) or 0)
        except Exception:
            rows = 0
        try:
            verdicts = int(db.scalar(
                "SELECT count(*) FROM fixed WHERE pass_fail IS NOT NULL AND TRIM(pass_fail)<>''",
                path=path, budget=0) or 0)
        except Exception:
            verdicts = 0
        try:
            closed = int(db.scalar("SELECT count(*) FROM fixed WHERE lower(state)='fixed'",
                                   path=path, budget=0) or 0)
        except Exception:
            closed = 0
    return {"exists": exists, "rows": rows, "verdicts": verdicts, "closed": closed,
            "ready": bool(exists and verdicts > 0)}


def tag_keys(path=None):
    """Tag keys available to segment by, most-covered first (for the UI selector)."""
    try:
        rows = db.query(
            "SELECT tag_key AS k, COUNT(DISTINCT asset_uuid) AS assets "
            "FROM tags WHERE tag_key IS NOT NULL AND TRIM(tag_key)<>'' "
            "GROUP BY tag_key ORDER BY assets DESC", path=path)
    except Exception:
        rows = []
    return [{"key": r["k"], "assets": r["assets"]} for r in rows]


def tag_values(path=None, tag_key=None, top=200):
    """Distinct values for one tag_key (most-covered first) — the options for the
    Filter control that scopes the whole dashboard to a single owner/team/etc."""
    if not tag_key:
        return []
    try:
        rows = db.query(
            "SELECT tag_value AS v, COUNT(DISTINCT asset_uuid) AS assets "
            "FROM tags WHERE tag_key=? AND tag_value IS NOT NULL AND TRIM(tag_value)<>'' "
            "GROUP BY tag_value ORDER BY assets DESC, tag_value LIMIT ?",
            (tag_key, int(top)), path=path)
    except Exception:
        rows = []
    return [{"value": r["v"], "assets": r["assets"]} for r in rows]


def readiness(path=None):
    """Everything the agent/page needs to decide what it can render."""
    th = thresholds(path)
    fx = fixed_status(path)
    keys = tag_keys(path)
    return {
        "sla_set": th is not None,
        "thresholds": th,
        "fixed": fx,
        "can_open_aging": th is not None,
        "can_remediation": th is not None and fx["ready"],
        "tag_keys": keys,
        "owner_key_present": any(t["key"] == OWNER_KEY for t in keys),
        "default_tag_key": OWNER_KEY if any(t["key"] == OWNER_KEY for t in keys)
                           else (keys[0]["key"] if keys else None),
    }


# --------------------------------------------------------------------------- #
#  lens 1 — the navi Pass/Fail verdict (overall + by severity)
# --------------------------------------------------------------------------- #
def verdict(path=None, tag_key=None, tag_value=None):
    fx = fixed_status(path)
    if not fx["ready"]:
        return {"available": False, "reason": "run `navi config sla calculate` first"}
    sc, scp = _scope(tag_key, tag_value)
    disp = _disp_exclude("fixed.", path) if _has_col("fixed", "plugin_id", path) else ""
    base = ("FROM fixed WHERE pass_fail IS NOT NULL AND TRIM(pass_fail)<>'' "
            "AND lower(severity) IN " + _SEV_IN + sc + disp)
    by_sev = db.query(
        "SELECT lower(severity) AS sev, "
        " SUM(CASE WHEN lower(pass_fail) LIKE 'pass%' THEN 1 ELSE 0 END) AS met, "
        " SUM(CASE WHEN lower(pass_fail) LIKE 'fail%' THEN 1 ELSE 0 END) AS missed, "
        " COUNT(*) AS total " + base + " GROUP BY lower(severity)", scp, path=path)
    met = sum(int(r["met"] or 0) for r in by_sev)
    missed = sum(int(r["missed"] or 0) for r in by_sev)
    total = met + missed
    return {"available": True, "met": met, "missed": missed, "total": total,
            "adherence_pct": round(100.0 * met / total, 1) if total else None,
            "by_severity": [dict(r) for r in by_sev]}


# --------------------------------------------------------------------------- #
#  lens 2 — open-vuln aging vs the SLA clock (present risk)
# --------------------------------------------------------------------------- #
def open_aging(path=None, tag_key=OWNER_KEY, top=12, tag_value=None):
    th = thresholds(path)
    if th is None:
        return {"available": False, "reason": "SLA thresholds not set"}
    age = _age_days("first_found")
    thr = _thr_case("severity", th)
    sc, scp = _scope(tag_key, tag_value)
    disp = _disp_exclude("vulns.", path)      # drop accepted/mitigated/ignored routes & paths
    by_sev = db.query(
        f"SELECT lower(severity) AS sev, COUNT(*) AS open_ct,"
        f" SUM(CASE WHEN {age} > {thr} THEN 1 ELSE 0 END) AS breached,"
        f" SUM(CASE WHEN {age} <= {thr} AND {age} > 0.8*{thr} THEN 1 ELSE 0 END) AS approaching,"
        f" ROUND(AVG({age}),1) AS avg_age_days,"
        f" ROUND(MAX({age}),1) AS oldest_days"
        f" FROM vulns WHERE lower(state) IN ('open','reopened') AND lower(severity) IN {_SEV_IN}{sc}{disp}"
        f" GROUP BY lower(severity)", scp, path=path)
    open_ct = sum(int(r["open_ct"] or 0) for r in by_sev)
    breached = sum(int(r["breached"] or 0) for r in by_sev)
    approaching = sum(int(r["approaching"] or 0) for r in by_sev)

    # how many open findings were removed because their route/path is dispositioned
    excluded = 0
    if disp:
        try:
            excluded = int(db.scalar(
                f"SELECT COUNT(*) FROM vulns WHERE lower(state) IN ('open','reopened') "
                f"AND lower(severity) IN {_SEV_IN}{sc}{_disp_exclude('vulns.', path, negate=False)}",
                scp, path=path) or 0)
        except Exception:
            excluded = 0

    age_v = _age_days("v.first_found")
    thr_v = _thr_case("v.severity", th)
    sc_v, scp_v = _scope(tag_key, tag_value, col="v.asset_uuid")
    disp_v = _disp_exclude("v.", path)
    by_owner = db.query(
        f"SELECT t.tag_value AS seg, COUNT(*) AS open_ct,"
        f" SUM(CASE WHEN {age_v} > {thr_v} THEN 1 ELSE 0 END) AS breached"
        f" FROM vulns v JOIN tags t ON t.asset_uuid = v.asset_uuid AND t.tag_key = ?"
        f" WHERE lower(v.state) IN ('open','reopened') AND lower(v.severity) IN {_SEV_IN}{sc_v}{disp_v}"
        f" GROUP BY t.tag_value ORDER BY breached DESC, open_ct DESC LIMIT {int(top)}",
        (tag_key, *scp_v), path=path)
    for r in by_owner:
        oc = int(r["open_ct"] or 0)
        r["breach_pct"] = round(100.0 * int(r["breached"] or 0) / oc, 1) if oc else 0.0

    within = open_ct - breached
    return {"available": True, "tag_key": tag_key, "tag_value": tag_value,
            "open": open_ct, "breached": breached, "approaching": approaching,
            "within": within, "excluded": excluded,
            "within_pct": round(100.0 * within / open_ct, 1) if open_ct else None,
            "by_severity": [dict(r) for r in by_sev],
            "by_owner": [dict(r) for r in by_owner]}


# --------------------------------------------------------------------------- #
#  lens 3 — remediation performance on CLOSED findings (history)
# --------------------------------------------------------------------------- #
def remediation(path=None, tag_key=OWNER_KEY, top=12, tag_value=None):
    fx = fixed_status(path)
    if not fx["ready"]:
        return {"available": False, "reason": "build `fixed` + run `navi config sla calculate`"}
    dur = _dur_days("first_found", "last_fixed")
    sc, scp = _scope(tag_key, tag_value)
    has_pid = _has_col("fixed", "plugin_id", path)
    disp = _disp_exclude("fixed.", path) if has_pid else ""
    base = ("FROM fixed WHERE lower(state)='fixed' AND pass_fail IS NOT NULL "
            "AND TRIM(pass_fail)<>'' AND lower(severity) IN " + _SEV_IN + sc + disp)
    by_sev = db.query(
        f"SELECT lower(severity) AS sev,"
        f" SUM(CASE WHEN lower(pass_fail) LIKE 'pass%' THEN 1 ELSE 0 END) AS met,"
        f" SUM(CASE WHEN lower(pass_fail) LIKE 'fail%' THEN 1 ELSE 0 END) AS missed,"
        f" COUNT(*) AS total,"
        f" ROUND(AVG(CASE WHEN last_fixed IS NOT NULL AND TRIM(last_fixed)<>'' THEN {dur} END),1) AS avg_fix_days"
        f" {base} GROUP BY lower(severity)", scp, path=path)
    met = sum(int(r["met"] or 0) for r in by_sev)
    missed = sum(int(r["missed"] or 0) for r in by_sev)
    total = met + missed

    sc_f, scp_f = _scope(tag_key, tag_value, col="f.asset_uuid")
    disp_f = _disp_exclude("f.", path) if has_pid else ""
    by_owner = db.query(
        f"SELECT t.tag_value AS seg,"
        f" SUM(CASE WHEN lower(f.pass_fail) LIKE 'pass%' THEN 1 ELSE 0 END) AS met,"
        f" SUM(CASE WHEN lower(f.pass_fail) LIKE 'fail%' THEN 1 ELSE 0 END) AS missed,"
        f" COUNT(*) AS total"
        f" FROM fixed f JOIN tags t ON t.asset_uuid = f.asset_uuid AND t.tag_key = ?"
        f" WHERE lower(f.state)='fixed' AND f.pass_fail IS NOT NULL AND TRIM(f.pass_fail)<>''"
        f" AND lower(f.severity) IN {_SEV_IN}{sc_f}{disp_f}"
        f" GROUP BY t.tag_value ORDER BY missed DESC, total DESC LIMIT {int(top)}",
        (tag_key, *scp_f), path=path)
    for r in by_owner:
        tt = int(r["total"] or 0)
        r["met_pct"] = round(100.0 * int(r["met"] or 0) / tt, 1) if tt else 0.0

    return {"available": True, "tag_key": tag_key, "tag_value": tag_value,
            "met": met, "missed": missed, "total": total,
            "met_pct": round(100.0 * met / total, 1) if total else None,
            "by_severity": [dict(r) for r in by_sev],
            "by_owner": [dict(r) for r in by_owner]}


# --------------------------------------------------------------------------- #
#  the whole dashboard + a compact snapshot for the trending store
# --------------------------------------------------------------------------- #
def dashboard(path=None, tag_key=None, tag_value=None):
    rdy = readiness(path)
    tag_key = tag_key or rdy["default_tag_key"] or OWNER_KEY
    values = tag_values(path, tag_key)
    # only honor a value that actually exists for this key (guards a stale selection
    # left over from a previous segment)
    tv = (tag_value or "").strip() or None
    if tv is not None and tv not in {v["value"] for v in values}:
        tv = None
    return {
        "readiness": rdy,
        "tag_key": tag_key,
        "tag_value": tv,
        "tag_values": values,
        "scoped": tv is not None,
        "verdict": verdict(path, tag_key, tv),
        "open_aging": open_aging(path, tag_key, tag_value=tv) if rdy["can_open_aging"] else {"available": False},
        "remediation": remediation(path, tag_key, tag_value=tv) if rdy["can_remediation"] else {"available": False},
    }


def snapshot_metrics(dash):
    """Flatten a dashboard() result into the small, stable metric dict the trending
    agent will chart over time. Only scalar headline numbers — no per-owner detail."""
    oa = dash.get("open_aging") or {}
    vd = dash.get("verdict") or {}
    rem = dash.get("remediation") or {}
    m = {
        "open_total": oa.get("open"),
        "open_breached": oa.get("breached"),
        "open_approaching": oa.get("approaching"),
        "open_within_pct": oa.get("within_pct"),
        "verdict_adherence_pct": vd.get("adherence_pct"),
        "remediation_met_pct": rem.get("met_pct"),
        "remediation_total": rem.get("total"),
    }
    for r in (oa.get("by_severity") or []):
        m["open_breached_%s" % r.get("sev")] = r.get("breached")
        m["open_%s" % r.get("sev")] = r.get("open_ct")
    return {k: v for k, v in m.items() if v is not None}
