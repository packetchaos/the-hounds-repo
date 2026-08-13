"""Fixed Explorer — Plott. Read-only navi.db search over the `fixed` table
(remediation history + Pass/Fail SLA verdicts from `navi config sla calculate`).

Filters: free text (plugin name / id / asset), severity, state, SLA outcome. Paginated
500/page, sorted worst-first (Fail, then by severity). Headline KPIs are computed over
the WHOLE filtered set, not just the visible page. `delta` is navi's TEXT column with an
ambiguous unit, so days-to-fix is computed from first_found → last_fixed here.
"""
from core import db

_PAGE = 500
_SEV = ("critical", "high", "medium", "low", "info")


def _dur_days(a, b):
    n = "substr(replace(replace(%s,'T',' '),'Z',''),1,19)"
    return "(julianday(%s) - julianday(%s))" % (n % b, n % a)


def _exists():
    try:
        return bool(db.scalar("SELECT 1 FROM sqlite_master WHERE type='table' AND name='fixed'",
                              budget=0))
    except Exception:
        return False


def _where(p):
    cl, args = [], []
    q = (p.get("q") or "").strip()
    if q:
        cl.append("(plugin_name LIKE ? OR asset_uuid LIKE ? OR plugin_id LIKE ?)")
        args += ["%" + q + "%"] * 3
    sev = (p.get("severity") or "").strip().lower()
    if sev in _SEV:
        cl.append("lower(severity)=?"); args.append(sev)
    state = (p.get("state") or "").strip().lower()
    if state:
        cl.append("lower(state)=?"); args.append(state)
    pf = (p.get("pass_fail") or "").strip().lower()
    if pf in ("pass", "fail"):
        cl.append("lower(pass_fail) LIKE ?"); args.append(pf + "%")
    elif pf == "none":
        cl.append("(pass_fail IS NULL OR TRIM(pass_fail)='')")
    return (" WHERE " + " AND ".join(cl)) if cl else "", args


def search(p):
    if not _exists():
        return {"ok": True, "result": {"missing": True, "rows": [], "kpi": {}}}, 200
    where, args = _where(p)
    args = tuple(args)
    off = max(0, int(p.get("offset") or 0))
    dur = _dur_days("first_found", "last_fixed")

    kpi = db.query(
        "SELECT COUNT(*) AS total,"
        " SUM(CASE WHEN lower(pass_fail) LIKE 'pass%' THEN 1 ELSE 0 END) AS met,"
        " SUM(CASE WHEN lower(pass_fail) LIKE 'fail%' THEN 1 ELSE 0 END) AS missed,"
        " SUM(CASE WHEN lower(state)='fixed' THEN 1 ELSE 0 END) AS closed,"
        " ROUND(AVG(CASE WHEN lower(state)='fixed' AND last_fixed IS NOT NULL"
        "   AND TRIM(last_fixed)<>'' THEN " + dur + " END),1) AS avg_fix_days"
        " FROM fixed" + where, args)
    k = dict(kpi[0]) if kpi else {}
    met, missed = int(k.get("met") or 0), int(k.get("missed") or 0)
    k["met_pct"] = round(100.0 * met / (met + missed), 1) if (met + missed) else None

    rows = db.query(
        "SELECT asset_uuid, plugin_id, plugin_name, severity, state, pass_fail,"
        " first_found, last_fixed, port,"
        " CASE WHEN last_fixed IS NOT NULL AND TRIM(last_fixed)<>'' THEN ROUND(" + dur + ",1) END AS fix_days"
        " FROM fixed" + where +
        " ORDER BY (pass_fail IS NULL),"
        "  CASE lower(pass_fail) WHEN 'fail' THEN 0 WHEN 'pass' THEN 1 ELSE 2 END,"
        "  CASE lower(severity) WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2"
        "   WHEN 'low' THEN 3 ELSE 4 END"
        " LIMIT ? OFFSET ?", args + (_PAGE + 1, off))
    has_next = len(rows) > _PAGE
    return {"ok": True, "result": {"rows": rows[:_PAGE], "kpi": k, "offset": off,
            "page": off // _PAGE + 1, "has_next": has_next, "count": min(len(rows), _PAGE)}}, 200


ACTIONS = {"search": search}
