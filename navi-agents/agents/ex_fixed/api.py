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


_WANT = ("asset_uuid", "plugin_id", "plugin_name", "severity", "state", "pass_fail",
         "first_found", "last_fixed", "port")


def _cols():
    try:
        return {r["name"] for r in db.query('PRAGMA table_info("fixed")', budget=0)}
    except Exception:
        return set()


def _c(cols, name):
    """A column of `fixed`, or NULL when this navi version's table doesn't have it."""
    return name if name in cols else "NULL"


def _where(p, cols=None):
    cols = set(_WANT) if cols is None else cols
    cl, args = [], []
    q = (p.get("q") or "").strip()
    if q:
        txt = [c for c in ("plugin_name", "asset_uuid", "plugin_id") if c in cols]
        if txt:
            cl.append("(" + " OR ".join(c + " LIKE ?" for c in txt) + ")")
            args += ["%" + q + "%"] * len(txt)
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
    cols = _cols()
    where, args = _where(p, cols)
    args = tuple(args)
    C = {n: _c(cols, n) for n in _WANT}
    off = max(0, int(p.get("offset") or 0))
    try:
        _n = max(1, min(_PAGE, int(p.get("limit") or _PAGE)))   # UI asks 10–50
    except (TypeError, ValueError):
        _n = _PAGE
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
        "SELECT " + ", ".join("%s AS %s" % (C[n], n) for n in _WANT) + ","
        " CASE WHEN last_fixed IS NOT NULL AND TRIM(last_fixed)<>'' THEN ROUND(" + dur + ",1) END AS fix_days"
        " FROM fixed" + where +
        " ORDER BY (pass_fail IS NULL),"
        "  CASE lower(pass_fail) WHEN 'fail' THEN 0 WHEN 'pass' THEN 1 ELSE 2 END,"
        "  CASE lower(severity) WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2"
        "   WHEN 'low' THEN 3 ELSE 4 END"
        " LIMIT ? OFFSET ?", args + (_n + 1, off))
    has_next = len(rows) > _n
    return {"ok": True, "result": {"rows": rows[:_n], "kpi": k, "offset": off,
            "page": off // _n + 1, "has_next": has_next, "count": min(len(rows), _n)}}, 200


ACTIONS = {"search": search}
