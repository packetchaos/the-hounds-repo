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
from core import db, tagname

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


# what "now" is in SQL. Tests pin it to a julianday literal so the SQL reference lenses and
# the fast engine age findings against the same instant.
_NOW_SQL = "julianday('now')"


def _age_days(col):
    """Days between now and an ISO timestamp column (T/Z-normalised)."""
    return ("(%s - julianday(substr(replace(replace(%s,'T',' '),'Z',''),1,19)))"
            % (_NOW_SQL, col))


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
            "WHERE %s AND td.asset_uuid=%s)" % (pid, disp_vals("vp.path"), tagname.sql_lit("td.tag_key", OWNER_KEY), au))
    if _table_exists("vuln_route", path):
        frags.append(
            "EXISTS (SELECT 1 FROM tags td JOIN vuln_route vr "
            "ON vr.plugin_list LIKE '%%''' || %s || '''%%' "
            "AND td.tag_value IN %s "
            "WHERE %s AND td.asset_uuid=%s)" % (pid, disp_vals("vr.app_name"), tagname.sql_lit("td.tag_key", OWNER_KEY), au))
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


def _valid_value(path, tag_key, tag_value, values):
    """The chosen filter value if it EXISTS for this key — checked directly, not by
    membership in the top-N `values` list (an owner ranked by breaches, e.g. a click on the
    worst-owner row, can fall outside the top 200 by asset count; the server then silently
    showed the whole estate). A valid value outside the list is added to it so the selector
    can show it."""
    tv = (tag_value or "").strip() or None
    if tv is None or not tag_key:
        return None
    if tv in {v["value"] for v in values}:
        return tv
    try:
        n = db.scalar("SELECT COUNT(DISTINCT asset_uuid) FROM tags WHERE tag_key=? AND tag_value=?",
                      (tag_key, tv), path=path)
    except Exception:
        n = 0
    if not n:
        return None
    values.append({"value": tv, "assets": int(n)})
    return tv


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
        "owner_key_present": any(t["key"] in tagname.names(OWNER_KEY) for t in keys),
        # Owner, else its test-run name (Hounds-Owner), else the most-covered key
        "default_tag_key": next((k for k in tagname.names(OWNER_KEY) if any(t["key"] == k for t in keys)),
                                keys[0]["key"] if keys else None),
    }


# --------------------------------------------------------------------------- #
#  The three lenses as SQL — the ORIGINAL implementation, kept as the reference the
#  fast engine below is tested against (tests/test_sla.py diffs them field by field).
#  Don't call these from the app: on a large navi.db the disposition EXISTS sub-queries
#  scan `tags` once per finding (minutes). verdict()/open_aging()/remediation() further
#  down return the same numbers from one linear pass.
#
#  lens 1 — the navi Pass/Fail verdict (overall + by severity)
# --------------------------------------------------------------------------- #
def verdict_sql(path=None, tag_key=None, tag_value=None):
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
def open_aging_sql(path=None, tag_key=OWNER_KEY, top=12, tag_value=None):
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
def remediation_sql(path=None, tag_key=OWNER_KEY, top=12, tag_value=None):
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


# =========================================================================== #
#  Fast engine — every lens, the SLA-owner metrics and the monthly trend from ONE
#  linear pass over `vulns` and `fixed` (plus one pass each over tags / assets /
#  vuln_paths / vuln_route). Same numbers as the SQL lenses above (asserted by
#  tests/test_sla.py on several fixtures), without the per-finding EXISTS scans.
#
#  Definitions (shown in the UI too):
#    age          now − first_found, in days (SQLite julianday, T/Z-normalised).
#    breached     an OPEN/REOPENED finding with age > its severity's SLA days.
#    approaching  open, not breached, age > 80% of the SLA window (legacy KPI).
#    due in N d   open, not breached, SLA days − age ≤ N.
#    days to fix  fix date − first_found. Fix date = fixed.last_fixed when navi's
#                 `fixed` table holds closed findings, else vulns.last_found on
#                 state='fixed' rows (the last time the finding was seen — a proxy).
#    fixed in SLA days to fix ≤ SLA days (our own math, not navi's Pass/Fail).
#  Findings on Ignored / Accepted / Mitigated routes & paths are excluded everywhere.
# =========================================================================== #
import datetime as _dt
import math as _math
import re as _re

from core import qprofile as _qp

_NORM = "julianday(substr(replace(replace(%s,'T',' '),'Z',''),1,19))"
_QUOTED = _re.compile(r"'([^']*)'")
DUE_WINDOWS = (7, 14, 30)
CROWN_ACR = 7.0
TREND_MONTHS = 24
OVERDUE_BUCKETS = ((30, "1–30 d over"), (90, "31–90 d over"), (180, "91–180 d over"),
                   (None, "> 180 d over"))
ENGINE_VERSION = 2


def _kbn_avg(xs):
    """AVG exactly as SQLite ≥3.43 computes it (Kahan-Babuska-Neumaier sum ÷ count)."""
    if not xs:
        return None
    s = err = 0.0
    for r in xs:
        t = s + r
        if abs(s) > abs(r):
            err += (s - t) + r
        else:
            err += (r - t) + s
        s = t
    if not _math.isinf(err) and not _math.isnan(err):
        s += err
    return s / len(xs)


def _median(xs):
    if not xs:
        return None
    ys = sorted(xs)
    n = len(ys)
    return ys[n // 2] if n % 2 else (ys[n // 2 - 1] + ys[n // 2]) / 2.0


def _pct_of(xs, q):
    if not xs:
        return None
    ys = sorted(xs)
    return ys[min(len(ys) - 1, int(_math.ceil(q * len(ys))) - 1)]


def _tables(con):
    return {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}


def _cols(con, table):
    try:
        return {r[1] for r in con.execute('PRAGMA table_info("%s")' % table)}
    except Exception:
        return set()


def _timed(con, sql, args=()):
    """Run a full-scan query, record it in the query profiler, return the cursor rows."""
    import time as _t
    t0 = _t.monotonic()
    rows = con.execute(sql, args).fetchall()
    try:
        _qp.record(sql, (_t.monotonic() - t0) * 1000.0)
    except Exception:
        pass
    return rows


def dispositions(con, tables=None):
    """{asset_uuid: {plugin_id,…}} for findings on a route/path the operator marked
    Ignored / Accepted / Mitigated (Owner tag '<route|path>: <disposition>' on that asset).
    The same rule as _disp_exclude(), evaluated once instead of per finding."""
    tables = tables if tables is not None else _tables(con)
    if "tags" not in tables or not ({"vuln_paths", "vuln_route"} & tables):
        return {}
    sufs = [": " + d for d in DISPOSITIONS]
    names_by_asset = {}
    okf, okp = tagname.sql_in("tag_key", OWNER_KEY)      # Owner + its test-run name
    for au, tv in con.execute(
            "SELECT asset_uuid, tag_value FROM tags WHERE " + okf + " AND (" +
            " OR ".join("tag_value LIKE ?" for _ in sufs) + ")",
            (*okp, *("%" + s for s in sufs))):
        if au is None or tv is None:
            continue
        for s in sufs:
            if tv.endswith(s):
                names_by_asset.setdefault(au, set()).add(tv[:-len(s)])
    if not names_by_asset:
        return {}
    ex = {}
    if "vuln_paths" in tables:
        for au, pid, pth in con.execute("SELECT asset_uuid, plugin_id, path FROM vuln_paths"):
            ns = names_by_asset.get(au)
            if ns and pid is not None and pth in ns:
                ex.setdefault(au, set()).add(str(pid))
    if "vuln_route" in tables:
        wanted = set().union(*names_by_asset.values())
        route_pids = {}
        for name, pl in con.execute("SELECT app_name, plugin_list FROM vuln_route"):
            if name in wanted and pl:
                route_pids.setdefault(name, set()).update(_QUOTED.findall(str(pl)))
        if route_pids:
            for au, ns in names_by_asset.items():
                for n in ns:
                    pids = route_pids.get(n)
                    if pids:
                        ex.setdefault(au, set()).update(pids)
    return ex


class _Month:
    """julianday → 'YYYY-MM' (memoised per day)."""
    def __init__(self):
        self.c = {}

    def __call__(self, jd):
        d = int(_math.floor(jd - 1721425.5)) + 1
        m = self.c.get(d)
        if m is None:
            try:
                m = _dt.date.fromordinal(d).strftime("%Y-%m")
            except (ValueError, OverflowError):
                m = "0000-00"
            self.c[d] = m
        return m


def _jd_iso(jd):
    try:
        return (_dt.datetime(1970, 1, 1) + _dt.timedelta(days=jd - 2440587.5)).strftime("%Y-%m-%d")
    except Exception:
        return None


def _top_pids(wp, n):
    """Plugin ids in the overall top-n plus each severity's top-n (wp is sorted worst-first)."""
    keep, per = set(), {}
    for i, (pid, p) in enumerate(wp):
        c = per.get(p[3], 0)
        if i < n or c < n:
            keep.add(pid)
        per[p[3]] = c + 1
    return keep


def compute(path=None, tag_key=None, tag_value=None, top=12, now_jd=None, rdy=None):
    """The whole SLA dashboard (legacy keys: readiness / verdict / open_aging / remediation,
    plus `metrics` and `trend`) in one pass. `now_jd` pins 'now' (tests)."""
    rdy = rdy or readiness(path)
    tag_key = tag_key or rdy["default_tag_key"] or OWNER_KEY
    values = tag_values(path, tag_key)
    tv = _valid_value(path, tag_key, tag_value, values)
    out = {"readiness": rdy, "tag_key": tag_key, "tag_value": tv, "tag_values": values,
           "scoped": tv is not None}
    th = rdy["thresholds"] or {}
    fx = rdy["fixed"]
    can_open, can_rem = rdy["can_open_aging"], rdy["can_remediation"]

    con = db.connect(path)
    con.row_factory = None
    try:
        if now_jd is None:
            now_jd = con.execute("SELECT julianday('now')").fetchone()[0]
        r1 = lambda x: (None if x is None else con.execute("SELECT round(?,1)", (x,)).fetchone()[0])
        tables = _tables(con)
        vcols = _cols(con, "vulns") if "vulns" in tables else set()
        fcols = _cols(con, "fixed") if "fixed" in tables else set()
        acols = _cols(con, "assets") if "assets" in tables else set()
        month = _Month()

        # ---- tags for the chosen key: segment list per asset (dup rows kept — the SQL JOIN
        #      counts each), and the scope set when a value is chosen
        seg_of, scope = {}, None
        if "tags" in tables:
            for au, val in _timed(con, "SELECT asset_uuid, tag_value FROM tags WHERE tag_key=?", (tag_key,)):
                if au is None:          # SQL joins / IN() never match NULL — keep parity
                    continue
                seg_of.setdefault(au, []).append(val)
            if tv is not None:
                scope = {au for au, vs in seg_of.items() if tv in vs}
        EX = dispositions(con, tables)

        # ---- assets: name + ACR for the worst-asset table and crown jewels
        ainfo, has_acr = {}, "acr" in acols
        if "assets" in tables and "uuid" in acols:
            sel = ["uuid", "hostname" if "hostname" in acols else "NULL",
                   "ip_address" if "ip_address" in acols else "NULL", "acr" if has_acr else "NULL"]
            for u, hn, ip, acr in _timed(con, "SELECT %s FROM assets" % ", ".join(sel)):
                try:
                    a = float(acr) if acr not in (None, "") else None
                except (TypeError, ValueError):
                    a = None
                ainfo[u] = (hn, ip, a)
        has_acr = has_acr and any(v[2] is not None for v in ainfo.values())

        # ---- fixed-date source for remediation speed + the trend
        fixed_src = None
        if {"first_found", "last_fixed", "state", "severity"} <= fcols and fx.get("closed"):
            fixed_src = "fixed"
        elif {"state", "first_found", "last_found", "severity"} <= vcols:
            fixed_src = "vulns"

        # ---------------- accumulators
        S = {s: {"open": 0, "breached": 0, "approaching": 0, "ages": [], "max_age": None,
                 "due": [0, 0, 0], "max_over": None,
                 "fx_durs": [], "fx_in": 0} for s in SEVERITIES}
        own_open = {}          # seg -> [open, breached, due7, crit_breached]
        excluded = 0
        over_b = [0, 0, 0, 0]
        oldest = None          # (over, au, pid, sev, age)
        A = {}                 # au -> [open, breached, max_over, crit_breached]
        P = {}                 # pid -> [breached, assets set, max_over, sev, open]
        pname = {}
        crown = {"open": 0, "breached": 0, "assets": set(), "assets_breached": set(),
                 "by_sev": {s: 0 for s in SEVERITIES}}
        T = {}                 # month -> [new, fixed, breach_open, breach_close, durs, in_sla]

        def tm(m):
            t = T.get(m)
            if t is None:
                t = T[m] = [0, 0, 0, 0, [], 0]
            return t

        def fixed_event(au, sev, jff, jfix):
            thr = th.get(sev)
            dur = jfix - jff
            if dur < 0:
                dur = 0.0
            tm(month(jff))[0] += 1
            t = tm(month(jfix))
            t[1] += 1
            t[4].append(dur)
            s = S[sev]
            s["fx_durs"].append(dur)
            if thr is not None:
                if dur <= thr:
                    t[5] += 1
                    s["fx_in"] += 1
                else:
                    tm(month(jff + thr))[2] += 1
                    t[3] += 1

        # ---------------- pass 1: vulns
        vfs_ok = can_open and {"severity", "state", "first_found", "asset_uuid"} <= vcols
        if "vulns" in tables and {"severity", "asset_uuid"} <= vcols and (vfs_ok or fixed_src == "vulns"):
            sel = ["asset_uuid", "plugin_id" if "plugin_id" in vcols else "NULL",
                   "lower(severity)", "lower(state)" if "state" in vcols else "'open'",
                   (_NORM % "first_found") if "first_found" in vcols else "NULL",
                   (_NORM % "last_found") if ("last_found" in vcols and fixed_src == "vulns") else "NULL",
                   "plugin_name" if "plugin_name" in vcols else "NULL"]
            states = ("'open','reopened','fixed'" if fixed_src == "vulns" else "'open','reopened'")
            rows = _timed(con, "SELECT %s FROM vulns WHERE lower(severity) IN %s AND lower(state) IN (%s)"
                          % (", ".join(sel), _SEV_IN, states) if "state" in vcols else
                          "SELECT %s FROM vulns WHERE lower(severity) IN %s" % (", ".join(sel), _SEV_IN))
            due_w = DUE_WINDOWS
            for au, pid, sev, st, jff, jlf, pn in rows:
                if scope is not None and au not in scope:
                    continue
                if pid is not None:
                    pid = str(pid)
                    ex = EX.get(au)
                    if ex and pid in ex:
                        if st != "fixed":
                            excluded += 1
                        continue
                if st == "fixed":
                    if jff is not None and jlf is not None:
                        fixed_event(au, sev, jff, jlf)
                    continue
                if not vfs_ok:
                    continue
                s = S[sev]
                thr = th.get(sev)
                s["open"] += 1
                age = (now_jd - jff) if jff is not None else None
                br = False
                if age is not None:
                    s["ages"].append(age)
                    if s["max_age"] is None or age > s["max_age"]:
                        s["max_age"] = age
                    tm(month(jff))[0] += 1
                    if thr is not None:
                        if age > thr:
                            br = True
                        else:
                            if age > 0.8 * thr:
                                s["approaching"] += 1
                            left = thr - age
                            if left <= due_w[2]:
                                s["due"][2] += 1
                                if left <= due_w[1]:
                                    s["due"][1] += 1
                                    if left <= due_w[0]:
                                        s["due"][0] += 1
                a = A.get(au)
                if a is None:
                    a = A[au] = [0, 0, None, 0]
                a[0] += 1
                if pid is not None:
                    p = P.get(pid)
                    if p is None:
                        p = P[pid] = [0, set(), None, sev, 0]
                        pname[pid] = pn
                    p[4] += 1
                ai = ainfo.get(au)
                crown_hit = has_acr and ai is not None and ai[2] is not None and ai[2] >= CROWN_ACR
                if crown_hit:
                    crown["open"] += 1
                    crown["assets"].add(au)
                if br:
                    over = age - thr
                    s["breached"] += 1
                    if s["max_over"] is None or over > s["max_over"]:
                        s["max_over"] = over
                    over_b[0 if over <= 30 else 1 if over <= 90 else 2 if over <= 180 else 3] += 1
                    if oldest is None or over > oldest[0]:
                        oldest = (over, au, pid, sev, age, pn)
                    tm(month(jff + thr))[2] += 1
                    a[1] += 1
                    if a[2] is None or over > a[2]:
                        a[2] = over
                    if sev == "critical":
                        a[3] += 1
                    if pid is not None:
                        p[0] += 1
                        p[1].add(au)
                        if p[2] is None or over > p[2]:
                            p[2] = over
                    if crown_hit:
                        crown["breached"] += 1
                        crown["assets_breached"].add(au)
                        crown["by_sev"][sev] += 1
                for seg in seg_of.get(au, ()):
                    o = own_open.get(seg)
                    if o is None:
                        o = own_open[seg] = [0, 0, 0, 0]
                    o[0] += 1
                    if br:
                        o[1] += 1
                        if sev == "critical":
                            o[3] += 1
                    elif age is not None and thr is not None and thr - age <= 7:
                        o[2] += 1
            del rows

        # ---------------- pass 2: fixed (verdict + remediation + fix dates)
        V = {}                 # sev -> [met, missed, total]
        R = {}                 # sev -> [met, missed, total, durs]
        own_rem = {}           # seg -> [met, missed, total, durs]
        if "fixed" in tables and (fx["ready"] or fixed_src == "fixed") and "severity" in fcols:
            f_pid = "plugin_id" in fcols
            sel = ["asset_uuid", "plugin_id" if f_pid else "NULL", "lower(severity)",
                   "lower(state)" if "state" in fcols else "NULL",
                   "pass_fail" if "pass_fail" in fcols else "NULL",
                   (_NORM % "first_found") if "first_found" in fcols else "NULL",
                   (_NORM % "last_fixed") if "last_fixed" in fcols else "NULL",
                   "last_fixed" if "last_fixed" in fcols else "NULL"]
            rows = _timed(con, "SELECT %s FROM fixed WHERE lower(severity) IN %s" % (", ".join(sel), _SEV_IN))
            for au, pid, sev, st, pf, jff, jlf, lf_raw in rows:
                if scope is not None and au not in scope:
                    continue
                if f_pid and pid is not None:
                    ex = EX.get(au)
                    if ex and str(pid) in ex:
                        continue
                if fixed_src == "fixed" and st == "fixed" and jff is not None and jlf is not None:
                    fixed_event(au, sev, jff, jlf)
                if pf is None:
                    continue
                pfs = str(pf)
                if pfs.strip(" ") == "":
                    continue
                pl = pfs.lower()
                met, missed = pl.startswith("pass"), pl.startswith("fail")
                if fx["ready"]:
                    v = V.get(sev)
                    if v is None:
                        v = V[sev] = [0, 0, 0]
                    v[0] += met
                    v[1] += missed
                    v[2] += 1
                if can_rem and st == "fixed":
                    r = R.get(sev)
                    if r is None:
                        r = R[sev] = [0, 0, 0, []]
                    r[0] += met
                    r[1] += missed
                    r[2] += 1
                    d = None
                    if lf_raw is not None and str(lf_raw).strip(" ") != "" and jff is not None and jlf is not None:
                        d = jlf - jff
                        r[3].append(d)
                    for seg in seg_of.get(au, ()):
                        o = own_rem.get(seg)
                        if o is None:
                            o = own_rem[seg] = [0, 0, 0, []]
                        o[0] += met
                        o[1] += missed
                        o[2] += 1
                        if d is not None:
                            o[3].append(d)
            del rows

        # ================= assemble the legacy lenses (identical shape to the SQL ones)
        if fx["ready"]:
            by = [{"sev": s, "met": V[s][0], "missed": V[s][1], "total": V[s][2]} for s in sorted(V)]
            met = sum(r["met"] for r in by)
            missed = sum(r["missed"] for r in by)
            tot = met + missed
            out["verdict"] = {"available": True, "met": met, "missed": missed, "total": tot,
                              "adherence_pct": round(100.0 * met / tot, 1) if tot else None,
                              "by_severity": by}
        else:
            out["verdict"] = {"available": False, "reason": "run `navi config sla calculate` first"}

        if can_open:
            by = []
            for s in sorted(SEVERITIES):
                x = S[s]
                if not x["open"]:
                    continue
                by.append({"sev": s, "open_ct": x["open"], "breached": x["breached"],
                           "approaching": x["approaching"], "avg_age_days": r1(_kbn_avg(x["ages"])),
                           "oldest_days": r1(x["max_age"])})
            oc = sum(r["open_ct"] for r in by)
            br = sum(r["breached"] for r in by)
            ap = sum(r["approaching"] for r in by)
            owners = sorted(own_open.items(), key=lambda kv: (-kv[1][1], -kv[1][0], str(kv[0])))
            bo = []
            for seg, o in owners:
                bo.append({"seg": seg, "open_ct": o[0], "breached": o[1],
                           "breach_pct": round(100.0 * o[1] / o[0], 1) if o[0] else 0.0,
                           "due_7": o[2], "crit_breached": o[3]})
            within = oc - br
            out["open_aging"] = {"available": True, "tag_key": tag_key, "tag_value": tv,
                                 "open": oc, "breached": br, "approaching": ap, "within": within,
                                 "excluded": excluded if EX else 0,
                                 "within_pct": round(100.0 * within / oc, 1) if oc else None,
                                 "by_severity": by, "by_owner": bo[:int(top)],
                                 "owners_total": len(bo)}
        else:
            out["open_aging"] = {"available": False}

        if can_rem:
            by = [{"sev": s, "met": R[s][0], "missed": R[s][1], "total": R[s][2],
                   "avg_fix_days": r1(_kbn_avg(R[s][3]))} for s in sorted(R)]
            met = sum(r["met"] for r in by)
            missed = sum(r["missed"] for r in by)
            tot = met + missed
            owners = sorted(own_rem.items(), key=lambda kv: (-kv[1][1], -kv[1][2], str(kv[0])))
            bo = [{"seg": seg, "met": o[0], "missed": o[1], "total": o[2],
                   "met_pct": round(100.0 * o[0] / o[2], 1) if o[2] else 0.0,
                   "avg_fix_days": r1(_kbn_avg(o[3]))} for seg, o in owners]
            out["remediation"] = {"available": True, "tag_key": tag_key, "tag_value": tv,
                                  "met": met, "missed": missed, "total": tot,
                                  "met_pct": round(100.0 * met / tot, 1) if tot else None,
                                  "by_severity": by, "by_owner": bo[:int(top)], "owners_total": len(bo)}
        else:
            out["remediation"] = {"available": False}

        # ================= SLA-owner metrics
        rnd1 = lambda x: None if x is None else round(x, 1)
        sev_rows, all_durs, all_in = [], [], 0
        for s in SEVERITIES:
            x = S[s]
            d = x["fx_durs"]
            all_durs += d
            all_in += x["fx_in"]
            sev_rows.append({
                "sev": s, "sla_days": th.get(s), "open": x["open"], "breached": x["breached"],
                "within_pct": round(100.0 * (x["open"] - x["breached"]) / x["open"], 1) if x["open"] else None,
                "due_7": x["due"][0], "due_14": x["due"][1], "due_30": x["due"][2],
                "max_over": rnd1(x["max_over"]),
                "fixed": len(d), "fixed_in_sla": x["fx_in"],
                "fixed_in_sla_pct": round(100.0 * x["fx_in"] / len(d), 1) if d and th.get(s) is not None else None,
                "mttr_mean": rnd1(sum(d) / len(d)) if d else None, "mttr_median": rnd1(_median(d)),
                "mttr_p90": rnd1(_pct_of(d, 0.9))})
        tot_open = sum(r["open"] for r in sev_rows)
        tot_br = sum(r["breached"] for r in sev_rows)

        def _asset_row(au, a):
            hn, ip, acr = ainfo.get(au, (None, None, None))
            return {"asset_uuid": au, "hostname": hn, "ip": ip, "acr": acr, "open": a[0],
                    "breached": a[1], "max_over": rnd1(a[2]), "crit_breached": a[3]}
        wa = sorted(((au, a) for au, a in A.items() if a[1]), key=lambda kv: (-kv[1][1], -(kv[1][2] or 0), str(kv[0])))
        wp = sorted(((pid, p) for pid, p in P.items() if p[0]), key=lambda kv: (-kv[1][0], -len(kv[1][1]), kv[0]))
        assets_breached = len(wa)
        keep_p = _top_pids(wp, 15)
        ob = None
        if oldest:
            over, au, pid, sev, age, pn = oldest
            hn, ip, _a = ainfo.get(au, (None, None, None))
            ob = {"days_over": rnd1(over), "age_days": rnd1(age), "severity": sev, "plugin_id": pid,
                  "plugin_name": pn, "asset_uuid": au, "hostname": hn, "ip": ip,
                  "first_found": _jd_iso(now_jd - age)}
        fx_n = len(all_durs)
        now_m = month(now_jd)
        out["metrics"] = {
            "available": can_open,
            "as_of": _jd_iso(now_jd),
            "by_severity": sev_rows,
            "totals": {"open": tot_open, "breached": tot_br,
                       "within_pct": round(100.0 * (tot_open - tot_br) / tot_open, 1) if tot_open else None,
                       "due_7": sum(r["due_7"] for r in sev_rows), "due_14": sum(r["due_14"] for r in sev_rows),
                       "due_30": sum(r["due_30"] for r in sev_rows),
                       "assets_open": len(A), "assets_breached": assets_breached,
                       "fixed": fx_n, "fixed_in_sla": all_in,
                       "fixed_in_sla_pct": round(100.0 * all_in / fx_n, 1) if fx_n and th else None,
                       "mttr_mean": rnd1(sum(all_durs) / fx_n) if fx_n else None,
                       "mttr_median": rnd1(_median(all_durs)), "excluded": excluded if EX else 0},
            "overdue_buckets": [{"label": lbl, "n": n} for (_, lbl), n in zip(OVERDUE_BUCKETS, over_b)],
            "oldest_breach": ob,
            "crown": {"available": has_acr, "acr_min": CROWN_ACR, "assets": len(crown["assets"]),
                      "open": crown["open"], "breached": crown["breached"],
                      "assets_breached": len(crown["assets_breached"]),
                      "by_sev": crown["by_sev"]},
            "worst_assets": [_asset_row(au, a) for au, a in wa[:15]],
            # top 15 overall + top 15 per severity, so a severity filter in the UI still has rows
            "worst_plugins": [{"plugin_id": pid, "plugin_name": pname.get(pid), "severity": p[3],
                               "breached": p[0], "assets": len(p[1]), "open": p[4],
                               "max_over": rnd1(p[2])}
                              for pid, p in wp if pid in keep_p],
            "plugins_breached": len(wp),
            "fixed_source": fixed_src,
            "has_owner_key": bool(seg_of),
        }

        # ================= monthly trend, reconstructed from finding dates
        # Without thresholds (or the columns open aging needs) open findings are never read, so
        # the backlog would be new-minus-fixed of FIXED findings only and fall toward zero —
        # report the trend unavailable rather than wrong.
        trend = {"available": False, "reason": "set SLA thresholds to see trends"} if not vfs_ok else {"available": False}
        if T and vfs_ok:
            months = sorted(m for m in T if m != "0000-00" and m <= now_m)
            if months:
                # window: the last TREND_MONTHS months up to now (gaps filled)
                y, mo = int(now_m[:4]), int(now_m[5:])
                win = []
                for _ in range(TREND_MONTHS):
                    win.append("%04d-%02d" % (y, mo))
                    mo -= 1
                    if mo == 0:
                        y, mo = y - 1, 12
                win = [m for m in reversed(win) if m >= months[0]]
                cn = cf = cbo = cbc = 0
                for m in months:
                    if m < win[0]:
                        t = T[m]
                        cn += t[0]; cf += t[1]; cbo += t[2]; cbc += t[3]
                rows_t = []
                for m in win:
                    t = T.get(m) or [0, 0, 0, 0, [], 0]
                    cn += t[0]; cf += t[1]; cbo += t[2]; cbc += t[3]
                    d = t[4]
                    rows_t.append({"month": m, "new": t[0], "fixed": t[1], "backlog": cn - cf,
                                   "breaches_opened": t[2] if th else None,
                                   "breached_backlog": (cbo - cbc) if th else None,
                                   "mttr_mean": rnd1(sum(d) / len(d)) if d else None,
                                   "mttr_median": rnd1(_median(d)),
                                   "fixed_in_sla_pct": round(100.0 * t[5] / len(d), 1) if d and th else None})
                trend = {"available": True, "rows": rows_t, "partial_last": True,
                         "fixed_source": fixed_src,
                         "basis": "reconstructed from finding dates in navi.db"}
        out["trend"] = trend
        out["engine"] = {"v": ENGINE_VERSION, "now_jd": now_jd}
    finally:
        con.close()
    return out


# --------------------------------------------------------------------------- #
#  public lenses — same signatures and shapes as before, served by the engine
# --------------------------------------------------------------------------- #
def verdict(path=None, tag_key=None, tag_value=None):
    return compute(path, tag_key, tag_value)["verdict"]


def open_aging(path=None, tag_key=OWNER_KEY, top=12, tag_value=None):
    if thresholds(path) is None:
        return {"available": False, "reason": "SLA thresholds not set"}
    return compute(path, tag_key, tag_value, top=top)["open_aging"]


def remediation(path=None, tag_key=OWNER_KEY, top=12, tag_value=None):
    if not fixed_status(path)["ready"]:
        return {"available": False, "reason": "build `fixed` + run `navi config sla calculate`"}
    return compute(path, tag_key, tag_value, top=top)["remediation"]


# --------------------------------------------------------------------------- #
#  the whole dashboard + a compact snapshot for the trending store
# --------------------------------------------------------------------------- #
def dashboard(path=None, tag_key=None, tag_value=None, now_jd=None):
    return compute(path, tag_key, tag_value, now_jd=now_jd)


def dashboard_sql(path=None, tag_key=None, tag_value=None):
    """The original SQL dashboard — reference for tests only (slow on a big navi.db)."""
    rdy = readiness(path)
    tag_key = tag_key or rdy["default_tag_key"] or OWNER_KEY
    values = tag_values(path, tag_key)
    tv = _valid_value(path, tag_key, tag_value, values)
    return {
        "readiness": rdy, "tag_key": tag_key, "tag_value": tv, "tag_values": values,
        "scoped": tv is not None,
        "verdict": verdict_sql(path, tag_key, tv),
        "open_aging": open_aging_sql(path, tag_key, tag_value=tv) if rdy["can_open_aging"] else {"available": False},
        "remediation": remediation_sql(path, tag_key, tag_value=tv) if rdy["can_remediation"] else {"available": False},
    }


def snapshot_metrics(dash):
    """Flatten a dashboard() result into the small, stable metric dict the trending
    agent will chart over time. Only scalar headline numbers — no per-owner detail."""
    oa = dash.get("open_aging") or {}
    vd = dash.get("verdict") or {}
    rem = dash.get("remediation") or {}
    mt = (dash.get("metrics") or {}).get("totals") or {}
    m = {
        "open_total": oa.get("open"),
        "open_breached": oa.get("breached"),
        "open_approaching": oa.get("approaching"),
        "open_within_pct": oa.get("within_pct"),
        "verdict_adherence_pct": vd.get("adherence_pct"),
        "remediation_met_pct": rem.get("met_pct"),
        "remediation_total": rem.get("total"),
        "due_7": mt.get("due_7"),
        "mttr_median": mt.get("mttr_median"),
    }
    for r in (oa.get("by_severity") or []):
        m["open_breached_%s" % r.get("sev")] = r.get("breached")
        m["open_%s" % r.get("sev")] = r.get("open_ct")
    return {k: v for k, v in m.items() if v is not None}
