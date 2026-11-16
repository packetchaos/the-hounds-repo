"""Compliance Explorer — Saluki. Read-only navi.db search over the `compliance` table (one row
per audit check result per asset, from `navi config update compliance`).

  search  — free text over check name / check id / audit file / asset (uuid, hostname, IP),
            plus filters: status, audit file, framework, exact check, exact asset. Paged on
            the server (failed → warning → unknown → passed, then by check). Headline KPIs are
            counted over the WHOLE filtered set, not just the visible page.
  facets  — the dropdown values: audit files and frameworks (from DISTINCT `reference`
            strings — one parse per distinct check, not per row) with result counts.
  export  — the filtered rows as CSV text, capped at EXPORT_MAX rows (the response says so).

navi stores `reference` as a stringified Python list ("[{'framework': '800-53', 'control':
'CM-7'}, …]"); the framework filter matches that text exactly, so it needs no parse per row.
"""
import csv
import io
import re

from core import compliance, db

_PAGE = 500
EXPORT_MAX = 50000
_STATUS_SQL = {"failed": "upper(c.status) LIKE 'FAIL%'", "passed": "upper(c.status) LIKE 'PASS%'",
               "warning": "upper(c.status) LIKE 'WARN%'",
               "unknown": "NOT (upper(COALESCE(c.status,'')) LIKE 'FAIL%' OR upper(COALESCE(c.status,'')) LIKE "
                          "'PASS%' OR upper(COALESCE(c.status,'')) LIKE 'WARN%')"}
_ORDER = ("CASE WHEN upper(c.status) LIKE 'FAIL%' THEN 0 WHEN upper(c.status) LIKE 'WARN%' THEN 1 "
          "WHEN upper(c.status) LIKE 'PASS%' THEN 3 ELSE 2 END, c.check_name, c.asset_uuid")
_ROW = ("asset_uuid", "check_id", "check_name", "status", "audit_file", "actual_value", "expected_value",
        "solution", "info", "see_also", "reference")


def _cols(table):
    try:
        return {r["name"] for r in db.query('PRAGMA table_info("%s")' % table, budget=0)}
    except Exception:
        return set()


def _like(s):
    return "%" + re.sub(r"([\\%_])", r"\\\1", s) + "%"


def _where(p, cc, ac):
    cl, args = [], []
    q = (p.get("q") or "").strip()
    if q:
        txt = ["c." + c for c in ("check_name", "check_id", "audit_file", "asset_uuid") if c in cc]
        txt += ["a." + c for c in ("hostname", "ip_address") if c in ac]
        if txt:
            cl.append("(" + " OR ".join(c + " LIKE ? ESCAPE '\\'" for c in txt) + ")")
            args += [_like(q)] * len(txt)
    st = (p.get("status") or "").strip().lower()
    if st in _STATUS_SQL:
        cl.append(_STATUS_SQL[st])
    af = (p.get("audit_file") or "").strip()
    if af and "audit_file" in cc:
        cl.append("c.audit_file = ?"); args.append(af)
    fw = (p.get("framework") or "").strip()
    if fw and "reference" in cc:
        # navi stores some frameworks with a leading space (' 800-53') — the facet list trims it
        cl.append("(c.reference LIKE ? ESCAPE '\\' OR c.reference LIKE ? ESCAPE '\\')")
        args += [_like("'framework': '%s'" % fw), _like("'framework': ' %s'" % fw)]
    chk = (p.get("check") or "").strip()
    if chk and "check_id" in cc:
        cl.append("c.check_id = ?"); args.append(chk)
    asset = (p.get("asset") or "").strip()
    if asset:
        cl.append("c.asset_uuid = ?"); args.append(asset)
    return (" WHERE " + " AND ".join(cl)) if cl else "", args


def _from(ac, join=True):
    """FROM clause; the assets join (hostname / IP) only when it is needed."""
    return " FROM compliance c" + (" LEFT JOIN assets a ON a.uuid = c.asset_uuid" if join and "uuid" in ac else "")


def _page(cc, ac, where, args, limit, offset):
    """One page in the explorer's order. Sorts only (rowid + sort keys) — not the wide text
    columns — then reads the full rows for that page by rowid: ~2× faster on 750k results."""
    need_join = bool(where) and ("a.hostname" in where or "a.ip_address" in where)
    ids = [r["rid"] for r in db.query("SELECT c.rowid AS rid" + _from(ac, need_join) + where + " ORDER BY " + _ORDER
                                      + " LIMIT ? OFFSET ?", tuple(args) + (limit, offset))]
    if not ids:
        return []
    by = {}
    for i in range(0, len(ids), 900):
        part = ids[i:i + 900]
        for r in db.query(_select(cc, ac) + ", c.rowid AS rid" + _from(ac) + " WHERE c.rowid IN (%s)"
                          % ",".join("?" * len(part)), tuple(part)):
            by[r["rid"]] = r
    return [by[i] for i in ids if i in by]


def _select(cc, ac):
    cols = ["%s AS %s" % ("c." + n if n in cc else "NULL", n) for n in _ROW]
    if "check_info" in cc:                   # navi's column is check_info (no `info`)
        cols[_ROW.index("info")] = ("COALESCE(NULLIF(TRIM(c.info),''), c.check_info) AS info" if "info" in cc
                                    else "c.check_info AS info")
    cols += ["%s AS %s" % ("a." + n if n in ac else "NULL", n) for n in ("hostname", "ip_address")]
    return "SELECT " + ", ".join(cols)


def _missing():
    return {"ok": True, "result": {"missing": True, "rows": [], "kpi": {},
                                   "reason": "no compliance data in navi.db — run navi config update compliance"}}, 200


def _refs(s):
    return ", ".join("%s %s" % (r.get("framework", ""), r.get("control", "")) if r.get("control")
                     else r.get("framework", "") for r in compliance.parse_reference(s))


def search(p):
    cc = _cols("compliance")
    if not cc:
        return _missing()
    ac = _cols("assets")
    where, args = _where(p, cc, ac)
    args = tuple(args)
    try:
        off = max(0, int(p.get("offset") or 0))
    except (TypeError, ValueError):
        off = 0
    try:
        n = max(1, min(_PAGE, int(p.get("limit") or _PAGE)))
    except (TypeError, ValueError):
        n = _PAGE
    k = db.query(
        "SELECT COUNT(*) AS results, COUNT(DISTINCT c.asset_uuid) AS assets,"
        " COUNT(DISTINCT c.check_id) AS checks,"
        " SUM(CASE WHEN upper(c.status) LIKE 'FAIL%' THEN 1 ELSE 0 END) AS failed,"
        " SUM(CASE WHEN upper(c.status) LIKE 'WARN%' THEN 1 ELSE 0 END) AS warning,"
        " SUM(CASE WHEN upper(c.status) LIKE 'PASS%' THEN 1 ELSE 0 END) AS passed,"
        " COUNT(DISTINCT CASE WHEN upper(c.status) LIKE 'FAIL%' THEN c.asset_uuid END) AS failing_assets"
        + _from(ac, "a.hostname" in where or "a.ip_address" in where) + where, args)
    kpi = {key: int(v or 0) for key, v in (dict(k[0]) if k else {}).items()}
    pf = kpi.get("passed", 0) + kpi.get("failed", 0)
    kpi["pass_pct"] = round(100.0 * kpi.get("passed", 0) / pf, 1) if pf else None
    rows = _page(cc, ac, where, args, n + 1, off)
    out = []
    for r in rows[:n]:
        r = dict(r)
        r.pop("rid", None)
        r["status"] = compliance._norm_status(r.get("status"))
        r["refs"] = _refs(r.pop("reference", None))
        out.append(r)
    return {"ok": True, "result": {"rows": out, "kpi": kpi, "offset": off, "page": off // n + 1,
                                   "has_next": len(rows) > n, "count": len(out)}}, 200


def facets(p):
    cc = _cols("compliance")
    if not cc:
        return _missing()
    files = []
    if "audit_file" in cc:
        files = [{"audit_file": r["audit_file"], "results": int(r["n"] or 0)} for r in db.query(
            "SELECT audit_file, COUNT(*) AS n FROM compliance WHERE COALESCE(audit_file,'')<>'' "
            "GROUP BY audit_file ORDER BY n DESC")]
    fw = {}
    if "reference" in cc:
        for r in db.query("SELECT reference, COUNT(*) AS n FROM compliance GROUP BY reference"):
            for f in {x.get("framework", "").strip() for x in compliance.parse_reference(r.get("reference"))}:
                if f:
                    fw[f] = fw.get(f, 0) + int(r["n"] or 0)
    return {"ok": True, "result": {"audit_files": files,
                                   "frameworks": [{"framework": f, "results": c}
                                                  for f, c in sorted(fw.items(), key=lambda x: (-x[1], x[0]))]}}, 200


_CSV = ("hostname", "ip_address", "asset_uuid", "status", "check_id", "check_name", "audit_file",
        "actual_value", "expected_value", "refs", "solution")


def export(p):
    cc = _cols("compliance")
    if not cc:
        return _missing()
    ac = _cols("assets")
    where, args = _where(p, cc, ac)
    rows = _page(cc, ac, where, args, EXPORT_MAX + 1, 0)
    capped = len(rows) > EXPORT_MAX
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(_CSV)
    for r in rows[:EXPORT_MAX]:
        r = dict(r)
        r["status"] = compliance._norm_status(r.get("status"))
        r["refs"] = _refs(r.get("reference"))
        w.writerow([_cell(r.get(c)) for c in _CSV])
    return {"ok": True, "csv": buf.getvalue(), "rows": min(len(rows), EXPORT_MAX), "capped": capped,
            "max": EXPORT_MAX}, 200


def _cell(v):
    """CSV cell, with spreadsheet-formula text neutralised (= + - @ at the start)."""
    s = "" if v is None else str(v)
    return "'" + s if s[:1] in ("=", "+", "-", "@") else s


ACTIONS = {"search": search, "facets": facets, "export": export}
