"""ACR log — a durable per-asset registry of every Asset Criticality Rating change the
Hounds make (and every asset an ACR change skipped).

Lives in the Tagging log's SQLite sidecar (``tag_jobs.db`` / ``NAVI_TAGLOG_DB``, see
core/tagq.py) as two extra tables, following the same pattern as core/activity.py (own
connection, WAL, best-effort — a DB hiccup never breaks an ACR write):

  acr_log      one row per asset per ACR change: when, which batch (one navi call), which
               Hound (acr / contract / ai / mcp), the tag selector, mod/score, the asset's
               ACR before → after (what navi computes from navi.db — core.acr_protect.preview),
               the Change Reasons, note, the human-readable business case, and the result:
                 applied           navi ran OK and the asset was in its update
                 blocked           writes are off (NAVI_ALLOW_WRITES) — nothing was sent
                 failed            navi failed / rejected the change
                 skipped_protected the asset carries NO : UPDATE — navi left it alone
                 skipped_no_acr    the asset has no ACR in navi.db — navi skips those
                 no_assets         (one summary row, no asset) the tag matched no asset in navi.db
               A refused change (a ' in the tag, a non-integer score, inc/dec over an ACR navi
               cannot int()) is never sent: its rows are failed with the reason. If navi crashes
               part-way anyway, assets in the ACR groups it sent first are applied, the rest failed.
  acr_protect  one row per asset per protection request (tag NO : UPDATE queued by a Hound),
               so the ACR page can show "requested, waiting for the next navi.db sync".

Written ONLY from core.navi_cli.acr() (the single ACR choke point) and
core.acr_protect.protect(). Everything else here is a read.
"""
import csv
import io
import json
import sqlite3
import threading
import time
import uuid as _uuid

from . import tagq

RESULTS = ("applied", "blocked", "failed", "skipped_protected", "skipped_no_acr", "no_assets")
_LOCK = threading.Lock()
_READY = None
_COLS = ("id", "ts", "batch", "agent", "category", "value", "mod", "score", "asset_uuid", "host", "ip",
         "acr_before", "acr_after", "status", "reasons", "note", "business_case", "result", "message", "tag_job")


def _con():
    con = sqlite3.connect(tagq._DBPATH, timeout=5.0)
    con.execute("PRAGMA busy_timeout=5000")
    return con


def _ensure():
    global _READY
    if _READY:
        return True
    try:
        con = _con()
        try:
            con.execute("PRAGMA journal_mode=WAL")
            con.execute("CREATE TABLE IF NOT EXISTS acr_log(id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, "
                        "batch TEXT, agent TEXT, category TEXT, value TEXT, mod TEXT, score TEXT, "
                        "asset_uuid TEXT, host TEXT, ip TEXT, acr_before TEXT, acr_after TEXT, status TEXT, "
                        "reasons TEXT, note TEXT, business_case TEXT, result TEXT, message TEXT, tag_job INTEGER)")
            con.execute("CREATE TABLE IF NOT EXISTS acr_protect(id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, "
                        "asset_uuid TEXT, agent TEXT, business_case TEXT, job_id INTEGER, batch TEXT)")
            con.execute("CREATE INDEX IF NOT EXISTS acr_log_asset ON acr_log(asset_uuid)")
            con.execute("CREATE INDEX IF NOT EXISTS acr_log_ts ON acr_log(ts)")
            con.execute("CREATE INDEX IF NOT EXISTS acr_log_batch ON acr_log(batch)")
            con.execute("CREATE INDEX IF NOT EXISTS acr_protect_asset ON acr_protect(asset_uuid)")
            con.commit()
        finally:
            con.close()
        _READY = True
    except Exception:
        _READY = False
    return _READY


def new_batch() -> str:
    return "acr-%d-%s" % (int(time.time() * 1000), _uuid.uuid4().hex[:6])


def _crashed(res) -> bool:
    """navi died on int(current_acr) (ValueError) — groups before that one were already sent."""
    r = res or {}
    return (not r.get("ok")) and "invalid literal for int()" in ((r.get("stderr") or "") + (r.get("stdout") or ""))


def _row_result(a, res, pv):
    """(result, acr_after, message) for one preview asset given navi's result (see module doc)."""
    r = res or {}
    st = a.get("status")
    after = _s(a.get("acr_after"))
    dup = ""
    if a.get("acr_rows"):
        dup = " navi.db has %d rows for this asset (ACR %s) — navi sends one update per ACR group%s." % (
            len(a["acr_rows"]), ", ".join(x if x is not None else "NULL" for x in a["acr_rows"]),
            (" (" + " then ".join(str(n) for _, n in a.get("sends") or []) + ")") if len(a.get("sends") or []) > 1 else "")
    if st == "protected":
        return "skipped_protected", "", "asset tagged NO : UPDATE — navi does not change its ACR"
    if st == "no_acr":
        return "skipped_no_acr", "", "asset has no ACR in navi.db — navi skips it"
    if st == "refused" or r.get("refused"):
        return "failed", after, ("not sent — " + (pv.get("refuse") or r.get("message") or "refused"))[:300]
    if r.get("blocked"):
        return "blocked", after, str(r.get("message") or "writes disabled on server")[:300]
    if st == "bad_acr":
        return "failed", "", "navi cannot read this asset's current ACR as a whole number — navi crashes on it"
    if r.get("ok"):
        return "applied", after, (_navi_text(r) + dup)[:300]
    crash = pv.get("crash_group")
    if _crashed(r) and crash is not None:
        before = [n for g, n in (a.get("sends") or []) if g < crash]
        if before:
            return "applied", _s(before[-1]), ("sent before navi crashed on a later ACR group (int() on an "
                                               "unreadable ACR)." + dup)[:300]
        return "failed", after, "never sent — navi crashed on an earlier ACR group (int() on an unreadable ACR)"
    return "failed", after, _navi_text(r)[:300]


def _navi_text(r):
    text = r.get("warning") or r.get("message")
    if not text:
        out = ((r.get("stdout") or "").strip() or (r.get("stderr") or "").strip()).splitlines()
        text = out[-1] if out else ("applied" if r.get("ok") else "navi returned a non-zero exit")
    return str(text)


def _summary_result(res):
    r = res or {}
    return "blocked" if r.get("blocked") else ("applied" if r.get("ok") else "failed")


def record_change(preview, res, agent, category, value, mod, score, reasons, note, business_case,
                  tag_job=None) -> dict:
    """Write one row per asset of an ACR change. `preview` is core.acr_protect.preview()
    computed immediately BEFORE the navi call (None/failed → one summary row, no assets)."""
    batch = new_batch()
    out = {"batch": batch, "counts": {k: 0 for k in RESULTS}, "logged": 0}
    if not _ensure():
        out["error"] = "ACR log unavailable"
        return out
    now = time.time()
    rs = json.dumps([str(x) for x in (reasons or [])])
    base = (now, batch, agent or "", category or "", value or "", mod or "", str(score))
    rows = []
    pv = preview if isinstance(preview, dict) else {}
    if pv.get("ok") and not pv.get("assets"):
        # the tag matched no asset in navi.db — navi changes nothing, but the change is registered
        result = _summary_result(res)
        if result == "applied":
            result = "no_assets"
        if pv.get("refuse") or (res or {}).get("refused"):
            result = "failed"
        out["counts"][result] += 1
        rows.append(base + ("", "", "", "", "", "no_assets", rs, note or "", business_case or "", result,
                            ("no asset in navi.db carries this tag — navi changed nothing. "
                             + (pv.get("refuse") or _navi_text(res or {})))[:300], tag_job))
    elif pv.get("ok"):
        for a in pv.get("assets") or []:
            result, after, msg = _row_result(a, res, pv)
            out["counts"][result] = out["counts"].get(result, 0) + 1
            rows.append(base + (a.get("uuid") or "", a.get("hostname") or "", a.get("ip") or "",
                                # acr_after = what navi set (blocked/failed rows: what it would have set)
                                _s(a.get("acr_before")), after, a.get("status") or "", rs, note or "",
                                business_case or "", result, msg, tag_job))
    else:
        # navi.db unreadable → the change is still registered, without per-asset detail
        result = _summary_result(res)
        out["counts"][result] += 1
        rows.append(base + ("", "", "", "", "", "unknown", rs, note or "", business_case or "", result,
                            (("preview unavailable (%s) — " % (pv.get("error") or "navi.db not readable"))
                             + _navi_text(res or {}))[:300], tag_job))
    try:
        with _LOCK:
            con = _con()
            try:
                con.executemany("INSERT INTO acr_log(ts,batch,agent,category,value,mod,score,asset_uuid,host,ip,"
                                "acr_before,acr_after,status,reasons,note,business_case,result,message,tag_job) "
                                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", rows)
                con.commit()
            finally:
                con.close()
        out["logged"] = len(rows)
    except Exception as e:
        out["error"] = str(e)
    return out


def _s(v):
    return "" if v is None else str(v)


def record_protect(uuids, agent, business_case, job_id=None, batch="") -> int:
    if not uuids or not _ensure():
        return 0
    now = time.time()
    try:
        with _LOCK:
            con = _con()
            try:
                con.executemany("INSERT INTO acr_protect(ts,asset_uuid,agent,business_case,job_id,batch) "
                                "VALUES(?,?,?,?,?,?)",
                                [(now, u, agent or "", business_case or "", job_id, batch or "") for u in uuids])
                con.commit()
            finally:
                con.close()
        return len(uuids)
    except Exception:
        return 0


def _q(sql, params=()):
    if not _ensure():
        return []
    try:
        con = _con()
        try:
            con.row_factory = sqlite3.Row
            return [dict(r) for r in con.execute(sql, params).fetchall()]
        finally:
            con.close()
    except Exception:
        return []


def _where(f):
    f = f or {}
    w, p = [], []
    for k in ("agent", "result", "business_case", "batch", "category", "value"):
        v = f.get(k)
        if v == "__none":                               # the page's "(none)" option
            w.append("(%s IS NULL OR %s = '')" % (k, k))
        elif v not in (None, ""):
            w.append("%s = ?" % k)
            p.append(str(v))
    if f.get("since") not in (None, ""):
        try:
            w.append("ts >= ?"); p.append(float(f["since"]))
        except (TypeError, ValueError):
            w.pop()
    if f.get("until") not in (None, ""):
        try:
            w.append("ts <= ?"); p.append(float(f["until"]))
        except (TypeError, ValueError):
            w.pop()
    q = str(f.get("q") or "").strip()
    if q:
        w.append("(asset_uuid LIKE ? OR host LIKE ? OR ip LIKE ?)")
        p += ["%" + q + "%"] * 3
    return ((" WHERE " + " AND ".join(w)) if w else ""), tuple(p)


def rows(filters=None, limit=5000) -> dict:
    """Newest-first ACR log rows matching the filters, plus the total match count."""
    w, p = _where(filters)
    lim = max(1, min(100000, int(limit or 5000)))
    data = _q("SELECT * FROM acr_log" + w + " ORDER BY id DESC LIMIT ?", p + (lim,))
    for r in data:
        try:
            r["reasons"] = json.loads(r.get("reasons") or "[]")
        except Exception:
            r["reasons"] = []
    tot = _q("SELECT COUNT(*) n FROM acr_log" + w, p)
    return {"rows": data, "total": (tot[0]["n"] if tot else 0), "limit": lim}


def facets() -> dict:
    """Distinct agents / results / business cases (with row counts) for the log's filters."""
    def g(col):
        return [{"v": r["v"], "n": r["n"]} for r in
                _q("SELECT %s v, COUNT(*) n FROM acr_log GROUP BY %s ORDER BY n DESC" % (col, col))]
    return {"agent": g("agent"), "result": g("result"), "business_case": g("business_case")}


_CSV_FORMULA = ("=", "+", "-", "@", "\t", "\r")


def csv_safe(v):
    """Neutralise spreadsheet formulas: a text cell starting with = + - @ TAB CR gets a leading '."""
    if isinstance(v, str) and v.startswith(_CSV_FORMULA):
        return "'" + v
    return v


def export_csv(filters=None) -> dict:
    w, p = _where(filters)
    data = _q("SELECT * FROM acr_log" + w + " ORDER BY id ASC", p)
    buf = io.StringIO()
    wr = csv.writer(buf)
    hdr = ["ts_utc", "batch", "agent", "category", "value", "mod", "score", "asset_uuid", "host", "ip",
           "acr_before", "acr_after", "result", "business_case", "reasons", "note", "message"]
    wr.writerow(hdr)
    for r in data:
        try:
            rs = ";".join(json.loads(r.get("reasons") or "[]"))
        except Exception:
            rs = ""
        wr.writerow([csv_safe(x) for x in (
            time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(r.get("ts") or 0)), r.get("batch"),
            r.get("agent"), r.get("category"), r.get("value"), r.get("mod"), r.get("score"),
            r.get("asset_uuid"), r.get("host"), r.get("ip"), r.get("acr_before"), r.get("acr_after"),
            r.get("result"), r.get("business_case"), rs, r.get("note"), r.get("message"))])
    return {"count": len(data), "csv": buf.getvalue(), "filename": "hounds-acr-log.csv"}


def applied_assets() -> dict:
    """{uuid: {last_ts, business_case, agent, acr_after, host, ip, changes}} for every asset the
    Hounds changed (result = applied), the last change winning."""
    out = {}
    for r in _q("SELECT asset_uuid, ts, business_case, agent, acr_after, host, ip, category, value, status "
                "FROM acr_log WHERE result='applied' AND asset_uuid<>'' ORDER BY id ASC"):
        u = r["asset_uuid"]
        prev = out.get(u)
        out[u] = {"last_ts": r["ts"], "business_case": r["business_case"] or "", "agent": r["agent"] or "",
                  "acr_after": r["acr_after"], "host": r["host"] or "", "ip": r["ip"] or "",
                  "selector": "%s : %s" % (r["category"], r["value"]),
                  "unchanged": r["status"] == "unchanged",      # navi re-sent the ACR it already had
                  "changes": (prev["changes"] + 1) if prev else 1}
    return out


def batch_uuids(batch, result="applied") -> list:
    return [r["asset_uuid"] for r in _q("SELECT DISTINCT asset_uuid FROM acr_log WHERE batch=? AND result=? "
                                       "AND asset_uuid<>''", (str(batch or ""), result))]


def protect_requests() -> dict:
    """{uuid: {ts, job_id, business_case, agent}} — the latest protection request per asset."""
    out = {}
    for r in _q("SELECT asset_uuid, ts, job_id, business_case, agent FROM acr_protect ORDER BY id ASC"):
        out[r["asset_uuid"]] = {"ts": r["ts"], "job_id": r["job_id"], "business_case": r["business_case"] or "",
                                "agent": r["agent"] or ""}
    return out


def result_counts() -> dict:
    return {r["result"]: r["n"] for r in _q("SELECT result, COUNT(*) n FROM acr_log GROUP BY result")}
