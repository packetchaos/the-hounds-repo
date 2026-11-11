"""Alert Raven — the alerting companion that rides with the pack.

Watches navi.db for conditions worth waking a human. Read-only detection; email
delivery is gated (NAVI_EMAIL). Alerts fire ON CHANGE — the fired-state must flip
false→true to notify — so a persistent condition emails once, not every cycle. A
single digest is sent per evaluation. Definitions + runtime state persist as JSON.

An alert is a METRIC (a number) + a CONDITION (op vs a threshold, optionally vs the
previous snapshot). Two metric sources:
  • builtin — a named Python check (cred_coverage, slow_scans) for things SQL can't
    express cleanly (scan-duration text, credential coverage).
  • sql     — a read-only SELECT whose first numeric cell (or row count) is the metric,
    plus an optional detail SELECT listing the affected assets for the email.
"""
import json
import os
import re
import time

from core import db, hx_summary, navi_cli, tagname
from core.security import private_open as _popen

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ALERT_DIR = os.environ.get("ALERT_DIR", os.path.join(HERE, "alerts"))
DEFS_PATH = os.path.join(ALERT_DIR, "alerts.json")
STATE_PATH = os.path.join(ALERT_DIR, "state.json")

SEVERITIES = ("info", "warning", "critical")
_OPS = ("gt", "lt", "gte", "lte", "eq", "appears", "drop_abs", "rise_abs", "drop_pct", "rise_pct")
_OP_LABEL = {"gt": "is above", "lt": "is below", "gte": "is at or above", "lte": "is at or below",
             "eq": "equals", "appears": "has any", "drop_abs": "drops by ≥", "rise_abs": "rises by ≥",
             "drop_pct": "drops ≥ %", "rise_pct": "rises ≥ %"}
_MAX_DETAIL = 100


# --------------------------------------------------------------------------- #
#  builtin checks — return {"value": float, "unit": str, "affected": [rows], "note": str}
# --------------------------------------------------------------------------- #
def _chk_cred_coverage(db_path, params):
    """% of assets with a clean credentialed scan (no plugin 104410 failure).
    Affected = the failed assets with the account parsed out of the 104410 output."""
    from core import scan_eval
    ev = scan_eval.evaluate(db_path)
    cred = ev.get("credential", {}) or {}
    total = int(cred.get("total_assets") or 0)
    fail = int(cred.get("cred_fail_assets") or 0)
    value = round(100.0 * (total - fail) / total, 1) if total else 100.0
    # pull the failed account out of the 104410 plugin output for each affected asset
    affected = []
    try:
        rows = db.query("SELECT v.asset_uuid, a.hostname, a.ip_address, v.output "
                        "FROM vulns v LEFT JOIN assets a ON a.uuid=v.asset_uuid "
                        "WHERE v.plugin_id='104410' LIMIT %d" % _MAX_DETAIL, path=db_path)
    except Exception:
        rows = []
    for r in rows:
        affected.append({"host": (r.get("hostname") or "").strip() or r.get("ip_address") or "(none)",
                         "ip": r.get("ip_address") or "", "account": _account_from_104410(r.get("output") or ""),
                         "uuid": r.get("asset_uuid") or ""})
    return {"value": value, "unit": "%", "affected": affected,
            "note": "%d of %d assets credentialed · %d failing (plugin 104410)" % (total - fail, total, fail)}


def _chk_slow_scans(db_path, params):
    """Assets whose last scan ran longer than `hours` (default 3), parsed from plugin
    19506 (Nessus Scan Information) — the same source the Scan-eval hound uses."""
    from core import scan_eval
    hours = float((params or {}).get("hours") or 3)
    limit = hours * 3600.0
    try:
        rows = db.query("SELECT v.asset_uuid, a.hostname, a.ip_address, v.output "
                        "FROM vulns v LEFT JOIN assets a ON a.uuid=v.asset_uuid "
                        "WHERE v.plugin_id='19506' AND v.output IS NOT NULL AND v.output<>''", path=db_path)
    except Exception:
        rows = []
    slow = []
    for r in rows:
        out = r.get("output") or ""
        dur = scan_eval._duration_sec(out)
        if dur is not None and dur > limit:
            slow.append({"host": (r.get("hostname") or "").strip() or r.get("ip_address") or "(none)",
                         "ip": r.get("ip_address") or "", "uuid": r.get("asset_uuid") or "",
                         "hours": round(dur / 3600.0, 1), "scan": scan_eval._field(out, "Scan name")})
    slow.sort(key=lambda x: -x["hours"])
    return {"value": float(len(slow)), "unit": "asset(s)", "affected": slow[:_MAX_DETAIL],
            "note": "%d asset(s) scanned longer than %gh" % (len(slow), hours)}


BUILTINS = {"cred_coverage": _chk_cred_coverage, "slow_scans": _chk_slow_scans}


def _account_from_104410(output):
    """Best-effort account/login extraction from a 104410 credential-failure output."""
    for pat in (r"account\s*[:=]\s*([^\n\r]+)", r"user(?:name)?\s*[:=]\s*([^\n\r]+)",
                r"login\s*[:=]\s*([^\n\r]+)", r"protocol\s*[:=]\s*([^\n\r]+)"):
        m = re.search(pat, output, re.I)
        if m:
            return m.group(1).strip()[:80]
    return "(account not in output)"


# --------------------------------------------------------------------------- #
#  template library — the "suggest patterns" seed set
# --------------------------------------------------------------------------- #
def _tpl(id, name, sev, desc, op, threshold, unit="", source="sql", builtin=None,
         metric_sql=None, detail_sql=None, params=None, requires=None):
    return {"id": id, "name": name, "severity": sev, "desc": desc, "op": op, "threshold": threshold,
            "unit": unit, "source": source, "builtin": builtin, "metric_sql": metric_sql,
            "detail_sql": detail_sql, "params": params or {}, "requires": requires or {}}


TEMPLATES = [
    _tpl("cred_coverage_drop", "Credentialed-scan coverage dropped", "warning",
         "Alerts when the share of assets with a clean credentialed scan falls by 15+ points "
         "since the last cycle. Lists the failing assets and the account from plugin 104410.",
         "drop_abs", 15, unit="%", source="builtin", builtin="cred_coverage",
         requires={"plugin": "104410"}),
    _tpl("slow_scans", "Asset scans taking over 3 hours", "warning",
         "Alerts when any asset's last scan ran longer than 3 hours (plugin 19506) — a sign of "
         "scanner overload or a stuck target.",
         "gt", 0, unit="asset(s)", source="builtin", builtin="slow_scans", params={"hours": 3},
         requires={"plugin": "19506"}),
    _tpl("kev_new", "New CISA KEV exposure", "critical",
         "Alerts when the count of assets carrying a CISA Known-Exploited vuln rises since the "
         "last cycle — actively-exploited risk just landed.",
         "rise_abs", 1, unit="asset(s)",
         metric_sql="SELECT COUNT(DISTINCT asset_uuid) FROM vulns WHERE xrefs LIKE '%CISA-KNOWN-EXPLOITED%'",
         detail_sql="SELECT DISTINCT a.hostname AS host, a.ip_address AS ip FROM vulns v "
                    "LEFT JOIN assets a ON a.uuid=v.asset_uuid WHERE v.xrefs LIKE '%CISA-KNOWN-EXPLOITED%' LIMIT 100",
         requires={"like": "CISA-KNOWN-EXPLOITED"}),
    _tpl("new_criticals", "New critical findings", "critical",
         "Alerts when the number of assets with a critical-severity finding rises since the last cycle.",
         "rise_abs", 1, unit="asset(s)",
         metric_sql="SELECT COUNT(DISTINCT asset_uuid) FROM vulns WHERE lower(severity)='critical'",
         detail_sql="SELECT DISTINCT a.hostname AS host, a.ip_address AS ip FROM vulns v "
                    "LEFT JOIN assets a ON a.uuid=v.asset_uuid WHERE lower(v.severity)='critical' LIMIT 100"),
    _tpl("certs_expiring", "Certificates expiring within 30 days", "warning",
         "Alerts when any certificate expires within the next 30 days (needs the certs table).",
         "gt", 0, unit="cert(s)",
         metric_sql="SELECT COUNT(*) FROM certs WHERE not_valid_after IS NOT NULL "
                    "AND date(not_valid_after) <= date('now','+30 day')",
         detail_sql="SELECT common_name AS host, not_valid_after AS ip FROM certs "
                    "WHERE not_valid_after IS NOT NULL AND date(not_valid_after) <= date('now','+30 day') LIMIT 100",
         requires={"table": "certs"}),
    _tpl("ownerless_rise", "Ownerless assets rising", "warning",
         "Alerts when the number of assets with no Owner tag rises since the last cycle.",
         "rise_abs", 1, unit="asset(s)",
         metric_sql="SELECT COUNT(uuid) FROM assets WHERE uuid NOT IN "
                    "(SELECT DISTINCT asset_uuid FROM tags WHERE " + tagname.sql_lit("tag_key", "Owner") + ")"),
    _tpl("eol_rise", "End-of-life / unsupported software rising", "warning",
         "Alerts when the count of assets running End-of-Life or unsupported software rises.",
         "rise_abs", 1, unit="asset(s)",
         metric_sql="SELECT COUNT(DISTINCT asset_uuid) FROM vulns WHERE lower(plugin_name) LIKE '%unsupported%' "
                    "OR lower(plugin_name) LIKE '%end of life%' OR lower(plugin_name) LIKE '%end-of-life%'"),
]
_TPL_BY_ID = {t["id"]: t for t in TEMPLATES}


# --------------------------------------------------------------------------- #
#  persistence
# --------------------------------------------------------------------------- #
def _load_defs():
    try:
        with open(DEFS_PATH, encoding="utf-8") as f:
            d = json.load(f)
            return d if isinstance(d, list) else []
    except Exception:
        return []


def _save_defs(defs):
    os.makedirs(ALERT_DIR, mode=0o700, exist_ok=True)
    with _popen(DEFS_PATH, "w", encoding="utf-8") as f:
        json.dump(defs, f, indent=2)


def _load_state():
    try:
        with open(STATE_PATH, encoding="utf-8") as f:
            s = json.load(f)
    except Exception:
        s = {}
    s.setdefault("snap", {}); s.setdefault("fired", {}); s.setdefault("history", []); s.setdefault("last_run", None)
    return s


def _save_state(s):
    os.makedirs(ALERT_DIR, mode=0o700, exist_ok=True)
    with _popen(STATE_PATH, "w", encoding="utf-8") as f:
        json.dump(s, f, indent=2)


def _new_id():
    return "al" + hex(int(time.time() * 1000))[2:] + hex(int.from_bytes(os.urandom(2), "big"))[2:]


# --------------------------------------------------------------------------- #
#  metric + evaluation
# --------------------------------------------------------------------------- #
def _read_only(sql):
    s = (sql or "").strip().rstrip(";")
    low = s.lower()
    if not (low.startswith("select") or low.startswith("with")):
        return None
    if re.search(r"\b(insert|update|delete|drop|alter|create|attach|pragma|replace|vacuum)\b", low):
        return None
    return s


_FM_HEAD = re.compile(r"^select\s+count\s*\(\s*distinct\s+asset_uuid\s*\)\s+from\s+vulns\s+where\s+(.+)$", re.I | re.S)
_FM_NAME = re.compile(r"^\(?\s*(?:lower\s*\(\s*plugin_name\s*\)|plugin_name)\s+like\s+'(%[^'%]+%)'\s*\)?$", re.I)
_FM_KEV = re.compile(r"^\(?\s*xrefs\s+like\s+'%CISA-KNOWN-EXPLOITED%'\s*\)?$", re.I)
_FM_CRIT = re.compile(r"^\(?\s*lower\s*\(\s*severity\s*\)\s*=\s*'critical'\s*\)?$", re.I)


def _fast_metric(sql, db_path=None):
    """Phase 1: an equivalent of the stock asset-count metrics (the kev_new / new_criticals /
    eol_rise templates, and the same shapes when written by hand or by the model) that reads the
    hx summaries or a covering index instead of every vulns row — or None to run the SQL as written.
    The stored/shown metric_sql never changes, so it keeps working on a navi.db without summaries.
      COUNT(DISTINCT asset_uuid) … xrefs LIKE '%CISA-KNOWN-EXPLOITED%'  → hx_asset.kev_any
      … lower(plugin_name) LIKE '%x%' [OR …]                           → hx_plugin.lname + hx_v_plugin
      … lower(severity)='critical'                                      → per finding, hx_v_plugin only"""
    m = _FM_HEAD.match(re.sub(r"\s+", " ", (sql or "").strip().rstrip(";")).strip())
    if not m:
        return None
    cond = m.group(1).strip()
    if not hx_summary.usable(db_path):
        return None
    if _FM_CRIT.match(cond):
        ib = db.indexed_by("hx_v_plugin", db_path)
        return ("SELECT COUNT(DISTINCT asset_uuid) FROM vulns%s WHERE lower(severity)='critical'" % ib) if ib else None
    if _FM_KEV.match(cond):
        return "SELECT COUNT(*) FROM hx_asset WHERE kev_any"
    pats = []
    for part in re.split(r"\s+or\s+", cond, flags=re.I):
        n = _FM_NAME.match(part.strip())
        if not n:
            return None
        pats.append("lname LIKE '%s'" % n.group(1))
    return "SELECT COUNT(asset_uuid) FROM (%s)" % hx_summary.assets_with("(" + " OR ".join(pats) + ")", path=db_path)


def _metric_of(alert, db_path):
    """{value, unit, affected, note} for either a builtin or a SQL alert."""
    if alert.get("source") == "builtin":
        fn = BUILTINS.get(alert.get("builtin"))
        if not fn:
            return {"value": None, "unit": alert.get("unit", ""), "affected": [], "note": "unknown builtin"}
        try:
            return fn(db_path, alert.get("params") or {})
        except Exception as e:
            return {"value": None, "unit": alert.get("unit", ""), "affected": [], "note": "check failed: %s" % e}
    sql = _read_only(alert.get("metric_sql"))
    if not sql:
        return {"value": None, "unit": alert.get("unit", ""), "affected": [], "note": "metric query must be a read-only SELECT"}
    try:
        fast = _fast_metric(sql, db_path)
        rows = db.query(fast, path=db_path) if fast else \
            db.user_query(sql, path=db_path)      # user/LLM SQL: secret tables unreadable
    except Exception as e:
        return {"value": None, "unit": alert.get("unit", ""), "affected": [], "note": "query error: %s" % e}
    value = None
    if rows:
        first = rows[0]
        vals = list(first.values())
        if vals and isinstance(vals[0], (int, float)):
            value = float(vals[0])
    if value is None:
        value = float(len(rows))          # no numeric metric column → treat as a row count
    affected = []
    det = _read_only(alert.get("detail_sql"))
    if det:
        try:
            drows = db.user_query(det, path=db_path)
            for r in drows[:_MAX_DETAIL]:
                vs = list(r.values())
                affected.append({"host": str(vs[0]) if vs else "", "ip": str(vs[1]) if len(vs) > 1 else "",
                                 "account": "", "uuid": ""})
        except Exception:
            pass
    return {"value": value, "unit": alert.get("unit", ""), "affected": affected, "note": ""}


def _fires(op, value, threshold, baseline):
    if value is None:
        return False
    try:
        t = float(threshold)
    except Exception:
        t = 0.0
    if op in ("gt",):
        return value > t
    if op in ("lt",):
        return value < t
    if op in ("gte",):
        return value >= t
    if op in ("lte",):
        return value <= t
    if op in ("eq",):
        return value == t
    if op == "appears":
        return value > 0
    if op == "drop_abs":
        return baseline is not None and (baseline - value) >= t
    if op == "rise_abs":
        return baseline is not None and (value - baseline) >= t
    if op == "drop_pct":
        return baseline not in (None, 0) and (baseline - value) / baseline * 100.0 >= t
    if op == "rise_pct":
        return baseline not in (None, 0) and (value - baseline) / baseline * 100.0 >= t
    return False


def evaluate_one(alert, db_path=None, baseline=None):
    m = _metric_of(alert, db_path)
    value = m["value"]
    fired = _fires(alert.get("op", "gt"), value, alert.get("threshold", 0), baseline)
    unit = m.get("unit") or alert.get("unit", "")
    vtxt = "—" if value is None else ("%g" % value)
    cond = "%s %s%s" % (_OP_LABEL.get(alert.get("op", "gt"), alert.get("op", "")),
                        alert.get("threshold", ""), (" " + unit) if unit and alert.get("op") not in ("drop_pct", "rise_pct") else "")
    msg = "%s = %s%s (%s)%s" % (alert.get("name", "alert"), vtxt, (" " + unit if unit else ""),
                                cond, ("" if baseline is None else " · was %g" % baseline))
    return {"id": alert.get("id"), "name": alert.get("name"), "severity": alert.get("severity", "warning"),
            "value": value, "baseline": baseline, "unit": unit, "fired": fired,
            "affected": m.get("affected", []), "note": m.get("note", ""), "message": msg}


def test(alert, db_path=None):
    """Dry-run: evaluate against the previous snapshot WITHOUT changing state or sending."""
    st = _load_state()
    base = st["snap"].get(alert.get("id")) if alert.get("id") else None
    res = evaluate_one(alert, db_path, baseline=base)
    res["would_fire"] = res["fired"]
    res["email_preview"] = _one_block(res)
    return res


# --------------------------------------------------------------------------- #
#  CRUD
# --------------------------------------------------------------------------- #
def list_alerts():
    return _load_defs()


def save_alert(alert):
    defs = _load_defs()
    a = dict(alert)
    a["severity"] = a.get("severity") if a.get("severity") in SEVERITIES else "warning"
    a.setdefault("enabled", True)
    a.setdefault("op", "gt")
    a.setdefault("source", "builtin" if a.get("builtin") else "sql")
    if a.get("source") == "sql" and not _read_only(a.get("metric_sql")):
        return {"ok": False, "error": "metric query must be a single read-only SELECT"}
    if a.get("id"):
        for i, d in enumerate(defs):
            if d.get("id") == a["id"]:
                defs[i] = {**d, **a}
                _save_defs(defs)
                return {"ok": True, "alert": defs[i]}
    a["id"] = _new_id()
    a.setdefault("created", time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
    defs.append(a)
    _save_defs(defs)
    return {"ok": True, "alert": a}


def add_template(template_id, overrides=None):
    t = _TPL_BY_ID.get(template_id)
    if not t:
        return {"ok": False, "error": "unknown template '%s'" % template_id}
    a = {k: t[k] for k in ("name", "severity", "op", "threshold", "unit", "source",
                           "builtin", "metric_sql", "detail_sql", "params")}
    a["template"] = template_id
    a["enabled"] = True
    if overrides:
        a.update(overrides)
    return save_alert(a)


def delete_alert(alert_id):
    defs = [d for d in _load_defs() if d.get("id") != alert_id]
    _save_defs(defs)
    st = _load_state()
    st["snap"].pop(alert_id, None); st["fired"].pop(alert_id, None)
    _save_state(st)
    return {"ok": True}


def toggle(alert_id, enabled):
    defs = _load_defs()
    for d in defs:
        if d.get("id") == alert_id:
            d["enabled"] = bool(enabled)
    _save_defs(defs)
    return {"ok": True}


# --------------------------------------------------------------------------- #
#  evaluate all → on-change digest
# --------------------------------------------------------------------------- #
def _one_block(res):
    lines = ["[%s] %s" % (res["severity"].upper(), res["name"]), "  " + res["message"]]
    if res.get("note"):
        lines.append("  " + res["note"])
    aff = res.get("affected") or []
    for a in aff[:20]:
        extra = (" · " + a["account"]) if a.get("account") else ""
        loc = a.get("ip") or ""
        hrs = (" · %sh" % a["hours"]) if a.get("hours") is not None else ""
        lines.append("    - %s%s%s%s" % (a.get("host", ""), (" (" + loc + ")") if loc else "", hrs, extra))
    if len(aff) > 20:
        lines.append("    … +%d more" % (len(aff) - 20))
    return "\n".join(lines)


def default_recipient():
    return (os.environ.get("NAVI_ALERT_EMAIL") or os.environ.get("NAVI_EMAIL_TO") or "").strip()


def allowed_recipients():
    """The only addresses Alert Raven mails: NAVI_ALERT_EMAIL / NAVI_EMAIL_TO (comma lists),
    configured by the operator — a request can't redirect alerts to an arbitrary inbox."""
    out = []
    for k in ("NAVI_ALERT_EMAIL", "NAVI_EMAIL_TO"):
        for a in re.split(r"[,;]", os.environ.get(k) or ""):
            a = a.strip()
            if a and a.lower() not in [x.lower() for x in out]:
                out.append(a)
    return out


def recipient_allowed(recipient):
    """(ok, reason). Blank = the configured default (must exist)."""
    allowed = allowed_recipients()
    r = (recipient or "").strip()
    if not r:
        return (True, "") if allowed else (False, "no recipient — set a default alert email "
                                                  "(NAVI_ALERT_EMAIL) on Settings first")
    want = [x.strip().lower() for x in re.split(r"[,;]", r) if x.strip()]
    low = {a.lower() for a in allowed}
    bad = [x for x in want if x not in low]
    if bad:
        return False, ("recipient not allowed: " + ", ".join(bad) + " — Alert Raven only mails the "
                       "configured alert address(es) (NAVI_ALERT_EMAIL).")
    return True, ""


def evaluate_all(db_path=None, send=False, recipient=None, source="manual"):
    """Evaluate every enabled alert. Fire (notify) only alerts whose condition just
    flipped false→true since the last run. Update snapshots + fired-state. When `send`
    and something newly fired, email ONE digest (gated). Returns the run summary."""
    defs = _load_defs()
    st = _load_state()
    evaluated, newly, still = [], [], []
    for a in defs:
        if not a.get("enabled", True):
            continue
        base = st["snap"].get(a["id"])
        res = evaluate_one(a, db_path, baseline=base)
        was = bool(st["fired"].get(a["id"]))
        st["snap"][a["id"]] = res["value"]
        st["fired"][a["id"]] = res["fired"]
        evaluated.append(res)
        if res["fired"] and not was:
            newly.append(res)
        elif res["fired"] and was:
            still.append(res)
    ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    st["last_run"] = ts
    sent = None
    if send and newly:
        sent = _send_digest(newly, recipient or default_recipient())
    st["history"].insert(0, {"ts": ts, "source": source, "evaluated": len(evaluated),
                             "newly": [r["name"] for r in newly], "still": len(still),
                             "sent": bool(sent and sent.get("ok"))})
    st["history"] = st["history"][:200]
    _save_state(st)
    return {"ok": True, "ts": ts, "evaluated": evaluated, "newly_fired": newly,
            "still_firing": still, "sent": sent, "recipient": recipient or default_recipient()}


def _send_digest(newly, recipient):
    if not recipient:
        return {"ok": False, "reason": "no recipient — set a default alert email (NAVI_ALERT_EMAIL) or pass one"}
    ok_r, why = recipient_allowed(recipient)
    if not ok_r:
        return {"ok": False, "reason": why}
    if not navi_cli.email_enabled():
        return {"ok": False, "reason": navi_cli.email_gate_reason()
                if hasattr(navi_cli, "email_gate_reason") else "email disabled (set NAVI_EMAIL=1)"}
    crit = sum(1 for r in newly if r["severity"] == "critical")
    subject = "🚨 [Hounds] %d alert%s fired%s" % (len(newly), "" if len(newly) == 1 else "s",
                                                  " · %d critical" % crit if crit else "")
    body = ["Alert Raven — %d alert(s) newly fired at %s UTC" % (len(newly), time.strftime("%Y-%m-%d %H:%M", time.gmtime())), ""]
    for r in sorted(newly, key=lambda x: {"critical": 0, "warning": 1, "info": 2}.get(x["severity"], 3)):
        body.append(_one_block(r)); body.append("")
    body.append("— The Hounds · Alert Raven (alerting). Read-only detection over navi.db.")
    try:
        return navi_cli.mail(to=recipient, subject=subject, message="\n".join(body), agent="alert")
    except Exception as e:
        return {"ok": False, "reason": str(e)}


# --------------------------------------------------------------------------- #
#  metrics + suggestions + NL craft
# --------------------------------------------------------------------------- #
def _within_days(iso, days):
    try:
        return (time.time() - time.mktime(time.strptime(iso[:19], "%Y-%m-%dT%H:%M:%S"))) <= days * 86400
    except Exception:
        return False


def metrics(db_path=None):
    defs = _load_defs()
    st = _load_state()
    enabled = [d for d in defs if d.get("enabled", True)]
    by_sev = {s: sum(1 for d in enabled if d.get("severity") == s) for s in SEVERITIES}
    fired_now = sum(1 for d in enabled if st["fired"].get(d["id"]))
    hist = st.get("history", [])
    def fired_count(days):
        return sum(len(h.get("newly", [])) for h in hist if _within_days(h.get("ts", ""), days))
    return {"ok": True, "defined": len(defs), "enabled": len(enabled), "disabled": len(defs) - len(enabled),
            "by_severity": by_sev, "firing_now": fired_now,
            "fired_7d": fired_count(7), "fired_30d": fired_count(30),
            "last_run": st.get("last_run"), "runs_logged": len(hist),
            "email_enabled": navi_cli.email_enabled(), "recipient": default_recipient()}


def history(limit=50):
    return _load_state().get("history", [])[:limit]


def suggest(db_path=None):
    """Which seed templates are relevant to THIS navi.db (so the UI can recommend them),
    each with a reason + a live count where cheap to compute."""
    out = []
    have_defs = {d.get("template") for d in _load_defs()}
    def scalar(sql):
        try:
            return db.scalar(_fast_metric(sql, db_path) or sql, path=db_path) or 0
        except Exception:
            return 0
    def has_table(t):
        try:
            return bool(db.query("SELECT name FROM sqlite_master WHERE type='table' AND name=?", (t,), path=db_path))
        except Exception:
            return False
    checks = {
        "cred_coverage_drop": (scalar("SELECT COUNT(*) FROM vulns WHERE plugin_id='104410'"), "assets currently failing credentialed scan"),
        "slow_scans": (scalar("SELECT COUNT(*) FROM vulns WHERE plugin_id='19506'"), "assets with scan-timing data"),
        "kev_new": (scalar("SELECT COUNT(DISTINCT asset_uuid) FROM vulns WHERE xrefs LIKE '%CISA-KNOWN-EXPLOITED%'"), "assets with a CISA KEV today"),
        "new_criticals": (scalar("SELECT COUNT(DISTINCT asset_uuid) FROM vulns WHERE lower(severity)='critical'"), "assets with a critical finding"),
        "certs_expiring": (scalar("SELECT COUNT(*) FROM certs WHERE not_valid_after IS NOT NULL AND date(not_valid_after)<=date('now','+30 day')") if has_table("certs") else 0, "certificates expiring ≤30d"),
        "ownerless_rise": (scalar("SELECT COUNT(uuid) FROM assets WHERE uuid NOT IN (SELECT DISTINCT asset_uuid FROM tags WHERE " + tagname.sql_lit("tag_key", "Owner") + ")"), "assets with no Owner tag"),
        "eol_rise": (scalar("SELECT COUNT(DISTINCT asset_uuid) FROM vulns WHERE lower(plugin_name) LIKE '%unsupported%' OR lower(plugin_name) LIKE '%end of life%'"), "assets on EOL/unsupported software"),
    }
    for t in TEMPLATES:
        n, label = checks.get(t["id"], (0, ""))
        relevant = t["id"] in ("kev_new", "new_criticals", "ownerless_rise") or n > 0
        out.append({"template": t["id"], "name": t["name"], "severity": t["severity"], "desc": t["desc"],
                    "op": t["op"], "threshold": t["threshold"], "unit": t["unit"],
                    "count": int(n), "count_label": label, "relevant": bool(relevant),
                    "already_added": t["id"] in have_defs})
    out.sort(key=lambda x: (not x["relevant"], x["already_added"], {"critical": 0, "warning": 1, "info": 2}.get(x["severity"], 3)))
    return {"ok": True, "suggestions": out}


_SCHEMA_HINT = ("Tables (navi.db): assets(uuid,hostname,ip_address,operating_system,acr,aes); "
                "vulns(asset_uuid,plugin_id,plugin_name,severity,vpr,xrefs,output,last_found); "
                "tags(asset_uuid,tag_key,tag_value); software(asset_uuid,software_string); "
                "certs(asset_uuid,common_name,subject_name,issuer_name,organization,not_valid_before,not_valid_after,key_length,signature_algorithm); "
                "vuln_route(route_id,app_name,plugin_list,total_vulns,vuln_type); "
                "vuln_paths(path_id,plugin_id,path,asset_uuid,finding_id); plugins(plugin_id,name,cves,severity); cpes(asset_uuid,cpe).")


def _alert_guide(include_output=False):
    """Craft context. Steers the model to navi's PURPOSE-BUILT tables (software, certs, routes,
    paths, plugins) instead of scanning the huge vulns.output blob, and honours the output toggle."""
    out_rule = (" You MAY use a LIKE on vulns.output as a last resort — the operator enabled output search."
                if include_output else
                " The operator did NOT enable plugin-output search, so DO NOT read vulns.output at all — "
                "everything you need is in the purpose-built tables and tags.")
    return (
        "\n\nnavi PRE-PARSES common plugin output into PURPOSE-BUILT tables — query THESE instead of scanning "
        "vulns.output (huge + slow). Prefer, in order:\n"
        "  • installed software / versions → software.software_string  (e.g. 'assets running OpenSSL 1.0')\n"
        "  • certificates → certs.* (common_name, issuer_name, not_valid_after, key_length, signature_algorithm)\n"
        "  • application routes → vuln_route.app_name (route-level, no asset_uuid)\n"
        "  • files / filesystem paths → vuln_paths.path (has asset_uuid)\n"
        "  • a specific plugin firing → vulns.plugin_name / vulns.plugin_id, or plugins.name / plugins.cves\n"
        "  • CISA KEV → vulns.xrefs LIKE '%CISA-KNOWN-EXPLOITED%'\n"
        "  • how the asset is labelled → tags.tag_key (category) + tags.tag_value.\n"
        + out_rule +
        "\n'An asset HAS <term>' = its uuid appears in tags(key/value), software.software_string, vuln_paths.path, "
        "certs(names), or a vuln whose plugin_name/xrefs" + ("/output" if include_output else "") +
        " matches. Join attributes with AND by INTERSECTing the asset_uuid sets so only assets matching ALL count.\n"
        "Examples:\n"
        "  • 'assets that have a MITRE and CISA KEV and EOL and NHI tag' → INTERSECT four tag subselects "
        "(lower(tag_key||' '||tag_value) LIKE '%mitre%', … '%kev%', … '%eol%', … '%nhi%')  ·  op appears\n"
        "  • 'assets running OpenSSL 1.0' → SELECT COUNT(DISTINCT asset_uuid) FROM software WHERE lower(software_string) LIKE '%openssl 1.0%'  ·  op appears\n"
        "  • 'certs signed with SHA-1' → SELECT COUNT(*) FROM certs WHERE lower(signature_algorithm) LIKE '%sha1%'  ·  op appears\n"
        "  • 'assets with a file under /opt/tomcat' → SELECT COUNT(DISTINCT asset_uuid) FROM vuln_paths WHERE lower(path) LIKE '%/opt/tomcat%'  ·  op appears\n"
        "  • 'new CISA KEV exposure' → SELECT COUNT(DISTINCT asset_uuid) FROM vulns WHERE xrefs LIKE '%CISA-KNOWN-EXPLOITED%'  ·  op rise_abs, threshold 1\n"
        "op: 'appears' fires when count>0 (for 'assets that have …'); rise_abs/drop_abs compare to the previous run "
        "(for 'new …'/'rising'/'dropping'); gt/lt for an explicit numeric threshold.")

# shorthand → LIKE fragments the deterministic fallback expands (all lowercase, no % wildcards)
_TERM_SYNONYMS = {
    "kev": ["kev", "known-exploited", "known exploited"],
    "cisa kev": ["kev", "known-exploited", "known exploited"],
    "cisa": ["cisa", "kev", "known-exploited"],
    "eol": ["eol", "end of life", "end-of-life", "unsupported"],
    "end of life": ["end of life", "end-of-life", "eol", "unsupported"],
    "unsupported": ["unsupported", "end of life", "eol"],
    "nhi": ["nhi", "non-human", "machine identity", "service account"],
    "mitre": ["mitre", "att&ck"],
}
_TERM_STOP = ("", "asset", "assets", "host", "hosts", "tag", "tags", "and", "or", "with")


def _like_frag(s):
    """Sanitise a term to a safe LIKE fragment (letters/digits/space/.&/_- only)."""
    return re.sub(r"\s+", " ", re.sub(r"[^a-z0-9 .&/_-]", " ", (s or "").lower())).strip()


def _extract_terms(prompt):
    """Pull the asset-defining terms out of a plain-English 'assets that have X and Y and Z'."""
    p = " " + (prompt or "").lower().strip().replace("'s ", " ") + " "
    for ph in ("alert me on", "alert me when", "alert me if", "alert on", "alert when",
               "warn me when", "warn me on", "warn when", "warn on", "notify me when", "notify me",
               "tell me when", "let me know when", "create an alert for", "alert for", "page me when",
               "assets that have", "assets that carry", "assets that are", "assets with",
               "any asset that has", "any asset with", "hosts that have", "hosts with",
               "that have", "that has", "that carry", "which have", "which has", "whose",
               "plugin output mentions", "plugin output contains", "output mentions", "output contains",
               "plugin output", "plugin name", " output ", " plugin ", " mentions ", " mention ",
               " contains ", " containing ", " named ", " called ", " running ", " software ",
               " signed ", " signed with ", " file ", " files ", " folder ", " directory ", " under ",
               " using ", " certificate ", " certificates ", " cert ", " certs ", " version ",
               " an ", " a ", " the ", " both ", " all of ", " all ", " any ", " is ", " are ",
               " carry ", " have ", " has ", " tagged ", " tag ", " tags ", " asset ", " assets ",
               " host ", " hosts ", " when ", " where "):
        p = p.replace(ph, " ")
    p = p.replace(" as well as ", " and ").replace(" and also ", " and ")
    parts = re.split(r"\band\b|,|&|\bplus\b|\bwith\b", p)
    out, seen = [], set()
    for x in parts:
        t = _like_frag(x)
        if t in _TERM_STOP or len(t) < 2:
            continue
        if t not in seen:
            seen.add(t); out.append(t)
    return out[:6]


def _existing_tables(db_path=None):
    try:
        return {r["name"] for r in db.query("SELECT name FROM sqlite_master WHERE type='table'", path=db_path)}
    except Exception:
        return {"tags", "vulns", "assets"}


def _term_subquery(term, include_output=False, tables=None):
    """asset_uuid set for one term — matched across the PURPOSE-BUILT tables (tags, software,
    vuln_paths, certs) plus plugin identity (name/xrefs). vulns.output is searched only when
    include_output is set. Only unions tables that actually exist in this navi.db."""
    tables = tables if tables is not None else _existing_tables()
    frags = _TERM_SYNONYMS.get(term, [term])
    frags = [f for f in (_like_frag(f) for f in frags) if f] or [_like_frag(term)]
    def like(col):
        return " OR ".join("lower(%s) LIKE '%%%s%%'" % (col, f) for f in frags)
    parts = []
    if "tags" in tables:
        parts.append("SELECT asset_uuid FROM tags WHERE " + like("tag_key||' '||tag_value"))
    if "software" in tables:
        parts.append("SELECT asset_uuid FROM software WHERE " + like("coalesce(software_string,'')"))
    if "vuln_paths" in tables:
        parts.append("SELECT asset_uuid FROM vuln_paths WHERE " + like("coalesce(path,'')"))
    if "certs" in tables:
        parts.append("SELECT asset_uuid FROM certs WHERE " + like("coalesce(common_name,'')||' '||coalesce(issuer_name,'')||' '||coalesce(subject_name,'')||' '||coalesce(signature_algorithm,'')||' '||coalesce(organization,'')"))
    if "vulns" in tables:
        vcol = "coalesce(plugin_name,'')||' '||coalesce(xrefs,'')" + ("||' '||coalesce(output,'')" if include_output else "")
        parts.append("SELECT asset_uuid FROM vulns WHERE " + like(vcol))
    if not parts:                      # nothing to search (shouldn't happen) — empty set
        parts = ["SELECT NULL AS asset_uuid WHERE 0"]
    return " UNION ".join(parts)


def _term_intersection_spec(terms, include_output=False, tables=None):
    tables = tables if tables is not None else _existing_tables()
    subs = ["SELECT asset_uuid FROM (%s)" % _term_subquery(t, include_output, tables) for t in terms]
    inter = " INTERSECT ".join(subs)
    metric_sql = "SELECT COUNT(*) FROM (%s)" % inter
    detail_sql = "SELECT a.hostname AS host, a.ip_address AS ip FROM assets a WHERE a.uuid IN (%s) LIMIT 100" % inter
    label = " + ".join(terms)
    searched = "tags, software, files/paths, certs, plugin name" + (", plugin output" if include_output else "")
    return {"ok": True, "name": ("Assets with " + label)[:80], "severity": "warning",
            "op": "appears", "threshold": 0, "unit": "asset(s)", "source": "sql",
            "metric_sql": metric_sql, "detail_sql": detail_sql, "include_output": include_output,
            "note": "Built from your terms (%s) across navi's purpose-built tables (%s). "
                    "Fires when ≥1 asset matches ALL of them — switch op to rise_abs to fire only on new ones. "
                    "Review the query, then Test before saving." % (label, searched)}


def craft(prompt, db_path=None, include_output=False):
    """Turn plain English into a draft alert: a read-only metric SELECT + an op + threshold
    the user can review before saving. Uses the model when a key is present; otherwise builds
    the query deterministically from navi's purpose-built tables. include_output lets it also
    scan the (large) vulns.output blob — off by default."""
    prompt = (prompt or "").strip()
    if not prompt:
        return {"ok": False, "error": "describe what to alert on"}
    include_output = bool(include_output)
    from core import llm
    if llm.available():
        sys = ("You design a security ALERT over a read-only SQLite database (navi.db, built by Tenable navi). "
               "Return ONLY a JSON object: "
               '{"name":"","severity":"info|warning|critical","metric_sql":"SELECT ...","op":"gt|lt|gte|lte|eq|appears|drop_abs|rise_abs|drop_pct|rise_pct","threshold":<number>,"unit":"","detail_sql":"SELECT ..."}. '
               "metric_sql MUST be ONE read-only SELECT returning a single numeric value (usually a COUNT). "
               "detail_sql is an optional SELECT listing affected assets as (host, ip) with a small LIMIT. "
               "NEVER write, UPDATE, DELETE, or use DDL/PRAGMA. " + _SCHEMA_HINT + _alert_guide(include_output))
        try:
            raw = llm._messages(sys, prompt, max_tokens=800)
            spec = llm._extract_json(raw)
        except Exception as e:
            spec = {"error": str(e)}
        if spec and spec.get("metric_sql") and _read_only(spec.get("metric_sql")):
            spec.setdefault("severity", "warning")
            spec.setdefault("op", "appears")
            spec.setdefault("threshold", 0)
            spec.setdefault("unit", "asset(s)")
            spec["source"] = "sql"
            spec["include_output"] = include_output
            spec["ok"] = True
            # gentle nudge if the model still reached for vulns.output when it wasn't allowed to
            if not include_output and re.search(r"\boutput\b", spec.get("metric_sql", "").lower()):
                spec["note"] = ((spec.get("note") or "") + " Tip: this scans vulns.output — prefer the "
                                "software/certs/vuln_paths tables, or enable 'search plugin output'.").strip()
            return spec
    return _craft_fallback(prompt, include_output, db_path)


def _craft_fallback(prompt, include_output=False, db_path=None):
    """No model key (or the model returned nothing usable) — build the alert deterministically
    from navi's purpose-built tables (+ optionally vulns.output)."""
    terms = _extract_terms(prompt)
    p = prompt.lower()
    wants_tag = ("tag" in p or "tagged" in p)  # explicit 'tag' → search tags/purpose-built tables, not the plugin-only template
    if len(terms) <= 1 and not wants_tag:      # a single classic concept → use the rich seed template
        guess = None
        if "cred" in p or "credential" in p:
            guess = "cred_coverage_drop"
        elif "scan" in p and ("hour" in p or "slow" in p or "long" in p or "time" in p):
            guess = "slow_scans"
        elif ("kev" in p or "exploit" in p) and "and" not in p:
            guess = "kev_new"
        elif "cert" in p or "expir" in p:
            guess = "certs_expiring"
        elif "critical" in p and "and" not in p:
            guess = "new_criticals"
        elif "ownerless" in p or "no owner" in p or "without an owner" in p:
            guess = "ownerless_rise"
        elif ("eol" in p or "end of life" in p or "unsupported" in p) and "and" not in p:
            guess = "eol_rise"
        if guess:
            t = _TPL_BY_ID[guess]
            return {"ok": True, "from_template": guess, "name": t["name"], "severity": t["severity"],
                    "op": t["op"], "threshold": t["threshold"], "unit": t["unit"], "source": t["source"],
                    "builtin": t["builtin"], "metric_sql": t["metric_sql"], "detail_sql": t["detail_sql"],
                    "params": t["params"],
                    "note": "Matched the closest seed template. Set ANTHROPIC_API_KEY for fully free-form alerts."}
    if terms:                                 # one or more asset-defining terms → intersect them
        return _term_intersection_spec(terms, include_output, _existing_tables(db_path))
    return {"ok": False, "error": "Couldn't turn that into an alert. Try naming what defines the asset — a tag "
                                  "category/value, a plugin name, or text in plugin output — e.g. \"assets that "
                                  "have a CISA KEV tag and an EOL tag\"."}


# --------------------------------------------------------------------------- #
#  send a real test email for one alert (confirm delivery works)
# --------------------------------------------------------------------------- #
def send_test(alert, recipient=None, db_path=None):
    """Email one alert's current state RIGHT NOW — regardless of whether it would fire — so the
    operator can confirm delivery works. Changes no state. Gated by NAVI_EMAIL."""
    rcpt = (recipient or default_recipient()).strip()
    if not rcpt:
        return {"ok": False, "reason": "no recipient — set a default alert email (NAVI_ALERT_EMAIL) above, or pass one"}
    ok_r, why = recipient_allowed(rcpt)
    if not ok_r:
        return {"ok": False, "reason": why, "recipient": rcpt}
    if not navi_cli.email_enabled():
        return {"ok": False, "reason": navi_cli.email_gate_reason()
                if hasattr(navi_cli, "email_gate_reason") else "email disabled (set NAVI_EMAIL=1)"}
    st = _load_state()
    base = st["snap"].get(alert.get("id")) if alert.get("id") else None
    res = evaluate_one(alert, db_path, baseline=base)
    subject = "🚨 [Hounds] TEST — Alert Raven: %s" % (alert.get("name") or "alert")
    body = ["This is a TEST email from Alert Raven, sent on demand to confirm delivery.",
            "If it reached this inbox, real digests will too when a condition fires.", "",
            _one_block(res), "",
            "— The Hounds · Alert Raven. Manual test — no alert state was changed."]
    try:
        r = navi_cli.mail(to=rcpt, subject=subject, message="\n".join(body), agent="alert")
        return {"ok": bool(r.get("ok")), "recipient": rcpt, "would_fire": res.get("fired"),
                "reason": r.get("message") or r.get("error")}
    except Exception as e:
        return {"ok": False, "reason": str(e), "recipient": rcpt}
