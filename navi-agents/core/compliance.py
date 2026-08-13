"""Compliance engine — the shared brain behind Minos (the Compliance Overview) and
Tiresias (the Compliance Asset deep-dive).

Read-only over navi.db (core.db). Works the `compliance` table (one row per audit
check result per asset) and joins to `vulns` for the audit↔vuln correlation.

navi schema quirks this module hides from the pages:
  • compliance.reference is a STRINGIFIED PYTHON LIST of {framework,control} dicts —
    "[{'framework':'800-53','control':'CM-7'}, …]" — parsed here with ast.literal_eval.
  • the audit CHECK identity is (check_id, check_name), NOT plugin_id (every compliance
    row shares one plugin_id). check_name starts with its control number ("2.6 …").
  • status ∈ {PASSED, FAILED, WARNING, UNKNOWN}. Compliance carries NO CVEs, so the
    audit↔vuln link is INFERRED by topic (keyword) overlap on the same asset.
"""
import ast

from core import db

STATUSES = ("passed", "failed", "warning", "unknown")
TAG_OWNER_CATEGORY = "Audit Owner"
TAG_LINK_CATEGORY = "Audit-Vuln Link"

# tag every asset carrying an audit result on the compliance table's asset_uuid — the
# same Tenable asset id VM/WAS use.
_SEV_ORDER = ("critical", "high", "medium", "low", "info")
_SEV_NUM = {"4": "critical", "3": "high", "2": "medium", "1": "low", "0": "info"}


def _norm_status(s):
    s = (s or "").strip().lower()
    if s.startswith("pass"):
        return "passed"
    if s.startswith("fail"):
        return "failed"
    if s.startswith("warn"):
        return "warning"
    return "unknown"


def _norm_sev(v):
    if v is None:
        return "info"
    s = str(v).strip().lower()
    if s in _SEV_ORDER:
        return s
    if s in _SEV_NUM:
        return _SEV_NUM[s]
    return {"informational": "info"}.get(s, "info")


def _sev_rank(v):
    n = _norm_sev(v)
    return _SEV_ORDER.index(n) if n in _SEV_ORDER else 9


def _table_exists(name, path=None):
    try:
        return bool(db.scalar("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
                              (name,), path=path, budget=0))
    except Exception:
        return False


def _cols(table, path=None):
    try:
        return {r["name"] for r in db.query('PRAGMA table_info("%s");' % table, path=path)}
    except Exception:
        return set()


def parse_reference(s):
    """'[{'framework':'800-53','control':'CM-7'}, …]' -> [{framework,control}] (trimmed).
    navi stores leading spaces on some frameworks (' 800-53') — normalise them."""
    if not s or not str(s).strip():
        return []
    try:
        v = ast.literal_eval(str(s))
    except (ValueError, SyntaxError):
        return []
    out = []
    if isinstance(v, (list, tuple)):
        for d in v:
            if isinstance(d, dict):
                fw = str(d.get("framework", "")).strip()
                ct = str(d.get("control", "")).strip()
                if fw:
                    out.append({"framework": fw, "control": ct})
    return out


def status(path=None):
    exists = _table_exists("compliance", path)
    rows = assets = checks = 0
    if exists:
        try:
            rows = int(db.scalar("SELECT count(*) FROM compliance", path=path, budget=0) or 0)
        except Exception:
            rows = 0
        try:
            assets = int(db.scalar("SELECT count(DISTINCT asset_uuid) FROM compliance",
                                   path=path, budget=0) or 0)
        except Exception:
            assets = 0
        try:
            checks = int(db.scalar("SELECT count(DISTINCT check_id) FROM compliance",
                                   path=path, budget=0) or 0)
        except Exception:
            checks = 0
    return {"exists": exists, "rows": rows, "assets": assets, "checks": checks,
            "ready": bool(exists and rows > 0)}


def _identities(path=None, uuids=None):
    """asset_uuid -> {hostname, ip} for the given uuids, from `assets` then `vulns`."""
    us = [u for u in (uuids or []) if u]
    if not us:
        return {}
    ph = ",".join("?" * len(us))
    ids = {}
    if _table_exists("assets", path):
        ac = _cols("assets", path)
        if "uuid" in ac:
            sel = ["uuid"] + [c for c in ("hostname", "ip_address") if c in ac]
            try:
                for r in db.query("SELECT %s FROM assets WHERE uuid IN (%s)" % (",".join(sel), ph),
                                  tuple(us), path=path):
                    ids[r["uuid"]] = {"hostname": r.get("hostname") or "", "ip": r.get("ip_address") or ""}
            except Exception:
                pass
    miss = [u for u in us if u not in ids or not ids[u].get("hostname")]
    if miss and _table_exists("vulns", path):
        vc = _cols("vulns", path)
        if "asset_uuid" in vc:
            hv = "asset_hostname" if "asset_hostname" in vc else None
            iv = "asset_ip" if "asset_ip" in vc else None
            sel = ["asset_uuid"] + [c for c in (hv, iv) if c]
            mph = ",".join("?" * len(miss))
            try:
                for r in db.query("SELECT DISTINCT %s FROM vulns WHERE asset_uuid IN (%s)"
                                  % (",".join(sel), mph), tuple(miss), path=path):
                    u = r["asset_uuid"]
                    cur = ids.get(u, {"hostname": "", "ip": ""})
                    if not cur.get("hostname") and hv:
                        cur["hostname"] = r.get(hv) or ""
                    if not cur.get("ip") and iv:
                        cur["ip"] = r.get(iv) or ""
                    ids[u] = cur
            except Exception:
                pass
    return ids


# --------------------------------------------------------------------------- #
#  Dashboard 1 — Minos: consolidated compliance overview
# --------------------------------------------------------------------------- #
_CTRL_AGG = (
    "SELECT check_id, MAX(check_name) AS check_name, MAX(audit_file) AS audit_file, "
    " COUNT(*) AS total, "
    " SUM(CASE WHEN upper(status) LIKE 'FAIL%' THEN 1 ELSE 0 END) AS failed, "
    " SUM(CASE WHEN upper(status) LIKE 'PASS%' THEN 1 ELSE 0 END) AS passed, "
    " SUM(CASE WHEN upper(status) LIKE 'WARN%' THEN 1 ELSE 0 END) AS warning, "
    " COUNT(DISTINCT asset_uuid) AS assets "
    "FROM compliance GROUP BY check_id")


def overview(path=None):
    st = status(path)
    if not st["ready"]:
        return {"available": False,
                "reason": "no compliance data in navi.db — run navi config update compliance"}
    srows = db.query("SELECT status, COUNT(*) AS n FROM compliance GROUP BY status", path=path)
    by_status = {s: 0 for s in STATUSES}
    for r in srows:
        by_status[_norm_status(r["status"])] += int(r["n"] or 0)
    total = sum(by_status.values())
    passed, failed, warning = by_status["passed"], by_status["failed"], by_status["warning"]

    controls = [dict(c) for c in db.query(_CTRL_AGG + " ORDER BY failed DESC, warning DESC, passed DESC",
                                          path=path)]
    top_failing = [c for c in controls if int(c["failed"] or 0) > 0][:30]
    failed_controls = sum(1 for c in controls if int(c["failed"] or 0) > 0)

    # framework rollup — parse reference on FAILED rows, count control-instances per framework
    fw = {}
    for r in db.query("SELECT reference FROM compliance WHERE upper(status) LIKE 'FAIL%'", path=path):
        for ref in parse_reference(r.get("reference")):
            fw[ref["framework"]] = fw.get(ref["framework"], 0) + 1
    frameworks = sorted(({"framework": k, "failed": v} for k, v in fw.items()),
                        key=lambda x: (-x["failed"], x["framework"]))[:20]

    audit_files = [dict(r) for r in db.query(
        "SELECT audit_file, COUNT(DISTINCT check_id) AS checks, COUNT(DISTINCT asset_uuid) AS assets, "
        " SUM(CASE WHEN upper(status) LIKE 'FAIL%' THEN 1 ELSE 0 END) AS failed, "
        " SUM(CASE WHEN upper(status) LIKE 'PASS%' THEN 1 ELSE 0 END) AS passed "
        "FROM compliance GROUP BY audit_file ORDER BY failed DESC", path=path)]

    arows = [dict(r) for r in db.query(
        "SELECT asset_uuid, COUNT(*) AS total, "
        " SUM(CASE WHEN upper(status) LIKE 'FAIL%' THEN 1 ELSE 0 END) AS failed, "
        " SUM(CASE WHEN upper(status) LIKE 'PASS%' THEN 1 ELSE 0 END) AS passed, "
        " SUM(CASE WHEN upper(status) LIKE 'WARN%' THEN 1 ELSE 0 END) AS warning "
        "FROM compliance GROUP BY asset_uuid ORDER BY failed DESC, warning DESC", path=path)]
    idents = _identities(path, [a["asset_uuid"] for a in arows])
    for a in arows:
        idn = idents.get(a["asset_uuid"], {})
        a["hostname"], a["ip"] = idn.get("hostname") or "", idn.get("ip") or ""
        p, f = int(a["passed"] or 0), int(a["failed"] or 0)
        a["pass_pct"] = round(100.0 * p / (p + f), 1) if (p + f) else None

    return {"available": True, "assets": st["assets"], "checks": st["checks"], "results": total,
            "by_status": by_status, "passed": passed, "failed": failed, "warning": warning,
            "pass_pct": round(100.0 * passed / (passed + failed), 1) if (passed + failed) else None,
            "failed_controls": failed_controls, "top_failing": top_failing,
            "frameworks": frameworks, "audit_files": audit_files, "assets_rows": arows}


def assets_list(path=None):
    """Compliance assets, worst-first, for the deep-dive selector."""
    st = status(path)
    if not st["ready"]:
        return []
    rows = db.query(
        "SELECT asset_uuid, COUNT(*) AS total, "
        " SUM(CASE WHEN upper(status) LIKE 'FAIL%' THEN 1 ELSE 0 END) AS failed, "
        " SUM(CASE WHEN upper(status) LIKE 'WARN%' THEN 1 ELSE 0 END) AS warning "
        "FROM compliance GROUP BY asset_uuid ORDER BY failed DESC, warning DESC", path=path)
    idents = _identities(path, [r["asset_uuid"] for r in rows])
    out = []
    for r in rows:
        idn = idents.get(r["asset_uuid"], {})
        out.append({"asset_uuid": r["asset_uuid"], "hostname": idn.get("hostname") or "",
                    "ip": idn.get("ip") or "", "failed": int(r["failed"] or 0),
                    "warning": int(r["warning"] or 0), "total": int(r["total"] or 0)})
    return out


# --------------------------------------------------------------------------- #
#  Dashboard 2 — Tiresias: per-asset deep-dive + audit↔vuln correlation
# --------------------------------------------------------------------------- #
# Topic map for the inference: (label, icon, check-side keywords, vuln-side keywords).
# A failed/warning check and a vuln on the SAME asset that both hit a topic are linked.
_TOPICS = [
    ("TLS / SSL", "🔐", ["tls", "ssl", "cipher", "https"], ["ssl", "tls", "cipher"]),
    ("Certificates", "📜", ["certificate", "tlscacert", "tlscert", "tlskey", "ca cert", "x509", "x.509"],
     ["certificate", "ssl cert", "x.509", "x509"]),
    ("Docker / Containers", "🐳", ["docker", "container", "registry", "daemon", "containerd"],
     ["docker", "container"]),
    ("SSH", "🔑", ["ssh"], ["ssh", "openssh"]),
    ("Authentication / Passwords", "👤",
     ["password", "pam", "login", "credential", " auth "],
     ["password", "default account", "default credential", "credential", "authentication bypass"]),
    ("Firewall / Network", "🧱", ["firewall", "iptables", "netfilter", "ufw", "port"], ["firewall"]),
    ("Logging / Audit", "📝", ["audit", "logging", "syslog", "rsyslog", "auditd"], ["logging", "syslog"]),
    ("Filesystem / Permissions", "📁",
     ["permission", "ownership", "read only", "read-only", "mount", "world-writable", "umask", "sticky"],
     ["permission", "world-writable", "writable"]),
    ("Kernel / Sysctl", "⚙️", ["kernel", "sysctl", "aslr", "randomize"], ["kernel"]),
    ("Time / NTP", "⏱️", ["ntp", "chrony", "time synchron"], ["ntp", "time"]),
]


def _hit(text, kws):
    t = (text or "").lower()
    return any(k in t for k in kws)


def _asset_vulns(path, asset_uuid, cap=2000):
    if not _table_exists("vulns", path):
        return []
    vc = _cols("vulns", path)
    if "asset_uuid" not in vc or "plugin_name" not in vc:
        return []
    want = [c for c in ("plugin_id", "plugin_name", "plugin_family", "severity", "cves",
                        "synopsis", "state", "score") if c in vc]
    try:
        rows = db.query("SELECT %s FROM vulns WHERE asset_uuid=? LIMIT %d" % (",".join(want), cap),
                        (asset_uuid,), path=path)
    except Exception:
        return []
    return [dict(r) for r in rows]


def _correlate(checks, vulns):
    """Infer audit↔vuln links on one asset by topic overlap. A topic surfaces only when
    BOTH a failed/warning check AND a vuln on the asset match it — that's the connection."""
    out = []
    open_checks = [c for c in checks if c["status"] in ("failed", "warning")]
    for label, icon, ckw, vkw in _TOPICS:
        tchecks = [c for c in open_checks
                   if _hit(c["check_name"], ckw) or _hit(c.get("solution"), ckw)]
        if not tchecks:
            continue
        seen, tvulns = set(), []
        for v in vulns:
            if _hit(v.get("plugin_name"), vkw) or _hit(v.get("plugin_family"), vkw) or _hit(v.get("synopsis"), vkw):
                pid = str(v.get("plugin_id") or v.get("plugin_name") or "")
                if pid not in seen:
                    seen.add(pid)
                    tvulns.append(v)
        if not tvulns:
            continue
        tvulns.sort(key=lambda v: _sev_rank(v.get("severity")))
        out.append({
            "topic": label, "icon": icon,
            "key": label.lower().replace(" / ", "-").replace(" ", "-").replace("/", ""),
            "check_count": len(tchecks), "vuln_count": len(tvulns),
            "checks": [{"check_name": c["check_name"], "status": c["status"]} for c in tchecks[:12]],
            "vulns": [{"plugin_id": v.get("plugin_id"), "plugin_name": v.get("plugin_name"),
                       "severity": _norm_sev(v.get("severity")), "family": v.get("plugin_family")}
                      for v in tvulns[:15]],
        })
    out.sort(key=lambda x: (-x["vuln_count"], -x["check_count"]))
    return out


def asset_detail(path=None, asset_uuid=None):
    st = status(path)
    if not st["ready"]:
        return {"available": False, "reason": "no compliance data in navi.db"}
    asset_uuid = (asset_uuid or "").strip()
    if not asset_uuid:
        al = assets_list(path)
        if not al:
            return {"available": False, "reason": "no compliance assets"}
        asset_uuid = al[0]["asset_uuid"]
    idn = _identities(path, [asset_uuid]).get(asset_uuid, {})
    # Select only columns this compliance table actually has (schema varies by navi
    # version / export) so a missing see_also / actual_value never crashes the query.
    cc = _cols("compliance", path)

    def _pick(*names):
        for n in names:
            if n in cc:
                return n
        return None

    fmap = {"check_id": _pick("check_id"), "check_name": _pick("check_name"),
            "audit_file": _pick("audit_file"), "status": _pick("status"),
            "reference": _pick("reference"), "see_also": _pick("see_also"),
            "solution": _pick("solution"), "actual": _pick("actual_value", "actual"),
            "expected": _pick("expected_value", "expected"), "info": _pick("check_info", "info")}
    sel = ", ".join("%s AS %s" % (v, k) for k, v in fmap.items() if v) or "check_id AS check_id"
    scol = fmap["status"] or "status"
    order = (" ORDER BY CASE WHEN upper(" + scol + ") LIKE 'FAIL%' THEN 0"
             " WHEN upper(" + scol + ") LIKE 'WARN%' THEN 1"
             " WHEN upper(" + scol + ") LIKE 'PASS%' THEN 2 ELSE 3 END")
    rows = db.query("SELECT " + sel + " FROM compliance WHERE asset_uuid=?" + order, (asset_uuid,), path=path)
    checks, by_status = [], {s: 0 for s in STATUSES}
    for r in rows:
        s = _norm_status(r.get("status"))
        by_status[s] = by_status.get(s, 0) + 1
        checks.append({"check_id": r.get("check_id"), "check_name": r.get("check_name") or "",
                       "audit_file": r.get("audit_file") or "", "status": s,
                       "frameworks": parse_reference(r.get("reference")),
                       "see_also": r.get("see_also") or "", "solution": (r.get("solution") or "").strip(),
                       "actual": (r.get("actual") or "").strip(),
                       "expected": (r.get("expected") or "").strip(),
                       "info": (r.get("info") or "").strip()})
    vulns = _asset_vulns(path, asset_uuid)
    sev = {s: 0 for s in _SEV_ORDER}
    for v in vulns:
        sev[_norm_sev(v.get("severity"))] += 1
    corr = _correlate(checks, vulns)
    p, f = by_status["passed"], by_status["failed"]
    return {"available": True,
            "asset": {"uuid": asset_uuid, "hostname": idn.get("hostname") or "", "ip": idn.get("ip") or ""},
            "by_status": by_status, "total": len(checks),
            "pass_pct": round(100.0 * p / (p + f), 1) if (p + f) else None,
            "checks": checks[:600], "checks_count": len(checks),
            "vulns_total": len(vulns), "vuln_severity": sev, "correlations": corr}


# --------------------------------------------------------------------------- #
#  Tagging support (cohorts only; the gated write is core.navi_cli from the api)
# --------------------------------------------------------------------------- #
def control_targets(path=None, check_id=None, failed_only=True):
    """asset_uuids that FAIL (default) a given control — the assets an Audit Owner owns."""
    cid = (check_id or "").strip()
    if not cid:
        return None
    cond = "check_id=?"
    if failed_only:
        cond += " AND upper(status) LIKE 'FAIL%'"
    rows = db.query("SELECT DISTINCT asset_uuid FROM compliance WHERE " + cond, (cid,), path=path)
    uuids = [r["asset_uuid"] for r in rows if r.get("asset_uuid")]
    name = db.scalar("SELECT check_name FROM compliance WHERE check_id=? LIMIT 1", (cid,), path=path) or ""
    return {"check_id": cid, "check_name": name, "uuids": uuids}


def correlation_targets(path=None, asset_uuid=None):
    """The single asset behind a deep-dive correlation tag (Audit-Vuln Link)."""
    au = (asset_uuid or "").strip()
    if not au:
        return None
    row = db.query("SELECT DISTINCT asset_uuid FROM compliance WHERE asset_uuid=?", (au,), path=path)
    return {"uuids": [r["asset_uuid"] for r in row if r.get("asset_uuid")]}


# --------------------------------------------------------------------------- #
#  Framework-scoped adherence — the Compliance Dashboard drives these         #
# --------------------------------------------------------------------------- #
def frameworks_list(path=None):
    """Distinct frameworks across all findings (parsed from `reference`), each with
    pass/fail/warning + control/asset counts — populates the dashboard dropdown."""
    if not _table_exists("compliance", path):
        return {"available": False, "reason": "no compliance data in navi.db — run navi config update compliance"}
    fw = {}
    try:
        rows = db.query("SELECT asset_uuid, status, reference FROM compliance", path=path)
    except Exception:
        rows = []
    for r in rows:
        st = _norm_status(r.get("status"))
        seen = set()
        for ref in parse_reference(r.get("reference")):
            f = ref.get("framework", "").strip()
            if not f or f in seen:
                continue
            seen.add(f)
            e = fw.setdefault(f, {"framework": f, "results": 0, "passed": 0, "failed": 0,
                                  "warning": 0, "controls": set(), "assets": set()})
            e["results"] += 1
            if st in ("passed", "failed", "warning"):
                e[st] += 1
            if ref.get("control"):
                e["controls"].add(ref["control"])
            if r.get("asset_uuid"):
                e["assets"].add(r["asset_uuid"])
    out = []
    for f, e in fw.items():
        pf = e["passed"] + e["failed"]
        out.append({"framework": f, "results": e["results"], "passed": e["passed"],
                    "failed": e["failed"], "warning": e["warning"], "controls": len(e["controls"]),
                    "assets": len(e["assets"]),
                    "pass_pct": round(100.0 * e["passed"] / pf, 1) if pf else None})
    out.sort(key=lambda x: (-x["failed"], -x["results"], x["framework"]))
    return {"available": True, "frameworks": out}


def framework_view(framework, path=None):
    """Adherence for ONE framework: control (check) pass/fail/warn, per-asset pass %,
    coverage and the top failing controls — using every finding whose `reference`
    maps to that framework."""
    if not framework or not str(framework).strip():
        return {"available": False, "reason": "framework required"}
    if not _table_exists("compliance", path):
        return {"available": False, "reason": "no compliance data in navi.db"}
    fwl = str(framework).strip().lower()
    by_status = {"passed": 0, "failed": 0, "warning": 0}
    per_asset, audit, checks = {}, {}, {}
    try:
        rows = db.query("SELECT asset_uuid, check_id, check_name, status, reference, "
                        "audit_file, solution FROM compliance", path=path)
    except Exception:
        rows = []
    for r in rows:
        refs = [x for x in parse_reference(r.get("reference"))
                if x.get("framework", "").strip().lower() == fwl]
        if not refs:
            continue
        st = _norm_status(r.get("status"))
        if st in by_status:
            by_status[st] += 1
        u = r.get("asset_uuid")
        pa = per_asset.setdefault(u, {"passed": 0, "failed": 0, "warning": 0})
        if st in pa:
            pa[st] += 1
        af = r.get("audit_file") or ""
        aa = audit.setdefault(af, {"audit_file": af, "passed": 0, "failed": 0, "warning": 0})
        if st in aa:
            aa[st] += 1
        cid = r.get("check_id")
        ca = checks.setdefault(cid, {"check_id": cid, "check_name": r.get("check_name") or cid,
                                     "controls": set(), "passed": 0, "failed": 0, "warning": 0,
                                     "assets": set(), "audit_file": af, "solution": r.get("solution") or ""})
        if st in ca:
            ca[st] += 1
        if u:
            ca["assets"].add(u)
        for x in refs:
            if x.get("control"):
                ca["controls"].add(x["control"])

    idents = _identities(path, list(per_asset.keys()))
    assets = []
    for u, pa in per_asset.items():
        pf = pa["passed"] + pa["failed"]
        idn = idents.get(u, {})
        assets.append({"asset_uuid": u, "hostname": idn.get("hostname") or "", "ip": idn.get("ip") or "",
                       "passed": pa["passed"], "failed": pa["failed"], "warning": pa["warning"],
                       "pass_pct": round(100.0 * pa["passed"] / pf, 1) if pf else None})
    assets.sort(key=lambda a: (-(a["failed"]), -(a["warning"])))

    clist = []
    for cid, ca in checks.items():
        pf = ca["passed"] + ca["failed"]
        clist.append({"check_id": cid, "check_name": ca["check_name"], "controls": sorted(ca["controls"])[:8],
                      "passed": ca["passed"], "failed": ca["failed"], "warning": ca["warning"],
                      "assets": len(ca["assets"]), "audit_file": ca["audit_file"], "solution": ca["solution"],
                      "pass_pct": round(100.0 * ca["passed"] / pf, 1) if pf else None})
    clist.sort(key=lambda c: (-(c["failed"]), -(c["warning"]), c["check_name"]))

    total = sum(by_status.values())
    pf = by_status["passed"] + by_status["failed"]
    return {"available": True, "framework": framework, "results": total, "by_status": by_status,
            "passed": by_status["passed"], "failed": by_status["failed"], "warning": by_status["warning"],
            "pass_pct": round(100.0 * by_status["passed"] / pf, 1) if pf else None,
            "controls": len(checks), "failing_controls": sum(1 for c in clist if c["failed"] > 0),
            "assets": len(per_asset), "top_failing": clist[:40], "assets_rows": assets[:300],
            "audit_files": sorted(audit.values(), key=lambda x: -x["failed"])}


# --------------------------------------------------------------------------- #
#  Tiresias — the AUDIT-FILE lens: the same estate through the audit file, not
#  the asset. Aggregate leaderboard + estate-wide audit↔vuln correlation, and a
#  per-file deep-dive (checks rollup, assets rollup, file-scoped correlation).
# --------------------------------------------------------------------------- #
_FAIL = "SUM(CASE WHEN upper(status) LIKE 'FAIL%' THEN 1 ELSE 0 END)"
_PASS = "SUM(CASE WHEN upper(status) LIKE 'PASS%' THEN 1 ELSE 0 END)"
_WARN = "SUM(CASE WHEN upper(status) LIKE 'WARN%' THEN 1 ELSE 0 END)"


def _pp(passed, failed):
    pf = (passed or 0) + (failed or 0)
    return round(100.0 * (passed or 0) / pf, 1) if pf else None


def _vulns_for_assets(path, uuids, cap=20000):
    """Vulns for a set of assets (chunked IN to dodge SQLite's ~999 param limit)."""
    if not uuids or not _table_exists("vulns", path):
        return []
    vc = _cols("vulns", path)
    if "asset_uuid" not in vc:
        return []
    want = [c for c in ("asset_uuid", "plugin_id", "plugin_name", "plugin_family",
                        "severity", "synopsis", "score", "cves") if c in vc]
    out, uu = [], list(uuids)
    for i in range(0, len(uu), 900):
        chunk = uu[i:i + 900]
        ph = ",".join("?" * len(chunk))
        try:
            rows = db.query("SELECT %s FROM vulns WHERE asset_uuid IN (%s) LIMIT %d"
                            % (",".join(want), ph, cap), tuple(chunk), path=path)
        except Exception:
            rows = []
        out.extend(dict(r) for r in rows)
        if len(out) >= cap:
            break
    return out


def _correlate_aggregate(path=None, audit_file=None):
    """Audit↔vuln correlation rolled up across assets (estate-wide, or scoped to one
    audit file). A topic surfaces where a FAILED/warning check and a matching vuln land
    on the SAME asset — the asset is the relationship. Returns topics with distinct
    checks, distinct vulns, and the count/sample of assets where they co-occur."""
    where = "(upper(status) LIKE 'FAIL%' OR upper(status) LIKE 'WARN%')"
    params = []
    if audit_file:
        where += " AND audit_file=?"
        params.append(audit_file)
    try:
        checks = db.query("SELECT asset_uuid, check_name, status, solution FROM compliance WHERE "
                          + where, tuple(params), path=path)
    except Exception:
        checks = []
    check_assets = {c["asset_uuid"] for c in checks if c.get("asset_uuid")}
    if not check_assets:
        return []
    vulns = _vulns_for_assets(path, check_assets)
    vby = {}
    for v in vulns:
        vby.setdefault(v.get("asset_uuid"), []).append(v)
    out = []
    for label, icon, ckw, vkw in _TOPICS:
        tchecks = [c for c in checks if _hit(c.get("check_name"), ckw) or _hit(c.get("solution"), ckw)]
        if not tchecks:
            continue
        tassets = {c["asset_uuid"] for c in tchecks if c.get("asset_uuid")}
        linked, tvulns = set(), {}
        for au in tassets:
            for v in vby.get(au, []):
                if _hit(v.get("plugin_name"), vkw) or _hit(v.get("plugin_family"), vkw) or _hit(v.get("synopsis"), vkw):
                    linked.add(au)
                    pid = str(v.get("plugin_id") or v.get("plugin_name") or "")
                    tvulns.setdefault(pid, v)
        if not linked:
            continue
        dchecks = {}
        for c in tchecks:
            dchecks.setdefault(c.get("check_name") or "", c)
        vlist = sorted(tvulns.values(), key=lambda v: _sev_rank(v.get("severity")))
        idents = _identities(path, list(linked)[:12])
        out.append({
            "topic": label, "icon": icon,
            "key": label.lower().replace(" / ", "-").replace(" ", "-").replace("/", ""),
            "check_count": len(dchecks), "vuln_count": len(tvulns), "asset_count": len(linked),
            "checks": [{"check_name": k, "status": v["status"]} for k, v in list(dchecks.items())[:10]],
            "vulns": [{"plugin_id": v.get("plugin_id"), "plugin_name": v.get("plugin_name"),
                       "severity": _norm_sev(v.get("severity")), "family": v.get("plugin_family")}
                      for v in vlist[:15]],
            "assets": [{"asset_uuid": u, "hostname": idents.get(u, {}).get("hostname") or "",
                        "ip": idents.get(u, {}).get("ip") or ""} for u in list(linked)[:10]],
        })
    out.sort(key=lambda x: (-x["asset_count"], -x["vuln_count"], -x["check_count"]))
    return out


def audit_files_list(path=None):
    """Worst-first list of audit files, for the lens picker + leaderboard."""
    if not _table_exists("compliance", path):
        return []
    rows = db.query(
        "SELECT audit_file, COUNT(DISTINCT check_id) AS checks, COUNT(DISTINCT asset_uuid) AS assets, "
        " COUNT(*) AS results, %s AS failed, %s AS passed, %s AS warning "
        "FROM compliance GROUP BY audit_file ORDER BY failed DESC, warning DESC" % (_FAIL, _PASS, _WARN),
        path=path)
    # per-file framework rollup from failing rows
    fw = {}
    for r in db.query("SELECT audit_file, reference FROM compliance WHERE upper(status) LIKE 'FAIL%'", path=path):
        af = r.get("audit_file") or ""
        for ref in parse_reference(r.get("reference")):
            fw.setdefault(af, {}).setdefault(ref["framework"], 0)
            fw[af][ref["framework"]] += 1
    out = []
    for r in rows:
        af = r.get("audit_file") or ""
        frs = sorted(fw.get(af, {}).items(), key=lambda x: -x[1])
        out.append({"audit_file": af, "checks": int(r["checks"] or 0), "assets": int(r["assets"] or 0),
                    "results": int(r["results"] or 0), "failed": int(r["failed"] or 0),
                    "passed": int(r["passed"] or 0), "warning": int(r["warning"] or 0),
                    "pass_pct": _pp(r["passed"], r["failed"]),
                    "frameworks": [f for f, _ in frs[:6]]})
    return out


def audit_overview(path=None):
    """The audit-file lens aggregate: leaderboard of files + estate-wide correlation."""
    st = status(path)
    if not st["ready"]:
        return {"available": False, "reason": "no compliance data in navi.db — run navi config update compliance"}
    files = audit_files_list(path)
    corr = _correlate_aggregate(path, None)
    return {"available": True, "files": files, "correlations": corr,
            "totals": {"files": len(files), "assets": st.get("assets"), "checks": st.get("checks"),
                       "topics": len(corr)}}


def audit_detail(audit_file, path=None):
    """One audit file, all its assets: adherence, checks rollup, assets rollup, and the
    file-scoped audit↔vuln correlation."""
    if not _table_exists("compliance", path):
        return {"available": False, "reason": "no compliance data in navi.db"}
    af = (audit_file or "").strip()
    if not af:
        fl = audit_files_list(path)
        if not fl:
            return {"available": False, "reason": "no audit files"}
        af = fl[0]["audit_file"]
    # aggregate status
    srow = db.query("SELECT %s AS failed, %s AS passed, %s AS warning, COUNT(*) AS results, "
                    "COUNT(DISTINCT check_id) AS checks, COUNT(DISTINCT asset_uuid) AS assets "
                    "FROM compliance WHERE audit_file=?" % (_FAIL, _PASS, _WARN), (af,), path=path)
    agg = dict(srow[0]) if srow else {}
    # checks rollup (per check_id)
    crows = db.query(
        "SELECT check_id, MAX(check_name) AS check_name, MAX(reference) AS reference, MAX(solution) AS solution, "
        " %s AS failed, %s AS passed, %s AS warning, COUNT(DISTINCT asset_uuid) AS assets "
        "FROM compliance WHERE audit_file=? GROUP BY check_id ORDER BY failed DESC, warning DESC" % (_FAIL, _PASS, _WARN),
        (af,), path=path)
    checks = []
    for r in crows:
        checks.append({"check_id": r["check_id"], "check_name": r.get("check_name") or r["check_id"],
                       "frameworks": parse_reference(r.get("reference")),
                       "solution": (r.get("solution") or "").strip(),
                       "passed": int(r["passed"] or 0), "failed": int(r["failed"] or 0),
                       "warning": int(r["warning"] or 0), "assets": int(r["assets"] or 0),
                       "pass_pct": _pp(r["passed"], r["failed"])})
    # assets rollup (assets that ran this file)
    arows = db.query(
        "SELECT asset_uuid, %s AS failed, %s AS passed, %s AS warning, COUNT(*) AS total "
        "FROM compliance WHERE audit_file=? GROUP BY asset_uuid ORDER BY failed DESC, warning DESC" % (_FAIL, _PASS, _WARN),
        (af,), path=path)
    idents = _identities(path, [r["asset_uuid"] for r in arows])
    assets = []
    for r in arows:
        idn = idents.get(r["asset_uuid"], {})
        assets.append({"asset_uuid": r["asset_uuid"], "hostname": idn.get("hostname") or "",
                       "ip": idn.get("ip") or "", "passed": int(r["passed"] or 0),
                       "failed": int(r["failed"] or 0), "warning": int(r["warning"] or 0),
                       "total": int(r["total"] or 0), "pass_pct": _pp(r["passed"], r["failed"])})
    # framework rollup for the file header
    fw = {}
    for r in db.query("SELECT reference FROM compliance WHERE audit_file=? AND upper(status) LIKE 'FAIL%'",
                      (af,), path=path):
        for ref in parse_reference(r.get("reference")):
            fw[ref["framework"]] = fw.get(ref["framework"], 0) + 1
    corr = _correlate_aggregate(path, af)
    return {"available": True, "audit_file": af,
            "failed": int(agg.get("failed") or 0), "passed": int(agg.get("passed") or 0),
            "warning": int(agg.get("warning") or 0), "results": int(agg.get("results") or 0),
            "checks_count": int(agg.get("checks") or 0), "assets_count": int(agg.get("assets") or 0),
            "pass_pct": _pp(agg.get("passed"), agg.get("failed")),
            "frameworks": sorted(({"framework": k, "failed": v} for k, v in fw.items()),
                                 key=lambda x: -x["failed"])[:10],
            "checks": checks[:400], "assets": assets[:300], "correlations": corr}
