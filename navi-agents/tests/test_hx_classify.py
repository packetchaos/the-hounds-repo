"""Regression tests — Phase 1 summary-table rewrites of the CLASSIFICATION & OWNERSHIP group
(build 456): classify (KEV / critical / unsupported-OS sets, plugin-name device signals),
identity (KEV / critical host sets, default-cred / AD sweeps, enumerator discovery), IoT
(plugin_carries_term batched per plugin, device_exposure, detection discovery), asset_ownership
(_vuln_risk), fused_score (per-asset vulns rollup, EPSS) and signals (plugin explorers).

For every rewritten function, on a synthetic navi.db whose plugin attributes are consistent per
plugin (like Tenable data) and WITH ⚡ Optimize's hx_plugin / hx_asset built:
  · the fast path returns the same result as HOUNDS_NO_SUMMARY=1 (today's SQL);
  · the fast path is really taken (statements traced: hx_* read, no plugin_name / xrefs LIKE and
    no GROUP BY asset_uuid over the vulns table);
  · stale summaries (one vulns row inserted after the build) fall back to the plain SQL.
No Tenable, no navi. Run: python3 tests/test_hx_classify.py"""
import atexit
import json
import os
import random
import re
import shutil
import sqlite3
import sys
import tempfile
import faulthandler; faulthandler.dump_traceback_later(300, exit=True)   # a hang fails loudly

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
TMP = tempfile.mkdtemp(prefix="hounds-hxc-")
atexit.register(shutil.rmtree, TMP, ignore_errors=True)
DB = os.path.join(TMP, "navi.db")
os.environ.update({"NAVI_CACHE_DIR": os.path.join(TMP, "cache"), "HOUNDS_CONFIG": os.path.join(TMP, "cfg.json"),
                   "NAVI_TAGLOG_DB": os.path.join(TMP, "taglog.db"), "NAVI_HISTORY_DIR": os.path.join(TMP, "hist"),
                   "NAVI_DB_PATH": DB})
os.environ.pop("HOUNDS_NO_SUMMARY", None)

fails = []


def check(cond, msg):
    print(("PASS " if cond else "FAIL ") + msg)
    if not cond:
        fails.append(msg)


KEV = "[{'type': 'CISA-KNOWN-EXPLOITED', 'id': '2023/01/10'}]"
# pid, name, family, severity, kev, cves, vpr, output(rng, asset_index) -> str
PLUGINS = [
    ("1001", "Fortinet FortiGate SSL VPN RCE", "Firewalls", "critical", 1, "CVE-2023-1111", "9.8", None),
    ("1002", "VMware ESXi Multiple Vulnerabilities", "Misc.", "high", 0, "CVE-2022-2222,CVE-2022-2223", "7.4", None),
    ("1003", "Siemens SIMATIC S7 PLC Detection", "SCADA", "medium", 0, "", "", None),
    ("1004", "Hikvision Camera Web Interface Detection", "CGI abuses", "info", 0, "", "", None),
    ("1005", "Synology DiskStation Manager Detection", "Misc.", "low", 0, "", "", None),
    ("1006", "Microsoft Windows Server 2012 Unsupported Version Detection", "Windows", "critical", 0, "", "10.0", None),
    ("1007", "Apache HTTP Server SEoL (2.2.x)", "Web Servers", "high", 0, "", "6.1", None),
    ("1008", "Default Password (admin) for 'root' Account", "Default Unix Accounts", "high", 0, "", "7.0", None),
    ("1009", "Kerberoastable Service Accounts", "Windows", "medium", 0, "", "5.0", None),
    ("1010", "Generic Remote Info", "General", "info", 0, "", "",
     lambda r, i: r.choice(["nothing to see", "krbtgt account present", "uses default credentials here",
                            "a service account runs this", "plain output"])),
    ("1011", "Apache Log4j < 2.15.0 Remote Code Execution", "Misc.", "critical", 1, "CVE-2021-44228", "10.0", None),
    ("1012", "OpenSSL 1.1.1 < 1.1.1w Multiple Vulnerabilities", "Web Servers", "medium", 0,
     "CVE-2023-5678,CVE-2023-3817", "4.4", None),
    ("1013", "Microsoft Windows 7 End of Life Detection", "Windows", "critical", 0, "", "9.0", None),
    ("1014", "Cisco IOS XE Web UI Privilege Escalation", "CISCO", "critical", 1, "CVE-2023-20198", "10.0", None),
    ("20811", "Microsoft Windows Installed Software Enumeration (credentialed check)", "Windows", "info", 0, "", "", None),
    ("22869", "Software Enumeration (SSH)", "General", "info", 0, "", "", None),
    ("11936", "OS Identification", "General", "info", 0, "", "",
     lambda r, i: "Remote operating system : %s\nConfidence level : %d\nMethod : SMB\n"
                  % (r.choice(["Microsoft Windows Server 2019", "Ubuntu 22.04", "Linux Kernel 5.4"]),
                     r.choice([56, 70, 95, 99]))),
    ("95928", "Linux User List Enumeration", "General", "info", 0, "", "",
     lambda r, i: "----------[ User Accounts ]----------\n\nUser : alice%d\nHome folder : /home/alice%d\n"
                  "Start script : /bin/bash\n\nUser : deploy\nHome folder : /home/deploy\nStart script : /bin/bash\n"
                  "----------[ System Accounts ]----------\n\nUser : daemon\nHome folder : /usr/sbin\n"
                  "Start script : /usr/sbin/nologin\n" % (i % 3, i % 3)),
    ("10860", "SMB Use Host SID to Enumerate Local Users", "Windows", "info", 0, "", "",
     lambda r, i: "\n  - Administrator (id 500)\n  - Guest (id 501)\n  - krbtgt (id 502)\n  - svc_sql (id 1103)\n"),
    ("90001", "Local User Enumeration via WMI", "Windows", "info", 0, "", "",
     lambda r, i: "User : svc_backup\nUser : bob\n"),
    ("19506", "Nessus Scan Information", "Settings", "info", 0, "", "",
     lambda r, i: "Credentialed checks : %s\n" % r.choice(["yes, as 'root' via ssh", "no"])),
    ("110723", "Target Credential Status by Authentication Protocol - No Credentials Provided", "Settings",
     "info", 0, "", "", None),
    ("149334", "SSH Password Authentication Accepted", "Misc.", "medium", 0, "", "", None),
    ("17651", "Microsoft Windows SMB : Obtains the Password Policy", "Windows", "info", 0, "", "",
     lambda r, i: r.choice(["Minimum password length: 0\n", "Password complexity: enabled\n"])),
    ("41028", "SNMP Agent Default Community Name (public)", "SNMP", "high", 0, "", "7.5",
     lambda r, i: r.choice(["community public", "community private"])),
    ("10859", "Microsoft Windows SMB LsaQueryInformationPolicy Function SID Enumeration", "Windows", "info", 0,
     "", "", None),
    ("54615", "Device Type", "General", "info", 0, "", "",
     lambda r, i: "Remote device type : %s\nConfidence level : 99\n" % r.choice(["embedded", "general-purpose", "printer"])),
    ("35716", "Ethernet Card Manufacturer Detection", "Misc.", "info", 0, "", "",
     lambda r, i: "The following card manufacturers were identified :\n\n00:11:32:aa:bb:cc : %s"
                  % r.choice(["Synology Incorporated", "Ubiquiti Inc", "VMware, Inc."])),
    ("66717", "mDNS Detection (Local Network)", "Service detection", "info", 0, "", "",
     lambda r, i: r.choice(["_googlecast._tcp Chromecast Ultra", "_ipp._tcp printer", "_smb._tcp"])),
    ("10863", "SSL Certificate Information", "General", "info", 0, "", "",
     lambda r, i: "Subject Name:\n\nCommon Name: %s\n" % r.choice(["Synology DSM", "Chromecast ICA", "www.example.com",
                                                                   "UniFi Controller", "pfSense webConfigurator"])),
    ("24260", "HyperText Transfer Protocol (HTTP) Information", "Web Servers", "info", 0, "", "",
     lambda r, i: "Server: %s" % r.choice(["Hikvision-Webs", "nginx", "Synology Web Station"])),
    ("104410", "Target Credential Status by Authentication Protocol - Failure for Provided Credentials",
     "Settings", "info", 0, "", "", None),
    ("277650", "Remote Service Does Not Support Post-Quantum Key Exchange", "General", "info", 0, "", "", None),
]
STATES = ["open", "OPEN", "reopened", "fixed", "open", "Open"]
SEV_CASE = {"critical": ["critical", "Critical"], "high": ["high", "High"], "medium": ["medium", "Medium"],
            "low": ["low", "Low"], "info": ["info", "Info"]}


def make_db(path, assets=240):
    if os.path.exists(path):
        os.remove(path)
    r = random.Random(11)
    c = sqlite3.connect(path)
    c.execute("PRAGMA journal_mode=WAL")
    c.execute("CREATE TABLE assets (uuid TEXT PRIMARY KEY, hostname TEXT, ip_address TEXT, operating_system TEXT, "
              "acr TEXT, aes TEXT, last_found TEXT, url TEXT, aws_id TEXT)")
    c.execute("""CREATE TABLE vulns (finding_id TEXT PRIMARY KEY, asset_uuid TEXT, plugin_id TEXT, plugin_name TEXT,
                 plugin_family TEXT, severity TEXT, state TEXT, xrefs TEXT, cves TEXT, score TEXT, output TEXT,
                 first_found TEXT, last_found TEXT, port TEXT)""")
    c.execute("CREATE TABLE plugins (plugin_id TEXT PRIMARY KEY, name TEXT, vpr_score TEXT)")
    c.execute("CREATE TABLE tags (asset_uuid TEXT, tag_key TEXT, tag_value TEXT)")
    c.execute("CREATE TABLE epss (cve TEXT, epss_value TEXT, percentile TEXT)")
    c.execute("CREATE TABLE sla (critical TEXT, high TEXT, medium TEXT, low TEXT)")
    c.execute("INSERT INTO sla VALUES ('7','30','60','90')")
    lf = "2026-11-01T00:00:00.000Z"
    hosts = ["win-srv", "ubu", "fw-edge", "plant-hmi", "cam", "nas", "esx", "box", "dc", "kiosk"]
    oses = ["Microsoft Windows Server 2019", "Ubuntu 22.04", "", "", "Linux Kernel 3.10", "", "VMware ESXi 7.0",
            "", "Microsoft Windows Server 2012 R2", "macOS 14"]
    A = []
    for i in range(assets):
        k = i % len(hosts)
        A.append(("a%04d" % i, "%s-%d" % (hosts[k], i), "10.0.%d.%d" % (i // 250, i % 250 + 1), oses[k],
                  str(r.randint(1, 10)), str(r.randint(100, 950)), lf, "https://cloud/a%d" % i,
                  "i-%x" % i if i % 37 == 0 else ""))
    c.executemany("INSERT INTO assets VALUES (?,?,?,?,?,?,?,?,?)", A)
    c.executemany("INSERT INTO plugins VALUES (?,?,?)", [(p[0], p[1], p[6]) for p in PLUGINS])
    cves = sorted({cv for p in PLUGINS for cv in p[5].split(",") if cv})
    c.executemany("INSERT INTO epss VALUES (?,?,?)", [(cv, "%.4f" % r.random(), "0.5") for cv in cves])
    rows = []
    n = 0
    for i, a in enumerate(A):
        for p in r.sample(PLUGINS, r.randint(3, 14)):
            for _ in range(r.choice([1, 1, 1, 2])):          # same plugin on two ports sometimes
                n += 1
                pid, name, fam, sev, kev, cv, vpr, outf = p
                rows.append(("f%06d" % n, a[0], pid, name, fam, r.choice(SEV_CASE[sev]), r.choice(STATES),
                             KEV if kev else "[]", cv, vpr, outf(r, i) if outf else "plugin output %s" % pid,
                             "2025-%02d-%02dT00:00:00.000Z" % (r.randint(1, 12), r.randint(1, 28))
                             if r.random() < .6 else "2026-10-%02dT00:00:00.000Z" % r.randint(1, 28),
                             lf, str(r.choice([22, 80, 443]))))
    c.executemany("INSERT INTO vulns VALUES (%s)" % ",".join("?" * 14), rows)
    T = []
    for i, a in enumerate(A):
        if i % 5 == 0:
            T.append((a[0], "Owner", "app%d: team%d" % (i % 3, i % 4)))
        if i % 7 == 0:
            T.append((a[0], "OS", "Windows"))
        if i % 11 == 0:
            T.append((a[0], "Asset Inventory", "Class: Network - Firewall"))
    c.executemany("INSERT INTO tags VALUES (?,?,?)", T)
    # ⚡ Optimize's covering indexes (the fast paths use INDEXED BY when they exist)
    c.execute("CREATE INDEX hx_v_plugin ON vulns(plugin_id, asset_uuid, state, severity)")
    c.execute("CREATE INDEX hx_v_asset ON vulns(asset_uuid, plugin_id, state, severity)")
    c.commit()
    c.close()


make_db(DB)

from core import db, hx_summary  # noqa: E402

wc = sqlite3.connect(DB, isolation_level=None)
built = hx_summary.build(wc)
wc.close()
hx_summary.invalidate()
check(built.get("ok") and built.get("plugins") == len(PLUGINS), "summary tables built on the fixture")

# ── statement trace: every connection core.db opens (pool + connect()) ──────────────────────
TRACE = []
_orig_open, _orig_connect = db._open, db.connect


def _traced(fn):
    def w(*a, **k):
        con = fn(*a, **k)
        try:
            con.set_trace_callback(TRACE.append)
        except Exception:
            pass
        return con
    return w


db.close_all()
db._open = _traced(_orig_open)
db.connect = _traced(_orig_connect)

from core import asset_ownership, classify, fused_score, identity, iot_common, signals  # noqa: E402
from core import hx_summary as _hs  # noqa: E402,F811


def norm(x):
    if isinstance(x, dict):
        return {k: norm(v) for k, v in x.items()}
    if isinstance(x, (list, tuple, set)):
        y = [norm(v) for v in x]
        return sorted(y, key=lambda v: json.dumps(v, sort_keys=True, default=str))
    return x


def run(fn, summary=True):
    """(normalised result, traced statements) with the summaries on / forced off."""
    if summary:
        os.environ.pop("HOUNDS_NO_SUMMARY", None)
    else:
        os.environ["HOUNDS_NO_SUMMARY"] = "1"
    _hs.invalidate()
    del TRACE[:]
    try:
        res = fn()
    finally:
        os.environ.pop("HOUNDS_NO_SUMMARY", None)
    return norm(res), list(TRACE)


def _vulns_reads(stmts):
    return [s for s in stmts if re.search(r"\bvulns\b", s)]


def slow_shapes(stmts):
    """vulns statements a fast path must not run: plugin-attribute LIKEs over the table, or an
    unindexed GROUP BY asset_uuid over every finding."""
    bad = []
    for s in _vulns_reads(stmts):
        if "hx_plugin" in s:
            continue
        if re.search(r"(plugin_name\)?\s+LIKE|xrefs\s+LIKE)", s, re.I):
            bad.append(s)
        elif re.search(r"GROUP BY asset_uuid", s) and "INDEXED BY" not in s and "slabr" not in s:
            bad.append(s)
    return bad


def uses_hx(stmts):
    """A hound statement over hx_plugin / hx_asset (hx_summary's own freshness probe — hx_meta,
    sqlite_master — doesn't count)."""
    return any(("hx_plugin" in s or "hx_asset" in s) and "hx_meta" not in s and "sqlite_master" not in s
               for s in stmts)


def equivalent(label, fn, allow_slow=False):
    slow, st_slow = run(fn, summary=False)
    fast, st_fast = run(fn, summary=True)
    check(slow == fast, f"{label}: fast path == HOUNDS_NO_SUMMARY=1 result")
    if slow != fast:
        print("   slow:", json.dumps(slow, default=str)[:600])
        print("   fast:", json.dumps(fast, default=str)[:600])
    check(not uses_hx(st_slow), f"{label}: HOUNDS_NO_SUMMARY=1 never reads hx_* tables")
    check(uses_hx(st_fast), f"{label}: fast path reads hx_plugin / hx_asset")
    bad = slow_shapes(st_fast)
    check(allow_slow or not bad, f"{label}: fast path runs no plugin-name/xrefs LIKE or full GROUP BY over vulns"
          + ("" if not bad else " — " + bad[0][:160]))
    return slow, fast, st_fast


# ── classify ──────────────────────────────────────────────────────────────────────────────
c_slow, c_fast, _ = equivalent("classify(glance)", lambda: classify.classify(glance=True))
check(c_fast["glance"]["kev_assets"] > 0 and c_fast["glance"]["critical_assets"] > 0 and c_fast["glance"]["eol_os"] > 0,
      "classify fixture exercises KEV, critical and unsupported-OS assets")
equivalent("classify.os_signals", lambda: classify.os_signals())
equivalent("classify.os_breakdown", lambda: classify.os_breakdown())
equivalent("classify._eol_os_assets", lambda: classify._eol_os_assets())

# ── identity ──────────────────────────────────────────────────────────────────────────────
i_slow, i_fast, st = equivalent("identity.scan", lambda: identity.scan())
check(i_fast["kevHostN"] > 0 and i_fast["critHostN"] > 0 and i_fast["dcHosts"] > 0 and i_fast["adHosts"] > 0,
      "identity fixture exercises KEV / critical / default-cred / AD host sets")
outp = [s for s in st if "lower(output) LIKE" in s and "service account" in s]
check(len(outp) == 1, "identity fast path folds the three unrestricted output sweeps into one pass (%d)" % len(outp))
check(not any("MAX(last_found)" in s and "vulns" in s for s in st), "identity freshness read off assets, not vulns")

# ── IoT ───────────────────────────────────────────────────────────────────────────────────
VOCAB = ["Synology", "Chromecast", "UniFi", "pfSense", "Hikvision", "_googlecast", "Ubiquiti", "nomatch-term"]
CARRIERS = ["10863", "35716", "66717", "24260", "1005", "1004", "54615"]


def _pct():
    total = iot_common.asset_total()
    return {"%s|%s" % (p, t): iot_common.plugin_carries_term(p, t, total=total) for p in CARRIERS for t in VOCAB}


iot_common._PCT.update(key=None)
p_slow, p_fast, st = equivalent("iot plugin_carries_term (carriers × vocabulary)", _pct)
check(any(v["count"] for v in p_fast.values()), "iot fixture has (plugin, term) hits")
per_plugin = [s for s in st if "output LIKE" in s and "FROM vulns" in s]
check(len(per_plugin) <= len(VOCAB) + len(CARRIERS) - 1,
      "plugin_carries_term: %d output reads for %d calls (one per plugin after the vocabulary is known)"
      % (len(per_plugin), len(VOCAB) * len(CARRIERS)))
iot_common._PCT.update(key=None)
for p in CARRIERS[:2]:
    check(norm({t: iot_common.plugin_carries_term(p, t)["asset_uuids"] for t in VOCAB})
          == norm({t: v for t, v in iot_common.plugin_carries_terms(p, VOCAB).items()}),
          f"plugin_carries_terms({p}) == the per-term answers")
uu = [a["uuid"] for a in db.query("SELECT uuid FROM assets")]
equivalent("iot device_exposure", lambda: iot_common.device_exposure(uu + ["missing-uuid"]))
DET = {"iot_name": "Synology NAS", "plugins": ["1005"], "name_contains": ["Synology", "DiskStation"],
       "output_contains": ["Synology"], "include_general_hosts": True}
equivalent("iot assets_for_detection", lambda: iot_common.assets_for_detection(DET))
check(iot_common.detection_query(DET) and "hx_plugin" not in iot_common.detection_query(DET),
      "the navi tag selector (detection_query) never references the summary tables")

# ── asset ownership / fused score / signals ───────────────────────────────────────────────
o_slow, o_fast, _ = equivalent("asset_ownership._vuln_risk", lambda: asset_ownership._vuln_risk())
check(any(v[0] for v in [tuple(x) for x in o_fast.values()]) and any(x[1] for x in o_fast.values()),
      "ownership fixture has critical and KEV assets")
equivalent("asset_ownership.overview", lambda: asset_ownership.overview())
f_slow, f_fast, st = equivalent("fused_score.overview", lambda: fused_score.overview(limit=5000))
check(f_fast["kpi"]["kev"] > 0 and f_fast["kpi"]["eol"] > 0 and f_fast["kpi"]["sla_breach"] > 0,
      "fused fixture exercises KEV, EOL and SLA breach")
equivalent("fused_score._epss_map", lambda: fused_score._epss_map(DB, 10 ** 9))
equivalent("fused_score.select_uuids", lambda: fused_score.select_uuids(threshold=40))
s_slow, s_fast, _ = equivalent("signals.compute_all", lambda: signals.compute_all())

# ── stale summaries fall back ─────────────────────────────────────────────────────────────
wc = sqlite3.connect(DB, isolation_level=None)
wc.execute("INSERT INTO vulns (finding_id, asset_uuid, plugin_id, plugin_name, severity, state, xrefs, output) "
           "VALUES ('fnew', 'a0001', '1001', 'Fortinet FortiGate SSL VPN RCE', 'critical', 'open', ?, 'x')", (KEV,))
wc.close()
_hs.invalidate()
check(not _hs.usable(), "one vulns row inserted after the build → summaries stale (usable() False)")
for label, fn in (("classify", lambda: classify.classify(glance=True)), ("identity", lambda: identity.scan()),
                  ("ownership", lambda: asset_ownership._vuln_risk()),
                  ("fused", lambda: fused_score.overview(limit=5000)),
                  ("iot", lambda: iot_common.device_exposure(uu)), ("signals", lambda: signals.compute_all())):
    stale, st_stale = run(fn, summary=True)
    plain, _ = run(fn, summary=False)
    check(not uses_hx(st_stale) and stale == plain, f"stale summaries: {label} falls back to the plain SQL")
iot_common._PCT.update(key=None)
stale, st_stale = run(lambda: iot_common.plugin_carries_term("10863", "Synology"))
check(not uses_hx(st_stale) and "plugin_name LIKE" in " ".join(st_stale), "stale summaries: plugin_carries_term falls back")

print("\n%d failure(s)" % len(fails))
sys.exit(1 if fails else 0)
