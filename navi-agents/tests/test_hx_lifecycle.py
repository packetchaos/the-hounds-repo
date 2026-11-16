"""Regression tests — Phase 1 (build 456) summary reads in the LIFECYCLE & KEV hounds.

Every rewritten reader must give the same answer from the hx_plugin / hx_asset summaries (and the
covering hx_v_* indexes) as from its plain-SQL fallback (HOUNDS_NO_SUMMARY=1) on realistic data —
plugin attributes (name, family, KEV xref, CVEs, VPR) consistent per plugin like Tenable's, a
recast severity on some findings, mixed-case states. Also: the fast path is really taken (the SQL
it sends reads hx_* and never scans vulns by a plugin-level LIKE), and stale summaries (one vulns
row inserted after the build) fall back to today's SQL.

Covers: core.eol scan/analyze · core.kev analyze · agents.cisakev summary/kev_dates ·
core.ai_assets scan (AI family + the S23 risk rollup) · agents.ai.api AI-family count ·
core.insights compute · core.alerts template metrics + suggest() · core.software
tenable_eol_assets + risk. Synthetic navi.db; no Tenable. Run: python3 tests/test_hx_lifecycle.py"""
import atexit
import json
import os
import random
import re
import shutil
import sqlite3
import sys
import tempfile
import faulthandler; faulthandler.dump_traceback_later(300, exit=True)

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
TMP = tempfile.mkdtemp(prefix="hounds-hxlc-")
atexit.register(shutil.rmtree, TMP, ignore_errors=True)
DB = os.path.join(TMP, "navi.db")
os.environ.update({"NAVI_CACHE_DIR": os.path.join(TMP, "cache"), "HOUNDS_CONFIG": os.path.join(TMP, "cfg.json"),
                   "NAVI_TAGLOG_DB": os.path.join(TMP, "taglog.db"), "NAVI_HISTORY_DIR": os.path.join(TMP, "hist"),
                   "NAVI_DB_PATH": DB, "NAVI_KEV_CACHE_S": "0"})
os.environ.pop("HOUNDS_NO_SUMMARY", None)
os.environ.pop("NAVI_ALLOW_WRITES", None)

fails = []


def check(cond, msg):
    print(("PASS " if cond else "FAIL ") + msg)
    if not cond:
        fails.append(msg)


KEV = "{'type': 'CISA-KNOWN-EXPLOITED', 'id': '%s'}"
CATALOG = {"catalogVersion": "t", "dateReleased": "2026-01-01", "vulnerabilities": [
    {"cveID": "CVE-2021-44228", "vendorProject": "Apache", "product": "Log4j", "vulnerabilityName": "Log4Shell",
     "dateAdded": "2021-12-10", "dueDate": "2021-12-24", "knownRansomwareCampaignUse": "Known"},
    {"cveID": "CVE-2022-22965", "vendorProject": "VMware", "product": "Spring", "vulnerabilityName": "Spring4Shell",
     "dateAdded": "2022-04-04", "dueDate": "2022-04-25", "knownRansomwareCampaignUse": "Unknown"},
    {"cveID": "CVE-2020-1472", "vendorProject": "Microsoft", "product": "Netlogon", "vulnerabilityName": "Zerologon",
     "dateAdded": "2021-11-03", "dueDate": "2099-01-01", "knownRansomwareCampaignUse": "Known"},
]}

# plugin_id: (name, family, severity, xrefs, cves, score, output-maker)
PLUGINS = {
    "11936": ("Microsoft Windows Server 2012 End of Life", "Windows", "critical", None, None, "7.4",
              lambda r: "Security End of Life : October 10, 2023\nInstalled: 2012 R2"),
    "201363": ("Apache Tomcat SEoL (8.0.x)", "Web Servers", "critical", None, None, "6.7",
               lambda r: "Security End of Life : June 30, 2018"),
    "108797": ("VMware ESXi Unsupported Version Detection", "General", "high", None, None, "",
               lambda r: r.choice(["End of support date : 2014/04/08", "End of support date : 2016/03/12",
                                   "Installed version : 5.5"])),
    "58987": ("PHP Unsupported Version Detection", "CGI abuses", "critical", None, None, "5.9",
              lambda r: r.choice(["Support ended : 2019-01-10", "End of life date : December 31, 2018", ""])),
    "33850": ("Unix Operating System Unsupported Version Detection", "General", "critical", None, None, "",
              lambda r: "The remote OS is no longer maintained."),
    "155999": ("Apache Log4j < 2.15.0 Remote Code Execution", "Misc.", "critical", KEV % "2021/12/10",
               "CVE-2021-44228,CVE-2021-45046", "9.9", lambda r: "Path : /opt/app/log4j-core-2.14.jar"),
    "159374": ("Spring Framework RCE (Spring4Shell)", "Misc.", "critical", KEV % "2022/04/04",
               "CVE-2022-22965", "9.0", lambda r: "Spring 5.3.17"),
    "140657": ("Netlogon Elevation of Privilege (Zerologon)", "Windows", "critical", None,
               "CVE-2020-1472", "9.6", lambda r: "vulnerable"),
    "160001": ("Chrome < 100 Multiple Vulnerabilities", "Windows", "high", KEV % "2022/04/04",
               "CVE-2022-1096", "8.1", lambda r: "Chrome 99"),
    "34477": ("Adobe Reader < 9.0 Multiple Vulnerabilities", "Windows", "high", None,
              "CVE-2008-2992,CVE-2008-0655", "8.8", lambda r: "Reader 8.1"),       # MITRE-mapped CVEs
    "173001": ("Ollama Detection", "Artificial Intelligence", "info", None, None, "",
               lambda r: "Ollama listening on 11434"),
    "173002": ("PyTorch Detection", "Artificial Intelligence", "medium", None, None, "4.2",
               lambda r: "torch 2.1 installed"),
    "93561": ("Docker Service Detection", "Service detection", "info", None, None, "",
              lambda r: "containers: 3"),
    "10107": ("HTTP Server Type and Version", "Web Servers", "info", None, None, "", lambda r: "nginx"),
    "19506": ("Nessus Scan Information", "Settings", "info", None, None, "", lambda r: "Scan duration : 600 sec"),
    "22869": ("Software Enumeration (SSH)", "General", "info", None, None, "", lambda r: "openssl-1.0.2k"),
}
for i in range(40):
    PLUGINS[str(50000 + i)] = ("Generic Finding %d" % i, "Fam%d" % (i % 4), ["critical", "high", "medium", "low", "info"][i % 5],
                               None, ("CVE-2019-%04d" % i) if i % 3 == 0 else None, "%.1f" % (i % 10 + 0.3) if i % 2 else "",
                               lambda r: "generic")
STATES = ["OPEN", "open", "REOPENED", "reopened", "fixed", "FIXED", None]


def make_db(path, n_assets=300, n=6000, seed=11):
    if os.path.exists(path):
        os.remove(path)
    c = sqlite3.connect(path)
    c.execute("PRAGMA journal_mode=WAL")
    c.executescript("""
    CREATE TABLE assets (uuid text PRIMARY KEY, hostname text, ip_address text, acr text, url text);
    CREATE TABLE vulns (finding_id text PRIMARY KEY, asset_uuid text, first_found text, last_found text, output text,
        plugin_id text, plugin_name text, plugin_family text, port text, severity text, state text, cves text,
        score text, xrefs text, url text);
    CREATE TABLE plugins (plugin_id text PRIMARY KEY, name text, severity text, cves text, vpr_score text);
    CREATE TABLE software (asset_uuid text, software_string text);
    CREATE TABLE cpes (asset_uuid text, cpe_string text);
    CREATE TABLE tags (asset_uuid text, tag_key text, tag_value text);
    CREATE TABLE vuln_route (app_name text, plugin_list text, total_vulns int);
    CREATE TABLE vuln_paths (asset_uuid text, plugin_id text, path text);
    """)
    r = random.Random(seed)
    uu = ["%08x-0000-4000-8000-%012d" % (i, i) for i in range(n_assets)]
    c.executemany("INSERT INTO assets VALUES (?,?,?,?,?)",
                  [(u, "host%d" % i, "10.0.%d.%d" % (i // 250, i % 250), str(r.choice([1, 3, 5, 8, 9, 10])), "")
                   for i, u in enumerate(uu)])
    pids = list(PLUGINS)
    weights = [6 if (PLUGINS[p][2] in ("critical",) or "Unsupported" in PLUGINS[p][0] or "Life" in PLUGINS[p][0]) else 3
               for p in pids]
    rows = []
    for i in range(n):
        pid = r.choices(pids, weights)[0]
        name, fam, sev, xr, cves, sc, out = PLUGINS[pid]
        if pid == "50001" and i % 4 == 0:
            sev = "critical"                          # a recast severity on some findings
        if sev and i % 7 == 0:
            sev = sev.capitalize()
        ff = "2%03d-%02d-%02dT10:00:00Z" % (r.choice([18, 19, 20, 21, 22, 23]), r.randint(1, 12), r.randint(1, 28))
        rows.append(("f%06d" % i, uu[r.randrange(n_assets - 10)], ff, ff, out(r), pid, name, fam,
                     str(r.choice([0, 0, 443, 11434])), sev, r.choice(STATES), cves, sc, xr, ""))
    c.executemany("INSERT INTO vulns VALUES (%s)" % ",".join("?" * 15), rows)
    c.executemany("INSERT INTO plugins VALUES (?,?,?,?,?)",
                  [(p, v[0], v[2], v[4] or "", v[5]) for p, v in PLUGINS.items()])
    c.executemany("INSERT INTO software VALUES (?,?)",
                  [(u, s) for u in uu[:120] for s in r.sample(["openssl-1.0.2k", "openssl-3.0.7", "php-7.2.1",
                                                               "tomcat-8.0.5", "python3-3.6.8", "nginx-1.20.1"], 3)])
    c.executemany("INSERT INTO tags VALUES (?,?,?)", [(u, "Owner", "team%d" % (i % 4)) for i, u in enumerate(uu[:200])])
    c.execute("CREATE INDEX hx_v_plugin ON vulns(plugin_id, asset_uuid, state, severity)")
    c.execute("CREATE INDEX hx_v_asset ON vulns(asset_uuid, plugin_id, state, severity)")
    c.commit()
    c.close()


make_db(DB)
from core import db, hx_summary  # noqa: E402

c = sqlite3.connect(DB, isolation_level=None)
hx_summary.build(c)
c.close()
hx_summary.invalidate()

# every SQL statement any connection runs, to prove which path was taken
LOG = []
_orig_open = db._open


def _traced(p):
    con = _orig_open(p)
    con.set_trace_callback(LOG.append)
    return con


db._open = _traced
db.close_all()


def run(fn, fast):
    """fn() with summaries on (fast=True) or forced off; returns (result, SQL it sent)."""
    if fast:
        os.environ.pop("HOUNDS_NO_SUMMARY", None)
    else:
        os.environ["HOUNDS_NO_SUMMARY"] = "1"
    hx_summary.invalidate()
    del LOG[:]
    try:
        res = fn()
    finally:
        os.environ.pop("HOUNDS_NO_SUMMARY", None)
    return res, list(LOG)


def reads_hx(sqls):
    """a hound statement that reads hx_plugin / hx_asset (not hx_summary's own freshness probe)"""
    return any(re.search(r"\bhx_(plugin|asset)\b", s) and "sqlite_master" not in s for s in sqls)


PLUGIN_SCAN = re.compile(r"FROM vulns(?: NOT INDEXED)? WHERE \(?\s*(?:lower\()?(?:plugin_name|plugin_family|xrefs)\b", re.I)


def no_plugin_scan(sqls):
    return not any(PLUGIN_SCAN.search(s) for s in sqls)


check(hx_summary.usable(), "summaries built and fresh on the fixture")

from core import eol, kev, ai_assets, insights, alerts, software  # noqa: E402
from agents.cisakev import agent as KA  # noqa: E402
from agents.ai import api as AIA  # noqa: E402
CAT = json.dumps(CATALOG)


def same(name, fn, norm=lambda x: x, extra=None):
    a, sa = run(fn, False)
    b, sb = run(fn, True)
    check(not reads_hx(sa), name + ": HOUNDS_NO_SUMMARY=1 runs the plain SQL (no hx_* reads)")
    check(reads_hx(sb) or (extra and extra(sb)), name + ": the fast path reads the summaries")
    check(no_plugin_scan(sb), name + ": the fast path sends no plugin-level LIKE scan over vulns")
    check(norm(a) == norm(b), name + ": fast path == fallback")
    return a, b


# ---- EOL (Charon)
def _scan_norm(x):
    return [(g["label"], g["asset_count"], sorted((str(p["plugin_id"]), p["plugin_name"], p["assets"]) for p in g["plugins"]))
            for g in x["groups"]]


a, b = same("eol.scan", eol.scan, _scan_norm)
check(a["groups"][0]["asset_count"] > 0 and a["groups"][1]["asset_count"] > 0, "eol.scan: fixture has both groups")
check([p["assets"] for p in b["groups"][0]["plugins"]] == sorted((p["assets"] for p in b["groups"][0]["plugins"]), reverse=True),
      "eol.scan fast: plugins most assets first")
a, b = same("eol.analyze", eol.analyze)
check(a["metrics"]["eol_assets"] > 0 and a["metrics"]["kev_assets"] > 0 and a["metrics"]["crit_assets"] > 0
      and a["date_groups"], "eol.analyze: fixture exercises KEV / critical overlap and dated groups")
_, sb = run(eol.analyze, True)
check(not any("NOT INDEXED" in s for s in sb) and any("FROM hx_asset" in s for s in sb),
      "eol.analyze fast: KEV/critical overlap from hx_asset, no NOT INDEXED vulns scan")
check(eol.parse_eol_date("Security End of Life : July 11, 2017") == "2017-07-11"
      and eol.parse_eol_match("x\nEnd of support date : 2014/04/08\n") == ("2014-04-08", "End of support date : 2014/04/08")
      and eol.parse_eol_match("nothing here") == (None, None), "eol.parse_eol_match (memoised) unchanged")

# ---- CISA KEV (Laelaps)
a, b = same("kev.analyze", lambda: kev.analyze(json_text=CAT, keep_uuids=True, allow_live=False))
check(a["metrics"]["kev_assets"] > 0 and a["metrics"]["no_xref_cves"] >= 1 and a["metrics"]["xref_only_assets"] > 0,
      "kev.analyze: fixture exercises xref, no-xref and xref-only rows")
same("cisakev.summary", KA.summary)
a, b = same("cisakev.kev_dates", KA.kev_dates)
check(len(a) == 2 and [r["kev_date"] for r in a] == ["2022/04/04", "2021/12/10"], "cisakev.kev_dates: both dates, newest first")

# ---- AI (Pythia)
a, b = same("ai_assets.scan", ai_assets.scan)
check(a["asset_count"] > 0 and a["kevCount"] > 0 and a["eolCount"] > 0, "ai_assets.scan: fixture has AI assets with KEV/EOL risk")
_, sb = run(ai_assets.scan, True)
check(any("hx_v_asset" in s and "hx_plugin" in s for s in sb), "ai_assets.scan fast: S23 risk rollup is index-only over hx_v_asset × hx_plugin")
same("ai.api._ai_fallbacks_and_count", AIA._ai_fallbacks_and_count,
     lambda x: (sorted(f["plugin"] for f in x[0]), x[1]))

# ---- Insights
a, b = same("insights.compute", lambda: insights.compute())
check(a.get("mitre_high", 0) > 0 or any(v for k, v in a.items() if "mitre" in k and isinstance(v, int) and v > 0),
      "insights.compute: MITRE-on-crown-jewel counter is exercised (non-zero)")

# ---- Alerts
for t in alerts.TEMPLATES:
    if t["id"] in ("kev_new", "new_criticals", "eol_rise"):
        a, b = same("alerts metric " + t["id"], lambda t=t: alerts._metric_of(t, DB)["value"],
                    extra=lambda s: any("hx_v_plugin" in x for x in s))
        check(a > 0, "alerts metric %s: non-zero on the fixture (%s)" % (t["id"], a))
same("alerts.suggest", lambda: alerts.suggest(DB))
check(alerts._fast_metric("SELECT COUNT(DISTINCT asset_uuid) FROM vulns WHERE plugin_name LIKE '%x%' AND state='open'") is None
      and alerts._fast_metric("SELECT COUNT(*) FROM vulns WHERE xrefs LIKE '%CISA-KNOWN-EXPLOITED%'") is None,
      "alerts: only the exact asset-count shapes are rewritten")
check(all(t["metric_sql"] is None or "hx_" not in t["metric_sql"] for t in alerts.TEMPLATES),
      "alerts: the shown/stored template metric_sql stays plain SQL (works without summaries)")

# ---- Software (Mimir)
same("software.tenable_eol_assets", lambda: sorted(software.tenable_eol_assets()))
from agents.software import api as SA  # noqa: E402
body, code = SA.inventory({})
srun = (body.get("drill") or {}).get("run")
check(code == 200 and srun, "software: inventory run for risk()")
if srun:
    a, b = same("software.risk", lambda: software.risk(srun), extra=lambda s: False)

# ---- stale summaries fall back
c = sqlite3.connect(DB)
c.execute("INSERT INTO vulns (finding_id, asset_uuid, plugin_id, plugin_name, plugin_family, severity, state, xrefs) "
          "VALUES ('fNEW', '00000001-0000-4000-8000-000000000001', '999999', 'Foo End of Life', 'General', 'critical', "
          "'open', ?)", (KEV % "2023/05/05",))
c.commit()
c.close()
hx_summary.invalidate()
check(not hx_summary.usable(), "stale: one vulns row after the build → usable() False")
for name, fn in (("eol.scan", eol.scan), ("eol.analyze", eol.analyze), ("cisakev.summary", KA.summary),
                 ("cisakev.kev_dates", KA.kev_dates), ("ai_assets.scan", ai_assets.scan),
                 ("kev.analyze", lambda: kev.analyze(json_text=CAT, allow_live=False)),
                 ("insights.compute", insights.compute), ("alerts.suggest", lambda: alerts.suggest(DB)),
                 ("software.tenable_eol_assets", lambda: sorted(software.tenable_eol_assets()))):
    x, sx = run(fn, True)
    y, sy = run(fn, False)
    check(not reads_hx(sx) and x == y, "stale: %s falls back to its plain SQL (same result as forced off)" % name)
check(any(g["eol_date"] == "2023-10-10" for g in eol.analyze()["date_groups"]) and
      any(r["kev_date"] == "2023/05/05" for r in KA.kev_dates()), "stale: the new row is visible through the fallback")

print("\n%d failure(s)" % len(fails))
sys.exit(1 if fails else 0)
