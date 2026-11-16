"""Regression tests for bugs found in the agent reviews (Mitre, KEV, EOL, Certificate,
Post-Quantum, AI, Identity, Software). Pure-function and tiny-fixture checks — no navi,
no network, no server. Run: python3 tests/test_agents.py  (or pytest)."""
import atexit
import datetime
import os
import shutil
import sqlite3
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
TMP = tempfile.mkdtemp(prefix="hounds-agents-")
atexit.register(shutil.rmtree, TMP, ignore_errors=True)

fails = []


def check(cond, msg):
    print(("PASS " if cond else "FAIL ") + msg)
    if not cond:
        fails.append(msg)


# ---------------------------------------------------------------- EOL
from core import eol  # noqa: E402

for name, want in [("Adobe Reader Unsupported Version Detection", "Application"),
                   ("Microsoft .NET Framework SEoL", "Application"),
                   ("Google Chrome SEoL", "Application"),
                   ("Microsoft Windows Server 2012 SEoL", "Operating system"),
                   ("Unsupported Windows OS (remote)", "Operating system"),
                   ("Cisco IOS XE SEoL", "Operating system"),
                   ("CentOS 6 SEoL", "Operating system")]:
    check(eol.kind_of(name, "Windows") == want, f"EOL kind_of: {name} → {want} (family ignored)")

p = os.path.join(TMP, "eol.db")
c = sqlite3.connect(p)
c.executescript("""
CREATE TABLE assets(uuid TEXT, hostname TEXT, ip_address TEXT, acr REAL);
CREATE TABLE vulns(asset_uuid TEXT, plugin_id TEXT, plugin_name TEXT, output TEXT, plugin_family TEXT,
                   state TEXT, first_found TEXT, xrefs TEXT, severity TEXT);
""")
for i in range(4):
    c.execute("INSERT INTO assets VALUES (?,?,?,?)", (f"u{i}", f"h{i}", f"10.0.0.{i}", 5))
rows = [("u0", "Support ended on 2019-04-30", "open"), ("u1", "Support ended on 2019-04-30", "open"),
        ("u2", "The remote OS is no longer supported.", "open"),          # no date stated
        ("u3", "Support ended on 2020-11-30", "fixed")]                   # fixed: not counted
for u, out, st in rows:
    c.execute("INSERT INTO vulns VALUES (?,?,?,?,?,?,?,?,?)",
              (u, "33850", "Unix Operating System Unsupported Version Detection", out, "General", st, None, "", "critical"))
c.commit(); c.close()
v = eol.analyze(db_path=p)
g = {x["eol_date"]: x for x in v["date_groups"]}
check(set(g) == {"2019-04-30"} and g["2019-04-30"]["uuids"] == ["u0", "u1"],
      "EOL date tag holds only assets whose own output states that date (undated + fixed excluded)")
s = eol.scan(db_path=p)
check(s["groups"][1]["asset_count"] == 0 and s["groups"][0]["asset_count"] == 3,
      "EOL scan() counts open findings only, like analyze()")

# ---------------------------------------------------------------- MITRE
from core import mitre  # noqa: E402

check(mitre.technique_ids("Technique: T828") == ["T0828"], "MITRE ICS 3-digit id T828 → T0828")
check(mitre.technique_ids("T855; T842") == ["T0855", "T0842"], "MITRE several ICS ids parsed")
check(mitre.technique_ids("T1059.001, T1190") == ["T1059.001", "T1190"], "MITRE enterprise ids unchanged")

# ---------------------------------------------------------------- launcher POST guard
from core import launcher  # noqa: E402


def hdr(d):
    return lambda k: d.get(k)


check(launcher.post_guard(hdr({"Content-Type": "application/json", "Host": "localhost:8000"})) is None,
      "POST guard: same-origin JSON accepted")
check(launcher.post_guard(hdr({"Content-Type": "application/json", "Host": "localhost:8000",
                               "Origin": "http://localhost:8000"})) is None, "POST guard: matching Origin accepted")
check(launcher.post_guard(hdr({"Content-Type": "text/plain", "Host": "localhost:8000"})) is not None,
      "POST guard: text/plain (cross-site form) refused")
check(launcher.post_guard(hdr({"Content-Type": "application/json", "Host": "localhost:8000",
                               "Origin": "http://evil.example"})) is not None, "POST guard: foreign Origin refused")

# Search Hounds are never served from a cache (server result cache or the browser page cache)
_calls = []
launcher.DISPATCH.setdefault("argos", {})
_saved = launcher.DISPATCH["argos"].get("lookup")
launcher.DISPATCH["argos"]["lookup"] = lambda p: (_calls.append(1) or ({"ok": True, "n": len(_calls)}, 200))
a1, _ = launcher._dispatch("argos", "lookup", {"target": "x"})
a2, _ = launcher._dispatch("argos", "lookup", {"target": "x"})
b2, _ = launcher._dispatch("argos", "lookup", {"target": "x", "background": True})
check(len(_calls) >= 2 and not a2.get("_cached") and a2["n"] == 2,
      "Argos lookups always hit navi.db — never the server result cache")
if _saved:
    launcher.DISPATCH["argos"]["lookup"] = _saved
# a background read is answered from the result its foreground twin cached (same key)
launcher.DISPATCH.setdefault("zz_bg", {})["run"] = lambda p: ({"ok": True, "v": 1}, 200)
launcher._dispatch("zz_bg", "run", {"x": 1})
bg, st = launcher._dispatch("zz_bg", "run", {"x": 1, "background": True})
check(bg.get("_cached") and not bg.get("background"), "a background call hits the foreground cache entry")
launcher.DISPATCH.pop("zz_bg", None)
SEARCH = ["argos"] + ["ex_" + x for x in ("apps", "assets", "fixed", "paths", "plugins", "routes", "tags", "vulns")]
check(all(a in launcher._NOCACHE_AGENTS for a in SEARCH + ["explore"]), "every Search Hound is a no-cache agent")
_root = os.path.dirname(HERE)
check(all('data-page-cache="off"' in open(os.path.join(_root, "agents", a, "page.html")).read() for a in SEARCH),
      "every Search Hound page opts out of the browser page cache")

# ---------------------------------------------------------------- category whitelist
from core import activity  # noqa: E402

check(activity.allowed_category("software", "Software EOL") and not activity.allowed_category("software", "Business Unit"),
      "Software tags only its own categories")
check(activity.allowed_category("ai", "AI ACR Raise") and not activity.allowed_category("ai", "Owner"),
      "AI tags only its own categories")
check(not activity.allowed_category("postquantum", "Business Unit"), "Post-Quantum tags only its own categories")

# ---------------------------------------------------------------- identity selector
from core import identity  # noqa: E402

check(identity.selector_for(["a", "b"]).startswith("SELECT uuid AS asset_uuid FROM assets"),
      "identity tag selector reads assets (one row per asset), not vulns")

# ---------------------------------------------------------------- Certificate: Feb 29
from agents.certificate import agent as cert_agent  # noqa: E402


class _Feb29(datetime.date):
    @classmethod
    def today(cls):
        return cls(2028, 2, 29)


_orig = cert_agent.datetime.date
cert_agent.datetime.date = _Feb29
try:
    pc = os.path.join(TMP, "cert.db")
    c = sqlite3.connect(pc)
    c.executescript("CREATE TABLE assets(uuid TEXT, hostname TEXT, ip_address TEXT, acr REAL);"
                    "CREATE TABLE vulns(asset_uuid TEXT, plugin_id TEXT, plugin_name TEXT, last_found TEXT);"
                    "CREATE TABLE certs(asset_uuid TEXT, common_name TEXT, organization TEXT, organization_unit TEXT,"
                    " not_valid_after TEXT, not_valid_before TEXT, issuer_name TEXT, signature_algorithm TEXT,"
                    " key_length TEXT, subject_name TEXT, serial_number TEXT);")
    c.commit(); c.close()
    try:
        r = cert_agent.CertificateAgent()._run(pc)
        check(r["window_end"] == "2029-02-28", "Certificate agent runs on Feb 29 (window ends Feb 28 next year)")
    except Exception as e:
        check(False, f"Certificate agent runs on Feb 29 ({e})")
finally:
    cert_agent.datetime.date = _orig


# ---------------------------------------------------------------- Scan Evaluations (Chronos)
from core import scan_eval  # noqa: E402

today = datetime.date.today()


def info(sip, feed, start, dur, cred, stype="Normal", ver="10.11.3"):
    return (f"Nessus version : {ver}\nPlugin feed version : {feed}\nScan type : {stype}\nScan name : Daily\n"
            f"Scan policy used : Basic Network Scan\nScanner IP : {sip}\nCredentialed checks : {cred}\n"
            f"Scan Start Date : {start.year}/{start.month}/{start.day} 20:42 EDT\nScan duration : {dur} sec\n")


ps = os.path.join(TMP, "scan.db")
c = sqlite3.connect(ps)
c.executescript("CREATE TABLE assets(uuid TEXT, hostname TEXT, ip_address TEXT, acr REAL, url TEXT);"
                "CREATE TABLE vulns(asset_uuid TEXT, plugin_id TEXT, plugin_name TEXT, output TEXT, state TEXT, last_found TEXT, url TEXT);")
newfeed = today.strftime("%Y%m%d") + "0100"
oldfeed = (today - datetime.timedelta(days=40)).strftime("%Y%m%d") + "0100"
D = datetime.timedelta
for u, acr in [("fail", 9), ("ok", 5), ("multi", 5), ("nocred", 8), ("agent", 5), ("stale", 9), ("never", 9), ("fixed", 5)]:
    c.execute("INSERT INTO assets VALUES (?,?,?,?,?)", (u, u, "10.0.0.1", acr, ""))
V = [("fail", "19506", info("10.0.0.5", newfeed, today, 100, "yes, as 'n' via ssh")), ("fail", "104410", ""), ("fail", "141118", ""),
     ("ok", "19506", info("10.0.0.5", newfeed, today - D(10), 100, "yes, as 'n' via ssh")), ("ok", "141118", ""),
     ("multi", "19506", info("10.0.0.6", oldfeed, today - D(40), 5000, "yes, as 'n' via ssh")), ("multi", "110723", ""),
     ("nocred", "19506", info("10.0.0.6", oldfeed, today, 100, "no")),
     ("agent", "19506", info("127.0.0.1", newfeed, today, 100, "yes (on the localhost)", stype="Unix Agent")),
     ("stale", "19506", info("10.0.0.5", newfeed, today - D(200), 100, "yes, as 'n' via ssh")), ("stale", "21745", ""),
     ("fixed", "19506", info("10.0.0.5", newfeed, today, 100, "yes, as 'n' via ssh"))]
for u, pid, out in V:
    c.execute("INSERT INTO vulns(asset_uuid, plugin_id, output, state) VALUES (?,?,?,?)", (u, pid, out, "open"))
c.execute("INSERT INTO vulns(asset_uuid, plugin_id, output, state) VALUES ('fixed','104410','','fixed')")
c.commit(); c.close()
ev = scan_eval.evaluate(db_path=ps, keep_uuids=True)
A = {x["asset_uuid"]: x for x in ev["assets"]}
check(A["fail"]["status"] == "ok" and A["fail"]["issue"] == "failed",
      "Chronos (build 465): 19506 yes + 104410 = credentialed, with a credential issue (not blind)")
check(A["multi"]["status"] == "ok", "Chronos: 110723 for one protocol doesn't override a credentialed 19506")
check(A["nocred"]["status"] == "uncredentialed", "Chronos: 19506 'Credentialed checks : no' = uncredentialed")
check(A["fixed"]["status"] == "ok", "Chronos: a FIXED 104410 no longer counts as a failure")
check(A["never"]["fresh"] == "never" and A["stale"]["fresh"] == "90+" and A["multi"]["fresh"] == "31-90"
      and A["ok"]["fresh"] == "8-30", "Chronos: freshness buckets from Scan Start Date")
check(A["agent"]["type"] == "Agent" and A["agent"]["scanner"] == "Nessus Agent (on host)", "Chronos: agent scans grouped as the on-host agent")
check(A["stale"]["patch"] == "failed", "Chronos: 21745 marks patch assessment failed")
sc = {x["key"]: x for x in ev["scanners"]}
check(sc["10.0.0.6"]["outdated"] and not sc["10.0.0.5"]["outdated"], "Chronos: scanner on a 40-day-old feed is flagged")
check(ev["_sets"]["crown:blind"] == {"nocred", "stale", "never"},
      "Chronos: crown-jewel blind spots = ACR ≥ 7 and not credentialed or stale/never (a credentialed host with an issue isn't blind)")
check(ev["_sets"]["slow"] == {"multi"}, "Chronos: scans over an hour are slow")
check(ev["credential"]["cred_fail_assets"] == 1, "Chronos: credential block (Alerts / Contract) counts open 104410 only")
os.environ["NAVI_DB_PATH"] = ps
from agents.scan_eval import api as se_api  # noqa: E402

out, code = se_api.tag({"confirm": True, "key": "Business Unit"})
check(code == 400, "Chronos tag: unknown key refused (server picks category and value)")
out, code = se_api.tag({"confirm": True, "key": "scanner", "name": "1.2.3.4"})
check(code == 400, "Chronos tag: a scanner not in navi.db is refused")


# ---------------------------------------------------------------- Custom App (Cavall Hound) metrics
os.environ["CUSTOMAPP_IGNORE_PATH"] = os.path.join(TMP, "ca_ignore.json")
from agents.customapp import agent as ca  # noqa: E402

pc = os.path.join(TMP, "capp.db")
c = sqlite3.connect(pc)
c.executescript("""
CREATE TABLE assets(uuid TEXT, hostname TEXT, ip_address TEXT, acr TEXT);
CREATE TABLE vulns(asset_uuid TEXT, plugin_id TEXT);
CREATE TABLE software(asset_uuid TEXT, software_string TEXT);
CREATE TABLE vuln_route(route_id INTEGER, app_name TEXT, vuln_type TEXT, total_vulns INTEGER, plugin_list TEXT);
CREATE TABLE vuln_paths(path TEXT, asset_uuid TEXT, plugin_id TEXT);
CREATE TABLE tags(asset_uuid TEXT, tag_key TEXT, tag_value TEXT);
INSERT INTO assets VALUES ('a1','h1','',9),('a2','h2','',3),('a3','h3','',NULL);
INSERT INTO vulns VALUES ('a1','11'),('a2','11'),('a3','22');
INSERT INTO software VALUES ('a1','openssl 3.0.2');
INSERT INTO vuln_route VALUES (1,'ACME PORTAL','Application',5,"['11']"),(2,'OPENSSL','Application',3,"['22']");
INSERT INTO vuln_paths VALUES ('/opt/widgetd/bin/widgetd','a3','99');
INSERT INTO tags VALUES ('a1','Owner','ACME PORTAL: alice'),('a3','Custom App','widgetd');
""")
c.commit(); c.close()
r = ca.CustomAppAgent()._run(pc)
C = {x["name"]: x for x in r["candidates"]}
check("OPENSSL" not in C, "Custom App: an app already in the software inventory is not a candidate")
check(C["ACME PORTAL"]["assets"] == 2 and C["ACME PORTAL"]["crown"] == 1 and C["ACME PORTAL"]["unowned"] == 1,
      "Custom App: route assets come from its plugins; crown jewels and unowned assets counted")
check(C["widgetd"]["assets"] == 1 and C["widgetd"]["named"], "Custom App: a path candidate already tagged Custom App is 'named'")
m = r["metrics"]
check(m["candidates"] == 2 and m["assets"] == 3 and m["named"] == 1 and m["crown_candidates"] == 1,
      "Custom App: page metrics add up")


# ---------------------------------------------------------------- WAS: Recon cohorts
from core import was as _was  # noqa: E402
WP = os.path.join(TMP, "was.db")
c = sqlite3.connect(WP)
c.executescript("""CREATE TABLE apps (name TEXT, target TEXT, uuid TEXT, config_id TEXT, asset_uuid TEXT,
  scan_completed_time TEXT, pages_crawled TEXT, requests_made TEXT, critical_count TEXT, high_count TEXT,
  medium_count TEXT, low_count TEXT, info_count TEXT, owasp TEXT, tech_list TEXT, notes TEXT);
  CREATE TABLE findings (scan_uuid TEXT, plugin_id TEXT, name TEXT, risk_factor TEXT);""")
c.execute("INSERT INTO apps VALUES ('shop','https://shop','u1','c1','a1','2026-01-01T00:00:00.000+00:00','5','9','2','0','1','0','3',"
          "\"{'A1': 2, 'A3': 0}\",\"['PHP', 'Nothing Found']\",'')")
c.commit(); c.close()
al = _was.apps_list(WP)
check(al and al[0]["owasp"] == {"A1": 2, "A3": 0} and al[0]["tech"] == ["PHP"] and al[0]["critical"] == 2
      and al[0]["medium"] == 1 and al[0]["asset_uuid"] == "a1" and al[0]["scan_completed_time"].startswith("2026-01-01"),
      "WAS: the app list carries severity, OWASP, tech and scan time so Recon can narrow to a cohort")


# ---------------------------------------------------------------- Compliance: Deep-Dive cohorts
from core import compliance as _comp  # noqa: E402
CP = os.path.join(TMP, "comp.db")
c = sqlite3.connect(CP)
c.executescript("""CREATE TABLE compliance (asset_uuid TEXT, check_id TEXT, check_name TEXT, status TEXT,
  audit_file TEXT, reference TEXT);""")
R800 = "[{'framework': ' 800-53', 'control': 'CM-7'}]"
RPCI = "[{'framework': 'PCI-DSSv3.2.1', 'control': '2.2'}]"
for row in [("x1", "c1", "Firewall on", "FAILED", "A.audit", R800), ("x1", "c2", "SSH off", "FAILED", "A.audit", RPCI),
            ("x2", "c1", "Firewall on", "FAILED", "B.audit", R800), ("x2", "c2", "SSH off", "PASSED", "A.audit", RPCI),
            ("x3", "c1", "Firewall on", "PASSED", "A.audit", R800), ("x3", "c2", "SSH off", "WARNING", "A.audit", RPCI),
            ("x4", "c1", "Firewall on", "PASSED", "A.audit", R800)]:
    c.execute("INSERT INTO compliance VALUES (?,?,?,?,?,?)", row)
c.commit(); c.close()
co = lambda f: (_comp.cohort(f, CP) or {}).get("uuids")
check(co("st:failed") == {"x1", "x2"} and co("st:warning") == {"x3"} and co("st:clean") == {"x4"},
      "Compliance cohorts: failed / warning / clean assets")
check(co("check:c1") == {"x1", "x2"} and co("fw:800-53") == {"x1", "x2"} and co("fw:PCI-DSSv3.2.1") == {"x1"},
      "Compliance cohorts: a control's and a framework's failing assets (framework names trimmed)")
check(co("audit:B.audit") == {"x2"} and co("pct:lt50") == {"x1"} and _comp.cohort("nope:1", CP) is None,
      "Compliance cohorts: audit file, under-50% pass, unknown cohort → None")
check([a["asset_uuid"] for a in _comp.assets_list(CP, only={"x2", "x3"})] == ["x2", "x3"],
      "Compliance: the Deep-Dive asset list narrows to a cohort, worst first")
c = sqlite3.connect(CP)
c.executemany("INSERT INTO compliance VALUES (?,?,?,?,?,?)", [
    ("x5", "trail ", "Trailing id", "FAILED", "  padded.audit  ", R800),     # ids / files with spaces
    (None, "c1", "Firewall on", "FAILED", "A.audit", R800)])                  # a row with no asset
c.commit(); c.close()
check(co("check:trail ") == {"x5"} and co("audit:  padded.audit  ") == {"x5"},
      "Compliance cohorts keep check ids / audit files verbatim (surrounding spaces)")
check(_comp.control_targets(CP, check_id="trail ")["uuids"] == ["x5"], "Audit Owner targets keep the check id verbatim")
check(all(a["asset_uuid"] for a in _comp.assets_list(CP)) and all(r["asset_uuid"] for r in _comp.overview(CP)["assets_rows"]),
      "Compliance: rows with no asset_uuid aren't listed as assets")
d = _comp.asset_detail(CP, "x1", focus_check="c2")
check(d["checks"][0]["check_id"] == "c2", "Deep-Dive: the control a Minos link came from sorts first (survives the 600 cap)")


# ---------------------------------------------------------------- every page's inline script parses
# (a stray apostrophe inside a '…' string kills a whole page; no other test would notice)
import glob as _glob, re as _re, shutil as _shutil, subprocess as _subp, tempfile as _tmpf  # noqa: E402
if _shutil.which("node"):
    _bad = []
    for _f in sorted(_glob.glob(os.path.join(_root, "agents", "*", "page.html")) + _glob.glob(os.path.join(_root, "web", "*.html"))
                     + [os.path.join(_root, "web", "assets", "console.js")]):
        _h = open(_f, encoding="utf-8").read()
        _parts = [_h] if _f.endswith(".js") else [m.group(2) for m in _re.finditer(
            r"<script(?![^>]*\bsrc=)([^>]*)>(.*?)</script>", _h, _re.S) if "module" not in m.group(1) and "json" not in m.group(1)]
        for _js in _parts:
            with _tmpf.NamedTemporaryFile("w", suffix=".js", delete=False) as _t:
                _t.write(_js)
            _r = _subp.run(["node", "--check", _t.name], capture_output=True, text=True)
            os.unlink(_t.name)
            if _r.returncode:
                _bad.append(os.path.relpath(_f, _root))
    check(not _bad, "every page's inline script parses (node --check): %s" % (_bad or "ok"))


def test_agent_regressions():
    """pytest entry point — every check above ran at import; fail with the list."""
    assert not fails, "\n".join(fails)


if __name__ == "__main__":
    print(f"\n{len(fails)} failure(s)")
    sys.exit(1 if fails else 0)
