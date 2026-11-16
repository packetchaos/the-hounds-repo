"""Regression tests — build 475: Software Explorer (Harrier), a search hound for zero-day hunting.

  · Version comparison (core/swsearch.vcmp): numbers as numbers, OpenSSL letter releases,
    pre-releases before the release, epochs ignored.
  · Range syntax: ';' = OR, spaces = AND, bare version = exact; bad text is an error, not a guess.
  · Search: where a product is installed (software + cpes, list-form asset uuids), the version
    filter, the range verdicts (in range / distro build / no version / not in range) and the
    where-installed breakdowns — all over the whole selection.
  · ✨ Lookup: the plan proposes sources and fetches nothing; the fetch reads ONLY the approved
    URLs, needs confirm:true, refuses non-public addresses; NVD / CVE.org / OSV parse by rules
    (fixtures follow each API's published schema); model output is validated before use.
Run: python3 tests/test_ex_software_475.py"""
import atexit
import json
import os
import shutil
import sqlite3
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
FX = os.path.join(HERE, "fixtures", "zeroday")
TMP = tempfile.mkdtemp(prefix="hounds-475-")
atexit.register(shutil.rmtree, TMP, ignore_errors=True)
DB = os.path.join(TMP, "navi.db")
os.environ.update({"NAVI_DB_PATH": DB, "NAVI_CACHE_DIR": os.path.join(TMP, "cache"),
                   "HOUNDS_CONFIG": os.path.join(TMP, "cfg.json"), "NAVI_TAGLOG_DB": os.path.join(TMP, "t.db"),
                   "NAVI_LLM_PROVIDER": "anthropic", "ANTHROPIC_API_KEY": ""})
fails = []


def check(cond, msg):
    print(("PASS " if cond else "FAIL ") + msg)
    if not cond:
        fails.append(msg)


U = ["%08d-0000-0000-0000-000000000000" % i for i in range(1, 9)]
c = sqlite3.connect(DB)
c.execute("CREATE TABLE assets (uuid text, hostname text, ip_address text, operating_system text, network text, "
          "acr text, last_found text)")
c.execute("CREATE TABLE software (asset_uuid text, software_string text)")
c.execute("CREATE TABLE cpes (asset_uuid text, cpe_string text)")
c.executemany("INSERT INTO assets VALUES (?,?,?,?,?,?,?)", [
    (U[0], "web01", "10.0.0.1", "Red Hat Enterprise Linux 7.9", "DMZ", "9", "2026-11-01"),
    (U[1], " ", "10.0.0.2", "Ubuntu 22.04", "Default", "5", "2026-11-02"),
    (U[2], "app03", "10.0.0.3", "Microsoft Windows Server 2019 Standard", "Default", "10", "2026-11-03"),
    (U[3], "db04", "10.0.0.4", "Red Hat Enterprise Linux 8.6", "Default", "7", "2026-11-04"),
    (U[4], "dev05", "10.0.0.5", "Ubuntu 22.04", "Default", None, "2026-11-05"),
    (U[5], "noapp06", "10.0.0.6", "Ubuntu 22.04", "Default", "3", "2026-11-06"),
])
c.executemany("INSERT INTO software VALUES (?,?)", [
    (U[0], "openssl-1.0.2k-19.el7"),                       # distro build, in <1.1.1
    (U[1], "openssl-3.0.2-0ubuntu1.10"),                  # distro build, not in <1.1.1
    (U[3], "openssl-libs-1.1.1k-7.el8_6"),                # a different product name
    (str([U[0], U[3]]), "log4j-2.14.1-1"),                # navi's list form: one row, two assets
    (U[4], "log4j-2.17.1-1"),                             # fixed
    (U[2], "Apache Log4j - 2.15.0  [version 2.15.0]"),    # Windows-style
    (U[5], "bash-5.1-6ubuntu1"),
])
c.executemany("INSERT INTO cpes VALUES (?,?)", [
    (U[2], "['cpe:/a:openssl:openssl:1.0.2u']"),           # upstream build via CPE, in <1.1.1
    (U[4], "['cpe:/a:openssl:openssl']"),                  # no version
])
c.commit()
c.close()

from core import advisory, swsearch as S  # noqa: E402

# ── 1. versions ───────────────────────────────────────────────────────────────
for a, b, want in [("2.4.9", "2.4.10", -1), ("1.0.2k", "1.0.2u", -1), ("2.0rc1", "2.0", -1), ("2.0", "2.0.0", 0),
                   ("1.0.2", "1.0.2a", -1), ("1.0.2a", "1.0.2.1", -1), ("1:2.3", "2.3", 0), ("v1.2", "1.2", 0),
                   ("2.0-beta2", "2.0-beta10", -1), ("1.2a1", "1.2", -1), ("1.2rc1", "1.2beta3", 1),
                   ("10.0.19041", "10.0.9", 1), ("2.0-beta9", "2.0.1", -1)]:
    check(S.vcmp(a, b) == want and S.vcmp(b, a) == -want, "vcmp(%s, %s) = %d" % (a, b, want))

# ── 2. ranges ─────────────────────────────────────────────────────────────────
r = S.parse_ranges(">=2.0 <2.17.1; >=2.18 <2.18.2")
check(r == [[(">=", "2.0"), ("<", "2.17.1")], [(">=", "2.18"), ("<", "2.18.2")]], "range: ';' = OR, spaces = AND")
check([S.in_ranges(v, r) for v in ("2.14.1", "2.17.1", "2.18.1", "1.9", "2.18.2")] == [True, False, True, False, False],
      "in_ranges: inside / at the fix / second line / below / at the second fix")
check(S.parse_ranges("3.0.2") == [[("=", "3.0.2")]] and S.in_ranges("3.0.2", S.parse_ranges("3.0.2")),
      "range: a bare version is exact")
for bad in ("abc", "<2.4 foo", "<"):
    try:
        S.parse_ranges(bad)
        check(False, "range %r should be rejected" % bad)
    except ValueError:
        check(True, "range %r is rejected, not guessed" % bad)
check(S.ranges_text(S.parse_ranges(">=2.0 <2.17.1; 3.0")) == ">=2.0 <2.17.1; 3.0", "ranges_text round-trips")
check(S.distro_build("openssl-1.0.2k-19.el7") and S.distro_build("bash-5.1-6ubuntu1")
      and not S.distro_build("log4j-2.14.1-1"), "distro builds recognised (.el7, ubuntu), upstream not")

# ── 3. search ─────────────────────────────────────────────────────────────────
res = S.search(q="openssl", ranges=S.parse_ranges("<1.1.1"))
k = res["kpi"]
st = {x["asset_uuid"]: x["status"] for x in res["rows"]}
check(st.get(U[0]) == "check", "openssl 1.0.2k-19.el7 in range → distro build (check)")
check(st.get(U[2]) == "affected", "openssl 1.0.2u from a CPE in range → in range (affected)")
check(st.get(U[1]) == "clear", "openssl 3.0.2 → not in range")
check(st.get(U[4]) == "unknown", "openssl CPE without a version → no version")
check(st.get(U[3]) == "clear", "openssl-libs 1.1.1k (term match) → not in range")
check(k["assets"] == 5 and k["affected"] == 1 and k["check"] == 1 and k["unknown"] == 1 and k["clear"] == 2,
      "KPIs count the whole selection: 5 assets · 1 in range · 1 distro · 1 no version · 2 clear")
check(k["crown"] == 2 and k["crown_hit"] == 2, "crown jewels (ACR 9–10): 2, both in range")
check(res["rows"][0]["status"] == "affected" and res["rows"][1]["status"] == "check", "rows: in range first")
check(sorted(p["name"] for p in res["products"]) == ["openssl", "openssl-libs"], "products: openssl + openssl-libs")
row = next(x for x in res["rows"] if x["asset_uuid"] == U[1])
check(row["hostname"] is None and row["ip_address"] == "10.0.0.2", "blank hostname comes back None (IP shown)")
bo = {b["label"]: b for b in res["breakdowns"]["os"]}
check(bo.get("Ubuntu 22.04", {}).get("assets") == 2 and "Red Hat Enterprise Linux 7" in bo,
      "OS breakdown groups by family/version")
check({b["label"] for b in res["breakdowns"]["acr"]} >= {"ACR 9–10 (crown)", "ACR not set"}, "ACR breakdown bands")
ex = S.search(q="openssl", exact=True)
check(ex["kpi"]["products"] == 1 and ex["kpi"]["assets"] == 4, "exact name: only 'openssl' (4 assets)")
lg = S.search(q="log4j")
check(lg["kpi"]["assets"] == 4, "log4j: list-form row counts both assets, plus the Windows-style name (4)")
check({p["name"] for p in lg["products"]} == {"log4j", "Apache Log4j"}, "Windows '[version x]' name parsed")
v = S.search(q="log4j", version="2.14.1")
check(v["kpi"]["assets"] == 2, "version filter: exactly 2.14.1 → 2 assets")
v = S.search(q="log4j", version="2.1*")
check(v["kpi"]["assets"] == 4, "version prefix 2.1* → 2.14.1, 2.15.0, 2.17.1 (4 assets)")
r4 = S.search(q="log4j", ranges=S.parse_ranges(">=2.13.0 <2.15.0; >=2.0-beta9 <2.3.1"))
check(r4["kpi"]["affected"] == 2 and r4["kpi"]["clear"] == 2, "Log4Shell range: 2.14.1 in, 2.15.0 / 2.17.1 out")
try:
    S.search(q="x")
    check(False, "a 1-character search should be refused")
except ValueError:
    check(True, "a 1-character search is refused")

mc = S.multi_count([{"key": "a", "terms": ["log4j"], "ranges": ">=2.13.0 <2.15.0"},
                    {"key": "b", "terms": ["openssl"], "ranges": "<1.1.1"},
                    {"key": "c", "terms": ["nginx", "ng"], "ranges": ""}])
check(mc["a"]["assets"] == 4 and mc["a"]["affected"] == 2, "multi_count: log4j 4 assets, 2 in range (= search)")
check(mc["b"]["affected"] == 1 and mc["b"]["check"] == 1 and mc["b"]["assets"] == 5, "multi_count: openssl = search")
check(mc["c"]["assets"] == 0 and mc["c"]["terms"] == ["nginx"], "multi_count: 2-letter terms skipped")

# ── 4. API ────────────────────────────────────────────────────────────────────
from core import launcher  # noqa: E402

b, s = launcher.dispatch("ex_software", "search", {"q": "openssl", "range": "<1.1.1", "limit": 2})
rs = b["result"]
check(s == 200 and rs["total"] == 5 and len(rs["rows"]) == 2 and rs["has_next"], "search API pages the rows (2 of 5)")
b, s = launcher.dispatch("ex_software", "search", {"q": "openssl", "range": "<1.1.1", "status": "affected"})
check(b["result"]["total"] == 1, "search API status filter: in range only")
b, s = launcher.dispatch("ex_software", "search", {"q": "openssl", "range": "<1.1.1 junk"})
check(b.get("ok") is False and "Range" in b.get("error", ""), "search API: a bad range is an error")
b, s = launcher.dispatch("ex_software", "export", {"q": "log4j"})
lines = b["csv"].strip().splitlines()
check(b["rows"] == 4 and lines[0].startswith("hostname,ip_address,asset_uuid"), "export: one CSV row per install")
b, s = launcher.dispatch("ex_software", "status", {})
check(b["result"]["software"] is True and b["result"]["records"] == 7, "status: software table + record count")

# ── 5. ✨ lookup ──────────────────────────────────────────────────────────────
calls = []
real_get = advisory.get


def fake_get(url, timeout=20):
    calls.append(url)
    host = url.split("/")[2]
    f = {"services.nvd.nist.gov": "nvd_CVE-2021-44228.json", "cveawg.mitre.org": "cveorg_CVE-2021-44228.json",
         "api.osv.dev": "osv_GHSA-jfh8-c2jp-5v3q.json"}.get(host, "advisory_page.html")
    return open(os.path.join(FX, f), encoding="utf-8").read(), ("text/html" if f.endswith("html") else
                                                               "application/json"), False


advisory.get = fake_get
b, s = launcher.dispatch("ex_software", "lookup_plan",
                         {"prompt": "the new log4j zero-day CVE-2021-44228 https://vendor.example/adv"})
pl = b["result"]
check(not calls, "lookup_plan fetches nothing")
check(pl["cves"] == ["CVE-2021-44228"] and [x["kind"] for x in pl["sources"]] == ["nvd", "cveorg", "osv", "page"],
      "plan: NVD, CVE.org, OSV for the CVE + the pasted page")
pk = advisory.plan("new Ivanti Connect Secure zero-day")
check(pk["cves"] == [] and pk["keywords"] == ["Ivanti", "Connect", "Secure"] and pk["sources"][0]["kind"] == "nvd_search"
      and "keywordSearch=Ivanti+Connect+Secure" in pk["sources"][0]["url"] and "pubStartDate=" in pk["sources"][0]["url"],
      "plan without a CVE: an NVD keyword search over recent disclosures (no 'zero-day' noise)")
pm = advisory.plan("that new ssh bug", interpret=lambda p: {"cves": ["CVE-2024-6387", "not-a-cve"], "keywords": []})
check(pm["cves"] == ["CVE-2024-6387"] and pm["interpreted_by"] == "model" and
      all(x["url"].startswith(("https://services.nvd.nist.gov/", "https://cveawg.mitre.org/", "https://api.osv.dev/"))
          for x in pm["sources"]), "a model can add CVE ids, never URLs; junk ids dropped")

b, s = launcher.dispatch("ex_software", "lookup_fetch", {"urls": [pl["sources"][0]["url"]]})
check(s == 400 and not calls, "lookup_fetch without confirm:true fetches nothing")
b, s = launcher.dispatch("ex_software", "lookup_fetch", {"urls": [], "confirm": True})
check(b.get("ok") is False and not calls, "lookup_fetch with no approved site fetches nothing")
b, s = launcher.dispatch("ex_software", "lookup_fetch",
                         {"urls": ["https://x%d.example/" % i for i in range(11)], "confirm": True})
check(b.get("ok") is False and not calls, "lookup_fetch refuses more than 10 sites")
approved = [x["url"] for x in pl["sources"][:3]]
b, s = launcher.dispatch("ex_software", "lookup_fetch", {"urls": approved, "confirm": True})
res = b["result"]
check(calls == approved, "lookup_fetch reads exactly the approved URLs, in order — nothing else")
check(all(v["ok"] and v["how"] == "rules" for v in res["visits"]), "NVD / CVE.org / OSV parsed by rules")
check(len(res["advisories"]) == 1, "the same CVE from three sources → one card")
adv = res["advisories"][0]
check(adv["kev"] and adv["severity"] == "CRITICAL" and adv["cvss"] == 10.0 and adv["sources"] == ["nvd", "cveorg", "osv"],
      "card: CISA KEV, CRITICAL 10.0, from nvd + cveorg + osv")
lp = next(p for p in adv["products"] if p["product"] == "log4j")
check(lp["ranges"] == ">=2.0.1 <2.3.1; >=2.4.0 <2.12.2; >=2.13.0 <2.15.0; 2.0-beta9; 2.0-rc1",
      "NVD cpeMatch ranges + beta/rc update field read (2.0-beta9)")
check(lp["fixed"] == "2.3.1, 2.12.2, 2.15.0", "every fixed line listed, oldest first")
check(lp["inventory"]["assets"] == 4 and lp["inventory"]["affected"] == 2, "inventory count: log4j 4 assets, 2 in range")
check(adv["products"][0]["product"] == "log4j", "products found in the inventory listed first")
check(not any(p["product"].startswith("sppa") and "running" in p.get("note", "") for p in adv["products"]),
      "NVD 'running on' (vulnerable:false) platform rows skipped")
cp = next(p for p in adv["products"] if p["product"] == "Apache Log4j2")
check(cp["ranges"] == ">=2.0-beta9 <2.3.1; >=2.4 <2.12.2; >=2.13.0 <2.15.0" and "Log4j2" in cp["terms"],
      "CVE.org: lessThan ranges, and the name without the vendor word as a search term")
op = {p["product"]: p for p in adv["products"]}
check(op["never-fixed-lib"]["ranges"] == ">=1.2.0", "OSV: introduced but never fixed → open range")
check(op["org.ops4j.pax.logging:pax-logging-log4j2"]["ranges"] == "<=1.9.2", "OSV: introduced 0 → last_affected")
check("log4j-scanner" not in op, "OSV: GIT commit ranges skipped (not comparable)")
calls.clear()
b, s = launcher.dispatch("ex_software", "lookup_fetch", {"urls": ["https://vendor.example/adv"], "confirm": True})
v = b["result"]["visits"][0]
check(v["ok"] and v["how"] == "none" and "no model" in v.get("note", ""),
      "a plain web page without a model: read, but not guessed at")

advisory.get = real_get
for u in ("http://127.0.0.1/x", "http://169.254.169.254/latest/meta-data", "https://10.1.2.3/", "http://[::1]/",
          "https://example.com:8443/", "file:///etc/passwd", "https://user:pw@example.com/", "ftp://example.com/"):
    try:
        advisory.check_url(u)
        check(False, "%s should be blocked" % u)
    except advisory.Blocked:
        check(True, "blocked: %s" % u)
calls.clear()
b, s = launcher.dispatch("ex_software", "lookup_fetch", {"urls": ["http://127.0.0.1:80/admin"], "confirm": True})
check(b["result"]["visits"][0]["error"].startswith("blocked"), "lookup_fetch: a loopback URL is blocked, not read")

mp = advisory.clean_model_products([{"vendor": "Ivanti", "product": "Connect Secure", "ranges": "<22.7R2.5",
                                      "terms": ["ivanti connect secure"]},
                                     {"product": "Policy Secure", "ranges": "versions before 22.7"},
                                     {"vendor": "x"}, "junk"])
check(len(mp) == 2 and mp[0]["ranges"] == "<22.7R2.5", "model products: a valid range kept")
check(mp[1]["ranges"] == "" and "could not be read" in mp[1]["note"], "model products: prose 'range' → note, not used")
txt = advisory.page_text(open(os.path.join(FX, "advisory_page.html")).read(), "text/html")
check("ignore me" not in txt and "9.1R18.6" in txt, "page text: scripts stripped, content kept")

# ── 6. registration ───────────────────────────────────────────────────────────
cj = open(os.path.join(ROOT, "web", "assets", "console.js"), encoding="utf-8").read()
check("['🔎 Software','/agents/ex_software/page.html']" in cj, "SEARCH_PAGES has Software")
check("ex_software:{name:'Harrier'" in cj and "ex_software:{does:" in cj, "codename + intro in console.js")
check("/agents/ex_software/page.html" in open(os.path.join(ROOT, "web", "search.html"), encoding="utf-8").read(),
      "search.html card")
check("ex_software" in launcher._NOCACHE_AGENTS, "launcher: never serves a remembered search")
mf = json.load(open(os.path.join(ROOT, "agents", "ex_software", "manifest.json")))
check(mf["codename"] == "Harrier" and set(mf["actions"]) == {"status", "search", "export", "lookup_plan", "lookup_fetch"},
      "manifest: Harrier + actions")
from core import downloads  # noqa: E402
src = downloads.get("zeroday_lookup")
check(src and src["approval"] is False, "listed in Settings' sources, NOT covered by auto-approve")
page = open(os.path.join(ROOT, "agents", "ex_software", "page.html"), encoding="utf-8").read()
check("confirm:true" in page and "on:false" in page, "page: sites start unticked; fetch sends confirm:true")

print()
print("%d failure(s)" % len(fails) if fails else "ALL PASS")
sys.exit(1 if fails else 0)
