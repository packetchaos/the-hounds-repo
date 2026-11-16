"""Wave 2 quick wins (build 455) — Argos, Command & Control, Custom Apps, Exposure Routes at scale.

Each hound must give the SAME answers as before while reading only what it needs:
  * Argos: one asset's findings in ONE index lookup (never `output` for lists), every vulns
    statement filtered by asset_uuid (a SEARCH on hx_v_asset when ⚡ Optimize built it), the
    at-a-glance numbers equal to the old per-statement SQL, software matched without a
    `LIKE '%uuid%'` scan unless the table really holds stringified uuid lists.
  * C2: the host list is a server-side search (keyset pages ≤ 200) whose pages add up to the
    old full list; counts / glance equal the old Python classification; plan() is
    plugin-first through hx_v_plugin (no LIKE over vulns, no output) with the same answer;
    precheck / verify / target inventory unchanged.
  * Custom Apps + Exposure Routes: only the route plugins' (plugin, asset) pairs are read
    (no DISTINCT over every pair in vulns); results identical with and without the indexes.
Synthetic navi.db in a temp dir (plus an ⚡ Optimized copy); no navi, no network.
Run: python3 tests/test_wave2_quickwins.py  (or pytest)."""
import atexit
import json
import os
import re
import shutil
import sqlite3
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
TMP = tempfile.mkdtemp(prefix="hounds-w2q-")
atexit.register(shutil.rmtree, TMP, ignore_errors=True)
os.environ["NAVI_CACHE_DIR"] = os.path.join(TMP, "cache")
os.environ["NAVI_TAGLOG_DB"] = os.path.join(TMP, "taglog.db")
os.environ["HOUNDS_CONFIG"] = os.path.join(TMP, "cfg.json")
os.environ["CUSTOMAPP_IGNORE_PATH"] = os.path.join(TMP, "ignore.json")
PLAIN = os.path.join(TMP, "plain.db")
IDX = os.path.join(TMP, "idx.db")
os.environ["NAVI_DB_PATH"] = PLAIN

fails = []


def check(cond, msg):
    print(("PASS " if cond else "FAIL ") + msg)
    if not cond:
        fails.append(msg)


def ago(days):
    return time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime(time.time() - days * 86400))


# --------------------------------------------------------------------------- fixture
c = sqlite3.connect(PLAIN)
c.executescript("""
CREATE TABLE assets (uuid TEXT UNIQUE, hostname TEXT, ip_address TEXT, operating_system TEXT, acr TEXT,
                     fqdn TEXT, network TEXT, aes TEXT, url TEXT);
CREATE TABLE vulns (finding_id TEXT PRIMARY KEY, asset_uuid TEXT, plugin_id TEXT, plugin_name TEXT, plugin_family TEXT,
                    severity TEXT, score TEXT, xrefs TEXT, state TEXT, first_found TEXT, last_found TEXT,
                    cves TEXT, output TEXT, port TEXT, protocol TEXT);
CREATE TABLE tags (asset_uuid TEXT, tag_key TEXT, tag_value TEXT, tag_uuid TEXT);
CREATE TABLE vuln_route (route_id TEXT, app_name TEXT, vuln_type TEXT, total_vulns INTEGER, plugin_list TEXT);
CREATE TABLE vuln_paths (path TEXT, asset_uuid TEXT, plugin_id TEXT, finding_id TEXT);
CREATE TABLE software (asset_uuid TEXT, software_string TEXT);
CREATE TABLE certs (asset_uuid TEXT, common_name TEXT, not_valid_after TEXT, signature_algorithm TEXT,
                    key_length TEXT, algorithm TEXT);
CREATE TABLE compliance (asset_uuid TEXT, check_name TEXT, status TEXT);
CREATE TABLE plugins (plugin_id TEXT PRIMARY KEY, name TEXT, cves TEXT, solution TEXT, cvss3_base_score TEXT);
""")
OS = ["Ubuntu 22.04", "Red Hat Enterprise Linux 8", "Microsoft Windows Server 2019", "Cisco IOS 15", "",
      "VMware ESXi 7", "Debian 12", None]
# plugins: id → (name, family, cves) — constant per plugin, as Tenable stores them
PL = {"19506": ("Nessus Scan Information", "Settings", ""),
      "11000": ("OpenSSL Unsupported Version Detection", "General", "['CVE-2016-2107']"),
      "11001": ("Apache Tomcat < 9.0.1 RCE", "Web Servers", "['CVE-2021-44228', 'CVE-2021-45046']"),
      "11002": ("Ubuntu USN-1: sudo vulnerability", "Ubuntu Local Security Checks", "['CVE-2021-3156']"),
      "11003": ("Jenkins < 2.1 Multiple Vulnerabilities", "CGI abuses", "['CVE-2024-23897']"),
      "11004": ("Windows KB500 Update", "Windows : Microsoft Bulletins", "['CVE-2017-0144']"),
      "11005": ("SSL Certificate Cannot Be Trusted", "General", ""),
      "11006": ("Custom Widget End of Life", "General", "")}
c.executemany("INSERT INTO plugins VALUES (?,?,?,?,?)",
              [(k, v[0], v[2], "Upgrade to version 9.0.1 or later.", "7.5") for k, v in PL.items() if k != "11006"])
fid = 0
for i in range(240):
    u = "a%07d-0000-0000-0000-%012d" % (i, i)
    osn = OS[i % len(OS)]
    ip = "" if i % 17 == 0 else ("10.0.%d.%d" % (i // 200, i % 200) + (" " if i % 23 == 0 else ""))
    c.execute("INSERT INTO assets VALUES (?,?,?,?,?,?,?,?,?)",
              (u, "host%03d" % i, ip, osn, str((i % 10) + 1) if i % 7 else "", "", "", "", ""))
    for pid in PL:
        if (i + int(pid)) % 3 == 0 or pid == "19506":
            fid += 1
            st = ["open", "reopened", "fixed", None][(i + fid) % 4]
            sev = ["critical", "high", "medium", "info"][(i + int(pid)) % 4]
            out = ("Scan Start Date : 2026/1/2 10:00 UTC\nScan name : weekly\nCredentialed checks : yes"
                   if pid == "19506" else "<html><body>x</body></html>" * (pid == "11005"))
            c.execute("INSERT INTO vulns VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                      ("f%d" % fid, u, pid, PL[pid][0], PL[pid][1], sev, str((i % 9) + 0.5),
                       "CISA-KNOWN-EXPLOITED" if pid == "11001" else "", st, ago(5 + (i % 50)), ago(1),
                       PL[pid][2], out, "443", "tcp"))
    if i % 5 == 0:
        c.execute("INSERT INTO tags VALUES (?,?,?,?)", (u, "Owner", "Apache Tomcat: alice", "t1"))
    if i % 11 == 0:
        c.execute("INSERT INTO tags VALUES (?,?,?,?)", (u, "Owner", "/opt/legacy: Accepted", "t2"))
        c.execute("INSERT INTO vuln_paths VALUES ('/opt/legacy', ?, '11002', 'x')", (u,))
    if i % 4 == 0:
        c.execute("INSERT INTO vuln_paths VALUES (?, ?, '11003', 'y')", ("/var/lib/jenkins/war/%d" % (i % 3), u))
        c.execute("INSERT INTO vuln_paths VALUES (?, ?, '11006', 'z')", ("/opt/widgetsrv/bin", u))
    c.execute("INSERT INTO software VALUES (?, ?)", (u, "openssl-1.0.2k-1.el7"))
    if i % 9 == 0:
        c.execute("INSERT INTO certs VALUES (?,?,?,?,?,?)", (u, "rsa%d" % i, "Dec 12 20:57:22 2030 GMT",
                                                            "SHA-1 With RSA Encryption", "1024 bits", "RSA"))
    c.execute("INSERT INTO compliance VALUES (?, 'c1', ?)", (u, "PASSED" if i % 2 else "FAILED"))
c.executemany("INSERT INTO vuln_route VALUES (?,?,?,?,?)",
              [("1", "Apache Tomcat", "Web", 40, "['11001', '19999']"),
               ("2", "Jenkins", "CI", 20, "['11003']"),
               ("3", "OpenSSL", "Library", 10, "['11000']"),
               ("4", "Widget Server", "Custom", 5, "['11006']")])
c.commit()
c.close()
shutil.copy(PLAIN, IDX)
from core import db, hx_optimize  # noqa: E402
hx_optimize.optimize(IDX)
check(db.has_index("hx_v_asset", IDX) and db.has_index("hx_v_plugin", IDX) and not db.has_index("hx_v_asset", PLAIN),
      "fixture: an un-optimized navi.db and an ⚡ Optimized copy")

# statement capture (expanded SQL, as SQLite runs it)
TRACE = []
_open = db._open


def _traced(p):
    con = _open(p)
    con.set_trace_callback(lambda s: TRACE.append(" ".join(s.split())))
    return con


db._open = _traced


def use(path):
    os.environ["NAVI_DB_PATH"] = path
    db.close_all()
    TRACE.clear()


def vulns_stmts():
    return [s for s in TRACE if re.search(r"\bFROM vulns\b", s, re.I)]


def plan_of(path, sql):
    con = sqlite3.connect("file:%s?mode=ro" % path, uri=True)
    con.create_function("_cert_days", 1, lambda x: None)
    try:
        return " | ".join(r[3] for r in con.execute("EXPLAIN QUERY PLAN " + sql))
    finally:
        con.close()


from agents.argos import api as A  # noqa: E402
from agents.c2 import api as C2  # noqa: E402
from core import c2_targets  # noqa: E402
from agents.customapp.agent import CustomAppAgent  # noqa: E402
from agents.exproute import agent as E  # noqa: E402

U = "a0000055-0000-0000-0000-000000000055"     # an asset with every kind of finding
U2 = "a0000011-0000-0000-0000-000000000011"    # carries the '/opt/legacy: Accepted' disposition

# --------------------------------------------------------------------------- Argos
res = {}
for path in (PLAIN, IDX):
    use(path)
    out = [A.lookup({"target": t})[0] for t in (U, U2, "10.0.0.55", "host077")]
    res[path] = out
    vs = vulns_stmts()
    check(all("asset_uuid" in s for s in vs),
          "Argos (%s): every vulns statement is filtered by asset_uuid (%d statements)"
          % (os.path.basename(path), len(vs)))
    wide = [s for s in vs if re.search(r"SELECT[^;]*\boutput\b", s, re.I) and "plugin_id" not in s.split("WHERE", 1)[-1]]
    check(not wide, "Argos (%s): `output` is read only for specific plugins, never for the findings list %s"
          % (os.path.basename(path), wide[:1]))
    check(not any("software" in s and "LIKE" in s for s in TRACE),
          "Argos (%s): single-uuid software table → no LIKE '%%uuid%%' scan" % os.path.basename(path))
def _norm(rs):
    # row order of tags / findings with equal sort keys follows the access path (table vs
    # index) — the same in build 454; compare as multisets
    out = []
    for r in rs:
        r = dict(r)
        for k in ("tags", "top_vulns"):
            if isinstance(r.get(k), list):
                r[k] = sorted(json.dumps(x, sort_keys=True, default=str) for x in r[k])
        out.append(r)
    return out


res = {k: _norm(v) for k, v in res.items()}
_d = [k for k in res[PLAIN][0] if json.dumps(res[PLAIN][0][k], sort_keys=True, default=str)
      != json.dumps(res[IDX][0][k], sort_keys=True, default=str)]
check(json.dumps(res[PLAIN], sort_keys=True, default=str) == json.dumps(res[IDX], sort_keys=True, default=str),
      "Argos: identical dossiers with and without the indexes %s" % _d)
use(IDX)
A.lookup({"target": U})
scans = [s for s in vulns_stmts() if "SCAN vulns" in plan_of(IDX, s)]
check(not scans, "Argos (optimized): every vulns statement is an index SEARCH, no SCAN vulns %s" % scans[:1])
main = [s for s in vulns_stmts() if "_st" in s]
check(len(main) == 1 and "output" not in main[0].split("FROM")[0],
      "Argos: the asset's findings + at-a-glance rows come from ONE statement without `output`")

# at-a-glance == the old per-statement SQL
use(PLAIN)
for u in (U, U2):
    g = A._glance(u, [])
    con = sqlite3.connect(PLAIN)
    op = "lower(COALESCE(state,'open')) IN ('open','reopened')"
    crit = con.execute(f"SELECT COUNT(*) FROM vulns WHERE asset_uuid=? AND {op} AND severity='critical'", (u,)).fetchone()[0]
    kev = con.execute(f"SELECT COUNT(*) FROM vulns WHERE asset_uuid=? AND {op} AND upper(xrefs) LIKE '%CISA-KNOWN-EXPLOITED%'", (u,)).fetchone()[0]
    eol = con.execute(f"SELECT COUNT(DISTINCT plugin_id) FROM vulns WHERE asset_uuid=? AND {op} AND "
                      "(lower(plugin_name) LIKE '%unsupported%' OR lower(plugin_name) LIKE '%end of life%' OR "
                      "lower(plugin_name) LIKE '%end-of-life%' OR lower(plugin_name) LIKE '%no longer supported%')", (u,)).fetchone()[0]
    con.close()
    check(g["findings"]["critical"] == crit and g["findings"]["kev"] == kev and g["eol"]["findings"] == eol,
          "Argos glance %s: critical/KEV/EOL from the merged rows == the old SQL (%s/%s/%s)" % (u[:5], crit, kev, eol))
    from core import sla as _sla
    con = db.connect()
    want = _sla.dispositions(con).get(u, set())
    con.close()
    check(A._asset_dispositions(u, _sla) == want,
          "Argos: per-asset dispositions == core.sla.dispositions()[asset] (%s)" % sorted(want))

# stringified-list software rows still match (and only then is the LIKE used)
L = os.path.join(TMP, "list.db")
shutil.copy(PLAIN, L)
cx = sqlite3.connect(L)
cx.execute("INSERT INTO software VALUES (?, 'nginx-1.20.1-1')", ("['%s', 'b0000-x']" % U,))
cx.commit()
cx.close()
use(L)
sw, _src = A._software_for(U)
check({s["name"] for s in sw} >= {"nginx", "openssl"} and any("LIKE" in s for s in TRACE if "software" in s),
      "Argos: a stringified uuid-list software row is still found (LIKE used only on such a table)")

# --------------------------------------------------------------------------- C2

def old_hosts(path):
    use(path)
    allh = C2._hosts_raw()
    lin = [h for h in allh if h["os_class"] == "linux" and h["ip"]]
    oth = [h for h in allh if not (h["os_class"] == "linux" and h["ip"])]
    return allh, lin, oth


for path in (PLAIN, IDX):
    allh, lin, oth = old_hosts(path)
    use(path)
    o, _ = C2.hosts({})
    pages, nxt = list(o["linux"]), o["next"]
    while nxt is not None:
        o2, _ = C2.hosts({"after": nxt, "limit": 7})
        if len(o2["linux"]) > 7:
            check(False, "C2 hosts: a page never exceeds its limit")
        pages += o2["linux"]
        nxt = o2["next"]
    check(pages == lin, "C2 hosts (%s): keyset pages add up to the old full Linux list, same order (%d)"
          % (os.path.basename(path), len(lin)))
    check(len(o["linux"]) <= 50 and o["linux_count"] == len(lin) and o["excluded_count"] == len(oth)
          and o["excluded_breakdown"] == C2._breakdown(oth),
          "C2 hosts: first page ≤ 50, counts + excluded breakdown == the old classification")
    q, _ = C2.hosts({"q": "HOST07"})
    exp = [h for h in lin if "host07" in (h["ip"] + " " + h["hostname"] + " " + h["os"]).lower()]
    check(q["linux"] == exp[:50], "C2 hosts: q searches ip/hostname/os server-side like the old filter (%d)" % len(exp))
    u, _ = C2.hosts({"q": lin[3]["uuid"]})
    check([h["uuid"] for h in u["linux"]] == [lin[3]["uuid"]], "C2 hosts: exact uuid search")
    big, _ = C2.hosts({"limit": 100000})
    check(len(big["linux"]) <= 200, "C2 hosts: limit is capped at 200")
    g, _ = C2.glance({})
    check(g["linux_hosts"] == len(lin), "C2 glance: Linux host count == the old full read (%d)" % len(lin))
    for t in [lin[0]["ip"], oth[1]["uuid"], "10.0.0.23", "9.9.9.9"]:
        pc, _ = C2.precheck({"target": t, "command": "uptime"})
        old = next((h for h in allh if h["ip"] == t or h["uuid"] == t), None)
        check(pc["host"] == old, "C2 precheck %s: same host as the old full scan" % t)
    ips = [h["ip"] for h in allh[:30] if h["ip"]] + [allh[40]["uuid"]]
    v, _ = C2.verify({"selector": "11001", "hosts": ips})
    exp_n = len([h for h in allh if h["ip"] in ips or h["uuid"] in ips])
    check(v["checked_hosts"] == exp_n, "C2 verify: same hosts checked (%d)" % exp_n)
    ex = c2_targets.expand([lin[0]["ip"], "HOST002", "10.0.0.23", "8.8.8.8"])
    inv = c2_targets._inventory()
    for t in ex["targets"]:
        a = inv.get(t["target"].lower())
        want = {k: a.get(k) for k in ("uuid", "hostname", "ip", "os", "os_class", "acr", "crown")} if a else None
        check(t["asset"] == want, "C2 targets: %s resolves like the old full inventory" % t["target"])

plans = {}
for path in (PLAIN, IDX):
    use(path)
    C2._SIG_CACHE.clear()
    plans[path] = {s: C2.plan({"selector": s})[0] for s in
                   ("11001", "openssl", "CVE-2021-3156", "Ubuntu Local Security", "ssl_cert", "zzz", "19506")}
    if path == IDX:
        st = vulns_stmts()
        check(not any("LIKE" in s for s in st), "C2 plan (optimized): no LIKE over vulns — plugin-first")
        check(not any(re.search(r"\boutput\b", s) for s in st), "C2 plan: never reads vulns.output")
        check(all("SCAN vulns USING COVERING INDEX" in plan_of(IDX, s) or "SEARCH" in plan_of(IDX, s)
                  for s in st if "json_each" in s),
              "C2 plan: matched plugins' findings read through hx_v_plugin")
for s in plans[PLAIN]:
    a, b = plans[PLAIN][s], plans[IDX][s]
    check(json.dumps(a, sort_keys=True, default=str) == json.dumps(b, sort_keys=True, default=str),
          "C2 plan %r: plugin-first answer == the row-level scan (%s assets, %s Linux)"
          % (s, a.get("matched_assets"), a.get("linux_count")))
check(all(p_["linux_count"] == len(p_["linux_hosts"]) for p_ in plans[IDX].values() if p_.get("ok") and not p_["truncated"]),
      "C2 plan: linux_count is exact")
check(len(plans[IDX]["19506"]["linux_hosts"]) <= C2._HOST_CAP, "C2 plan: host lists are capped")

# --------------------------------------------------------------------------- Custom Apps
cres = {}
for path in (PLAIN, IDX):
    use(path)
    cres[path] = CustomAppAgent()._run(db_path=path)
    st = vulns_stmts()
    check(st and all("plugin_id IN" in s for s in st),
          "Custom Apps (%s): vulns read only for the candidate routes' plugins" % os.path.basename(path))
check(json.dumps(cres[PLAIN], sort_keys=True, default=str) == json.dumps(cres[IDX], sort_keys=True, default=str),
      "Custom Apps: identical result with and without the indexes")
con = sqlite3.connect(PLAIN)
tom = {r[0] for r in con.execute("SELECT DISTINCT asset_uuid FROM vulns WHERE plugin_id IN ('11001','19999')")}
own = {r[0] for r in con.execute("SELECT asset_uuid FROM tags WHERE tag_key='Owner'")}
crown = {r[0] for r in con.execute("SELECT uuid FROM assets WHERE acr<>'' AND CAST(acr AS REAL)>=7")}
con.close()
tc = next((x for x in cres[PLAIN]["candidates"] if x["name"] == "Apache Tomcat"), None)
check(tc is not None and tc["assets"] == len(tom) and tc["unowned"] == len(tom - own) and tc["crown"] == len(tom & crown),
      "Custom Apps: route assets / unowned / crown == direct SQL (%s/%s/%s)"
      % (len(tom), len(tom - own), len(tom & crown)))

# --------------------------------------------------------------------------- Exposure Routes
eres = {}
for path in (PLAIN, IDX):
    use(path)
    b = E._base(path)
    om = E.ownership_map(path, base=b)
    cov = E.coverage(path, base=b, om=om, users_total=0)
    eres[path] = (om, cov, {k: sorted(map(str, v)) for k, v in b["route_assets"].items()})
    st = vulns_stmts()
    check(not any(re.fullmatch(r"SELECT DISTINCT plugin_id, asset_uuid FROM vulns", s) for s in st),
          "Exposure Routes (%s): no DISTINCT over every (plugin, asset) pair" % os.path.basename(path))
check(json.dumps(eres[PLAIN], sort_keys=True, default=str) == json.dumps(eres[IDX], sort_keys=True, default=str),
      "Exposure Routes: identical ownership map / coverage with and without the indexes")
con = sqlite3.connect(PLAIN)
pairs = con.execute("SELECT DISTINCT plugin_id, asset_uuid FROM vulns").fetchall()
con.close()
naive = {}
for pid, au in pairs:
    for app, pl in (("Apache Tomcat", {"11001", "19999"}), ("Jenkins", {"11003"}), ("OpenSSL", {"11000"}),
                    ("Widget Server", {"11006"})):
        if pid in pl:
            naive.setdefault(app, set()).add(au)
check(eres[PLAIN][2] == {k: sorted(v) for k, v in naive.items()},
      "Exposure Routes: route → assets == the old every-pair computation")
use(IDX)
b = E._base(IDX)
check(E.plugin_assets(b, "11005", IDX) == len({au for pid, au in pairs if pid == "11005"}),
      "Exposure Routes: champion asset count by one index lookup == the pair count")


def test_wave2_quickwins():
    assert not fails, "\n".join(fails)


if __name__ == "__main__":
    print(f"\n{len(fails)} failure(s)")
    sys.exit(1 if fails else 0)
