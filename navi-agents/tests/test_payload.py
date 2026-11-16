"""The page payload contract (build 455) — core/payload.py + the four hounds that adopted it
first (Software, Certificates, AI Inventory, Asset Ownership) + core/pagecache summary entries.

Checks: cap() never ships more than the byte cap / 200 rows; next-tokens are signed and bound
to their query; keyset paging over the result store equals a Python sort (ties included) and
never repeats or skips a row; filters / search / counts; expired runs; the drill action
validates every input; each hound's ▶ Run response has no asset-UUID arrays, stays ≤ 2 MB and
carries the same headline numbers as the full engine result; tag KEYS rebuild the right asset
sets on the server; the page cache keeps a summary entry instead of dropping an oversized run.
Tiny synthetic navi.db in a temp dir; navi is never called (writes are gated off, the tag
queue is a temp file). Run: python3 tests/test_payload.py  (or pytest)."""
import atexit
import datetime
import json
import os
import random
import re
import shutil
import sqlite3
import sys
import tempfile
import uuid as _uuid

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
TMP = tempfile.mkdtemp(prefix="hounds-payload-")
atexit.register(shutil.rmtree, TMP, ignore_errors=True)
os.environ["NAVI_CACHE_DIR"] = os.path.join(TMP, "cache")
os.environ["NAVI_TAGLOG_DB"] = os.path.join(TMP, "tl.db")
os.environ.pop("NAVI_ALLOW_WRITES", None)
DB = os.path.join(TMP, "navi.db")
os.environ["NAVI_DB_PATH"] = DB

fails = []


def check(cond, msg):
    print(("PASS " if cond else "FAIL ") + msg)
    if not cond:
        fails.append(msg)


UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)


def uuid_arrays(o, path="$", out=None):
    """Paths of every list holding more than one asset-UUID string (the contract forbids them)."""
    out = [] if out is None else out
    if isinstance(o, list):
        if sum(1 for x in o if isinstance(x, str) and UUID_RE.match(x)) > 1:
            out.append(path)
        for x in o:
            uuid_arrays(x, path + "[]", out)
    elif isinstance(o, dict):
        for k, v in o.items():
            uuid_arrays(v, path + "." + str(k), out)
    return out


def longest_list(o):
    if isinstance(o, list):
        return max([len(o)] + [longest_list(x) for x in o])
    if isinstance(o, dict):
        return max([0] + [longest_list(v) for v in o.values()])
    return 0


def size(o):
    return len(json.dumps(o, default=str, separators=(",", ":")).encode())


# ------------------------------------------------------------------ fixture navi.db
random.seed(455)
N_ASSETS = 900
U = [str(_uuid.UUID(int=random.getrandbits(128))) for _ in range(N_ASSETS)]
today = datetime.date.today()
c = sqlite3.connect(DB)
c.executescript("""
CREATE TABLE assets(uuid TEXT, hostname TEXT, ip_address TEXT, acr TEXT, aes INTEGER, url TEXT);
CREATE TABLE vulns(asset_uuid TEXT, plugin_id TEXT, plugin_name TEXT, plugin_family TEXT, output TEXT, port TEXT,
                   severity TEXT, xrefs TEXT, score TEXT, state TEXT, last_found TEXT, url TEXT);
CREATE TABLE software(asset_uuid TEXT, software_string TEXT);
CREATE TABLE cpes(asset_uuid TEXT, cpe_string TEXT);
CREATE TABLE tags(asset_uuid TEXT, tag_key TEXT, tag_value TEXT);
CREATE TABLE certs(asset_uuid TEXT, common_name TEXT, organization TEXT, organization_unit TEXT, not_valid_after TEXT,
                   not_valid_before TEXT, issuer_name TEXT, subject_name TEXT, signature_algorithm TEXT, key_length TEXT);
CREATE TABLE vuln_route(app_name TEXT, plugin_list TEXT);
CREATE TABLE vuln_paths(asset_uuid TEXT, plugin_id TEXT, path TEXT);
""")
for i, u in enumerate(U):
    c.execute("INSERT INTO assets VALUES (?,?,?,?,0,'')", (u, "host%03d" % i, "10.0.%d.%d" % (i // 250, i % 250),
                                                           str(random.choice([1, 3, 5, 7, 8, 9, 10]))))
    for _ in range(3):
        pid = random.choice(["100", "200", "300", "400"])
        name = {"100": "Apache HTTP Server < 2.4 Multiple Vulnerabilities", "200": "OpenSSL Unsupported Version",
                "300": "Ollama API Detection", "400": "SSL Certificate Expiry"}[pid]
        c.execute("INSERT INTO vulns VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                  (u, pid, name, "General", "port 11434 requires no authentication" if pid == "300" else "x",
                   "11434" if pid == "300" else "0", random.choice(["critical", "high", "4", "low"]),
                   "CISA-KNOWN-EXPLOITED:2023" if pid == "100" else "", {"100": "9.1", "200": "6.0", "300": "5.0", "400": "2.0"}[pid],
                   "open", "2026-01-01", ""))
    for _ in range(2):
        n = random.choice(["openssl", "httpd", "postgresql-server", "kernel", "chromadb"])
        c.execute("INSERT INTO software VALUES (?,?)", (u, "%s-%s-1.el8" % (n, random.choice(["1.0.2k", "1.1.1", "3.0.7", "2.4.6"]))))
    if i % 7 == 0:
        c.execute("INSERT INTO cpes VALUES (?,?)", (u, "['cpe:/a:nginx:nginx:1.20', 'p-cpe:/a:redhat:enterprise_linux:openssl:1.0.2k']"))
    for _ in range(random.choice([0, 1, 2])):
        d = today + datetime.timedelta(days=random.randint(-500, 400))
        nva = d.strftime("%b %d 12:00:00 %Y GMT") if random.random() < .5 else d.isoformat()
        cn = random.choice(["nessus.local", "chromecast", "web.example", "ubnt camera"])
        c.execute("INSERT INTO certs VALUES (?,?,?,?,?,?,?,?,?,?)", (u, cn, "Org", "OU", nva, "", "CN=" + cn, "CN=" + cn,
                                                                     random.choice(["sha256WithRSA", "sha1WithRSA"]),
                                                                     random.choice(["2048", "1024"])))
    if i % 5 == 0:
        c.execute("INSERT INTO tags VALUES (?,?,?)", (u, "Business Owner", "Jane"))
    if i % 11 == 0:
        c.execute("INSERT INTO tags VALUES (?,?,?)", (u, "Owner", "Apache: Web Team"))
    if i % 13 == 0:
        c.execute("INSERT INTO tags VALUES (?,?,?)", (u, "CISA KEV", "Vulnerable"))
    if i % 9 == 0:
        c.execute("INSERT INTO vuln_paths VALUES (?,?,?)", (u, "100", "/opt/app%d" % (i % 3)))
c.execute("INSERT INTO vuln_route VALUES ('Apache', \"['100', '999']\")")
c.execute("INSERT INTO vuln_route VALUES ('OpenSSL', \"['200']\")")
c.commit()
c.close()

from core import pagecache, payload  # noqa: E402

# ------------------------------------------------------------------ 1. cap()
b = payload.response(summary={"n": 1}, top=list(range(1000)), rows=list(range(5000)), deep={"x": list(range(900))})
check(len(b["top"]) == 200 and len(b["rows"]) == 200 and len(b["deep"]["x"]) == 200 and b["meta"]["truncated"],
      "cap(): every list ≤ 200 rows, meta.truncated set")
big = {"top": [{"blob": "x" * 50000} for _ in range(150)]}
payload.cap(big, limit=2 * 1024 * 1024)
check(size(big) <= 2 * 1024 * 1024 and big["meta"]["truncated"] and len(big["top"]) < 150,
      "cap(): a 7.5 MB response is trimmed under 2 MB (%d rows kept)" % len(big["top"]))
small = payload.response(summary={"a": 1}, top=[1, 2])
check(not small["meta"].get("truncated") and small["top"] == [1, 2] and small["meta"]["bytes"] > 0, "cap(): small responses untouched")
check(payload.fmt_total(payload.total(10000, False)) == "10,000+" and payload.fmt_total(5) == "5", "totals format 10,000+")

# ------------------------------------------------------------------ 2. tokens
bind = {"run": "r", "sec": "s", "sort": "", "f": [], "q": ""}
tok = payload.make_token({"b": payload._bind_hash(bind), "k": [1, 2], "pos": 50})
check(payload.read_token(tok, bind)["pos"] == 50, "token round-trips")
for bad, why in ((tok[:-1] + ("0" if tok[-1] != "0" else "1"), "a forged signature"),
                 ("x" * 40 + "." + "0" * 32, "an unsigned token"), ("../../etc", "garbage"), (None, "no token")):
    try:
        payload.read_token(bad, bind)
        check(False, "token with %s is refused" % why)
    except payload.BadToken:
        check(True, "token with %s is refused" % why)
try:
    payload.read_token(tok, dict(bind, q="other"))
    check(False, "a token bound to another query is refused")
except payload.BadToken:
    check(True, "a token bound to another query is refused")

# ------------------------------------------------------------------ 3. the result store
S = payload.STORE
rows = [{"i": i, "acr": random.choice([1, 5, 9, None]), "name": "n%04d" % random.randint(0, 50)} for i in range(1234)]
with S.begin("testhound") as W:
    for r in rows:
        W.add("t", r, uid="u%d" % (r["i"] % 300), flags=["odd" if r["i"] % 2 else "even", "a%s" % r["acr"]],
              keys=(-(r["acr"] or 0), r["name"]), text=r["name"], rk=str(r["i"]))
    W.section("empty")
run = W.run


def walk(sort, flags=(), q="", lim=97):
    out, after, n = [], None, None
    while True:
        got, after, cnt, _ex = S.page(run, "t", sort=sort, flags=flags, q=q, limit=lim, after=after)
        n = cnt if n is None else n
        out += got
        if not after:
            return out, n


got, n = walk(("s1", "s2"))
want = sorted(rows, key=lambda r: (-(r["acr"] or 0), r["name"], r["i"]))
check([r["i"] for r in got] == [r["i"] for r in want] and n == len(rows),
      "keyset paging (sort acr↓, name) == Python sort, ties by row order, no row repeated/skipped (%d rows)" % len(got))
got, n = walk(None)
check([r["i"] for r in got] == list(range(len(rows))), "default order = the hound's own ranking (insertion)")
got, n = walk(("s1",), flags=["odd", "a9"])
want = [r for r in rows if r["i"] % 2 and r["acr"] == 9]
check(sorted(r["i"] for r in got) == sorted(r["i"] for r in want) and n == len(want), "filters AND together; count exact")
got, n = walk(None, q="N004")
check(n == sum(1 for r in rows if "n004" in r["name"]) and all("n004" in r["name"] for r in got), "search is case-insensitive substring")
check(S.section_total(run, "empty") == 0 and S.page(run, "empty")[2] == 0, "an empty section totals 0")
check(len(S.uids(run, "t")) == 300 and len(S.uids(run, "t", ["odd"])) == 150, "uids(): distinct asset set of a (filtered) section")
check(S.row(run, "t", "7")["i"] == 7 and S.row(run, "t", "nope") is None, "row(): lookup by key")
for _ in range(payload.KEEP_RUNS + 1):
    with S.begin("testhound") as W2:
        W2.add("t", {"i": 0})
check(S.run_info(run, "testhound") is None, "older runs are pruned (KEEP_RUNS=%d per hound)" % payload.KEEP_RUNS)
check(S.run_info(W2.run, "testhound") and S.run_info(W2.run, "otherhound") is None, "a run belongs to its hound only")

# ------------------------------------------------------------------ 4. the drill action validates everything
with S.begin("testhound") as W3:
    for r in rows:
        W3.add("t", r, flags=["odd" if r["i"] % 2 else "even"], keys=(-(r["acr"] or 0),))
SEC = {"t": {"sorts": {"acr": ("s1",)}, "flags": {"odd", "even"}}}
d, code = payload.drill("testhound", {"run": W3.run, "section": "t", "sort": "acr", "limit": 50}, SEC)
check(code == 200 and len(d["top"]) == 50 and d["page"]["next"] and d["total"]["value"] == len(rows), "drill: first page + token")
d2, code = payload.drill("testhound", {"run": W3.run, "section": "t", "sort": "acr", "limit": 50, "next": d["page"]["next"]}, SEC)
check(code == 200 and d2["page"]["start"] == 50 and {r["i"] for r in d2["top"]}.isdisjoint({r["i"] for r in d["top"]}),
      "drill: next page starts at row 51 and repeats nothing")
for p, why in (({"section": "zz"}, "unknown section"), ({"sort": "x"}, "unknown sort"), ({"filter": ["evil"]}, "unknown filter"),
               ({"q": "x" * 500}, "an over-long search"), ({"next": d["page"]["next"], "filter": ["odd"]}, "a token from another query"),
               ({"next": "abc"}, "a malformed token")):
    body, code = payload.drill("testhound", dict({"run": W3.run, "section": "t", "sort": "acr"}, **p), SEC)
    check(code == 400 and not body["ok"], "drill refuses %s" % why)
body, code = payload.drill("testhound", {"run": "testhound-0123456789abcdef", "section": "t"}, SEC)
check(body.get("expired") and not body["ok"], "drill on a pruned / unknown run → expired (press ▶ Run)")
body, code = payload.drill("other", {"run": W3.run, "section": "t"}, SEC)
check(body.get("expired"), "drill on another hound's run is refused")
n, ex = payload.capped_count("SELECT 1 FROM vulns", cap=100)
check((n, ex) == (100, False), "capped_count probes cap+1 rows → (cap, inexact)")
n, ex = payload.capped_count("SELECT 1 FROM assets WHERE acr='10'", cap=10000)
check(ex and n == sum(1 for _ in sqlite3.connect(DB).execute("SELECT 1 FROM assets WHERE acr='10'")), "capped_count exact under the cap")


# ------------------------------------------------------------------ 5. the four hounds
def contract_ok(name, body):
    arr = uuid_arrays(body)
    check(not arr, "%s: no asset-UUID arrays in the payload (%s)" % (name, ", ".join(arr[:3]) or "none"))
    check(size(body) <= payload.MAX_BYTES and longest_list(body) <= payload.TOP_MAX,
          "%s: ≤ 2 MB (%d bytes) and no list > 200 rows" % (name, size(body)))
    check(isinstance(body.get("drill"), dict) and body["drill"].get("run") and isinstance(body.get("total"), dict),
          "%s: drill handle + total" % name)


# --- Certificates
from agents.certificate import api as CA, agent as CAg  # noqa: E402
body, code = CA.run({})
contract_ok("certificate.run", body)
full = CAg.CertificateAgent()._run(None)
check(body["result"]["metrics"] == full["metrics"] and body["summary"] == full["metrics"], "certificate: metrics == the engine's")
check("tag_actions" not in body["result"] and "expired" not in body["result"] and "iot_app_cache" not in body["result"],
      "certificate: no certificate / IoT / tag-action lists in the payload")
crun = body["drill"]["run"]
allc, after = [], None
while True:
    d, _c = CA.drill({"run": crun, "section": "certs", "sort": "near", "limit": 200, **({"next": after} if after else {})})
    allc += d["top"]
    after = d["page"]["next"]
    if not after:
        break
m = body["summary"]
check(len(allc) == m["expired"] + m["failing"], "certificate: paging walks every expired/failing cert (%d)" % len(allc))
check([abs(x["days_left"]) for x in allc] == sorted(abs(x["days_left"]) for x in allc), "certificate: closest to today first")
d, _c = CA.drill({"run": crun, "section": "certs", "sort": "near", "filter": ["expired", "crown"]})
check(d["total"]["value"] == sum(1 for x in allc if x["status"] == "expired" and x["crown"]), "certificate: filters = the page's")
dv, _c = CA.dates({"run": crun, "filter": ["failing"]})
check(set(dv["values"]) == {x["tag_value"] for x in allc if x["status"] == "failing"}, "certificate: 'Select shown' dates = the view's")
dc, _c = CA.dates({"run": crun, "values": dv["values"][:3]})
want = [x for x in allc if x["tag_value"] in dv["values"][:3]]
check(dc["certs"] == len(want) and dc["assets"] == len({x["asset_uuid"] for x in want}), "certificate: selection counts")

# --- Software
from agents.software import api as SA  # noqa: E402
from core import software as SW  # noqa: E402
body, code = SA.inventory({})
contract_ok("software.inventory", body)
srun = body["drill"]["run"]
check(body["summary"]["nasset"] == N_ASSETS and body["summary"]["nprod"] >= 5, "software: KPIs (assets inventoried, products)")
allp, after = [], None
while True:
    d, _c = SA.drill({"run": srun, "section": "products", "view": "common", "limit": 3, **({"next": after} if after else {})})
    allp += d["top"]
    after = d["page"]["next"]
    if not after:
        break
check(len(allp) == body["summary"]["nprod"] and [p["nasset"] for p in allp] == sorted((p["nasset"] for p in allp), reverse=True),
      "software: 'Most deployed' view pages every product, most assets first")
ossl = next(p for p in allp if p["name"] == "openssl")
real = {r[0] for r in sqlite3.connect(DB).execute("SELECT asset_uuid FROM software WHERE software_string LIKE 'openssl-%'")} | \
       {r[0] for r in sqlite3.connect(DB).execute("SELECT asset_uuid FROM cpes WHERE cpe_string LIKE '%:openssl:%'")}
check(ossl["nasset"] == len(real) and set(SW.assets_for(product="openssl")) == real, "software: a product KEY rebuilds its exact asset set")
v = ossl["vers"][0]["v"]
vs = set(SW.assets_for(product="openssl", version=v))
check(len(vs) == ossl["vers"][0]["assets"], "software: a product+version KEY = that version's asset count")
tb, code = SA.tag({"confirm": True, "category": "Software", "value": "openssl", "run": srun, "key": {"product": "openssl"}})
check(code == 200 and tb.get("count") == len(real), "software: tag by KEY tags the server-built set (%s assets)" % tb.get("count"))
tb, code = SA.tag({"confirm": True, "category": "Software", "value": "x", "key": {"role": "Not A Role"}})
check(code == 400, "software: an unknown crown role is refused")
x, _c = SA.run_sql({"sql": "SELECT * FROM vulns"})
check(x["count"] == SA.RUN_SQL_PAGE and x["page"]["next"] and x["total"]["value"] == N_ASSETS * 3,
      "software run_sql: capped at 200 rows a page with a next token + a total")
x2, _c = SA.run_sql({"sql": "SELECT * FROM vulns", "next": x["page"]["next"]})
check(x2["page"]["start"] == 200 and x2["count"] == 200, "software run_sql: the token pages on")
x3, c3 = SA.run_sql({"sql": "SELECT * FROM assets", "next": x["page"]["next"]})
check(c3 == 400, "software run_sql: a token issued for other SQL is refused")
lc, _c = SA.lifecycle({"run": srun, "results": [{"name": "openssl", "slug": "openssl", "latest": "3.0.7", "eolVers": ["1.0.2k"]}]})
eol_set = set(SW.assets_for(product="openssl", version="1.0.2k"))
check(lc["summary"]["eolAssetsEndoflife"] == len(eol_set) and lc["top"] and lc["top"][0]["eol"]["eolAssetCount"] == len(eol_set),
      "software: lifecycle verdicts → server-side EOL asset counts")
rk, _c = SA.risk({"run": srun})
check(rk["ok"] and rk["top"] and rk["top"][0]["risk"] >= rk["top"][-1]["risk"], "software: risk leaderboard server-side, ranked")
cr, _c = SA.crown({"run": srun})
check(any(r["role"] == "Database" for r in cr["top"]), "software: crown-jewel roles computed with the inventory")

# --- AI Inventory
from agents.ai import api as AA  # noqa: E402
from core import ai_assets  # noqa: E402
body, code = AA.run({"fp": {}})
contract_ok("ai.run", body)
arun = body["drill"]["run"]
res = AA._enrich(ai_assets.scan())
check(body["result"]["asset_count"] == res["asset_count"] and body["result"]["metrics"] == res["metrics"],
      "ai: asset_count + metrics == the engine's")
check("assets" not in body["result"] and all("uuids" not in f for f in body["result"]["view"]["frameworks"]),
      "ai: no asset list / framework uuids in the payload")
k, _c = AA.counts({"run": arun, "filter": ["exposed"]})
check(k["total"] == sum(1 for x in res["assets"] if x["exposed"]), "ai: counts of a filtered view (exposed)")
fw = body["result"]["view"]["frameworks"][0]
want = next(f for f in res["frameworks"] if f["name"] == fw["name"])
uu, err = AA._key_uuids({"run": arun, "key": {"fw": fw["name"]}})
check(sorted(uu) == sorted(want["uuids"]), "ai: a framework KEY rebuilds its asset set server-side")
uu, err = AA._key_uuids({"run": arun, "key": {"filter": ["role:" + res["assets"][0]["role"]]}})
check(sorted(uu) == sorted(x["asset_uuid"] for x in res["assets"] if x["role"] == res["assets"][0]["role"]), "ai: a role KEY")
uu, err = AA._key_uuids({"run": arun, "key": {"filter": ["../etc"]}})
check(err, "ai: an unknown filter key is refused")

# --- Asset Ownership
from agents.asset_ownership import api as OA  # noqa: E402
from core import asset_ownership as eng  # noqa: E402
body, code = OA.overview({})
contract_ok("asset_ownership.overview", body)
full = eng.overview(DB)
check(body["result"]["kpi"] == full["kpi"] and "assets" not in body["result"], "asset_ownership: KPIs == the engine's, no asset list")
orun = body["drill"]["run"]
seq, after = [], None
while True:
    d, _c = OA.drill({"run": orun, "section": "assets", "sort": "claimed", "limit": 200, **({"next": after} if after else {})})
    seq += [r["uuid"] for r in d["top"]]
    after = d["page"]["next"]
    if not after:
        break
want = [r["uuid"] for r in sorted(full["assets"], key=lambda r: ((r["claimed_pct"] if r["claimed_pct"] is not None else 999),
                                                                  -(r["acr"] or 0)))]
check(seq == want, "asset_ownership: 'Claimed ↑' paging == the page's old client sort (%d rows)" % len(seq))
d, _c = OA.drill({"run": orun, "section": "assets", "sort": "acr", "filter": ["noowner"], "q": "host00"})
check(d["total"]["value"] == sum(1 for r in full["assets"] if not r["has_owner"] and "host00" in (r["hostname"] or "")),
      "asset_ownership: scope + search on the server")
check([r["uuid"] for r in body["result"]["blind_spots"]] == [r["uuid"] for r in full["blind_spots"]] and
      [r["uuid"] for r in body["result"]["crown_jewels"]] == [r["uuid"] for r in full["crown_jewels"]][:50],
      "asset_ownership: blind spots + top crown jewels == the engine's order")
pl, _c = OA.plan({"prompt": "assign Jane to all assets"})
check("uuids" not in pl and len(pl.get("matched") or []) <= 50, "asset_ownership: plan returns no uuid list")
check(eng._asset_routes_paths(U[0])[0] == sorted({a for a, l in (("Apache", "100"), ("OpenSSL", "200"))
                                                  if any(r[0] == l for r in sqlite3.connect(DB).execute(
                                                      "SELECT plugin_id FROM vulns WHERE asset_uuid=?", (U[0],)))}),
      "asset_ownership: one asset's routes by plugin ids (no LIKE join over every finding)")

# ------------------------------------------------------------------ 6. page cache keeps a summary
key = "/agents/software/page.html"
huge = {"steps": [{"id": "swRun"}], "at": 7, "resp": {
    "POST /api/software/run_sql {}": {"status": 200, "body": {"ok": True, "rows": [{"asset_uuid": "x" * 36, "n": i} for i in range(60000)],
                                                             "summary": {"products": 12}}},
    "POST /api/software/small {}": {"status": 200, "body": {"ok": True, "n": 1}}}}
_old = pagecache.MAX_BYTES
pagecache.MAX_BYTES = 1024 * 1024
ok, err = pagecache.put(key, huge)
e = pagecache.get(key)
rb = (e or {}).get("resp", {}).get("POST /api/software/run_sql {}", {}).get("body", {})
check(ok and e and rb.get("_pc_trimmed") and len(rb["rows"]) <= 200 and rb["summary"] == {"products": 12}
      and e["resp"]["POST /api/software/small {}"]["body"] == {"ok": True, "n": 1},
      "page cache: an oversized run keeps a SUMMARY entry (decision data kept, rows trimmed, small reads intact)")
check((pagecache.meta(key) or {}).get("trimmed") == 1, "page cache: the listing marks it trimmed")
pagecache.MAX_BYTES = 100
ok, err = pagecache.put(key, huge)
check(not ok and pagecache.get(key) is None, "page cache: when even the summary can't fit, the entry is dropped (as before)")
pagecache.MAX_BYTES = _old

# ------------------------------------------------------------------ 7. pages use the shared helper, never post uuids
for pg in ("software", "certificate", "ai", "asset_ownership"):
    html = open(os.path.join(ROOT, "agents", pg, "page.html"), encoding="utf-8").read()
    check("hDrill(" in html, "%s page pages through the shared hDrill helper" % pg)
    check(not re.search(r"uuids\s*:", html), "%s page never posts a uuids list" % pg)
js = open(os.path.join(ROOT, "web", "assets", "console.js"), encoding="utf-8").read()
i = js.index("function hDrill(")
seg = js[i:js.index("/* ===== end hDrill ===== */")]
check("innerHTML" in seg and "esc(" in seg and "OFFSET" not in seg.upper().replace("OFFSETWIDTH", ""), "hDrill escapes its pager text")

print("\n%d failure(s)" % len(fails))
sys.exit(1 if fails else 0)
