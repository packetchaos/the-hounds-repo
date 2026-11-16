"""Regression tests for Asset Classification (Linnaeus): the ▶ Run keeps every result key the
AI Contract depends on, the 📊 At a glance numbers (open-only KEV / critical, unsupported-OS via
the EOL selector, low-confidence OS fingerprints, risk leaders, riskiest unclassified asset),
missing-table / missing-column safety, and the gated tag action (confirm, list-only uuids,
remove=False). Tiny synthetic navi.db files in a temp dir; no navi, no network.
Run: python3 tests/test_classify.py  (or pytest).
`python3 tests/test_classify.py --make-db PATH` writes the fixture DB (for manual page checks)."""
import atexit
import json
import os
import re
import shutil
import sqlite3
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)


def build_db(path, ip_col=True):
    if os.path.exists(path):
        os.remove(path)
    c = sqlite3.connect(path)
    c.execute("CREATE TABLE assets (uuid TEXT, hostname TEXT, %s operating_system TEXT, acr TEXT, aes TEXT, aws_id TEXT)"
              % ("ip_address TEXT," if ip_col else ""))
    c.execute("CREATE TABLE vulns (asset_uuid TEXT, plugin_id TEXT, plugin_name TEXT, output TEXT, severity TEXT, "
              "xrefs TEXT, state TEXT)")
    c.execute("CREATE TABLE tags (asset_uuid TEXT, tag_key TEXT, tag_value TEXT)")
    A = [  # uuid, hostname, os, acr, aws_id
        ("w1", "win-srv-1", "Microsoft Windows Server 2019", "8", ""),
        ("w2", "win-srv-2", "Microsoft Windows Server 2019", "5", ""),
        ("w3", "win-srv-3", "Microsoft Windows Server 2012", "5", ""),
        ("l1", "ubu-1", "Ubuntu 22.04", "6", ""),
        ("l2", "ubu-2", "Ubuntu 22.04", "4", ""),
        ("m1", "mac-1", "macOS 14", "3", ""),
        ("i1", "cam-1", "", "2", ""),
        ("n1", "fw-edge", "", "9", ""),
        ("c1", "ec2-a", "", "5", "i-0abc"),
        ("u1", "legacy-dc", "", "9", ""),
        ("u2", "box-2", "", "4", ""),
        ("u3", "<img src=x onerror=alert(1)>", "", "", ""),
        ("u4", "kiosk-4", "", "3", ""),
    ]
    for i, (u, h, o, acr, aws) in enumerate(A):
        if ip_col:
            c.execute("INSERT INTO assets VALUES (?,?,?,?,?,?,?)", (u, h, "10.0.0.%d" % (i + 1), o, acr, "", aws))
        else:
            c.execute("INSERT INTO assets VALUES (?,?,?,?,?,?)", (u, h, o, acr, "", aws))
    T = [("w1", "Asset Inventory", "Class: Windows - Windows Server 2019"),
         ("w2", "Asset Inventory", "Class: Windows - Windows Server 2019"),
         ("w3", "Asset Inventory", "Class: Windows - Windows Server 2012"),
         ("l1", "OS", "Ubuntu"), ("l2", "OS", "Ubuntu"), ("m1", "OS", "macOS"),
         ("i1", "IoT", "Camera"), ("n1", "Asset Inventory", "Network: Firewall"),
         ("w1", "Owner", "VM Team")]
    c.executemany("INSERT INTO tags VALUES (?,?,?)", T)
    KEV = "CISA-KNOWN-EXPLOITED:2022/01/01"
    V = [("w1", "1", "Some KEV vuln", "", "critical", KEV, "open"),
         ("w2", "2", "Fixed crit", "", "critical", "", "fixed"),
         ("w3", "108797", "Microsoft Windows Server 2012 Unsupported Version Detection", "", "critical", "", "fixed"),
         ("l1", "3", "Open crit", "", "Critical", "", "open"),
         ("u1", "108797", "Microsoft Windows Server 2008 R2 Unsupported Version Detection", "", "critical", KEV, "open"),
         ("u1", "11936", "OS Identification",
          "Remote operating system : Microsoft Windows Server 2008 R2 Enterprise\nConfidence level : 95\nMethod : SMB", "info", "", "open"),
         ("u2", "11936", "OS Identification",
          "Remote operating system : Linux Kernel 3.10 on CentOS Linux release 7\nConfidence level : 56\nMethod : SinFP", "info", "", "open"),
         ("u2", "4", "Open crit 2", "", "critical", "", "reopened"),
         ("u4", "22024", "Adobe Reader Unsupported Version Detection", "", "high", "", "open")]
    c.executemany("INSERT INTO vulns VALUES (?,?,?,?,?,?,?)", V)
    c.commit()
    c.close()


if len(sys.argv) > 2 and sys.argv[1] == "--make-db":
    build_db(sys.argv[2])
    print("wrote", sys.argv[2])
    sys.exit(0)

TMP = tempfile.mkdtemp(prefix="hounds-classify-")
atexit.register(shutil.rmtree, TMP, ignore_errors=True)
os.environ["NAVI_CACHE_DIR"] = os.path.join(TMP, "cache")
DB = os.path.join(TMP, "navi.db")
os.environ["NAVI_DB_PATH"] = DB
build_db(DB)

from core import navi_cli  # noqa: E402

TAGGED = []
navi_cli.tag = lambda *a, **k: (TAGGED.append((a, k)) or {"ok": True, "job_id": len(TAGGED)})
from core import classify as C  # noqa: E402
from agents.classify import api  # noqa: E402

fails = []


def check(cond, msg):
    print(("PASS " if cond else "FAIL ") + msg)
    if not cond:
        fails.append(msg)


# ---- ▶ Run: every existing key kept + glance ----
o, st = api.run({})
r = o["result"]
check(st == 200 and r["ok"], "run ok")
for k in ("ok", "total", "classified", "unclassified", "coverage_pct", "tagged_any", "stats", "classes",
          "unclassified_reasons"):
    check(k in r, "run keeps result key %r" % k)
# build 464 payload contract: no per-asset list in the run — the drill-down asks `assets`
check("assets" not in r and r.get("assets_total") == r["total"], "run ships no per-asset list (assets_total %s)" % r.get("assets_total"))
_c0 = r["classes"][0]["cls"]
ao, _st = api.assets({"cls": _c0})
check(ao["ok"] and ao["count"] == r["classes"][0]["count"] and all(x["cls"] == _c0 for x in ao["assets"]),
      "drill-down: `assets` returns one class's rows (%s: %d)" % (_c0, ao["count"]))
ao2, _st = api.assets({"cls": _c0, "limit": 1})
check(ao2["count"] == ao["count"] and ao2["shown"] == 1 and ao2["truncated"] and
      (not any(x.get("kev") for x in ao["assets"]) or ao2["assets"][0].get("kev")),
      "drill-down caps the rows, riskiest (KEV) first, and still reports the class total")
check(r["total"] == 13 and r["classified"] == 9 and r["unclassified"] == 4, "13 assets: 9 classified, 4 unclassified")
cls = {c["cls"]: c for c in r["classes"]}
check(set(cls) == {"Windows", "Linux", "macOS", "IoT", "Network", "Cloud", "Unclassified"}, "classes %s" % sorted(cls))
g = r.get("glance") or {}
check(g.get("kev_assets") == 2, "KEV assets = 2 (open only) — got %s" % g.get("kev_assets"))
check(g.get("critical_assets") == 4, "critical assets = 4: w1, l1, u1, u2 (w2's fixed critical ignored) — got %s"
      % g.get("critical_assets"))
check(cls["Windows"]["critical"] == 1, "fixed critical on w2 not counted for Windows")
check(g.get("eol_os") == 1, "unsupported OS = 1 (u1; fixed w3 and app-only u4 excluded) — got %s" % g.get("eol_os"))
check(cls["Unclassified"]["eol_os"] == 1 and cls["Windows"]["eol_os"] == 0, "per-class EOL OS counts")
check(g.get("os_fingerprinted") == 2 and g.get("low_conf") == 1, "OS fingerprints 2, low-confidence (<70) 1")
check((g.get("top_kev_class") or {}).get("cls") == "Windows", "top KEV class = Windows (Unclassified excluded)")
check((g.get("top_crit_class") or {}).get("cls") in ("Windows", "Linux"), "top critical class among classified")
check((g.get("riskiest_unclassified") or {}).get("uuid") == "u1", "riskiest unclassified = u1 (KEV + ACR 9)")
check(g.get("unclassified_kev") == 1 and g.get("cloud_detected") == 1, "unclassified KEV 1, cloud-by-metadata 1")
check(g.get("owned") == 1 and g.get("unowned_classified") == 8, "owned 1, classified-without-owner 8")
# cross-check with SQL
con = sqlite3.connect(DB)
kev_sql = con.execute("SELECT COUNT(DISTINCT asset_uuid) FROM vulns WHERE xrefs LIKE '%CISA-KNOWN-EXPLOITED%' "
                      "AND state IN ('open','reopened')").fetchone()[0]
check(kev_sql == g.get("kev_assets"), "KEV count matches SQL")
# topology / insights path stays cheap: no glance, no eol_os flag
plain = C.classify()
check("glance" not in plain and "eol_os" not in plain["assets"][0], "classify() without glance adds nothing")

# ---- the other three ▶ Run reads ----
t, _ = api.tree({"by": "class"})
check(t["ok"] and t["result"]["ok"] and t["result"]["total"] == 13, "tree by class")
ob, _ = api.os_breakdown({})
fams = {f["family"]: f["count"] for f in ob["result"]["families"]}
check(fams.get("Windows") == 1 and fams.get("Linux") == 1, "os_breakdown: u1 Windows, u2 Linux (%s)" % fams)
sg, _ = api.signals({})
check(sg["result"]["ok"] and sg["result"]["assets_with_signal"] >= 2, "signals")

# ---- robustness ----
a, _ = api.assets(None)
check(a["ok"] and a["count"] == 13, "assets(None) does not crash")
op, _ = api.os_plan({"prompt": "", "families": "Windows"})
check(op["ok"] and op["families"] == [], "os_plan ignores a non-list families param")
op, _ = api.os_plan({"prompt": "tag windows by OS over 90%"})
check(op["threshold"] == 90 and [c["value"] for c in op["cohorts"]] == ["Windows Server 2008 R2"], "os_plan windows ≥90")

# ---- gated tag ----
b, st = api.tag({"facet": "OS", "value": "X", "uuids": ["u1"]})
check(st == 400 and not TAGGED, "tag without confirm → 400, nothing written")
b, st = api.tag({"facet": "OS", "value": "X", "uuids": "u1u2", "confirm": True})
check(st == 400 and not TAGGED, "tag with a string uuids → 400 (no per-character tagging)")
b, st = api.tag({"facet": "OS", "value": "Windows", "uuids": ["u1", "x'); DROP"], "confirm": True})
check(st == 200 and TAGGED and TAGGED[-1][1].get("remove") is False, "tag writes with remove=False")
check("''" in TAGGED[-1][1].get("query", ""), "uuid quotes escaped in the tag query")
b, st = api.tag({"cls": "Windows", "confirm": True})
check(st == 200 and b["asset_count"] == 3 and b["value"] == "Asset Inventory : Class: Windows", "tag a class by path")
# build 464: the OS explorer sends counts only and tags by KEY — the server rebuilds the set
ob, _ = api.os_breakdown({})
check(all("uuids" not in f and all("uuids" not in v for v in f.get("versions") or []) for f in ob["result"]["families"]),
      "os_breakdown ships no uuid arrays")
n0 = len(TAGGED)
b, st = api.tag({"facet": "OS", "value": "Windows", "os": {"family": "Windows"}, "confirm": True})
check(st == 200 and b["asset_count"] == 1 and "'u1'" in TAGGED[-1][1].get("query", "") and len(TAGGED) > n0,
      "tag an OS family by key → the server rebuilds its exact uuid set (%s)" % b.get("asset_count"))
b, st = api.tag({"facet": "OS", "value": "X", "os": "Windows", "confirm": True})
check(st == 400, "a malformed OS key → 400")
b, st = api.tag({"facet": "OS", "value": "X", "os": {"family": "NoSuchOS"}, "confirm": True})
check(st == 400, "an OS key with no assets → 400, nothing written")
# build 464: OS Signals + OS plan cohorts carry counts only; a cohort tags by KEY
sg2, _ = api.signals({})
check(all("uuids" not in c for c in sg2["result"]["cohorts"]), "signals: no uuid arrays")
c0 = sg2["result"]["cohorts"][0]
full = [c for c in C.os_signals(only_untagged=True)["cohorts"] if c["facet"] == c0["facet"] and c["value"] == c0["value"]][0]
b, st = api.tag({"facet": c0["facet"], "value": "renamed", "sig": {"facet": c0["facet"], "value": c0["value"]}, "confirm": True})
check(st == 200 and b["asset_count"] == len(full["uuids"]) == c0["count"],
      "signals cohort tagged by key → the server rebuilds its exact set (%d)" % b.get("asset_count", 0))
op2, _ = api.os_plan({"prompt": "tag windows by OS over 90%"})
check(all("uuids" not in c for c in op2["cohorts"]), "os_plan: no uuid arrays")
b, st = api.tag({"facet": "OS", "value": op2["cohorts"][0]["value"], "plan": {"prompt": "tag windows by OS over 90%",
                 "threshold": op2["threshold"], "families": op2["families"], "group": op2["group"], "value": op2["cohorts"][0]["value"]},
                 "confirm": True})
check(st == 200 and b["asset_count"] == op2["cohorts"][0]["count"], "os_plan cohort tagged by key")
b, st = api.tag({"facet": "OS", "value": "x", "sig": "nope", "confirm": True})
check(st == 400, "malformed cohort key → 400")
# build 464: the drill-down pages / searches on the server; "select all" is a key
o, _st = api.run({})
dr = o["result"].get("drill") or {}
check(dr.get("run") and dr.get("section") == "assets", "run hands back a drill handle into the stored run")
wcls = [c for c in o["result"]["classes"] if c["cls"] == "Windows"][0]
d1, _st = api.drill({"run": dr["run"], "section": "assets", "filter": ["cls:Windows"], "limit": 2})
check(d1["ok"] and d1["total"]["value"] == wcls["count"] and len(d1["top"]) == 2 and d1["page"]["next"],
      "drill: one class, paged on the server (2 of %d, next token)" % wcls["count"])
d2, _st = api.drill({"run": dr["run"], "section": "assets", "filter": ["cls:Windows"], "limit": 2, "next": d1["page"]["next"]})
seen = [r["uuid"] for r in d1["top"] + d2["top"]]
check(len(seen) == len(set(seen)) == wcls["count"] and all(r["cls"] == "Windows" for r in d1["top"] + d2["top"]),
      "drill: the next page continues with no repeats — every asset of the class is reachable")
d3, _st = api.drill({"run": dr["run"], "section": "assets", "filter": ["cls:Windows"], "q": d1["top"][0]["hostname"]})
check(d3["ok"] and any(r["uuid"] == d1["top"][0]["uuid"] for r in d3["top"]), "drill: server-side search")
bad, st = api.drill({"run": dr["run"], "section": "assets", "filter": ["role:x"]})
check(st == 400, "drill: an undeclared filter → 400")
n0 = len(TAGGED)
b, st = api.tag({"facet": "Device Type", "value": "Kiosk", "set": {"run": dr["run"], "cls": "Windows"}, "confirm": True})
check(st == 200 and b["asset_count"] == wcls["count"], "select all → the tag key {run, cls} rebuilds the whole class (%s)" % b.get("asset_count"))
b, st = api.tag({"facet": "Device Type", "value": "Kiosk", "set": {"run": dr["run"], "cls": "Windows", "q": d1["top"][0]["hostname"]}, "confirm": True})
check(st == 200 and b["asset_count"] == d3["total"]["value"], "select all under a search → just the matches")
b, st = api.tag({"facet": "Device Type", "value": "Kiosk", "set": {"run": "nope", "cls": "Windows"}, "confirm": True})
check(st == 400 and b.get("expired"), "a select-all key for a pruned run → 400 expired, nothing written")

# ---- AI Contract still reads OS signals ----
from core import contract  # noqa: E402
items = contract._ad_classify({})
check(isinstance(items, list) and items, "contract _ad_classify still produces items")

# ---- missing tables / columns ----
for name, ddl in (("assets_only.db", ["CREATE TABLE assets (uuid TEXT, hostname TEXT, ip_address TEXT)",
                                      "INSERT INTO assets VALUES ('a','h','1.1.1.1')"]),
                  ("empty.db", [])):
    p = os.path.join(TMP, name)
    c = sqlite3.connect(p)
    for d in ddl:
        c.execute(d)
    c.commit()
    c.close()
    res = C.classify(p, glance=True)
    if name == "empty.db":
        check(res["ok"] is False and "error" in res, "no assets table → clean error")
        check(C.os_signals(p)["ok"] is False and C.os_breakdown(p)["ok"] is False, "signals/breakdown error cleanly")
    else:
        check(res["ok"] and res["glance"]["eol_os"] == 0 and res["glance"]["kev_assets"] == 0,
              "assets-only DB (no vulns/tags) → zeros, no crash")
        check(C.os_signals(p)["ok"] and C.os_breakdown(p)["ok"], "signals/breakdown on assets-only DB")
p = os.path.join(TMP, "noip.db")
build_db(p, ip_col=False)
res = C.classify(p, glance=True)
check(res["ok"] and res["total"] == 13 and res["assets"][0]["ip"] == "", "assets without ip_address column")
check(C.os_signals(p)["ok"], "os_signals without ip_address column")

# ---- recipe + page contract ----
rec = [x for x in json.load(open(os.path.join(ROOT, "core", "release_recipes.json")))["pages"]
       if x.get("agent") == "classify"]
check(rec and [q["action"] for q in rec[0]["requests"]] == ["run", "tree", "os_breakdown", "signals"],
      "▶ Run recipe: run, tree, os_breakdown, signals")
html = open(os.path.join(ROOT, "agents", "classify", "page.html"), encoding="utf-8").read()
check("mountSectionNav()" in html and "setNavCount(" in html, "page mounts the jump nav")
check('id="secMetrics"' in html and "📊 At a glance" in html and 'renderGlance(host' in html and 'class="mkpi"' not in html
      and not re.search(r"^function renderGlance\(", html, re.M), "At a glance section (shared renderGlance template, not shadowed)")
check(len(re.findall(r"\bconfirm\(", html)) >= 5, "confirm() before every write path")
check(not re.search(r"""on\w+="[^"]*\$\{""", html), "no inline handlers built from data")
check("/agents/eol/page.html" in html and "/agents/iot_squad/page.html" in html and "/agents/argos/page.html?target=" in html
      and "/agents/fused_score/page.html" in html, "metric links to EOL, IoT Discovery, Argos, Exposure Score")
for href in re.findall(r"""['"](/agents/[a-z_]+/page\.html|/web/[a-z-]+\.html)""", html):
    fp = os.path.join(ROOT, href.lstrip("/"))
    check(os.path.exists(fp), "link target exists: " + href)
tail = html.split("mountAgentHeader(")[1]
check("run()" not in tail.split("</script>")[0].replace("try{ run(); }", ""), "explicit-run: nothing runs on load")

print("%d failure(s)" % len(fails))
sys.exit(1 if fails else 0)
