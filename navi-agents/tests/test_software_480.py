"""Regression tests — build 480: finding Java 17, and the asset list behind a software count.

  · The software-string parser read a major number INSIDE a package name as the version:
    java-17-openjdk-headless-17.0.9.0.9-2.el8 → ("java", "17"). It now gives
    ("java-17-openjdk-headless", "17.0.9.0.9"); ordinary name-version-release strings are unchanged.
  · Harrier's Version box: a bare "17" matched only a version recorded as exactly "17", so Windows
    Java ("17.0.9.0") was never found. "17" now means 17 and its sub-versions (not 170 / 1.17),
    "=17" is exact, "17*" is a text prefix.
  · Mimir's asset counts open the Asset Explorer list (?software=<product>[&version=]). Every
    relevant asset is stored on the server; the browser pulls 500 rows per request and shows 20 per
    page (build 481). ⬇ CSV exports every asset in THAT list (and its search) — not the rows on
    screen, and not every asset in navi.db.
Run: python3 tests/test_software_480.py"""
import atexit
import csv
import io
import os
import shutil
import sqlite3
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
TMP = tempfile.mkdtemp(prefix="hounds-480-")
atexit.register(shutil.rmtree, TMP, ignore_errors=True)
DB = os.path.join(TMP, "navi.db")
os.environ.update({"NAVI_DB_PATH": DB, "NAVI_CACHE_DIR": os.path.join(TMP, "cache"),
                   "HOUNDS_CONFIG": os.path.join(TMP, "cfg.json"), "NAVI_TAGLOG_DB": os.path.join(TMP, "t.db")})
fails = []


def check(cond, msg):
    print(("PASS " if cond else "FAIL ") + msg)
    if not cond:
        fails.append(msg)


# 700 assets: 600 run RHEL Java 17 (navi's list shape), 3 Windows JDK 17, 2 Java 8, 1 "openjdk-170" decoy
U = ["%08d-aaaa-bbbb-cccc-dddddddddddd" % i for i in range(700)]
SW = {
    "java-17-openjdk-headless-17.0.9.0.9-2.el8": U[0:600],
    "Java(TM) SE Development Kit 17.0.9 (64-bit)  [version 17.0.9.0]": U[600:603],
    "java-1.8.0-openjdk-1.8.0.392.b08-4.el8": U[603:605],
    "javafoo-170.1-1": [U[605]],
    "bash-5.1-6ubuntu1": U[0:10],
}
c = sqlite3.connect(DB)
c.execute("CREATE TABLE assets (uuid text, hostname text, ip_address text, operating_system text, acr text, "
          "aes text, last_found text, url text)")
c.execute("CREATE TABLE software (asset_uuid text, software_string text)")
c.executemany("INSERT INTO assets VALUES (?,?,?,?,?,?,?,?)",
              [(u, "h%03d" % i, "10.1.%d.%d" % (i // 250, i % 250), "Linux", str(i % 10 + 1), "", "2026-11-01", "")
               for i, u in enumerate(U)])
c.executemany("INSERT INTO software VALUES (?,?)", [(str(us), s) for s, us in SW.items()])
c.commit()
c.close()

from core import software as sw, swsearch  # noqa: E402

# ── 1. parser ────────────────────────────────────────────────────────────────
P = {
    "java-17-openjdk-headless-17.0.9.0.9-2.el8": ("java-17-openjdk-headless", "17.0.9.0.9"),
    "openjdk-17-jre-headless-17.0.9+9-1~deb12u1": ("openjdk-17-jre-headless", "17.0.9+9"),
    "java-1.8.0-openjdk-1.8.0.392.b08-4.el8": ("java-1.8.0-openjdk", "1.8.0.392.b08"),
    "bash-5.1-6ubuntu1": ("bash", "5.1"),
    "openssl-1.1.1k-7.el8_6": ("openssl", "1.1.1k"),
    "python3-torch-2.1.0-1": ("python3-torch", "2.1.0"),
    "kernel-4.18.0-513.el8": ("kernel", "4.18.0"),
    "perl-IO-Socket-SSL-2.066-4.el8": ("perl-IO-Socket-SSL", "2.066"),
    "foo-1.0-beta-2": ("foo", "1.0"),
    "Microsoft Edge  [version 120.0.2210.91]": ("Microsoft Edge", "120.0.2210.91"),
}
for s, want in P.items():
    check(sw.parse_nvr_js(s) == want and sw.parse_software(s) == want,
          "parser: %s → %s (got %s)" % (s, want, sw.parse_nvr_js(s)))
check(sw.eol_slug(sw.parse_nvr_js("java-1.8.0-openjdk-1.8.0.392.b08-4.el8")[0]) == "oracle-jdk",
      "the java-1.8.0-openjdk → endoflife.date alias now gets the name it was written for")

# ── 2. Harrier's Version box ─────────────────────────────────────────────────
vm = swsearch.version_match
check(vm("17.0.9.0", "17") and vm("17", "17") and vm("17.0.9+8", "17") and vm("1:17.0.1", "17"),
      "version 17 matches 17, 17.0.9.0, 17.0.9+8 and 1:17.0.1")
check(not vm("170", "17") and not vm("1.17", "17") and not vm("", "17"), "version 17 does not match 170, 1.17 or none")
check(vm("3.0.2.1", "3.0.2") and not vm("3.0.2k", "3.0.2"), "3.0.2 matches 3.0.2.1 but not 3.0.2k (a different release)")
check(vm("2.0.0", "2.0", True) and not vm("3.0.2.1", "3.0.2", True), "=x is exact (2.0 == 2.0.0)")
r = swsearch.search(q="java", version="17")
k = r["kpi"]
check(k["assets"] == 603, "Harrier: java + version 17 → the 600 RHEL + 3 Windows Java 17 assets (got %s)" % k["assets"])
check(sorted(p["name"] for p in r["products"]) == ["Java(TM) SE Development Kit 17.0.9 (64-bit)", "java-17-openjdk-headless"],
      "Harrier: both Java 17 products, no Java 8 and no 170 decoy")
check(swsearch.search(q="java", version="=17")["kpi"]["assets"] == 0, "Harrier: =17 is exact — no install is exactly 17")
check(swsearch.search(q="java", version="17*")["kpi"]["assets"] == 604, "Harrier: 17* is still a plain text prefix (it also takes the 170.1 decoy)")
r = swsearch.search(q="java", ranges=swsearch.parse_ranges("<17.0.10"))
check(r["kpi"]["affected"] + r["kpi"]["check"] >= 600,
      "Harrier: a <17.0.10 range now compares 17.0.9.0.9, not the bare major '17'")

# ── 3. Mimir counts → Asset Explorer list (first 500) + CSV of every asset ──
prod, info = sw.product_sets()
rows = {r["name"]: r for r in (sw.product_row(x) for x in prod.values())}
j = rows.get("java-17-openjdk-headless") or {}
check(j.get("nasset") == 600 and j.get("nver") == 1, "Mimir: java-17-openjdk-headless on 600 assets, 1 version")
from agents.ex_assets import api as ex  # noqa: E402
o, code = ex.software({"product": "java-17-openjdk-headless"})
ev = o.get("evidence") or {}
top = o.get("top") or []
run = (o.get("drill") or {}).get("run")
check(code == 200 and ev.get("count") == 600 and len(top) == 500 and (o.get("total") or {}).get("value") == 600,
      "Asset Explorer software list: 600 relevant assets stored, the first 500 sent (got %s / %s)" % (ev.get("count"), len(top)))
check((o.get("drill") or {}).get("action") == "software_page" and run, "the list pages through software_page")
acrs = [float(t.get("acr") or 0) for t in top]
check(acrs and acrs == sorted(acrs, reverse=True) and acrs[0] == 10, "the list starts with the highest ACR")
nxt = (o.get("page") or {}).get("next")
o2, _ = ex.software_page({"run": run, "next": nxt})
top2 = o2.get("top") or []
check(len(top2) == 100 and not (o2.get("page") or {}).get("next")
      and len({t["uuid"] for t in top} | {t["uuid"] for t in top2}) == 600,
      "the next request sends the other 100 — 600 distinct assets, no repeats")
o3, _ = ex.software_page({"run": run, "limit": 5000})
check(len(o3.get("top") or []) == 500, "a request can't ask for more than 500 rows")
ok_ = ex.software_page({"run": run, "q": "h00"})[0]
check((ok_.get("total") or {}).get("value") == 10, "search narrows the stored list (h000–h009)")
ok_ = ex.drill({"run": run, "section": "assets", "limit": 5000})[0]
check(len(ok_.get("top") or []) == 200, "the ordinary drill keeps its 200-row cap")
# CSV: every RELEVANT asset — the 600 with this product, not the 700 in navi.db — and the search
o, code = ex.software_export({"product": "java-17-openjdk-headless", "run": run})
data = list(csv.reader(io.StringIO(o.get("csv") or "")))
ids = {r[-1] for r in data[1:]}
check(code == 200 and o.get("rows") == 600 and len(data) == 601 and ids == set(U[:600]),
      "⬇ CSV: exactly the 600 assets in this list — not the 500 sent, not all 700 in navi.db")
o, _ = ex.software_export({"product": "java-17-openjdk-headless", "run": run, "q": "h00"})
check(o.get("rows") == 10, "⬇ CSV follows the search box (10 rows for h00)")
o, _ = ex.software_export({"product": "java-17-openjdk-headless", "run": "hound-0000000000000000", "q": "h00"})
check(o.get("rows") == 10, "⬇ CSV still works (rebuilt from navi.db) if the stored list has expired")
o, _ = ex.software({"product": "java-17-openjdk-headless", "version": "17.0.9.0.9"})
check((o.get("evidence") or {}).get("count") == 600, "version link: the 600 assets on 17.0.9.0.9")
o, _ = ex.software({"product": "bash"})
check((o.get("evidence") or {}).get("count") == 10 and len(o.get("top") or []) == 10, "a small product: all 10 in one request")
check(ex.software({})[1] == 400 and ex.software_export({"product": 5})[1] == 400, "bad requests are refused")
from core import launcher  # noqa: E402
check(not any(launcher.is_mutating(a, {}) for a in ("software", "software_page", "software_export")),
      "the new actions are reads")

# ── 4. the pages wire it ─────────────────────────────────────────────────────
mp = open(os.path.join(ROOT, "agents", "software", "page.html"), encoding="utf-8").read()
check("/agents/ex_assets/page.html?software=" in mp and mp.count("swAL(") >= 4,
      "Mimir: product, version and risk-leaderboard asset counts link to the list")
ap = open(os.path.join(ROOT, "agents", "ex_assets", "page.html"), encoding="utf-8").read()
check("'software_export'" in ap and "'software_page'" in ap and "SHOW=20" in ap,
      "Asset Explorer: software mode pulls 500-row chunks, shows 20 per page, full CSV")
hp = open(os.path.join(ROOT, "agents", "ex_software", "page.html"), encoding="utf-8").read()
check("$('ver').value='='+x.label" in hp, "Harrier: clicking a version keeps that exact version")

print()
print("%d failure(s)" % len(fails) if fails else "ALL PASS")
sys.exit(1 if fails else 0)
