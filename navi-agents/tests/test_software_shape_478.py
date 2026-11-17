"""Regression tests — build 478: navi's real `software` table shape.

navi config software (navi/plugins/config.py update_software → insert_software) writes ONE row per
distinct software string, and asset_uuid is the Python list of every asset with it, as text —
"['uuid-1', 'uuid-2']", even for one asset. The sample / lab databases held one uuid per row, so
these bugs never showed:

  · Mimir counted one install per ROW → "installs" ≈ "versions" (237 / 237) instead of per asset.
  · Shadow IT (signals) compared the list text to asset uuids → every banner asset looked blind.
  · On the Scent (insights) joined it to assets.uuid → 0 % inventory coverage.
  · Alert Raven's term alerts selected the list text as an asset uuid → 1 instead of N.
  · The AI query guidance (llm / dashboard / advanced search) told the model to join it directly.
Both shapes must give the same answers.
Run: python3 tests/test_software_shape_478.py"""
import atexit
import os
import shutil
import sqlite3
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
TMP = tempfile.mkdtemp(prefix="hounds-478-")
atexit.register(shutil.rmtree, TMP, ignore_errors=True)
LIST_DB = os.path.join(TMP, "navi_list.db")      # navi's real shape
FLAT_DB = os.path.join(TMP, "navi_flat.db")      # one uuid per row (sample / older datasets)
os.environ.update({"NAVI_DB_PATH": LIST_DB, "NAVI_CACHE_DIR": os.path.join(TMP, "cache"),
                   "HOUNDS_CONFIG": os.path.join(TMP, "cfg.json"), "NAVI_TAGLOG_DB": os.path.join(TMP, "t.db")})
fails = []


def check(cond, msg):
    print(("PASS " if cond else "FAIL ") + msg)
    if not cond:
        fails.append(msg)


U = ["%08d-1111-2222-3333-444444444444" % i for i in range(1, 11)]
# software string → assets that have it (10 assets; openssl on 9 in 2 versions; one asset with none)
INSTALLED = {
    "openssl-1.1.1k-7.el8_6": U[0:6],                 # 6 assets
    "openssl-3.0.2-0ubuntu1.10": U[6:9],              # 3 assets
    "bash-5.1-6ubuntu1": U[0:9],                      # 9 assets
    "python3-torch-2.1.0-1": [U[2]],                  # 1 asset — still a one-item LIST in navi
    "Microsoft Edge  [version 120.0.2210.91]": [U[3], U[4]],
}


def build(path, list_shape):
    c = sqlite3.connect(path)
    c.execute("CREATE TABLE assets (uuid text, hostname text, ip_address text, operating_system text, "
              "network text, acr text, last_found text)")
    c.execute("CREATE TABLE software (asset_uuid text, software_string text)")
    c.execute("CREATE TABLE vulns (asset_uuid text, plugin_id text, plugin_name text, output text, severity text, "
              "state text, cves text, xrefs text, score text)")
    c.execute("CREATE TABLE tags (asset_uuid text, tag_key text, tag_value text)")
    c.executemany("INSERT INTO assets VALUES (?,?,?,?,?,?,?)",
                  [(u, "h%d" % i, "10.0.0.%d" % i, "Linux", "Default", "5", "2026-11-01") for i, u in enumerate(U, 1)])
    if list_shape:
        c.executemany("INSERT INTO software VALUES (?,?)", [(str(us), s) for s, us in INSTALLED.items()])
    else:
        c.executemany("INSERT INTO software VALUES (?,?)", [(u, s) for s, us in INSTALLED.items() for u in us])
    # service banners (Shadow IT): on an inventoried asset and on the one without inventory
    c.executemany("INSERT INTO vulns VALUES (?,?,?,?,?,?,?,?,?)", [
        (U[0], "10107", "HTTP Server Type and Version", "nginx/1.18", "info", "OPEN", "", "", ""),
        (U[9], "10107", "HTTP Server Type and Version", "Apache/2.4.6", "info", "OPEN", "", "", ""),
    ])
    c.commit()
    c.close()


build(LIST_DB, True)
build(FLAT_DB, False)
c = sqlite3.connect(LIST_DB)
check(c.execute("SELECT asset_uuid FROM software WHERE software_string LIKE 'python3-torch%'").fetchone()[0]
      == str([U[2]]), "fixture: navi's shape — even one asset is a list \"['…']\"")
c.close()

from core import alerts, db, signals, software as sw, swsearch  # noqa: E402

for name, P in (("navi list shape", LIST_DB), ("one-uuid rows", FLAT_DB)):
    # ── Mimir ──────────────────────────────────────────────────────────────────
    prod, info = sw.product_sets(db_path=P)
    rows = {r["name"]: r for r in (sw.product_row(x) for x in prod.values())}
    o = rows.get("openssl", {})
    check(o.get("nver") == 2 and o.get("nasset") == 9 and o.get("installs") == 9,
          "[%s] Mimir openssl: 2 versions, 9 assets, 9 installs (got %s/%s/%s)"
          % (name, o.get("nver"), o.get("nasset"), o.get("installs")))
    b = rows.get("bash", {})
    check(b.get("nver") == 1 and b.get("installs") == 9, "[%s] Mimir bash: 1 version on 9 installs" % name)
    check(sum(r["installs"] for r in rows.values()) == sum(len(v) for v in INSTALLED.values()),
          "[%s] Mimir total installs = asset-installs (21), not rows" % name)
    # ── the shared helper ──────────────────────────────────────────────────────
    inv = sw.inventory_assets(P)
    check(inv == set(U[:9]), "[%s] inventory_assets: the 9 assets with software" % name)
    # ── Shadow IT ──────────────────────────────────────────────────────────────
    sh = signals._shadow(P)
    check(sh.get("invAssets") == 9 and sh.get("blindAssets") == 1,
          "[%s] Shadow IT: 9 with inventory, 1 blind (got %s / %s)" % (name, sh.get("invAssets"), sh.get("blindAssets")))
    # ── Alert Raven term alert ────────────────────────────────────────────────
    spec = alerts._term_intersection_spec(["openssl"], tables={"software"})
    n = sqlite3.connect(P).execute(spec["metric_sql"]).fetchone()[0]
    check(n == 9, "[%s] alert 'assets with openssl' counts 9 assets (got %s)" % (name, n))
    det = sqlite3.connect(P).execute(spec["detail_sql"]).fetchall()
    check(len(det) == 9, "[%s] alert detail lists the 9 assets" % name)
    # ── Software Explorer ──────────────────────────────────────────────────────
    r = swsearch.search(q="openssl", path=P)
    check(r["kpi"]["assets"] == 9 and r["kpi"]["versions"] == 2 and r["kpi"]["installs"] == 9,
          "[%s] Software Explorer openssl: 9 assets · 2 versions · 9 installs" % name)
    # ── the SQL expansion through the read-only guard ─────────────────────────
    q = ("SELECT COUNT(DISTINCT j.value) AS n FROM software s, %s j WHERE s.software_string LIKE '%%openssl%%'"
         % sw.sw_assets_sql())
    check(db.user_query(q, path=P)[0]["n"] == 9, "[%s] sw_assets_sql() expands it, and passes the read-only guard" % name)

# ── On the Scent (insights) — same coverage on both shapes ─────────────────
from core import insights  # noqa: E402
sa = []
for P in (LIST_DB, FLAT_DB):
    try:
        res = insights.compute(P)
        k = res.get("kpis") if isinstance(res.get("kpis"), dict) else res
        sa.append(k.get("shadow_assets"))
    except Exception as e:
        sa.append("err %s" % e)
check(sa == [1, 1], "On the Scent: 1 asset without inventory on both shapes (got %s)" % sa)

# ── the model is told the real shape ───────────────────────────────────────
from core import dashboard, llm  # noqa: E402
from agents.explore import api as ex  # noqa: E402
lsrc = open(os.path.join(ROOT, "core", "llm.py"), encoding="utf-8").read()
check("NEVER compare, join or COUNT software.asset_uuid directly" in lsrc, "software NL query: list shape + json_each")
check("json_each" in dashboard.SCHEMA_NOTES, "dashboard builder: list shape + json_each")
check(any("json_each" in n for a, b, n in ex._NAVI_JOINS if b == "software.asset_uuid"),
      "advanced search join map: list shape + json_each")
asrc = open(os.path.join(ROOT, "core", "alerts.py"), encoding="utf-8").read()
check("COUNT(DISTINCT j.value) FROM software s, json_each" in asrc, "Alert Raven example uses the expansion")

print()
print("%d failure(s)" % len(fails) if fails else "ALL PASS")
sys.exit(1 if fails else 0)
