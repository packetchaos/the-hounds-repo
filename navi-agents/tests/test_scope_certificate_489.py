"""Regression tests — build 489: Certania (certificate) by tag.

  · With a tag_scope {key, value}, Certania covers only the certificates ON the assets carrying
    that tag (and the cert-issue plugin hits on them). Every per-certificate value (status, days
    left, flags, tag value, crown) is the whole-estate value; only the population changes.
  · No scope = exactly the pre-489 SQL and result.
  · A tag run keeps its own result (api._TAG_RESULTS) and its own drill rows (hound
    certificate_tag), so it never replaces AGENT.result nor prunes the estate's run; drill / dates
    only read a run of the same scope.
  · Writes from a tag view (tags_apply, tags_issues) re-read the tag's assets from navi.db on the
    server and tag only those; navi is never called (tag_pages / tag are mocked).
Run: python3 tests/test_scope_certificate_489.py"""
import atexit
import datetime
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
TMP = tempfile.mkdtemp(prefix="hounds-489-cert-")
atexit.register(shutil.rmtree, TMP, ignore_errors=True)
DB = os.path.join(TMP, "navi.db")
shutil.copy(os.path.join(ROOT, "sample_navi.db"), DB)
os.environ.update({"NAVI_DB_PATH": DB, "NAVI_CACHE_DIR": os.path.join(TMP, "cache"),
                   "HOUNDS_CONFIG": os.path.join(TMP, "cfg.json"), "NAVI_TAGLOG_DB": os.path.join(TMP, "t.db")})
os.environ.pop("NAVI_ALLOW_WRITES", None)
fails = []


def check(cond, msg):
    print(("PASS " if cond else "FAIL ") + msg)
    if not cond:
        fails.append(msg)


con = sqlite3.connect(DB)
# the tag with the most certificate assets that is not the whole cert population
TK, TV, NCA = con.execute(
    "SELECT t.tag_key, t.tag_value, COUNT(DISTINCT c.asset_uuid) n FROM certs c JOIN tags t ON t.asset_uuid=c.asset_uuid "
    "WHERE TRIM(COALESCE(t.tag_value,''))<>'' GROUP BY 1,2 ORDER BY n DESC, 1, 2 LIMIT 1").fetchone()
TAGGED = {r[0] for r in con.execute("SELECT DISTINCT asset_uuid FROM tags WHERE tag_key=? AND tag_value=?", (TK, TV))}
ALL_CERT_ASSETS = con.execute("SELECT COUNT(DISTINCT asset_uuid) FROM certs").fetchone()[0]
print(f"lab: scope {TK} : {TV} — {len(TAGGED)} tagged assets, {NCA} with certs (of {ALL_CERT_ASSETS})")
check(0 < NCA < ALL_CERT_ASSETS, "the lab tag is a strict subset of the certificate assets")

from core import db, launcher, navi_cli, payload, tagscope  # noqa: E402
from agents.certificate import api as CA, agent as CAg  # noqa: E402

# ── 1. whole estate unchanged: the exact pre-489 SQL, no params, same result ──────────────
PRE489_SQL = [
    "SELECT count(uuid) FROM assets;",
    "SELECT MAX(last_found) FROM vulns;",
    "SELECT plugin_id, plugin_name, COUNT(DISTINCT asset_uuid) AS asset_count FROM vulns WHERE plugin_name LIKE "
    "'%Certificate%' GROUP BY plugin_id, plugin_name ORDER BY asset_count DESC;",
]
seen = []
_q, _s, _i = db.query, db.scalar, db.iter


def spy(fn):
    def w(sql, *a, **k):
        seen.append((sql, a[0] if a and not isinstance(a[0], str) else k.get("params", ())))
        return fn(sql, *a, **k)
    return w


db.query, db.scalar, db.iter = spy(_q), spy(_s), spy(_i)
est = CAg.CertificateAgent()._run(None)
db.query, db.scalar, db.iter = _q, _s, _i
sqls = [s for s, _a in seen if not s.startswith("PRAGMA")]
check(all(x in sqls for x in PRE489_SQL), "estate run issues the pre-489 meta / matrix SQL verbatim")
cert_sql = [s for s in sqls if s.startswith("SELECT c.asset_uuid")]
check(len(cert_sql) == 1 and cert_sql[0].endswith("FROM certs c LEFT JOIN assets a ON a.uuid = c.asset_uuid;"),
      "estate cert scan has no WHERE (pre-489 statement)")
check(all(not a for s, a in seen if not s.startswith("PRAGMA")), "estate run binds no scope params")
check("scope" not in est, "an estate result carries no scope")
est2 = CAg.CertificateAgent()._run(None, scope=None)
strip = lambda r: {k: v for k, v in r.items() if k != "run"}
check(strip(est) == strip(est2), "scope=None == no scope argument")
body, _ = CA.run({})
check(body.get("scope") is None and "scope" not in body and body["result"]["metrics"] == est["metrics"],
      "run {} (no tag_scope): the estate payload, no scope key")
body_ts, _ = CA.run({"tag_scope": {}})            # launcher drops an empty scope; parse() → estate too
check(body_ts["result"]["metrics"] == est["metrics"], "an empty tag_scope is the whole estate")
# optional: a pristine pre-489 agent.py (e.g. another work copy) gives the identical estate result
PRISTINE = os.environ.get("CERT_PRISTINE_AGENT")
if PRISTINE and os.path.exists(PRISTINE):
    import importlib.util
    spec = importlib.util.spec_from_file_location("agents.certificate._pristine", PRISTINE)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    old = mod.CertificateAgent()._run(None)
    check(strip(old) == strip(est), "estate result == the pristine pre-489 agent's, byte for byte")
    payload.STORE.drop(old["run"])
# the estate run the rest of the test compares against (the store keeps a hound's last 2 runs)
body, _ = CA.run({})
EST_RUN = body["drill"]["run"]
EST_RESULT = CA.AGENT.result

# ── 2. scoped counts == hand-computed over the tag's assets ─────────────────────────────
from core.certdates import parse_cert_date  # noqa: E402
today = datetime.date.today()
try:
    end = today.replace(year=today.year + 1)
except ValueError:
    end = today.replace(year=today.year + 1, day=28)
rows = con.execute("SELECT asset_uuid, not_valid_after FROM certs").fetchall()
mine = [r for r in rows if r[0] in TAGGED]
pairs = set()
for u, na in mine:
    d = parse_cert_date(na)
    if d and (d < today or today <= d <= end):
        pairs.add((u, d))
h_exp = sum(1 for _u, d in pairs if d < today)
h_fail = len(pairs) - h_exp
h_matrix = {str(p): n for p, n in con.execute(
    "SELECT plugin_id, COUNT(DISTINCT asset_uuid) FROM vulns WHERE plugin_name LIKE '%Certificate%' AND asset_uuid IN "
    "(SELECT asset_uuid FROM tags WHERE tag_key=? AND tag_value=?) GROUP BY plugin_id", (TK, TV))}

o, _ = CA.run({"tag_scope": {"key": TK, "value": TV}})
check(o["ok"] and o.get("scope", {}).get("label") == f"{TK} : {TV}" and o["scope"]["assets"] == len(TAGGED),
      "scoped run says its scope (label + tagged assets)")
R = o["result"]
m = R["metrics"]
check(m["cert_rows"] == len(mine) and m["cert_assets"] == NCA, f"cert rows / assets = the tag's ({len(mine)} / {NCA})")
check(m["expired"] == h_exp and m["failing"] == h_fail, f"expired / failing = hand count ({h_exp} / {h_fail})")
check(R["asset_total"] == len(TAGGED), "asset_total = the tag's assets")
check({str(x["plugin_id"]): x["asset_count"] for x in R["cert_issue_matrix"]} == h_matrix,
      "cert-issue matrix counted over the tag's assets only")
check(CA.AGENT.result is EST_RESULT, "a scoped run leaves AGENT.result (the estate / hub card) alone")
TAG_RUN = o["drill"]["run"]
check(TAG_RUN.startswith(CAg.TAG_HOUND + "-"), "scoped drill rows live under their own store hound")

# ── 3. per-asset values identical ────────────────────────────────────────────────────────
def all_rows(run, sec, store):
    return list(store.iter_rows(run, sec))


erows = {(r["asset_uuid"], r["expiry_iso"], r.get("common_name")): r for r in all_rows(EST_RUN, "certs", payload.STORE)}
srows = all_rows(TAG_RUN, "certs", CAg.TAG_STORE)
check(len(srows) == h_exp + h_fail and all(r["asset_uuid"] in TAGGED for r in srows), "every scoped cert row is on a tagged asset")
check(srows and all(erows.get((r["asset_uuid"], r["expiry_iso"], r.get("common_name"))) == r for r in srows),
      "each scoped cert row == its whole-estate row (status, days, flags, tag value, crown)")
eiot = {(r["ip"], r["vendor"], r["product"]): r for r in all_rows(EST_RUN, "iot", payload.STORE)}
siot = all_rows(TAG_RUN, "iot", CAg.TAG_STORE)
# the IoT cache keeps the first row per (ip, vendor, product) — across assets, so where an untagged
# asset shares a tagged asset's IP the estate's representative row is the untagged one; the tag view
# shows the tagged asset's own row. The classification itself is per certificate, so it must agree.
check(siot and all(r["asset_uuid"] in TAGGED for r in siot), "IoT/app cache rows: tagged assets only")
check(all((r["ip"], r["vendor"], r["product"]) in eiot and
          (r["device_type"], r["vendor"], r["product"]) == CAg.classify(r["cert_cn"], r["cert_org"], r["cert_ou"])
          and (eiot[(r["ip"], r["vendor"], r["product"])]["asset_uuid"] != r["asset_uuid"]
               or eiot[(r["ip"], r["vendor"], r["product"])] == r) for r in siot),
      "IoT/app cache: same classification; same row wherever the estate picked the same asset")
ecr = {r["asset_uuid"]: r for r in all_rows(EST_RUN, "crown", payload.STORE)}
check(all(r["asset_uuid"] in TAGGED and ecr.get(r["asset_uuid"]) == r for r in all_rows(TAG_RUN, "crown", CAg.TAG_STORE)),
      "crown-jewel rows: tagged assets only, same per-asset rollup")

# drill / dates honour the scope, and never cross views
S = {"tag_scope": {"key": TK, "value": TV}}
d, _ = CA.drill(dict(S, run=TAG_RUN, section="certs", sort="near", limit=200))
check(d.get("ok", True) is not False and d["total"]["value"] == len(srows) and d.get("scope"), "scoped drill pages the tag run")
d, _ = CA.drill(dict(S, run=EST_RUN, section="certs"))
check(d.get("ok") is False and d.get("expired"), "a scoped drill refuses the estate's run")
d, _ = CA.drill({"run": TAG_RUN, "section": "certs"})
check(d.get("ok") is False, "an estate drill refuses a tag run")
d, _ = CA.drill({"tag_scope": {"key": TK, "value": TV + "x"}, "run": TAG_RUN, "section": "certs"})
check(d.get("ok") is False, "another tag's drill refuses this tag's run")
dv, _ = CA.dates(dict(S, run=TAG_RUN, filter=[]))
check(dv["ok"] and set(dv["values"]) == {r["tag_value"] for r in srows}, "scoped dates = the tag view's dates")
dc, _ = CA.dates(dict(S, run=TAG_RUN, values=dv["values"]))
check(dc["certs"] == len(srows) and dc["assets"] == len({r["asset_uuid"] for r in srows}), "scoped selection counts")
dx, _ = CA.dates(dict(S, run=EST_RUN, filter=[]))
check(dx.get("ok") is False, "scoped dates refuse the estate's run")
o0, _ = CA.run({"tag_scope": {"key": "no such key", "value": "x"}})
check(o0.get("ok") is False and "no asset" in o0["error"], "a tag no asset carries is refused, plainly")

# ── 4. every page-called action is declared in the manifest, and the launcher lets it through
page = open(os.path.join(ROOT, "agents", "certificate", "page.html"), encoding="utf-8").read()
called = set(re.findall(r"API\.post\('([a-z_]+)'", page)) | set(re.findall(r"jpost\('/api/certificate/([a-z_]+)'", page))
if "hDrill(" in page:
    called.add("drill")
man = json.load(open(os.path.join(ROOT, "agents", "certificate", "manifest.json"), encoding="utf-8"))
ts = man.get("tag_scope") or {}
declared = set(ts.get("actions") or []) | set(ts.get("ignore") or [])
check(called and called <= declared, f"page actions {sorted(called)} all declared in tag_scope")
check(set(ts.get("actions") or []) == set(CA.ACTIONS), "every action honours the scope (none ignored)")
check("mountTagScope({agent:'certificate'" in page and page.index("mountTagScope(") > page.index("mountAgentHeader("),
      "page mounts the tag bar after its header")
check("tagScopeNote()" in page and page.count("tagScopeNote()") >= 3, "confirm dialogs name the scope")
tagscope._POLICY.pop("certificate", None)
for a in sorted(called):
    check(tagscope.check("certificate", a, {"tag_scope": {"key": TK, "value": TV}}) is None, f"launcher accepts scoped {a}")
check(tagscope.check("certificate", "nope", {"tag_scope": {"key": TK, "value": TV}}) is not None,
      "launcher refuses a scoped undeclared action")

# ── 5. scoped writes: the set is re-read on the server and stays inside the tag ───────────
pages, plain = [], []
def fake_pages(cat, val, batches, **kw):          # navi is never run
    batches = list(batches)
    pages.append((cat, val, batches))
    return [{"ok": True, "job_id": len(pages)}] if batches else []


navi_cli.tag_pages = fake_pages
_collect = navi_cli.collect_uuids
got = []


def spy_collect(sql, params=(), path=None):
    r = _collect(sql, params, path)
    got.append((sql, tuple(params), r))
    return r


navi_cli.collect_uuids = spy_collect
navi_cli.tag = lambda *a, **k: (plain.append((a, k)) or {"ok": True, "job_id": 99})
vals = sorted({r["tag_value"] for r in srows})
w, _ = CA.tags_apply(dict(S, values=vals, confirm=True, uuids=["evil-uuid"], asset_uuids=["evil-uuid"]))
check(w["ok"] and w["queued"] == len(vals) and w.get("scope"), "scoped tags_apply queues every selected date")
sel = set().union(*[set(r) for _s, _p, r in got]) if got else set()
check(got and all(_p[-2:] == (TK, TV) for _s, _p, _r in got), "the tag scope is bound into every set query (server-side)")
check(sel and sel <= TAGGED and "evil-uuid" not in sel, "scoped date tagging selects only tagged assets")
# hand: every tagged asset with a cert on one of those dates
exp_sel = {r["asset_uuid"] for r in srows}
check(sel == exp_sel, "…exactly the tagged assets behind the selected dates")
# the same dates in the estate reach more (or equal) assets — the scope really narrowed it
got.clear()
CA.tags_apply({"values": vals, "confirm": True})
est_sel = set().union(*[set(r) for _s, _p, r in got]) if got else set()
check(est_sel >= sel and all(not _p for _s, _p, _r in got), "estate tags_apply: the pre-489 unscoped set queries")
got.clear()
issues = [{"plugin_id": x["plugin_id"], "plugin_name": x["plugin_name"]} for x in R["cert_issue_matrix"]]
plain.clear()
w, _ = CA.tags_issues(dict(S, issues=issues, confirm=True))
check(w["ok"] and w["queued"] == len(issues) and not plain, "scoped tags_issues computes the set (no estate-wide navi --plugin)")
isel = set().union(*[set(r) for _s, _p, r in got]) if got else set()
check(isel and isel <= TAGGED, "scoped cert-issue tagging stays inside the tag")
hand = {r[0] for r in con.execute("SELECT DISTINCT asset_uuid FROM vulns WHERE plugin_name LIKE '%Certificate%' AND asset_uuid IN "
                                  "(SELECT asset_uuid FROM tags WHERE tag_key=? AND tag_value=?)", (TK, TV))}
check(isel == hand, "…exactly the tagged assets those plugins fired on")
w, _ = CA.tags_issues({"issues": issues, "confirm": True})
check(len(plain) == len(issues) and all(k.get("plugin") and k.get("remove") is False for _a, k in plain),
      "estate tags_issues: unchanged navi --plugin, remove=False")
w, _ = CA.tags_apply(dict(S, values=vals, confirm="true"))
check(w.get("ok") is False, "a scoped write still needs confirm = JSON true")
w, _ = CA.tags_apply({"tag_scope": {"key": "no such key", "value": "x"}, "values": vals, "confirm": True})
check(w.get("ok") is False, "a scoped write to a tag with no assets is refused")
navi_cli.collect_uuids = _collect

# ── 6. own caches keep scoped and estate apart ───────────────────────────────────────────
check(CA._TAG_RESULTS.get((TK, TV)) is not None and CA.AGENT.result is EST_RESULT, "tag result cached apart from AGENT.result")
pairs_t = con.execute("SELECT DISTINCT tag_key, tag_value FROM tags WHERE TRIM(COALESCE(tag_value,''))<>'' "
                      "ORDER BY tag_key, tag_value LIMIT 8").fetchall()
first_other = None
for k, v in pairs_t:
    if (k, v) == (TK, TV):
        continue
    oo, _ = CA.run({"tag_scope": {"key": k, "value": v}})
    first_other = first_other or (k, v, oo["drill"]["run"])
check(len(CA._TAG_RESULTS) <= tagscope.MAX_TAGS, "the tag result cache holds at most 5 tags")
check(payload.STORE.run_info(EST_RUN, "certificate") is not None, "many tag runs never prune the estate's drill rows")
d, _ = CA.drill({"run": EST_RUN, "section": "certs", "sort": "near"})
check(d.get("ok", True) is not False and d["total"]["value"] == est["metrics"]["expired"] + est["metrics"]["failing"],
      "the estate's run still pages after the tag runs")
n_tag_runs = len([1 for _ in CAg.TAG_STORE._connect().execute("SELECT 1 FROM runs WHERE hound=?", (CAg.TAG_HOUND,))])
check(n_tag_runs <= tagscope.MAX_TAGS * CAg.TAG_KEEP_PER_SCOPE, f"tag runs bounded ({n_tag_runs})")
# the newest 5 tags each keep their run
newest = list(CA._TAG_RESULTS.items())
check(all(CAg.TAG_STORE.run_info(r["run"], CAg.TAG_HOUND) for _k, r in newest), "each of the newest 5 tags keeps its run")
# re-running the estate doesn't touch tag runs
b2, _ = CA.run({})
check(all(CAg.TAG_STORE.run_info(r["run"], CAg.TAG_HOUND) for _k, r in newest), "an estate run keeps the tag runs")
check(b2["result"]["metrics"] == est["metrics"], "and the estate metrics are unchanged after all the tag runs")
# the read cache keys on the payload: a scoped and an unscoped request never share a key
try:
    kf = getattr(launcher, "_cache_key", None) or getattr(launcher, "_key", None)
    if kf:
        check(kf("certificate", "drill", {"run": "x"}) != kf("certificate", "drill", {"run": "x", "tag_scope": {"key": TK, "value": TV}}),
              "launcher read-cache key differs with a scope")
except Exception as e:
    print("note: launcher key check skipped:", e)

con.close()
print("\n%d failure(s)" % len(fails) if fails else "\nALL PASS")
sys.exit(1 if fails else 0)
