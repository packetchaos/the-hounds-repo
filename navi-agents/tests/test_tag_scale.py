"""Tag-path scale regression (build 453): every hound's tag reaches navi as an argument that fits.

navi gets `navi enrich tag --c C --v V --query "<SQL>"`; the --query is ONE argv element and
Linux refuses one argument over 128 KiB ("Argument list too long" — an inline UUID IN-list of
~3,300+ assets). The standard now (core.navi_cli.tag_set): the Hounds compute the tag's asset set
(the hound's own SQL condition, streamed, or its Python result) and page it — ≤ 1,999 assets → one
navi job; more → a TAG SERIES on core.tagq (one job per ≤ 1,999-UUID page, one at a time, progress,
retry one page, cancel the rest), add-only, every argument guarded at < 100 KB.

  A. the shared helper: batching, byte guard, refusals, tag_capped routing; the series itself
     (5,000 assets → pages of 1,999/1,999/1,002, progress, retry one page, cancel the rest).
  B. a generated 150k-asset navi.db: each hound tag path → the argv navi would get (subprocess
     stubbed, tag queue run inline) has every argument < 100 KB, and the tags select the full set.
  C. the small test DBs (/home/claude/act/*.db): each tag path selects the SAME assets as build
     452 did (/home/claude/base452) — the query navi would run is evaluated on the DB per build.
     Skipped when either is missing.

No navi, no network. Run: python3 tests/test_tag_scale.py  (or pytest).
`python3 tests/test_tag_scale.py --harness <repo root> <navi.db> <out.json>` records the tag calls
one build makes on one DB (used by part C and by the before/after argument-size measurement)."""
import atexit
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
LIMIT = 100_000
BASE452 = os.environ.get("HOUNDS_BASE452", "/home/claude/base452")
ACT = os.environ.get("HOUNDS_ACT_DIR", "/home/claude/act")


# =========================================================================== harness
def harness(root, dbp, out):
    """Run every hound tag path of the build at `root` on `dbp`, recording each navi_cli.tag
    call (category, value, selector). Nothing is written; navi is never run."""
    sys.path.insert(0, root)
    os.environ["NAVI_DB_PATH"] = dbp
    tmp = tempfile.mkdtemp(prefix="hounds-tagscale-h-")
    os.environ["NAVI_CACHE_DIR"] = os.path.join(tmp, "cache")
    os.environ["NAVI_TAGLOG_DB"] = os.path.join(tmp, "tl.db")
    os.environ["HOUNDS_CONFIG"] = os.path.join(tmp, "cfg.json")
    os.environ["NAVI_HISTORY_DIR"] = os.path.join(tmp, "hist")
    os.environ.pop("NAVI_ALLOW_WRITES", None)
    from core import navi_cli
    rec, errs = [], {}
    cur = {"case": ""}

    def fake_tag(category="", value="", query="", remove=False, agent="", sync=False, op="tag",
                 business_case="", **sel):
        rec.append({"case": cur["case"], "category": category, "value": value, "query": query or "",
                    "remove": bool(remove),
                    "sel": {k: str(v) for k, v in sel.items() if v not in (None, "", False)}})
        return {"ok": True, "queued": True, "job_id": len(rec)}
    navi_cli.tag = fake_tag
    try:
        from core import tagq as _tq

        def fake_series(fn, pages, meta=None, runner=""):
            for kw, _n in pages:
                fake_tag(**kw)
            return {"series": "s-x", "pages": len(pages), "assets": 0, "job_ids": [], "id": None}
        _tq.submit_series = fake_series
    except Exception:
        pass

    def case(name, fn):
        cur["case"] = name
        try:
            fn()
        except Exception as e:                       # a path a DB can't exercise — compared as such
            errs[name] = "%s: %s" % (type(e).__name__, e)

    from core import db

    def have(t):
        return bool(db.scalar("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (t,)))

    def c_scan_eval():
        from agents.scan_eval import api
        from core import scan_eval
        for k in api.VALUES:
            api.tag({"confirm": True, "key": k})
        ev = scan_eval.evaluate(keep_uuids=True)
        for dim, names in ev["_dim_uuids"].items():
            for nm in sorted(names)[:3]:
                api.tag({"confirm": True, "key": dim, "name": nm})

    def c_compliance():
        from agents.compliance import api
        if not have("compliance"):
            return
        for r in db.query("SELECT DISTINCT check_id FROM compliance WHERE upper(status) LIKE 'FAIL%' "
                          "ORDER BY check_id LIMIT 25"):
            api.tag({"confirm": True, "owner": "Owner X", "check_id": r["check_id"]})

    def c_cisakev():
        from agents.cisakev import api
        from core import kev
        a = kev.analyze(allow_live=False)
        dues = sorted({c["due_date"] for c in a.get("cves", []) if c.get("due_date")})
        if dues:
            api.tag_due({"confirm": True, "dues": dues})
        api.tag_ransomware({"confirm": True})

    def c_eol():
        from agents.eol import api
        from core import eol
        dates = [g["eol_date"] for g in eol.analyze().get("date_groups", [])]
        if dates:
            api.tag_eol_date({"confirm": True, "dates": dates})

    def c_certificate():
        from agents.certificate import api
        if not have("certs"):
            return
        res = api.AGENT.run()
        vals = sorted({a["value"] for a in res.get("tag_actions", [])})
        if vals:
            api.tags_apply({"confirm": True, "values": vals})

    def c_fused():
        from agents.fused_score import api
        from core import fused_score as fs
        api._tag_set(fs.select_uuids(threshold=80), "P1")

    def c_ai():
        from agents.ai import api
        from core import ai_assets
        res = ai_assets.scan()
        sets = ai_assets.atlas_sets(res.get("assets"))
        for t in sorted(sets["tech"]):
            if t in ai_assets.ATLAS_TECH:
                api.tag_atlas({"confirm": True, "key": "tech:" + t})
        for t in sorted(sets["tactic"]):
            if t in ai_assets.ATLAS_TACTIC_ORDER:
                api.tag_atlas({"confirm": True, "key": "tactic:" + t})
        allu = [x["asset_uuid"] for x in res.get("assets") or []]
        if allu:
            api.tag({"confirm": True, "category": "AI", "value": "Present", "uuids": allu})

    def c_identity():
        from agents.identity import api
        from core import identity
        res = identity.scan()
        for a in (res.get("accounts") or [])[:6]:
            api._tag_one("Identity", a["user"], a.get("asset_uuids"))
        for k, uu in sorted((res.get("host_sets") or {}).items())[:4]:
            api._tag_one("Identity Risk", k, uu)

    def c_attackpath():
        from agents.attackpath import api
        api.tag_entry({"confirm": True})
        api.tag_target({"confirm": True})

    def c_postquantum():
        from agents.postquantum import api
        from agents.postquantum.agent import transport_analysis
        for s in transport_analysis().get("signals", []):
            if not s.get("assets"):
                continue
            if hasattr(api, "tag_signal"):            # 453: the page sends the signal key
                api.tag_signal({"confirm": True, "key": s["key"]})
            else:                                      # 452: the page sent the signal's uuids
                api.tag_uuids({"confirm": True, "category": "PQC Transport", "value": s["key"],
                               "uuids": s["uuids"]})
        api.tag({"confirm": True})

    def c_asset_ownership():
        from agents.asset_ownership import api
        from core import asset_ownership as eng
        for prompt in ("assign Jane Smith to production", "assign Bob Ray to all assets"):
            p = eng.plan(prompt)
            if not p.get("ok") or not p.get("uuids"):
                continue
            body = {"confirm": True, "owner": p["owner"], "layer": "business"}
            if hasattr(eng, "match_filter"):           # 453: the page sends the plan's filter
                body["filter"] = p.get("filter") or {}
            else:
                body["uuids"] = p["uuids"]
            api.apply(body)

    def c_classify():
        from agents.classify import api
        from core import classify
        for c in (classify.os_signals(only_untagged=True).get("cohorts") or [])[:4]:
            if c.get("uuids"):
                api.tag({"confirm": True, "facet": c.get("facet"), "value": c.get("value"), "uuids": c["uuids"]})

    def c_contract():
        from core import contract as C
        os.environ["HOUNDS_LLM_DISABLE"] = "1"
        p = C.plan()
        for blk in p.get("agents", []):
            cur["case"] = "contract:" + blk["agent"]
            for it in blk.get("items") or []:
                sp = dict(it["spec"])
                fake_tag(**sp)

    for name, fn in [("scan_eval", c_scan_eval), ("compliance", c_compliance), ("cisakev", c_cisakev),
                     ("eol", c_eol), ("certificate", c_certificate), ("fused_score", c_fused),
                     ("ai", c_ai), ("identity", c_identity), ("attackpath", c_attackpath),
                     ("postquantum", c_postquantum), ("asset_ownership", c_asset_ownership),
                     ("classify", c_classify), ("contract", c_contract)]:
        case(name, fn)
    with open(out, "w") as f:
        json.dump({"rec": rec, "errors": errs}, f)
    shutil.rmtree(tmp, ignore_errors=True)


if len(sys.argv) >= 5 and sys.argv[1] == "--harness":
    harness(sys.argv[2], sys.argv[3], sys.argv[4])
    sys.exit(0)


# =========================================================================== test setup
sys.path.insert(0, ROOT)
TMP = tempfile.mkdtemp(prefix="hounds-tagscale-")
atexit.register(shutil.rmtree, TMP, ignore_errors=True)
for k, v in {"NAVI_CACHE_DIR": "cache", "NAVI_TAGLOG_DB": "tl.db", "HOUNDS_CONFIG": "cfg.json",
             "NAVI_HISTORY_DIR": "hist"}.items():
    os.environ[k] = os.path.join(TMP, v)
BIG = os.path.join(TMP, "big.db")
os.environ["NAVI_DB_PATH"] = BIG
os.environ["NAVI_ALLOW_WRITES"] = "1"
os.environ["NAVI_BIN"] = sys.executable           # any existing absolute path: navi "is available"
os.environ["NAVI_CWD"] = TMP
os.environ["NAVI_TAG_GAP_MS"] = "0"
os.environ["NAVI_SERIES_PAUSE_MS"] = "0"

fails = []


def check(cond, msg):
    print(("PASS " if cond else "FAIL ") + msg)
    if not cond:
        fails.append(msg)


from core import navi_cli, tagq  # noqa: E402

ARGV = []


class _P:
    returncode, stdout, stderr = 0, "Your tag is being updated", ""


class _Fail:
    returncode, stdout, stderr = 1, "", "HTTP 500 from Tenable"


FAIL_IF = {"marker": None}            # a page whose --query holds this uuid fails
HOLD = {"ev": None}                   # block navi until set (cancel test)


def _fake_run(cmd, **k):
    if HOLD["ev"] is not None:
        HOLD["ev"].wait(10)
    ARGV.append(list(cmd))
    if FAIL_IF["marker"] and any(FAIL_IF["marker"] in x for x in cmd):
        return _Fail()
    return _P()


_REAL_RUN = subprocess.run                          # navi_cli.subprocess IS this module — keep the real one
navi_cli.subprocess.run = _fake_run
_JOBS = {"n": 0}


def _inline_submit(fn, kwargs, meta=None):
    """The tag queue, run inline: the navi command is built (and captured) right away."""
    _JOBS["n"] += 1
    fn(**kwargs)
    return {"id": _JOBS["n"], "status": "done"}


tagq.submit = _inline_submit


def wait_idle(t=60):
    """Wait until no tag-series page is queued or running (series run on the real queue)."""
    import time as _t
    end = _t.time() + t
    while _t.time() < end:
        with tagq._LOCK:
            busy = any(j.get("status") in ("queued", "running") for j in tagq._JOBS
                       if j.get("series") and not (tagq._SERIES.get(j["series"]) or {}).get("cancelled"))
        if not busy and tagq._Q.unfinished_tasks == 0:
            return True
        _t.sleep(0.05)
    return False


def U(i):
    return "%08x-0000-4000-8000-%012x" % (i, i)


# =========================================================================== A. helper
uu = [U(i) for i in range(10_000)]
bs = navi_cli.uuid_batches(uu + uu[:50] + ["", None])
check(len(bs) == 6 and max(len(b) for b in bs) <= 1999 and sum(len(b) for b in bs) == 10_000
      and sorted(x for b in bs for x in b) == sorted(uu),
      "uuid_batches: 10,000 UUIDs (dupes/blanks dropped) → 6 batches of ≤ 1,999, every UUID once")
check(all(len(navi_cli.uuids_query(b).encode()) < LIMIT for b in bs), "every batch query < 100 KB")
long_ids = ["x" * 400 + str(i) for i in range(2000)]
lb = navi_cli.uuid_batches(long_ids)
check(len(lb) > 1 and all(len(navi_cli.uuids_query(b).encode()) < LIMIT for b in lb)
      and sum(len(b) for b in lb) == 2000, "byte guard splits batches of long ids by size, not just count")
check(navi_cli.uuid_batches(["y" * 200_000]) == [], "an id that can never fit is dropped, not sent")
check(navi_cli.uuids_query(["a'b"]) == "SELECT uuid AS asset_uuid FROM assets WHERE uuid IN ('a''b')",
      "uuids_query keeps the assets shape and escapes quotes")
check(navi_cli.uuids_query(["a"], "asset_uuid", "compliance")
      == "SELECT DISTINCT asset_uuid FROM compliance WHERE asset_uuid IN ('a')", "uuids_query over another table")
ARGV.clear()
r = navi_cli.tag("Big", "Q", query="SELECT 1 WHERE '" + "z" * 120_000 + "'")
check(r.get("ok") is False and r.get("refused") and not ARGV, "tag() refuses a >100 KB --query up front (never queued)")
r = navi_cli._tag_exec("Big", "Q", query="x" * 150_000)
check(r.get("ok") is False and r.get("refused") and not ARGV, "_tag_exec's hard guard never runs an oversize argv")
r = navi_cli._acr_exec("C", "V" * 150_000, 9, reasons=["business"])
check(r.get("ok") is False and r.get("refused") and not ARGV, "_acr_exec's hard guard too")
ARGV.clear()
jobs = navi_cli.tag_uuids_batched("Cat", "Val", uu, agent="test")
wait_idle()
check(len(jobs) == 6 and len(ARGV) == 6 and all("-remove" not in a for a in ARGV)
      and all(a[a.index("--c") + 1] == "Cat" and a[a.index("--v") + 1] == "Val" for a in ARGV),
      "tag_uuids_batched: one add-only navi job per batch, one category/value")
check(max(len(x.encode()) for a in ARGV for x in a) < LIMIT, "…every argument < 100 KB")
ARGV.clear()
big_q = navi_cli.uuids_query(uu)
jobs = navi_cli.tag_capped("Cat", "Val", uuids=uu, query=big_q)
wait_idle()
check(len(ARGV) == 6 and max(len(x.encode()) for a in ARGV for x in a) < LIMIT,
      "tag_capped: an oversize IN-list query with its uuids falls back to batches")
ARGV.clear()
jobs = navi_cli.tag_capped("Cat", "Val", uuids=uu, remove=True)
check(jobs and jobs[0].get("ok") is False and not ARGV, "tag_capped: a batched set is never removed (-remove)")
ARGV.clear()
jobs = navi_cli.tag_capped("Cat", "Val", uuids=uu, query="SELECT asset_uuid FROM vulns WHERE plugin_id='1'")
check(len(ARGV) == 1 and ARGV[0][-1].startswith("SELECT asset_uuid FROM vulns"),
      "tag_capped: a predicate query is sent as ONE job (navi re-selects the full set)")
ARGV.clear()
jobs = navi_cli.tag_capped("Cat", "Val", uuids=uu, fallbacks=[{"plugin": "20811", "output": "x"}])
check(len(ARGV) == 1 and "--plugin" in ARGV[0], "tag_capped: over the cap with built-in fallbacks → navi built-ins")

# ---- the tag SERIES (core.tagq): paging, progress, retry one page, cancel the rest
ARGV.clear()
five = [U(100_000 + i) for i in range(5000)]
jobs = navi_cli.tag_set("Series", "Five", uuids=five, agent="test")
wait_idle()
sid = jobs[0].get("series") if jobs else None
pr = tagq.series_progress(sid) if sid else {}
check(len(jobs) == 3 and [j.get("page") for j in jobs] == [1, 2, 3] and len({j.get("series") for j in jobs}) == 1,
      "5,000 assets → ONE tag series of 3 page jobs")
check([a[-1].count("','") + 1 for a in ARGV] == [1999, 1999, 1002], "…pages of 1,999 / 1,999 / 1,002 UUIDs, in order")
check(pr.get("pages") == 3 and pr.get("done") == 3 and pr.get("assets") == 5000 and pr.get("assets_done") == 5000,
      "…progress: 3 of 3 pages done, 5,000 of 5,000 assets")
lj = [j for j in tagq.list_jobs() if j.get("series") == sid]
check(len(lj) == 3 and all(j.get("pages") == 3 and "page %d of 3" % j["page"] in j.get("detail", "") for j in lj),
      "…the Tagging log shows each page as 'page n of N' with its own row")
check(all(tagq.job_output(j["id"]) for j in lj), "…each page keeps its own navi output")
check(max(len(x.encode()) for a in ARGV for x in a) < LIMIT and all("-remove" not in a for a in ARGV),
      "…every page's argument < 100 KB, add-only")
# a failed page, retried alone
ARGV.clear()
FAIL_IF["marker"] = five[2500]                       # lives in page 2
jobs = navi_cli.tag_set("Series", "Retry", uuids=five, agent="test")
wait_idle()
sid2 = jobs[0]["series"]
pr = tagq.series_progress(sid2)
check(pr["done"] == 2 and pr["error"] == 1 and len(ARGV) == 3,
      "a failing page does not stop the series (pages 1 and 3 done, page 2 error)")
FAIL_IF["marker"] = None
bad = next(j for j in tagq.list_jobs() if j.get("series") == sid2 and j.get("status") == "error")
ARGV.clear()
rr = navi_cli.retry_page(bad["id"])
wait_idle()
pr = tagq.series_progress(sid2)
check(rr.get("ok") and bad["page"] == 2 and len(ARGV) == 1 and five[2500] in ARGV[0][-1] and pr["done"] == 3,
      "retry re-runs ONLY the failed page; the series is then 3 of 3")
check(not navi_cli.retry_page(lj[0]["id"]).get("ok"), "a page that succeeded can't be re-run as a retry")
# cancel the rest
import threading as _th  # noqa: E402
ARGV.clear()
HOLD["ev"] = _th.Event()
jobs = navi_cli.tag_set("Series", "Cancel", uuids=five, agent="test")
sid3 = jobs[0]["series"]
cn = navi_cli.cancel_series(sid3)
HOLD["ev"].set()
HOLD["ev"] = None
wait_idle()
pr = tagq.series_progress(sid3)
check(cn["cancelled"] >= 2 and pr["cancelled"] >= 2 and pr["done"] <= 1 and len(ARGV) <= 1,
      "cancel stops the rest of the series (waiting pages → cancelled, never run)")
check(navi_cli.retry_page(next(j["id"] for j in tagq.list_jobs() if j.get("series") == sid3
                               and j.get("status") == "cancelled")).get("ok"), "a cancelled page can be retried alone")
wait_idle()
os.environ.pop("NAVI_ALLOW_WRITES")
ARGV.clear()
jobs = navi_cli.tag_set("Series", "Gated", uuids=five, agent="test")
wait_idle()
pr = tagq.series_progress(jobs[0]["series"])
check(not ARGV and pr["error"] == 3, "writes gate: with NAVI_ALLOW_WRITES unset every page is blocked (navi never runs)")
os.environ["NAVI_ALLOW_WRITES"] = "1"


# =========================================================================== B. 150k assets
N = 150_000
KEV = "{'type': 'CISA-KNOWN-EXPLOITED', 'id': '2021/12/10'}"
SCANINFO = ("Information about this scan : \nNessus version : 10.8.3\nPlugin feed version : 202611010000\n"
            "Scan type : Normal\nScan name : Big Scan\nScan policy used : Basic Network Scan\n"
            "Scanner IP : 10.9.9.9\nCredentialed checks : no\nSafe checks : yes\n"
            "Scan Start Date : 2020/1/2 3:04 UTC\nScan duration : 4000 sec\n")


def build_big(path):
    c = sqlite3.connect(path)
    c.executescript("""PRAGMA journal_mode=OFF; PRAGMA synchronous=OFF;
    CREATE TABLE assets (uuid TEXT, hostname TEXT, ip_address TEXT, acr TEXT, aes TEXT, operating_system TEXT);
    CREATE TABLE vulns (asset_uuid TEXT, plugin_id TEXT, plugin_name TEXT, plugin_family TEXT, severity TEXT,
                        score REAL, cves TEXT, xrefs TEXT, state TEXT, output TEXT, first_found TEXT, last_found TEXT);
    CREATE TABLE tags (asset_uuid TEXT, tag_key TEXT, tag_value TEXT);
    CREATE TABLE certs (asset_uuid TEXT, common_name TEXT, organization TEXT, organization_unit TEXT,
                        not_valid_after TEXT, signature_algorithm TEXT, key_length TEXT);
    CREATE TABLE compliance (asset_uuid TEXT, check_id TEXT, check_name TEXT, audit_file TEXT, status TEXT,
                             reference TEXT);""")
    ids = [U(i) for i in range(N)]
    c.executemany("INSERT INTO assets VALUES (?,?,?,?,?,?)",
                  ((u, "h%d" % i, "10.%d.%d.%d" % (i >> 16, (i >> 8) & 255, i & 255), "9", "0", "Linux")
                   for i, u in enumerate(ids)))
    ff, lf = "2021-12-11T00:00:00.000Z", "2020-01-02T00:00:00.000Z"
    rows = []
    for u in ids:
        rows += [(u, "19506", "Nessus Scan Information", "Settings", "info", 0, "", "", "open", SCANINFO, ff, lf),
                 (u, "21745", "OS Security Patch Assessment Failed", "Settings", "info", 0, "", "", "open", "", ff, lf),
                 (u, "155999", "Apache Log4j < 2.15.0 RCE", "Misc.", "critical", 10.0, "CVE-2021-44228", KEV,
                  "open", "", ff, lf),
                 (u, "33850", "Unix Operating System Unsupported Version Detection", "General", "critical", 10.0,
                  "", "", "open", "The remote OS is no longer supported.\nEnd of life date : 2020-01-14\n", ff, lf)]
    c.executemany("INSERT INTO vulns VALUES (?,?,?,?,?,?,?,?,?,?,?,?)", rows)
    c.executemany("INSERT INTO certs VALUES (?,?,?,?,?,?,?)",
                  ((u, "svc.example.com", "Example", "IT", "Jan 14 00:00:00 2020 GMT", "sha256WithRSAEncryption",
                    "2048") for u in ids))
    c.executemany("INSERT INTO compliance VALUES (?,?,?,?,?,?)",
                  ((u, "CIS-1.1", "Password length", "cis.audit", "FAILED", "") for u in ids))
    c.executemany("INSERT INTO tags VALUES (?,?,?)", ((u, "Environment", "Production") for u in ids))
    c.commit()
    c.close()


build_big(BIG)
ALL = {U(i) for i in range(N)}
BIGC = sqlite3.connect(BIG)


def selected(argvs):
    """The asset set navi would tag for these commands (each --query evaluated on navi.db)."""
    out = set()
    for a in argvs:
        if "--query" in a:
            out |= {r[0] for r in BIGC.execute(a[a.index("--query") + 1])}
    return out


def big_case(label, fn, expect=ALL):
    ARGV.clear()
    try:
        fn()
        wait_idle(120)
    except Exception as e:
        check(False, "%s at 150k assets: raised %s: %s" % (label, type(e).__name__, e))
        return
    mx = max((len(x.encode()) for a in ARGV for x in a), default=0)
    sel = selected(ARGV) if expect is not None else None
    check(ARGV and mx < LIMIT and (expect is None or sel == expect),
          "%s at 150k assets: %d navi job(s), largest argument %s bytes%s"
          % (label, len(ARGV), format(mx, ","), "" if expect is None else ", tags all %s assets" % format(len(sel), ",")))
    return ARGV[:]


from agents.scan_eval import api as SE  # noqa: E402
for k in ("status:uncredentialed", "patch:failed", "fresh:90+", "slow"):
    big_case("scan_eval " + k, lambda k=k: SE.tag({"confirm": True, "key": k}))
big_case("scan_eval scanner dim", lambda: SE.tag({"confirm": True, "key": "scanner", "name": "10.9.9.9"}))
pa = big_case("scan_eval patch:failed (predicate)", lambda: SE.tag({"confirm": True, "key": "patch:failed"}))
check(pa and len(pa) == 76, "…patch:failed: the SQL condition's set, paged (76 pages)")
from agents.compliance import api as CO  # noqa: E402
co = big_case("compliance Audit Owner", lambda: CO.tag({"confirm": True, "owner": "Jane", "check_id": "CIS-1.1"}))
check(co and len(co) == 76, "…paged: 76 pages")
from agents.cisakev import api as KA  # noqa: E402
from core import kev as _kev  # noqa: E402
_due = next((c["due_date"] for c in _kev.analyze(allow_live=False).get("cves", []) if c["cve"] == "CVE-2021-44228"), None)
kd = big_case("cisakev due date", lambda: KA.tag_due({"confirm": True, "dues": [_due]}))
check(kd and len(kd) == 76, "…paged: 76 pages")
big_case("cisakev ransomware", lambda: KA.tag_ransomware({"confirm": True}))
from agents.eol import api as EA  # noqa: E402
ed = big_case("eol date", lambda: EA.tag_eol_date({"confirm": True, "dates": ["2020-01-14"]}))
check(ed and len(ed) == 76, "…paged: 76 pages")
from agents.certificate import api as CA  # noqa: E402
CA.AGENT.result = None
cd = big_case("certificate expiry date", lambda: CA.tags_apply({"confirm": True, "values": ["Jan-14-2020"]}))
check(cd and len(cd) == 76, "…paged: 76 pages")
from agents.fused_score import api as FA  # noqa: E402
big_case("fused_score Priority (batched)", lambda: FA._tag_set(sorted(ALL), "P1"))
from agents.identity import api as IA  # noqa: E402
big_case("identity account (batched)", lambda: IA.tag({"confirm": True, "category": "Identity", "value": "root",
                                                       "asset_uuids": sorted(ALL)}))
from agents.postquantum import api as PA  # noqa: E402
big_case("postquantum tag_uuids (batched)", lambda: PA.tag_uuids({"confirm": True, "category": "PQC Risk",
                                                                  "value": "Vulnerable : RSA", "uuids": sorted(ALL)}))
big_case("postquantum roadmap_tag (batched)", lambda: PA.roadmap_tag({"confirm": True, "uuids": sorted(ALL)}))
from agents.attackpath import api as AP  # noqa: E402
big_case("attackpath Pivot (server-side role set, paged)", lambda: AP._tag(sorted(ALL), "Pivot", {"confirm": True}))
check(AP.tag({"confirm": True, "value": "Pivot", "uuids": ["x"]})[1] == 400,
      "attackpath tag refuses a client UUID list (it takes a key: entry/target/pivot/fix:<fix>)")
from agents.software import api as SW  # noqa: E402
big_case("software tag, no name (batched)", lambda: SW.tag({"confirm": True, "value": "OpenSSL", "uuids": sorted(ALL)}))
from agents.classify import api as CL  # noqa: E402
big_case("classify cohort (batched)", lambda: CL.tag({"confirm": True, "facet": "OS", "value": "Linux",
                                                      "uuids": sorted(ALL)}))
from agents.ai import api as AIA  # noqa: E402
big_case("ai tag (batched)", lambda: AIA.tag({"confirm": True, "category": "AI", "value": "Present",
                                              "uuids": sorted(ALL)}))
from agents.asset_ownership import api as OA  # noqa: E402
big_case("asset_ownership business owner (filter → server set, batched)",
         lambda: OA.apply({"confirm": True, "owner": "Jane", "layer": "business",
                           "filter": {"tags": [{"key": "Environment", "value": "Production"}]}}))
from core import acr_protect  # noqa: E402
big_case("acr_protect NO : UPDATE (batched)", lambda: acr_protect.protect(sorted(ALL), agent="acr"))
from core import contract as C  # noqa: E402
sp = C._uuid_specs("Priority", "P1", sorted(ALL))
check(len(sp) == 76 and max(len(s["query"].encode()) for s in sp) < LIMIT
      and {x for s in sp for x in (r[0] for r in BIGC.execute(s["query"]))} == ALL,
      "contract _uuid_specs: 150k → 76 batches < 100 KB, the full set")
fat = [{"label": "x", "rank": 1, "unit": "u", "spec": {"category": "c", "value": "v", "remove": False,
                                                      "query": navi_cli.uuids_query(sorted(ALL)[:5000])}}]
fs = C._enforce_size(fat)
check(len(fs) == 3 and max(len(i["spec"]["query"].encode()) for i in fs) < LIMIT,
      "contract _enforce_size splits an oversize IN-list into ≤1,999 / < 100 KB candidates")
BIGC.close()


# =========================================================================== C. same assets as 452
def run_harness(root, dbp):
    out = os.path.join(TMP, "h-%s-%s.json" % (os.path.basename(root.rstrip("/")), os.path.basename(dbp)))
    env = {k: v for k, v in os.environ.items() if not k.startswith(("NAVI_", "HOUNDS_"))}
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    p = _REAL_RUN([sys.executable, os.path.abspath(__file__), "--harness", root, dbp, out],
                       cwd=TMP, env=env, capture_output=True, text=True, timeout=900)
    if not os.path.exists(out):
        raise RuntimeError("harness failed for %s on %s: %s" % (root, dbp, (p.stderr or p.stdout)[-1500:]))
    with open(out) as f:
        return json.load(f)


def selection(res, dbp):
    """{(case, category, value): sorted asset set + built-in selectors} for one build/DB."""
    c = sqlite3.connect("file:%s?mode=ro" % dbp, uri=True)
    out = {}
    for r in res["rec"]:
        k = (r["case"], r["category"], r["value"])
        s = out.setdefault(k, set())
        if r["query"]:
            s |= {str(x[0]) for x in c.execute(r["query"])}
        if r["sel"]:
            s.add("sel:" + json.dumps(r["sel"], sort_keys=True))
    c.close()
    return {k: sorted(v) for k, v in out.items()}


DBS = ["navi_test.db", "kev_full.db", "eol_full.db", "cert_full.db", "scan_full.db", "ai_full.db",
       "id_full.db", "ap_full.db"]
if not (os.path.isdir(os.path.join(BASE452, "core")) and os.path.isdir(ACT)):
    print("SKIP part C (no %s or %s)" % (BASE452, ACT))
else:
    for name in DBS:
        dbp = os.path.join(ACT, name)
        if not os.path.exists(dbp):
            continue
        old, new = run_harness(BASE452, dbp), run_harness(ROOT, dbp)
        so, sn = selection(old, dbp), selection(new, dbp)
        diff = sorted(str(k) for k in set(so) | set(sn) if so.get(k) != sn.get(k))
        cases = sorted({r["case"].split(":")[0] for r in new["rec"]})
        check(not diff and set(old["errors"]) == set(new["errors"]),
              "%s: every tag selects the same assets as build 452 (%d tags across %s)%s"
              % (name, len(sn), ", ".join(cases), (" — differs: " + "; ".join(diff[:4])) if diff else ""))
        big_new = max((len(r["query"].encode()) for r in new["rec"]), default=0)
        check(big_new < LIMIT, "%s: largest --query now %s bytes" % (name, format(big_new, ",")))

print("\n%d failure(s)" % len(fails))
if __name__ == "__main__":
    sys.exit(1 if fails else 0)
