"""Regression tests — the bug & security sweep of the scale work (builds 452 → 456).

Each check pins a defect the sweep reproduced:
  · a confirmed write (Contract run_now) is never cancelled by a disconnect / supersede
  · supersede cancels only the SAME request from a tab (payload-aware)
  · a background job keeps the caller's identity (a remote hx_cancel stays 403)
  · c2's LIKE matcher is linear (no regex backtracking) and equals SQLite LIKE
  · a sync chain refreshes the summaries only after its last sync; the Contract waits for
    ⚡ Optimize instead of skipping the vulns sync
  · the polled Tagging log sends a summary of long --query selectors, not 78 KB per page
  · retrying one page of a tag series doesn't make the series run two pages at once
  · hx_optimize's read connection escapes the navi.db path
Synthetic; no Tenable. Run: python3 tests/test_sweep_456.py"""
import atexit
import os
import random
import shutil
import sqlite3
import sys
import tempfile
import threading
import time
import faulthandler; faulthandler.dump_traceback_later(240, exit=True)

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
TMP = tempfile.mkdtemp(prefix="hounds-sweep-")
atexit.register(shutil.rmtree, TMP, ignore_errors=True)
DB = os.path.join(TMP, "navi.db")
os.environ.update({"NAVI_CACHE_DIR": os.path.join(TMP, "cache"), "HOUNDS_CONFIG": os.path.join(TMP, "cfg.json"),
                   "NAVI_TAGLOG_DB": os.path.join(TMP, "taglog.db"), "NAVI_HISTORY_DIR": os.path.join(TMP, "hist"),
                   "NAVI_DB_PATH": DB, "NAVI_TAG_GAP_MS": "0"})

c = sqlite3.connect(DB)
c.execute("CREATE TABLE vulns (asset_uuid text, plugin_id text, plugin_name text, severity text, state text)")
c.execute("CREATE TABLE assets (uuid text, hostname text, ip_address text)")
c.commit()
c.close()

from core import launcher, db, gates  # noqa: E402

fails = []


def check(cond, msg):
    print(("PASS " if cond else "FAIL ") + msg)
    if not cond:
        fails.append(msg)


# ── launcher: writes vs cancel, supersede, background identity ──────────────────────────────
class _Fake:
    def __init__(self, acts):
        self.ACTIONS = acts


seen = {}


def _slow_write(p):
    # a confirmed write that reads navi.db while the client goes away
    time.sleep(0.4)
    try:
        db.scalar("SELECT 1")
        seen["write"] = "ran"
    except db.QueryTimeout:
        seen["write"] = "cancelled"
    return {"ok": True, "scope": getattr(db.current_scope(), "label", None)}, 200


def _slow_read(p):
    t = time.time()
    try:
        while time.time() - t < 1.5:
            db.checkpoint()
            time.sleep(0.05)
    except db.QueryTimeout:
        return {"ok": False, "cancelled": True, "q": p.get("q")}, 200
    return {"ok": True, "q": p.get("q")}, 200


def _who(p):
    return {"ok": True, "loopback": gates.client_is_loopback()}, 200


orig_get = launcher._agent_api if hasattr(launcher, "_agent_api") else None
_fake = {"run_now": _slow_write, "find": _slow_read, "who": _who}


def _patch():
    real = launcher._dispatch_run

    def fake_run(agent_id, action, payload):
        if agent_id == "fakesw":
            return _fake[action](dict(payload or {}))
        return real(agent_id, action, payload)
    launcher._dispatch_run = fake_run
    return real


real_run = _patch()
launcher._JOB_ACTIONS.add(("fakesw", "run_now"))
tok = db.Cancel()
threading.Timer(0.1, tok.cancel).start()
body, _ = launcher.dispatch("fakesw", "run_now", {"confirm": True}, cancel=tok, tab="t1")
check(seen.get("write") == "ran", "a confirmed write isn't cancelled by the client's disconnect token")
check(body.get("scope") == "job", "a confirmed Contract-style run keeps the 'job' budget (%s)" % body.get("scope"))

out = {}
th = threading.Thread(target=lambda: out.setdefault("a", launcher.dispatch("fakesw", "find", {"q": "a"}, tab="t1")[0]))
th.start()
time.sleep(0.2)
out["b"] = launcher.dispatch("fakesw", "find", {"q": "b"}, tab="t1")[0]
th.join(5)
check(out["a"].get("ok") and not out["a"].get("cancelled"), "two different reads of one action from one tab don't cancel each other")
th = threading.Thread(target=lambda: out.setdefault("c", launcher.dispatch("fakesw", "find", {"q": "c"}, tab="t1")[0]))
th.start()
time.sleep(0.2)
launcher.dispatch("fakesw", "find", {"q": "c", "_run": 1}, tab="t1")
th.join(5)
check(out["c"].get("budget") or out["c"].get("cancelled") or out["c"].get("ok") is False,
      "the same read re-sent from the tab still supersedes the older one")
launcher._dispatch_run = real_run

# background job keeps the caller's identity
from core import jobq  # noqa: E402
gates_tok = gates.set_client("203.0.113.9", http=True)
try:
    ctx_seen = {}
    import contextvars  # noqa: E402
    cx = contextvars.copy_context()
    j = jobq.submit(lambda: cx.run(lambda: ctx_seen.setdefault("lb", gates.client_is_loopback())), {"agent": "t"})
finally:
    gates.reset_client(gates_tok)
for _ in range(50):
    if "lb" in ctx_seen:
        break
    time.sleep(0.1)
check(ctx_seen.get("lb") is False, "a copied context carries a remote caller onto the job thread")
src = open(os.path.join(ROOT, "core", "launcher.py"), encoding="utf-8").read()
check("_ctx.run(_work)" in src, "launcher runs background work inside the request's context")
check('"hx_cancel"' in src.split("_MUTATING = {", 1)[1].split("}", 1)[0],
      "hx_cancel / tag_cancel are mutating (never cached, never backgrounded)")

# ── c2: linear LIKE ──────────────────────────────────────────────────────────────────────────
from agents.c2 import api as c2api  # noqa: E402
mem = sqlite3.connect(":memory:")
r = random.Random(3)
bad = 0
for _ in range(5000):
    t = "".join(r.choice("abc") for _ in range(r.randint(0, 8)))
    p = "".join(r.choice("abc%_") for _ in range(r.randint(1, 5)))
    if mem.execute("SELECT ? LIKE ?", (t, "%" + p + "%")).fetchone()[0] != bool(c2api._like(p).search(t)):
        bad += 1
check(bad == 0, "c2 selector matcher equals SQLite LIKE on 5,000 random cases (%d differ)" % bad)
t0 = time.time()
for _ in range(200):
    c2api._like("_%_%_%_%_%_%_%_%_%Q").search("a" * 120)
check(time.time() - t0 < 1.0, "a pathological selector stays linear (%.3fs for 200)" % (time.time() - t0))

# ── sync chains vs ⚡ Optimize ────────────────────────────────────────────────────────────────
from core import cli_jobs, hx_optimize  # noqa: E402
calls = []
orig = hx_optimize.status
hx_optimize.status = lambda path=None: {"summary": {"present": True, "fresh": False}}
orig_run = hx_optimize.run
hx_optimize.run = lambda path=None: calls.append(1) or {"ok": True}
try:
    cli_jobs._refresh_summaries({"kind": "assets", "status": "done", "lines": [], "_local": True, "_no_refresh": True})
    time.sleep(1.2)
    check(not calls, "a sync that isn't the last of its chain doesn't start Optimize")
finally:
    hx_optimize.status, hx_optimize.run = orig, orig_run
csrc = open(os.path.join(ROOT, "core", "contract.py"), encoding="utf-8").read()
check("cli_jobs.hx_busy()" in csrc and "refresh_summaries=(i == len(kinds) - 1)" in csrc,
      "the Contract's assets → vulns chain waits for Optimize and refreshes only after the last sync")
jsrc = open(os.path.join(ROOT, "core", "cli_jobs.py"), encoding="utf-8").read()
check("start_update(k, refresh_summaries=False)" in jsrc, "rebuild's derived-table chain doesn't refresh in between")

# ── tag queue: brief log + retry without forking the series ──────────────────────────────────
from core import tagq, navi_cli  # noqa: E402
tagq.set_workers(4)
running, peak, lk = set(), [0], threading.Lock()
state = {"fail": True}


def fn(**kw):
    q = kw["query"]
    with lk:
        running.add(q)
        if q != "q1":
            peak[0] = max(peak[0], len([x for x in running if x != "q1"]))
    time.sleep(0.3)
    with lk:
        running.discard(q)
    return {"ok": not (q == "q1" and state["fail"])}


tagq.register_runner("tag", fn)
s = tagq.submit_series(fn, [({"category": "C", "value": "V", "query": "q%d" % i, "remove": False}, 10)
                            for i in range(1, 8)], {"agent": "x"}, runner="tag")
time.sleep(0.8)
state["fail"] = False
rr = tagq.retry_page(s["job_ids"][0])
check(rr.get("ok"), "retry of a failed series page is accepted")
time.sleep(4)
check(peak[0] == 1, "after a retry the series still runs one page at a time (peak %d)" % peak[0])
uu = ["%032x" % i for i in range(4000)]
pages = navi_cli.uuid_batches(uu)
tagq.submit_series(lambda **k: {"ok": True}, [({"category": "C", "value": "V", "query": navi_cli.uuids_query(p),
                                                "remove": False}, len(p)) for p in pages], {"agent": "x"})
time.sleep(1.5)
full = tagq.list_jobs()
brief = tagq.list_jobs(brief=True)
big = [j for j in full if len((j.get("spec") or {}).get("query") or "") > 500]
check(big, "full list keeps the whole --query (tag_export / retry replay it)")
check(all(len((j.get("spec") or {}).get("query") or "") <= 500 for j in brief)
      and any((j.get("spec") or {}).get("query_trimmed") for j in brief),
      "the polled Tagging log collapses long --query selectors")
from agents.explore import api as exapi  # noqa: E402
check(all(len((j.get("spec") or {}).get("query") or "") <= 500 for j in exapi.tag_jobs({})[0]["jobs"]),
      "explore tag_jobs (polled every 2 s) uses the brief list")

# ── hx_optimize: escaped read URI ─────────────────────────────────────────────────────────────
odd = os.path.join(TMP, "we?ird #dir%")
os.makedirs(odd)
oddb = os.path.join(odd, "navi.db")
shutil.copy(DB, oddb)
cc = hx_optimize._ro(oddb)
try:
    cc.execute("CREATE TABLE x(a)")
    ro = False
except sqlite3.Error:
    ro = True
check(ro, "hx_optimize opens a navi.db path with ?, # and % read-only")
cc.close()


# ── hounds: software pre-filter, risk on an older navi.db, EOL plan paging, certdash, ownership ──
sw = sqlite3.connect(DB)
sw.execute("CREATE TABLE software (asset_uuid text, software_string text)")
sw.executemany("INSERT INTO software VALUES (?,?)", [
    ("11111111-1111-1111-1111-111111111111", "Foo [x64] Bar [version 1.0]"),
    ("22222222-2222-2222-2222-222222222222", "Émile Tool [version 2.0]"),
    ("33333333-3333-3333-3333-333333333333", "openssl [version 3.0.1]")])
sw.commit()
sw.close()
from core import software, payload  # noqa: E402
allp, _i = software.product_sets()
for k in [k for k in allp if k.startswith(("foo", "émile", "\u00e9mile"))]:
    one, _ = software.product_sets(only={k})
    check(len((one.get(k) or {}).get("assets", ())) == len(allp[k]["assets"]) > 0,
          "software: tagging %r finds its assets (pre-filter matches the parsed name)" % k)
from agents.software import api as swapi  # noqa: E402
ro_ = swapi.run({})[0]
run = (ro_.get("drill") or {}).get("run") or ro_.get("run")
rk = swapi.risk({"run": run})[0]
check(rk.get("ok") is not False or "unavailable" in str(rk.get("error")),
      "software risk on a navi.db without xrefs/score answers (no 500)")
check(rk.get("ok") is True, "software risk runs on a navi.db without xrefs/score columns")
orig_plan = software.eol_plan
software.eol_plan = lambda r: [{"name": "p%d" % i, "slug": "nginx", "newest": "",
                                "versions": ["1.%d" % j for j in range(300)]} for i in range(320)]
try:
    got, start, guard = [], 0, 0
    while start is not None and guard < 10:
        b = swapi.eol_plan({"run": run, "start": start})[0]
        got += b.get("plan") or []
        start, guard = b.get("next_start"), guard + 1
    check(len(got) == 320, "software EOL plan pages every product (%d of 320)" % len(got))
    check(all(len(x["vers"].split("\n")) == 300 for x in got), "…and every version of each (300, not 200)")
finally:
    software.eol_plan = orig_plan
cd = open(os.path.join(ROOT, "web", "certdash.html"), encoding="utf-8").read()
check("API.post('drill',{run, section:'certs'" in cd and "res.twelve_month" not in cd,
      "Certificate Dashboard reads the paged certificate list (no dead expired/twelve_month fields)")
osrc = open(os.path.join(ROOT, "agents", "asset_ownership", "api.py"), encoding="utf-8").read()
check('AGENT.result = {"kpi"' in osrc, "Asset Ownership sets the hub card summary after a run")

print("\n%d failure(s)" % len(fails))
sys.exit(1 if fails else 0)
