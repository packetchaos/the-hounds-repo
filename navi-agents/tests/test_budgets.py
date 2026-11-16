"""Regression tests for request-scoped query budgets + cancellation (build 455):
core/db.budget_scope (default budget for statements that pass none, one deadline per request,
explicit budgets win, no scope = old default, heavy for "job", hits recorded, private
connections honour it), core/launcher.request_scope (open / run / job / writes-none mapping),
launcher.dispatch (budget stops answer 200 {ok:false, budget:true, message}; a hound that
caught the exception itself still gets budget:true; budget-limited answers are not cached;
cancel token + supersede by tab), the stdlib server cancelling a request's SQL when the client
disconnects, core/jobq workers under "job" (+ jobq.cancel), and Release the Hounds running each
hound under "job" + heavy with per-hound budget hits in its state.
Tiny synthetic navi.db + fake agents — no navi, no network.
Run: python3 tests/test_budgets.py  (or pytest)."""
import atexit
import json
import os
import shutil
import socket
import sqlite3
import sys
import tempfile
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
TMP = tempfile.mkdtemp(prefix="hounds-budgets-")
atexit.register(shutil.rmtree, TMP, ignore_errors=True)
os.environ.update({"NAVI_CACHE_DIR": os.path.join(TMP, "cache"),
                   "HOUNDS_CONFIG": os.path.join(TMP, "cfg.json"),
                   "NAVI_HISTORY_DIR": os.path.join(TMP, "hist"),
                   "NAVI_TAGLOG_DB": os.path.join(TMP, "taglog.db")})
for k in ("SQLITE_TMPDIR", "NAVI_QUERY_BUDGET_MS", "NAVI_QUERY_MAX_ROWS", "NAVI_OPEN_BUDGET_S",
          "NAVI_RUN_BUDGET_S", "NAVI_JOB_BUDGET_S", "NAVI_BUDGET_OPEN_S", "NAVI_BUDGET_JOB_S"):
    os.environ.pop(k, None)
DB = os.path.join(TMP, "navi.db")
os.environ["NAVI_DB_PATH"] = DB

con = sqlite3.connect(DB)
con.executescript("CREATE TABLE assets (uuid TEXT); CREATE TABLE vulns (asset_uuid TEXT, plugin_id INT);")
con.executemany("INSERT INTO vulns VALUES (?,?)", [("a%d" % (i % 50), i % 97) for i in range(5000)])
con.commit()
con.close()

from core import db, launcher, jobq, release, snapcache, pagecache  # noqa: E402

snapcache.CACHE_DIR = os.environ["NAVI_CACHE_DIR"]
SLOW = ("WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM c WHERE x < 500000000) "
        "SELECT count(*) FROM c")
MED = ("WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM c WHERE x < %d) "
       "SELECT count(*) FROM c")
fails = []


def check(cond, msg):
    print(("PASS " if cond else "FAIL ") + msg)
    if not cond:
        fails.append(msg)


def raises(fn, exc):
    try:
        fn()
    except exc as e:
        return e
    except Exception as e:
        return ("wrong", e)
    return None


def secs_for(n):
    t = time.monotonic()
    db.scalar(MED % n, budget=0)
    return time.monotonic() - t


# calibrate a ~0.6 s statement for this machine
N = 2000000
while secs_for(N) < 0.4 and N < 2e8:
    N *= 2
MID = MED % N
T_MID = max(secs_for(N), secs_for(N))

# ---------------------------------------------------------------- no scope = old default
check(db.current_scope() is None, "no scope by default")
t = time.monotonic()
check(db.scalar(MID) > 0, "no scope: default budget stays unlimited (-1 → env, off)")

# ---------------------------------------------------------------- scope presets + env
os.environ["NAVI_OPEN_BUDGET_S"] = "0.25"
os.environ["NAVI_RUN_BUDGET_S"] = "7"
os.environ["NAVI_JOB_BUDGET_S"] = "11"
sb = db.scope_budgets()
check(sb == {"open": 0.25, "run": 7.0, "job": 11.0}, "scope budgets read NAVI_OPEN/RUN/JOB_BUDGET_S")
os.environ.pop("NAVI_RUN_BUDGET_S")
# build 458: no hound times out under 2 hours (owner's rule)
check(db.scope_budgets()["run"] == 7200 and db.scope_budgets()["job"] == 11.0,
      "run budget defaults to 2 h")
check(raises(lambda: db.budget_scope("bogus").__enter__(), ValueError) is not None, "unknown scope → ValueError")

with db.budget_scope("open") as sc:
    check(db.current_scope() is sc and sc.label == "open" and sc.seconds == 0.25, "scope active inside block")
    t = time.monotonic()
    e = raises(lambda: db.scalar(SLOW), db.BudgetExceeded)
    el = time.monotonic() - t
    check(isinstance(e, db.BudgetExceeded) and e.label == "open" and el < 2,
          "statement with no budget uses the scope's 'open' budget (%.2f s)" % el)
    check(sc.tripped and sc.hits[0]["kind"] == "budget", "the hit is recorded on the scope")
check(db.current_scope() is None, "scope restored after the block")

# explicit budgets always win
with db.budget_scope("open"):
    check(db.scalar(MID, budget=0) > 0, "explicit budget=0 (unlimited) wins over the scope")
    check(db.scalar(MID, budget=None) > 0, "explicit budget=None wins over the scope")
with db.budget_scope(30):
    e = raises(lambda: db.scalar(SLOW, budget=0.2), db.BudgetExceeded)
    check(isinstance(e, db.BudgetExceeded) and e.seconds == 0.2, "explicit budget=0.2 wins over a 30 s scope")
    e = raises(lambda: db.query(SLOW, budget="open"), db.BudgetExceeded)
    check(isinstance(e, db.BudgetExceeded) and e.label == "open", "explicit preset wins over the scope")

# one deadline per request (not per statement)
os.environ["NAVI_OPEN_BUDGET_S"] = "0.5"
with db.budget_scope("open"):
    check(db.scalar("SELECT count(*) FROM vulns") == 5000, "a statement early in the request runs")
    time.sleep(0.6)                                     # the request spent its 0.5 s elsewhere
    e = raises(lambda: db.scalar(MID), db.BudgetExceeded)
    check(isinstance(e, db.BudgetExceeded), "per-request deadline: the 2nd statement runs out of the shared budget")
os.environ["NAVI_OPEN_BUDGET_S"] = "%.3f" % (T_MID * 4)
with db.budget_scope("open", per_request=False):
    time.sleep(T_MID * 4.2)                             # past a per-request deadline…
    db.scalar(MID)
    check(db.scalar(MID) > 0, "per_request=False: each statement gets the full budget")
os.environ["NAVI_OPEN_BUDGET_S"] = "%.3f" % (T_MID * 4)

# nested: innermost wins; "none" clears
with db.budget_scope("open"):
    with db.budget_scope("none"):
        check(db.scalar(MID) > 0, "inner budget_scope('none') = unlimited inside an 'open' scope")
    check(db.current_scope().label == "open", "outer scope restored after inner")

# iter() honours the scope too
os.environ["NAVI_OPEN_BUDGET_S"] = "0.25"
with db.budget_scope("open") as sc:
    e = raises(lambda: list(db.iter(SLOW)), db.BudgetExceeded)
    check(isinstance(e, db.BudgetExceeded) and sc.tripped, "db.iter() under the scope → BudgetExceeded, recorded")

# heavy for 'job'
seen = {}


def watch(key):
    for _ in range(200):
        a = db.active()
        if a:
            seen[key] = a[0]
            return
        time.sleep(0.01)


th = threading.Thread(target=watch, args=("job",))
th.start()
with db.budget_scope("job"):
    db.scalar(MID)
th.join()
check(seen.get("job", {}).get("heavy") is True and seen["job"].get("budget") == "job",
      "'job' scope → statements are heavy (one big scan at a time), labelled job")
th = threading.Thread(target=watch, args=("run",))
th.start()
with db.budget_scope("run"):
    db.scalar(MID)
th.join()
check(seen.get("run", {}).get("heavy") is False, "'run' scope → statements are light")
with db.budget_scope("job"):
    th = threading.Thread(target=watch, args=("jobx",))
    th.start()
    db.scalar(MID, heavy=False)
    th.join()
check(seen.get("jobx", {}).get("heavy") is False, "explicit heavy=False wins over the job scope")

# private connections (db.connect) honour the scope + cancel token
with db.budget_scope("open") as sc:
    c = db.connect()
    t = time.monotonic()
    try:
        c.execute(SLOW).fetchone()
        ok = False
    except sqlite3.OperationalError as e:
        ok = "interrupt" in str(e).lower()
    c.close()
    check(ok and time.monotonic() - t < 2 and sc.tripped, "db.connect() connection interrupted by the scope deadline")
c = db.connect()
check(c.execute(MID).fetchone()[0] > 0, "db.connect() with no scope: unchanged (runs to completion)")
c.close()
tok = db.Cancel()
with db.cancel_scope(tok):
    c = db.connect()
    threading.Timer(0.2, tok.cancel).start()
    try:
        c.execute(SLOW).fetchone()
        ok = False
    except sqlite3.OperationalError:
        ok = True
    c.close()
check(ok, "db.connect() connection stopped by the cancel_scope token")

# db.checkpoint(): Python loops over fetched rows obey the scope + cancel too
db.checkpoint()                                         # no scope: never raises
with db.budget_scope(0.2) as sc:
    db.checkpoint()
    time.sleep(0.3)
    e = raises(db.checkpoint, db.BudgetExceeded)
    check(isinstance(e, db.BudgetExceeded) and sc.tripped, "db.checkpoint() raises once the request's budget is spent")
tok = db.Cancel()
tok.cancel()
with db.cancel_scope(tok):
    check(isinstance(raises(db.checkpoint, db.QueryCancelled), db.QueryCancelled), "db.checkpoint() raises when cancelled")

# ---------------------------------------------------------------- budget payload
e = db.BudgetExceeded("SELECT 1", 5, "open")
p = db.budget_payload(e)
check(p["ok"] is False and p["budget"] is True and "narrow" in p["message"] and "▶ Run" in p["message"]
      and p["label"] == "open" and p["seconds"] == 5 and p["error"] == p["message"],
      "budget_payload: open → points at ▶ Run; error = message (pages render o.error)")
p = db.budget_payload(db.BudgetExceeded("SELECT 1", 300, "run"))
check("background" in p["message"], "budget_payload: run → narrow / run in the background")
check(p.get("optimize") is True and "Optimize" in p["message"], "budget_payload: no ⚡ Optimize indexes → says so")
check(db.budget_payload(db.QueryCancelled("x")).get("cancelled") is True, "budget_payload: cancelled flag")
check(db.budget_payload(db.TooManyRows(10, "x")).get("max_rows") == 10, "budget_payload: max_rows")

# ---------------------------------------------------------------- request_scope mapping
rs = launcher.request_scope
check(rs("insights", "scent", {"peek": True}) == "open", "peek → open")
check(rs("fused_score", "snapshot", {"peek": True, "_nocache": True}) == "open", "snapshot peek → open")
check(rs("settings", "db_checks", {}) == "open", "Settings page-load read → open")
check(rs("alert", "suggest", {}) == "open", "Alert Raven page-load read → open")
check(rs("contract", "get", {}) == "open" and rs("explore", "activity", {"agent": "x"}) == "open",
      "contract get / activity → open")
check(rs("anything", "status", {}) == "open", "live state (_LIVE) → open")
check(rs("identity", "run", {}) == "run" and rs("postquantum", "run", {}) == "run"
      and rs("iot_squad", "run", {}) == "run", "▶ Run actions (release recipes) → run")
check(rs("fused_score", "snapshot", {}) == "run", "snapshot build request (no peek) → run")
check(rs("ex_vulns", "search", {"q": "x"}) == "run", "search (also a click) → run")
check(rs("acr", "run", {"_run": "abc"}) == "run", "_run (a ▶ Run click) → run")
check(rs("ex_plugins", "search", {}, "open") == "open", "client hint X-Hounds-Budget: open honoured")
check(rs("ex_plugins", "search", {}, "job") == "run", "client can't ask for 'job'")
check(rs("eol", "run", {"background": True}) == "open", "background:true → the request only enqueues")
check(rs("eol", "tag", {"confirm": True}) is None and rs("x", "apply", {}) is None,
      "writes (mutating / confirm) → no default budget")
check(rs("contract", "run_now", {"confirm": True}) == "job", "AI Contract run → job")
check(all(rs(a, b, {}) == "run" for a, b in launcher._run_actions() if (a, b) not in launcher._OPEN_ACTIONS),
      "every release-recipe step not opened on load → run")

# ---------------------------------------------------------------- dispatch under a scope
calls = {}


def a_slow(p):
    return {"ok": True, "n": db.scalar(SLOW)}, 200


def a_swallow(p):
    try:
        db.scalar(SLOW)
    except Exception as e:
        return {"ok": False, "error": str(e)}, 200
    return {"ok": True}, 200


def a_partial(p):
    try:
        db.scalar(SLOW)
    except db.QueryTimeout:
        pass
    return {"ok": True, "rows": []}, 200


def a_fast(p):
    calls["fast"] = calls.get("fast", 0) + 1
    return {"ok": True, "n": db.scalar("SELECT count(*) FROM vulns"), "scope": db.current_scope().label}, 200


def a_write(p):
    return {"ok": True, "scope": (db.current_scope().label if db.current_scope() else None)}, 200


def a_unbounded(p):
    calls["unb"] = db.scalar(SLOW)
    return {"ok": True}, 200


launcher.DISPATCH["fakeb"] = {"slow": a_slow, "swallow": a_swallow, "partial": a_partial,
                              "fast": a_fast, "tag": a_write, "unb": a_unbounded}
launcher._OPEN_ACTIONS |= {("fakeb", "slow"), ("fakeb", "swallow"), ("fakeb", "partial"), ("fakeb", "fast")}
launcher.clear_cache()

os.environ["NAVI_OPEN_BUDGET_S"] = "0.3"
t = time.monotonic()
body, status = launcher.dispatch("fakeb", "slow", {})
el = time.monotonic() - t
check(status == 200 and body.get("ok") is False and body.get("budget") is True and body.get("label") == "open"
      and "narrow" in body.get("message", "") and el < 3,
      "page-open read past the open budget → 200 {ok:false, budget:true, message} in %.2f s" % el)
check(db.active() == [], "no statement left running after the budget stop")
body, status = launcher.dispatch("fakeb", "swallow", {})
check(body.get("ok") is False and body.get("budget") is True and body.get("error") and body.get("message"),
      "a hound that caught the exception itself still answers budget:true (+ its error)")
body, status = launcher.dispatch("fakeb", "partial", {})
check(body.get("ok") is True and body.get("budget_partial") is True and body.get("budget_message"),
      "a hound that answered anyway is flagged budget_partial")
k = launcher._cache_key("fakeb", "partial", {})
check(k not in launcher._CACHE, "a budget-limited answer is never cached")
body, _ = launcher.dispatch("fakeb", "fast", {})
check(body.get("ok") is True and body.get("scope") == "open" and not body.get("budget_partial"),
      "a read within budget answers normally (scope open)")
body, _ = launcher.dispatch("fakeb", "tag", {"confirm": True})
check(body.get("scope") is None, "a write runs with no default budget (as before)")
os.environ["NAVI_RUN_BUDGET_S"] = "0.3"
body, _ = launcher.dispatch("fakeb", "unb", {})
check(body.get("budget") is True and body.get("label") == "run", "unlisted action → run budget (NAVI_RUN_BUDGET_S)")
os.environ.pop("NAVI_RUN_BUDGET_S")

# cancel token (what the servers trip on disconnect) + supersede by tab
tok = db.Cancel()
threading.Timer(0.3, tok.cancel).start()
t = time.monotonic()
body, _ = launcher.dispatch("fakeb", "unb", {}, cancel=tok)
check(body.get("budget") is True and body.get("cancelled") is True and time.monotonic() - t < 3,
      "cancel token tripped mid-query → its SQL stops, answer {budget, cancelled}")
check(db.active() == [], "db.active() empty after the cancel")
res = {}


def first():
    res["first"] = launcher.dispatch("fakeb", "unb", {}, tab="tab1")[0]


th = threading.Thread(target=first)
th.start()
time.sleep(0.3)
res["second"] = launcher.dispatch("fakeb", "fast", {}, tab="tab1")[0]       # other action: no supersede
check(th.is_alive(), "a different action from the same tab doesn't supersede")
threading.Thread(target=lambda: res.setdefault("third", launcher.dispatch("fakeb", "unb", {}, tab="tab2", cancel=db.Cancel()))).start()
time.sleep(0.2)
tok3 = db.Cancel()
threading.Timer(0.4, tok3.cancel).start()
res["sup"] = launcher.dispatch("fakeb", "unb", {}, tab="tab1", cancel=tok3)[0]   # same tab+action
th.join(5)
check(not th.is_alive() and res["first"].get("cancelled") is True,
      "a newer identical request from the same tab cancels the older one")
db.cancel()                                                                     # stop tab2's
time.sleep(0.3)
check(db.active() == [], "nothing left running")

# ---------------------------------------------------------------- stdlib server: disconnect
import app_stdlib  # noqa: E402
from http.server import ThreadingHTTPServer  # noqa: E402

os.environ["NAVI_RUN_BUDGET_S"] = "60"
srv = ThreadingHTTPServer(("127.0.0.1", 0), app_stdlib.Handler)
port = srv.server_address[1]
threading.Thread(target=srv.serve_forever, daemon=True).start()


def post(path, body, headers=None, read=True):
    s = socket.create_connection(("127.0.0.1", port))
    b = json.dumps(body).encode()
    h = {"Host": "127.0.0.1:%d" % port, "Content-Type": "application/json", "Content-Length": str(len(b))}
    h.update(headers or {})
    s.sendall(("POST %s HTTP/1.1\r\n" % path).encode() + "".join("%s: %s\r\n" % kv for kv in h.items()).encode()
              + b"\r\n" + b)
    if not read:
        return s
    data = b""
    while True:
        d = s.recv(65536)
        if not d:
            break
        data += d
    s.close()
    return json.loads(data.split(b"\r\n\r\n", 1)[1] or b"{}")


r = post("/api/fakeb/fast", {})
check(r.get("ok") is True and r.get("scope") == "open", "stdlib server: page-open read runs under 'open'")
r = post("/api/fakeb/fast", {"_nocache": True}, {"X-Hounds-Budget": "run"})
check(r.get("scope") == "run", "stdlib server: X-Hounds-Budget header honoured")
calls.pop("unb", None)
s = post("/api/fakeb/unb", {}, read=False)
for _ in range(100):
    if db.active():
        break
    time.sleep(0.02)
check(len(db.active()) == 1, "stdlib server: the ▶ Run query is running")
t = time.monotonic()
s.close()                                                        # the browser aborted / left
for _ in range(150):
    if not db.active():
        break
    time.sleep(0.02)
el = time.monotonic() - t
check(db.active() == [] and el < 2.5, "client disconnect → its SQL is cancelled (db.active() empty after %.2f s)" % el)
check("unb" not in calls, "the cancelled action never completed")
srv.shutdown()
os.environ.pop("NAVI_RUN_BUDGET_S")

# ---------------------------------------------------------------- jobq workers run under 'job'
got = {}


def job_fn():
    sc = db.current_scope()
    got["label"], got["heavy"] = sc.label, sc.heavy
    return {"ok": True}


j = jobq.submit(job_fn, {"agent": "fakeb", "action": "x"})
for _ in range(200):
    if (jobq.get(j["id"]) or {}).get("status") in ("done", "error"):
        break
    time.sleep(0.02)
check(got == {"label": "job", "heavy": True}, "jobq worker: background work runs under 'job' + heavy")


def job_slow():
    db.scalar(SLOW)
    return {"ok": True}


j = jobq.submit(job_slow, {"agent": "fakeb", "action": "slow"})
for _ in range(200):
    if db.active():
        break
    time.sleep(0.02)
check(jobq.cancel(j["id"]) is True, "jobq.cancel(job) accepted")
for _ in range(200):
    if (jobq.get(j["id"]) or {}).get("status") in ("done", "error"):
        break
    time.sleep(0.02)
jj = jobq.get(j["id"])
check(jj["status"] == "error" and (jj.get("result") or {}).get("cancelled") is True and db.active() == [],
      "a cancelled job stops its SQL and answers {budget, cancelled}")
os.environ["NAVI_JOB_BUDGET_S"] = "0.3"
j = jobq.submit(job_slow, {"agent": "fakeb", "action": "slow"})
for _ in range(300):
    if (jobq.get(j["id"]) or {}).get("status") in ("done", "error"):
        break
    time.sleep(0.02)
jj = jobq.get(j["id"])
check((jj.get("result") or {}).get("budget") is True and (jj.get("result") or {}).get("label") == "job",
      "a job past NAVI_JOB_BUDGET_S answers budget:true (label job)")

# ---------------------------------------------------------------- Release under 'job' + heavy
os.environ["NAVI_JOB_BUDGET_S"] = "0.4"
rel_seen = {}


def r_ok(p):
    sc = db.current_scope()
    th = threading.Thread(target=watch, args=("rel",))
    th.start()
    db.scalar(MED % 300000)
    th.join()
    rel_seen["scope"] = (sc.label, sc.heavy)
    return {"ok": True, "result": {"x": 1}}, 200


def r_slow(p):
    return {"ok": True, "n": db.scalar(SLOW)}, 200


launcher.DISPATCH["relA"] = {"run": r_ok}
launcher.DISPATCH["relB"] = {"run": r_slow}
release.recipes = lambda: {"pages": [
    {"agent": "relA", "label": "A", "kind": "page", "steps": ["run"],
     "requests": [{"agent": "relA", "action": "run", "body": {}}]},
    {"agent": "relB", "label": "B", "kind": "page", "steps": ["run"],
     "requests": [{"agent": "relB", "action": "run", "body": {}}]}]}
release._auto_approve = lambda: True
st = release.start(True)
for _ in range(400):
    if release.state().get("status") in ("done", "cancelled"):
        break
    time.sleep(0.02)
s = release.state()
items = {i["agent"]: i for i in s["items"]}
check(rel_seen.get("scope") == ("job", True), "Release: each hound runs under 'job' with heavy=True")
check(seen.get("rel", {}).get("heavy") is True, "Release: its statements hold the heavy-scan slot")
check(items["relA"]["status"] == "done" and not items["relA"].get("budget"), "Release: a hound within budget → done, no hits")
check(items["relB"]["status"] == "error" and (items["relB"].get("budget") or {}).get("hits", 0) >= 1
      and items["relB"]["budget"]["label"] == "job", "Release: budget hits recorded per hound")
check(s.get("budget_hits", 0) >= 1, "Release: total budget hits in the release state")
check((release.last() or {}).get("budget_hits", 0) >= 1, "Release: hits persisted in release_last.json")
os.environ["NAVI_JOB_BUDGET_S"] = "60"
release.start(True)
for _ in range(200):
    if db.active():
        break
    time.sleep(0.02)
t = time.monotonic()
release.cancel()
for _ in range(200):
    if release.state().get("status") in ("done", "cancelled") and not db.active():
        break
    time.sleep(0.02)
check(release.state().get("status") == "cancelled" and db.active() == [] and time.monotonic() - t < 3,
      "Release cancel stops the running hound's SQL, not just the next request")

print("\n%d failure(s)" % len(fails))
sys.exit(1 if fails else 0)
