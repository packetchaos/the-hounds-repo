"""Regression tests for the navi.db access layer (core/db.py, build 453 scale work):
pooled read-only connections (reuse per thread, reopen when navi.db is replaced), PRAGMAs
(query_only, temp_store=FILE + temp dir, cache, mmap off), budgets (presets, BudgetExceeded,
cancel from another thread, cancel_scope, cancel by id), max_rows / TooManyRows, db.iter
streaming, the heavy-scan semaphore (one at a time, light never blocked, re-entrant), the
user-SQL authorizer on the shared pool (keys/smtp/ssh/resend, ATTACH, PRAGMA), connect()
still a private connection, and N threads hammering the pool.
Tiny synthetic navi.db in a temp dir — no navi, no network.
Run: python3 tests/test_db_layer.py  (or pytest)."""
import atexit
import contextlib
import os
import shutil
import sqlite3
import sys
import tempfile
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
TMP = tempfile.mkdtemp(prefix="hounds-dblayer-")
atexit.register(shutil.rmtree, TMP, ignore_errors=True)
os.environ.update({"NAVI_CACHE_DIR": os.path.join(TMP, "cache"),
                   "HOUNDS_CONFIG": os.path.join(TMP, "cfg.json"),
                   "NAVI_HISTORY_DIR": os.path.join(TMP, "hist"),
                   "NAVI_TAGLOG_DB": os.path.join(TMP, "taglog.db")})
os.environ.pop("SQLITE_TMPDIR", None)
os.environ.pop("NAVI_QUERY_BUDGET_MS", None)
os.environ.pop("NAVI_QUERY_MAX_ROWS", None)
DB = os.path.join(TMP, "navi.db")
os.environ["NAVI_DB_PATH"] = DB

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
    except Exception as e:          # wrong type
        return ("wrong", e)
    return None


def make_db(path, n_assets=50, n_vulns=20000, tag="v1"):
    if os.path.exists(path):
        os.remove(path)
    con = sqlite3.connect(path)
    con.executescript("""
      CREATE TABLE assets (uuid TEXT, ip_address TEXT, hostname TEXT);
      CREATE TABLE vulns (asset_uuid TEXT, plugin_id INTEGER, severity TEXT);
      CREATE TABLE keys (access_key TEXT, secret_key TEXT);
      CREATE TABLE smtp (server TEXT, password TEXT);
      CREATE TABLE ssh (username TEXT, password TEXT, key_file TEXT);
      CREATE TABLE resend (api_key TEXT);
      CREATE TABLE marker (v TEXT);
    """)
    con.executemany("INSERT INTO assets VALUES (?,?,?)",
                    [(f"u{i}", f"10.0.0.{i}", f"h{i}") for i in range(n_assets)])
    con.executemany("INSERT INTO vulns VALUES (?,?,?)",
                    [(f"u{i % n_assets}", i % 997, ("critical", "high", "low")[i % 3])
                     for i in range(n_vulns)])
    con.execute("INSERT INTO keys VALUES ('AK-SECRET','SK-SECRET')")
    con.execute("INSERT INTO smtp VALUES ('mail','pw')")
    con.execute("INSERT INTO ssh VALUES ('root','pw','')")
    con.execute("INSERT INTO resend VALUES ('re_x')")
    con.execute("INSERT INTO marker VALUES (?)", (tag,))
    con.commit()
    con.close()


make_db(DB)
from core import db  # noqa: E402

# A statement that runs for a long time on any DB (recursive CTE, no I/O).
SLOW = ("WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM c WHERE x < 500000000) "
        "SELECT count(*) FROM c")

# ---- 1. results identical to a plain connection --------------------------------------
plain = sqlite3.connect(DB)
plain.row_factory = sqlite3.Row
ref = [dict(r) for r in plain.execute("SELECT asset_uuid, count(*) n FROM vulns GROUP BY 1 ORDER BY 1")]
check(db.query("SELECT asset_uuid, count(*) n FROM vulns GROUP BY 1 ORDER BY 1") == ref,
      "query() returns the same list[dict] as a plain sqlite3 connection")
check(db.scalar("SELECT count(*) FROM vulns") == 20000, "scalar() first column of first row")
check(db.scalar("SELECT uuid FROM assets WHERE 0") is None, "scalar() on no rows → None")
check(db.scalar("SELECT uuid FROM assets ORDER BY uuid") == "u0", "scalar() reads only the first row")
check(db.query("SELECT ?+? s", (2, 3)) == [{"s": 5}], "positional params")
check(db.query("SELECT :a a", {"a": 7}) == [{"a": 7}], "named params")
check(db.query("SELECT 1 x", (), DB, 0) == [{"x": 1}], "old positional signature (sql, params, path, budget)")
e = raises(lambda: db.query("SELECT * FROM nope"), sqlite3.OperationalError)
check(e is not None and not isinstance(e, tuple), "SQL errors still raise sqlite3.OperationalError")
e = raises(lambda: db.query("SELECT 1", path=os.path.join(TMP, "missing.db")), FileNotFoundError)
check(e is not None and not isinstance(e, tuple), "missing navi.db → FileNotFoundError (as before)")
check(db.tags_present() == [], "tags_present() on a db without tags → []")
plain.close()

# ---- 2. connection reuse per thread + PRAGMAs ------------------------------------------
db.close_all()
s0 = db.pool_stats()
for _ in range(50):
    db.query("SELECT uuid FROM assets WHERE uuid=?", ("u1",))
s1 = db.pool_stats()
check(s1["opened"] - s0["opened"] == 1, f"50 sequential statements open ONE connection ({s1['opened'] - s0['opened']})")
check(s1["reused"] - s0["reused"] == 49, "…and reuse it 49 times")
w = db._checkout(DB, False)
try:
    con = w.con
    check(con.execute("PRAGMA query_only").fetchone()[0] == 1, "PRAGMA query_only=1")
    check(con.execute("PRAGMA temp_store").fetchone()[0] == 1, "PRAGMA temp_store=FILE (1)")
    check(con.execute("PRAGMA cache_size").fetchone()[0] == -256 * 1024, "PRAGMA cache_size = 256 MB")
    check(con.execute("PRAGMA mmap_size").fetchone()[0] == 0, "PRAGMA mmap_size = 0 (off)")
    check(con.execute("PRAGMA busy_timeout").fetchone()[0] == 3000, "PRAGMA busy_timeout = 3000")
    tdir = con.execute("PRAGMA temp_store_directory").fetchone()[0]
    check(tdir == os.path.join(TMP, "cache", "sqlite_tmp") and os.path.isdir(tdir),
          "temp_store_directory = <NAVI_CACHE_DIR>/sqlite_tmp (SQLITE_TMPDIR unset)")
    e = raises(lambda: con.execute("CREATE TABLE x(a)"), sqlite3.OperationalError)
    check(e is not None and not isinstance(e, tuple), "pooled connection cannot write")
finally:
    db._checkin(w)
check(db.tmp_info()["dir"] == os.path.join(TMP, "cache", "sqlite_tmp"), "tmp_info() reports the temp dir")

# a second thread doing sequential work also reuses its own connection
ids = []


def worker_seq():
    for _ in range(20):
        w = db._checkout(DB, False)
        ids.append(id(w))
        db._checkin(w)


t = threading.Thread(target=worker_seq)
t.start()
t.join()
check(len(set(ids)) == 1, "a thread gets back the connection it used last")

# nested: a query inside an iter loop takes a second connection, results stay right
outer = []
for r in db.iter("SELECT uuid FROM assets ORDER BY uuid LIMIT 5", chunk=2):
    outer.append((r["uuid"], db.scalar("SELECT count(*) FROM vulns WHERE asset_uuid=?", (r["uuid"],))))
check(outer == [("u0", 400), ("u1", 400), ("u10", 400), ("u11", 400), ("u12", 400)],
      "query() inside an iter() loop (separate leased connection)")

# ---- 3. reopen when navi.db is replaced -------------------------------------------------
check(db.scalar("SELECT v FROM marker") == "v1", "marker v1 before replace")
new = os.path.join(TMP, "navi.db.new")
make_db(new, n_assets=7, n_vulns=10, tag="v2")
os.replace(new, DB)                                 # navi -rebuild / restore style replace
check(db.scalar("SELECT v FROM marker") == "v2", "file replaced (new inode) → pooled connection reopened")
check(db.scalar("SELECT count(*) FROM assets") == 7, "…and reads the new file's data")
# in-place rewrite by a writer (same inode)
wc = sqlite3.connect(DB)
wc.execute("UPDATE marker SET v='v3'")
wc.execute("INSERT INTO assets VALUES ('x','1.1.1.1','x')")
wc.commit()
wc.close()
check(db.scalar("SELECT v FROM marker") == "v3", "in-place rewrite seen by the pooled connection")
check(db.scalar("SELECT count(*) FROM assets") == 8, "…new rows visible")
make_db(DB)                                         # back to the 50 / 20000 fixture
check(db.scalar("SELECT count(*) FROM vulns") == 20000, "delete + recreate → reopened")
# switching NAVI_DB_PATH (Settings) → another pool key
other = os.path.join(TMP, "other.db")
make_db(other, n_assets=3, n_vulns=1, tag="other")
os.environ["NAVI_DB_PATH"] = other
check(db.scalar("SELECT v FROM marker") == "other", "NAVI_DB_PATH switch → reads the other navi.db")
os.environ["NAVI_DB_PATH"] = DB
check(db.scalar("SELECT v FROM marker") == "v1", "…and back")

# ---- 4. budgets + cancel ------------------------------------------------------------------
e = raises(lambda: db.query(SLOW, budget=0.3), db.BudgetExceeded)
check(e is not None and not isinstance(e, tuple), "budget=0.3 s → BudgetExceeded")
check(isinstance(e, db.QueryTimeout), "BudgetExceeded is a QueryTimeout (old callers still catch it)")
check("narrow it" in str(e), "BudgetExceeded message tells the user to narrow it")
p = db.budget_payload(e)
check(p["ok"] is False and p["budget"] is True and "narrow" in p["message"], "budget_payload → {ok:false, budget:true, message}")
# build 458: no hound times out under 2 hours (owner's rule) — run / job presets are 2 h
check(db.BUDGETS["open"] == 5 and db.BUDGETS["run"] == 7200 and db.BUDGETS["job"] == 7200, "presets open 5 s / run 2 h / job 2 h")
saved = dict(db.BUDGETS)
db.BUDGETS["open"] = 0.2
t0 = time.monotonic()
e = raises(lambda: db.query(SLOW, budget="open"), db.BudgetExceeded)
check(e is not None and not isinstance(e, tuple) and e.label == "open" and time.monotonic() - t0 < 3,
      "budget='open' preset enforced (label carried)")
db.BUDGETS.update(saved)
check(raises(lambda: db.query("SELECT 1", budget="bogus"), ValueError) is not None, "unknown preset → ValueError")
check(db.query("SELECT 1 x", budget=None) == [{"x": 1}], "budget=None unlimited")
check(db.scalar("SELECT count(*) FROM vulns", budget=5) == 20000, "statement within budget completes")
check(db.scalar("SELECT count(*) FROM vulns") == 20000, "connection usable after an interrupted statement")

# cancel from another thread via token
tok = db.Cancel()
threading.Timer(0.3, tok.cancel).start()
t0 = time.monotonic()
e = raises(lambda: db.query(SLOW, cancel=tok), db.QueryCancelled)
check(e is not None and not isinstance(e, tuple) and time.monotonic() - t0 < 5, "Cancel token tripped from another thread stops the query")
check(db.budget_payload(e).get("cancelled") is True, "budget_payload marks cancelled")

# cancel_scope (request-level) + cancel by thread / id from another thread
res = {}


def scoped():
    with db.cancel_scope() as tk:
        res["tok"] = tk
        try:
            db.query(SLOW)
            res["r"] = "finished"
        except db.QueryCancelled:
            res["r"] = "cancelled"


th = threading.Thread(target=scoped)
th.start()
time.sleep(0.3)
res["tok"].cancel()
th.join(10)
check(res.get("r") == "cancelled", "cancel_scope token stops statements in that thread")

res2 = {}


def by_id():
    try:
        db.query(SLOW)
        res2["r"] = "finished"
    except db.QueryCancelled:
        res2["r"] = "cancelled"


th = threading.Thread(target=by_id)
th.start()
running = []
for _ in range(50):
    running = [a for a in db.active() if "RECURSIVE" in a["sql"]]
    if running:
        break
    time.sleep(0.05)
check(len(running) == 1 and running[0]["thread"] == th.ident, "active() lists the running statement")
n = db.cancel(running[0]["id"]) if running else 0
th.join(10)
check(n == 1 and res2.get("r") == "cancelled", "cancel(stmt_id) from another thread")
check(db.active() == [], "nothing left running")

# iter honours budget + cancel too
e = raises(lambda: list(db.iter(SLOW, budget=0.3)), db.BudgetExceeded)
check(e is not None and not isinstance(e, tuple), "iter() budget → BudgetExceeded")

# ---- 5. max_rows + streaming --------------------------------------------------------------
e = raises(lambda: db.query("SELECT * FROM vulns", max_rows=1000), db.TooManyRows)
check(e is not None and not isinstance(e, tuple) and e.max_rows == 1000, "query(max_rows=1000) on 20000 rows → TooManyRows")
check("db.iter" in str(e), "TooManyRows message points to db.iter()")
check(len(db.query("SELECT * FROM vulns LIMIT 1000", max_rows=1000)) == 1000, "exactly max_rows rows is fine")
check(db.scalar("SELECT count(*) FROM vulns") == 20000, "connection fine after TooManyRows (cursor reset)")
chunks = list(db.iter_chunks("SELECT * FROM vulns", chunk=3000))
check([len(c) for c in chunks] == [3000] * 6 + [2000], "iter_chunks yields chunk-sized lists")
rows = list(db.iter("SELECT asset_uuid, plugin_id FROM vulns ORDER BY rowid"))
check(len(rows) == 20000 and rows[0] == {"asset_uuid": "u0", "plugin_id": 0}, "iter() yields every row as a dict")
tup = next(db.iter("SELECT asset_uuid, plugin_id FROM vulns ORDER BY rowid", tuples=True))
check(tup == ("u0", 0), "iter(tuples=True) yields plain tuples")
g = db.iter("SELECT * FROM vulns", chunk=100)
next(g)
check(len(db.active()) == 1, "an open iter() is a running statement")
g.close()
check(db.active() == [] and db.pool_stats()["running"] == 0, "closing the generator early releases it")
# a stream does not hold a read snapshot after it ends (pooled conn not in a transaction)
list(db.iter("SELECT * FROM vulns", chunk=500))
with db._POOL_LOCK:
    check(all(not w.con.in_transaction for w in db._IDLE), "idle pooled connections hold no read transaction")

# ---- 6. heavy-scan semaphore ------------------------------------------------------------
order, gate = [], threading.Event()


def heavy_a():
    for r in db.iter("SELECT uuid FROM assets", heavy=True, chunk=1):
        if not order:
            order.append("A-start")
            gate.set()
            time.sleep(0.6)               # hold the heavy slot
    order.append("A-end")


def heavy_b():
    gate.wait(5)
    db.query("SELECT count(*) FROM vulns", budget="job")   # budget='job' ⇒ heavy
    order.append("B-done")


ta, tb = threading.Thread(target=heavy_a), threading.Thread(target=heavy_b)
ta.start()
tb.start()
gate.wait(5)
time.sleep(0.1)
t0 = time.monotonic()
light = db.scalar("SELECT count(*) FROM assets")            # never waits on the semaphore
light_s = time.monotonic() - t0
ta.join(10)
tb.join(10)
check(order == ["A-start", "A-end", "B-done"], f"two heavy statements run one after the other ({order})")
check(light == 50 and light_s < 0.3, f"a light statement is not blocked by a running heavy one ({light_s:.3f}s)")
# re-entrant within one thread (heavy query inside a heavy iter must not deadlock)
done = []


def reentrant():
    for r in db.iter("SELECT uuid FROM assets LIMIT 2", heavy=True):
        done.append(db.scalar("SELECT count(*) FROM vulns WHERE asset_uuid=?", (r["uuid"],), heavy=True))


th = threading.Thread(target=reentrant)
th.start()
th.join(10)
check(done == [400, 400], "heavy statement nested in a heavy iter (same thread) does not deadlock")
# waiting for the heavy slot counts against the budget
hold, release = threading.Event(), threading.Event()


def holder():
    for _ in db.iter("SELECT uuid FROM assets", heavy=True, chunk=1):
        hold.set()
        release.wait(10)
        break


th = threading.Thread(target=holder)
th.start()
hold.wait(5)
e = raises(lambda: db.query("SELECT 1", heavy=True, budget=0.3), db.BudgetExceeded)
check(e is not None and not isinstance(e, tuple) and e.waited, "waiting for the heavy slot past the budget → BudgetExceeded(waited)")
release.set()
th.join(10)
check(db.query("SELECT 1 x", heavy=True) == [{"x": 1}], "heavy slot free again afterwards")

# ---- 7. authorizer on the shared pool -----------------------------------------------------
for t in ("keys", "smtp", "ssh", "resend"):
    e = raises(lambda t=t: db.user_query(f"SELECT * FROM {t}"), sqlite3.DatabaseError)
    check(e is not None and not isinstance(e, tuple), f"user_query cannot read {t}")
for sql in ("SELECT k.secret_key FROM assets a JOIN keys k",
            "WITH x AS (SELECT * FROM smtp) SELECT * FROM x",
            "SELECT (SELECT password FROM ssh) p",
            "ATTACH DATABASE ':memory:' AS m",
            "PRAGMA table_info(keys)",
            "SELECT load_extension('x')"):
    e = raises(lambda s=sql: db.user_query(s), sqlite3.DatabaseError)
    check(e is not None and not isinstance(e, tuple), f"user_query blocks: {sql[:40]}")
# the SAME sql run unguarded first must not leak a cached, un-authorized statement to user SQL
check(db.query("SELECT access_key FROM keys")[0]["access_key"] == "AK-SECRET", "internal query can read keys (ssh_status etc.)")
e = raises(lambda: db.user_query("SELECT access_key FROM keys"), sqlite3.DatabaseError)
check(e is not None and not isinstance(e, tuple), "…but the same SQL via user_query is still denied")
check(db.user_query("SELECT count(*) n FROM assets") == [{"n": 50}], "user_query reads normal tables")
e = raises(lambda: list(db.user_iter("SELECT * FROM resend")), sqlite3.DatabaseError)
check(e is not None and not isinstance(e, tuple), "user_iter is guarded too")
check(db.query("SELECT count(*) n FROM keys") == [{"n": 1}], "unguarded pool unaffected by user SQL")
check(db.ssh_status()["configured"] is True, "ssh_status() still reads presence of ssh creds")
# connect() still returns a private connection the caller can customise and close
c = db.connect()
c.row_factory = None
c.create_function("f1", 1, lambda x: x)
check(c.execute("SELECT f1(3)").fetchone() == (3,) and c.execute("PRAGMA temp_store").fetchone()[0] == 1,
      "connect(): private connection with the same PRAGMAs")
c.close()
check(db.scalar("SELECT count(*) FROM assets") == 50, "closing a connect() connection doesn't affect the pool")

# ---- 8. thread safety ------------------------------------------------------------------
errs, results = [], []


def hammer(k):
    try:
        for i in range(40):
            u = f"u{(k * 7 + i) % 50}"
            n = db.scalar("SELECT count(*) FROM vulns WHERE asset_uuid=?", (u,))
            rows = db.query("SELECT uuid FROM assets WHERE uuid=?", (u,))
            if i % 10 == 0:
                s = sum(1 for _ in db.iter("SELECT plugin_id FROM vulns WHERE asset_uuid=?", (u,), chunk=37))
                if s != n:
                    errs.append(("iter", u, s, n))
            if i % 13 == 0:
                try:
                    db.user_query("SELECT * FROM keys")
                    errs.append(("leak", k))
                except sqlite3.DatabaseError:
                    pass
            results.append((n, rows[0]["uuid"] == u))
    except Exception as e:
        errs.append(repr(e))


ths = [threading.Thread(target=hammer, args=(k,)) for k in range(12)]
for t in ths:
    t.start()
for t in ths:
    t.join(60)
check(not errs, f"12 threads × 40 mixed statements: no errors ({errs[:3]})")
check(len(results) == 480 and all(n == 400 and ok for n, ok in results), "…and every result correct")
st = db.pool_stats()
check(st["running"] == 0 and st["idle"] <= 3, f"pool drained, idle connections bounded ({st})")
db.close_all()
check(db.pool_stats()["idle"] == 0, "close_all() empties the pool")

print(f"\n{len(fails)} failure(s)")
sys.exit(1 if fails else 0)
