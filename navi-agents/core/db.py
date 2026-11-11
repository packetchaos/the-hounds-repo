"""Read-only access to navi.db.

The backend NEVER writes to navi.db directly — it opens the file in SQLite
read-only mode so an agent run can never lock or mutate navi's database.
Tag writes go through the navi CLI (see navi_cli.py), which is navi's own
supported write path.

Scale (148–600 GB navi.db) — how statements run:

* **Pooled read-only connections.** ``query()`` / ``scalar()`` / ``iter()`` lease a
  connection from a small pool keyed by (navi.db path, guarded?) instead of opening a new
  one per statement. A thread gets back the connection it used last (thread affinity), so
  its SQLite page cache (index interior pages) stays hot across statements and requests.
  A connection is exclusive to ONE running statement at a time, so a ``query()`` inside an
  ``iter()`` loop simply leases a second one. Connections are reopened when the file at the
  path is replaced or rewritten (dev/inode/size/mtime/ctime — navi ``-rebuild``, Settings
  switching navi.db) and dropped after any SQLite error. ``close_all()`` empties the pool.
* **PRAGMAs once per connection:** ``query_only=1`` (on top of ``mode=ro``),
  ``temp_store=FILE`` (big GROUP BY / DISTINCT / ORDER BY sorts spill to disk instead of
  RAM; the directory is ``SQLITE_TMPDIR`` or ``<NAVI_CACHE_DIR>/sqlite_tmp``),
  ``cache_size`` 256 MB (NAVI_DB_CACHE_MB), ``mmap_size=0`` (NAVI_DB_MMAP_MB — a ≤2 GB map
  can't cover a 148 GB file; it only inflates RSS, the OS page cache does the work),
  ``busy_timeout=3000``.
* **Streaming:** ``iter()`` yields rows in chunks (fetchmany); ``query(max_rows=N)`` raises
  ``TooManyRows`` instead of materialising millions of dicts.
* **Budgets + cancel:** ``budget=`` takes seconds or a preset — ``"open"`` 5 s, ``"run"``
  2 h, ``"job"`` 2 h, ``None``/``0`` unlimited, ``-1`` (default) = NAVI_QUERY_BUDGET_MS
  (off unless set). A progress handler checks the deadline and the statement's ``Cancel``
  token, so another thread can stop a running statement (``token.cancel()``,
  ``cancel(stmt_id)`` or ``cancel_scope(token)`` around a whole request). Raises
  ``BudgetExceeded`` / ``QueryCancelled`` (both ``QueryTimeout``); ``budget_payload(e)``
  turns them into the API's ``{ok: false, budget: true, message}``.
* **Request-scoped default budget:** ``budget_scope("open"|"run"|"job"|seconds)`` sets the
  budget for every statement in the block that passes none (one deadline per request;
  explicit budgets win; no scope = the old default). The API layer sets it per request
  (core/launcher.dispatch: page-open reads "open", ▶ Run "run", background "job").
* **One heavy scan at a time:** statements run with ``heavy=True`` (default for
  ``budget="job"``) take a process-wide semaphore (NAVI_HEAVY_SCANS, default 1), re-entrant
  per thread; light statements never wait on it.
* ``connect()`` still returns a NEW private connection the caller owns and closes (callers
  change its row_factory / functions / authorizer); it gets the same PRAGMAs.
"""
import builtins
import contextlib
import itertools
import os
import sqlite3
import threading
import time
import urllib.request

from . import qprofile

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_DISCOVERED = None

# Optional wall-clock budget per query. DEFAULT OFF (0): on a huge navi.db a real
# query may legitimately take minutes, and aborting it means "no query ever runs".
# We rely on PAGINATION to keep result sets small and let slow queries finish (the
# server is threaded, so one slow query doesn't block other pages). Set
# NAVI_QUERY_BUDGET_MS to re-enable an abort deadline; callers may still pass an
# explicit `budget=` (health does, for its tiny always-on probe).
_BUDGET_S = float(os.environ.get("NAVI_QUERY_BUDGET_MS", "0")) / 1000.0


def _envf(name, default):
    try:
        return float(os.environ.get(name, "") or default)
    except ValueError:
        return float(default)


# Budget presets (seconds). None = unlimited.
BUDGETS = {
    "open": _envf("NAVI_BUDGET_OPEN_S", 5),        # page opens, peeks, explore, Argos
    "run": _envf("NAVI_BUDGET_RUN_S", 2 * 3600),   # ▶ Run of a hound — never under 2 h (owner's rule)
    "job": _envf("NAVI_BUDGET_JOB_S", 2 * 3600),   # background runs (jobq, Release) — 2 h
    "none": None,
}
_CACHE_KB = int(_envf("NAVI_DB_CACHE_MB", 256) * 1024)
_MMAP_BYTES = int(_envf("NAVI_DB_MMAP_MB", 0) * 1024 * 1024)
_BUSY_MS = 3000
_POOL_IDLE = max(0, int(_envf("NAVI_DB_POOL_IDLE", 3)))    # idle connections kept (all paths)
_POOL_IDLE_S = _envf("NAVI_DB_POOL_IDLE_S", 300)           # idle connection lifetime
_MAX_ROWS = int(_envf("NAVI_QUERY_MAX_ROWS", 0)) or None   # default row cap for query() (off)
_PROGRESS_OPS = 10000                                      # VM ops between deadline checks
_CHUNK = 5000


class QueryTimeout(Exception):
    """A statement was stopped before it finished (budget or cancel)."""


class BudgetExceeded(QueryTimeout):
    def __init__(self, sql="", seconds=None, label=None, waited=False):
        self.sql, self.seconds, self.label, self.waited = sql, seconds, label, waited
        what = (f"the {label!r} budget ({seconds:g} s)" if label
                else f"its time budget ({seconds:g} s)" if seconds else "its time budget")
        why = (" while waiting for another heavy full scan to finish" if waited else "")
        super().__init__(f"query exceeded {what}{why} — narrow it (filter by tag, severity, "
                         f"plugin or time window, add LIMIT) or run it in the background: "
                         f"{' '.join(str(sql).split())[:80]}")


class QueryCancelled(QueryTimeout):
    def __init__(self, sql=""):
        self.sql = sql
        super().__init__(f"query cancelled: {' '.join(str(sql).split())[:80]}")


class TooManyRows(Exception):
    def __init__(self, max_rows, sql=""):
        self.max_rows, self.sql = max_rows, sql
        super().__init__(f"query returned more than {max_rows:,} rows — narrow it (filter, "
                         f"aggregate, add LIMIT) or stream it with db.iter(): "
                         f"{' '.join(str(sql).split())[:80]}")


_OPTIMIZE_IDX = "hx_v_asset"       # built by ⚡ Optimize (core/hx_optimize.py)
_HINT_OPEN = (" Opening a page only reads summaries — press ▶ Run for the full analysis "
              "(or run it in the background).")
_HINT_RUN = (" Narrow it (filter by tag, severity, plugin or time window) or run it in the "
             "background, where the 'job' budget applies.")
_HINT_OPT = " ⚡ Optimize (Settings) hasn't been run on this navi.db — its indexes make most hound reads index seeks."


def budget_payload(e) -> dict:
    """The API's answer for a statement stopped by a budget / cancel / row cap.
    {ok:false, budget:true, message, error (= message), label?, seconds?, cancelled?, max_rows?,
    optimize?} —
    `message` keeps the exception text ("…narrow it…") plus a hint for the request kind
    ("open"/"run") and, when the ⚡ Optimize indexes are missing, a pointer to them."""
    msg = str(e)
    d = {"ok": False, "budget": True}
    if isinstance(e, QueryCancelled):
        d["cancelled"] = True
    if isinstance(e, TooManyRows):
        d["max_rows"] = e.max_rows
    if isinstance(e, BudgetExceeded):
        if e.label:
            d["label"] = e.label
        if e.seconds:
            d["seconds"] = e.seconds
        msg += _HINT_OPEN if e.label == "open" else _HINT_RUN if e.label == "run" else ""
    if not isinstance(e, QueryCancelled):
        try:
            if not has_index(_OPTIMIZE_IDX):
                d["optimize"] = True
                msg += _HINT_OPT
        except Exception:
            pass
    d["message"] = msg
    d["error"] = msg            # most pages render o.error on ok:false (some o.message)
    return d


class Cancel:
    """Cancellation token: ``cancel()`` from any thread stops every statement bound to it
    (passed as ``cancel=`` or active via ``cancel_scope``) within ~10k SQLite VM steps."""
    __slots__ = ("_ev",)

    def __init__(self):
        self._ev = threading.Event()

    def cancel(self):
        self._ev.set()

    def is_set(self):
        return self._ev.is_set()

    cancelled = property(is_set)


_TLS = threading.local()


@contextlib.contextmanager
def cancel_scope(token=None):
    """Bind a Cancel token to every db statement this thread runs inside the block."""
    token = token or Cancel()
    prev = getattr(_TLS, "cancel", None)
    _TLS.cancel = token
    try:
        yield token
    finally:
        _TLS.cancel = prev


# --------------------------------------------------------------------------- #
#  Request-scoped DEFAULT budget (budget_scope)
# --------------------------------------------------------------------------- #
# The API layer (core/launcher.dispatch, core/jobq, core/release) wraps each request in
# budget_scope("open" | "run" | "job" | seconds). Every query()/scalar()/iter()/iter_chunks()
# that does NOT pass its own budget (budget=-1, the default) then runs under the scope:
#   * per_request=True (default): ONE deadline for the whole request (scope start + seconds),
#     so a page open with ten 4 s statements still answers in ~5 s, not 40 s;
#   * heavy defaults to True for "job" (one heavy scan at a time) unless the scope says so;
#   * explicit budgets ALWAYS win (budget=0/None = unlimited, budget="run", seconds…);
#   * no scope (scripts, tests, the MCP server's own callers) = today's default (-1 → env, off).
# Raw connections from connect() also honour the scope's deadline + the cancel_scope token
# (a progress handler that reads the running thread's scope), unless the caller replaces it.
# Budget/cancel/row-cap hits under a scope are recorded on it (scope.hits) so the API layer
# can flag a response as budget-limited even when the hound caught the exception itself.
def scope_budgets() -> dict:
    """Seconds per scope preset — read from the env at scope creation (tests can set it)."""
    return {"open": _envf("NAVI_OPEN_BUDGET_S", _envf("NAVI_BUDGET_OPEN_S", 5)),
            "run": _envf("NAVI_RUN_BUDGET_S", 2 * 3600),
            "job": _envf("NAVI_JOB_BUDGET_S", _envf("NAVI_BUDGET_JOB_S", 2 * 3600))}


class Scope:
    """The request's default budget (see budget_scope)."""
    __slots__ = ("seconds", "label", "heavy", "per_request", "t0", "deadline", "hits", "_lock")

    def __init__(self, seconds, label, heavy, per_request):
        self.seconds, self.label, self.heavy, self.per_request = seconds, label, heavy, per_request
        self.t0 = time.monotonic()
        self.deadline = self.t0 + seconds if (seconds and per_request) else None
        self.hits = []                    # [{kind, message}] — budget / cancel / rows hits
        self._lock = threading.Lock()

    def note(self, e):
        kind = ("cancel" if isinstance(e, QueryCancelled) else "rows" if isinstance(e, TooManyRows)
                else "budget")
        with self._lock:
            if len(self.hits) < 50:
                self.hits.append({"kind": kind, "message": str(e)[:300], "exc": e})

    @property
    def tripped(self) -> bool:
        return bool(self.hits)

    def first(self):
        """The first recorded exception (for budget_payload), or None."""
        with self._lock:
            return self.hits[0]["exc"] if self.hits else None

    def expired(self) -> bool:
        return self.deadline is not None and time.monotonic() > self.deadline

    def summary(self) -> dict:
        with self._lock:
            kinds = {}
            for h in self.hits:
                kinds[h["kind"]] = kinds.get(h["kind"], 0) + 1
            return {"label": self.label, "seconds": self.seconds, "hits": len(self.hits),
                    "kinds": kinds, "first": self.hits[0]["message"] if self.hits else None,
                    "elapsed": round(time.monotonic() - self.t0, 2)}


def current_scope():
    """The Scope active on this thread, or None."""
    return getattr(_TLS, "scope", None)


@contextlib.contextmanager
def budget_scope(budget, *, heavy=None, per_request=True):
    """Set the DEFAULT budget for every db statement this thread runs inside the block.

    budget       "open" | "run" | "job" (scope_budgets(): NAVI_OPEN_BUDGET_S 5, NAVI_RUN_BUDGET_S
                 2 h, NAVI_JOB_BUDGET_S 2 h), "none"/None/0 = unlimited (also clears an outer
                 scope), or seconds.
    heavy        default for statements without their own heavy= (None → True for "job").
    per_request  one deadline for the whole block (default) instead of per statement.
    Yields the Scope (hits, summary()). Nested scopes: the innermost wins."""
    if isinstance(budget, str):
        if budget == "none":
            secs, label = None, "none"
        else:
            sb = scope_budgets()
            if budget not in sb:
                raise ValueError(f"unknown budget scope {budget!r} (use open, run, job, none or seconds)")
            secs, label = sb[budget], budget
    elif not budget or budget <= 0:
        secs, label = None, None
    else:
        secs, label = float(budget), None
    if secs is not None and secs <= 0:
        secs = None
    sc = Scope(secs, label, (label == "job") if heavy is None else bool(heavy), per_request)
    prev = getattr(_TLS, "scope", None)
    _TLS.scope = sc
    try:
        yield sc
    finally:
        _TLS.scope = prev


def checkpoint(what="python work"):
    """Raise QueryCancelled / BudgetExceeded when this request was cancelled or its
    budget_scope deadline has passed. SQL is stopped by the progress handler, but a hound's
    Python loop over rows it already fetched (output parsing…) is not — call this every
    few hundred rows in such loops so the budget and client-disconnect cancel bound them too.
    No scope / token → never raises (cheap: two thread-local reads)."""
    tok = getattr(_TLS, "cancel", None)
    sc = getattr(_TLS, "scope", None)
    if tok is not None and tok.is_set():
        e = QueryCancelled("(%s)" % what)
    elif sc is not None and sc.expired():
        e = BudgetExceeded("(%s)" % what, sc.seconds, sc.label)
    else:
        return
    if sc is not None:
        sc.note(e)
    raise e


def _scope_progress():
    """Progress handler for caller-owned connections (connect()): honour the running thread's
    budget_scope deadline and cancel_scope token. No scope / token → never interrupts."""
    tok = getattr(_TLS, "cancel", None)
    sc = getattr(_TLS, "scope", None)
    if tok is not None and tok.is_set():
        if sc is not None and not sc.tripped:
            sc.note(QueryCancelled("(statement on a private connection)"))
        return 1
    if sc is not None and sc.expired():
        if not sc.tripped:
            sc.note(BudgetExceeded("(statement on a private connection)", sc.seconds, sc.label))
        return 1
    return 0


def _resolve_budget(budget):
    """-> (seconds or None, label or None)."""
    if isinstance(budget, str):
        if budget not in BUDGETS:
            raise ValueError(f"unknown budget preset {budget!r} (use {', '.join(BUDGETS)})")
        s = BUDGETS[budget]
        return (s if s and s > 0 else None), budget
    if budget == -1:
        budget = _BUDGET_S
    if not budget or budget <= 0:
        return None, None
    return float(budget), None


def _ro_uri(p):
    """Build a valid read-only SQLite file: URI on BOTH POSIX and Windows.

    A Windows path like ``C:\\Users\\me\\navi.db`` is NOT a valid URI —
    ``file:C:\\Users\\...`` fails. It must be ``file:///C:/Users/me/navi.db``.
    pathname2url handles the drive letter + slash conversion + escaping on every
    platform, so navi.db opens whether the operator is on macOS, Linux or Windows.
    """
    return "file:" + urllib.request.pathname2url(os.path.abspath(p)) + "?mode=ro"


def _asset_count(p):
    """Assets in a navi.db (a proxy for 'this is the real synced db'). -1 if unreadable."""
    try:
        con = sqlite3.connect(_ro_uri(p), uri=True)
        try:
            n = con.execute("SELECT count(*) FROM assets").fetchone()[0] or 0
        except Exception:
            n = 0
        con.close()
        return n
    except Exception:
        return -1


def discover_navi_db(force=False):
    """Find the navi.db the mcp / navi CLI actually uses, so the operator doesn't
    have to set NAVI_DB_PATH. Order:
      1. NAVI_DB_PATH env (explicit override always wins).
      2. The navi.db with the MOST assets among navi's common locations — that's the
         real synced database the navi-mcp reads/writes.
      3. The bundled sample_navi.db (demo fixture) as a last resort.
    Cached after the first call (pass force=True to re-scan)."""
    global _DISCOVERED
    env = os.environ.get("NAVI_DB_PATH")
    if env:
        return env
    if _DISCOVERED is not None and not force:
        return _DISCOVERED
    home = os.path.expanduser("~")
    dirs = [os.getcwd(), _REPO_ROOT, home,
            os.path.join(home, ".navi"), os.path.join(home, "navi"),
            os.path.join(home, "Documents"), os.path.join(home, "Documents", "navi"),
            os.path.join(home, "Desktop"), os.path.join(home, "Downloads")]
    seen, best, best_n = set(), None, -1
    for d in dirs:
        p = os.path.abspath(os.path.join(d, "navi.db"))
        if p in seen or not os.path.exists(p):
            continue
        seen.add(p)
        n = _asset_count(p)
        if n > best_n:                       # the fullest navi.db wins (real > empty)
            best_n, best = n, p
    if best is None:                         # no real navi.db found → demo fixture
        sample = os.path.join(_REPO_ROOT, "sample_navi.db")
        best = sample if os.path.exists(sample) else os.path.join(_REPO_ROOT, "navi.db")
    _DISCOVERED = best
    return best


def db_path() -> str:
    return discover_navi_db()


# --------------------------------------------------------------------------- #
#  Temp directory for SQLite sorters (temp_store=FILE)
# --------------------------------------------------------------------------- #
_TMP_LOCK = threading.Lock()
_TMP_DIR = None          # resolved once per process; "" = SQLite's default


def tmp_dir() -> str:
    """Where SQLite spills big sorts: $SQLITE_TMPDIR, else <NAVI_CACHE_DIR>/sqlite_tmp."""
    d = os.environ.get("SQLITE_TMPDIR")
    if d:
        return d
    cache = os.environ.get("NAVI_CACHE_DIR") or os.path.join(_REPO_ROOT, "data", "cache")
    return os.path.join(cache, "sqlite_tmp")


def tmp_info(path: str | None = None) -> dict:
    """Temp dir + free space vs navi.db size (a heavy GROUP BY may need ~10 % of the file)."""
    d = _TMP_DIR or tmp_dir()
    out = {"dir": d, "free_bytes": None, "db_bytes": None, "ok": True}
    try:
        st = os.statvfs(d)
        out["free_bytes"] = st.f_bavail * st.f_frsize
    except (OSError, AttributeError):
        pass
    try:
        out["db_bytes"] = os.path.getsize(path or db_path())
    except OSError:
        pass
    if out["free_bytes"] is not None and out["db_bytes"]:
        out["ok"] = out["free_bytes"] >= out["db_bytes"] * 0.10
    return out


def _set_tmp_dir(con):
    """Point SQLite's temp files at tmp_dir() — once per process (the pragma is global)."""
    global _TMP_DIR
    if _TMP_DIR is not None:
        return
    with _TMP_LOCK:
        if _TMP_DIR is not None:
            return
        d = tmp_dir()
        try:
            os.makedirs(d, mode=0o700, exist_ok=True)
            con.execute("PRAGMA temp_store_directory=" + "'" + d.replace("'", "''") + "'")
            _TMP_DIR = d
        except Exception:
            _TMP_DIR = ""        # unwritable / pragma compiled out → SQLite's default


def _sig(p):
    """Identity of the file at path p — changes when navi replaces or rewrites it."""
    st = os.stat(p)
    return (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns)


def _open(p) -> sqlite3.Connection:
    con = sqlite3.connect(_ro_uri(p), uri=True, check_same_thread=False)
    con.row_factory = sqlite3.Row
    _set_tmp_dir(con)
    # perf + safety tuning for large navi.db files (read-only; safe)
    for pragma in ("PRAGMA query_only=1", "PRAGMA temp_store=FILE",
                   f"PRAGMA cache_size=-{_CACHE_KB}", f"PRAGMA mmap_size={_MMAP_BYTES}",
                   f"PRAGMA busy_timeout={_BUSY_MS}"):
        try:
            con.execute(pragma)
        except Exception:
            pass
    return con


def connect(path: str | None = None) -> sqlite3.Connection:
    """A NEW private read-only connection (caller owns it and must close it)."""
    p = path or db_path()
    if not os.path.exists(p):
        raise FileNotFoundError(f"navi.db not found at {p!r} (set NAVI_DB_PATH)")
    con = _open(p)
    # budget_scope / cancel_scope reach private connections too (a no-op without a scope)
    con.set_progress_handler(_scope_progress, _PROGRESS_OPS)
    return con


# --------------------------------------------------------------------------- #
#  User / LLM SQL — the engine-level guard
# --------------------------------------------------------------------------- #
# navi keeps credentials in navi.db: `keys` (Tenable access/secret keys), `smtp` (mail
# password), `ssh` (push credentials), `resend` (mail API key). No user- or model-written
# query may read them. The regex checks in each agent are a first filter; this authorizer is
# the backstop SQLite itself enforces, whatever the SQL looks like (aliases, sub-selects,
# CTEs, views…). Use user_query() / harden() for ANY SQL that a person or a model wrote.
SECRET_TABLES = frozenset({"keys", "smtp", "ssh", "resend"})
_SQLITE_OK, _SQLITE_DENY = 0, 1
_A_PRAGMA, _A_READ, _A_ATTACH, _A_DETACH, _A_FUNCTION = 19, 20, 24, 25, 31
_BAD_FUNCS = frozenset({"load_extension", "readfile", "writefile", "edit", "fts3_tokenizer",
                        "zipfile", "unzip", "sqlite_compileoption_used", "sqlite_offset"})
# internal tables a query may read: schema introspection only
_SQLITE_INTERNAL_OK = frozenset({"sqlite_master", "sqlite_schema", "sqlite_temp_master",
                                 "sqlite_temp_schema", "sqlite_sequence"})


def user_sql_authorizer(action, arg1, arg2, dbname, trigger):
    """sqlite3 authorizer for user/LLM SQL: deny reads of navi's secret tables and of
    sqlite internals beyond the schema, ATTACH/DETACH, PRAGMA, file/host functions, and
    reads of any database other than navi.db (main/temp)."""
    if action == _A_READ:
        t = (arg1 or "").lower()
        if t in SECRET_TABLES:
            return _SQLITE_DENY
        if t.startswith("sqlite_") and t not in _SQLITE_INTERNAL_OK:
            return _SQLITE_DENY
        if dbname not in (None, "", "main", "temp"):
            return _SQLITE_DENY
    elif action in (_A_ATTACH, _A_DETACH, _A_PRAGMA):
        return _SQLITE_DENY
    elif action == _A_FUNCTION and arg2 and arg2.lower() in _BAD_FUNCS:
        return _SQLITE_DENY
    return _SQLITE_OK


def harden(con):
    """Install the user-SQL guard on an open connection (and disable extension loading)."""
    try:
        con.enable_load_extension(False)
    except Exception:
        pass
    con.set_authorizer(user_sql_authorizer)
    return con


def user_query(sql: str, params: tuple = (), path: str | None = None,
               budget: float | None = -1, *, max_rows: int | None = None,
               cancel: "Cancel | None" = None, heavy: bool | None = None) -> list[dict]:
    """db.query() for SQL a person or a model wrote — runs under user_sql_authorizer, so
    navi's credential tables (keys / smtp / ssh / resend) are unreadable. Raises
    sqlite3.DatabaseError ('not authorized') when the query touches one.
    Runs on a SEPARATE pool of connections whose authorizer is installed once at open and
    never removed, so unguarded internal statements can't share a prepared statement or a
    connection with user SQL."""
    return query(sql, params, path, budget, _guard=True, max_rows=max_rows,
                 cancel=cancel, heavy=heavy)


def user_iter(sql: str, params: tuple = (), path: str | None = None, budget=-1, **kw):
    """db.iter() for user/LLM SQL (guarded connection pool)."""
    kw["_guard"] = True
    return iter(sql, params, path, budget, **kw)


# --------------------------------------------------------------------------- #
#  Connection pool
# --------------------------------------------------------------------------- #
class _Conn:
    __slots__ = ("con", "path", "guard", "sig", "stmt", "last_thread", "idle_since", "broken")

    def __init__(self, path, guard, sig):
        self.path, self.guard, self.sig = path, guard, sig
        self.stmt = None                  # the _Stmt currently running on it
        self.last_thread = None
        self.idle_since = 0.0
        self.broken = False
        self.con = _open(path)
        if guard:
            harden(self.con)              # permanent: PRAGMAs above ran before the guard
        self.con.set_progress_handler(self._progress, _PROGRESS_OPS)

    def _progress(self):
        s = self.stmt
        if s is None:
            return 0
        if s.cancel is not None and s.cancel.is_set():
            s.why = "cancel"
            return 1
        if s.deadline is not None and time.monotonic() > s.deadline:
            s.why = "budget"
            return 1
        return 0

    def close(self):
        try:
            self.con.close()
        except Exception:
            pass


_POOL_LOCK = threading.Lock()
_IDLE: list = []                          # idle _Conn, most recently released last
_STATS = {"opened": 0, "reused": 0, "closed": 0}


def _checkout(path, guard) -> _Conn:
    p = os.path.abspath(path)
    try:
        sig = _sig(p)
    except OSError:
        raise FileNotFoundError(f"navi.db not found at {path!r} (set NAVI_DB_PATH)") from None
    me = threading.get_ident()
    now = time.monotonic()
    stale, pick = [], None
    with _POOL_LOCK:
        keep = []
        for w in _IDLE:
            if w.path == p and w.guard == guard and w.sig != sig:
                stale.append(w)           # file replaced / rewritten → reopen
            elif _POOL_IDLE_S and now - w.idle_since > _POOL_IDLE_S:
                stale.append(w)
            else:
                keep.append(w)
        _IDLE[:] = keep
        cands = [i for i, w in enumerate(_IDLE) if w.path == p and w.guard == guard]
        if cands:
            mine = [i for i in cands if _IDLE[i].last_thread == me]
            pick = _IDLE.pop((mine or cands)[-1])
            _STATS["reused"] += 1
        _STATS["closed"] += len(stale)
    for w in stale:
        w.close()
    if pick is None:
        pick = _Conn(p, guard, sig)
        with _POOL_LOCK:
            _STATS["opened"] += 1
    return pick


def _checkin(w: _Conn):
    w.stmt = None
    try:
        if w.con.in_transaction:          # never park a connection holding a read snapshot
            w.con.rollback()
    except Exception:
        w.broken = True
    if not w.broken:
        try:
            w.broken = _sig(w.path) != w.sig
        except OSError:
            w.broken = True
    if w.broken or not _POOL_IDLE:
        w.close()
        with _POOL_LOCK:
            _STATS["closed"] += 1
        return
    w.last_thread = threading.get_ident()
    w.idle_since = time.monotonic()
    drop = []
    with _POOL_LOCK:
        _IDLE.append(w)
        while len(_IDLE) > _POOL_IDLE:
            drop.append(_IDLE.pop(0))
        _STATS["closed"] += len(drop)
    for d in drop:
        d.close()


def close_all():
    """Close every idle pooled connection (tests, Settings switching navi.db)."""
    with _POOL_LOCK:
        idle = list(_IDLE)
        _IDLE.clear()
        _STATS["closed"] += len(idle)
    for w in idle:
        w.close()


def pool_stats() -> dict:
    with _POOL_LOCK:
        return dict(_STATS, idle=len(_IDLE), running=len(_RUNNING))


# --------------------------------------------------------------------------- #
#  Statements: budgets, cancel, heavy-scan admission
# --------------------------------------------------------------------------- #
_HEAVY_N = max(1, int(_envf("NAVI_HEAVY_SCANS", 1)))
_HEAVY = threading.BoundedSemaphore(_HEAVY_N)
_RUNNING: dict = {}                       # stmt id -> _Stmt (for active() / cancel())
_IDS = itertools.count(1)


class _Stmt:
    __slots__ = ("id", "sql", "deadline", "seconds", "label", "cancel", "why", "heavy",
                 "held", "t0", "thread", "scope")

    def __init__(self, sql, budget, cancel, heavy):
        self.id = next(_IDS)
        self.sql = sql
        self.t0 = time.monotonic()
        self.scope = sc = getattr(_TLS, "scope", None)
        if budget == -1 and sc is not None:       # no explicit budget → the request's scope
            self.seconds, self.label = sc.seconds, sc.label
            self.deadline = (sc.deadline if sc.per_request
                             else (self.t0 + sc.seconds if sc.seconds else None))
            if heavy is None:
                heavy = sc.heavy
            budget = None                         # (heavy default below comes from the scope)
        else:
            self.seconds, self.label = _resolve_budget(budget)
            self.deadline = self.t0 + self.seconds if self.seconds else None
        self.cancel = cancel if cancel is not None else getattr(_TLS, "cancel", None)
        if self.cancel is None:
            self.cancel = Cancel()        # so cancel(stmt_id) works for every statement
        self.why = None
        self.heavy = bool(heavy) if heavy is not None else (budget == "job")
        self.held = False
        self.thread = threading.get_ident()

    def error(self):
        if self.why == "cancel":
            return QueryCancelled(self.sql)
        return BudgetExceeded(self.sql, self.seconds, self.label)

    def hit(self, e):
        """Record a budget / cancel / row-cap stop on the request's scope (if any)."""
        if self.scope is not None:
            self.scope.note(e)
        return e


def _admit(s: _Stmt):
    """Take the heavy-scan semaphore (re-entrant per thread), within the statement budget."""
    if not s.heavy:
        return
    depth = getattr(_TLS, "heavy", 0)
    if depth:
        _TLS.heavy = depth + 1
        s.held = True
        return
    while True:
        if s.cancel.is_set():
            raise QueryCancelled(s.sql)
        wait = 0.25
        if s.deadline is not None:
            left = s.deadline - time.monotonic()
            if left <= 0:
                raise BudgetExceeded(s.sql, s.seconds, s.label, waited=True)
            wait = min(wait, left)
        if _HEAVY.acquire(timeout=wait):
            break
    _TLS.heavy = 1
    s.held = True


def _release_heavy(s: _Stmt):
    if not s.held:
        return
    s.held = False
    depth = getattr(_TLS, "heavy", 1) - 1
    _TLS.heavy = depth
    if depth <= 0:
        _TLS.heavy = 0
        _HEAVY.release()


def active() -> list[dict]:
    """Statements running right now (for a 'running queries' view / cancel button)."""
    now = time.monotonic()
    with _POOL_LOCK:
        run = list(_RUNNING.values())
    return [{"id": s.id, "sql": " ".join(s.sql.split())[:200], "secs": round(now - s.t0, 2),
             "budget": s.label or s.seconds, "heavy": s.heavy, "thread": s.thread} for s in run]


def cancel(stmt_id=None, thread=None) -> int:
    """Cancel running statement(s) by id, by thread ident, or all (no args). Returns count."""
    with _POOL_LOCK:
        run = list(_RUNNING.values())
    n = 0
    for s in run:
        if (stmt_id is None or s.id == stmt_id) and (thread is None or s.thread == thread):
            s.cancel.cancel()
            n += 1
    return n


def _record(sql, t0):
    try:                        # profile real data queries (skip introspection)
        head = sql.lstrip()[:8].upper()
        if not (head.startswith("EXPLAIN") or head.startswith("PRAGMA")
                or "sqlite_master" in sql.lower()):
            qprofile.record(sql, (time.monotonic() - t0) * 1000.0)
    except Exception:
        pass


def _translate(e, s):
    if isinstance(e, sqlite3.OperationalError) and "interrupt" in str(e).lower():
        return s.error() if s.why else QueryTimeout(f"query interrupted: {s.sql[:80]}")
    return None


def _run(sql, params, path, budget, guard, max_rows, cancel_tok, heavy, mode):
    """mode: 'all' -> list[dict], 'one' -> first row (dict) or None."""
    s = _Stmt(sql, budget, cancel_tok, heavy)
    if max_rows is None:
        max_rows = _MAX_ROWS
    w = cur = None
    try:
        with _POOL_LOCK:
            _RUNNING[s.id] = s            # visible to active()/cancel() while it waits, too
        _admit(s)                         # heavy slot first, so a waiter holds no connection
        w = _checkout(path or db_path(), guard)
        w.stmt = s
        if s.cancel.is_set():
            raise QueryCancelled(sql)
        cur = w.con.execute(sql, params)
        if mode == "one":
            r = cur.fetchone()
            return dict(r) if r is not None else None
        if not max_rows:
            return [dict(r) for r in cur.fetchall()]
        out = []
        while True:
            batch = cur.fetchmany(min(_CHUNK, max_rows + 1 - len(out)))
            if not batch:
                return out
            out.extend(dict(r) for r in batch)
            if len(out) > max_rows:
                raise TooManyRows(max_rows, sql)
    except (QueryTimeout, TooManyRows) as e:
        s.hit(e)
        raise
    except Exception as e:
        if w is not None:
            w.broken = not isinstance(e, (sqlite3.OperationalError, sqlite3.ProgrammingError)) \
                or _broken_msg(e)
        t = _translate(e, s)
        if t is not None:
            raise s.hit(t) from e
        raise
    finally:
        if cur is not None:
            try:
                cur.close()               # reset the statement → ends the read snapshot
            except Exception:
                w.broken = True
        with _POOL_LOCK:
            _RUNNING.pop(s.id, None)
        _release_heavy(s)
        if w is not None:
            _checkin(w)
            _record(sql, s.t0)


def _broken_msg(e):
    m = str(e).lower()
    return any(k in m for k in ("disk i/o", "malformed", "not a database", "unable to open",
                                "readonly database", "database is locked"))


def query(sql: str, params: tuple = (), path: str | None = None,
          budget: float | str | None = -1, _guard: bool = False, *,
          max_rows: int | None = None, cancel: Cancel | None = None,
          heavy: bool | None = None) -> list[dict]:
    """Run one read-only statement and return all rows as dicts.

    budget   seconds, a preset ("open"/"run"/"job"), None/0 = unlimited, -1 = env default.
    max_rows raise TooManyRows past N rows (default NAVI_QUERY_MAX_ROWS, off).
    cancel   a Cancel token another thread may trip (default: the cancel_scope's token).
    heavy    take the one-heavy-scan-at-a-time semaphore (default: budget == "job").
    """
    return _run(sql, params, path, budget, bool(_guard), max_rows, cancel, heavy, "all")


def scalar(sql: str, params: tuple = (), path: str | None = None,
           budget: float | str | None = -1, *, cancel: Cancel | None = None,
           heavy: bool | None = None):
    """First column of the first row (reads ONE row, not the whole result)."""
    r = _run(sql, params, path, budget, False, None, cancel, heavy, "one")
    if not r:
        return None
    return next(builtins.iter(r.values()))


def iter(sql: str, params: tuple = (), path: str | None = None,   # noqa: A001 (db.iter)
         budget: float | str | None = -1, *, chunk: int = _CHUNK, cancel: Cancel | None = None,
         heavy: bool | None = None, tuples: bool = False, _guard: bool = False):
    """Stream rows (dicts, or tuples with tuples=True) fetched `chunk` at a time.

    The connection is leased for the whole iteration (and the heavy semaphore held, if
    heavy); both are released when the generator is exhausted, closed or garbage-collected —
    use ``with contextlib.closing(db.iter(...)) as rows:`` when you may stop early. The
    budget deadline counts from the first row requested and includes the consumer's time."""
    for batch in iter_chunks(sql, params, path, budget, chunk=chunk, cancel=cancel,
                             heavy=heavy, tuples=tuples, _guard=_guard):
        yield from batch


def iter_chunks(sql: str, params: tuple = (), path: str | None = None,
                budget: float | str | None = -1, *, chunk: int = _CHUNK,
                cancel: Cancel | None = None, heavy: bool | None = None,
                tuples: bool = False, _guard: bool = False):
    """Like iter() but yields lists of up to `chunk` rows."""
    s = _Stmt(sql, budget, cancel, heavy)
    w = cur = None
    try:
        with _POOL_LOCK:
            _RUNNING[s.id] = s
        _admit(s)
        w = _checkout(path or db_path(), bool(_guard))
        if s.cancel.is_set():
            raise QueryCancelled(sql)
        cur = w.con.cursor()
        if tuples:
            cur.row_factory = None
        w.stmt = s
        try:
            cur.execute(sql, params)
        except Exception as e:
            t = _translate(e, s)
            if t is not None:
                raise t from e
            raise
        while True:
            w.stmt = s
            try:
                batch = cur.fetchmany(max(1, int(chunk)))
            except Exception as e:
                t = _translate(e, s)
                if t is not None:
                    raise t from e
                raise
            if not batch:
                return
            if not tuples:
                batch = [dict(r) for r in batch]
            if s.cancel.is_set():
                raise QueryCancelled(sql)
            if s.deadline is not None and time.monotonic() > s.deadline:
                raise BudgetExceeded(sql, s.seconds, s.label)
            yield batch
    except (QueryTimeout, TooManyRows) as e:
        s.hit(e)
        raise
    except GeneratorExit:
        raise
    except Exception as e:
        if w is not None:
            w.broken = not isinstance(e, (sqlite3.OperationalError, sqlite3.ProgrammingError)) \
                or _broken_msg(e)
        raise
    finally:
        if cur is not None:
            try:
                cur.close()
            except Exception:
                w.broken = True
        with _POOL_LOCK:
            _RUNNING.pop(s.id, None)
        _release_heavy(s)
        if w is not None:
            _checkin(w)
            _record(sql, s.t0)


def _arm_budget(con, budget):
    """Abort a query after `budget` seconds on a caller-owned connection (from connect())."""
    secs, _ = _resolve_budget(budget)
    if not secs:
        return
    deadline = time.monotonic() + secs
    con.set_progress_handler(lambda: 1 if time.monotonic() > deadline else 0, _PROGRESS_OPS)


_IDX_CACHE = {}
_IDX_LOCK = threading.Lock()


def indexes(path: str | None = None) -> set:
    """Names of the indexes in navi.db (cached per file signature — reopen/rebuild refreshes it)."""
    p = path or db_path()
    try:
        sig = _sig(p)
    except Exception:
        sig = None
    with _IDX_LOCK:
        hit = _IDX_CACHE.get(p)
        if hit and hit[0] == sig:
            return hit[1]
    try:
        # own budget + token: never cut short by (or recorded on) the caller's request scope
        names = {r["name"] for r in query("SELECT name FROM sqlite_master WHERE type='index'", path=p,
                                          budget=0, cancel=Cancel())}
    except Exception:
        names = set()
    with _IDX_LOCK:
        _IDX_CACHE[p] = (sig, names)
    return names


def has_index(name: str, path: str | None = None) -> bool:
    return name in indexes(path)


def indexed_by(name: str, path: str | None = None) -> str:
    """' INDEXED BY "name"' when that index exists, else '' — for whole-table aggregates the index
    COVERS (e.g. per-asset severity rollups over hx_v_asset). On a real navi.db a vulns row is ~5.5 KB
    (plugin output), so reading the ~2 GB index instead of the 148 GB table is the whole win; the
    planner won't pick it itself because hx_optimize marks the vulns indexes 'unordered' (which keeps
    UNcovered queries off a row-by-row index walk). INDEXED BY a missing index is an error, hence the
    guard. Usage: f"SELECT … FROM vulns{db.indexed_by('hx_v_asset')} WHERE …"."""
    return (' INDEXED BY "%s"' % name) if (name and name.replace("_", "").isalnum() and has_index(name, path)) else ""


def tags_present(categories=None, path: str | None = None) -> list:
    """Distinct (tag_key, tag_value) pairs that ACTUALLY exist in navi.db right now.

    This is the ground truth for whether a tag has been applied — agents use it so
    the UI reflects navi.db instead of a sticky client-side 'applied' flag. Optional
    `categories` limits the result to those tag_keys. Empty on any error / no table.
    """
    try:
        rows = query("SELECT DISTINCT tag_key, tag_value FROM tags "
                     "WHERE tag_key IS NOT NULL AND tag_value IS NOT NULL", path=path)
    except Exception:
        return []
    if categories:
        cats = {str(c) for c in categories}
        rows = [r for r in rows if str(r.get("tag_key")) in cats]
    return [{"tag_key": r.get("tag_key"), "tag_value": r.get("tag_value")} for r in rows]


# Curated categorical columns to profile so NL→SQL matches the ACTUAL value
# formats/casing in THIS navi.db (e.g. severity is 'high' not 'High'; state 'OPEN').
_CATCOLS = {
    "assets": ["operating_system", "network"],
    "vulns": ["severity", "state", "protocol", "plugin_family"],
    "vuln_route": ["vuln_type"],
    "tags": ["tag_key", "tag_value"],
    "certs": ["signature_algorithm", "country"],
    "fixed": ["severity"],
    "agents": ["platform", "status"],
}


def _table_cols(table, path=None):
    try:
        return {r["name"] for r in query(f'PRAGMA table_info("{table}");', path=path)}
    except Exception:
        return set()


def value_hint(tables, path=None, cap: int = 60) -> str:
    """Read the real distinct values of categorical columns for the given tables and
    return a prompt block so the model matches the actual format (case/enums)."""
    lines = []
    for t in tables:
        cols = _table_cols(t, path)
        for c in _CATCOLS.get(t, []):
            if c not in cols:
                continue
            try:
                rows = query(f'SELECT DISTINCT "{c}" AS v FROM "{t}" '
                             f'WHERE "{c}" IS NOT NULL AND TRIM("{c}")<>\'\' LIMIT {cap}', path=path)
            except Exception:
                continue
            vals = [str(r["v"]) for r in rows if r.get("v") is not None]
            if vals and len(vals) < cap:
                lines.append(f"  {t}.{c} ∈ {{ " + " | ".join(vals) + " }")
    if not lines:
        return ""
    return ("\nMatch these ACTUAL values EXACTLY (including case) — do not guess "
            "formats:\n" + "\n".join(lines) + "\n")


def ssh_status(path: str | None = None) -> dict:
    """SSH-credential readiness for ``navi action push``, read from navi's ``ssh`` table
    (schema set by ``navi config ssh``: ``username, password, key_file``).

    This is a READ of PRESENCE only — the secret values are NEVER returned. A stored
    plaintext ``password`` is a hygiene flag: navi keeps it unencrypted in navi.db, so a
    key file (``key_file``) is the preferred auth and navi.db should be protected. Used by
    the Settings panel and the Command & Control (Amarok) gate banner so an operator knows
    whether a push can even authenticate before arming remote execution.
    """
    try:
        cols = {r["name"] for r in query('PRAGMA table_info("ssh")', path=path, budget=0)}
    except Exception:
        cols = set()
    if not cols:
        return {"table": False, "configured": False, "count": 0, "has_password": False,
                "has_key": False, "plaintext_password": False, "auth": "none",
                "message": "No `ssh` table in navi.db — run `navi config ssh` to set the SSH "
                           "service-account credentials `navi action push` needs to authenticate."}
    ucol = "username" if "username" in cols else None
    pcol = "password" if "password" in cols else None
    kcol = "key_file" if "key_file" in cols else None
    sel = ", ".join(c for c in (ucol, pcol, kcol) if c) or "*"
    try:
        rows = query(f'SELECT {sel} FROM ssh', path=path, budget=0)
    except Exception:
        rows = []
    count, has_pw, has_key = 0, False, False
    for r in rows:
        u = str(r.get(ucol) or "").strip() if ucol else ""
        pw = str(r.get(pcol) or "").strip() if pcol else ""
        kf = str(r.get(kcol) or "").strip() if kcol else ""
        if u or pw or kf:
            count += 1
        if pw:
            has_pw = True
        if kf:
            has_key = True
    configured = count > 0
    auth = ("key+password" if (has_key and has_pw) else "key" if has_key
            else "password" if has_pw else "none")
    if not configured:
        msg = "`ssh` table present but empty — run `navi config ssh` before any push."
    elif has_pw:
        msg = (f"SSH configured ({count}) — a PLAINTEXT SSH password is stored in navi.db's `ssh` "
               "table. Prefer key-file auth (`navi config ssh` with a key) and protect navi.db.")
    else:
        msg = f"SSH configured ({count}) via key file."
    return {"table": True, "configured": configured, "count": count, "has_password": has_pw,
            "has_key": has_key, "plaintext_password": has_pw, "auth": auth, "message": msg}
