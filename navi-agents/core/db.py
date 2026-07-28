"""Read-only access to navi.db.

The backend NEVER writes to navi.db directly — it opens the file in SQLite
read-only mode so an agent run can never lock or mutate navi's database.
Tag writes go through the navi CLI (see navi_cli.py), which is navi's own
supported write path.
"""
import os
import sqlite3
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


class QueryTimeout(Exception):
    pass


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


def connect(path: str | None = None) -> sqlite3.Connection:
    p = path or db_path()
    if not os.path.exists(p):
        raise FileNotFoundError(f"navi.db not found at {p!r} (set NAVI_DB_PATH)")
    con = sqlite3.connect(_ro_uri(p), uri=True, check_same_thread=False)
    con.row_factory = sqlite3.Row
    # perf tuning for large navi.db files (read-only; safe)
    for pragma in ("PRAGMA temp_store=MEMORY", "PRAGMA cache_size=-131072",
                   "PRAGMA mmap_size=1073741824", "PRAGMA busy_timeout=3000"):
        try:
            con.execute(pragma)
        except Exception:
            pass
    return con


def _arm_budget(con, budget):
    """Abort a query after `budget` seconds so a full scan can't hang the app."""
    if not budget or budget <= 0:
        return
    deadline = time.monotonic() + budget
    con.set_progress_handler(lambda: 1 if time.monotonic() > deadline else 0, 20000)


def query(sql: str, params: tuple = (), path: str | None = None,
          budget: float | None = -1) -> list[dict]:
    con = connect(path)
    _arm_budget(con, _BUDGET_S if budget == -1 else budget)
    _t0 = time.monotonic()
    try:
        cur = con.execute(sql, params)
        return [dict(r) for r in cur.fetchall()]
    except sqlite3.OperationalError as e:
        if "interrupt" in str(e).lower():
            raise QueryTimeout(f"query exceeded time budget: {sql[:80]}") from e
        raise
    finally:
        try:                        # profile real data queries (skip introspection)
            head = sql.lstrip()[:8].upper()
            if not (head.startswith("EXPLAIN") or head.startswith("PRAGMA")
                    or "sqlite_master" in sql.lower()):
                qprofile.record(sql, (time.monotonic() - _t0) * 1000.0)
        except Exception:
            pass
        con.close()


def scalar(sql: str, params: tuple = (), path: str | None = None,
           budget: float | None = -1):
    rows = query(sql, params, path, budget=budget)
    if not rows:
        return None
    return next(iter(rows[0].values()))


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
