"""Query profiler + index advisor.

Every read that goes through core.db is timed and logged here, tagged with the
agent/action that ran it (set by the launcher). The advisor then groups the log,
runs EXPLAIN QUERY PLAN on the slow ones to see which do a full table SCAN with no
index, pulls the WHERE / JOIN columns, and suggests CREATE INDEX statements — so a
long run on a 200 GB db becomes a concrete "build these indexes" list.

Session-only (in memory); restarting the server clears it.
"""
import os
import re
import threading
import time

_LOG = []                       # list of {sql, ms, ts, agent, action}
_LOCK = threading.Lock()
_MAX = int(os.environ.get("NAVI_QPROFILE_MAX", "600"))
_MIN_MS = float(os.environ.get("NAVI_QPROFILE_MIN_MS", "0"))   # log everything by default
_CTX = threading.local()

# columns we never bother indexing (booleans / tiny domains) or that are handled
# specially. plugin_list/xrefs are TEXT blobs matched with LIKE — see non-sargable.
_SKIP_COLS = {"remove", "confirm", "output"}   # output = huge plugin-output text; never index it


def set_context(agent="", action=""):
    _CTX.agent, _CTX.action = agent or "", action or ""


def clear_context():
    _CTX.agent, _CTX.action = "", ""


def record(sql, ms):
    if ms < _MIN_MS:
        return
    a = getattr(_CTX, "agent", "") or ""
    act = getattr(_CTX, "action", "") or ""
    with _LOCK:
        _LOG.append({"sql": " ".join(str(sql).split())[:2000], "ms": round(ms, 1),
                     "ts": time.time(), "agent": a, "action": act})
        if len(_LOG) > _MAX:
            del _LOG[0:len(_LOG) - _MAX]


def entries():
    with _LOCK:
        return list(_LOG)


_SEQ = [0]


def mark():
    """A cursor into the log so a caller can grab the queries a run added."""
    with _LOCK:
        return len(_LOG)


def since(m):
    """Queries recorded since mark() m — the queries one agent run issued."""
    with _LOCK:
        m = max(0, min(int(m or 0), len(_LOG)))
        return [dict(e) for e in _LOG[m:]]


def clear():
    with _LOCK:
        _LOG.clear()


# ------------------------------------------------------------------ advisor ----
def _norm(sql):
    """Collapse a query to a shape so repeats group: strip string/number literals
    and IN-lists, lowercase keywords stay. Used only for grouping + display."""
    s = re.sub(r"'(?:[^']|'')*'", "'?'", sql)          # string literals
    s = re.sub(r"\bIN\s*\([^)]*\)", "IN (?)", s, flags=re.I)
    s = re.sub(r"\b\d+\b", "?", s)
    return " ".join(s.split())


_ID = r"[A-Za-z_][A-Za-z0-9_]*"
_LIKE_LEAD = re.compile(r"LIKE\s+'%", re.I)                       # leading-wildcard LIKE
_FUNC_COL = re.compile(r"\b(LOWER|UPPER|SUBSTR|CAST|REPLACE|TRIM|COALESCE)\s*\(", re.I)
_SQL_KEYWORDS = {"select", "from", "where", "and", "or", "in", "on", "as", "by",
                 "group", "order", "limit", "distinct", "count", "max", "min", "sum",
                 "avg", "join", "left", "inner", "not", "null", "is", "case", "when",
                 "then", "else", "end", "like", "between", "desc", "asc", "having",
                 "union", "all", "with", "exists", "true", "false"}
_SCHEMA = {"map": None, "path": None}


def _schema(db_path):
    """{table: set(columns)} for the REAL tables in navi.db (cached per db path)."""
    if _SCHEMA["map"] is not None and _SCHEMA["path"] == db_path:
        return _SCHEMA["map"]
    sch = {}
    try:
        from . import db
        tabs = db.query("SELECT name FROM sqlite_master WHERE type='table' "
                        "AND name NOT LIKE 'sqlite_%'", path=db_path, budget=5)
        for t in tabs:
            n = t["name"]
            cols = db.query(f'PRAGMA table_info("{n}")', path=db_path, budget=5)
            sch[n.lower()] = {c["name"].lower() for c in cols}
    except Exception:
        sch = {}
    _SCHEMA["map"], _SCHEMA["path"] = sch, db_path
    return sch


def _alias_map(sql, real):
    """alias/table token -> real table name (only for tables that actually exist)."""
    amap = {}
    for m in re.finditer(rf"\b(?:FROM|JOIN)\s+({_ID})(?:\s+(?:AS\s+)?({_ID}))?", sql, re.I):
        tbl = m.group(1).lower()
        if tbl not in real:                          # CTE / subquery alias — not indexable
            continue
        amap[tbl] = tbl
        alias = (m.group(2) or "").lower()
        if alias and alias not in _SQL_KEYWORDS:
            amap[alias] = tbl
    return amap


def _cols_for(sql, real, schema):
    """Sargable (table, column) filters, resolved to REAL tables + verified columns."""
    amap = _alias_map(sql, real)
    qtables = list(dict.fromkeys(amap.values()))     # real tables used in this query
    out = []
    # qualified: alias.col / table.col
    for m in re.finditer(rf"\b({_ID})\.({_ID})\s*(=|<=|>=|<|>|\bIN\b|\bBETWEEN\b)", sql, re.I):
        tbl = amap.get(m.group(1).lower()); col = m.group(2).lower()
        if tbl and col in schema.get(tbl, ()) and col not in _SKIP_COLS:
            out.append((tbl, col))
    # bare col — attribute only if exactly ONE table in the query owns that column
    for m in re.finditer(rf"(?<![.\w])({_ID})\s*(=|<=|>=|<|>|\bIN\b|\bBETWEEN\b)", sql, re.I):
        col = m.group(1).lower()
        if col in _SQL_KEYWORDS or col in _SKIP_COLS:
            continue
        owners = [t for t in qtables if col in schema.get(t, ())]
        if len(owners) == 1:
            out.append((owners[0], col))
    seen, res = set(), []
    for c in out:
        if c not in seen:
            seen.add(c); res.append(c)
    return res


def _explain_scans(sql, db_path):
    """Tables the planner FULL-SCANs (no index) + the raw plan lines."""
    if "?" in sql:
        return set(), []
    try:
        from . import db
        rows = db.query("EXPLAIN QUERY PLAN " + sql, path=db_path, budget=8)
    except Exception:
        return set(), []
    scans, lines = set(), []
    for r in rows:
        detail = str(r.get("detail") or "")
        lines.append(detail)
        m = re.match(rf"SCAN\s+(?:TABLE\s+)?({_ID})", detail, re.I)
        if m:
            scans.add(m.group(1).lower())
    return scans, lines


def suggest(db_path=None, top=12):
    """Group the log, find the slowest distinct queries, and for the ones doing a
    full table SCAN propose REAL indexes. {queries:[…], indexes:[…]}."""
    log = entries()
    schema = _schema(db_path)
    real = set(schema.keys())
    groups = {}
    for e in log:
        k = _norm(e["sql"])
        g = groups.setdefault(k, {"sample": e["sql"], "count": 0, "total_ms": 0.0,
                                  "max_ms": 0.0, "agents": set()})
        g["count"] += 1
        g["total_ms"] += e["ms"]
        g["max_ms"] = max(g["max_ms"], e["ms"])
        if e["agent"]:
            g["agents"].add(e["agent"])
    ranked = sorted(groups.values(), key=lambda x: -x["total_ms"])[:top]

    index_votes = {}
    out_queries = []
    for g in ranked:
        sql = g["sample"]
        scans, plan = _explain_scans(sql, db_path)
        cols = _cols_for(sql, real, schema)
        # only index columns whose table is actually being SCANned (if we know the plan)
        by_tbl = {}
        for tbl, col in cols:
            if scans and tbl not in scans:
                continue
            by_tbl.setdefault(tbl, [])
            if col not in by_tbl[tbl]:
                by_tbl[tbl].append(col)
        suggs = []
        for t, cs in by_tbl.items():
            cs = cs[:3]
            key = (t, tuple(cs))
            v = index_votes.setdefault(key, {"ms": 0.0, "count": 0})
            v["ms"] += g["total_ms"]; v["count"] += g["count"]
            suggs.append("CREATE INDEX IF NOT EXISTS idx_%s_%s ON %s(%s);"
                         % (t, "_".join(cs), t, ", ".join(cs)))
        nonsarg = []
        if _LIKE_LEAD.search(sql):
            nonsarg.append("leading-wildcard LIKE '%…' can't use an index — consider an "
                           "exploded/normalized column (e.g. route_plugin) or FTS.")
        if _FUNC_COL.search(sql):
            nonsarg.append("function on a column (LOWER/CAST/COALESCE) — index the raw "
                           "column, or store a computed column.")
        out_queries.append({
            "sql": sql, "count": g["count"], "total_ms": round(g["total_ms"], 1),
            "max_ms": round(g["max_ms"], 1), "avg_ms": round(g["total_ms"] / g["count"], 1),
            "agents": sorted(g["agents"]), "full_scan": sorted(scans),
            "plan": plan, "suggested_indexes": suggs, "nonsargable": nonsarg})

    indexes = []
    for (t, cs), v in sorted(index_votes.items(), key=lambda kv: -kv[1]["ms"]):
        indexes.append({"table": t, "columns": list(cs),
                        "ddl": "CREATE INDEX IF NOT EXISTS idx_%s_%s ON %s(%s);"
                               % (t, "_".join(cs), t, ", ".join(cs)),
                        "total_ms": round(v["ms"], 1), "query_hits": v["count"]})
    return {"queries": out_queries, "indexes": indexes, "sampled": len(log)}
