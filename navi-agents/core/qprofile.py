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


_SELECT_LIST = re.compile(r"\bSELECT\b(?:(?!\bSELECT\b).)*?\bFROM\b", re.I | re.S)
_LIKE_COL = re.compile(rf"(?:\b(?:LOWER|UPPER)\s*\(\s*)?\b((?:{_ID}\.)?{_ID})\s*\)?\s+(?:NOT\s+)?LIKE\s+'%", re.I)
_FUNC_ON = re.compile(rf"\b(LOWER|UPPER|SUBSTR|CAST|REPLACE|TRIM|COALESCE)\s*\(\s*((?:{_ID}\.)?{_ID})", re.I)
_LIKE_JOIN = re.compile(rf"LIKE\s+'%(?:[^']|'')*'\s*\|\|\s*((?:{_ID}\.)?{_ID})", re.I)
_SMALL_ROWS = 50000                        # a full scan of a table this small isn't worth a hint
_ROWS = {"path": None, "n": {}}


def _predicates(sql):
    """The filtering part of a statement: the SELECT lists removed (a LIKE or a function in a
    result column costs nothing an index could save), WHERE / ON / HAVING / CASE arms kept."""
    s = sql
    for _ in range(20):
        t = _SELECT_LIST.sub("SELECT * FROM", s)
        if t == s:
            break
        s = t
    return s


def _table_rows(tbl, db_path):
    """Approximate row count (sqlite_stat1's first figure, else MAX(rowid)), cached per db."""
    if _ROWS["path"] != db_path:
        _ROWS["path"], _ROWS["n"] = db_path, {}
    if tbl in _ROWS["n"]:
        return _ROWS["n"][tbl]
    n = None
    try:
        from . import db
        r = db.query("SELECT stat FROM sqlite_stat1 WHERE tbl=? LIMIT 1", (tbl,), path=db_path, budget=3)
        if r and r[0].get("stat"):
            n = int(str(r[0]["stat"]).split()[0])
        if n is None:
            n = int(db.scalar('SELECT MAX(rowid) FROM "%s"' % tbl.replace('"', '""'), path=db_path, budget=3) or 0)
    except Exception:
        n = None
    _ROWS["n"][tbl] = n
    return n


def _nonsargable(sql, scans, plan, real, schema, db_path):
    """Hints only for patterns that COST something: a leading-wildcard LIKE or a function on a
    column inside a filter / join (not in the SELECT list), on a table the plan full-SCANs that
    is not small. Names the column and the table's size."""
    pred = _predicates(sql)
    amap = _alias_map(sql, real)
    qtables = list(dict.fromkeys(amap.values()))
    known_plan = bool(plan)
    scans = {amap.get(x, x) for x in (scans or ())}          # plan lines name aliases ("SCAN a")

    def owner(ref):
        ref = ref.lower()
        if "." in ref:
            a, c = ref.split(".", 1)
            t = amap.get(a)
            return (t, c) if t and c in schema.get(t, ()) else (None, c)
        ts = [t for t in qtables if ref in schema.get(t, ())]
        return (ts[0], ref) if len(ts) == 1 else (None, ref)

    def costly(t):
        if not t or t.startswith("hx_"):
            return False
        if known_plan and t not in scans:
            return False                         # the planner reaches it through an index
        n = _table_rows(t, db_path)
        return n is None or n >= _SMALL_ROWS

    def fmt(t, c):
        n = _table_rows(t, db_path)
        return "%s.%s%s" % (t, c, (" (%s rows%s)" % (format(n, ","), ", full scan" if t in scans else ""))
                            if n else "")

    out = []
    likes = [owner(m.group(1)) for m in _LIKE_COL.finditer(pred)]
    # a JOIN on a LIKE built from another column (route plugin_list vs v.plugin_id): the cost
    # is that other side's scan
    likes += [owner(m.group(1)) for m in _LIKE_JOIN.finditer(pred)]
    likes = list(dict.fromkeys((t, c) for t, c in likes if costly(t)))
    if likes:
        hint = ("leading-wildcard LIKE '%…' on " + ", ".join(fmt(t, c) for t, c in likes[:3]) +
                " can't use an index — consider an exploded/normalized table (e.g. route_plugin) or FTS.")
        if any(c == "output" for _t, c in likes):
            hint += (" ⚡ Optimize's signal table (hx_hits) answers AI / Identity output searches when "
                     "it is fresh — run Optimize after each sync.")
        if any(c == "plugin_list" for _t, c in likes) or "plugin_list like" in pred.lower():
            hint += " ⚡ Optimize's hx_route_plugin answers route membership when it is fresh."
        out.append(hint)
    funcs = [(m.group(1).upper(),) + owner(m.group(2)) for m in _FUNC_ON.finditer(pred)]
    funcs = list(dict.fromkeys((f, t, c) for f, t, c in funcs if costly(t)))
    if funcs:
        out.append("function on a column in a filter/join (" +
                   ", ".join("%s(%s)" % (f, fmt(t, c)) for f, t, c in funcs[:3]) +
                   ") — index the raw column, or store a computed column.")
    return out


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
        nonsarg = _nonsargable(sql, scans, plan, real, schema, db_path)
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
