"""Dashboard Builder — turn a plain-English request into a navi.db dashboard.

The operator types what they want to see ("top 10 plugins by affected assets",
"assets by operating system", "certs expiring per month"). The model (core.llm)
proposes ONE read-only SQL SELECT plus a visualization choice; this module then:

  1. validates the SQL is a single, read-only SELECT (defence in depth — the DB
     connection is already opened read-only in core.db), and
  2. runs it and returns rows + the chosen viz so the UI can render it in the
     project style (KPI tiles / bar chart / table).

Nothing is ever written. This agent only reads navi.db.
"""
import re
import sqlite3

from core import db

try:
    from core import llm
except Exception:  # pragma: no cover
    llm = None

# Hints appended to the (dynamically introspected) schema so the model writes
# valid SQL against whatever navi.db it is actually pointed at.
SCHEMA_NOTES = (
    "Notes: a `cves` column (if present) looks like \"['CVE-2023-48795']\" — match "
    "with LIKE '%CVE-%'; acr/aes/score are numbers stored as text — use "
    "CAST(col AS REAL). For EPSS ALWAYS join the small zipper(plugin_id,epss_value) "
    "table on vulns.plugin_id (do NOT join the 300k-row epss table by cves LIKE). For "
    "CERTIFICATE questions use the certs table; for SOFTWARE questions use the software "
    "table (software_string). Dates are ISO strings. Use ONLY the tables/columns listed.")

# join keys the dashboard may use (mirrors the advanced-search map)
_JOINS = [
    ("assets.uuid", "vulns.asset_uuid"), ("assets.uuid", "tags.asset_uuid"),
    ("assets.uuid", "software.asset_uuid"), ("assets.uuid", "certs.asset_uuid"),
    ("assets.uuid", "vuln_paths.asset_uuid"), ("assets.uuid", "fixed.asset_uuid"),
    ("assets.uuid", "compliance.asset_uuid"), ("assets.agent_uuid", "agents.uuid"),
    ("vulns.plugin_id", "plugins.plugin_id"), ("vulns.plugin_id", "zipper.plugin_id"),
    ("findings.config_id", "apps.config_id"),
]


def schema_text(db_path: str = None) -> str:
    """Introspect the live navi.db and return a compact schema description so the
    model writes SQL against the columns that actually exist (sample or real)."""
    try:
        con = db.connect(db_path)
    except Exception as e:
        return f"(could not read schema: {e})\n" + SCHEMA_NOTES
    try:
        tables = [r[0] for r in con.execute(
            "SELECT name FROM sqlite_master WHERE type='table' "
            "AND name NOT LIKE 'sqlite_%' ORDER BY name").fetchall()]
        lines = []
        for t in tables:
            cols = [r[1] for r in con.execute(f'PRAGMA table_info("{t}")').fetchall()]
            if cols:
                lines.append(f"{t}({', '.join(cols)})")
        body = "navi.db schema (SQLite, READ-ONLY):\n" + "\n".join(lines)
        tset = set(tables)
        joins = "\n".join(f"  {a} = {b}" for (a, b) in _JOINS
                          if a.split(".")[0] in tset and b.split(".")[0] in tset)
        if joins:
            body += "\n\nJOIN KEYS:\n" + joins
        try:
            body += "\n" + db.value_hint(tables, path=db_path)
        except Exception:
            pass
        return body + "\n" + SCHEMA_NOTES
    finally:
        con.close()

_SELECT_RE = re.compile(r"^\s*(select|with)\b", re.I)
# write/DDL/schema verbs + functions that could touch the host or other databases
_FORBID_RE = re.compile(
    r"\b(insert|update|delete|drop|alter|create|attach|detach|pragma|replace|"
    r"vacuum|reindex|truncate|grant|revoke|load_extension|readfile|writefile|"
    r"edit|fts3_tokenizer|zipfile|sqlite_dbpage|dbstat)\b", re.I)
_LIMIT_RE = re.compile(r"\blimit\b", re.I)

# SQLite authorizer action codes (hard-coded so behaviour is identical on all
# Python versions). The authorizer is the engine-level backstop: even if a query
# slipped past the regex, the database itself refuses anything but reads of navi.db.
_SQLITE_OK, _SQLITE_DENY = 0, 1
_ACT_ATTACH, _ACT_DETACH = 24, 25
_ACT_READ, _ACT_FUNCTION = 20, 31
_BAD_FUNCS = {"load_extension", "readfile", "writefile", "edit",
              "fts3_tokenizer", "zipfile", "unzip", "sqlite_compileoption_used"}


def _authorizer(action, arg1, arg2, dbname, trigger):
    """Deny ATTACH/DETACH (reaching other DBs), dangerous functions (file/host
    access), and reads of any database other than navi.db (main/temp). Everything
    else is a normal read and allowed."""
    if action in (_ACT_ATTACH, _ACT_DETACH):
        return _SQLITE_DENY
    if action == _ACT_FUNCTION and arg2 and arg2.lower() in _BAD_FUNCS:
        return _SQLITE_DENY
    if action == _ACT_READ and dbname not in (None, "", "main", "temp"):
        return _SQLITE_DENY
    return _SQLITE_OK


def safe_sql(sql: str):
    """Return (clean_sql, error). Read-only single-SELECT guard."""
    s = (sql or "").strip().rstrip(";").strip()
    if not s:
        return None, "no SQL produced"
    if not _SELECT_RE.match(s):
        return None, "only SELECT / WITH queries are allowed"
    if ";" in s:
        return None, "only a single statement is allowed"
    if _FORBID_RE.search(s):
        return None, "read-only queries only (no writes / DDL / file access)"
    return s, None


def _cap(sql: str, n: int = 500) -> str:
    return sql if _LIMIT_RE.search(sql) else f"{sql} LIMIT {n}"


def _run_readonly(sql: str, db_path: str = None) -> list:
    """Run a vetted SELECT on a hardened, read-only connection: SQLite opened in
    mode=ro (no writes), extension loading disabled, and an authorizer that blocks
    ATTACH/DETACH, file/host functions, and cross-database reads. The Dashboard
    builder can therefore only ever read navi.db — it cannot 'query out'."""
    con = db.connect(db_path)            # file:...?mode=ro (read-only)
    try:
        try:
            con.enable_load_extension(False)
        except Exception:
            pass
        con.set_authorizer(_authorizer)
        cur = con.execute(sql)
        return [dict(r) for r in cur.fetchall()]
    finally:
        con.set_authorizer(None)
        con.close()


def build(prompt: str, db_path: str = None) -> dict:
    """NL prompt -> rendered dashboard spec. Read-only end to end."""
    if not prompt or not prompt.strip():
        return {"ok": False, "error": "describe the dashboard you want to see"}
    if llm is None or not getattr(llm, "available", lambda: False)():
        return {"ok": False, "needs_key": True,
                "error": "Dashboard Builder needs the model to translate your request "
                         "into SQL. Set ANTHROPIC_API_KEY (or use the artifact, which "
                         "uses on-device inference)."}
    spec = llm.dashboard(prompt, schema_text(db_path))
    if not spec.get("ok"):
        return {"ok": False, "error": spec.get("message", "could not interpret the request")}
    clean, err = safe_sql(spec.get("sql", ""))
    if err:
        return {"ok": False, "error": err, "sql": spec.get("sql", "")}
    try:
        rows = _run_readonly(_cap(clean), db_path=db_path)
    except Exception as e:
        return {"ok": False, "error": f"query failed: {e}", "sql": clean}
    cols = list(rows[0].keys()) if rows else []
    viz = spec.get("viz", "table")
    if viz not in ("kpi", "bar", "line", "pie", "table"):
        viz = "table"
    return {"ok": True, "prompt": prompt, "title": spec.get("title", "Dashboard"),
            "viz": viz, "label_col": spec.get("label_col"),
            "value_col": spec.get("value_col"), "note": spec.get("note", ""),
            "sql": clean, "columns": cols, "rows": rows[:300],
            "row_count": len(rows), "model": spec.get("model")}
