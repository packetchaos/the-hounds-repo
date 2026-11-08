"""Software Analyzer agent — self-contained HTTP actions."""
import re

from core import activity, db, downloads, llm, navi_cli, software
from .agent import SoftwareAgent
from core.gates import confirmed

AGENT = SoftwareAgent()

# endoflife.date is fetched by the BROWSER (page.html eolCycles) only when the user presses
# ▶ Run lifecycle check / ▶ Run all — no separate approval card, so the Auto-approve setting
# doesn't change it; registered so Settings lists every external source the pack uses.
downloads.register("endoflife", "endoflife.date lifecycle API", ["https://endoflife.date/api/<product>.json"],
                   agent="software", approval=False,
                   purpose="Per-product end-of-life / latest-release data for Mimir's lifecycle check "
                           "(one GET per matched product, cached 7 days in the browser).",
                   fallback="none — products without data show n/a")

_SQL_BANNED = re.compile(
    r"\b(insert|update|delete|drop|alter|create|attach|detach|pragma|replace|"
    r"vacuum|reindex|truncate|grant|revoke|load_extension|readfile|writefile)\b", re.I)


def _safe_select(sql, add_limit=True):
    s = (sql or "").strip().rstrip(";").strip()
    if not s:
        return None, "no SQL produced"
    if not re.match(r"^(select|with)\b", s, re.I):
        return None, "only SELECT / WITH queries are allowed"
    if ";" in s:
        return None, "only a single statement is allowed"
    if _SQL_BANNED.search(s):
        return None, "read-only queries only (no writes / DDL / file access)"
    if add_limit and not re.search(r"\blimit\b", s, re.I):
        s += " LIMIT 500"
    return s, None


def _cols(table):
    try:
        return sorted({r["name"] for r in db.query(f'PRAGMA table_info("{table}");')})
    except Exception:
        return []


def run(p):
    return {"ok": True, "agent": AGENT.meta(), "result": AGENT.run()}, 200


# navi's installed-software enumeration plugins (Windows / Unix-SSH / macOS). When a
# software tag would exceed the 1999-UUID endpoint cap we tag by these plugins with the
# product name as a -regex over the plugin output — navi matches server-side in one call
# instead of looping UUID pages. Small sets still tag by the precise UUID --query.
_SW_ENUM_PLUGINS = ("20811", "22869", "83991")


def _software_fallbacks(name):
    nm = (name or "").strip()
    if not nm:
        return []
    rx = re.escape(nm)   # product name as a literal regex over plugin output
    return [{"plugin": pid, "output": rx, "regex": True} for pid in _SW_ENUM_PLUGINS]


def tag(p):
    if not confirmed(p):
        return {"ok": False, "error": "confirm=true required to tag"}, 400
    category = (p.get("category") or "Software").strip() or "Software"
    if not activity.allowed_category("software", category):
        return {"ok": False, "error": f"category '{category}' is not one this agent writes"}, 400
    value = (p.get("value") or "").strip()
    uuids = [u for u in (p.get("uuids") or []) if u]
    name = (p.get("name") or "").strip()
    if not value or not uuids:
        return {"ok": False, "error": "value and uuids are required"}, 400
    inl = ",".join("'" + str(u).replace("'", "''") + "'" for u in uuids)
    q = "SELECT uuid AS asset_uuid FROM assets WHERE uuid IN (" + inl + ")"
    fallbacks = _software_fallbacks(name)
    jobs = navi_cli.tag_capped(category, value, uuids=uuids, query=q,
                               fallbacks=fallbacks, agent="software")
    over = len(uuids) > navi_cli.UUID_CAP and bool(fallbacks)
    job_ids = [j.get("job_id") for j in jobs if j.get("job_id") is not None]
    return {"ok": True, "category": category, "value": value,
            "count": len(uuids), "commands": len(jobs),
            "mode": "builtin" if over else "query", "over_cap": over,
            "job_ids": job_ids, "job_id": (job_ids[0] if job_ids else None),
            "result": (jobs[0] if jobs else {}),
            "writes_enabled": navi_cli.writes_enabled(),
            "write_gate_reason": navi_cli.write_gate_reason()}, 200


def nl_translate(p):
    """NL question -> ONE read-only SELECT over software ⋈ assets ⋈ vulns (asset_uuid PK).
    Generates SQL only; the page reviews/refines, then runs it via /api/explore/run_sql."""
    prompt = (p.get("prompt") or "").strip()
    if not prompt:
        return {"ok": False, "error": "empty question"}, 400
    sw_cols = _cols("software")
    if not sw_cols:
        return {"ok": False, "error": "no 'software' table in navi.db"}, 200
    gen = llm.software_query(prompt, sw_cols, _cols("assets"), _cols("vulns"),
                             value_hint=db.value_hint(["assets", "vulns"]))
    if not gen.get("ok"):
        return {"ok": False, "message": gen.get("message", "AI unavailable"),
                "llm_available": llm.available()}, 200
    sql, err = _safe_select(gen.get("sql", ""))
    if err:
        return {"ok": False, "message": err, "sql": gen.get("sql", "")}, 200
    return {"ok": True, "sql": sql, "model": gen.get("model")}, 200


def run_sql(p):
    """Execute a user-reviewed read-only SELECT (re-validated) and return rows.
    No LIMIT is added here: the page's own inventory / EOL / leaderboard queries need every row
    (a silent LIMIT 500 truncated them). NL-generated SQL already carries LIMIT 500 from nl_translate."""
    sql, err = _safe_select(p.get("sql", ""), add_limit=False)
    if err:
        return {"ok": False, "message": err}, 200
    try:
        rows = db.user_query(sql)          # engine-level guard: navi's credential tables are unreadable
    except Exception as e:
        return {"ok": False, "message": str(e), "sql": sql}, 200
    return {"ok": True, "sql": sql, "rows": rows, "count": len(rows),
            "columns": list(rows[0].keys()) if rows else []}, 200


def nl_query(p):
    """Back-compat one-shot: translate + run in a single call."""
    out, code = nl_translate(p)
    if code != 200 or not out.get("ok"):
        return out, code
    return run_sql({"sql": out["sql"]})


ACTIONS = {"run": run, "tag": tag, "nl_query": nl_query,
           "nl_translate": nl_translate, "run_sql": run_sql}
