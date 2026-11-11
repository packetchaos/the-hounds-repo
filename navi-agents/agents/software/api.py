"""Software Analyzer agent — self-contained HTTP actions.

Payload contract (build 455): the page no longer pulls raw tables through run_sql (that was
3.9 M rows / 525 MB at 150k assets and out of memory at 600k). The analysis runs here
(core.software — a faithful port of the page's parsers) and the page gets decision data:

  inventory  ▶ Run — KPIs + page 1 of the products + a drill handle (products are stored
             server-side for the run; versions carry asset COUNTS, never uuids)
  drill      page / search / sort / filter the products (views: sprawl, common, single,
             eol, delta, all)
  product    one product's versions (the drill-down card)
  eol_plan   the slug-matched products + versions the browser looks up on endoflife.date
  lifecycle  the browser's EOL verdicts → per-product EOL / behind-latest asset counts
  crown      crown-jewel roles (computed with the inventory)
  risk       the risk leaderboard (server-side rollup, top 40)
  tag        gated; a KEY ({run, key:{product, version?|kind?} | {role}}) — the server
             rebuilds the asset set from navi.db and pages it (navi_cli.tag_set). A raw
             `uuids` list is still accepted from server-side callers (Contract, tests).
  run_sql    the ✨ Ask box only: capped at 200 rows per page, 10,000 rows in all, paged
             with a signed token; never used for bulk data.
"""
import re

from core import activity, db, downloads, llm, navi_cli, payload, software
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


SECTIONS = {"products": {
    "sorts": {"sprawl": ("s1", "s2"), "common": ("s2", "s3"), "single": ("s4",), "all": ("s4",),
              "eol": ("s5",), "delta": ("s6", "s2")},
    "flags": {"multi", "single", "eol", "delta", "src:software", "src:cpe", "src:both"}}}
# each page view = (sort, filter) — the page's swSorted()
VIEWS = {"sprawl": ("sprawl", ["multi"]), "common": ("common", []), "single": ("single", ["single"]),
         "eol": ("eol", ["eol"]), "delta": ("delta", ["delta"]), "all": ("all", [])}


def _run_ok(p):
    run = (p or {}).get("run")
    return run if payload.STORE.run_info(run, "software") else None


_GONE = ({"ok": False, "expired": True, "error": "this run is no longer on the server — press ▶ Run again"}, 200)


def inventory(p):
    """▶ Run — the inventory KPIs and page 1 of the version-sprawl view (contract response)."""
    try:
        inv = software.inventory()
    except Exception as e:
        msg = str(e)
        return {"ok": False, "error": msg + (" — populate it with a navi software sync first."
                                             if re.search(r"no such table", msg) else "")}, 200
    sm = inv["summary"]
    view = (p or {}).get("view") if (p or {}).get("view") in VIEWS else "sprawl"
    srt, flt = VIEWS[view]
    b, _c = payload.drill("software", {"run": inv["run"], "section": "products", "sort": srt, "filter": flt,
                                       "limit": 50}, SECTIONS)
    return payload.response(summary=sm, top=b.get("top") or [], total_=b.get("total"), page=b.get("page"),
                            drill={"action": "drill", "run": inv["run"], "section": "products", "view": view},
                            tag={"key": "product", "count": sm["nprod"]},
                            crown=inv["crown"], agent=AGENT.meta()), 200


def run(p):
    """Back-compat name for ▶ Run: the contract response (never the raw product / uuid lists).
    The Contract's discovery reads core.software.analyze() itself (core/contract._ad_software)."""
    return inventory(p)


def drill(p):
    """Page the products. A `view` (sprawl/common/single/eol/delta/all) sets the sort + filter."""
    q = dict(p or {})
    view = q.pop("view", None)
    if view in VIEWS:
        q["sort"], q["filter"] = VIEWS[view][0], list(VIEWS[view][1])
    return payload.drill("software", q, SECTIONS)


def product(p):
    run = _run_ok(p)
    if not run:
        return _GONE
    name = (p.get("name") or "") if isinstance(p.get("name"), str) else ""
    row = payload.STORE.row(run, "products", name.lower())
    if not row:
        return {"ok": False, "error": "no such product in this run"}, 200
    return payload.response(summary={}, top=[], total_=payload.total(len(row.get("vers") or [])), product=row), 200


def eol_plan(p):
    run = _run_ok(p)
    if not run:
        return _GONE
    pl = software.eol_plan(run)
    return payload.response(summary={"products": len(pl)}, top=[], total_=payload.total(len(pl)), plan=pl[:3000]), 200


def lifecycle(p):
    """The browser's endoflife.date verdicts → EOL counts (server side). Read-only on navi.db;
    updates only this run's stored product rows."""
    run = _run_ok(p)
    if not run:
        return _GONE
    res = p.get("results") if isinstance(p.get("results"), list) else []
    eol = software.lifecycle(run, res[:5000])
    b, _c = payload.drill("software", {"run": run, "section": "products", "sort": "eol", "filter": ["eol"], "limit": 50},
                          SECTIONS)
    return payload.response(summary=eol, top=b.get("top") or [], total_=b.get("total"), page=b.get("page"),
                            drill={"action": "drill", "run": run, "section": "products", "view": "eol"}), 200


def crown(p):
    run = _run_ok(p)
    if not run:
        return _GONE
    info = payload.STORE.run_info(run, "software")
    c = (info["meta"] or {}).get("crown") or {"roles": [], "assets": 0}
    return payload.response(summary={"assets": c.get("assets", 0), "roles": len(c.get("roles") or [])},
                            top=c.get("roles") or [], total_=payload.total(len(c.get("roles") or []))), 200


def risk(p):
    run = _run_ok(p)
    if not run:
        return _GONE
    r = software.risk(run)
    return payload.response(summary={"total": r["total"], "named": r["named"]}, top=r["rows"],
                            total_=payload.total(r["total"])), 200


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
    name = (p.get("name") or "").strip()
    if isinstance(p.get("key"), dict):
        # the page's form: a KEY — the server rebuilds the asset set from navi.db
        uuids, err = _key_uuids(p)
        if err:
            return {"ok": False, "error": err}, 400
        if not value:
            return {"ok": False, "error": "value is required"}, 400
        if not uuids:
            return {"ok": False, "error": "no assets match that key"}, 200
    else:
        uuids = [u for u in (p.get("uuids") or []) if u]       # server-side callers (Contract, tests)
    if not value or not uuids:
        return {"ok": False, "error": "value and uuids are required"}, 400
    fallbacks = _software_fallbacks(name)
    # ≤ cap: the exact assets in ≤1,999-UUID batches; over it: navi built-ins (see above)
    jobs = navi_cli.tag_capped(category, value, uuids=uuids, fallbacks=fallbacks, agent="software")
    over = len(uuids) > navi_cli.UUID_CAP and bool(fallbacks)
    job_ids = [j.get("job_id") for j in jobs if j.get("job_id") is not None]
    return {"ok": True, "category": category, "value": value,
            "count": len(uuids), "commands": len(jobs),
            "mode": "builtin" if over else "query", "over_cap": over,
            "job_ids": job_ids, "job_id": (job_ids[0] if job_ids else None),
            "result": (jobs[0] if jobs else {}),
            "writes_enabled": navi_cli.writes_enabled(),
            "write_gate_reason": navi_cli.write_gate_reason()}, 200


def _key_uuids(p):
    """(uuids, error) for a tag KEY: {product, version?} · {product, kind:'eol'|'behind'} ·
    {role}. EOL / behind sets use the run's stored lifecycle verdicts."""
    k = p.get("key") or {}
    role = k.get("role")
    if isinstance(role, str) and role:
        if role not in {r for r, _a, _k in software.CROWN_ROLES}:
            return [], "unknown crown-jewel role"
        return software.assets_for(role=role), None
    prod = k.get("product")
    if not isinstance(prod, str) or not prod.strip():
        return [], "key needs a product or a role"
    kind = k.get("kind")
    if kind in ("eol", "behind"):
        run = _run_ok(p)
        if not run:
            return [], "this run is no longer on the server — press ▶ Run again"
        row = payload.STORE.row(run, "products", prod.lower()) or {}
        e = row.get("eol") or {}
        if not e.get("latest") and not e.get("eolVers"):
            return [], "run the lifecycle check first"
        ev = set(e.get("eolVers") or [])
        if kind == "eol":
            vers = sorted(ev)
        else:
            lat = e.get("latest") or ""
            vers = [v["v"] for v in row.get("vers") or [] if v["v"] and v["v"] not in ev and lat
                    and software.ver_cmp(v["v"], lat) < 0]
        return software.assets_for(product=prod, versions=vers), None
    if "version" in k:
        v = k.get("version")
        if not isinstance(v, str):
            return [], "bad version"
        return software.assets_for(product=prod, version=v), None
    return software.assets_for(product=prod), None


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


RUN_SQL_PAGE = 200          # rows per page
RUN_SQL_MAX = 10000         # rows reachable in all (the ✨ Ask box, not bulk data)


def run_sql(p):
    """Execute a user-reviewed read-only SELECT (re-validated) — CAPPED and PAGED (build 455):
    at most RUN_SQL_PAGE rows per response, RUN_SQL_MAX in all, streamed (db.user_iter) so a
    query matching millions of rows never materialises them; `next` is a signed token bound to
    the SQL. `total` is a capped count ("10,000+"). The page's own analysis no longer uses this."""
    sql, err = _safe_select(p.get("sql", ""), add_limit=False)
    if err:
        return {"ok": False, "message": err}, 200
    bind = {"sql": sql}
    start = 0
    if p.get("next"):
        try:
            start = int(payload.read_token(p["next"], bind)["pos"])
        except payload.BadToken as e:
            return {"ok": False, "message": str(e)}, 400
    if start >= RUN_SQL_MAX:
        return {"ok": False, "message": "only the first %d rows can be paged — narrow the question" % RUN_SQL_MAX}, 200
    rows, more = [], False
    try:
        it = db.user_iter(sql)          # engine-level guard: navi's credential tables are unreadable
        try:
            for i, r in enumerate(it):
                if i < start:
                    continue
                if len(rows) >= RUN_SQL_PAGE:
                    more = True
                    break
                rows.append(dict(r) if not isinstance(r, dict) else r)
        finally:
            close = getattr(it, "close", None)
            if close:
                close()
    except Exception as e:
        return {"ok": False, "message": str(e), "sql": sql}, 200
    nxt = payload.make_token({"b": payload._bind_hash(bind), "k": [], "pos": start + len(rows)}) \
        if (more and start + len(rows) < RUN_SQL_MAX) else None
    if not more:
        tot = payload.total(start + len(rows))
    else:
        try:                            # capped count probe, on the guarded connection too
            n = (db.user_query("SELECT COUNT(*) AS n FROM (SELECT 1 FROM (%s) LIMIT %d)" % (sql, RUN_SQL_MAX + 1),
                               budget="open") or [{}])[0].get("n") or 0
        except Exception:
            n = 0
        tot = payload.total(min(n, RUN_SQL_MAX), n <= RUN_SQL_MAX) if n else payload.total(start + len(rows), False)
    body = payload.response(summary={}, top=rows, total_=tot, page={"next": nxt, "start": start, "limit": RUN_SQL_PAGE},
                            sql=sql, rows=rows, count=len(rows), truncated=bool(more),
                            columns=list(rows[0].keys()) if rows else [])
    body["rows"] = body["top"]          # cap() trims `top`; `rows` mirrors it for older callers
    body["count"] = len(body["rows"])
    return body, 200


def nl_query(p):
    """Back-compat one-shot: translate + run in a single call."""
    out, code = nl_translate(p)
    if code != 200 or not out.get("ok"):
        return out, code
    return run_sql({"sql": out["sql"]})


ACTIONS = {"run": run, "inventory": inventory, "drill": drill, "product": product, "eol_plan": eol_plan,
           "lifecycle": lifecycle, "crown": crown, "risk": risk, "tag": tag, "nl_query": nl_query,
           "nl_translate": nl_translate, "run_sql": run_sql}
