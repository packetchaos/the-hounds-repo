"""Explore — shared read-only drill-down service.

Backs the two reusable detail pages (web/asset.html, web/vuln.html) that every
agent's widgets link into. All reads go through core.db (sqlite read-only); this
service never writes. It is registered as a hidden agent so its actions mount at
/api/explore/<action> on every server, but it does NOT appear as a runnable card
on the hub.

Actions
  asset      payload {uuid}   -> asset info + its vulns/plugins + its certs
  vuln       payload {plugin} -> plugin name + every affected asset + outputs
  cert_month payload {month}  -> assets whose cert fails in YYYY-MM + the cert
                                 plugins seen on those assets
"""
import re

from core import db, llm, navi_cli

# tables the NL→SQL explorer boxes are allowed to query
_NL_TABLES = {"assets", "vulns", "vuln_route", "vuln_paths"}
_SQL_BANNED = re.compile(
    r"\b(insert|update|delete|drop|alter|create|attach|detach|pragma|replace|"
    r"vacuum|reindex|truncate|grant|revoke|load_extension|readfile|writefile)\b", re.I)


def _safe_select(sql: str):
    s = (sql or "").strip().rstrip(";").strip()
    if not s:
        return None, "no SQL produced"
    if not re.match(r"^(select|with)\b", s, re.I):
        return None, "only SELECT / WITH queries are allowed"
    if ";" in s:
        return None, "only a single statement is allowed"
    if _SQL_BANNED.search(s):
        return None, "read-only queries only (no writes / DDL / file access)"
    if not re.search(r"\blimit\b", s, re.I):
        s += " LIMIT 500"
    return s, None


def _cols(table):
    """Column names for a table (read-only PRAGMA), [] on error."""
    try:
        return {r["name"] for r in db.query(f'PRAGMA table_info("{table}");')}
    except Exception:
        return set()


_MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
     "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}


def _parse_not_after(s):
    """'Apr 03 16:07:23 2027 GMT' -> 'YYYY-MM-DD' (or None)."""
    m = re.match(r"([A-Z][a-z]{2})\s+(\d{1,2})\s+[\d:]+\s+(\d{4})", s or "")
    if not m:
        return None
    return f"{int(m.group(3)):04d}-{_MONTHS[m.group(1)]:02d}-{int(m.group(2)):02d}"


def asset(p):
    uuid = (p.get("uuid") or "").strip()
    if not uuid:
        return {"ok": False, "error": "uuid required"}, 400
    a_url = ", url" if "url" in _cols("assets") else ""
    v_url = ", url" if "url" in _cols("vulns") else ""
    info = db.query(f"SELECT uuid, hostname, ip_address{a_url} FROM assets WHERE uuid=? LIMIT 1;", (uuid,))
    vulns = db.query(
        f"SELECT plugin_id, plugin_name, output, last_found{v_url} FROM vulns "
        "WHERE asset_uuid=? ORDER BY CAST(plugin_id AS INTEGER);", (uuid,))
    try:
        certs = db.query(
            "SELECT common_name, organization, organization_unit, not_valid_after, "
            "signature_algorithm, key_length FROM certs WHERE asset_uuid=?;", (uuid,))
    except Exception:
        certs = []
    for c in certs:
        c["expiry_iso"] = _parse_not_after(c.get("not_valid_after"))
    try:
        from core import hostprofile
        host = hostprofile.profile(uuid)
    except Exception:
        host = {}
    return {"ok": True, "asset": (info[0] if info else {"uuid": uuid, "hostname": "", "ip_address": ""}),
            "vulns": vulns, "certs": certs, "host": host,
            "counts": {"vulns": len(vulns), "certs": len(certs)}}, 200


def vuln(p):
    plugin = str(p.get("plugin") or "").strip()
    if not plugin:
        return {"ok": False, "error": "plugin required"}, 400
    has_v_url = "url" in _cols("vulns")
    has_a_url = "url" in _cols("assets")
    plugin_url = None
    if has_v_url:
        plugin_url = db.scalar("SELECT url FROM vulns WHERE plugin_id=? AND url IS NOT NULL AND url<>'' LIMIT 1;", (plugin,))
    name = db.scalar("SELECT plugin_name FROM vulns WHERE plugin_id=? LIMIT 1;", (plugin,))
    fsel = ", v.url AS finding_url" if has_v_url else ""
    asel = ", a.url AS asset_url" if has_a_url else ""
    rows = db.query(
        f"SELECT v.asset_uuid, a.hostname, a.ip_address, v.output, v.last_found{fsel}{asel} "
        "FROM vulns v LEFT JOIN assets a ON a.uuid=v.asset_uuid "
        "WHERE v.plugin_id=? ORDER BY a.ip_address;", (plugin,))
    for r in rows:
        r["hostname"] = (r.get("hostname") or "").strip() or "(none)"
    return {"ok": True, "plugin": plugin, "plugin_name": name or "(unknown plugin)",
            "plugin_url": plugin_url, "assets": rows, "count": len(rows)}, 200


def cert_month(p):
    month = (p.get("month") or "").strip()  # 'YYYY-MM'
    if not re.match(r"^\d{4}-\d{2}$", month):
        return {"ok": False, "error": "month must be YYYY-MM"}, 400
    a_url = ", a.url AS asset_url" if "url" in _cols("assets") else ""
    certs = db.query(
        "SELECT c.asset_uuid, a.hostname, a.ip_address, c.common_name, "
        "c.not_valid_after, c.signature_algorithm, c.key_length" + a_url + " "
        "FROM certs c LEFT JOIN assets a ON a.uuid=c.asset_uuid;")
    assets, seen, uuids = [], set(), set()
    for c in certs:
        iso = _parse_not_after(c.get("not_valid_after"))
        if not iso or iso[:7] != month:
            continue
        key = (c["asset_uuid"], iso)
        if key in seen:
            continue
        seen.add(key)
        uuids.add(c["asset_uuid"])
        assets.append({"asset_uuid": c["asset_uuid"],
                       "hostname": (c.get("hostname") or "").strip() or "(none)",
                       "ip": c.get("ip_address"), "cn": c.get("common_name"),
                       "asset_url": c.get("asset_url"),
                       "expiry_iso": iso, "date": c.get("not_valid_after"),
                       "signature_algorithm": c.get("signature_algorithm"),
                       "key_length": c.get("key_length")})
    assets.sort(key=lambda x: x["expiry_iso"])
    # relevant cert plugins seen on exactly those assets
    plugins = []
    if uuids:
        ph = ",".join("?" * len(uuids))
        plugins = db.query(
            "SELECT plugin_id, plugin_name, COUNT(DISTINCT asset_uuid) AS asset_count "
            "FROM vulns WHERE plugin_name LIKE '%Certificate%' AND asset_uuid IN (" + ph + ") "
            "GROUP BY plugin_id, plugin_name ORDER BY asset_count DESC;", tuple(uuids))
    return {"ok": True, "month": month, "assets": assets, "plugins": plugins,
            "counts": {"assets": len(assets), "plugins": len(plugins)}}, 200


def applied(p):
    """Applied tags straight from navi.db's `tags` table — the source of truth for
    'applied' status (so agent pages don't rely on a local cache)."""
    try:
        rows = db.query("SELECT tag_key, tag_value FROM tags WHERE tag_value IS NOT NULL;")
    except Exception:
        rows = []
    return {"ok": True, "applied": [{"tag_key": r.get("tag_key"), "tag_value": r.get("tag_value")}
                                    for r in rows]}, 200


def tags_compare(p):
    """Tenable ⇄ navi.db tag comparison. The Tenable side is the LIVE tag list
    (`navi explore info tags`, straight from the platform API); the navi.db side is
    the local `tags` table (asset assignments as of the last sync). The delta =
    what exists on one side but not the other, i.e. what has not synced. Read-only.

    `side` in the payload picks which half to fetch so the UI can load the fast
    navi.db side instantly and the (possibly slow, live-API) Tenable side after:
      "navi"    -> only the navi.db tags table (instant)
      "tenable" -> only `navi explore info tags` (may hit the platform API)
      "both"    -> both (default)."""
    side = (p or {}).get("side", "both")
    navi_rows, navi_err = [], ""
    if side in ("both", "navi"):
        try:
            navi = db.query("SELECT tag_key, tag_value, COUNT(DISTINCT asset_uuid) c "
                            "FROM tags WHERE tag_value IS NOT NULL "
                            "GROUP BY tag_key, tag_value")
        except Exception as e:
            navi, navi_err = [], str(e)
        navi_rows = [{"cat": r.get("tag_key"), "val": r.get("tag_value"), "c": r.get("c") or 0}
                     for r in navi]
    ten_rows, ten_ok, ten_msg, ten_src = [], False, "", "navi explore info tags"
    if side in ("both", "tenable"):
        lt = navi_cli.list_tags()
        ten_rows = [{"cat": t.get("category"), "val": t.get("value")}
                    for t in lt.get("tags", []) if t.get("category") and t.get("value")]
        ten_ok = bool(lt.get("ok"))
        ten_msg = lt.get("message") or lt.get("stderr") or ""
        ten_src = lt.get("source", ten_src)
    return {"ok": True, "side": side,
            "navi": navi_rows, "navi_error": navi_err,
            "ten": ten_rows, "ten_ok": ten_ok,
            "ten_source": ten_src, "ten_message": ten_msg}, 200


def nl_translate(p):
    """NL question -> ONE read-only SELECT over a single allowed table. Generates
    the SQL only; the caller reviews/refines and then runs it via run_sql."""
    table = (p.get("table") or "").strip()
    prompt = (p.get("prompt") or "").strip()
    if table not in _NL_TABLES:
        return {"ok": False, "error": f"table must be one of {sorted(_NL_TABLES)}"}, 400
    if not prompt:
        return {"ok": False, "error": "empty question"}, 400
    cols = sorted(_cols(table))
    if not cols:
        return {"ok": False, "error": f"no such table '{table}' in navi.db"}, 200
    gen = llm.table_query(prompt, table, cols, value_hint=db.value_hint([table]))
    if not gen.get("ok"):
        return {"ok": False, "message": gen.get("message", "AI unavailable"),
                "llm_available": llm.available()}, 200
    sql, err = _safe_select(gen.get("sql", ""))
    if err:
        return {"ok": False, "message": err, "sql": gen.get("sql", "")}, 200
    return {"ok": True, "sql": sql, "model": gen.get("model")}, 200


def run_sql(p):
    """Execute a user-reviewed read-only SELECT and return rows. Re-validated
    server-side (SELECT/WITH only, single statement, no DDL/writes, LIMIT<=500)."""
    sql, err = _safe_select(p.get("sql", ""))
    if err:
        return {"ok": False, "message": err}, 200
    try:
        rows = db.query(sql)
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


# Curated navi.db join keys — the model applies whichever tables actually exist.
_NAVI_JOINS = [
    ("assets.uuid", "vulns.asset_uuid", "one asset → many vuln findings"),
    ("assets.uuid", "tags.asset_uuid", "asset → tag assignments (tag_key / tag_value)"),
    ("assets.uuid", "software.asset_uuid", "installed software per asset"),
    ("assets.uuid", "certs.asset_uuid", "SSL/TLS certs per asset"),
    ("assets.uuid", "vuln_paths.asset_uuid", "vulnerable filesystem paths per asset"),
    ("assets.uuid", "fixed.asset_uuid", "remediated findings per asset"),
    ("assets.uuid", "compliance.asset_uuid", "compliance checks per asset"),
    ("assets.agent_uuid", "agents.uuid", "Nessus agent for an asset"),
    ("vulns.plugin_id", "plugins.plugin_id", "plugin metadata (description, solution, xrefs)"),
    ("vulns.plugin_id", "zipper.plugin_id", "EPSS per finding — FAST. zipper(plugin_id, epss_value) = one EPSS score per plugin. USE THIS for EPSS."),
    ("vulns.cves LIKE '%'||epss.cve||'%'", "epss.cve", "EPSS by CVE — SLOW fallback only (epss has 300k+ rows). Prefer zipper."),
    ("findings.config_id", "apps.config_id", "WAS findings ↔ WAS app/scan"),
]


def _all_tables():
    try:
        return [r["name"] for r in db.query(
            "SELECT name FROM sqlite_master WHERE type='table' "
            "AND name NOT LIKE 'sqlite_%' ORDER BY name;") if r.get("name")]
    except Exception:
        return []


def schema(p):
    """Live tables + columns + the join keys available in THIS navi.db."""
    tabs = _all_tables()
    cols = {t: sorted(_cols(t)) for t in tabs}
    joins = [{"left": a, "right": b, "note": n} for (a, b, n) in _NAVI_JOINS
             if a.split(".")[0].split(" ")[0] in tabs and b.split(".")[0] in tabs]
    return {"ok": True, "tables": cols, "joins": joins}, 200


def advanced_translate(p):
    """NL question -> ONE read-only SELECT that may JOIN across tables. Execute
    the returned SQL with run_sql (re-validated read-only)."""
    prompt = (p.get("prompt") or "").strip()
    if not prompt:
        return {"ok": False, "error": "empty question"}, 400
    tabs = _all_tables()
    if not tabs:
        return {"ok": False, "error": "no tables in navi.db"}, 200
    schema_text = "\n".join(f"  {t}({', '.join(sorted(_cols(t)))})" for t in tabs)
    join_text = "\n".join(
        f"  {a} = {b}   -- {n}" for (a, b, n) in _NAVI_JOINS
        if a.split(".")[0].split(" ")[0] in tabs and b.split(".")[0] in tabs)
    gen = llm.advanced_query(prompt, schema_text, join_text,
                             value_hint=db.value_hint(tabs))
    if not gen.get("ok"):
        return {"ok": False, "message": gen.get("message", "AI unavailable"),
                "llm_available": llm.available()}, 200
    sql, err = _safe_select(gen.get("sql", ""))
    if err:
        return {"ok": False, "message": err, "sql": gen.get("sql", "")}, 200
    return {"ok": True, "sql": sql, "model": gen.get("model")}, 200


def columns(p):
    """Column names for an allowed explorer table — used by the column picker."""
    table = (p.get("table") or "").strip()
    if table not in _NL_TABLES and table != "software":
        return {"ok": False, "error": f"table must be one of {sorted(_NL_TABLES | {'software'})}"}, 400
    cols = sorted(_cols(table))
    return {"ok": True, "table": table, "columns": cols}, 200


def which_agent(p):
    """Recommend the agent(s) for a plain-English task. The caller passes the
    roster it already has from /api/registry so this stays self-contained."""
    prompt = (p.get("prompt") or "").strip()
    agents = p.get("agents") or []
    if not prompt:
        return {"ok": False, "error": "empty question"}, 400
    out = llm.which_agent(prompt, agents)
    if not out.get("ok"):
        return {"ok": False, "message": out.get("message", "AI unavailable"),
                "llm_available": llm.available()}, 200
    return {"ok": True, "picks": out.get("picks", []), "note": out.get("note", ""),
            "model": out.get("model")}, 200


def navi_refresh(p):
    """Fire-and-forget: kick `navi config update assets`/`vulns` in the background to
    pull freshly-applied tags/ACR into navi.db. Returns immediately (large syncs can
    take minutes; nothing waits on them)."""
    from core import navi_cli
    kinds = p.get("kinds") or ["assets"]
    if not isinstance(kinds, (list, tuple)):
        kinds = [kinds]
    return {"ok": True, **navi_cli.update_async(tuple(kinds))}, 200


def navi_optimize(p):
    """Fire-and-forget `navi config optimize` — builds SQL indexes so tagging on big
    datasets goes from minutes to seconds. Returns immediately."""
    from core import navi_cli
    return {"ok": True, **navi_cli.optimize_async()}, 200


def tag_workers(p):
    """Get/set how many tags run in parallel (1-32). Pass {workers:N} to resize."""
    from core import tagq
    if p.get("workers") is not None:
        tagq.set_workers(p.get("workers"))
    return {"ok": True, "counts": tagq.counts()}, 200


def tag_jobs(p):
    """The background tag queue — every tag write the server has seen this run."""
    from core import tagq
    return {"ok": True, "jobs": tagq.list_jobs(), "counts": tagq.counts()}, 200


def tag_clear(p):
    """Drop finished jobs from the log (keeps queued/running)."""
    from core import tagq
    return {"ok": True, "removed": tagq.clear(), "counts": tagq.counts()}, 200


def _acr_cmd(spec):
    """Render a `navi enrich acr` command from an ACR spec (for exported scripts)."""
    from core.contract import _sh
    reasons = [x for x in (spec.get("reasons") or ["business"])]
    return ("navi enrich acr --c %s --v %s --score %s --mod %s %s%s" % (
        _sh(spec.get("category")), _sh(spec.get("value")), spec.get("score", 0),
        spec.get("mod", "set"), " ".join("-" + r for r in reasons),
        (" --note " + _sh(spec.get("note"))) if spec.get("note") else ""))


def tag_export(p):
    """Export every navi command in the Tagging log as a runnable script — a shell
    script (default) or a python script — so the batch can be dropped into cron.

    payload: {format: 'sh'|'py' (default 'sh'), which: 'all'|'done' (default 'all')}
    Rebuilds each command from the job's retained spec, reproducing the exact
    `navi enrich tag` / `navi enrich acr` calls (add-only unless the job was a
    removal). Emitted oldest-first for replay.
    """
    from core import tagq
    from core.contract import _cmd_for_spec
    fmt = (p.get("format") or "sh").lower()
    which = (p.get("which") or "all").lower()
    # CSV export — a portable record of the tagging log the AI Contract can re-import
    # (survives server restarts, unlike the in-memory queue).
    if fmt == "csv":
        import csv as _csv
        import io as _io
        buf = _io.StringIO()
        w = _csv.writer(buf)
        w.writerow(["agent", "category", "value", "selector", "detail", "op", "status"])
        rows = 0
        for j in tagq.list_jobs():
            if which == "done" and j.get("status") != "done":
                continue
            w.writerow([j.get("agent", ""), j.get("category", ""), j.get("value", ""),
                        j.get("selector", ""), j.get("detail", ""), j.get("op", ""),
                        j.get("status", "")])
            rows += 1
        return {"ok": True, "format": "csv", "count": rows,
                "filename": "navi-tags-log.csv", "script": buf.getvalue()}, 200
    jobs = list(reversed(tagq.list_jobs()))          # log is newest-first; replay oldest-first
    cmds = []
    for j in jobs:
        if which == "done" and j.get("status") != "done":
            continue
        spec = j.get("spec") or {}
        if not spec.get("category") and not spec.get("value"):
            continue
        is_acr = (j.get("op") == "acr" or spec.get("_acr")
                  or ("score" in spec and "query" not in spec and "plugin" not in spec
                      and "cve" not in spec and "xrefs" not in spec))
        cmds.append(_acr_cmd(spec) if is_acr else _cmd_for_spec(spec))
    n = len(cmds)
    if fmt in ("py", "python"):
        body = "\n".join("    %r," % c for c in cmds)
        script = ('#!/usr/bin/env python3\n'
                  '"""Replay every navi command captured in The Hounds tagging log.\n'
                  'Generated for cron — runs each navi command in order, logging pass/fail.\n'
                  'Requires the navi CLI on PATH (or set NAVI_BIN) with API keys configured."""\n'
                  'import os, shlex, subprocess, sys\n\n'
                  'NAVI = os.environ.get("NAVI_BIN", "navi")\n'
                  'COMMANDS = [\n' + body + '\n]\n\n'
                  'def main():\n'
                  '    ok = fail = 0\n'
                  '    for i, c in enumerate(COMMANDS, 1):\n'
                  '        argv = shlex.split(c)\n'
                  '        if argv and argv[0] == "navi":\n'
                  '            argv[0] = NAVI\n'
                  '        print(f"[{i}/{len(COMMANDS)}] {c}")\n'
                  '        r = subprocess.run(argv, capture_output=True, text=True)\n'
                  '        if r.returncode == 0:\n'
                  '            ok += 1\n'
                  '        else:\n'
                  '            fail += 1\n'
                  '            sys.stderr.write((r.stderr or r.stdout or "").strip() + "\\n")\n'
                  '    print(f"done: {ok} ok, {fail} failed")\n'
                  '    sys.exit(1 if fail else 0)\n\n'
                  'if __name__ == "__main__":\n'
                  '    main()\n')
        fn = "navi-tags-from-log.py"
    else:
        lines = "\n".join(c.replace("navi ", '"$NAVI" ', 1) for c in cmds)
        script = ('#!/usr/bin/env bash\n'
                  '# Replay every navi command captured in The Hounds tagging log.\n'
                  '# Generated for cron — e.g.:  0 * * * * /path/to/navi-tags-from-log.sh >> /var/log/navi-tags.log 2>&1\n'
                  '# Requires the navi CLI on PATH (or export NAVI_BIN) with API keys configured.\n'
                  'set -uo pipefail\n'
                  'NAVI="${NAVI_BIN:-navi}"\n\n'
                  + lines + ("\n\n" if lines else "\n")
                  + 'echo "replayed ' + str(n) + ' navi command(s)"\n')
        fn = "navi-tags-from-log.sh"
    return {"ok": True, "format": ("py" if fmt in ("py", "python") else "sh"),
            "count": n, "filename": fn, "script": script}, 200


def verify_tags(p):
    """Confirm applied tags actually LANDED in the tenant by cross-checking each
    tag job against the LIVE tag list (`navi explore info tags`, straight from the
    Tenable API). For every 'tag' job, report whether its category:value now shows
    up live. Tags take up to ~30 min to propagate, so 'not yet' is expected right
    after applying — re-verify later.

    Payload (all optional):
      jobs   -> a list of {category,value,op,ok} to check; defaults to the live
                background tag queue (this session's applied tags).
    Read-only; no write gate."""
    lt = navi_cli.list_tags()
    live = {((t.get("category") or "").strip(), (t.get("value") or "").strip())
            for t in lt.get("tags", []) if t.get("category") and t.get("value")}
    jobs = (p or {}).get("jobs")
    if not jobs:
        try:
            from core import tagq
            jobs = tagq.list_jobs()
        except Exception:
            jobs = []
    results, seen = [], set()
    for j in jobs:
        cat = (j.get("category") or "").strip()
        val = (j.get("value") or "").strip()
        if not cat or not val:
            continue
        op = j.get("op", "tag")
        key = (cat, val, op)
        if key in seen:
            continue
        seen.add(key)
        present = (cat, val) in live
        if op == "remove":
            # -remove strips a tag's assets but the value can persist in the tenant,
            # so `info tags` presence can't confirm a removal. Mark it inconclusive.
            verdict = "removed" if not present else "still-present"
        elif j.get("ok") is False:
            verdict = "failed"
        else:
            verdict = "landed" if present else "pending"
        results.append({"id": j.get("id"), "category": cat, "value": val, "op": op,
                        "ok": j.get("ok"), "live_present": present, "verdict": verdict})
    landed = sum(1 for r in results if r["verdict"] == "landed")
    pending = sum(1 for r in results if r["verdict"] == "pending")
    return {"ok": True, "live_ok": bool(lt.get("ok")),
            "source": lt.get("source", "navi explore info tags"),
            "live_count": len(live),
            "message": lt.get("message") or lt.get("stderr") or "",
            "summary": {"checked": len(results), "landed": landed, "pending": pending},
            "results": results}, 200


ACTIONS = {"asset": asset, "vuln": vuln, "cert_month": cert_month, "applied": applied,
           "tags_compare": tags_compare, "verify_tags": verify_tags,
           "nl_query": nl_query, "nl_translate": nl_translate, "run_sql": run_sql,
           "columns": columns, "which_agent": which_agent,
           "schema": schema, "advanced_translate": advanced_translate,
           "navi_refresh": navi_refresh, "navi_optimize": navi_optimize,
           "tag_workers": tag_workers,
           "tag_jobs": tag_jobs, "tag_clear": tag_clear, "tag_export": tag_export}
