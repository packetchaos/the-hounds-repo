"""Natural-language → ACR changes via the Anthropic API (standalone backend).

Turns an operator's plain-English instruction into a validated list of ACR
changes against the live tag list. The model only *proposes*; the UI previews
and the human approves before any gated write.

Config: set ANTHROPIC_API_KEY (and optionally ANTHROPIC_MODEL). With no key the
caller falls back to the deterministic rule parser, so the app still works.
"""
import json
import os
import ssl
import urllib.error
import urllib.request

API_URL = "https://api.anthropic.com/v1/messages"
DEFAULT_MODEL = os.environ.get("ANTHROPIC_MODEL", "claude-haiku-4-5-20251001")


def _ssl_context():
    """Build an SSL context that can verify api.anthropic.com. Prefer certifi's CA
    bundle (fixes the common macOS 'CERTIFICATE_VERIFY_FAILED' with python.org
    Python); fall back to the system default."""
    try:
        import certifi
        return ssl.create_default_context(cafile=certifi.where())
    except Exception:
        return ssl.create_default_context()


_SSL_CTX = _ssl_context()

SYSTEM = (
    "You convert an operator's plain-English instruction into Asset Criticality "
    "Rating (ACR) changes for Tenable tags. You are given the full list of tags "
    "(category + value). The instruction may contain SEVERAL distinct rules in one "
    "explanation (e.g. 'drop all IoT and lab gear by 5, set internet-facing to 9, "
    "bump production databases to 10, leave route tags alone'). Evaluate EVERY rule "
    "against EVERY tag and emit ONE change per tag that any rule matches — different "
    "tags get different mod/score depending on which rule applies. A tag matches a "
    "rule when the rule's subject keyword(s) appear in its category or value "
    "(case-insensitive / semantic). If several rules match one tag, use the most "
    "specific; skip tags no rule mentions. Return ONLY a JSON object, no prose:\n"
    '{"changes":[{"category":"<exact category>","value":"<exact value>",'
    '"mod":"set|inc|dec","score":<integer 1-10>,'
    '"reason":"business|compliance|mitigation|development","why":"<=8 words: which rule"}]}\n'
    "mod=set is an absolute ACR; mod=inc increases each asset's ACR by score; "
    "mod=dec decreases it by score. score is 1-10. NEVER invent a tag not in the "
    'provided list. If nothing should change, return {"changes":[]}.')


def available() -> bool:
    return bool(os.environ.get("ANTHROPIC_API_KEY"))


def _extract_json(text: str) -> dict:
    text = text.strip()
    if text.startswith("```"):
        text = text.split("```", 2)[1]
        if text.lstrip().startswith("json"):
            text = text.lstrip()[4:]
    s, e = text.find("{"), text.rfind("}")
    if s >= 0 and e > s:
        text = text[s:e + 1]
    return json.loads(text)


def _messages(system: str, user: str, max_tokens: int = 1000, timeout: int = 40) -> str:
    """Low-level single-turn call; returns the model's text. Raises on failure."""
    key = os.environ.get("ANTHROPIC_API_KEY")
    if not key:
        raise RuntimeError("no ANTHROPIC_API_KEY")
    body = {"model": DEFAULT_MODEL, "max_tokens": max_tokens, "system": system,
            "messages": [{"role": "user", "content": user}]}
    req = urllib.request.Request(
        API_URL, data=json.dumps(body).encode(),
        headers={"x-api-key": key, "anthropic-version": "2023-06-01",
                 "content-type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_SSL_CTX) as r:
            resp = json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        # Surface the REAL reason from Anthropic's JSON body, not just "Bad Request".
        body = ""
        try:
            body = e.read().decode("utf-8", "replace")
        except Exception:
            pass
        msg = body
        try:
            msg = (json.loads(body).get("error") or {}).get("message") or body
        except Exception:
            pass
        hint = ""
        low = (msg or "").lower()
        if e.code == 400 and "credit balance" in low:
            hint = ("  → Your Anthropic account has no usable credit. Add a payment "
                    "method / buy credits at console.anthropic.com → Billing.")
        elif e.code == 400 and ("model" in low and ("not found" in low or "invalid" in low)):
            hint = (f"  → The model '{DEFAULT_MODEL}' isn't available to this key. "
                    "Set ANTHROPIC_MODEL to one you have access to "
                    "(e.g. claude-3-5-haiku-latest).")
        elif e.code in (401, 403):
            hint = ("  → The key was rejected. Use a real API key that starts with "
                    "'sk-ant-' from console.anthropic.com → API Keys (not a Claude.ai "
                    "login or OAuth token).")
        raise RuntimeError(f"Anthropic API HTTP {e.code}: {msg or e.reason}{hint}") from e
    except urllib.error.URLError as e:
        if "CERTIFICATE_VERIFY_FAILED" in str(e):
            raise RuntimeError(
                "SSL certificate verification failed reaching api.anthropic.com. "
                "Fix: run  pip install --upgrade certifi  (the app picks it up "
                "automatically), or on macOS run the 'Install Certificates.command' "
                "that ships with your python.org Python.") from e
        raise
    return "".join(b.get("text", "") for b in resp.get("content", []))


APP_SYSTEM = (
    "Extract the custom application the user wants to tag from their message. "
    'Return ONLY JSON: {"name":"<short tag name>","keywords":["<path search term>",...]}. '
    "name is what the tag value should be (e.g. 'navi'). keywords are lowercase "
    "substrings to search filesystem paths for (usually the app name and obvious "
    "folder/binary variants). Keep keywords short and specific.")


def extract_app(prompt: str) -> dict:
    """NL → {ok, name, keywords[]}. Falls back to a naive parse if no LLM."""
    if not available():
        # naive fallback: last quoted term, else last word
        import re as _re
        m = _re.findall(r"['\"]([^'\"]+)['\"]", prompt or "")
        name = (m[-1] if m else (prompt or "").strip().split()[-1] if prompt.strip() else "")
        name = name.strip().lower()
        return {"ok": bool(name), "fallback": True, "name": name,
                "keywords": [name] if name else []}
    try:
        data = _extract_json(_messages(APP_SYSTEM, prompt, max_tokens=300))
        kws = [k.lower() for k in data.get("keywords", []) if k]
        name = (data.get("name") or (kws[0] if kws else "")).strip()
        return {"ok": bool(name), "name": name, "keywords": kws or ([name] if name else []),
                "model": DEFAULT_MODEL}
    except Exception as e:
        return {"ok": False, "fallback": True, "message": str(e)}


def cert_plan(system_prompt: str, certs: list[dict], timeout: int = 40) -> dict:
    """Certificate triage: the (editable) static system prompt + the failing-cert
    list → an assessment + per-cert tag/skip decisions. Falls back cleanly with
    no key (caller then tags everything deterministically)."""
    if not available():
        return {"ok": False, "fallback": True,
                "message": "no ANTHROPIC_API_KEY — tagging all candidates deterministically"}
    user = ("Certificates failing in the next 12 months (JSON):\n"
            + json.dumps(certs) + "\n\nReturn ONLY the JSON described in the system prompt.")
    try:
        data = _extract_json(_messages(system_prompt, user, max_tokens=1400, timeout=timeout))
        return {"ok": True, "assessment": data.get("assessment", ""),
                "tag": data.get("tag", []), "skip": data.get("skip", []),
                "model": DEFAULT_MODEL}
    except Exception as e:
        return {"ok": False, "fallback": True, "message": f"LLM call failed ({e})"}


DASH_SYSTEM = (
    "You are a Tenable security data analyst. Convert the user's request into ONE "
    "read-only SQLite query over the navi.db schema below (you MAY join across tables "
    "using the JOIN KEYS), and pick the best chart for the data's shape. "
    "Return ONLY a JSON object, no prose:\n"
    '{"title":"<short dashboard title>","sql":"SELECT ...","viz":"kpi|bar|line|pie|table",'
    '"label_col":"<category/date column>","value_col":"<numeric column>",'
    '"note":"<=14 word caption"}\n'
    "Rules: query ONLY this navi.db — never ATTACH another database and never use "
    "file/host functions (load_extension, readfile, writefile). sql MUST be a single "
    "SELECT (or WITH ... SELECT) — never INSERT, UPDATE, DELETE, DROP, ALTER, CREATE, "
    "ATTACH, PRAGMA, REPLACE, or multiple statements. Always add a LIMIT (<=50). "
    "Return exactly two columns for charts: label_col (text category or date) then "
    "value_col (numeric), ordered sensibly. Chart choice by shape: 'line' for a "
    "time/date series; 'pie' for parts-of-a-whole with <=8 categories; 'bar' to rank "
    "categories by a number (value_col DESC); 'kpi' for one row of scalar totals; "
    "'table' otherwise. Prefer COUNT(*) aggregates and GROUP BY for distributions.\n\n")


def dashboard(prompt: str, schema: str, timeout: int = 40) -> dict:
    """NL request → {ok, title, sql, viz, label_col, value_col, note}. The model
    only proposes SQL; the caller validates it is read-only and runs it against the
    read-only DB connection."""
    if not available():
        return {"ok": False, "fallback": True,
                "message": "no ANTHROPIC_API_KEY — the Dashboard Builder needs the model to write SQL"}
    try:
        data = _extract_json(_messages(
            DASH_SYSTEM + schema,
            "Request: " + (prompt or "") + "\n\nReturn ONLY the JSON object.",
            max_tokens=700, timeout=timeout))
        return {"ok": True, "title": data.get("title", "Dashboard"),
                "sql": data.get("sql", ""), "viz": data.get("viz", "table"),
                "label_col": data.get("label_col"), "value_col": data.get("value_col"),
                "note": data.get("note", ""), "model": DEFAULT_MODEL}
    except Exception as e:
        return {"ok": False, "fallback": True, "message": f"LLM call failed ({e})"}


IDENTITY_SYSTEM = (
    "You convert an operator's plain-English instruction into TAG assignments for "
    "discovered identities (accounts) on Tenable assets. You are given the list of "
    "identities (user + class: nhi|human|service|system). Return ONLY JSON:\n"
    '{"assignments":[{"user":"<exact user>","category":"<tag category>","value":"<tag value>"}]}\n'
    "Rules: include ONLY identities that should be tagged. Use the user names exactly "
    "as given. Pick a sensible category (e.g. NHI, Identity) and a concise value. If "
    "nothing should be tagged, return {\"assignments\":[]}.")


def identity_plan(prompt: str, accounts: list[dict], timeout: int = 40) -> dict:
    """NL instruction + identities -> {ok, assignments:[{user,category,value}]}."""
    if not available():
        return {"ok": False, "fallback": True,
                "message": "no ANTHROPIC_API_KEY — use the per-row Tag buttons instead"}
    slim = [{"user": a.get("user"), "class": a.get("klass")} for a in accounts]
    user = ("Identities (JSON):\n" + json.dumps(slim) + "\n\nInstruction:\n" + (prompt or "")
            + "\n\nReturn ONLY the JSON described in the system prompt.")
    try:
        data = _extract_json(_messages(IDENTITY_SYSTEM, user, max_tokens=1200, timeout=timeout))
        return {"ok": True, "assignments": data.get("assignments", []), "model": DEFAULT_MODEL}
    except Exception as e:
        return {"ok": False, "fallback": True, "message": f"LLM call failed ({e})"}


OWNER_SYSTEM = (
    "You map exposure ROUTES and filesystem PATHS to OWNERS (a user or a group) per "
    "the operator's instruction. You are given the list of ROUTES (by app_name), PATHS, "
    "and OWNERS (name + type). The instruction may contain several rules. For every "
    "route/path the instruction refers to, output one mapping to the owner it names. "
    "Match routes/paths by keyword/semantics against app_name or path text; match the "
    "owner by name (case-insensitive) to an EXACT entry in the OWNERS list. Use the exact "
    "app_name / path / owner name from the lists — never invent. Skip anything no rule "
    'mentions. Return ONLY JSON: {"mappings":[{"kind":"route|path","match":"<exact '
    'app_name or path>","owner":"<exact owner name>"}]}.')


def owner_plan(prompt: str, routes: list[str], paths: list[str],
               owners: list[dict], timeout: int = 40) -> dict:
    """NL + routes/paths/owners -> {ok, mappings:[{kind,match,owner}]}."""
    if not available():
        return {"ok": False, "fallback": True,
                "message": "no ANTHROPIC_API_KEY — natural-language owner mapping needs the model"}
    payload = {"routes": routes, "paths": paths, "owners": owners}
    user = ("Lists (JSON):\n" + json.dumps(payload) + "\n\nInstruction:\n" + (prompt or "")
            + "\n\nReturn ONLY the JSON described in the system prompt.")
    try:
        data = _extract_json(_messages(OWNER_SYSTEM, user, max_tokens=1500, timeout=timeout))
        return {"ok": True, "mappings": data.get("mappings", []), "model": DEFAULT_MODEL}
    except Exception as e:
        return {"ok": False, "fallback": True, "message": f"LLM call failed ({e})"}


def table_query(prompt: str, table: str, columns: list, timeout: int = 40,
                value_hint: str = "") -> dict:
    """NL question -> ONE read-only SELECT over a single navi.db table.
    Returns {ok, sql} or {ok:False, fallback, message}. The caller still
    validates the SQL is read-only before running it. value_hint carries the
    actual distinct values of categorical columns so casing/enums match."""
    if not available():
        return {"ok": False, "fallback": True,
                "message": "no ANTHROPIC_API_KEY — natural-language SQL needs the model"}
    sys = (
        "You convert a question into ONE read-only SQLite SELECT over the navi.db "
        f"table {table}({', '.join(columns)}). Return ONLY the SQL — no prose, no "
        "markdown fence. Query ONLY this table (filter/aggregate/GROUP BY/ORDER BY "
        "allowed). Always include a LIMIT (<=500). NEVER write/UPDATE/DELETE/DROP/"
        "ALTER/CREATE/ATTACH/PRAGMA. Notes: cves looks like \"['CVE-2023-...']\" "
        "(match LIKE '%CVE-%'); acr/aes/score are numbers stored as text (use "
        "CAST(col AS REAL)); score on vulns is the VPR." + (value_hint or ""))
    try:
        txt = _messages(sys, "Question: " + (prompt or ""), max_tokens=400, timeout=timeout)
        sql = (txt or "").strip()
        if sql.startswith("```"):
            sql = sql.split("```", 2)[1]
            if sql.lstrip().lower().startswith("sql"):
                sql = sql.lstrip()[3:]
        return {"ok": True, "sql": sql.strip().rstrip(";").strip(), "model": DEFAULT_MODEL}
    except Exception as e:
        return {"ok": False, "fallback": True, "message": f"LLM call failed ({e})"}


def contract_select(agent_name: str, logic: str, items: list, top_n: int = 50,
                    timeout: int = 40) -> dict:
    """Apply a human's plain-English logic to an agent's candidate list and return
    which items to KEEP (by index). items: [{i, label, rank}]. Falls back to the
    caller's risk-ranked top_n when no key/logic. Returns {ok, keep:[i,...], note}."""
    if not logic or not available():
        return {"ok": False, "fallback": True,
                "message": "no logic or no ANTHROPIC_API_KEY — using risk-ranked top-N"}
    import json
    listing = "\n".join(f'{it["i"]}: {it["label"]} (rank {it.get("rank","?")})' for it in items)
    sys = (
        f"You apply a human's tagging policy to the '{agent_name}' agent's candidate "
        "list. Decide which candidates to tag. Honor inclusions AND exclusions in the "
        "policy (e.g. 'tag all IoT but not Dell or Intel — those are laptops'). If the "
        "policy doesn't restrict, keep the highest-rank items. Return ONLY JSON: "
        '{"keep":[<indices to tag>],"note":"<one line>"}.\n\nPolicy: ' + logic +
        "\n\nCandidates (index: label):\n" + listing)
    try:
        txt = _messages(sys, "Return the JSON.", max_tokens=900, timeout=timeout)
        t = (txt or "").strip()
        if t.startswith("```"):
            t = t.split("```", 2)[1]
            if t.lstrip().lower().startswith("json"):
                t = t.lstrip()[4:]
        a, b = t.find("{"), t.rfind("}")
        data = json.loads(t[a:b + 1] if a >= 0 and b > a else t)
        keep = [int(x) for x in data.get("keep", []) if str(x).strip().lstrip("-").isdigit()]
        return {"ok": True, "keep": keep, "note": data.get("note", ""), "model": DEFAULT_MODEL}
    except Exception as e:
        return {"ok": False, "fallback": True, "message": f"LLM call failed ({e})"}


def advanced_query(prompt: str, schema_text: str, join_text: str, timeout: int = 40,
                   value_hint: str = "") -> dict:
    """NL question -> ONE read-only SELECT that may JOIN across navi.db tables.
    schema_text lists table(columns); join_text lists the available join keys;
    value_hint carries the actual distinct values of categorical columns."""
    if not available():
        return {"ok": False, "fallback": True,
                "message": "no ANTHROPIC_API_KEY — advanced cross-table search needs the model"}
    sys = (
        "You convert a question into ONE read-only SQLite SELECT over a Tenable "
        "navi.db. You MAY join across any of these tables as needed.\nTables:\n"
        + schema_text + "\n\nJOIN KEYS (use these exact relationships):\n" + join_text +
        "\n\nRules: Return ONLY the SQL — no prose, no markdown fence. Use table "
        "aliases and qualify columns. Prefer the asset_uuid foreign keys. For EPSS, "
        "ALWAYS join the small zipper table on plugin_id (JOIN zipper z ON "
        "z.plugin_id=v.plugin_id, CAST(z.epss_value AS REAL)); do NOT join the huge "
        "epss table by cves LIKE unless zipper is absent (epss has 300k+ rows and will "
        "time out). For CERTIFICATE questions use the certs table; for SOFTWARE / "
        "installed-product questions use the software table (software_string) — they "
        "give better results than scanning vulns. Use GROUP BY / MAX / aggregates when "
        "the question implies highest/most/per. Always include a LIMIT (<=500). NEVER "
        "write/UPDATE/DELETE/DROP/ALTER/CREATE/ATTACH/PRAGMA. Notes: "
        "acr/aes/epss_value/score are numeric-as-text "
        "(CAST(col AS REAL)); tags identify a tag via tag_key (category) + tag_value."
        + (value_hint or ""))
    try:
        txt = _messages(sys, "Question: " + (prompt or ""), max_tokens=600, timeout=timeout)
        sql = (txt or "").strip()
        if sql.startswith("```"):
            sql = sql.split("```", 2)[1]
            if sql.lstrip().lower().startswith("sql"):
                sql = sql.lstrip()[3:]
        return {"ok": True, "sql": sql.strip().rstrip(";").strip(), "model": DEFAULT_MODEL}
    except Exception as e:
        return {"ok": False, "fallback": True, "message": f"LLM call failed ({e})"}


def which_agent(prompt: str, agents: list, timeout: int = 40) -> dict:
    """Recommend 1–3 agents for a task. `agents` is a list of dicts with id/name/
    summary (and optional codename). Returns {ok, picks:[{id,why}], note}."""
    if not available():
        return {"ok": False, "fallback": True,
                "message": "no ANTHROPIC_API_KEY — the agent recommender needs the model"}
    import json
    roster = "\n".join(
        f"{a.get('id')} — {a.get('codename') or a.get('name')}: {a.get('summary','')}"
        for a in agents if a.get("id"))
    sys = (
        'You are a router for a Tenable/navi security agent suite called "The Hounds". '
        "Given the user's task, pick the 1-3 most relevant agents from the roster and "
        'explain briefly why each fits. Return ONLY JSON: {"picks":[{"id":"<exact id>",'
        '"why":"<one sentence>"}],"note":"<optional one-line tip>"}.\n\n'
        "Roster (id — name — what it does):\n" + roster)
    try:
        txt = _messages(sys, "Task: " + prompt, max_tokens=500, timeout=timeout)
        t = (txt or "").strip()
        if t.startswith("```"):
            t = t.split("```", 2)[1]
            if t.lstrip().lower().startswith("json"):
                t = t.lstrip()[4:]
        a, b = t.find("{"), t.rfind("}")
        data = json.loads(t[a:b + 1] if a >= 0 and b > a else t)
        return {"ok": True, "picks": data.get("picks", []),
                "note": data.get("note", ""), "model": DEFAULT_MODEL}
    except Exception as e:
        return {"ok": False, "fallback": True, "message": f"LLM call failed ({e})"}


def software_query(prompt: str, sw_cols: list, asset_cols: list, vuln_cols: list,
                   timeout: int = 40, value_hint: str = "") -> dict:
    """NL question -> ONE read-only SELECT over the software inventory, joining
    software ⋈ assets ⋈ vulns on the asset_uuid primary key. Returns {ok, sql}
    or {ok:False, fallback, message}. Caller still validates read-only SQL."""
    if not available():
        return {"ok": False, "fallback": True,
                "message": "no ANTHROPIC_API_KEY — natural-language SQL needs the model"}
    sys = (
        "You convert a question into ONE read-only SQLite SELECT over a navi.db "
        "software inventory.\nTables and columns:\n"
        f"  software({', '.join(sw_cols)})  -- software_string is a free-text "
        "product+version string, e.g. \"openssl-1.1.1k-7.el8\"\n"
        f"  assets({', '.join(asset_cols)})\n"
        f"  vulns({', '.join(vuln_cols)})\n"
        "JOIN KEYS (primary keys): software.asset_uuid = assets.uuid ; "
        "software.asset_uuid = vulns.asset_uuid ; vulns.asset_uuid = assets.uuid.\n"
        "Always start FROM software and LEFT JOIN assets/vulns only when the question "
        "needs them. When joining vulns (one row per finding) use DISTINCT or GROUP BY "
        "to avoid duplicating software rows.\n"
        "Return ONLY the SQL — no prose, no markdown fence. Always include a LIMIT "
        "(<=500). NEVER write/UPDATE/DELETE/DROP/ALTER/CREATE/ATTACH/PRAGMA.\n"
        "Notes: match products with software.software_string LIKE '%name%'; "
        "cves looks like \"['CVE-2023-...']\" "
        "(match LIKE '%CVE-%'); acr/aes/score are numbers stored as text (use "
        "CAST(col AS REAL)); vulns.score is the VPR; a cloud asset has a non-empty "
        "aws_id/azure_vm_id/gcp_instance_id." + (value_hint or ""))
    try:
        txt = _messages(sys, "Question: " + (prompt or ""), max_tokens=500, timeout=timeout)
        sql = (txt or "").strip()
        if sql.startswith("```"):
            sql = sql.split("```", 2)[1]
            if sql.lstrip().lower().startswith("sql"):
                sql = sql.lstrip()[3:]
        return {"ok": True, "sql": sql.strip().rstrip(";").strip(), "model": DEFAULT_MODEL}
    except Exception as e:
        return {"ok": False, "fallback": True, "message": f"LLM call failed ({e})"}


def interpret(prompt: str, tags: list[dict], timeout: int = 40) -> dict:
    """Return {"ok":True,"changes":[...]} or {"ok":False,"fallback":True,...}."""
    key = os.environ.get("ANTHROPIC_API_KEY")
    if not key:
        return {"ok": False, "fallback": True,
                "message": "no ANTHROPIC_API_KEY set — using the deterministic rule parser"}
    tag_lines = "\n".join(f"- {t['category']} : {t['value']}" for t in tags)
    try:
        text = _messages(SYSTEM, f"Instruction:\n{prompt}\n\nTags:\n{tag_lines}",
                         max_tokens=1500, timeout=timeout)
        data = _extract_json(text)
        return {"ok": True, "changes": data.get("changes", []),
                "model": DEFAULT_MODEL}
    except Exception as e:
        return {"ok": False, "fallback": True,
                "message": f"LLM call failed ({e}) — using the deterministic parser"}
