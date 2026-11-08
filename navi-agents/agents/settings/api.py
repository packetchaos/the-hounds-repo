"""Settings — repo-only control panel (hidden agent; mounts at /api/settings/*).

Four jobs:
  • status / set_env — read & live-set the environment variables the app uses,
                       persisted via core.config_store (file) or kept in memory (ephemeral).
  • config_mode      — switch the store between 'file' and 'ephemeral'.
  • db_checks        — is each navi.db table populated? (routes/paths/epss/…).
  • navi_start/poll  — run long `navi config update <kind>` in a live CLI window.
  • token usage      — Anthropic input/output tokens since server start (via core.llm).
  • downloads        — Auto-approve downloads switch + the registered external sources
                       (core.downloads); cheap, read by every page that downloads.
"""
import os
import urllib.parse

from core import cli_jobs, config_store, db, downloads, gates, llm, navi_cli, tagname

# Environment variables surfaced on the page. secret=True → value is masked and never
# echoed back; an empty submit for a secret means "leave unchanged" (don't wipe it).
_ENV_FIELDS = [
    # ---- reasoning layer: BRING YOUR OWN MODEL (see BYO_MODEL.md) ----
    {"key": "NAVI_LLM_PROVIDER", "label": "Model provider", "choices": list(llm.PROVIDERS),
     "help": "Where the pack's reasoning runs. anthropic = Claude API · openai = ANY "
             "/chat/completions endpoint (OpenAI, OpenRouter, vLLM, LM Studio, Groq…) · "
             "ollama = fully local, no key, nothing leaves the machine · bedrock = AWS "
             "Bedrock Converse (needs boto3). Blank = auto-detect from whichever key is set."},
    {"key": "NAVI_LLM_MODEL", "label": "Model",
     "help": "Model id for the chosen provider — e.g. claude-haiku-4-5-20251001, gpt-4o-mini, "
             "llama3.1, qwen2.5:14b, anthropic.claude-3-5-haiku-20241022-v1:0. "
             "Blank = that provider's default."},
    {"key": "NAVI_LLM_BASE_URL", "label": "Endpoint (base URL)", "guarded": True,   # prompts carry navi.db data
     "help": "Override the endpoint. openai → include the version path "
             "(e.g. http://localhost:1234/v1). ollama → http://127.0.0.1:11434. "
             "Blank = the provider's default."},
    {"key": "NAVI_LLM_API_KEY", "label": "Model API key", "secret": True,
     "help": "Key for the chosen provider (ANTHROPIC_API_KEY / OPENAI_API_KEY still work). "
             "Ollama needs none; Bedrock uses your AWS credentials."},
    {"key": "NAVI_LLM_MAX_TOKENS", "label": "Max output tokens", "num": True,
     "help": "Ceiling on reasoning output tokens for EVERY agent (default 8000). "
             "Lower it for small local models."},
    {"key": "AWS_REGION", "label": "AWS region (Bedrock)",
     "help": "Region for the Bedrock Converse API, e.g. us-east-1. Credentials come from the "
             "normal AWS chain (env, profile, SSO, instance/task role)."},
    {"key": "ANTHROPIC_API_KEY", "label": "Anthropic API key (legacy)", "secret": True,
     "help": "Still honoured when the provider is anthropic. Create at "
             "platform.claude.com/settings/keys (starts sk-ant-)."},
    {"key": "ANTHROPIC_MODEL", "label": "Anthropic model (legacy)",
     "help": "Back-compat alias for the model when provider=anthropic. NAVI_LLM_MODEL wins."},
    {"key": "NAVI_ALLOW_WRITES", "label": "Allow tag writes", "bool": True, "guarded": True,
     "help": "1 = Execute-tags / ACR writes actually run; 0 = gated (planned only)."},
    {"key": "NAVI_EMAIL", "label": "Allow email (Gabriel)", "bool": True, "guarded": True,
     "help": "1 = Gabriel can send mail — a SEPARATE opt-in on top of writes. SMTP is set out-of-band via `navi config smtp`."},
    {"key": "NAVI_REMOTE_CODE_EXECUTION", "label": "Allow remote execution (Amarok)", "bool": True,
     "guarded": True,
     "help": "1 = Amarok can run `navi action push` — remote code execution over SSH to a Linux host. "
             "The pack's HIGHEST-risk capability, a SEPARATE opt-in stacked ON TOP of writes; keep 0 "
             "unless actively remediating. SSH creds come from `navi config ssh` (see the SSH chip above)."},
    {"key": "NAVI_ALERT_EMAIL", "label": "Default alert email",
     "help": "Where Alert Raven sends alert digests when something fires. Per-alert overrides win over this default."},
    {"key": "NAVI_BIN", "label": "navi binary path", "env_only": True,
     "help": "Absolute path to the navi CLI if it isn't on PATH. Read-only here: set it in the "
             "server's environment / .env / hounds.config.json and restart (a browser-settable "
             "binary path would be remote code execution)."},
    {"key": downloads.ENV, "label": "Auto-approve downloads", "bool": True, "section": "downloads",
     "help": "1 = hounds that fetch an external, read-only data source (see External downloads) "
             "skip the human-approval card and download straight away, showing the source URL; "
             "0 = ask every time (default). Offline they still fall back to the bundled snapshot."},
    {"key": tagname.ENV_ON, "label": "Test run — prefix every tag the Hounds create", "bool": True,
     "section": "testrun",
     "help": "1 = every tag CATEGORY a Hound writes gets the prefix phrase + '-' "
             "(Lifecycle : EOL → Hounds-Lifecycle : EOL) so a trial run is easy to spot and to "
             "clean up in Tag Removal; 0 = normal names (default). Removals and ACR on a "
             "category you type are always exact."},
    {"key": tagname.ENV_PHRASE, "label": "Prefix phrase", "section": "testrun",
     "help": "Default Hounds. 1–24 letters, digits, spaces or _; the '-' separator is added "
             "for you. Reads recognise both the plain and the prefixed name."},
    {"key": "NAVI_DB_PATH", "label": "navi.db path", "guarded": True,
     "help": "Absolute path to navi's database (must be an existing SQLite file). Blank = the "
             "bundled sample. Changing it needs a local (loopback) browser and a confirmation."},
    {"key": "NAVI_CWD", "label": "navi working dir", "env_only": True,
     "help": "Directory navi runs in (holds navi.db). Blank = auto-detected next to the db. "
             "Read-only here: set it in the environment / hounds.config.json and restart."},
]

# navi.db tables the user can verify + refresh. `update` is the canonical key in
# core.cli_jobs.COMMANDS (which knows the exact navi verb — not all are `config update`).
_DB_TABLES = [
    {"name": "Assets", "table": "assets", "update": "assets",
     "help": "Core asset inventory. navi config update assets"},
    {"name": "Tags", "table": "tags", "update": "tags",
     "help": "Asset tags. Refreshed by the assets sync — navi config update assets."},
    {"name": "Vulns", "table": "vulns", "update": "vulns",
     "help": "Findings — the core table most hounds read. navi config update vulns"},
    {"name": "Plugins", "table": "plugins", "update": "plugins",
     "help": "Plugin metadata. navi config update plugins --size 10000"},
    {"name": "Agents", "table": "agents", "update": "agents",
     "help": "Nessus agent inventory. navi config update agents"},
    {"name": "Certificates", "table": "certs", "update": "certificates",
     "help": "Cert inventory (Certania/Heimdall). Built via navi config certificates."},
    {"name": "Software", "table": "software", "update": "software",
     "help": "Software inventory (Mimir). Built via navi config software (credentialed scans)."},
    {"name": "Compliance", "table": "compliance", "update": "compliance",
     "help": "Compliance / audit results. navi config update compliance"},
    {"name": "Fixed (SLA)", "table": "fixed", "update": "fixed",
     "help": "Remediation history + SLA clock (Sköll). navi config update fixed, then Recalculate SLA below."},
    {"name": "EPSS", "table": "epss", "update": "epss",
     "help": "EPSS exploit-probability scores. Built via navi config epss."},
    {"name": "Routes", "table": "vuln_route", "update": "routes",
     "help": "Exposure routes (Atlas/Cavall). Not part of a normal full sync. navi config update route"},
    {"name": "Paths", "table": "vuln_paths", "update": "paths",
     "help": "Filesystem paths (Atlas/Cavall). Not part of a normal full sync. navi config update paths"},
    {"name": "Web Apps", "table": "apps", "update": "was",
     "help": "Tenable WAS web-app configs (needs a WAS license). navi config update was"},
]


def _mask(v):
    # never echo any part of a secret — not even a prefix/suffix hint
    return "set" if v else ""


# Keys that are sent to the model endpoint — cleared when the endpoint/provider changes
# over HTTP unless a new key arrives in the same request (else a changed base URL would
# ship the stored key to whoever runs that URL).
_LLM_KEYS = ("NAVI_LLM_API_KEY", "ANTHROPIC_API_KEY", "OPENAI_API_KEY")
_LLM_ENDPOINT = ("NAVI_LLM_BASE_URL", "NAVI_LLM_PROVIDER")
_ENABLE_VALUES = ("1", "true", "yes", "on")


def _display(key, raw):
    """What the page may see for a non-secret field (no credentials embedded in URLs)."""
    if key == "NAVI_LLM_BASE_URL":
        return llm.display_url(raw)
    return raw


def _sqlite_ok(path):
    """(ok, reason): an existing, readable SQLite database file."""
    if not os.path.isabs(path):
        return False, "must be an absolute path"
    if not os.path.isfile(path):
        return False, "no such file"
    try:
        with open(path, "rb") as fh:
            head = fh.read(16)
    except OSError as e:
        return False, f"not readable ({e.strerror or e})"
    if head != b"SQLite format 3\x00":
        return False, "not a SQLite database"
    return True, ""


def _env_view():
    out = []
    for f in _ENV_FIELDS:
        raw = _display(f["key"], os.environ.get(f["key"], ""))
        out.append({**f, "set": bool(raw), "source": config_store.source(f["key"]),
                    "value": ("" if f.get("secret") else raw),
                    "masked": (_mask(raw) if f.get("secret") else raw)})
    return out


def status(p):
    return {"ok": True,
            "env": _env_view(),
            "writes_enabled": navi_cli.writes_enabled(),
            "email_enabled": navi_cli.email_enabled(),
            "email_gate_reason": navi_cli.email_gate_reason(),
            "rce_enabled": navi_cli.rce_enabled(),
            "rce_gate_reason": navi_cli.rce_gate_reason(),
            "ssh": db.ssh_status(),
            "navi_available": navi_cli.navi_available(),
            "navi_path": (navi_cli._resolve_navi() or ""),
            "navi_cwd": (cli_jobs._run_cwd() or ""),
            "write_gate_reason": navi_cli.write_gate_reason(),
            "db_path": db.db_path(),
            "llm": dict(llm.config(), why=("" if llm.available() else llm.why_unavailable())),
            "usage": llm.usage(),
            "downloads": downloads.status(),
            "tag_prefix": tagname.status(),
            "config": config_store.info()}, 200


def config_mode(p):
    ok, msg = config_store.set_mode((p.get("mode") or "").strip().lower())
    body, _ = status(p)
    body["ok"], body["message"] = ok, msg
    if not ok:
        body["error"] = msg
    return body, 200


def set_env(p):
    """Apply Settings-page values. Security rules (core.gates / SECURITY in README):
      • env_only fields (NAVI_BIN, NAVI_CWD) are never accepted over HTTP — a browser-set
        binary path / working dir is code execution;
      • guarded fields (the write / email / remote-exec gates, NAVI_DB_PATH) may be ENABLED or
        changed only by a loopback caller with confirm === true (turning a gate OFF is always
        allowed); NAVI_DB_PATH must name an existing SQLite file;
      • changing the model endpoint or provider clears every stored model key that wasn't
        re-entered in the same request; the base URL must be http(s)."""
    changes = p.get("env") or {}
    if not isinstance(changes, dict):
        return {"ok": False, "error": "env must be an object"}, 400
    keys = {f["key"]: f for f in _ENV_FIELDS}
    applied, rejected, invalid, refused = [], [], {}, {}
    local = gates.client_is_loopback()
    ok_confirm = gates.confirmed(p)
    for k, v in changes.items():
        f = keys.get(k)
        if not f:
            continue
        v = "" if v is None else str(v).strip()
        cur_raw = os.environ.get(k) or ""
        if not f.get("secret") and v == _display(k, cur_raw) and v != cur_raw:
            continue                       # the page echoed the sanitised display value back — unchanged
        if f.get("env_only"):
            if v != cur_raw:
                refused[k] = (f"{k} can't be changed from the browser — set {k} in the server's "
                              "environment / .env / hounds.config.json and restart.")
            continue
        if f.get("guarded") and v != cur_raw:
            lowering = bool(f.get("bool")) and v.lower() not in _ENABLE_VALUES
            if not lowering:
                if not local:
                    refused[k] = (f"{k} can only be changed from this machine (a loopback browser) — "
                                  "or set it in the environment / hounds.config.json and restart.")
                    continue
                if not ok_confirm:
                    refused[k] = f"{k} needs an explicit confirmation (confirm: true) to change."
                    continue
                if k == "NAVI_DB_PATH" and v:
                    good, why = _sqlite_ok(v)
                    if not good:
                        invalid[k] = f"NAVI_DB_PATH {why}: {v}"
                        continue
        if k == "NAVI_ALERT_EMAIL" and v:
            norm, err = navi_cli.clean_recipients(v)
            if err:
                invalid[k] = f"Alert email: {err}."
                continue
            v = norm
        if k == "NAVI_LLM_BASE_URL" and v:
            u = urllib.parse.urlparse(v)
            if u.scheme not in ("http", "https") or not u.netloc:
                invalid[k] = "Endpoint must be an http:// or https:// URL."
                continue
        if k == tagname.ENV_PHRASE and v:
            ok_, ph, err = tagname.normalize_phrase(v)   # strips a typed trailing '-'
            if not ok_:
                invalid[k] = err
                continue
            v = "" if ph == tagname.DEFAULT_PHRASE else ph   # default = unset
        if f.get("secret") and v == "":
            continue                       # empty secret = leave unchanged
        if not f.get("secret") and v and llm.looks_like_secret(v):
            rejected.append(k)             # an API key pasted into a model/path field — never store it there
            continue
        cur = os.environ.get(k) or ""
        if v == cur or (f.get("bool") and not cur and v in ("0", "false", "no")):
            continue                       # unchanged (an unset gate already means 0) — don't persist it
        if v == "":
            os.environ.pop(k, None)
        else:
            os.environ[k] = v
        # keep the import-bound llm constants live (they're read at module import)
        if k == "NAVI_LLM_PROVIDER":
            llm.set_provider(v)
        elif k in ("NAVI_LLM_MODEL", "ANTHROPIC_MODEL"):
            llm.set_model(None)            # re-resolve from env (handles set, cleared and back-compat alias)
        elif k in ("NAVI_LLM_MAX_TOKENS", "ANTHROPIC_MAX_TOKENS"):
            llm.set_max_tokens(v)
        applied.append(k)
    # A changed endpoint/provider must not inherit a key typed for the old one.
    cleared = []
    if any(k in applied for k in _LLM_ENDPOINT):
        supplied = {k for k in _LLM_KEYS if str(changes.get(k) or "").strip()}
        for k in _LLM_KEYS:
            if k not in supplied and os.environ.get(k):
                os.environ.pop(k, None)
                cleared.append(k)
        applied.extend(cleared)
    # provider/model/endpoint interact — re-resolve once after the whole batch so the
    # order fields arrive in can't leave the layer half-switched.
    if any(k.startswith("NAVI_LLM_") or k in ("ANTHROPIC_MODEL", "AWS_REGION") for k in applied):
        llm.set_provider(os.environ.get("NAVI_LLM_PROVIDER") or "")
    store_err = None
    if applied:
        try:
            config_store.note_set(applied)      # file mode → written to hounds.config.json
        except Exception as e:
            store_err = f"applied live, but could not write the config file: {e}"
    if applied:
        # /api/health is cached (30s) — drop it so the header chips reflect the change
        # immediately instead of lagging behind the Settings page.
        try:
            from core import health as _health
            _health.invalidate()
        except Exception:
            pass
    body, _ = status(p)
    body["applied"] = applied
    if rejected:
        body["rejected"] = rejected
        body["warning"] = ("Not saved: " + ", ".join(rejected) + " — that value looks like an API key. "
                           "Put keys in the API key field; the model box takes a model id (e.g. claude-haiku-4-5-20251001).")
    if invalid:
        body["invalid"] = invalid
        body["warning"] = ((body.get("warning") + " ") if body.get("warning") else "") + \
            "Not saved: " + " ".join(invalid.values())
    if refused:
        body["refused"] = refused
        body["needs_confirm"] = [k for k, why in refused.items() if "confirm" in why]
        body["warning"] = ((body.get("warning") + " ") if body.get("warning") else "") + \
            "Not saved: " + " ".join(refused.values())
    if cleared:
        body["cleared_keys"] = cleared
        body["warning"] = ((body.get("warning") + " ") if body.get("warning") else "") + \
            ("The model endpoint/provider changed, so the stored model key(s) were cleared ("
             + ", ".join(cleared) + ") — re-enter the key for the new endpoint.")
    body["persisted"] = bool(applied) and config_store.mode() == "file" and not store_err
    if store_err:
        body["store_error"] = store_err
    return body, 200


def db_checks(p):
    rows = []
    for t in _DB_TABLES:
        exists, n = False, 0
        try:
            exists = bool(db.scalar(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
                (t["table"],), budget=0))
            if exists:
                n = int(db.scalar('SELECT count(*) FROM "%s"' % t["table"], budget=0) or 0)
        except Exception:
            pass
        rows.append({**t, "exists": exists, "rows": n, "populated": bool(exists and n > 0)})
    return {"ok": True, "tables": rows, "db_path": db.db_path()}, 200


def navi_start(p):
    r = cli_jobs.start_optimize() if p.get("optimize") else cli_jobs.start_update(p.get("kind"))
    return (r, 200) if r.get("ok") else (r, 400)


def navi_poll(p):
    return cli_jobs.poll(p.get("job_id"), p.get("since", 0)), 200


def navi_jobs(p):
    return {"ok": True, "jobs": cli_jobs.recent()}, 200


def reset_usage(p):
    llm.reset_usage()
    return {"ok": True, "usage": llm.usage()}, 200


def sla_get(p):
    """Current per-severity SLA day-thresholds + fixed-table readiness (drives Sköll)."""
    from core import sla as _sla
    return {"ok": True, "thresholds": _sla.thresholds(), "fixed": _sla.fixed_status(),
            "db_path": db.db_path()}, 200


def sla_set(p):
    """Overwrite the SLA thresholds via navi's own `config sla reset` (non-interactive
    flags). Not tenant-write-gated — it's a local navi.db config write."""
    from core import sla as _sla
    r = dict(navi_cli.set_sla(p.get("critical"), p.get("high"), p.get("medium"), p.get("low")))
    r["thresholds"] = _sla.thresholds()          # echo back what navi.db now holds
    r["fixed"] = _sla.fixed_status()
    if not r.get("ok") and not r.get("error"):
        r["error"] = "navi config sla reset did not complete — check the navi binary / cwd"
    return r, 200


def downloads_status(p):
    """Cheap, live: is Settings → Auto-approve downloads ON, and the registered sources.
    Pass id to also get that one source (what downloadsAutoApproved('<id>') reads)."""
    return downloads.status((p or {}).get("id") or None), 200


ACTIONS = {"status": status, "downloads": downloads_status, "set_env": set_env, "config_mode": config_mode, "db_checks": db_checks,
           "navi_start": navi_start, "navi_poll": navi_poll, "navi_jobs": navi_jobs,
           "reset_usage": reset_usage, "sla_get": sla_get, "sla_set": sla_set}
