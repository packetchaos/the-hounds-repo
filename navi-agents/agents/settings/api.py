"""Settings — repo-only control panel (hidden agent; mounts at /api/settings/*).

Four jobs:
  • status / set_env — read & live-set the environment variables the app uses.
  • db_checks        — is each navi.db table populated? (routes/paths/epss/…).
  • navi_start/poll  — run long `navi config update <kind>` in a live CLI window.
  • token usage      — Anthropic input/output tokens since server start (via core.llm).
"""
import os

from core import cli_jobs, db, llm, navi_cli

# Environment variables surfaced on the page. secret=True → value is masked and never
# echoed back; an empty submit for a secret means "leave unchanged" (don't wipe it).
_ENV_FIELDS = [
    {"key": "ANTHROPIC_API_KEY", "label": "Anthropic API key", "secret": True,
     "help": "Enables the editable-prompt AI on each agent. Create at console.anthropic.com (starts sk-ant-)."},
    {"key": "ANTHROPIC_MODEL", "label": "Anthropic model",
     "help": "Blank = claude-haiku-4-5-20251001. Set if that model isn't on your key (e.g. claude-3-5-haiku-latest)."},
    {"key": "ANTHROPIC_MAX_TOKENS", "label": "Max output tokens", "num": True,
     "help": "Ceiling on reasoning output tokens (default 8000). Lower it for older models."},
    {"key": "NAVI_ALLOW_WRITES", "label": "Allow tag writes", "bool": True,
     "help": "1 = Execute-tags / ACR writes actually run; 0 = gated (planned only)."},
    {"key": "NAVI_EMAIL", "label": "Allow email (Gabriel)", "bool": True,
     "help": "1 = Gabriel can send mail — a SEPARATE opt-in on top of writes. SMTP is set out-of-band via `navi config smtp`."},
    {"key": "NAVI_REMOTE_CODE_EXECUTION", "label": "Allow remote execution (Amarok)", "bool": True,
     "help": "1 = Amarok can run `navi action push` — remote code execution over SSH to a Linux host. "
             "The pack's HIGHEST-risk capability, a SEPARATE opt-in stacked ON TOP of writes; keep 0 "
             "unless actively remediating. SSH creds come from `navi config ssh` (see the SSH chip above)."},
    {"key": "NAVI_ALERT_EMAIL", "label": "Default alert email",
     "help": "Where Alert Raven sends alert digests when something fires. Per-alert overrides win over this default."},
    {"key": "NAVI_BIN", "label": "navi binary path",
     "help": "Absolute path to the navi CLI if it isn't on PATH."},
    {"key": "NAVI_DB_PATH", "label": "navi.db path",
     "help": "Absolute path to navi's database. Blank = the bundled sample."},
    {"key": "NAVI_CWD", "label": "navi working dir",
     "help": "Directory navi runs in (holds navi.db). Blank = auto-detected next to the db."},
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
    if not v:
        return ""
    return (v[:6] + "…" + v[-4:]) if len(v) > 12 else "set"


def _env_view():
    out = []
    for f in _ENV_FIELDS:
        raw = os.environ.get(f["key"], "")
        out.append({**f, "set": bool(raw),
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
            "llm": {"available": llm.available(), "model": llm.DEFAULT_MODEL,
                    "max_tokens": llm.MAX_TOKENS_CAP},
            "usage": llm.usage()}, 200


def set_env(p):
    changes = p.get("env") or {}
    keys = {f["key"]: f for f in _ENV_FIELDS}
    applied = []
    for k, v in changes.items():
        f = keys.get(k)
        if not f:
            continue
        v = "" if v is None else str(v).strip()
        if f.get("secret") and v == "":
            continue                       # empty secret = leave unchanged
        if v == "":
            os.environ.pop(k, None)
        else:
            os.environ[k] = v
        if k == "ANTHROPIC_MODEL":         # keep import-bound llm constants live
            llm.set_model(v)
        elif k == "ANTHROPIC_MAX_TOKENS":
            llm.set_max_tokens(v)
        applied.append(k)
    body, _ = status(p)
    body["applied"] = applied
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


ACTIONS = {"status": status, "set_env": set_env, "db_checks": db_checks,
           "navi_start": navi_start, "navi_poll": navi_poll, "navi_jobs": navi_jobs,
           "reset_usage": reset_usage, "sla_get": sla_get, "sla_set": sla_set}
