"""Config store — persists Settings-page values (AI model, keys, gates, paths).

Two modes, picked on the Settings page:

  file       Values are saved to ``hounds.config.json`` (repo root, chmod 600,
             git-ignored) and re-applied every time the server or MCP starts.
  ephemeral  Values live only in this server process. Nothing is written to disk;
             a restart forgets them. Switching to ephemeral DELETES any saved
             config so no keys are left behind — only a tiny marker
             ``{"mode": "ephemeral"}`` remains so the choice survives a restart.

``HOUNDS_CONFIG`` overrides the location (an absolute path), or set it to ``off``
to disable the store entirely (never read, never written — env/.env only).

Precedence at startup (highest first):
  shell env  >  hounds.config.json  >  .env  >  run.py defaults
A value exported in the shell always wins; the Settings page shows each field's
source so you can see when that happens. run.py records which keys came from
.env in ``HOUNDS_DOTENV_KEYS`` so the config file can override them.

Secrets are stored in plain text (file mode 0600) — same exposure as a .env.
Use ephemeral mode, or the shell / a secrets manager, if that's not acceptable.
"""
import json
import os
import threading
import time

_HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_LOCK = threading.Lock()

# keys the store is allowed to manage — mirrors the Settings page fields
MANAGED = (
    "NAVI_LLM_PROVIDER", "NAVI_LLM_MODEL", "NAVI_LLM_BASE_URL", "NAVI_LLM_API_KEY",
    "NAVI_LLM_MAX_TOKENS", "AWS_REGION", "ANTHROPIC_API_KEY", "ANTHROPIC_MODEL",
    "NAVI_ALLOW_WRITES", "NAVI_EMAIL", "NAVI_REMOTE_CODE_EXECUTION", "NAVI_ALERT_EMAIL",
    "NAVI_BIN", "NAVI_DB_PATH", "NAVI_CWD", "NAVI_AUTO_APPROVE_DOWNLOADS",
    "NAVI_TAG_TEST_RUN", "NAVI_TAG_PREFIX",
)

_STATE = {"booted": False, "mode": "file", "sources": {}, "saved_at": None,
          "error": None, "session": set(), "shell": set()}


def _setting():
    return (os.environ.get("HOUNDS_CONFIG") or "").strip()


def disabled() -> bool:
    return _setting().lower() in ("off", "0", "false", "no", "none", "disabled")


def path() -> str:
    s = _setting()
    if s and not disabled():
        return os.path.abspath(os.path.expanduser(s))
    return os.path.join(_HERE, "hounds.config.json")


def _read():
    p = path()
    if not os.path.exists(p):
        return None
    with open(p, encoding="utf-8") as f:
        return json.load(f)


def _write(doc):
    p = path()
    tmp = p + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=2, sort_keys=True)
        f.write("\n")
    os.replace(tmp, p)
    try:
        os.chmod(p, 0o600)
    except OSError:
        pass


def bootstrap():
    """Apply the saved config to os.environ. Idempotent; runs on first `core` import."""
    with _LOCK:
        if _STATE["booted"]:
            return
        _STATE["booted"] = True
        dotenv = {k for k in (os.environ.get("HOUNDS_DOTENV_KEYS") or "").split(",") if k}
        defaults = {k for k in (os.environ.get("HOUNDS_DEFAULT_KEYS") or "").split(",") if k}
        src = {}
        for k in MANAGED:
            if k in os.environ:
                src[k] = ".env" if k in dotenv else ("default" if k in defaults else "shell")
        _STATE["shell"] = {k for k, v in src.items() if v == "shell"}
        if disabled():
            _STATE["mode"] = "disabled"
            _STATE["sources"] = src
            return
        try:
            doc = _read()
        except Exception as e:                       # unreadable file: say so, don't crash
            _STATE["error"] = f"could not read {path()}: {e}"
            doc = None
        if doc is None:
            _STATE["mode"] = "file"                  # default: Save creates the file
        elif (doc.get("mode") or "file") == "ephemeral":
            _STATE["mode"] = "ephemeral"
        else:
            _STATE["mode"] = "file"
            _STATE["saved_at"] = doc.get("saved_at")
            for k, v in (doc.get("env") or {}).items():
                if k not in MANAGED or v in (None, ""):
                    continue
                if src.get(k) == "shell":
                    continue                         # an exported shell value always wins
                os.environ[k] = str(v)
                src[k] = "config"
        _STATE["sources"] = src


def mode() -> str:
    bootstrap()
    return _STATE["mode"]


def source(key):
    return _STATE["sources"].get(key) or ("session" if key in _STATE["session"] else "")


def note_set(keys):
    """Called after the Settings page applies values: mark them, then persist if in file mode."""
    bootstrap()
    for k in keys:
        if k not in MANAGED:
            continue
        if os.environ.get(k):
            _STATE["session"].add(k)
            _STATE["sources"][k] = "config" if _STATE["mode"] == "file" else "session"
        else:
            _STATE["sources"].pop(k, None)
            _STATE["session"].discard(k)
    if _STATE["mode"] == "file":
        save()


def _snapshot():
    """Values to persist: what was set on the Settings page or loaded from the file —
    never shell exports, .env lines or run.py defaults the user hasn't touched."""
    return {k: os.environ[k] for k in MANAGED
            if os.environ.get(k) and _STATE["sources"].get(k) not in ("shell", "default", ".env")}


def save():
    with _LOCK:
        doc = {"version": 1, "mode": "file",
               "saved_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
               "env": _snapshot()}
        _write(doc)
        _STATE["saved_at"] = doc["saved_at"]
        _STATE["error"] = None
        for k in doc["env"]:
            _STATE["sources"][k] = "config"


def set_mode(new):
    """Switch between 'file' and 'ephemeral'. Returns (ok, message)."""
    bootstrap()
    if _STATE["mode"] == "disabled":
        return False, "the config store is disabled (HOUNDS_CONFIG=off) — unset it and restart to use it"
    if new not in ("file", "ephemeral"):
        return False, "mode must be 'file' or 'ephemeral'"
    if new == "file":
        _STATE["mode"] = "file"
        save()
        return True, f"saved to {path()} — re-applied on every start"
    # ephemeral: drop every saved value; keep only the choice itself
    with _LOCK:
        _write({"version": 1, "mode": "ephemeral"})
        _STATE["mode"] = "ephemeral"
        _STATE["saved_at"] = None
        for k, s in list(_STATE["sources"].items()):
            if s == "config":
                _STATE["sources"][k] = "session"
    return True, "ephemeral — saved values deleted from disk; current values stay live until restart"


def info() -> dict:
    bootstrap()
    p = path()
    return {"mode": _STATE["mode"], "path": p, "exists": os.path.exists(p),
            "saved_at": _STATE["saved_at"], "error": _STATE["error"],
            "sources": {k: source(k) for k in MANAGED if source(k)},
            "shell_keys": sorted(_STATE["shell"])}
