"""Keep secrets out of anything the UI can see.

The model / cloud keys live in the server environment and must never reach the
browser — not in a status chip, not inside a provider error message, not echoed in
a stack trace. ``scrub()`` walks a response and replaces:

  • the exact value of every configured secret env var, and
  • anything shaped like a provider key (``sk-…``, ``sk-ant-…``, AWS access-key ids),

with a fixed ``[redacted]`` marker. core.launcher runs it over every API response
and /api/health, so no individual agent has to remember to.
"""
import os
import re
import time

SECRET_ENV = ("NAVI_LLM_API_KEY", "ANTHROPIC_API_KEY", "OPENAI_API_KEY",
              "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_ACCESS_KEY_ID",
              "TIO_ACCESS_KEY", "TIO_SECRET_KEY")
MARK = "[redacted]"
_KEYLIKE = re.compile(r"\b(?:sk-(?:ant-)?[A-Za-z0-9_\-]{12,}|AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16})\b")


# Secret COLUMNS navi stores inside navi.db (see core.db.SECRET_TABLES). Their values are
# scrubbed too, so even a code path that read one by mistake can't echo it to the browser.
_DB_SECRET_COLS = {"keys": ("access_key", "secret_key"), "smtp": ("password",),
                   "ssh": ("password",), "resend": ("api_key",)}
_DB_CACHE = {"key": None, "at": 0.0, "vals": []}
_DB_TTL = 60.0


def _db_secrets():
    """Values of navi.db's credential columns (cached ~60 s per db file + mtime)."""
    try:
        from core import db
        p = db.db_path()
        st = os.stat(p)
    except Exception:
        return []
    key = (p, st.st_mtime_ns)
    now = time.monotonic()
    if _DB_CACHE["key"] == key and now - _DB_CACHE["at"] < _DB_TTL:
        return _DB_CACHE["vals"]
    vals = []
    try:
        con = db.connect(p)
        try:
            have = {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            for t, cols in _DB_SECRET_COLS.items():
                if t not in have:
                    continue
                tcols = {r[1] for r in con.execute(f'PRAGMA table_info("{t}")')}
                for c in cols:
                    if c in tcols:
                        for (v,) in con.execute(f'SELECT "{c}" FROM "{t}" LIMIT 50'):
                            v = str(v or "").strip()
                            if len(v) >= 8:
                                vals.append(v)
        finally:
            con.close()
    except Exception:
        vals = []
    _DB_CACHE.update(key=key, at=now, vals=vals)
    return vals


def _secrets():
    env = [v for v in (os.environ.get(k, "").strip() for k in SECRET_ENV) if len(v) >= 8]
    return env + [v for v in _db_secrets() if v not in env]


def text(s, secrets=None):
    if not isinstance(s, str) or not s:
        return s
    for v in (secrets if secrets is not None else _secrets()):
        if v in s:
            s = s.replace(v, MARK)
    if "sk-" in s or "AKIA" in s or "ASIA" in s:
        s = _KEYLIKE.sub(MARK, s)
    return s


def scrub(obj, _secrets_cache=None, _depth=0):
    """Return obj with every string scrubbed. Containers are rebuilt only if needed."""
    sec = _secrets_cache if _secrets_cache is not None else _secrets()
    if isinstance(obj, str):
        return text(obj, sec)
    if _depth > 40:
        return obj
    if isinstance(obj, dict):
        out = None
        for k, v in obj.items():
            nv = scrub(v, sec, _depth + 1)
            if nv is not v:
                if out is None:
                    out = dict(obj)
                out[k] = nv
        return obj if out is None else out
    if isinstance(obj, (list, tuple)):
        changed = False
        items = []
        for v in obj:
            nv = scrub(v, sec, _depth + 1)
            changed = changed or (nv is not v)
            items.append(nv)
        return (type(obj)(items) if isinstance(obj, tuple) else items) if changed else obj
    return obj
