#!/usr/bin/env python3
"""One-command launcher — works on a stock Python install, no pip required.

    python3 run.py            # auto: uses the built-in zero-dependency server
    python3 run.py fastapi    # FastAPI (auto-installs it if missing)
    python3 run.py flask      # Flask  (auto-installs it if missing)
    python3 run.py stdlib     # force the zero-dependency server

Always run from the repo root (the folder that contains this file, agents/ and
app_*.py). Builds the bundled sample navi.db on first run; point NAVI_DB_PATH at
navi's real database for production.
"""
import importlib.util
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
os.chdir(HERE)


def load_dotenv():
    """Load KEY=VALUE lines from a .env in the repo root (no pip dependency).
    Lets you keep ANTHROPIC_API_KEY, ANTHROPIC_MODEL, NAVI_ALLOW_WRITES, NAVI_BIN,
    etc. in a file instead of exporting them in every shell. Real environment
    variables always win — a value already set in the shell is never overwritten."""
    path = os.path.join(HERE, ".env")
    if not os.path.exists(path):
        return
    loaded = []
    try:
        with open(path, encoding="utf-8") as f:
            for raw in f:
                line = raw.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                if line.lower().startswith("export "):
                    line = line[7:].lstrip()
                key, _, val = line.partition("=")
                key = key.strip()
                val = val.strip().strip('"').strip("'")
                if key and key not in os.environ:   # shell env wins
                    os.environ[key] = val
                    loaded.append(key)
        # tell core.config_store which keys came from .env (the Settings config file may
        # override those; a value exported in the shell is never overridden)
        os.environ["HOUNDS_DOTENV_KEYS"] = ",".join(loaded)
        print("loaded .env")
    except Exception as e:
        print("  could not read .env:", e)


load_dotenv()
_defaulted = [k for k in ("NAVI_DB_PATH", "NAVI_ALLOW_WRITES") if k not in os.environ]
os.environ.setdefault("NAVI_DB_PATH", os.path.join(HERE, "sample_navi.db"))
os.environ.setdefault("NAVI_ALLOW_WRITES", "0")
# defaults, like .env values, may be overridden by the Settings config file
os.environ["HOUNDS_DEFAULT_KEYS"] = ",".join(_defaulted)


def have(mod):
    return importlib.util.find_spec(mod) is not None


def pip_install(*pkgs):
    print("installing:", " ".join(pkgs), "…")
    try:
        subprocess.run([sys.executable, "-m", "pip", "install", "--quiet", *pkgs], check=True)
        return True
    except Exception as e:
        print("  pip install failed:", e)
        return False


def _fixture_needs_build(p):
    """True if the DB at p is missing, empty, or an invalid fixture (no assets table/rows)."""
    if not os.path.exists(p) or os.path.getsize(p) == 0:
        return True
    try:
        import sqlite3
        con = sqlite3.connect(p)
        try:
            n = con.execute("SELECT count(*) FROM assets").fetchone()[0]
        finally:
            con.close()
        return not n
    except Exception:
        return True


# Auto-(re)build the bundled sample when it's missing or empty (a 0-byte/partial file
# used to slip through the old exists-only check and surface as "no assets table").
# Guarded to the sample filename so a real navi.db the user points NAVI_DB_PATH at is never clobbered.
_dbp = os.environ["NAVI_DB_PATH"]
if os.path.basename(_dbp) == "sample_navi.db" and os.path.exists("make_sample_db.py") and _fixture_needs_build(_dbp):
    print("building sample dataset…")
    subprocess.run([sys.executable, "make_sample_db.py"], check=True)

which = (sys.argv[1] if len(sys.argv) > 1 else "").lower()
fast = have("fastapi") and have("uvicorn")
flsk = have("flask")

if which.startswith("fa"):
    if not fast and pip_install("fastapi", "uvicorn[standard]"):
        fast = have("fastapi") and have("uvicorn")
    app = "app_fastapi.py" if fast else "app_stdlib.py"
elif which.startswith("fl"):
    if not flsk and pip_install("flask"):
        flsk = have("flask")
    app = "app_flask.py" if flsk else "app_stdlib.py"
elif which.startswith("st"):
    app = "app_stdlib.py"
else:
    app = "app_fastapi.py" if fast else ("app_flask.py" if flsk else "app_stdlib.py")

if not os.path.exists(app):
    sys.exit(f"ERROR: {app} not found — run this from the repo root.")
if app == "app_stdlib.py":
    print("using the built-in zero-dependency server (no FastAPI/Flask needed).")
sys.exit(subprocess.call([sys.executable, app]))
