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
os.environ.setdefault("NAVI_DB_PATH", os.path.join(HERE, "sample_navi.db"))
os.environ.setdefault("NAVI_ALLOW_WRITES", "0")


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


if not os.path.exists(os.environ["NAVI_DB_PATH"]) and os.path.exists("make_sample_db.py"):
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
