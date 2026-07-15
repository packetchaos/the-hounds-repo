"""Flask launcher — serves the hub, the registry, and every discovered agent.

Run:  python3 app_flask.py
Identical behavior to app_fastapi.py (both call core.launcher).
"""
import mimetypes
import os

from flask import Flask, jsonify, request, send_from_directory

from core import launcher

# Windows fix: Flask/Werkzeug derive a static file's Content-Type from Python's
# `mimetypes`, which on Windows reads the registry — where .js/.css are frequently
# mis-registered (e.g. .js as text/plain). A stylesheet or script served with the
# wrong MIME type is rejected by the browser, so the hub loads UNSTYLED. Pin the
# correct types at import so behaviour matches macOS/Linux regardless of the
# registry. (app_stdlib.py uses its own MIME table and was never affected.)
for _ext, _type in ((".css", "text/css"), (".js", "application/javascript"),
                    (".mjs", "application/javascript"), (".json", "application/json"),
                    (".svg", "image/svg+xml"), (".woff2", "font/woff2"),
                    (".woff", "font/woff")):
    mimetypes.add_type(_type, _ext)

HERE = os.path.dirname(os.path.abspath(__file__))
WEB = os.path.join(HERE, "web")
AGENTS = os.path.join(HERE, "agents")

# static_folder=None DISABLES Flask's built-in /static endpoint. Flask otherwise
# auto-registers /static/<path:filename> pointing at a "static/" folder next to this
# module (which doesn't exist here); that built-in rule is registered FIRST and wins,
# so our own /static/<path:p> route below never fires and every /static/console.css
# and /static/console.js returns 404 → the hub loads completely UNSTYLED. Disabling
# the built-in lets our route serve web/assets/*. (macOS runs FastAPI, so it never hit
# this; Windows has no uvicorn and falls back to Flask, which is where it showed up.)
app = Flask(__name__, static_folder=None)


def _resp(payload_status):
    payload, status = payload_status
    return jsonify(payload), status


@app.get("/api/health")
def health():
    return jsonify(launcher.health())


@app.get("/api/registry")
def registry():
    return jsonify(launcher.registry())


@app.post("/api/<agent_id>/<action>")
def act(agent_id, action):
    payload = request.get_json(force=True, silent=True) or {}
    return _resp(launcher.dispatch(agent_id, action, payload))


@app.get("/")
def index():
    return send_from_directory(WEB, "index.html")


@app.get("/static/<path:p>")
def static_assets(p):
    return send_from_directory(os.path.join(WEB, "assets"), p)


@app.get("/web/<path:p>")
def web_files(p):
    return send_from_directory(WEB, p)


@app.get("/agents/<path:p>")
def agent_files(p):
    return send_from_directory(AGENTS, p)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "8001")))
