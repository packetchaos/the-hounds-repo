"""Flask launcher — serves the hub, the registry, and every discovered agent.

Run:  python3 app_flask.py
Identical behavior to app_fastapi.py (both call core.launcher).
"""
import os

from flask import Flask, abort, jsonify, make_response, redirect, request, send_from_directory

from core import security
security.harden_process()                 # umask 077 before anything creates a file

from core import launcher  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
WEB = os.path.join(HERE, "web")
AGENTS = os.path.join(HERE, "agents")

# static_folder=None disables Flask's built-in /static route (which points at a
# nonexistent navi-agents/static/ and would shadow our /static → web/assets route,
# 404-ing console.css / console.js). Our explicit /static handler below serves them.
app = Flask(__name__, static_folder=None)
app.config["MAX_CONTENT_LENGTH"] = security.MAX_BODY      # → 413


@app.before_request
def _gate():
    """Host allowlist + access token + POST guard on EVERY request (core.security)."""
    if request.method == "GET" and security.host_ok(request.headers.get("Host")):
        ex = security.token_exchange(request.path, request.query_string.decode("latin-1"))
        if ex:
            code, hdrs = ex
            if code == 403:
                return jsonify({"ok": False, "error": "invalid access token"}), 403
            resp = make_response("", code)
            for k, v in hdrs.items():
                resp.headers[k] = v
            return resp
    if request.content_length is not None and request.content_length > security.MAX_BODY:
        return jsonify({"ok": False, "error": "request body too large"}), 413
    bad = security.check(request.method, request.path, request.headers.get, request.remote_addr)
    if bad:
        return jsonify({"ok": False, "error": bad[1]}), bad[0]
    return None


def _static(base, p):
    if not security.static_allowed(p):
        abort(404)
    return send_from_directory(base, p)


def _resp(payload_status):
    payload, status = payload_status
    return jsonify(payload), status


@app.get("/api/health")
def health():
    return jsonify(launcher.health())


@app.get("/api/registry")
def registry():
    return jsonify(launcher.registry())


@app.get("/api/jobs")
def jobs():
    return jsonify(launcher.jobs_list())


@app.get("/api/jobs/<int:job_id>")
def job_get(job_id):
    return jsonify(launcher.jobs_get(job_id))


@app.post("/api/jobs/clear")
def jobs_clear():
    return jsonify(launcher.jobs_clear())


@app.get("/api/profile")
def profile():
    return jsonify(launcher.profile())


@app.post("/api/profile/clear")
def profile_clear():
    return jsonify(launcher.profile_clear())


@app.post("/api/<agent_id>/<action>")
def act(agent_id, action):
    payload = request.get_json(force=True, silent=True) or {}
    return _resp(launcher.dispatch(agent_id, action, payload, peer=request.remote_addr, http=True))


@app.get("/")
def index():
    return send_from_directory(WEB, "index.html")


@app.get("/static/<path:p>")
def static_assets(p):
    return _static(os.path.join(WEB, "assets"), p)


@app.get("/web/<path:p>")
def web_files(p):
    return _static(WEB, p)


@app.get("/agents/<path:p>")
def agent_files(p):
    return _static(AGENTS, p)


@app.after_request
def _no_stale_assets(resp):
    # always revalidate — an updated console.js / page must never be shadowed by a stale copy
    resp.headers["Cache-Control"] = "no-cache"
    for k, v in security.SECURITY_HEADERS.items():
        resp.headers[k] = v
    return resp


if __name__ == "__main__":
    from werkzeug.serving import WSGIRequestHandler

    class _Timeout(WSGIRequestHandler):
        timeout = security.SOCKET_TIMEOUT

    _port = int(os.environ.get("PORT", "8001"))
    _warn = security.startup_warning()
    if _warn:
        print(_warn)
    print("  The Hounds (Flask) →  " + security.startup_url(_port))
    app.run(host=security.bind_host(), port=_port, request_handler=_Timeout)
