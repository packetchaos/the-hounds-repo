"""Flask launcher — serves the hub, the registry, and every discovered agent.

Run:  python3 app_flask.py
Identical behavior to app_fastapi.py (both call core.launcher).
"""
import os

from flask import Flask, jsonify, request, send_from_directory

from core import launcher

HERE = os.path.dirname(os.path.abspath(__file__))
WEB = os.path.join(HERE, "web")
AGENTS = os.path.join(HERE, "agents")

# static_folder=None disables Flask's built-in /static route (which points at a
# nonexistent navi-agents/static/ and would shadow our /static → web/assets route,
# 404-ing console.css / console.js). Our explicit /static handler below serves them.
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
