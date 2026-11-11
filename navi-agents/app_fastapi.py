"""FastAPI launcher — serves the hub, the registry, and every discovered agent.

Run:  python3 app_fastapi.py        (or: uvicorn app_fastapi:app --port 8000)
Drop a folder into agents/ and restart to add an agent.
"""
import os

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles

from core import security
security.harden_process()                 # umask 077 before anything creates a file

from core import launcher  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
WEB = os.path.join(HERE, "web")
AGENTS = os.path.join(HERE, "agents")

app = FastAPI(title="Navi Agents", version="2.0.0")


def _harden(resp):
    # always revalidate — an updated console.js / page must never be shadowed by a stale copy
    resp.headers["Cache-Control"] = "no-cache"
    for k, v in security.SECURITY_HEADERS.items():
        resp.headers[k] = v
    return resp


@app.middleware("http")
async def _gate(request: Request, call_next):
    """Host allowlist + access token + POST guard + body cap on EVERY request, and the
    security headers on every response (core.security)."""
    path = request.url.path
    hget = request.headers.get
    if request.method == "GET" and security.host_ok(hget("host")):
        ex = security.token_exchange(path, request.url.query)
        if ex:
            code, hdrs = ex
            if code == 403:
                return _harden(JSONResponse({"ok": False, "error": "invalid access token"}, status_code=403))
            r = PlainTextResponse("", status_code=code)
            for k, v in hdrs.items():
                r.headers[k] = v
            return _harden(r)
    peer = request.client.host if request.client else None
    bad = security.check(request.method, path, hget, peer)
    if bad:
        return _harden(JSONResponse({"ok": False, "error": bad[1]}, status_code=bad[0]))
    if request.method in ("GET", "HEAD") and path.startswith(("/agents/", "/static/", "/web/")):
        rel = path.split("/", 2)[2] if path.count("/") >= 2 else ""
        if not security.static_allowed(rel):
            return _harden(JSONResponse({"error": "not found"}, status_code=404))
    try:
        n = int(hget("content-length") or 0)
    except ValueError:
        n = -1
    if n < 0 or n > security.MAX_BODY:
        return _harden(JSONResponse({"ok": False, "error": "request body too large"}, status_code=413))
    return _harden(await call_next(request))


def _resp(payload_status):
    payload, status = payload_status
    return JSONResponse(payload, status_code=status)


@app.get("/api/health")
def health():
    return launcher.health()


@app.get("/api/registry")
def registry():
    return launcher.registry()


@app.get("/api/jobs")
def jobs():
    return launcher.jobs_list()


@app.get("/api/jobs/{job_id}")
def job_get(job_id: int):
    return launcher.jobs_get(job_id)


@app.post("/api/jobs/clear")
def jobs_clear():
    return launcher.jobs_clear()


@app.get("/api/profile")
def profile():
    return launcher.profile()


@app.post("/api/profile/clear")
def profile_clear():
    return launcher.profile_clear()


async def _read_capped(request: Request) -> bytes:
    """Read the body, refusing (None) anything past MAX_BODY — covers chunked uploads that
    carry no Content-Length."""
    buf = bytearray()
    async for chunk in request.stream():
        buf += chunk
        if len(buf) > security.MAX_BODY:
            return None
    return bytes(buf)


@app.post("/api/{agent_id}/{action}")
async def act(agent_id: str, action: str, request: Request):
    raw = await _read_capped(request)
    if raw is None:
        return JSONResponse({"ok": False, "error": "request body too large"}, status_code=413)
    try:
        import json as _json
        payload = _json.loads(raw or b"{}")
    except Exception:
        payload = {}
    peer = request.client.host if request.client else None
    # Run the action on the threadpool (it no longer blocks the event loop) under a request
    # budget (core/launcher.request_scope) and a cancel token tripped when the client
    # disconnects (fetch aborted / tab closed) — the running SQL stops, see core/db.
    import asyncio
    from starlette.concurrency import run_in_threadpool
    from core import db as _db
    hint = (request.headers.get("x-hounds-budget") or "").strip().lower() or None
    tab = (request.headers.get("x-hounds-tab") or "").strip()[:64] or None
    token = _db.Cancel()
    task = asyncio.ensure_future(run_in_threadpool(
        launcher.dispatch, agent_id, action, payload, peer=peer, http=True,
        budget_hint=hint, cancel=token, tab=tab))
    while not task.done():
        done, _ = await asyncio.wait({task}, timeout=0.25)
        if not done and not token.is_set():
            try:
                if await request.is_disconnected():
                    token.cancel()
            except Exception:
                pass
    resp = _resp(task.result())
    try:
        launcher.note_response(agent_id, action, len(getattr(resp, "body", b"") or b""))  # > 2 MB → logged
    except Exception:
        pass
    return resp


@app.get("/")
def index():
    return FileResponse(os.path.join(WEB, "index.html"))


# agent pages, READMEs and static files
if os.path.isdir(AGENTS):
    app.mount("/agents", StaticFiles(directory=AGENTS), name="agents")
if os.path.isdir(WEB):
    app.mount("/static", StaticFiles(directory=os.path.join(WEB, "assets")), name="static")
    app.mount("/web", StaticFiles(directory=WEB), name="web")


if __name__ == "__main__":
    import uvicorn
    _port = int(os.environ.get("PORT", "8000"))
    _warn = security.startup_warning()
    if _warn:
        print(_warn)
    print("  The Hounds (FastAPI) →  " + security.startup_url(_port))
    uvicorn.run("app_fastapi:app", host=security.bind_host(), port=_port, reload=False,
                timeout_keep_alive=int(min(security.SOCKET_TIMEOUT, 30)))
