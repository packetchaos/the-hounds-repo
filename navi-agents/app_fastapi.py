"""FastAPI launcher — serves the hub, the registry, and every discovered agent.

Run:  python3 app_fastapi.py        (or: uvicorn app_fastapi:app --port 8000)
Drop a folder into agents/ and restart to add an agent.
"""
import os

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles

from core import launcher

HERE = os.path.dirname(os.path.abspath(__file__))
WEB = os.path.join(HERE, "web")
AGENTS = os.path.join(HERE, "agents")

app = FastAPI(title="Navi Agents", version="2.0.0")


def _resp(payload_status):
    payload, status = payload_status
    return JSONResponse(payload, status_code=status)


@app.get("/api/health")
def health():
    return launcher.health()


@app.get("/api/registry")
def registry():
    return launcher.registry()


@app.post("/api/{agent_id}/{action}")
async def act(agent_id: str, action: str, request: Request):
    try:
        payload = await request.json()
    except Exception:
        payload = {}
    return _resp(launcher.dispatch(agent_id, action, payload))


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
    uvicorn.run("app_fastapi:app", host="0.0.0.0",
                port=int(os.environ.get("PORT", "8000")), reload=False)
