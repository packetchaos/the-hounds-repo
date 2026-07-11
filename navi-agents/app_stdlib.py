"""Zero-dependency launcher — uses only the Python standard library.

Serves the hub, /api/health, /api/registry, the generic POST /api/<id>/<action>
dispatch, and static files (web assets, agent pages, READMEs). No FastAPI/Flask
required, so `python3 app_stdlib.py` (or `python3 run.py`) works on a stock
Python install. For production you can still use app_fastapi.py / app_flask.py.
"""
import json
import os
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from core import launcher

HERE = os.path.dirname(os.path.abspath(__file__))
WEB = os.path.join(HERE, "web")
ASSETS = os.path.join(WEB, "assets")
AGENTS = os.path.join(HERE, "agents")

MIME = {".html": "text/html; charset=utf-8", ".css": "text/css; charset=utf-8",
        ".js": "application/javascript; charset=utf-8", ".json": "application/json; charset=utf-8",
        ".svg": "image/svg+xml", ".md": "text/plain; charset=utf-8", ".png": "image/png",
        ".ico": "image/x-icon", ".woff2": "font/woff2", ".pdf": "application/pdf"}


def _safe_join(base, rel):
    """Resolve a URL path under `base`, refusing traversal. Windows-safe: paths are
    compared case-insensitively via normcase (Windows drive/case can differ between
    calls, which broke the old case-sensitive startswith check → 404 on /static/*)."""
    base = os.path.abspath(base)
    rel = urllib.parse.unquote(rel).replace("\\", "/").lstrip("/")
    p = os.path.abspath(os.path.join(base, *[s for s in rel.split("/") if s not in ("", ".", "..")]))
    b, pp = os.path.normcase(base), os.path.normcase(p)
    return p if (pp == b or pp.startswith(b + os.sep)) else None


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, body, ctype="application/json; charset=utf-8"):
        if isinstance(body, (dict, list)):
            body = json.dumps(body).encode()
        elif isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _file(self, path):
        if not path or not os.path.isfile(path):
            return self._send(404, {"error": "not found"})
        ctype = MIME.get(os.path.splitext(path)[1].lower(), "application/octet-stream")
        with open(path, "rb") as f:
            self._send(200, f.read(), ctype)

    def do_GET(self):
        u = urllib.parse.urlparse(self.path).path
        if u in ("/", "/index.html"):
            return self._file(os.path.join(WEB, "index.html"))
        if u == "/api/health":
            return self._send(200, launcher.health())
        if u == "/api/registry":
            return self._send(200, launcher.registry())
        if u.startswith("/static/"):
            return self._file(_safe_join(ASSETS, u[len("/static/"):]))
        if u.startswith("/web/"):
            return self._file(_safe_join(WEB, u[len("/web/"):]))
        if u.startswith("/agents/"):
            return self._file(_safe_join(AGENTS, u[len("/agents/"):]))
        self._send(404, {"error": "not found"})

    def do_POST(self):
        u = urllib.parse.urlparse(self.path).path
        parts = u.strip("/").split("/")
        if len(parts) == 3 and parts[0] == "api":
            n = int(self.headers.get("Content-Length") or 0)
            try:
                payload = json.loads(self.rfile.read(n) or b"{}")
            except Exception:
                payload = {}
            body, status = launcher.dispatch(parts[1], parts[2], payload)
            return self._send(status, body)
        self._send(404, {"error": "not found"})

    def log_message(self, *a):
        pass


def _print_write_status():
    try:
        from core import navi_cli, db
        p = db.db_path()
        src = "sample fixture" if p.endswith("sample_navi.db") else "navi.db"
        print(f"navi.db: {p}   ({src} — reads + tag-writes both use this)")
        s = navi_cli.write_status()
        if s["writes_enabled"] and s["navi_resolved"]:
            print(f"WRITES: ENABLED  ·  navi -> {s['navi_resolved']}")
        elif s["writes_enabled"]:
            print("WRITES: enabled, but navi CLI NOT FOUND — set NAVI_BIN=/path/to/navi")
        else:
            print("WRITES: DISABLED — set NAVI_ALLOW_WRITES=1 (this shell) "
                  "or `touch ALLOW_WRITES` in the repo root, then restart. "
                  "Run `python3 check_writes.py` to diagnose.")
    except Exception:
        pass


def main():
    want = int(os.environ.get("PORT", "8000"))
    # Bind the requested port; if it's taken, walk up to the next free one so a busy
    # 8000 never leaves the user staring at a dead/blank tab. All frontend links are
    # origin-relative, so any port works — you just open the URL we print below.
    srv = None
    for port in range(want, want + 25):
        try:
            srv = ThreadingHTTPServer(("0.0.0.0", port), Handler)
            break
        except OSError:
            if port == want:
                print(f"port {want} is busy — trying the next free port…")
            continue
    if srv is None:
        raise SystemExit(f"no free port between {want} and {want + 24}. "
                         f"Set PORT to a free one, e.g. PORT=8080 python3 run.py")
    port = srv.server_address[1]
    print("\n" + "=" * 60)
    print(f"  The Hounds is running.  Open this in your browser:")
    print(f"      →  http://localhost:{port}")
    print(f"  (open the URL — do NOT double-click web/index.html)")
    print("=" * 60 + "\n")
    _print_write_status()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped.")


if __name__ == "__main__":
    main()
