"""Zero-dependency launcher — uses only the Python standard library.

Serves the hub, /api/health, /api/registry, the generic POST /api/<id>/<action>
dispatch, and static files (web assets, agent pages, READMEs). No FastAPI/Flask
required, so `python3 app_stdlib.py` (or `python3 run.py`) works on a stock
Python install. For production you can still use app_fastapi.py / app_flask.py.
"""
import json
import os
import select
import socket
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from core import security
security.harden_process()                 # umask 077 before anything creates a file

from core import launcher, db  # noqa: E402

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


class _DisconnectWatch:
    """Trip `token` (a db.Cancel) when the client closes the connection while its request is
    still running — the browser aborted the fetch, the tab navigated away or was closed.
    The server speaks HTTP/1.0 (one request per connection), so after the body is read the
    client sends nothing more: a readable socket whose MSG_PEEK returns b'' (FIN) or an
    error (RST) means it's gone. Polled every 0.2 s on a small daemon thread; the running
    SQL then stops within ~10k VM steps (db progress handler) and the action returns."""

    def __init__(self, sock, token, interval=0.2):
        self.sock, self.token, self.interval = sock, token, interval
        self.done = threading.Event()
        self.t = None

    def _loop(self):
        while not self.done.wait(self.interval):
            try:
                r, _, x = select.select([self.sock], [], [self.sock], 0)
                if x:
                    raise OSError("socket exception")
                if r and not self.sock.recv(1, socket.MSG_PEEK):
                    self.token.cancel()
                    return
            except (OSError, ValueError):
                self.token.cancel()
                return

    def __enter__(self):
        if self.sock is not None:
            self.t = threading.Thread(target=self._loop, name="hounds-disconnect-watch", daemon=True)
            self.t.start()
        return self

    def __exit__(self, *exc):
        self.done.set()
        return False


class Handler(BaseHTTPRequestHandler):
    timeout = security.SOCKET_TIMEOUT       # a stalled client can't pin a worker thread forever

    def _peer(self):
        try:
            return self.client_address[0]
        except Exception:
            return None

    def _gate(self, method):
        """Host allowlist + token + POST guard; True when the request was refused."""
        u = urllib.parse.urlparse(self.path)
        if method == "GET" and security.host_ok(self.headers.get("Host")):
            ex = security.token_exchange(u.path, u.query)
            if ex:
                code, hdrs = ex
                if code == 403:
                    self._send(403, {"ok": False, "error": "invalid access token"})
                else:
                    self._send(code, b"", "text/plain; charset=utf-8", extra=hdrs)
                return True
        bad = security.check(method, u.path, self.headers.get, self._peer())
        if bad:
            self._send(bad[0], {"ok": False, "error": bad[1]})
            return True
        return False

    def _send(self, code, body, ctype="application/json; charset=utf-8", extra=None):
        if isinstance(body, (dict, list)):
            body = json.dumps(body).encode()
        elif isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        # always revalidate — an updated console.js / page must never be shadowed by a stale copy
        self.send_header("Cache-Control", "no-cache")
        for k, v in security.SECURITY_HEADERS.items():
            self.send_header(k, v)
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _file(self, path):
        if not path or not os.path.isfile(path):
            return self._send(404, {"error": "not found"})
        ctype = MIME.get(os.path.splitext(path)[1].lower(), "application/octet-stream")
        with open(path, "rb") as f:
            self._send(200, f.read(), ctype)

    def _static(self, base, rel):
        if not security.static_allowed(rel):
            return self._send(404, {"error": "not found"})
        return self._file(_safe_join(base, rel))

    def do_GET(self):
        if self._gate("GET"):
            return
        u = urllib.parse.urlparse(self.path).path
        if u in ("/", "/index.html"):
            return self._file(os.path.join(WEB, "index.html"))
        if u == "/api/health":
            return self._send(200, launcher.health())
        if u == "/api/registry":
            return self._send(200, launcher.registry())
        if u == "/api/jobs":
            return self._send(200, launcher.jobs_list())
        if u.startswith("/api/jobs/"):
            return self._send(200, launcher.jobs_get(u[len("/api/jobs/"):]))
        if u == "/api/profile":
            return self._send(200, launcher.profile())
        if u.startswith("/static/"):
            return self._static(ASSETS, u[len("/static/"):])
        if u.startswith("/web/"):
            return self._static(WEB, u[len("/web/"):])
        if u.startswith("/agents/"):
            return self._static(AGENTS, u[len("/agents/"):])
        self._send(404, {"error": "not found"})

    def do_POST(self):
        u = urllib.parse.urlparse(self.path).path
        if self._gate("POST"):
            return
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            n = -1
        if n < 0 or n > security.MAX_BODY:
            self.close_connection = True
            return self._send(413, {"ok": False, "error": "request body too large (limit %d MB)"
                                    % (security.MAX_BODY // (1024 * 1024))})
        if (self.headers.get("Transfer-Encoding") or "").lower() == "chunked":
            self.close_connection = True
            return self._send(411, {"ok": False, "error": "Content-Length required"})
        if u == "/api/jobs/clear":
            return self._send(200, launcher.jobs_clear())
        if u == "/api/profile/clear":
            return self._send(200, launcher.profile_clear())
        parts = u.strip("/").split("/")
        if len(parts) == 3 and parts[0] == "api":
            try:
                payload = json.loads(self.rfile.read(n) or b"{}")
            except Exception:
                payload = {}
            # request budget + cancel: X-Hounds-Budget (open|run) is the page's hint, X-Hounds-Tab
            # lets a newer identical request from the same tab supersede this one, and a client
            # disconnect cancels the running SQL (core/launcher.dispatch, core/db.budget_scope)
            hint = (self.headers.get("X-Hounds-Budget") or "").strip().lower() or None
            tab = (self.headers.get("X-Hounds-Tab") or "").strip()[:64] or None
            token = db.Cancel()
            with _DisconnectWatch(self.connection, token):
                body, status = launcher.dispatch(parts[1], parts[2], payload, peer=self._peer(),
                                                 http=True, budget_hint=hint, cancel=token, tab=tab)
            try:
                if isinstance(body, (dict, list)):
                    body = json.dumps(body).encode()
                    launcher.note_response(parts[1], parts[2], len(body))   # > 2 MB → logged
                return self._send(status, body)
            except (BrokenPipeError, ConnectionResetError):
                self.close_connection = True      # the client left — nothing to answer
                return None
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
    host = security.bind_host()
    srv_cls = ThreadingHTTPServer
    if ":" in host:                                  # IPv6 bind (e.g. HOUNDS_BIND=::1)
        import socket as _s

        class _V6(ThreadingHTTPServer):
            address_family = _s.AF_INET6
        srv_cls = _V6
    for port in range(want, want + 25):
        try:
            srv = srv_cls((host, port), Handler)
            break
        except OSError:
            if port == want:
                print(f"port {want} is busy — trying the next free port…")
            continue
    if srv is None:
        raise SystemExit(f"no free port between {want} and {want + 24}. "
                         f"Set PORT to a free one, e.g. PORT=8080 python3 run.py")
    port = srv.server_address[1]
    warn = security.startup_warning()
    if warn:
        print("\n" + warn)
    print("\n" + "=" * 60)
    print(f"  The Hounds is running.  Open this in your browser:")
    print(f"      →  {security.startup_url(port)}")
    if security.token_required(None):
        print("  (the URL carries this launch's access token — it is printed only here)")
    print(f"  (open the URL — do NOT double-click web/index.html)")
    print("=" * 60 + "\n")
    _print_write_status()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped.")


if __name__ == "__main__":
    main()
