"""HTTP security policy shared by every server (app_stdlib / app_flask / app_fastapi).

One place decides who may talk to the console, so the three servers can't drift:

  • Bind      127.0.0.1 by default. LAN / remote access is an explicit opt-in:
              HOUNDS_BIND=0.0.0.0 (or a specific address) — printed with a loud warning.
  • Host      every request (GET too) must carry a Host header naming this console:
              localhost / 127.0.0.1 / [::1] (any port) + HOUNDS_ALLOWED_HOSTS (comma list).
              When bound to a non-loopback address the bound IP and this machine's own
              hostname/IPs are added. Anything else → 403. This is what kills DNS rebinding
              (an attacker's hostname resolving to 127.0.0.1 still sends Host: evil.example).
  • Token     when the console is reachable from other hosts (non-loopback bind, or a peer
              that isn't loopback), every /api request needs the per-launch access token:
              printed ONCE in the startup URL (http://host:port/?token=…, Jupyter-style),
              exchanged on that first GET for an HttpOnly SameSite=Strict cookie, accepted
              thereafter from that cookie or an X-Hounds-Token header (scripts).
  • POST      JSON Content-Type required (a cross-site <form> can't send it without a CORS
              preflight we never answer); a present Origin must be same-origin with an
              allowlisted host; Origin "null" (sandboxed iframes, file://) is refused.
  • Headers   X-Frame-Options SAMEORIGIN / CSP frame-ancestors 'self' / nosniff / no-referrer on every response.
  • Limits    request bodies are capped (MAX_BODY → 413); sockets time out.

Nothing here logs the token; it is printed exactly once, in the startup banner.
"""
import hashlib
import hmac
import ipaddress
import os
import secrets
import socket
import urllib.parse

LOOPBACK_NAMES = {"localhost", "127.0.0.1", "::1", "localhost.localdomain"}
DEFAULT_BIND = "127.0.0.1"

# Per-launch token (regenerated on every start). Only REQUIRED when the console is reachable
# from another host; harmless otherwise. The cookie name is derived from the token so two
# consoles on one machine (different ports share cookies) never clobber each other.
TOKEN = secrets.token_urlsafe(32)
COOKIE = "hounds_" + hashlib.sha256(TOKEN.encode()).hexdigest()[:10]
TOKEN_HEADER = "X-Hounds-Token"

SECURITY_HEADERS = {
    # SAMEORIGIN, not DENY: the console frames its own pages (Exposure Routes embeds
    # /web/ownermap.html?embed=1). Other sites still can't frame it (clickjacking).
    "X-Frame-Options": "SAMEORIGIN",
    "Content-Security-Policy": "frame-ancestors 'self'",   # only this directive: pages use inline scripts
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
}

# Request body cap. The page cache accepts entries up to core.pagecache.MAX_BYTES (64 MB raw
# JSON) inside a JSON envelope, so the cap sits comfortably above it.
try:
    _PC_MAX = int(os.environ.get("NAVI_PAGECACHE_MAX_BYTES", str(64 * 1024 * 1024)))
except ValueError:
    _PC_MAX = 64 * 1024 * 1024
MAX_BODY = int(os.environ.get("HOUNDS_MAX_BODY") or max(80 * 1024 * 1024, int(_PC_MAX * 1.25)))
SOCKET_TIMEOUT = float(os.environ.get("HOUNDS_SOCKET_TIMEOUT", "120"))

# Static files the servers may hand out from agents/ and web/ — page assets only, never source.
STATIC_EXT = {".html", ".css", ".js", ".json", ".md", ".png", ".svg", ".jpg", ".jpeg", ".gif",
              ".ico", ".webp", ".woff", ".woff2", ".csv", ".pdf", ".txt"}


def harden_process():
    """Files this process creates are owner-only (navi.db extracts, caches, logs, configs)."""
    try:
        os.umask(0o077)
    except Exception:
        pass


# --------------------------------------------------------------------------- #
#  bind + host allowlist
# --------------------------------------------------------------------------- #
def bind_host() -> str:
    return (os.environ.get("HOUNDS_BIND") or "").strip() or DEFAULT_BIND


def _is_loopback_ip(h) -> bool:
    h = (h or "").strip().strip("[]").lower()
    if h in LOOPBACK_NAMES:
        return True
    if h.startswith("::ffff:"):
        h = h[7:]
    try:
        return ipaddress.ip_address(h).is_loopback
    except ValueError:
        return False


def is_loopback_bind(h=None) -> bool:
    return _is_loopback_ip(bind_host() if h is None else h)


def is_loopback_peer(addr) -> bool:
    """True when the TCP peer is this machine. None = in-process / unknown → not a peer."""
    return _is_loopback_ip(addr) if addr else False


_HOSTS_CACHE = {"key": None, "set": frozenset()}


def allowed_hosts() -> frozenset:
    extra = (os.environ.get("HOUNDS_ALLOWED_HOSTS") or "").strip()
    b = bind_host()
    key = (extra, b)
    if _HOSTS_CACHE["key"] == key:
        return _HOSTS_CACHE["set"]
    s = set(LOOPBACK_NAMES)
    for h in extra.split(","):
        h = h.strip().strip("[]").lower().rstrip(".")
        if h:
            s.add(h)
    if not is_loopback_bind(b):
        if b not in ("0.0.0.0", "::", ""):
            s.add(b.strip("[]").lower())
        # this machine's own names/addresses — what a LAN colleague types
        try:
            hn = socket.gethostname()
            s.add(hn.lower())
            s.add(socket.getfqdn().lower())
            for ip in socket.gethostbyname_ex(hn)[2]:
                s.add(ip)
        except Exception:
            pass
    fs = frozenset(s)
    _HOSTS_CACHE.update(key=key, set=fs)
    return fs


def split_host(host_header):
    """'Example.com:8000' → 'example.com'; '[::1]:8000' → '::1'. None when malformed."""
    h = (host_header or "").strip().lower()
    if not h or any(c in h for c in " /\\@\r\n\t"):
        return None
    if h.startswith("["):
        end = h.find("]")
        if end < 0:
            return None
        name, rest = h[1:end], h[end + 1:]
        if rest and not (rest.startswith(":") and rest[1:].isdigit()):
            return None
        return name
    if h.count(":") == 1:
        name, port = h.split(":")
        if not port.isdigit():
            return None
        h = name
    elif h.count(":") > 1:
        return None                              # bare IPv6 must be bracketed in Host
    return h.rstrip(".")


def host_ok(host_header) -> bool:
    name = split_host(host_header)
    return bool(name) and name in allowed_hosts()


# --------------------------------------------------------------------------- #
#  access token
# --------------------------------------------------------------------------- #
def token_required(peer_addr=None) -> bool:
    """A token is needed whenever someone other than this machine could be talking to us:
    the console is bound to a non-loopback address, or the peer itself isn't loopback
    (e.g. the server was started by hand with `uvicorn --host 0.0.0.0`)."""
    if force_token() or not is_loopback_bind():
        return True
    return bool(peer_addr) and not is_loopback_peer(peer_addr)


def force_token() -> bool:
    """HOUNDS_REQUIRE_TOKEN=1 — require the token even on loopback (shared jump boxes, where
    other local users can reach 127.0.0.1)."""
    return (os.environ.get("HOUNDS_REQUIRE_TOKEN") or "").strip().lower() in ("1", "true", "yes", "on")


def _eq(a, b) -> bool:
    return bool(a) and bool(b) and hmac.compare_digest(str(a).encode(), str(b).encode())


def parse_cookies(cookie_header):
    out = {}
    for part in (cookie_header or "").split(";"):
        k, _, v = part.strip().partition("=")
        if k:
            out[k] = v
    return out


def token_ok(get_header) -> bool:
    if _eq(get_header(TOKEN_HEADER) or "", TOKEN):
        return True
    return _eq(parse_cookies(get_header("Cookie")).get(COOKIE, ""), TOKEN)


def cookie_header() -> str:
    return f"{COOKIE}={TOKEN}; HttpOnly; SameSite=Strict; Path=/"


def token_exchange(path, query):
    """GET /anything?token=<t>: returns (status, headers) — a redirect to the same URL minus
    the token, setting the session cookie — or None when the request carries no token.
    A wrong token is a 403 (no cookie)."""
    qs = urllib.parse.parse_qs(query or "", keep_blank_values=True)
    if "token" not in qs:
        return None
    if not _eq((qs.get("token") or [""])[0], TOKEN):
        return 403, {}
    rest = urllib.parse.urlencode([(k, v) for k, vs in qs.items() if k != "token" for v in vs], doseq=True)
    loc = (path or "/") + ("?" + rest if rest else "")
    return 302, {"Location": loc, "Set-Cookie": cookie_header()}


def startup_url(port) -> str:
    """The URL to print. Includes the token only when a token is required."""
    b = bind_host()
    host = "localhost" if is_loopback_bind(b) or b in ("0.0.0.0", "::") else b
    if b in ("0.0.0.0", "::"):
        try:
            host = socket.gethostname() or "localhost"
        except Exception:
            host = "localhost"
    if ":" in host and not host.startswith("["):
        host = "[" + host + "]"
    url = f"http://{host}:{port}/"
    return url + ("?token=" + TOKEN if token_required(None) else "")


def startup_warning() -> str:
    """Loud banner text when the console is exposed beyond loopback ('' when it isn't)."""
    b = bind_host()
    if is_loopback_bind(b):
        return ""
    return ("!" * 72 + "\n"
            f"  WARNING: HOUNDS_BIND={b} — The Hounds is reachable from OTHER HOSTS.\n"
            "  Anyone who can reach this port and holds the access token below controls\n"
            "  the console (and, if writes are enabled, your Tenable tenant). Every /api\n"
            "  call needs the token; share the URL only with people you trust, prefer an\n"
            "  SSH tunnel, and set HOUNDS_ALLOWED_HOSTS to the name/IP clients will type.\n"
            + "!" * 72)


# --------------------------------------------------------------------------- #
#  the request gate (every server calls this first)
# --------------------------------------------------------------------------- #
def post_guard(get_header):
    """Cross-site POST defence. Returns an error string, or None when the request is fine."""
    ctype = (get_header("Content-Type") or "").lower()
    if "application/json" not in ctype:
        return "POST must be Content-Type: application/json"
    origin = (get_header("Origin") or "").strip()
    if origin:
        if origin.lower() == "null":
            return "cross-origin request refused (Origin: null)"
        u = urllib.parse.urlparse(origin)
        if u.scheme not in ("http", "https") or not u.netloc:
            return "cross-origin request refused"
        if u.netloc.lower() != (get_header("Host") or "").strip().lower():
            return "cross-origin request refused"
        if not host_ok(u.netloc):
            return "cross-origin request refused (origin host not allowed)"
    sfs = (get_header("Sec-Fetch-Site") or "").strip().lower()
    if sfs == "cross-site":
        return "cross-site request refused"
    return None


def check(method, path, get_header, peer_addr=None):
    """Gate one request. Returns None when allowed, else (status, message)."""
    if not host_ok(get_header("Host")):
        return 403, ("Host header not allowed. Open the console via localhost / 127.0.0.1, or add "
                     "this name to HOUNDS_ALLOWED_HOSTS and restart.")
    is_api = (path or "").startswith("/api/") or path == "/api"
    if is_api and token_required(peer_addr):
        if is_loopback_bind() and peer_addr and not is_loopback_peer(peer_addr):
            # bound to loopback but a non-loopback peer reached us (server launched by hand on
            # 0.0.0.0 without HOUNDS_BIND): no token was ever printed, so refuse outright.
            return 403, ("remote access is disabled — restart with HOUNDS_BIND=0.0.0.0 to allow it "
                         "(an access token is printed at startup)")
        if not token_ok(get_header):
            return 401, ("access token required — open the URL printed at startup "
                         "(http://host:port/?token=…), or send the X-Hounds-Token header")
    if (method or "").upper() == "POST":
        bad = post_guard(get_header)
        if bad:
            return 403, bad
    return None


def static_allowed(rel_path) -> bool:
    """Only page assets may be served from agents/ and web/ — never .py source, caches, or
    dotfiles."""
    rel = urllib.parse.unquote(rel_path or "").replace("\\", "/")
    parts = [s for s in rel.split("/") if s]
    if not parts:
        return False
    if any(s.startswith(".") or s == "__pycache__" for s in parts):
        return False
    return os.path.splitext(parts[-1])[1].lower() in STATIC_EXT


def private_open(path, mode="w", **kw):
    """open() for a file only the owner may read (0600 on creation, re-asserted on an existing
    file) — caches, logs, alert state, contracts, page-cache entries."""
    flags = os.O_WRONLY | os.O_CREAT | (os.O_APPEND if "a" in mode else os.O_TRUNC)
    fd = os.open(path, flags, 0o600)
    try:
        os.fchmod(fd, 0o600)
    except (AttributeError, OSError):
        pass
    return os.fdopen(fd, mode, **kw)


def private_file(path):
    """Best-effort chmod 0600 (e.g. an SQLite db someone else's library created)."""
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
