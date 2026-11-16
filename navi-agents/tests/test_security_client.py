"""Client-side security regression checks (build 442 security sweep).

Static checks over web/assets/*.js, web/*.html, web/hounds/*.html, agents/*/page.html and
agents/was/report.html, plus a small Node unit check of safeUrl / safeHref / _csvCell when
`node` is on PATH. No server, no browser. Run: python3 tests/test_security_client.py
"""
import glob
import json
import os
import re
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
fails = []


def check(cond, msg):
    print(("PASS " if cond else "FAIL ") + msg)
    if not cond:
        fails.append(msg)


def rd(rel):
    with open(os.path.join(ROOT, rel), encoding="utf-8") as f:
        return f.read()


PAGES = sorted(set(
    [os.path.relpath(p, ROOT) for p in glob.glob(os.path.join(ROOT, "agents", "*", "page.html"))]
    + ["agents/was/report.html"]
    + [os.path.relpath(p, ROOT) for p in glob.glob(os.path.join(ROOT, "web", "*.html"))]
    + [os.path.relpath(p, ROOT) for p in glob.glob(os.path.join(ROOT, "web", "hounds", "*.html"))]
    + [os.path.relpath(p, ROOT) for p in glob.glob(os.path.join(ROOT, "web", "assets", "*.js"))]))
SRC = {p: rd(p) for p in PAGES}
CJS = SRC["web/assets/console.js"]
EMAIL = SRC["agents/email/page.html"]

# ---------------------------------------------------------------- 1. email hand-off + preview
check("get('handoff')" not in EMAIL and '?handoff' not in EMAIL,
      "email: the ?handoff= URL source is gone")
check("location.search" not in EMAIL and "URLSearchParams" not in EMAIL,
      "email: the page reads nothing from the URL")
check("sessionStorage.getItem('gabriel_handoff')" in EMAIL,
      "email: hand-offs still arrive via sessionStorage")
check(not re.search(r'class="prev">\$\{\s*m\.body_html', EMAIL),
      "email: body_html is no longer injected with innerHTML")
check(re.search(r'<iframe class="prevFrame"[^>]*\ssandbox=""', EMAIL) is not None and ".srcdoc=" in EMAIL,
      "email: body_html preview renders in a fully sandboxed srcdoc iframe")
check("allow-scripts" not in EMAIL and "allow-same-origin" not in EMAIL,
      "email: the preview sandbox grants neither scripts nor same-origin")
check(re.search(r"\[\s*'to'\s*,\s*'cc'\s*,\s*'bcc'\s*,\s*'recipient'\s*,\s*'recipients'\s*\]", EMAIL) is not None
      and "to:'', needs_address:true" in EMAIL,
      "email: a hand-off can't pre-fill recipients (to/cc/bcc dropped, message `to` cleared)")
check("Recipients:" in EMAIL and "confirm('Send '" in EMAIL,
      "email: the send confirm lists the recipients")
url_handoffs = [p for p, s in SRC.items() if re.search(r"email/page\.html\?", s)]
check(not url_handoffs, f"no page hands off to Gabriel through the URL ({url_handoffs})")

# ---------------------------------------------------------------- 2. URL params → HTML
CA = SRC["agents/customapp/page.html"]
check("'+h.focus+'" not in CA and "esc(h.focus)" in CA, "customapp: ?focus is escaped before flash()")
bad_h = []
for p, s in SRC.items():
    for m in re.finditer(r"flash\([^;\n]*?['\"`]\s*\+\s*h\.(focus|from|q|target)\b", s):
        bad_h.append(p)
check(not bad_h, f"no flash() concatenates a raw handoff param ({bad_h})")

# ---------------------------------------------------------------- 3. server error echoes
bad_err = []
for p, s in SRC.items():
    for m in re.finditer(r"flash\([^;\n]*?'✗[^']*'\s*\+\s*\(?\s*(o|r|err|e)\.(error|message)\b", s):
        bad_err.append(f"{p}:{s.count(chr(10), 0, m.start()) + 1}")
check(not bad_err, f"no flash('✗ '+o.error / e.message) without esc() ({bad_err[:6]})")

# ---------------------------------------------------------------- 4. LLM picks → crest img
for p in ("web/index.html", "web/meet.html"):
    s = SRC[p]
    check("'/static/crests/'+p.id" not in s and "crestSrc(p.id)" in s,
          f"{p}: LLM pick ids go through crestSrc() (no raw id in <img src>)")
    check("byId0[p.id]" in s, f"{p}: only LLM picks naming a known agent are rendered")

# ---------------------------------------------------------------- 5/7. attributes from data / localStorage
check('data-st="${esc(c.status)}"' in SRC["agents/compliance_asset/page.html"],
      "compliance_asset: data-st is escaped")
CD = SRC["web/compliancedash.html"]
check('data-id="${d.id}"' not in CD and 'data-x="${d.id}"' not in CD and 'data-id="${it.id}"' not in CD,
      "compliancedash: localStorage ids are escaped in data-id / data-x")
check("data-sw=\"'+d.id+'\"" not in CJS and "data-sw=\"'+esc(d.id)+'\"" in CJS,
      "console.js: dashboard tab ids (localStorage) are escaped")

# ---------------------------------------------------------------- 6. CSV formula guard
check(re.search(r"function _csvCell\(v\)\{[^\n]*\n[^\n]*\^\[=\+\\-@\\t\\r\]", CJS) is not None,
      "console.js: _csvCell neutralises = + - @ TAB CR")
csv_builders = [p for p, s in SRC.items() if p != "web/assets/console.js"
                and re.search(r"\.join\(','\)\s*\)\s*\.join\(\s*'\\(r\\)?n'", s)]
check(not csv_builders, f"no page builds CSV text itself outside _csvCell ({csv_builders})")

# ---------------------------------------------------------------- 8. data-built hrefs
check("function safeUrl(" in CJS and "function safeHref(" in CJS, "console.js: safeUrl/safeHref helpers exist")
raw_url_href = []
for p, s in SRC.items():
    for m in re.finditer(r"href=\\?[\"']?(?:\$\{|'\s*\+\s*)esc\((?:[a-z]\w*\.)?(url|target|see_also)\)", s):
        raw_url_href.append(f"{p}:{s.count(chr(10), 0, m.start()) + 1}")
    for m in re.finditer(r"href=\\?[\"']?\$\{String\(\w+(\.\w+)?\)\.replace\(", s):
        raw_url_href.append(f"{p}:{s.count(chr(10), 0, m.start()) + 1}")
check(not raw_url_href, f"no href built from a data URL field without safeUrl() ({raw_url_href[:6]})")
need_safe = {"agents/argos/page.html": 2, "agents/identity/page.html": 1, "agents/scan_eval/page.html": 1,
             "agents/ex_assets/page.html": 1, "agents/ex_vulns/page.html": 1, "agents/ex_tags/page.html": 1,
             "agents/ai/page.html": 1, "agents/was/report.html": 2, "agents/was_asset/page.html": 1,
             "agents/compliance_asset/page.html": 1, "web/vuln.html": 1, "web/ownermap.html": 1}
for p, n in need_safe.items():
    check(SRC[p].count("safeUrl(") >= n, f"{p}: uses safeUrl() at its data-built links")

# ---------------------------------------------------------------- 9. inline handlers from data
inline = []
for p, s in SRC.items():
    for m in list(re.finditer(r'\son[a-z]+=\\?"[^"]*?(\$\{|\'\s*\+)', s)) + list(re.finditer(r"\son[a-z]+='[^']*?(\$\{|\+)", s)):
        inline.append(f"{p}:{s.count(chr(10), 0, m.start()) + 1}")
check(not inline, f"no inline on*= handler is built from data ({inline[:6]})")
check("onclick=\"emailFindings(" not in CJS and "onclick='emailFindings(" not in CJS,
      "console.js: emailFindingsBtn uses data-efb + a listener, not onclick")

# ---------------------------------------------------------------- confirm is a JSON boolean
str_confirm = [p for p, s in SRC.items() if re.search(r"confirm\s*:\s*['\"](true|1|yes)['\"]", s)]
check(not str_confirm, f"every write sends confirm as boolean true, never a string ({str_confirm})")

# ---------------------------------------------------------------- settings / alert confirms
ST = SRC["web/settings.html"]
check("f.env_only" in ST and "readonly disabled" in ST, "settings: env_only fields (NAVI_BIN, NAVI_CWD) render read-only")
check("needs_confirm" in ST and "env:env2, confirm:true" in ST and "confirm('Confirm this security-sensitive change" in ST,
      "settings: guarded changes get a confirm() and are resent with confirm:true")
check(ST.count("postEnv(") >= 4 and "API.post('set_env',{env})" not in ST.replace("API.post('set_env',{env}); }catch(e){ return", ""),
      "settings: every set_env goes through the confirm round-trip")
check("clears the stored model API key" in ST, "settings: the base-URL/provider field warns that model keys get cleared")
AL = SRC["agents/alert/page.html"]
check("API.post('send_test',{id, confirm:true})" in AL and "confirm('Send a REAL test email" in AL,
      "alert: Test email confirms first and sends confirm:true")
check("{send:true,confirm:true}" in AL and "confirm('Evaluate every enabled alert and EMAIL" in AL,
      "alert: Evaluate + send confirms first and sends confirm:true")
check("esc(r.error)" in AL and "esc((r&&r.error)||'evaluation failed')" in AL, "alert: a 400's error is shown (escaped)")

# ---------------------------------------------------------------- Node unit checks
node = shutil.which("node")
if node:
    def grab(name):
        i = CJS.index("function " + name + "(")
        j, d = CJS.index("{", i), 0
        k = j
        while True:
            d += {"{": 1, "}": -1}.get(CJS[k], 0)
            k += 1
            if d == 0:
                return CJS[i:k]
    js = "\n".join(grab(n) for n in ("safeUrl", "safeHref", "_csvCell")) + r"""
const out = {
  u: ['https://cloud.tenable.com/x?a=1', 'HTTP://x.y', '  https://a.b  ', 'javascript:alert(1)', 'JaVaScRiPt:x',
      ' javascript:x', 'java\tscript:x', 'data:text/html,x', 'vbscript:x', '//evil.com', '/agents/x', '#x', '', null,
      'https://a\nb', '\u0001javascript:x'].map(x => safeUrl(x)),
  h: ['/agents/x/page.html?a=1', '#sec', '?q=1', '//evil.com', '/\\evil.com', 'javascript:x', 'https://ok.io'].map(x => safeHref(x)),
  c: ['=1+1', '+cmd', '-2+3', '@SUM(A1)', '\tx', '\rx', '-5', '+3.5', '-1e5', 'ok', 'a,b', '="x"', 7, -3].map(_csvCell)
};
console.log(JSON.stringify(out));
"""
    try:
        r = subprocess.run([node, "-e", js], capture_output=True, text=True, timeout=30)
        o = json.loads(r.stdout.strip().splitlines()[-1])
        check(o["u"] == ['https://cloud.tenable.com/x?a=1', 'HTTP://x.y', 'https://a.b', '#', '#', '#', '#', '#', '#',
                         '#', '#', '#', '#', '#', '#', '#'],
              "node: safeUrl keeps only absolute http(s) URLs")
        check(o["h"] == ['/agents/x/page.html?a=1', '#sec', '?q=1', '#', '#', '#', 'https://ok.io'],
              "node: safeHref allows same-origin relative links, refuses //, /\\ and javascript:")
        check(o["c"] == ["'=1+1", "'+cmd", "'-2+3", "'@SUM(A1)", "'\tx", "\"'\rx\"", '-5', '+3.5', '-1e5', 'ok',
                         '"a,b"', "\"'=\"\"x\"\"\"", '7', '-3'],
              "node: _csvCell prefixes formula cells, leaves plain numbers alone")
    except Exception as e:  # pragma: no cover
        check(False, f"node unit check ran ({e})")
else:
    print("SKIP node unit checks (node not on PATH)")

print(f"\n{len(fails)} failure(s)")
sys.exit(1 if fails else 0)
