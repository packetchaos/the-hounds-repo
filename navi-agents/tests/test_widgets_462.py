"""Regression tests — build 462: ⛶ full screen + 📧 Gabriel (picture AND list) on six widgets.

ATT&CK matrix (MITRE) · ATLAS map (AI) · KEV remediation due dates · Software risk leaderboard ·
Attack map (Attack Paths) · Ownership Sankey (Exposure Routes). The email `widget` action is
double-gated, attaches the picture (PNG, or an HTML snapshot), puts the list inline (≤200 rows)
and zips picture + full CSV when the list is longer. Run: python3 tests/test_widgets_462.py"""
import atexit
import base64
import json
import os
import re
import shutil
import sys
import tempfile
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
TMP = tempfile.mkdtemp(prefix="hounds-462-")
atexit.register(shutil.rmtree, TMP, ignore_errors=True)
os.environ.update({"NAVI_CACHE_DIR": os.path.join(TMP, "cache"), "HOUNDS_CONFIG": os.path.join(TMP, "cfg.json"),
                   "NAVI_TAGLOG_DB": os.path.join(TMP, "taglog.db"), "NAVI_HISTORY_DIR": os.path.join(TMP, "hist")})

fails = []


def check(cond, msg):
    print(("PASS " if cond else "FAIL ") + msg)
    if not cond:
        fails.append(msg)


def page(p):
    return open(os.path.join(ROOT, p), encoding="utf-8").read()


# ── console.js helpers ────────────────────────────────────────────────────────────────────────
js = page("web/assets/console.js")
for fn in ("function hSnapshot(", "function hFull(", "function hWidget(", "function _inlineStyles("):
    check(fn in js, "console.js defines " + fn.split(" ")[1].rstrip("("))
check("requestFullscreen" in js and "hw-fs" in js, "full screen: Fullscreen API with an overlay fallback")
check("mode==='widget'" in js or 'mode==="widget"' in js, "hMail has a widget mode (picture + list)")
check("hw-full" in js[js.index("function hMailAuto"):js.index("function hMailAuto") + 2500],
      "hMailAuto skips tables inside a widget that already has its own 📧")

# ── each page wires its widget ────────────────────────────────────────────────────────────────
wired = {"agents/mitre/page.html": "secMatrix", "agents/ai/page.html": "secAtlas",
         "agents/cisakev/page.html": "secDue", "agents/software/page.html": "secRisk",
         "agents/attackpath/page.html": "secMap", "agents/exproute/page.html": "snkCard"}
for p, sid in wired.items():
    s = page(p)
    m = re.search(r"hWidget\('%s',\{(.{0,1600})" % sid, s, re.S)
    check(bool(m) and "visual:" in m.group(1) and "rows:" in m.group(1),
          "%s: %s has ⛶ + 📧 with a picture and a list" % (p.split("/")[1], sid))
    check(('id="%s"' % sid) in s, "%s: section #%s exists" % (p.split("/")[1], sid))
check('id="dueVis"' in page("agents/cisakev/page.html"), "KEV: the timeline + legend are one picture (#dueVis)")
check("grow:'#map'" in page("agents/attackpath/page.html"), "Attack map grows to the screen and re-fits")
check("SNK_LAST={items, links}" in page("agents/exproute/page.html"), "Sankey keeps the drawn links for the list")
check("SW.risk=o" in page("agents/software/page.html"), "Software keeps the leaderboard for the list")

# ── SLA Adherence: every trend chart is its own half-page widget ───────────────────────────────
sla = page("agents/sla/page.html")
ids = re.findall(r"\{id:'(ch\w+)'", sla)
check(ids == ["chBacklog", "chNewFixed", "chBreaches", "chDays", "chInSla", "chDailyOpen", "chDailyPct"],
      "SLA: seven trend charts, one widget each (%s)" % ids)
check('id="trendGrid"' in sla and ".halfgrid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr))" in sla,
      "SLA: the charts sit two to a row (half the page each), one column on phones")
check("CH.forEach(c=>hWidget(c.id" in sla and "onResize:on=>draw(c,on)" in sla and "const W=opts.w||440" in sla,
      "SLA: each chart has ⛶ (redrawn at screen size) + 📧 picture & list")
check("chartBox(" not in sla.split("function renderTrend(){")[1].split("/* ===")[0],
      "SLA: no chart left inside the Over time card")

# ── the email `widget` action ─────────────────────────────────────────────────────────────────
from agents.email import api  # noqa: E402
from core import navi_cli  # noqa: E402
check(api.ACTIONS.get("widget") is api.widget, "email action 'widget' registered")
sent = []
orig = (navi_cli.email_enabled, navi_cli.mail)


def fake_mail(**kw):
    rec = dict(kw)
    if kw.get("file"):
        rec["file_bytes"] = open(kw["file"], "rb").read()
        rec["file_name"] = os.path.basename(kw["file"])
    rec["html_body"] = open(kw["html"], encoding="utf-8").read()
    sent.append(rec)
    return {"ok": True, "message": "sent"}


navi_cli.mail = fake_mail
PNG = "data:image/png;base64," + base64.b64encode(b"\x89PNG\r\n\x1a\nfake").decode()
try:
    navi_cli.email_enabled = lambda: False
    o, code = api.widget({"to": "a@b.c", "confirm": True, "rows": [{"a": 1}]})
    check(code == 200 and o.get("blocked") and not sent, "gated: email disabled → blocked, nothing sent")
    navi_cli.email_enabled = lambda: True
    o, code = api.widget({"to": "a@b.c", "confirm": "true", "rows": [{"a": 1}]})
    check(code == 400 and not sent, "gated: confirm must be JSON true")
    o, code = api.widget({"to": "a@b.c", "confirm": True})
    check(code == 400 and not sent, "nothing to send → 400")
    o, code = api.widget({"to": "a@b.c", "confirm": True, "png": "data:text/html;base64,AAAA", "rows": [{"a": 1}]})
    check(code == 400 and not sent, "picture must be a PNG data-URI")

    o, code = api.widget({"to": "a@b.c", "confirm": True, "title": "ATT&CK <matrix>", "png": PNG,
                          "columns": ["technique", "assets"],
                          "rows": [{"technique": "T1190<script>", "assets": 3}]})
    m = sent[-1]
    check(o["ok"] and o["attached"].endswith(".png") and m["file_bytes"].startswith(b"\x89PNG"),
          "PNG picture rides as the attachment")
    check("T1190&lt;script&gt;" in m["html_body"] and "<script>" not in m["html_body"]
          and "ATT&amp;CK &lt;matrix&gt;" in m["html_body"], "list inline and escaped")
    check(o["rows"] == 1 and o["rows_inline"] == 1, "rows reported")

    o, code = api.widget({"to": "a@b.c", "confirm": True, "title": "Sankey", "html": "<html>snap</html>",
                          "rows": [{"x": 1}]})
    check(o["attached"].endswith(".html") and sent[-1]["file_bytes"] == b"<html>snap</html>",
          "no PNG (Safari) → the HTML snapshot is attached")

    rows = [{"n": i} for i in range(250)]
    o, code = api.widget({"to": "a@b.c", "confirm": True, "title": "Big", "png": PNG, "rows": rows})
    z = zipfile.ZipFile(os.path.join(TMP, "z.zip"), "w")
    z.close()
    p = os.path.join(TMP, "got.zip")
    open(p, "wb").write(sent[-1]["file_bytes"])
    names = zipfile.ZipFile(p).namelist()
    csvb = zipfile.ZipFile(p).read([n for n in names if n.endswith(".csv")][0]).decode("utf-8-sig")
    check(o["attached"].endswith(".zip") and any(n.endswith(".png") for n in names)
          and len(csvb.strip().splitlines()) == 251 and o["rows_inline"] == 200,
          ">200 rows: first 200 inline, zip holds picture + full CSV")
    o, code = api.widget({"to": "a@b.c", "confirm": True, "title": "Big", "rows": rows})
    check(o["attached"].endswith(".csv"), ">200 rows, no picture → CSV attached")
    leftover = [d for d in os.listdir(tempfile.gettempdir()) if d.startswith("hounds_widget_")]
    check(not leftover, "temp files cleaned up")
finally:
    navi_cli.email_enabled, navi_cli.mail = orig

from core import version  # noqa: E402
check(version.BUILD >= 462, "build 462")
print("\n%d failure(s)" % len(fails))
sys.exit(1 if fails else 0)
