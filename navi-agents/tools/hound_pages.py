"""Render the "Meet the Hound" one-pagers (web/hounds/<id>.html) from their content files.

Each hound's one-pager — the printable sheet behind its hub card's "Info ↗" — is generated from
tools/hound_pages/<id>.json so the copy can be reviewed and corrected in one place:

  codename, discipline, category, tagline, lore, problem, does, capabilities [[lead, text]…],
  how, who, glance {img, caption, note}, better, different [[lead, text]…] (optional), cta

  · the crest is embedded from web/assets/crests/<id>.png (a lettered placeholder when missing);
  · the "At a glance" figure is the hound's own At a glance widget, captured from its live page
    (tools/hound_pages/glance/<id>.png — re-capture with tools/hound_pages_capture.js);
  · text is plain (HTML-escaped); `backticks` render as code.

Run:  python3 tools/hound_pages.py            # every content file
      python3 tools/hound_pages.py acr sla    # just these
      python3 tools/hound_pages.py --intro    # rebuild the in-app intro (AGENT_INTRO in
                                              # web/assets/console.js) from the same files

The in-app intro — the "what it does & the name" panel under each hound's header — shows
`does` and the capabilities, so the app and the printed one-pager always say the same thing.
"""
import base64
import html
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SRC = os.path.join(HERE, "hound_pages")
OUT = os.path.join(ROOT, "web", "hounds")
CRESTS = os.path.join(ROOT, "web", "assets", "crests")
EXTRA_CSS = """
.glance { width:100%; margin-bottom:14px; }
.glance h3 { font-size:12px; text-transform:uppercase; letter-spacing:1px; color:#5457cc;
  border-bottom:1px solid #dde3f2; padding-bottom:3px; margin-bottom:7px; font-weight:700; }
.glance figure { background:#f6f7fd; border:1px solid #e1e4f5; border-radius:10px; padding:8px; text-align:center; }
.glance img { max-width:100%; max-height:3.1in; object-fit:contain; display:inline-block; }
.glance figcaption { font-size:10.5px; color:#5b6580; line-height:1.4; margin-top:6px; text-align:left; }
.glance figcaption b { color:#3a3f8f; }
.glance .gnote { font-size:9.5px; color:#8891a6; font-style:italic; margin-top:4px; text-align:left; }
code { font-family:'DejaVu Sans Mono', ui-monospace, monospace; font-size:.92em; background:#eef0fb; padding:0 3px; border-radius:3px; }
.crest.ph { display:flex; align-items:center; justify-content:center; font-size:58px; font-weight:700; color:#fff;
  background:linear-gradient(140deg,#3b3e8f,#6d70e6); }
"""


def t(s):
    """Plain text → HTML (escaped); `x` → <code>x</code>."""
    s = html.escape(str(s or ""), quote=False)
    return re.sub(r"`([^`]+)`", r"<code>\1</code>", s)


def items(lst):
    return "<ul>" + "".join("<li><b>%s —</b> %s</li>" % (t(a), t(b)) for a, b in lst) + "</ul>"


_KEEP_CHUNKS = (b"IHDR", b"PLTE", b"tRNS", b"IDAT", b"IEND")


def png_b64(path):
    """A PNG as base64 with only its image chunks — metadata (text, provenance stamps a file
    copy may add) is dropped, so the same picture always embeds the same bytes."""
    import struct
    data = open(path, "rb").read()
    if data[:8] != b"\x89PNG\r\n\x1a\n":
        return base64.b64encode(data).decode()
    out, i = [data[:8]], 8
    while i + 8 <= len(data):
        n, typ = struct.unpack(">I4s", data[i:i + 8])
        if typ in _KEEP_CHUNKS:
            out.append(data[i:i + 12 + n])
        i += 12 + n
    return base64.b64encode(b"".join(out)).decode()


def crest(hid, name):
    p = os.path.join(CRESTS, hid + ".png")
    if os.path.exists(p):
        b64 = png_b64(p)
        return '<img class="crest" src="data:image/png;base64,%s" alt="%s crest">' % (b64, html.escape(name))
    return '<div class="crest ph" aria-label="%s (crest coming)">%s</div>' % (html.escape(name), html.escape(name[:1]))


def glance(g, hid):
    if not g:
        return ""
    img = ""
    p = os.path.join(SRC, "glance", g.get("img") or (hid + ".png"))
    if os.path.exists(p):
        img = '<img src="data:image/png;base64,%s" alt="%s">' % (
            png_b64(p), html.escape("At a glance — " + hid))
    note = '<div class="gnote">%s</div>' % t(g["note"]) if g.get("note") and not img else ""
    return ('<div class="glance"><h3>At a glance</h3><figure>%s<figcaption>%s</figcaption>%s</figure></div>'
            % (img, t(g.get("caption")), note))


def render(hid):
    c = json.load(open(os.path.join(SRC, hid + ".json"), encoding="utf-8"))
    css = open(os.path.join(SRC, "onepager.css"), encoding="utf-8").read() + EXTRA_CSS
    name = c["codename"]
    sec = lambda h, body, span=False: '      <section%s><h3>%s</h3>%s</section>\n' % (
        ' class="span2"' if span else "", t(h), body)
    p = lambda s: "<p>%s</p>" % t(s)
    body = (sec("The Problem", p(c["problem"])) + sec("What It Does", p(c["does"]))
            + "      " + glance(c.get("glance"), hid) + "\n"
            + sec("Key Capabilities", items(c["capabilities"]), True)
            + sec("How It Works", p(c["how"])) + sec("Who It's For", p(c["who"]))
            + sec("Works Better With", p(c["better"]), True)
            + (sec("Why It's Different", items(c["different"]), True) if c.get("different") else ""))
    return ("""<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>%(up)s — The Hounds</title><style>%(css)s</style></head><body>
<!-- generated by tools/hound_pages.py from tools/hound_pages/%(id)s.json — edit that, not this -->
<div class="toolbar"><button onclick="window.print()">🖨 Print / Save as PDF</button></div>
<div class="sheet">
  <div class="hdr"><div class="hrow">
    %(crest)s
    <div><div class="codename">%(up)s</div>
      <div class="discipline">%(disc)s</div>
      <div class="chip">Category · %(cat)s</div></div>
  </div></div>
  <div class="tagline">“%(tag)s”</div>
  <div class="body">
    <div class="lore">%(lore)s</div>
    <div class="grid">
%(body)s    </div>
  </div>
  <div class="cta">%(cta)s</div>
  <div class="foot"><span><b>THE HOUNDS</b> — human-in-the-loop AI security agents for Tenable VM / Tenable One</span>
    <span>Gated writes · Evidence-first · Honest about coverage</span></div>
</div></body></html>
""" % {"id": hid, "up": t(name.upper()), "css": css, "crest": crest(hid, name), "disc": t(c["discipline"]),
       "cat": t(c["category"]), "tag": t(c["tagline"]), "lore": t(c["lore"]), "body": body, "cta": t(c["cta"])})


CONSOLE = os.path.join(ROOT, "web", "assets", "console.js")
INTRO_START, INTRO_END = "const AGENT_INTRO = {", "\n};"
INTRO_KEEP = ("advanced",)      # intro entries with no one-pager (kept as they are)


def _js(s):
    """A JS string literal (JSON-escaped, and safe inside a <script> file)."""
    return json.dumps(s, ensure_ascii=False).replace("</", "<\\/")


def intro_block(old_block):
    """The AGENT_INTRO object rebuilt from the content files (HTML-escaped; `x` → mono)."""
    mono = lambda x: re.sub(r"<code>([^<]*)</code>", r"<span class='mono'>\1</span>", t(x))
    lines = [INTRO_START,
             " /* generated by tools/hound_pages.py --intro from tools/hound_pages/<id>.json — edit those */"]
    for hid in sorted(f[:-5] for f in os.listdir(SRC) if f.endswith(".json")):
        c = json.load(open(os.path.join(SRC, hid + ".json"), encoding="utf-8"))
        caps = ["<b>%s</b> — %s" % (t(a), mono(b)) for a, b in c["capabilities"]]
        lines.append(" %s:{does:%s,caps:[\n   %s]}," % (hid, _js(mono(c["does"])), ",\n   ".join(_js(x) for x in caps)))
    for key in INTRO_KEEP:
        m = re.search(r"\n( %s:\{does:.*?\]\},?)" % re.escape(key), old_block, re.S)
        if m:
            lines.append(m.group(1).rstrip(",") + ",")
    return "\n".join(lines)


def write_intro():
    s = open(CONSOLE, encoding="utf-8").read()
    i = s.index(INTRO_START)
    j = s.index(INTRO_END, i)
    out = s[:i] + intro_block(s[i:j]) + s[j:]
    with open(CONSOLE, "w", encoding="utf-8") as f:
        f.write(out)
    print("wrote AGENT_INTRO in web/assets/console.js")


def main(ids):
    if ids == ["--intro"]:
        return write_intro()
    ids = ids or sorted(f[:-5] for f in os.listdir(SRC) if f.endswith(".json"))
    for hid in ids:
        if not re.fullmatch(r"[a-z0-9_]{1,40}", hid):
            raise SystemExit("bad id: %r" % hid)
        out = render(hid)
        with open(os.path.join(OUT, hid + ".html"), "w", encoding="utf-8") as f:
            f.write(out)
        print("wrote web/hounds/%s.html (%d KB)" % (hid, len(out) // 1024))


if __name__ == "__main__":
    main(sys.argv[1:])
