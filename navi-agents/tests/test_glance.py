"""Regression tests for the shared "📊 At a glance" template (renderGlance in web/assets/console.js,
.glx… classes in web/assets/console.css) and the pages migrated to it.

- JS unit check (needs `node` on PATH; skipped otherwise): the glance block of console.js runs in
  node against a tiny fake DOM — hostile text is escaped, hrefs go through safeHref
  (javascript: dropped, '/x' and '#x' kept), no inline on*= handlers, zero values dimmed,
  filter clicks call opts.onFilter and toggle .on, onClick handlers fire, active filters marked.
- Static checks: the CSS defines the template classes with light + dark tokens; migrated pages
  call renderGlance and no longer define their own .mkpi / .mk / .mhead CSS.
No server, no browser. Run: python3 tests/test_glance.py  (or pytest)."""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
fails = []


def check(cond, msg):
    print(("PASS " if cond else "FAIL ") + msg)
    if not cond:
        fails.append(msg)


def read(rel):
    with open(os.path.join(ROOT, rel), encoding="utf-8") as f:
        return f.read()


CJS = read("web/assets/console.js")
CSS = read("web/assets/console.css")
MIGRATED = ["agents/%s/page.html" % a for a in (
    "identity", "was", "ai", "fused_score", "postquantum", "argos", "sla", "insights", "mitre", "classify", "customapp", "asset_ownership", "scan_eval", "iot_squad", "c2", "acr", "attackpath", "certificate", "cisakev", "compliance", "eol", "exproute")]

# ---------------------------------------------------------------- console.js API surface
check("function renderGlance(target, groups, opts)" in CJS, "console.js: renderGlance(target, groups, opts) exists")
check("function glanceNum(" in CJS and "function glanceSetActive(" in CJS, "console.js: glanceNum + glanceSetActive helpers exist")
# a global `const fnum` / `const N` would collide with the pages' own (classic scripts share one scope)
check(not re.search(r"^(const|let) (fnum|N|renderGlance|glanceNum)\b", CJS, re.M),
      "console.js: no global const/let that collides with page-local helpers")
start = CJS.find("/* ===== 📊 At a glance")
end = CJS.find("/* ===== end At a glance ===== */")
check(start > 0 and end > start, "console.js: the glance block is delimited")
BLOCK = CJS[start:end]
check(not re.search(r"\son[a-z]+=", BLOCK), "glance block builds no inline on*= handler")

# ---------------------------------------------------------------- console.css
for cls in (".glx{", ".glx-p{", ".glx-k{", ".glx-h{", ".glx-d{", ".glx-bar{", ".glx-lg{", ".glx-cs{", ".glx-c{",
            ".glx-rk{", ".glx-r{", ".glx-zero{", ".glx-act:focus-visible{", ".glx .on{", ".glx-sev-crit{", ".glx-sev-ok{"):
    check(cls in CSS, "console.css defines " + cls)
check("minmax(min(220px,100%),1fr)" in CSS, "console.css: glance grid never overflows a phone")
gcss = CSS[CSS.find("/* ===== 📊 At a glance"):]
dark = re.search(r":root\{([^}]*--glx-s1[^}]*)\}", gcss)
light = re.search(r'\[data-theme="light"\]\{([^}]*--glx-s1[^}]*)\}', gcss)
check(bool(dark and light) and all(("--glx-s%d" % i) in dark.group(1) and ("--glx-s%d" % i) in light.group(1) for i in range(1, 9)),
      "console.css: series palette s1…s8 has dark and light values")
rules = re.sub(r"(:root|\[data-theme=\"light\"\])\{[^}]*\}", "", gcss)
check(not re.search(r"#[0-9a-fA-F]{3,8}\b|rgba?\(", rules), "console.css: glance rules use tokens only (no hard-coded colours)")

# ---------------------------------------------------------------- migrated pages
for p in MIGRATED:
    s = read(p)
    check("renderGlance(" in s, p + ": uses renderGlance")
    check(not re.search(r"\.(mkpi|mk|mhead)\s*[{.\[:]", s.split("<script")[0]) and not re.search(r"^\s*a?\.mk\b", s, re.M),
          p + ": no page-local .mkpi/.mk/.mhead CSS")
    check('class="mk' not in s and "class=\"mkpi" not in s, p + ": no .mk / .mkpi markup left")
    check(not re.search(r"^function renderGlance\(", s, re.M), p + ": does not shadow the shared renderGlance")
    check("mountSectionNav()" in s and "setNavCount(" in s and "data-run" in s, p + ": jump nav, nav counts, data-run kept")
ID = read("agents/identity/page.html")
for f in ("g:human", "g:service", "g:machine", "g:flagged", "f:privileged", "f:reused", "f:nonexp", "f:ssh",
          "f:privexp", "f:kev", "f:crown", "f:crit"):
    check("filter:'%s'" % f in ID, "identity: glance filter %s kept" % f)
check("Most common risk flags" in ID and "label:'Human'" in ID and "label:'Credentialed'" in ID,
      "identity: the three old charts are folded into the glance (ranked flags, class bar, coverage bar)")
WAS = read("agents/was/page.html")
check("href:reconFor(f)" in WAS and "zero:!n" in WAS and "glxCov" in WAS,
      "was: glance links into Web App Recon, dims empty cohorts, scan-coverage card uses the template")

# ---------------------------------------------------------------- JS unit check in node
NODE = shutil.which("node")
if not NODE:
    print("SKIP node not on PATH — JS unit check skipped")
else:
    helpers = []
    for pat in (r"^const esc = .*$", r"^function safeUrl\(u, fallback\)\{[\s\S]*?^\}", r"^function safeHref\(u, fallback\)\{[\s\S]*?^\}"):
        m = re.search(pat, CJS, re.M)
        check(bool(m), "console.js helper found: " + pat[:24])
        helpers.append(m.group(0) if m else "")
    harness = r"""
function El(tag){ this.tagName=String(tag).toUpperCase(); this.children=[]; this._h=''; this.listeners={}; this.className='';
  this.dataset={}; const cl=new Set(); this.classList={add:c=>cl.add(c),remove:c=>cl.delete(c),contains:c=>cl.has(c),toggle:(c,on)=>{ if(on===undefined)on=!cl.has(c); on?cl.add(c):cl.delete(c); return on; }};
  this._attrs={}; }
El.prototype={ set innerHTML(v){ this._h=v; this.children=[]; }, get innerHTML(){ return this._h; },
  appendChild(c){ this.children.push(c); return c; }, addEventListener(t,f){ (this.listeners[t]=this.listeners[t]||[]).push(f); },
  querySelectorAll(){ return this._q||[]; }, contains(){ return true; }, setAttribute(k,v){ this._attrs[k]=v; } };
const HOST=new El('div'); const document={ getElementById:id=>id==='host'?HOST:null, createElement:t=>new El(t) };
let scrolled=0; setTimeout=(f)=>0;
""" + "\n".join(helpers) + "\n" + BLOCK + r"""
const out={};
const bad='<img src=x onerror=alert(1)>"\'&';
let calls=[], custom=0;
const root=renderGlance('host',[
  {title:bad, t:bad, hero:{v:0, l:bad, u:bad, href:'javascript:alert(1)'},
   bar:[{label:bad,value:3,color:'red;background:url(x)'},{label:'b',value:0,color:'crit'},{label:'c',value:2,color:'s3'}],
   chips:[{v:'0',l:'zero chip',filter:'f:x'},{v:'1,234',l:'link',href:'/agents/was/page.html?f=a&b=<c>'},{v:'5',l:'anchor',href:'#secX'},
          {v:'7',l:'fn',onClick:()=>custom++},{v:'0%',l:'pct zero',zero:false},{v:'9',l:'active',filter:'f:y'}],
   ranked:{title:'R', items:[{label:bad,value:4},{label:'z',value:0}], sev:'crit'}},
  {title:'empty', ranked:{items:[], empty:'nothing here'}}
], {active:['f:y'], onFilter:(f,el,on)=>calls.push([f,on])});
const h=HOST.children[0].innerHTML;
out.returned=root===HOST.children[0]; out.cls=root.className;
out.raw=h.indexOf('<img')>=0; out.escaped=h.indexOf('&lt;img src=x onerror=alert(1)&gt;')>=0;
out.inline=/\son[a-z]+=/i.test(h.replace(/&lt;img src=x onerror=alert\(1\)&gt;/g,''));
out.js=/href="javascript:/i.test(h); out.heroLink=/class="glx-h[^"]*"[^>]*href=/.test(h);
out.link=h.indexOf('href="/agents/was/page.html?f=a&amp;b=&lt;c&gt;"')>=0; out.anchor=h.indexOf('href="#secX"')>=0;
out.badColor=h.indexOf('url(x)')>=0; out.series=h.indexOf('var(--glx-s3)')>=0&&h.indexOf('var(--crit)')>=0;
out.zeroHero=/class="glx-h glx-sev-none glx-zero"/.test(h); out.zeroChip=/glx-c glx-sev-none glx-zero glx-act"[^>]*data-glx-f="f:x"/.test(h);
out.notZero=!/glx-zero[^"]*"[^>]*title="0% pct zero/.test(h) && /title="0% pct zero/.test(h);
out.commaNotZero=!/glx-zero[^>]*title="1,234 link/.test(h);
out.active=/class="glx-c glx-sev-none glx-act on" role="button" tabindex="0" aria-pressed="true" data-glx-f="f:y"/.test(h);
out.roles=(h.match(/role="button" tabindex="0"/g)||[]).length; out.empty=h.indexOf('nothing here')>=0;
out.rankedZero=/glx-r glx-sev-crit glx-zero/.test(h);
// simulate a filter click on the f:x chip (index 1: hero is not clickable after javascript: was dropped)
const idx=(re)=>{ const m=h.match(re); return m?m[1]:null; };
const fi=idx(/data-glx-f="f:x" data-glx-i="(\d+)"/); const ci=idx(/data-glx-i="(\d+)"[^>]*title="7 fn/);
const mk=(i,tag)=>{ const e=new El(tag||'span'); e.dataset.glxI=String(i); e.closest=()=>e; return e; };
const fire=(e,type,key)=>{ const ev={target:e, key:key, prevented:false, preventDefault(){ this.prevented=true; }}; (root.listeners[type]||[]).forEach(f=>f(ev)); return ev; };
const fe=mk(fi); const ev1=fire(fe,'click'); out.filter1=JSON.stringify(calls); out.prevented=ev1.prevented; out.onAfter=fe.classList.contains('on');
fe.classList.add('on'); fire(fe,'click'); out.filter2=JSON.stringify(calls[1]||null);
fire(fe,'keydown','Enter'); out.kbd=calls.length===3; fire(fe,'keydown','a'); out.kbdOther=calls.length===3;
fire(mk(ci),'click'); out.custom=custom;
out.num=[glanceNum(1234), glanceNum(null), glanceNum('—'), glanceNum(0)].join('|');
// v2 suffix, onClick+href, ranked vt + more footer
HOST.children=[]; let fh=0;
const r2=renderGlance('host',[{title:'x', hero:{v:57, v2:'44.5%', l:'owned'},
  chips:[{v:'3', l:'both', href:'/agents/argos/page.html?target=a', onClick:()=>fh++}],
  ranked:{items:[{label:'p', value:12, vt:'12%'}], more:'+4 more', moreHref:'#secY'}}]);
const h2=HOST.children[0].innerHTML;
out.v2=h2.indexOf('<small class="glx-v2">44.5%</small>')>=0; out.vt=h2.indexOf('<b>12%</b>')>=0;
out.more=/class="glx-more glx-act" href="#secY"[^>]*>\+4 more</.test(h2);
const bi=(h2.match(/href="\/agents\/argos\/page.html\?target=a" data-glx-i="(\d+)"/)||[])[1];
const be=new El('a'); be.dataset.glxI=String(bi); be.closest=()=>be;
const fire2=(ev)=>{ (r2.listeners['click']||[]).forEach(f=>f(ev)); return ev; };
const e1=fire2({target:be, prevented:false, preventDefault(){ this.prevented=true; }});
const e2=fire2({target:be, ctrlKey:true, prevented:false, preventDefault(){ this.prevented=true; }});
out.both=bi!=null && fh===1 && e1.prevented && !e2.prevented;
// a chip with both t and u: the tooltip keeps the u detail (a chip shows no u line); no doubling when t has it
HOST.children=[];
renderGlance('host',[{title:'x', chips:[{v:'2', l:'no owner', t:'apps lacking owners', u:'22 assets carry no Owner tag'},
  {v:'3', l:'dup', t:'3 dup — 9 rows', u:'9 rows'}]}]);
const h3=HOST.children[0].innerHTML;
out.tipU=h3.indexOf('title="apps lacking owners — 22 assets carry no Owner tag"')>=0 && h3.indexOf('title="3 dup — 9 rows"')>=0;
// keyboard toggle where the page redraws the glance: focus moves to the new chip with the same filter
HOST.children=[]; let focused=null;
const nu={focus:()=>{ focused='new'; }};
document.body={contains:()=>false}; document.querySelector=q=>q.indexOf('data-glx-f="f:k"')>=0?nu:null; HOST.id='';
const r4=renderGlance('host',[{title:'x', chips:[{v:'1', l:'k', filter:'f:k'}]}], {onFilter:()=>{}});
const k4=(HOST.children[0].innerHTML.match(/data-glx-f="f:k" data-glx-i="(\d+)"/)||[])[1];
const ke=new El('span'); ke.dataset.glxI=String(k4); ke.closest=()=>ke;
(r4.listeners['keydown']||[]).forEach(f=>f({type:'keydown', key:'Enter', target:ke, preventDefault(){}}));
out.refocus=focused==='new';
process.stdout.write(JSON.stringify(out));
"""
    with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False, encoding="utf-8") as t:
        t.write(harness)
    try:
        r = subprocess.run([NODE, t.name], capture_output=True, text=True, timeout=60)
    finally:
        os.unlink(t.name)
    check(r.returncode == 0, "node harness ran (%s)" % r.stderr.strip()[:300])
    o = json.loads(r.stdout or "{}") if r.returncode == 0 else {}
    check(o.get("returned") and o.get("cls") == "glx", "renderGlance returns the .glx root it mounted")
    check(not o.get("raw") and o.get("escaped"), "hostile text is escaped (no raw <img>)")
    check(not o.get("inline"), "no inline on*= handler in the rendered HTML")
    check(not o.get("js") and not o.get("heroLink"), "javascript: href dropped by safeHref (headline not a link)")
    check(o.get("link") and o.get("anchor"), "same-origin '/…' and '#…' hrefs kept (escaped)")
    check(not o.get("badColor") and o.get("series"), "bar colours: unsafe values replaced by the palette; sev + s1…s8 resolve to tokens")
    check(o.get("zeroHero") and o.get("zeroChip") and o.get("rankedZero"), "zero headline / chip / ranked row dimmed (.glx-zero)")
    check(o.get("notZero") and o.get("commaNotZero"), "zero:false overrides; '1,234' is not zero")
    check(o.get("active"), "opts.active marks the active filter chip (.on, aria-pressed)")
    check(o.get("roles", 0) >= 3, "filter / onClick items are focusable buttons (role + tabindex)")
    check(o.get("empty"), "ranked.empty shown when there are no items")
    check(o.get("filter1") == '[["f:x",true]]' and o.get("prevented") and o.get("onAfter"),
          "filter click → opts.onFilter(filter, el, true) and the chip gets .on")
    check(o.get("filter2") == '["f:x",false]', "clicking the active chip again → onFilter(filter, el, false)")
    check(o.get("kbd") and o.get("kbdOther"), "Enter activates a focused chip; other keys don't")
    check(o.get("custom") == 1, "onClick handler fires via the delegated listener")
    check(o.get("num") == "1,234|—|—|0", "glanceNum formats counts (null → —)")
    check(o.get("v2") and o.get("vt") and o.get("more"), "v2 suffix, ranked vt display text and the 'more' footer render")
    check(o.get("both"), "onClick + href: a click runs the handler; ctrl/cmd-click follows the link")
    check(o.get("tipU"), "a chip's tooltip keeps its u detail line when t lacks it (customapp 'no Owner tag' count)")
    check(o.get("refocus"), "keyboard filter toggle that redraws the glance keeps focus on the same chip")

# readability (build 449): group / ranked titles have their own colour; the faint grey is readable
def _lum(h):
    c = [int(h[i:i + 2], 16) / 255 for i in (1, 3, 5)]
    c = [x / 12.92 if x <= 0.03928 else ((x + 0.055) / 1.055) ** 2.4 for x in c]
    return 0.2126 * c[0] + 0.7152 * c[1] + 0.0722 * c[2]
def _cr(a, b):
    a, b = _lum(a), _lum(b)
    return (max(a, b) + .05) / (min(a, b) + .05)
_K = re.search(r"\.glx-k\{[^}]*\}", CSS).group(0); _RT = re.search(r"\.glx-rt\{[^}]*\}", CSS).group(0)
check("var(--glx-title)" in _K and "var(--glx-title)" in _RT, "glance titles use --glx-title, not the faint grey")
_LB = re.compile(r'\[data-theme="light"\]\{[^}]*\}')
_dark = _LB.sub("", CSS)                         # tokens outside the light-theme blocks
_lightblk = "\n".join(_LB.findall(CSS))
_tok = lambda blk, name: re.search(r"--%s:(#[0-9a-fA-F]{6})" % name, blk).group(1)
for _nm, _blk, _bgs in (("dark", _dark, ("panel", "panel-2", "bg")), ("light", _lightblk, ("panel", "panel-2", "bg"))):
    for _fg in ("ink-3", "glx-title"):
        _w = min(_cr(_tok(_blk, _fg), _tok(_blk, b)) for b in _bgs)
        check(_w >= 4.5, "%s: --%s is readable on every panel (worst %.1f:1, need ≥ 4.5)" % (_nm, _fg, _w))

# placement (build 450): the glance is its own "📊 At a glance" section — the first jump-nav
# section, right under the header card — never inside the header (description + ▶ Run)
MOVED = {"identity": "metrics", "ai": "metrics", "fused_score": "kpis", "postquantum": "metrics", "mitre": "metrics",
         "customapp": "metrics", "scan_eval": "metrics", "attackpath": "metrics", "certificate": "metrics",
         "cisakev": "metrics", "eol": "metrics", "exproute": "kpi", "sla": "kpi"}
for _p, _cid in MOVED.items():
    _h = read("agents/%s/page.html" % _p)
    _secs = list(re.finditer(r'<section\b[^>]*>', _h))
    _nav = [m for m in _secs if "data-nav=" in m.group(0)]
    _g = next((m for m in _secs if 'id="secGlance"' in m.group(0)), None)
    _ok = bool(_g) and 'data-nav="At a glance"' in _g.group(0) and _nav and _nav[0].start() == _g.start()
    _end = _h.index("</section>", _g.end()) if _g else -1
    _inside = _g is not None and _g.end() < _h.find('id="%s"' % _cid) < _end
    _hdr = _h[_secs[0].start():_h.index("</section>", _secs[0].end())] if _secs else ""
    check(_ok and _inside and 'id="%s"' % _cid not in _hdr and "data-run" in _hdr,
          "%s: At a glance is its own first jump-nav section (#%s inside it, not in the header)" % (_p, _cid))
for _p in MIGRATED:
    _h = read(_p)
    check(re.search(r'data-nav(-label)?="At a glance"|sec\(\'secGlance\',\'At a glance\'', _h) is not None,
          "%s: the glance is a jump-nav section" % _p)
    check("<b>At a glance</b> —" not in _h, "%s: no inline '📊 At a glance —' line left in a header" % _p)

check(re.search(r"\.glx-c b,\.glx-h b\{[^}]*text-overflow:ellipsis", CSS) is not None,
      "console.css: long chip / headline values truncate (a hostname can't push its label out)")

print(f"\n{len(fails)} failure(s)")
sys.exit(1 if fails else 0)
