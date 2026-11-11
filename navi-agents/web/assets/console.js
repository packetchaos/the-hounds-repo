/* Navi Agents — shared front-end helpers used by the hub and every agent page. */

/* ===== Hound page cache — come back to where you left off ======================
   Every agent page keeps its last run in this browser's IndexedDB. Navigate away
   and come back: the inputs are refilled, the page's ▶ buttons are replayed in the
   same order, and every read it makes is answered from the local copy instead of
   re-running the agent. A strip under the header shows the age, ↻ Re-run (fresh,
   bypasses the server cache too) and ✕ Clear.

   Opting a page in: put data-run on each button that produces results — the
   primary ▶ Run plus any later read phase (✨ Ask, ▶ Run Sankey, ▶ Run SQL…).
   <body data-autorun> marks a page that loads its results by itself on open (its
   load-time reads are cached too, and its pickers are restored).
   <body data-page-cache="off"> turns the cache off for a page that loads a live list on
   open (ACR, Agent Groups, Tag Removal…) — those must always show the current state.
   <body data-cache-inputs="off"> skips saving/restoring fields — for editors whose
   fields mirror server state (Contract, Alert), where stale values would fight the
   live config.
   Writes are never stored or replayed: tag / apply / send / delete … actions,
   anything sent with confirm:true, and live status endpoints always go to the
   server — and while a page is being restored, any write it fires is swallowed.
   Tunables (localStorage): houndsCacheTTLh (hours, default 24), houndsCacheOff=1. */
/* ===== Request budgets — the UI side of core/launcher.request_scope (build 455) =============
   Every same-origin POST /api/<agent>/<action> carries
     X-Hounds-Tab: <random id for this tab's page>  — a newer identical request from this tab
                   supersedes (cancels) the older one on the server;
     X-Hounds-Budget: open | run  — "open" until the user first clicks a ▶ Run button
                   ([data-run] or a ▶ label) or presses Enter in its query box on this page,
                   "run" after (a ?run=1 hand-off, a page-cache replay and the banner's own
                   buttons count as runs). A caller that sets the header itself wins.
   A response that says {budget:true} (stopped by its budget / cancel / row cap) or
   {budget_partial:true} (answered, but some part hit the budget) raises ONE standard banner
   with the server's message|budget_message, a "Run in background" button (re-sends that read
   with background:true — the job budget applies — then re-runs the page's last ▶ to show the
   result the job left in the server cache) and, when the payload says optimize, a link to
   Settings → ⚡ Optimize. budget_partial answers are never stored in the page cache (HC). */
const H_WRITE_RE = /^(apply|bulk_apply|assign|tag|tag_.+|.+_tag|tags_.+|send|send_.+|delete|remove|rotate|encrypt|decrypt|refresh|save|set|set_.+|.+_set|toggle|add_.+|arm|disarm|run_now|command|upload|push_file|campaign|abort|verify|run_checks|cred_test|path_check|deploy|rollback|promote|ignore_.+|detections_.+|evaluate|test|trust|run_all|reset_usage|navi_.+|build_from_.+)$/;
const H_READ_OK = new Set(['tag_plan','os_plan','detections_export']);   // read actions whose names look like writes
const HB = (function(){
  const TAB = Date.now().toString(36)+Math.random().toString(36).slice(2,10);
  const S = { ran: /(?:^|[?&])run=1(?:&|$)/.test(location.search), lastBtn:null, last:null, seq:0 };
  const API_RE = /^\/api\/([a-z0-9_]+)\/([a-z0-9_]+)$/;
  function markRun(btn){ S.ran=true; if(btn && btn.id) S.lastBtn=btn.id; }
  const isRunBtn = b => !!b && (b.hasAttribute('data-run') || /^\s*▶/.test(b.textContent||''));
  document.addEventListener('click', ev=>{
    if(!ev.isTrusted) return;
    const b=ev.target && ev.target.closest && ev.target.closest('button,a[data-run]');
    if(b && !b.disabled && isRunBtn(b) && !b.closest('#hbBanner')) markRun(b);
  }, true);
  document.addEventListener('keydown', ev=>{
    if(!ev.isTrusted || ev.key!=='Enter' || ev.isComposing) return;
    const t=ev.target; if(!t || !/^(INPUT|TEXTAREA)$/.test(t.tagName)) return;
    if(t.tagName==='TEXTAREA' && !(ev.ctrlKey||ev.metaKey)) return;
    let n=t.parentElement, b=null;
    while(n && n!==document.body && !b){ b=[...n.querySelectorAll('button')].find(isRunBtn)||null; if(n.tagName==='SECTION') break; n=n.parentElement; }
    if(b) markRun(b);
  }, true);

  function apiPath(url){ try{ const p=new URL(url, location.href); if(p.origin!==location.origin) return null;
    const m=p.pathname.match(API_RE); return m ? {agent:m[1], action:m[2], path:p.pathname} : null; }catch(e){ return null; } }
  const _fetch = window.fetch ? window.fetch.bind(window) : null;
  if(_fetch) window.fetch = async function(input, init){
    const url = typeof input==='string' ? input : (input && input.url) || '';
    const method = String((init && init.method) || (input && input.method) || 'GET').toUpperCase();
    const ap = method==='POST' ? apiPath(url) : null;
    if(!ap || (input && typeof input!=='string' && !init)) return _fetch(input, init);
    const h = new Headers((init && init.headers) || {});
    if(!h.has('X-Hounds-Tab')) h.set('X-Hounds-Tab', TAB);
    if(!h.has('X-Hounds-Budget')) h.set('X-Hounds-Budget', S.ran ? 'run' : 'open');
    init = Object.assign({}, init, {headers:h});
    const r = await _fetch(input, init);
    if(r.status===200 && ap.agent!=='hub' && ap.agent!=='jobs'){
      const len=+(r.headers.get('Content-Length')||0);
      if(!(len > 16e6)) r.clone().text().then(t=>{
        if(t.indexOf('"budget')<0) return;
        let j; try{ j=JSON.parse(t); }catch(e){ return; }
        if(j && typeof j==='object' && (j.budget===true || j.budget_partial===true))
          show(j, ap, typeof init.body==='string' ? init.body : null);
      }).catch(()=>{});
    }
    return r;
  };

  /* ---- the standard banner ---- */
  function style(){ if(document.getElementById('hbStyle')) return;
    const st=document.createElement('style'); st.id='hbStyle';
    st.textContent='.hb-banner{display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin:0 0 12px;padding:8px 12px;border:1px solid var(--line);border-left:3px solid var(--warn,#d9a400);border-radius:var(--radius-sm,8px);background:var(--panel-2);font-size:13px;color:var(--ink-2,var(--ink));overflow-wrap:anywhere}.hb-banner b{color:var(--ink)}.hb-banner .hb-msg{flex:1 1 260px;min-width:0}.hb-banner .hb-acts{display:flex;gap:6px;flex-wrap:wrap;align-items:center}';
    (document.head||document.documentElement).appendChild(st); }
  function hide(){ const b=document.getElementById('hbBanner'); if(b) b.remove(); }
  function canBackground(ap, body){
    if(!body) return false;
    let b; try{ b=JSON.parse(body); }catch(e){ return false; }
    if(!b || typeof b!=='object' || Array.isArray(b) || 'confirm' in b || b.background) return false;
    if(H_WRITE_RE.test(ap.action) && !H_READ_OK.has(ap.action)) return false;
    return ['hub','settings','jobs','profile'].indexOf(ap.agent)<0;
  }
  function show(j, ap, body){
    if(!document.body) return;
    style(); hide();
    const partial = !j.budget && j.budget_partial;
    const msg = String((partial ? (j.budget_message||j.message) : (j.message||j.budget_message||j.error)) || 'This request hit its time budget.');
    const bg = canBackground(ap, body);
    const d=document.createElement('div'); d.id='hbBanner'; d.className='hb-banner'; d.setAttribute('role','status');
    d.innerHTML='<span class="hb-msg">⏱ <b>'+(partial?'Partial result':(j.cancelled?'Stopped':'Stopped at its time budget'))+'</b> · '+esc(msg)+'</span>'+
      '<span class="hb-acts">'+
      (bg?'<button class="btn sm" type="button" id="hbBg" title="Re-send this read as a background job (the 45-min job budget applies); track it in the Runs log">⏳ Run in background</button>':'')+
      (j.optimize?'<a class="btn ghost sm" id="hbOpt" href="/web/settings.html#secHx" title="Build the Hounds\' indexes on navi.db">⚡ Optimize (Settings)</a>':'')+
      '<button class="btn ghost sm" type="button" id="hbX" aria-label="Dismiss">✕</button></span>';
    const wrap=document.querySelector('.wrap')||document.body;
    const first=[...wrap.children].find(e=>e.id!=='actv' && e.id!=='hcBanner' && e.classList && e.classList.contains('card'));
    if(first) wrap.insertBefore(d, first); else wrap.prepend(d);
    d.querySelector('#hbX').onclick=hide;
    if(bg) d.querySelector('#hbBg').onclick=()=>background(d, ap, body);
  }
  async function background(d, ap, body){
    const my=++S.seq; markRun(null);
    const b=JSON.parse(body); delete b._run; delete b._nocache; b.background=true;
    const acts=d.querySelector('.hb-acts'), m=d.querySelector('.hb-msg');
    acts.innerHTML='<span class="spin"></span>';
    let st; try{ st=await (await window.fetch(ap.path, {method:'POST', headers:{'Content-Type':'application/json','X-Hounds-Budget':'run'}, body:JSON.stringify(b)})).json(); }catch(e){ st={ok:false, error:e.message}; }
    if(!st || !st.job_id){
      if(st && st.ok!==false){ m.innerHTML='✓ <b>Already computed</b> · the server had this result cached.'; acts.innerHTML=again(); wire(d); }
      else { m.innerHTML='✗ '+esc((st&&(st.error||st.message))||'could not start a background run'); acts.innerHTML='<button class="btn ghost sm" type="button" id="hbX">✕</button>'; d.querySelector('#hbX').onclick=hide; }
      return; }
    try{ hJobBadge(); }catch(e){}
    m.innerHTML='⏳ <b>Running in the background</b> · job #'+esc(st.job_id)+' — you can leave this page; it is in the <a href="/web/agent-runs.html">Runs log</a>.';
    acts.innerHTML='<span class="spin"></span>';
    for(;;){
      await new Promise(r=>setTimeout(r, 2000)); if(my!==S.seq || !d.isConnected) return;
      let j; try{ j=((await (await fetch('/api/jobs/'+encodeURIComponent(st.job_id))).json())||{}).job; }catch(e){ continue; }
      if(!j) return;
      if(j.status==='done' || j.status==='error'){
        try{ hJobBadge(); }catch(e){}
        const res=j.result||{}, bad=j.status==='error' || res.ok===false;
        if(bad){ m.innerHTML='✗ <b>Background run stopped</b> · '+esc(res.message||res.error||j.message||'failed'); acts.innerHTML='<a class="btn ghost sm" href="/web/agent-runs.html">Runs log</a><button class="btn ghost sm" type="button" id="hbX">✕</button>'; d.querySelector('#hbX').onclick=hide; return; }
        m.innerHTML='✓ <b>Finished in the background</b>'+(st.cached_result===false?' · see the result in the <a href="/web/agent-runs.html">Runs log</a>.':' · the server kept the result for a few minutes.');
        acts.innerHTML = st.cached_result===false ? '<button class="btn ghost sm" type="button" id="hbX">✕</button>' : again();
        wire(d); return; }
    }
  }
  function again(){ const b=S.lastBtn && document.getElementById(S.lastBtn);
    return (b?'<button class="btn run sm" type="button" id="hbShow">▶ Show results</button>':'')+'<button class="btn ghost sm" type="button" id="hbX">✕</button>'; }
  function wire(d){ const x=d.querySelector('#hbX'); if(x) x.onclick=hide;
    const s=d.querySelector('#hbShow'); if(s) s.onclick=()=>{ const b=document.getElementById(S.lastBtn); hide(); if(b) b.click(); }; }
  return { tab:TAB, markRun, hasRun:()=>S.ran, show, hide };
})();

const HC = (function(){
  const ENABLED = location.pathname.startsWith('/agents/') &&
                  !(document.body && document.body.dataset.pageCache==='off') &&   // live-list pages opt out
                  !(function(){ try{ return localStorage.getItem('houndsCacheOff')==='1'; }catch(e){ return false; } })();
  const KEY = location.pathname + location.search;
  const TTL_MS = (function(){ let h=24; try{ const v=parseFloat(localStorage.getItem('houndsCacheTTLh')); if(v>0) h=v; }catch(e){} return h*3600e3; })();
  const MAX_PAGES = 80;
  // never cached: writes + live state. Mirrors core/launcher._MUTATING and widens it.
  const WRITE_RE = H_WRITE_RE;   // shared with HB (request budgets)
  const LIVE_RE  = /^(status|log|loop_log|history|scheduler|list|get|applied|metrics|verify_tags|tags_compare|which_agent|activity)$/;
  const SKIP_AGENTS = new Set(['jobs','profile','settings','hub']);
  const READ_OK = H_READ_OK;
  const S = { on:ENABLED, key:KEY, mode:'live', entry:null, inflight:0, last:0, steps:[], dirty:false, ready:null, runCtx:false,
              src:'server', onServer:false, respDirty:false };
  // body keys a page leaves out of its cache key (<body data-cache-ignore="fp,allow">): values
  // that live in one browser's localStorage, so another browser's replay still matches
  const IGNORE = new Set(((document.body && document.body.dataset.cacheIgnore)||'').split(',').map(x=>x.trim()).filter(Boolean));
  /* requests set off by a real ▶ Run / Run all / Enter are this hound's "runs" — mark them
     until the page goes quiet, so the server can keep a durable last-run history */
  let _runSeq=0;
  function startRunCtx(){ const my=++_runSeq;
    if(!S.runCtx) S.runCtx=Date.now().toString(36)+Math.random().toString(36).slice(2,6);   // one id per run (Run all = one run)
    setTimeout(async()=>{ await quiet(30*60e3); if(my===_runSeq){ S.runCtx=null; try{ window.dispatchEvent(new Event('hounds:ran')); }catch(e){} } }, 150); }

  /* ---- storage: the SERVER keeps every page's entry (core/pagecache.py via /api/hub/pc_*),
     so it is shared across browsers and Release the Hounds can fill it. This browser's
     IndexedDB is only a fallback for when the server can't be reached. ---- */
  const _rawFetch = window.fetch ? window.fetch.bind(window) : null;
  async function srv(action, body){
    const r = await _rawFetch('/api/hub/'+action, {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(body||{})});
    if(!r.ok && r.status!==400) throw new Error('page cache: HTTP '+r.status);
    return r.json(); }
  // the newer of the server's copy and this browser's fallback copy (a run saved here while
  // the server was down, or one too large for the server, must not lose to an older server copy)
  async function cacheGet(k){
    let sv=null, ok=true; try{ const o=await srv('pc_get',{key:k}); sv=(o&&o.entry)||null; }catch(e){ ok=false; }
    const lo=await idbGet(k);
    if(lo && (!sv || (lo.at||0)>(sv.at||0))){ S.src='browser'; return lo; }
    S.src= ok?'server':'browser'; return sv; }
  async function cachePut(v){
    try{ const o=await srv('pc_put',{key:v.key, entry:v}); if(!o||!o.ok) throw new Error((o&&o.error)||'refused');
      S.src='server'; S.onServer=true; idbDel(v.key); }
    catch(e){ S.src='browser'; S.onServer=false; await idbPut(v); prune(); } }
  // field edits after a run: send only the small fields, not every response again
  async function cachePatch(v){
    if(!S.onServer) return cachePut(v);
    try{ const o=await srv('pc_patch',{key:v.key, fields:{final:v.final, steps:v.steps, at:v.at, title:v.title}});
      if(o&&o.ok) return; }catch(e){}
    return cachePut(v); }
  async function cacheDel(k){ try{ await srv('pc_del',{key:k}); }catch(e){} return idbDel(k); }
  /* ---- tiny IndexedDB wrapper (fallback only) ---- */
  let _db=null;
  function idb(){ if(_db) return _db;
    _db = new Promise((res,rej)=>{ try{ const r=indexedDB.open('hounds-page-cache',1);
      r.onupgradeneeded=()=>r.result.createObjectStore('pages',{keyPath:'key'});
      r.onsuccess=()=>res(r.result); r.onerror=()=>rej(r.error); }catch(e){ rej(e); } });
    return _db; }
  async function tx(mode, fn){ const d=await idb(); return new Promise((res,rej)=>{
    const t=d.transaction('pages',mode); const st=t.objectStore('pages'); let out; const r=fn(st);
    if(r) r.onsuccess=()=>{ out=r.result; }; t.oncomplete=()=>res(out); t.onerror=()=>rej(t.error); t.onabort=()=>rej(t.error); }); }
  const idbGet = k => tx('readonly', st=>st.get(k)).catch(()=>null);
  const idbPut = v => tx('readwrite', st=>st.put(v)).catch(()=>null);
  const idbDel = k => tx('readwrite', st=>st.delete(k)).catch(()=>null);
  async function prune(){ try{ const all=await tx('readonly', st=>st.getAll());
    if(!all || all.length<=MAX_PAGES) return;
    all.sort((a,b)=>(a.at||0)-(b.at||0)).slice(0, all.length-MAX_PAGES).forEach(e=>idbDel(e.key)); }catch(e){} }

  /* ---- request classification ---- */
  function stable(o){ if(o==null||typeof o!=='object') return JSON.stringify(o);
    if(Array.isArray(o)) return '['+o.map(stable).join(',')+']';
    return '{'+Object.keys(o).sort().map(k=>JSON.stringify(k)+':'+stable(o[k])).join(',')+'}'; }
  function classify(url, method, body){
    let p; try{ p=new URL(url, location.href); }catch(e){ return null; }
    if(p.origin!==location.origin) return null;
    const m=p.pathname.match(/^\/api\/([a-z0-9_]+)\/([a-z0-9_]+)$/); if(!m) return null;
    const agent=m[1], action=m[2];
    let b={}; if(body){ try{ b=JSON.parse(body); }catch(e){ b=null; } }
    const write = (WRITE_RE.test(action) && !READ_OK.has(action)) || (agent==='contract' && action==='load') || !!(b && b.confirm);
    if(write) return {write:true};
    if(!b || SKIP_AGENTS.has(agent) || LIVE_RE.test(action) || b.background) return null;
    const k={}; for(const x in (b||{})) if(!/^(_label|_nocache|_run|refresh)$/.test(x) && !IGNORE.has(x)) k[x]=b[x];
    return { key: method+' '+p.pathname+' '+stable(k), body:b };
  }

  /* ---- fetch interception: serve from the local copy while replaying, record always ---- */
  if(ENABLED && window.fetch){
    const _fetch = window.fetch.bind(window);
    window.fetch = async function(input, init){
      const url = typeof input==='string' ? input : (input && input.url) || '';
      const method = String((init && init.method) || (input && input.method) || 'GET').toUpperCase();
      const info = classify(url, method, init && typeof init.body==='string' ? init.body : null);
      if(!info) return _fetch(input, init);
      await S.ready;
      if(info.write){
        // a replay only ever clicks reads; a write here is a side-effect (e.g. an autosave
        // fired by a restored field) — swallow it rather than change anything server-side.
        if(S.mode!=='live') return new Response(JSON.stringify({ok:false, skipped:true,
          error:'write skipped while restoring this page from the local cache'}), {status:200, headers:{'Content-Type':'application/json'}});
        if(S.mode==='live') setTimeout(()=>{ try{ window.dispatchEvent(new Event('hounds:wrote')); }catch(e){} }, 1500);
        return _fetch(input, init);
      }
      S.last = Date.now();
      if(S.mode==='replay' && S.entry && S.entry.resp && S.entry.resp[info.key]){
        const c=S.entry.resp[info.key];
        let b=c.body; if(b && typeof b==='object' && !Array.isArray(b)) b=Object.assign({}, b, {_replayed:true});
        return new Response(JSON.stringify(b), {status:c.status||200, headers:{'Content-Type':'application/json'}});
      }
      const extra = {};
      if(S.mode==='fresh' && method==='POST') extra._nocache = true;
      if(S.runCtx && S.mode==='live' && method==='POST') extra._run = S.runCtx;   // durable run history (core/activity.py)
      if(Object.keys(extra).length) init = Object.assign({}, init, {body: JSON.stringify(Object.assign({}, info.body, extra))});
      S.inflight++;
      try{
        const r = await _fetch(input, init);
        try{ if(r.status<400){ const j=await r.clone().json();
          // a budget-limited answer (ok:false budget / ok:true budget_partial) is never stored
          if(!(j && typeof j==='object' && (j.ok===false || j.budget || j.budget_partial))) record(info.key, r.status, j); } }catch(e){}
        return r;
      } finally { S.inflight--; S.last=Date.now(); }
    };
  }

  function blank(){ return {key:KEY, at:Date.now(), title:document.title, steps:[], final:null, resp:{}}; }
  function record(k, status, body){
    if(!S.entry) S.entry = blank();
    S.entry.resp[k] = {status, body}; S.respDirty=true;
    const ks=Object.keys(S.entry.resp); if(ks.length>250) delete S.entry.resp[ks[0]];
    persistSoon();
  }
  /* write-through: save as soon as a result lands (coalesced), never on unload —
     browsers abort IndexedDB writes started while a page is being torn down. */
  let _busy=false, _again=false;
  function persistSoon(){ if(_busy){ _again=true; return; } _busy=true;
    Promise.resolve().then(persist).catch(()=>{}).then(()=>{ _busy=false; if(_again){ _again=false; persistSoon(); } }); }
  const autorun = () => !!(document.body && document.body.hasAttribute('data-autorun'));
  const PAGE_AGENT = (location.pathname.match(/^\/agents\/([^/]+)\//)||[])[1] || '';
  // a deep link (?uuid=…, ?q=…) that makes the page run itself on open counts as a run
  const deepLinkRun = e => !!location.search && Object.keys(e.resp||{}).some(k=>k.startsWith('POST /api/'+PAGE_AGENT+'/'));
  function worthKeeping(e){ return e && (e.steps.length || autorun() || deepLinkRun(e)); }
  async function persist(){ const e=S.entry; if(!worthKeeping(e)) return;
    e.title=document.title;
    if(S.respDirty || !S.onServer){ S.respDirty=false; await cachePut(e); }
    else await cachePatch(e); }
  let _editT=null;
  function persistEditSoon(){ clearTimeout(_editT); _editT=setTimeout(persistSoon, 1200); }

  /* ---- input snapshots (ids only; never passwords / files) ---- */
  const noInputs = () => !!(document.body && document.body.dataset.cacheInputs==='off');
  function fields(){ if(noInputs()) return [];
    return [...document.querySelectorAll('input[id],select[id],textarea[id]')]
    .filter(el=>!el.closest('#app-header') && !/^(password|file|hidden|button|submit)$/i.test(el.type||'')); }
  function snap(){ const o={}; fields().forEach(el=>{
      if(el.type==='checkbox'||el.type==='radio') o[el.id]={c:el.checked};
      else if(el.multiple) o[el.id]={m:[...el.selectedOptions].map(x=>x.value)};
      else o[el.id]={v:el.value}; }); return o; }
  const sleep = ms => new Promise(r=>setTimeout(r,ms));
  async function waitFor(fn, ms){ const t0=Date.now(); for(;;){ const v=fn(); if(v) return v; if(Date.now()-t0>ms) return null; await sleep(60); } }
  async function restore(o){ if(!o) return;
    for(const id in o){ const el=document.getElementById(id); if(!el) continue; const s=o[id];
      if(el.tagName==='SELECT' && s.v!=null && s.v!=='' && !el.multiple)
        await waitFor(()=>[...el.options].some(x=>x.value===s.v), 2500);
      let changed=false;
      if('c' in s){ if(el.checked!==s.c){ el.checked=s.c; changed=true; } }
      else if('m' in s){ [...el.options].forEach(x=>{ const w=s.m.includes(x.value); if(x.selected!==w){ x.selected=w; changed=true; } }); }
      else if(el.value!==s.v){ el.value=s.v; changed=true; }
      if(changed){ el.dispatchEvent(new Event('input',{bubbles:true})); el.dispatchEvent(new Event('change',{bubbles:true})); }
    } }
  async function quiet(max){ const t0=Date.now(); await sleep(60);
    while(Date.now()-t0 < (max||30000)){ if(S.inflight===0 && !window.__RUN_ALL_BUSY && Date.now()-S.last>350) return; await sleep(80); } }

  /* user-driven recording: a trusted click on a data-run button starts/extends the run */
  if(ENABLED){
    document.addEventListener('click', ev=>{
      if(!ev.isTrusted || S.mode!=='live') return;
      const b=ev.target.closest && ev.target.closest('button[data-run],a[data-run]'); if(!b || !b.id) return;
      if(!S.entry) S.entry=blank();
      const steps=S.entry.steps, i=steps.findIndex(s=>s.id===b.id);
      if(i>=0) steps.length=i;                       // re-running an earlier phase drops the later ones
      if(!steps.length) S.entry.at=Date.now();
      steps.push({id:b.id, inputs:snap()});
      delete S.entry.released; S.respDirty=true;     // the user's own run now, not a release's
      S.entry.final=null; persistSoon(); hideBanner(); startRunCtx();
    }, true);
    // Enter in a query box runs the page's ▶/✨ button for that box — record it as that button's step
    document.addEventListener('keydown', ev=>{
      if(!ev.isTrusted || S.mode!=='live' || ev.key!=='Enter' || ev.isComposing) return;
      const t=ev.target; if(!t || !/^(INPUT|TEXTAREA)$/.test(t.tagName)) return;
      if(t.tagName==='TEXTAREA' && !(ev.ctrlKey||ev.metaKey)) return;
      let n=t.parentElement, b=null;
      while(n && n!==document.body && !b){ b=n.querySelector('button[data-run][id]'); if(n.tagName==='SECTION') break; n=n.parentElement; }
      if(!b) return;
      if(!S.entry) S.entry=blank();
      const steps=S.entry.steps, i=steps.findIndex(s=>s.id===b.id);
      if(i>=0) steps.length=i;
      if(!steps.length) S.entry.at=Date.now();
      steps.push({id:b.id, inputs:snap()});
      delete S.entry.released; S.respDirty=true;
      S.entry.final=null; persistSoon(); hideBanner(); startRunCtx();
    }, true);
    const onEdit = ev=>{ if(!ev.isTrusted || S.mode!=='live') return;
      if(!S.entry){ if(!autorun()) return; S.entry=blank(); }
      if(!S.entry.steps.length && !autorun()) return;
      S.entry.final=snap(); persistEditSoon(); };
    document.addEventListener('input', onEdit, true);
    document.addEventListener('change', onEdit, true);
  }

  /* ---- banner ---- */
  function ago(t){ const s=Math.max(0,(Date.now()-t)/1000);
    if(s<60) return 'just now'; if(s<3600) return Math.round(s/60)+' min ago';
    if(s<86400) return Math.round(s/3600)+' h ago'; return Math.round(s/86400)+' d ago'; }
  function hideBanner(){ const b=document.getElementById('hcBanner'); if(b) b.remove(); }
  function showBanner(e, misses){
    if(!document.getElementById('hcStyle')){ const st=document.createElement('style'); st.id='hcStyle';
      st.textContent='.hc-banner{display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin:0 0 12px;padding:8px 12px;border:1px solid var(--line);border-left:3px solid var(--accent);border-radius:var(--radius-sm,8px);background:var(--panel-2);font-size:13px;color:var(--ink-2,var(--ink))}.hc-banner b{color:var(--ink)}.hc-banner .sp{flex:1}';
      document.head.appendChild(st); }
    hideBanner();
    const d=document.createElement('div'); d.id='hcBanner'; d.className='hc-banner';
    const rel=!!(e.released&&e.released.by==='release');
    d.innerHTML='<span>'+(rel?'🐾 Released by <a href="/">Release the Hounds</a> · <b>':'↺ Restored your last run · <b>')+ago(e.at)+'</b>'+
      ' <span class="sub">— saved '+(S.src==='browser'?'in this browser':'on the server')+(misses?' ('+misses+' read'+(misses>1?'s':'')+' fetched live)':'')+'</span></span>'+
      '<span class="sp"></span><button class="btn sm" type="button" id="hcRerun" title="Run again with fresh data (bypasses every cache)">↻ Re-run</button>'+
      '<button class="btn sm" type="button" id="hcClear" title="Forget this page\'s saved run">✕ Clear</button>';
    // sits under the codename strip and the Done so far panel, right above the page's own cards
    const wrap=document.querySelector('.wrap')||document.body;
    const first=[...wrap.children].find(e=>e.id!=='actv' && e.id!=='hcBanner' && e.classList.contains('card'));
    if(first) wrap.insertBefore(d, first); else wrap.prepend(d);
    d.querySelector('#hcRerun').onclick=()=>rerun();
    d.querySelector('#hcClear').onclick=()=>clear();
  }

  /* ---- replay driver ---- */
  async function drive(fresh){
    const e=S.entry; let misses=0;
    try{ HB.markRun(null); }catch(err){}   // a replay re-runs the page's ▶ steps: run budget
    const before=Object.keys(e.resp).length;
    for(const st of e.steps){
      await restore(st.inputs);
      // optional step (e.g. ✓ Approve on a download hound): clicked only if it is showing
      const b=await waitFor(()=>{ const x=document.getElementById(st.id); return x && !x.disabled && (!st.optional || x.offsetParent) ? x : null; },
                            st.optional ? 1500 : 6000);
      if(!b){ if(st.optional) continue; break; }
      b.click(); await quiet();
    }
    if(e.final){ await restore(e.final); await quiet(); }
    misses = fresh ? 0 : Math.max(0, Object.keys(e.resp).length-before);
    S.mode='live';
    if(fresh){ e.at=Date.now(); delete e.released; S.respDirty=true; await persist(); }
    else showBanner(e, misses);
  }
  function rerun(){ try{ sessionStorage.setItem('hcFresh:'+KEY,'1'); }catch(e){} location.reload(); }
  async function clear(){ await cacheDel(KEY); S.entry=null; location.reload(); }

  S.ready = (async()=>{
    if(!ENABLED) return;
    let fresh=false; try{ fresh=sessionStorage.getItem('hcFresh:'+KEY)==='1'; sessionStorage.removeItem('hcFresh:'+KEY); }catch(e){}
    const e = await cacheGet(KEY);
    // expired for THIS browser's TTL → just don't replay it (the shared server copy stays
    // for other browsers; the server prunes)
    if(!e || !Array.isArray(e.steps) || !e.resp || (Date.now()-(e.at||0)) > TTL_MS) return;
    S.entry = e; S.onServer = S.src==='server';
    if(fresh){ e.resp={}; S.mode='fresh'; } else S.mode='replay';
  })();
  if(ENABLED) window.addEventListener('load', async()=>{
    await S.ready;
    if(S.mode==='live' || !S.entry) return;
    await sleep(30);                    // let the page's own load-time script bind its handlers
    try{ await drive(S.mode==='fresh'); }catch(err){ S.mode='live'; }
  });

  /* ---- ▶ Run all — for hounds with more than one ▶ Run step ----------------------
     Declarative: <button class="btn run sm" id="runAll" data-run data-run-all="load,pqcRun,…">▶ Run all</button>
     Clicks each step's button in order, waiting for it to finish (its button re-enabled
     and no API call in flight) before the next. A step whose button is still disabled
     after 60 s (e.g. needs an earlier result) is skipped. data-run on the Run-all button
     makes the page cache replay the whole sequence on return. */
  async function runAll(btn){
    if(window.__RUN_ALL_BUSY) return;
    const ids=(btn.dataset.runAll||'').split(',').map(x=>x.trim()).filter(Boolean);
    const label=btn.dataset.label||(btn.dataset.label=btn.innerHTML);
    window.__RUN_ALL_BUSY=true; btn.disabled=true; btn.classList.add('pressed');
    let done=0, skipped=[];
    try{
      for(let i=0;i<ids.length;i++){
        const step=await waitFor(()=>{ const x=document.getElementById(ids[i]); return x && !x.disabled ? x : null; }, 60000);
        if(!step){ skipped.push(ids[i]); continue; }
        const name=(step.textContent||'').replace(/^\s*▶\s*(Run\s*)?/,'').trim() || 'main run';
        btn.innerHTML='<span class="spin"></span> '+(i+1)+'/'+ids.length+' · '+esc(name);
        step.click(); await sleep(120);
        // finished = the step's button is enabled again and the page has gone quiet
        const t0=Date.now();
        while(Date.now()-t0 < 30*60e3){
          const x=document.getElementById(ids[i]);
          if((!x || !x.disabled) && S.inflight===0 && Date.now()-S.last>400) break;
          await sleep(100);
        }
        done++;
      }
    } finally {
      window.__RUN_ALL_BUSY=false; btn.disabled=false; btn.classList.remove('pressed'); btn.innerHTML=label;
      btn.title='Last run: '+done+'/'+ids.length+' steps'+(skipped.length?' · skipped '+skipped.join(', '):'');
    }
  }
  function wireRunAll(){ document.querySelectorAll('button[data-run-all]').forEach(b=>{ if(!b.__ra){ b.__ra=1; b.addEventListener('click',()=>runAll(b)); } }); }
  if(document.readyState==='loading') document.addEventListener('DOMContentLoaded', wireRunAll); else wireRunAll();

  return { state:S, rerun, clear, runAll,
           clearAll: async()=>{ try{ await srv('pc_del',{all:true}); }catch(e){} try{ const all=await tx('readonly', st=>st.getAllKeys()); (all||[]).forEach(idbDel); }catch(e){} },
           replaying: ()=>S.mode!=='live' };
})();


/* ---- theme (dark default; light toggle; persisted; honours OS on first paint) ---- */
const _SUN='<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="4.5"/><path d="M12 2v2M12 20v2M2 12h2M20 12h2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M19.1 4.9l-1.4 1.4M6.3 17.7l-1.4 1.4"/></svg>';
const _MOON='<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 12.8A8.5 8.5 0 1 1 11.2 3 6.6 6.6 0 0 0 21 12.8Z"/></svg>';
function getTheme(){
  let t=null; try{t=localStorage.getItem('naviTheme');}catch(e){}
  if(!t) t=(window.matchMedia&&window.matchMedia('(prefers-color-scheme: light)').matches)?'light':'dark';
  return t;
}
function applyTheme(t){
  if(t==='light') document.documentElement.setAttribute('data-theme','light');
  else document.documentElement.removeAttribute('data-theme');
  const b=document.getElementById('naviTheme');
  if(b) b.innerHTML=(t==='light'?_MOON:_SUN)+'<span>'+(t==='light'?'Dark':'Light')+'</span>';
}
function toggleTheme(){
  const next=getTheme()==='light'?'dark':'light';
  try{localStorage.setItem('naviTheme',next);}catch(e){}
  applyTheme(next);
}
applyTheme(getTheme());   // set <html> attribute ASAP to avoid flash
function _mountThemeBtn(){
  if(document.getElementById('naviTheme')) return;
  const b=document.createElement('button'); b.id='naviTheme'; b.type='button';
  b.setAttribute('aria-label','Toggle colour theme'); b.onclick=toggleTheme;
  document.body.appendChild(b); applyTheme(getTheme());
}
if(document.readyState!=='loading') _mountThemeBtn();
else document.addEventListener('DOMContentLoaded',_mountThemeBtn);

/* ---- handoff: read ?focus / ?run from the URL on agent pages ---- */
function handoffParams(){
  const q=new URLSearchParams(location.search);
  return {focus:(q.get('focus')||'').trim(), run:q.get('run')==='1', from:q.get('from')||''};
}
/* Highlight + scroll to the first table row containing `text` (case-insensitive). */
function focusRow(tableSel, text){
  if(!text) return false;
  const t=text.toLowerCase();
  const rows=document.querySelectorAll(tableSel+' tbody tr');
  for(const r of rows){
    if((r.textContent||'').toLowerCase().includes(t)){
      r.style.outline='2px solid var(--accent)'; r.style.outlineOffset='-2px';
      r.scrollIntoView({behavior:'smooth',block:'center'});
      setTimeout(()=>{r.style.transition='outline-color 1s ease';r.style.outlineColor='transparent';},2600);
      return true;
    }
  }
  return false;
}

async function jget(u){ const r = await fetch(u); return r.json(); }
async function jpost(u, b){
  const r = await fetch(u, {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(b||{})});
  return r.json();
}
const esc = s => String(s==null?'':s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
/* ---- URL hygiene for links built from data (navi.db fields, LLM output, catalogs) ----
   safeUrl(u)  → u only when it is an absolute http:/https: URL, else `fallback` ('#').
               Use for EXTERNAL links from data: assets.url, vulns.url, apps.target,
               findings.url, compliance see_also, catalog links … (javascript:, data:,
               vbscript:, file:, protocol-relative // and anything else → fallback).
   safeHref(u) → like safeUrl but also allows same-origin relative links ('/x', '#x',
               '?x') — for hrefs a server computed for in-console navigation.
   Always esc() the result when interpolating it into an attribute. */
function safeUrl(u, fallback){
  const v=String(u==null?'':u).trim();
  return /^https?:\/\/[^\s]/i.test(v) && !/[\u0000-\u001f]/.test(v) ? v : (fallback===undefined?'#':fallback);
}
function safeHref(u, fallback){
  const v=String(u==null?'':u).trim();
  if(/^(\/(?![\/\\])|#|\?)/.test(v) && !/[\u0000-\u001f]/.test(v)) return v;
  return safeUrl(v, fallback);
}
/* Defence in depth: a click on any link whose scheme is not http(s)/same-origin
   (javascript:, data:, vbscript:) is cancelled, wherever the link came from. */
document.addEventListener('click', e=>{ const a=e.target&&e.target.closest&&e.target.closest('a[href]'); if(!a) return;
  if(/^\s*(javascript|data|vbscript):/i.test(a.getAttribute('href')||'')){ e.preventDefault(); e.stopImmediatePropagation(); } }, true);
/* Only crest ids that belong to a known agent are rendered (ids come from LLM output). */
/* Image fallbacks without inline handlers: <img data-fb="hide"> hides itself on error,
   data-fb="ph" becomes the 🐾 placeholder tile, any other value becomes that text. */
document.addEventListener('error', e=>{ const im=e.target; if(!im||im.tagName!=='IMG'||!im.dataset||im.dataset.fb==null) return;
  const fb=im.dataset.fb; if(fb==='hide'){ im.style.display='none'; return; }
  if(fb==='ph'){ const d=document.createElement('div'); d.className='crestph'; d.textContent='🐾'; im.replaceWith(d); return; }
  im.replaceWith(document.createTextNode(fb||'🐾')); }, true);
function crestSrc(id){ return /^[a-z0-9_-]{1,40}$/i.test(String(id||'')) ? '/static/crests/'+encodeURIComponent(id)+'.png' : ''; }

/* Per-agent API helper: posts to /api/<agentId>/<action>.
   Every response is quietly scanned for the finding IDs + asset UUIDs + tag the agent just
   worked with, and offered to Gabriel via the floating "Email findings" button — the pack's
   uniform "second option" (email the findings, as an alternative/complement to tagging). */
function agentApi(agentId){
  window.__AGENT_ID = agentId;   // used by the header to show this agent's codename
  return {
    post: async (action, body) => { const r = await jpost(`/api/${agentId}/${action}`, body);
      try{ _harvestFindings(agentId, action, r, body); }catch(e){} return r; },
  };
}

/* Run a heavy agent action in the BACKGROUND (same pattern as the Tagging log).
 * Returns immediately with a job; polls the Runs log and resolves with the result
 * when it finishes. Usage:
 *   const res = await runAgentJob('insights','run',{}, {onStart:id=>…}); render(res);
 */
async function runAgentJob(agentId, action, payload, opts){
  opts = opts || {};
  const start = await jpost(`/api/${agentId}/${action}`,
    Object.assign({background:true}, payload||{}, opts.label?{_label:opts.label}:{}));
  if(!start || !start.job_id){          // server answered inline (cached / not backgrounded)
    if(opts.onDone) opts.onDone(start); return start;
  }
  if(opts.onStart) opts.onStart(start.job_id);
  try{ hJobBadge(); }catch(e){}
  const id = start.job_id;
  return await new Promise(resolve => {
    const tick = async () => {
      let o; try{ o = await jget(`/api/jobs/${id}`); }catch(e){ setTimeout(tick, 2000); return; }
      const j = o && o.job;
      if(!j){ if(opts.onError) opts.onError('job not found'); resolve(null); return; }
      if(j.status === 'done'){ try{hJobBadge();}catch(e){} if(opts.onDone) opts.onDone(j.result||{}); resolve(j.result||{}); return; }
      if(j.status === 'error'){ try{hJobBadge();}catch(e){} if(opts.onError) opts.onError(j.message||'failed'); resolve(null); return; }
      setTimeout(tick, 1500);           // queued / running — keep polling
    };
    tick();
  });
}

/* Header badge: N runs in progress → link to the Runs log (mirrors the tag log). */
async function hJobBadge(){
  const el = document.getElementById('runsBadge'); if(!el) return;
  try{
    const o = await jget('/api/jobs'); const c = (o && o.counts) || {};
    const active = (c.running||0) + (c.queued||0);
    el.innerHTML = active
      ? `<a class="chip" href="/web/agent-runs.html" title="Agent runs in progress" style="text-decoration:none;color:var(--accent)"><span class="spin"></span> ${active} run${active>1?'s':''}</a>`
      : `<a class="chip" href="/web/agent-runs.html" title="Runs + query profile + index advisor" style="text-decoration:none">🧾 Runs &amp; queries</a>`;
  }catch(e){ el.innerHTML=''; }
}
/* Deep-scan a run/tag response for asset UUIDs, plugin (finding) IDs, and a tag
   category:value, then registerFindings() so any agent gets the Gabriel hand-off for free.
   Named the email agent's own calls are ignored. */
const _UUID_RE=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
function _harvestFindings(agentId, action, resp, reqBody){
  if(agentId==='email' || !resp || typeof resp!=='object') return;
  if(/^(status|recipients|preview|send|meta|health|schema)$/.test(action||'')) return;
  const uu=new Set(), fids=new Set(); let tag=null;
  function walk(o,depth){
    if(!o || depth>6) return;
    if(Array.isArray(o)){ o.forEach(v=>walk(v,depth+1)); return; }
    if(typeof o!=='object') return;
    for(const k in o){ const v=o[k]; const lk=k.toLowerCase();
      if((lk==='uuid'||lk==='asset_uuid'||lk==='asset'||lk==='uuids'||lk==='asset_uuids')){
        (Array.isArray(v)?v:[v]).forEach(x=>{ if(typeof x==='string'&&x.length>=6&&x.length<80) uu.add(x); });
      }
      if(lk==='plugin_id'||lk==='plugin'||lk==='pid'||lk==='plugin_ids'){
        (Array.isArray(v)?v:[v]).forEach(x=>{ const s=String(x).trim(); if(/^\d{3,7}$/.test(s)) fids.add(s); });
      }
      if(!tag && o.category && o.value && typeof o.category==='string' && typeof o.value==='string')
        tag={category:o.category, value:o.value};
      if(typeof v==='string' && _UUID_RE.test(v)) uu.add(v);
      if(v && typeof v==='object') walk(v,depth+1);
    }
  }
  walk(resp,0);
  // The REQUEST body is an equally good (often BETTER) source: a tag action sends the
  // exact asset uuids / items it is tagging, while many agents' responses only echo a
  // count. Without this, those hounds (e.g. Pythia) hand Gabriel a tag but zero assets.
  walk(reqBody,0);
  // a tag the caller just requested (reqBody) is a good source too
  if(!tag && reqBody && reqBody.category && reqBody.value) tag={category:reqBody.category, value:reqBody.value};
  if(!uu.size && !fids.size && !tag) return;
  const cn=(typeof CODENAMES!=='undefined' && CODENAMES[agentId]) || null;
  const hound=cn ? cn.name.replace(/\s+Hound$/,'') : agentId;
  registerFindings({source_agent:agentId, source_hound:hound,
    headline:(cn?cn.name:agentId)+' findings',
    finding_ids:[...fids], asset_uuids:[...uu], tag:tag||undefined});
}

/* ---- Codenames + lore (the Hound Pack) — shown expandable in each agent header ---- */
const CODENAMES = {
  c2:{name:'Amarok',lore:'<b>Amarok</b>, the giant wolf of Inuit legend that hunts its quarry down alone in the night — here he is the pack\'s executor, carrying the operator\'s command to a single Linux host over SSH: run one order, ship it a file, or apply a patch drawn from the vulns table. He moves one host at a time, acts only when <b>armed</b> and confirmed, goes canary-first with stop-on-failure, and every push is written to the ledger.'},
  classify:{name:'Linnaeus',lore:'Carl <b>Linnaeus</b>, the father of taxonomy who gave every living thing its name and rank \u2014 here he classifies every asset by what it <i>is</i> (Windows / Linux / macOS / IoT / OT / network / hypervisor), from the OS field with a plugin-output fallback, so the rest of the pack knows exactly what each host is.'},
  was:{name:'Arachne',lore:'<b>Arachne</b>, the Aztec dog-god who guides souls through the shadow-world — here he walks your web apps\' hidden surface, the dynamic (DAST) findings that live behind the login and inside the request/response, mapping OWASP-class exposure a network scan never sees.'},
  sla:{name:'Sk\u00f6ll',lore:'<b>Sk\u00f6ll</b>, the wolf that forever chases the sun across the sky — here he chases every finding against its clock, surfacing the SLA breaches: what is overdue, by how long, and for whom, so remediation deadlines can\'t quietly slip.'},
  asset_ownership:{name:'Terminus',lore:'<b>Terminus</b>, the Roman god of boundary stones and property lines — he answers who owns each asset. Business leaders own groups of assets (Business Owner), technology owners hold routes &amp; paths (Owner, via Atlas), and a single Asset Owner can claim an asset\'s every route &amp; path. Surfaces what is unclaimed, what is blind, and what the pack knows about your crown jewels.'},
  fused_score:{name:'Nemesis',lore:'<b>Nemesis</b>, the goddess of retribution who brings the reckoning to what has earned it — here she fuses every Hound\'s signal into one exposure score per asset, surfaces the worst from each and where they converge, ranks the estate worst-first, and turns a remediation play into a projected reduction. The pack\'s convergence page.'},
  ex_apps:{name:'Vizsla',lore:'The <b>Vizsla</b> — a tireless pointer bred to range wide and mark its quarry — here it ranges the WAS inventory and points you at every web application navi has seen, so you can pick one and dig in.'},
  ex_fixed:{name:'Plott',lore:'The <b>Plott</b> — bays the moment it trees its quarry — here it trails the findings that have been <b>fixed</b> (closed / remediated), so you can prove what is actually put to bed versus what only looks quiet.'},
 certificate:{name:'Certania',lore:'Coined from <b>“certificate”</b> + the loyal hound. It stands watch over the chain of trust, sniffing out certificates about to expire.'},
 iot_squad:{name:'Cerberus Hound',lore:'<b>Cerberus</b>, the many-headed dog guarding the underworld’s gate. The IoT squad is a pack guarding the network edge — the unknown devices at the gate.'},
 acr:{name:'Anubis',lore:'<b>Anubis</b>, who weighs the heart against the feather of truth. ACR calibration weighs each asset’s <i>true</i> criticality.'},
 customapp:{name:'Cavall Hound',lore:'<b>Cavall Panoptes</b>, the giant with a hundred ever-open eyes. It sees the custom apps your inventory misses.'},
 mitre:{name:'Orthrus Hound',lore:'<b>Orthrus</b>, the two-headed dog and brother of Cerberus. It links two worlds — mapping CVEs to adversary ATT&CK techniques.'},
 eol:{name:'Charon',lore:'<b>Charon</b>, the ferryman across the Styx. It ferries end-of-life and unsupported software to its reckoning.'},
 dashboard:{name:'Daedalus',lore:'<b>Daedalus</b>, the master craftsman who built the Labyrinth. The dashboard builder crafts a custom view from one plain-English request.'},
 ai:{name:'Pythia',lore:'<b>Pythia</b>, the Oracle of Delphi. It finds the oracles in your estate — the AI/ML software and model hosts.'},
 identity:{name:'Janus',lore:'<b>Janus</b>, the two-faced god of doorways. Identity guards the doorways — accounts human and non-human, two faces each.'},
 scan_eval:{name:'Chronos',lore:'<b>Chronos</b>, the embodiment of time. Scan Evaluations measures where your scans spend their time.'},
 insights:{name:'Sphinx',lore:'<b>The Sphinx</b>, who guarded Thebes with riddles. “Unknown Unknowns” poses the gaps in your coverage back to you.'},
 exproute:{name:'Atlas',lore:'<b>Atlas</b>, the Titan who gave his name to the <i>atlas</i> — the book of maps. It maps exposure routes and paths to their owners.'},
 software:{name:'Mimir',lore:'<b>Mimir</b>, the Norse keeper of the well of wisdom. It remembers every software version in the estate and shows you the sprawl.'},
 tagremoval:{name:'Garmr Hound',lore:'<b>Garmr</b>, the blood-stained hound at the gates of Hel who howls at Ragnarök — the world’s cleansing. The tag-removal agent unmakes tags, clearing what no longer belongs before the pack re-tags.'},
 agentgroup:{name:'Sirius Hound',lore:'<b>Sirius</b>, the Dog Star — brightest in the sky, that marshals the lesser stars. It musters every Tenable agent into its group and tags it <span class="mono">Agent Group:&lt;name&gt;</span>.'},
 contract:{name:'Covenant',lore:'A <b>covenant</b> is a binding promise. It captures your tagging &amp; ACR policy once, then keeps it — planning first, executing only when armed, looping every few hours.'},
 cisakev:{name:'Laelaps Hound',lore:'<b>Laelaps</b>, the hound fated to always catch its quarry. It hunts down every <b>Known Exploited Vulnerability</b> — already proven caught in the wild — and tags it <span class="mono">CISA KEV:&lt;date&gt;</span>.'},
 postquantum:{name:'Heimdall',lore:'<b>Heimdall</b>, the ever-watchful guardian who sees to the ends of the world and hears the grass grow. It watches the <b>quantum horizon</b> — flagging the RSA/ECC crypto that won’t survive it.'},
 attackpath:{name:'Fenrir Hound',lore:'<b>Fenrir</b>, the great wolf the gods chained until, at Ragnarök, he breaks free and runs down his prey. The attack-path agent traces how a breach slips its chains — <b>foothold → lateral move → crown jewel</b>.'},
 ex_assets:{name:'Bloodhound',lore:'The <b>Bloodhound</b> — finest tracker of the pack. The asset explorer tracks any host across navi.db.'},
 ex_vulns:{name:'Hellhound',lore:'The <b>Hellhound</b> — a beast that hunts in the dark. The vulnerability explorer hunts findings by plugin, CVE, severity, VPR.'},
 ex_plugins:{name:'Foxhound',lore:'The <b>Foxhound</b> — bred to flush quarry from cover. The plugin explorer flushes out every distinct plugin.'},
 ex_routes:{name:'Wolfhound',lore:'The <b>Wolfhound</b> — large enough to run down a wolf. The route explorer runs down application routes.'},
 ex_paths:{name:'Greyhound',lore:'The <b>Greyhound</b> — fastest of the hounds. The path explorer sprints through filesystem paths.'},
 ex_tags:{name:'Basset',lore:'The <b>Basset</b> — nose held low, bred to read every scent mark on the trail. The tag explorer reads the marks the pack leaves — every tag category and value, and exactly which assets carry them.'},
 argos:{name:'Argos Hound',lore:'<b>Argos</b>, Odysseus’s faithful hound — the only one who knew his master’s true identity after twenty years. Give it one UUID or IP and it recognizes that asset across every table, telling its whole story.'},
 was_asset:{name:'Beagle',lore:'The <b>Beagle</b> — a scent hound that works a trail to map exactly where its quarry has been. Argos for web apps: point it at one app and it follows navi’s WAS info plugins to lay out the terrain — sitemap, scan telemetry, target facts, the screenshot, external URLs, cookies and methods — every plugin clickable to its raw stored output.'},
 compliance:{name:'Minos',lore:'<b>Minos</b>, the mythic judge who weighs each case and renders a verdict — here he weighs the estate against its audit benchmarks. Pass, fail, warning; the controls failing the most assets; how failures map to NIST, PCI, HIPAA, CIS and ISO — and a way to assign an Audit Owner to a control’s failing assets.'},
 custom_audit:{name:'Draco',lore:'<b>Draco</b>, the Athenian lawgiver who set down the first written legal code — here he turns a policy requirement into a written, enforceable Tenable <span class="mono">.audit</span> check. Describe the need in plain English and Claude drafts valid Nessus checks, or build one field-by-field from the platform catalog; Draco validates the syntax and auto-maps each check to its framework controls, then hands you a scan-ready file. Minos judges against benchmarks; Draco writes them.'},
 compliance_asset:{name:'Tiresias',lore:'<b>Tiresias</b>, the detective — point him at one asset and he lays out every audit check it passed, failed or warned (actual vs expected, the fix, the framework mappings), then infers the connection between a failed control and the real findings that back it, so a config gap and the vuln proving it can be tagged and routed together.'},
 advanced:{name:'Deerhound',lore:'The <b>Deerhound</b> — a great sighthound bred to run down big game over vast open ground. The advanced search ranges across every table at once, joining and filtering the whole estate.'},
 email:{name:'Gabriel',lore:'<b>Gabriel</b>, the messenger — the one who carries the word to those who need it. The email agent closes the loop: it takes what the pack found and delivers it to the humans who own it, with deep-links back into Tenable.'},
 alert:{name:'Alert Raven',lore:'In the wild, <b>ravens ride with the wolf pack</b> — scouting ahead, then calling out where the kill (and the danger) is; the wolves hunt, the raven watches the sky. <b>Alert Raven</b> rides with the Hounds the same way: it keeps watch over navi.db and calls out — an email digest — the moment a tracked condition turns dangerous.'},
};
/* ---- "Deep dive" — the origin article + code behind each agent (script → agent) ----
   Each idea started as a Medium article by Casey Reid (packetchaos), became a navi
   command, and is now an agent. Fill in article/code per agent id; where present a
   "Deep dive" link appears on the agent's header and its Release-the-Hounds card. */
const NAVI_REPO = 'https://github.com/packetchaos/navi';
const NAVI_SERVICES = 'https://github.com/packetchaos/navi_services';
const DEEP_DIVE = {
  agentgroup: { year:'2022',
    article: {url:'https://packetchaos.medium.com/tagging-agents-by-agent-group-in-tenable-io-83c4258a17dc',
              title:'Tagging Agents by Agent Group in Tenable.io — Casey Reid (2022)'},
    code: {url: NAVI_SERVICES + '/tree/master/agent_group_tags', label:'navi_services · agent_group_tags'}},
  acr: { year:'2022',
    article: {url:'https://packetchaos.medium.com/change-asset-criticality-acr-by-tag-in-tenable-io-ecbe08b5fdfb',
              title:'Change Asset Criticality (ACR) by Tag in Tenable.io — Casey Reid (2022)'},
    code: {url: NAVI_REPO + '/blob/master/navi/plugins/action.py', label:'navi · navi/plugins/action.py (ACR / navi lumin)'}},
  cisakev: { year:'2023',
    article: {url:'https://packetchaos.medium.com/tag-assets-by-cisa-known-exploits-released-april-7th-433b1df4d180',
              title:'Tag assets by CISA Known Exploits — Casey Reid (2023)'},
    code: {url: NAVI_SERVICES + '/tree/master/CISA_Adds_Known_Exploits', label:'navi_services · CISA_Adds_Known_Exploits'}},
  mitre: { year:'2023',
    article: {url:'https://packetchaos.medium.com/tag-tenable-io-assets-by-mitre-att-ck-impact-d1cf21fd46a3',
              title:'Tag Tenable.io Assets by MITRE ATT&CK impact — Casey Reid (2023)'},
    code: {url: NAVI_SERVICES + '/tree/master/mitre_technique_tags', label:'navi_services · mitre_technique_tags'}},
  identity: { year:'2023',
    article: {url:'https://packetchaos.medium.com/youre-fired-now-where-do-you-have-local-accounts-589457f178a5',
              title:'You’re Fired! Now, where do you have local accounts? — Casey Reid (2023)'},
    code: {url: NAVI_SERVICES + '/tree/master/tag_by_user_accounts', label:'navi_services · tag_by_user_accounts'}},
  eol: { year:'2023',
    article: {url:'https://packetchaos.medium.com/security-end-of-life-seol-where-am-i-exposed-a2fb93c5feb1',
              title:'Security End of Life (SEoL) — Where am I exposed? — Casey Reid (2023)'},
    code: {url: NAVI_SERVICES + '/blob/master/securtity_end_of_life/SEoL.py', label:'navi_services · SEoL.py'}},
  ai: { year:'2024',
    article: {url:'https://packetchaos.medium.com/where-am-i-using-ai-d15d1d027d18',
              title:'Where am I using AI? — Casey Reid (2024)'},
    code: {url: NAVI_REPO, label:'navi (tag by plugin_family "Artificial Intelligence")'}},
  software: { year:'2023',
    article: {url:'https://packetchaos.medium.com/building-a-software-inventory-with-nessus-30590d1e5a56',
              title:'Building a Software Inventory with Nessus — Casey Reid (2023)'},
    code: {url: NAVI_REPO, label:'navi (navi software generate · parses plugins 20811/22869)'}},
  customapp: { year:'2023',
    article: {url:'https://packetchaos.medium.com/my-guilty-obsession-tagging-by-plugin-output-c1ccad6c2791',
              title:'My Guilty Obsession: Tagging by Plugin Output — Casey Reid (2023)'},
    code: {url: NAVI_REPO + '/blob/master/navi/plugins/enrich.py', label:'navi · navi/plugins/enrich.py (tag --plugin --output)'}},
  // IoT + Cert agents both come from "tagging by plugin output" (SSL-cert plugin 10863, mDNS 66717)
  iot_squad: { year:'2023',
    article: {url:'https://packetchaos.medium.com/my-guilty-obsession-tagging-by-plugin-output-c1ccad6c2791',
              title:'My Guilty Obsession: Tagging by Plugin Output — Casey Reid (2023) · IoT via plugins 10863 / 66717'},
    code: {url: NAVI_REPO + '/blob/master/navi/plugins/enrich.py', label:'navi · navi/plugins/enrich.py (tag --plugin --output)'}},
  certificate: { year:'2023',
    article: {url:'https://packetchaos.medium.com/my-guilty-obsession-tagging-by-plugin-output-c1ccad6c2791',
              title:'My Guilty Obsession: Tagging by Plugin Output — Casey Reid (2023) · certs via SSL-cert plugin 10863'},
    code: {url: NAVI_REPO + '/blob/master/navi/plugins/config.py', label:'navi · navi/plugins/config.py (certificate)'}},
  scan_eval: { year:'2023',
    article: {url:'https://packetchaos.medium.com/for-the-love-of-19506-b2bba4d62c8',
              title:'For the Love of 19506 — Casey Reid (2023) · origin of “navi scan evaluate”'},
    code: {url: NAVI_REPO, label:'navi (scan evaluate)'}},
  contract: { year:'2026',
    article: {url:'https://packetchaos.medium.com/the-navi-mcp-11-skills-driving-accurate-exposure-management-automation-461dcae63b2a',
              title:'The Navi MCP — 11 Skills driving accurate Exposure Management automation — Casey Reid (2026, member-only)'},
    code: {url:'https://github.com/packetchaos/navi-mcp', label:'navi-mcp + navi-claude-skills on GitHub'}},
  // general "origin of navi tagging" — shown on any agent without its own article yet:
  _fallback: { year:'2023',
    article: {url:'https://packetchaos.medium.com/my-guilty-obsession-tagging-by-plugin-output-c1ccad6c2791',
              title:'My Guilty Obsession: Tagging by Plugin Output — Casey Reid (the origin of navi tagging)'},
    code: {url: NAVI_REPO + '/blob/master/navi/plugins/enrich.py', label:'navi · navi/plugins/enrich.py (tag by plugin output)'}},
  // ↓ still open for their own dedicated article (fall back to the general one for now):
  // certificate, iot_squad, exproute, postquantum, contract, tagremoval, dashboard
};
/* search / explorer agents have no origin article — no deep dive for them.
   postquantum + attackpath were built on THIS project (not from the navi origin), so no origin story. */
const _DD_SKIP = new Set(['ex_assets','ex_vulns','ex_plugins','ex_routes','ex_paths','ex_tags','postquantum','attackpath',
  'advsearch','advanced','explore','dash','dashboard','mcpcmp','customdash','tags','tagdetail','taglog','tags-log','asset','vuln']);  /* search / explorer / generic tools — no hound origin story */
function deepDive(id){ if(_DD_SKIP.has(id)) return null; return (typeof DEEP_DIVE!=='undefined') && (DEEP_DIVE[id] || DEEP_DIVE._fallback) || null; }
function deepDiveChips(id){
  const d = deepDive(id); if(!d) return '';
  let h='';
  if(d.year) h+='<span class="sub" style="font-size:11px;color:var(--ink-3);align-self:center;white-space:nowrap">📖 Origin story · '+d.year+'</span>';
  if(d.article&&d.article.url) h+='<a class="btn ghost sm" href="'+esc(safeUrl(d.article.url))+'" target="_blank" rel="noopener noreferrer" title="'+esc(d.article.title||'Read the origin article')+'">Deep dive ↗</a>';
  if(d.code&&d.code.url) h+='<a class="btn ghost sm" href="'+esc(safeUrl(d.code.url))+'" target="_blank" rel="noopener noreferrer" title="'+esc(d.code.label||'Source code')+'">‹ › Code</a>';
  return h;
}
/* just the origin-story date + article link (shown under the agent name on cards) */
function deepDiveMeta(id){ const d=deepDive(id); if(!d) return '';
  let h='';
  if(d.year) h+='<span class="sub" style="font-size:11px;color:var(--ink-3)">📖 Origin story · '+d.year+'</span>';
  if(d.article&&d.article.url) h+='<a href="'+esc(safeUrl(d.article.url))+'" target="_blank" rel="noopener noreferrer" title="'+esc(d.article.title||'')+'" style="font-size:12px;color:var(--accent);font-weight:600;text-decoration:none">Deep dive ↗</a>';
  return h?('<div class="ddmeta" style="display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin:2px 0 0">'+h+'</div>'):''; }
/* just the code link (shown with Execute / Open in the actions row) */
// The ‹ › Code link points at the agent's own folder in the-hounds-repo on GitHub.
const HOUNDS_REPO='https://github.com/packetchaos/the-hounds-repo/tree/main/navi-agents/agents/';
const HOUNDS_REPO_ALIAS={act1:'certificate',squad:'iot_squad',capp:'customapp',ident:'identity',scaneval:'scan_eval'};
function houndsRepoUrl(id){ return HOUNDS_REPO+(HOUNDS_REPO_ALIAS[id]||id); }
function deepDiveCode(id){ const d=deepDive(id); if(!d) return '';
  return '<a class="btn ghost sm" href="'+esc(safeUrl(houndsRepoUrl(id)))+'" target="_blank" rel="noopener noreferrer" title="Source — this hound in the-hounds-repo">‹ › Code</a>'; }
/* ===== Per-agent intro: value line + expanded key capabilities (from the field guide) ===== */
const AGENT_INTRO = {
 certificate:{does:"Keeps certificate expirations from becoming outages — finds every cert expiring within a year, shows exactly who's affected, and tags the risk before it bites.",caps:[
   "Pulls every certificate expiring in the next <b>12 months</b> from navi.db and maps each one to the asset that presents it.",
   "Builds <b>two heat maps</b> — issue × asset and expiry-month × asset — to reveal clustering and drive a renewal plan.",
   "Tags affected assets <span class='mono'>Cert failure:&lt;Mon-DD-YYYY&gt;</span> (gated) so dashboards and downstream agents can prioritize them.",
   "Caches IoT / appliance devices seen in certificate subjects — feeding the IoT squad and Heimdall's crypto inventory."]},
 iot_squad:{does:"A four-agent pack that hunts unmanaged IoT/OT at the network edge, names it, tags it — and gets smarter every run.",caps:[
   "Runs <b>Discovery → Expansion → Cross-Reference → QA</b> to detect devices Nessus mislabels as generic Linux.",
   "Fingerprints by plugin, SSL certificate, MAC OUI and mDNS to identify vendor + device type.",
   "Tags confirmed devices <span class='mono'>IoT:&lt;name&gt;</span> using navi built-ins (<span class='mono'>--plugin/--output</span>) so large fleets tag server-side, not by UUID list.",
   "Learns new detection signatures over time and lets you approve or reject candidates from a review queue."]},
 acr:{does:"The hub of the whole pack — turns everyone's tags into Asset Criticality so the right things rise to the top.",caps:[
   "Adjusts ACR per tag (<b>set / +N / −N</b>) with a required business justification.",
   "Bulk-applies ACR by rule across many tags at once, including plain-English rule authoring.",
   "Converts producer tags (crown jewel, KEV, exposed AI) into the ACR every correlator keys off.",
   "Retune once and Fenrir, Heimdall, Pythia and Janus all re-prioritize together."]},
 customapp:{does:"Finds the software your inventory can't see — custom and in-house apps hiding in routes and paths — and lets you name them.",caps:[
   "Mines <span class='mono'>vuln_route</span> + <span class='mono'>vuln_paths</span> to surface apps missing from the credentialed software table.",
   "Tag a custom app in <b>plain English</b>; it searches routes/paths and tags every matching asset.",
   "Tags via <span class='mono'>--route_id</span> and a precise path query (gated), filling Mimir's inventory gaps.",
   "Detects when the routing/paths tables aren't populated and tells you the exact navi commands to run."]},
 mitre:{does:"Maps your real CVEs to adversary ATT&CK techniques — so you see not just what's vulnerable, but how it gets attacked.",caps:[
   "Fetches the live <b>ATT&CK → CVE</b> mapping and matches it against the CVEs actually in navi.db.",
   "Tags each CVE with its technique / impact, strictly via navi's native <span class='mono'>--cve</span> selector.",
   "Complements Laelaps: KEV proves <i>exploited</i>, ATT&CK explains the <i>technique</i>.",
   "Feeds On the Scent with technique-on-crown-jewel insight."]},
 eol:{does:"Ferries End-of-Life and unsupported software to its reckoning — tagging the assets running code no vendor will patch.",caps:[
   "Tags assets running <b>End-of-Life / unsupported</b> software, unioned with Mimir's endoflife.date data.",
   "Uses navi's plugin-name match (built-in) so tagging scales without UUID lists.",
   "Marks EOL software as an exploitable foothold for Fenrir's attack-path chains.",
   "Feeds Mimir's risk view and Anubis's ACR rules."]},
 dashboard:{does:"Builds a custom view from one plain-English request — KPIs, a chart, or a table — for anything we didn't ship a page for.",caps:[
   "Describe a view in plain English; it writes <b>one read-only</b> SELECT over navi.db (or live counts via Tenable One).",
   "Renders as KPI tiles, a bar chart, or a sortable data table.",
   "<b>Read-only</b> — nothing is ever written.",
   "Promote a useful view to a saved Custom Dashboard."]},
 ai:{does:"The oracle for AI risk — finds every AI/ML system in the estate, classifies what it is, and flags what's exposed.",caps:[
   "Content-first discovery across the AI plugin family + software + CPEs + plugin output.",
   "Classifies <b>role</b> (Serving / Vector / GPU / MLOps / LLM client / Dev tool) and flags exposed endpoints.",
   "Correlates AI × KEV, governs data-egress (sanctioned vs shadow), and maps findings to <b>MITRE ATLAS</b>.",
   "Includes a 🔍 Why evidence inspector + false-positive suppression; tags <span class='mono'>AI Role:*</span>, <span class='mono'>AI Exposed</span>, <span class='mono'>AI Priority</span>."]},
 identity:{does:"Guards the doorways — inventories human and non-human identities and flags the weak credentials attackers pivot through.",caps:[
   "Content-first <b>NHI + human identity</b> discovery; flags non-expiring, privileged, guest-enabled and machine identities.",
   "Surfaces coverage gaps (blind hosts), SSH password auth and weak policy.",
   "Correlates crown-jewel identities, account reuse, default/blank creds and AD attack paths.",
   "Tags the hosting assets — Fenrir's single biggest source of credential pivots."]},
 scan_eval:{does:"Measures where your scans spend their time — and, crucially, what they can't see: the blind and uncredentialed hosts.",caps:[
   "Per-asset <b>credential health</b>: failed, insufficient privilege, intermittent or no credentials — from the Target Credential Status / Issues plugins and 19506.",
   "<b>Scan freshness</b> (never / 30 / 90 days), agent vs network, and <b>crown-jewel blind spots</b>.",
   "Scanner / policy / scan time per asset, load share, credential success and <b>plugin-feed currency</b>.",
   "Tags the exact assets under <span class='mono'>Scan Health</span> so scanning gaps become actionable.",
   "The honesty layer — blind hosts are the 'we can't see this' caveat for Janus, Fenrir and On the Scent."]},
 insights:{does:"Your morning 'what am I not seeing' page — rolls every agent's findings into one ranked exposure view.",caps:[
   "Aggregates all producers into an <b>Exposure-at-a-glance</b> ranked list + category tiles.",
   "Click any bar to drill straight into the Dashboard builder.",
   "Highlights unknown-unknowns — the coverage and exposure gaps across the pack."]},
 exproute:{does:"Puts a name on remediation — maps who owns which routes and paths so findings route to a human.",caps:[
   "Pulls users &amp; groups (navi primary, Tenable MCP backup) — paginated and searchable.",
   "Describe in plain English who owns which routes/paths; it tags every matched asset <span class='mono'>Owner:&lt;group/user&gt;</span> (gated).",
   "Tracks ownership coverage — how much of the attack surface has an owner assigned."]},
 software:{does:"Remembers every software version in the estate and shows you the sprawl — plus EOL, crown jewels and a risk leaderboard.",caps:[
   "Merges <span class='mono'>software</span> + <span class='mono'>cpes</span> inventories into one product map: version sprawl, most-deployed, single-install, source delta.",
   "Adds endoflife.date lifecycle and a 'behind latest' worklist.",
   "Surfaces <b>crown-jewel software</b> → suggested ACR, and ranks products on a KEV/critical <b>risk leaderboard</b>.",
   "Tags <span class='mono'>Software:*</span>, <span class='mono'>Software EOL:*</span>, <span class='mono'>Crown Jewel:*</span>, <span class='mono'>Software Risk:*</span> (gated); auto-switches to plugin+regex tagging past the 1999-UUID cap."]},
 tagremoval:{does:"The cleanup hound — the only agent allowed to remove tags, unmaking what no longer belongs before the pack re-tags.",caps:[
   "Lists existing tags with their asset counts and lets you select exactly what to remove.",
   "Removes tags via navi's ephemeral <span class='mono'>-remove</span> — the <b>only</b> agent permitted to delete tags.",
   "Preserves tag UUIDs where it matters so downstream references don't break.",
   "Can feed the Contract's removal policy (remove → wait → re-tag)."]},
 agentgroup:{does:"Musters every Tenable agent into its group and tags it — turning agent groups into segmentation you can act on.",caps:[
   "Tags assets by Tenable agent group via navi's <span class='mono'>--group</span> built-in.",
   "Turns agent-group membership into <span class='mono'>Agent Group:&lt;name&gt;</span> segmentation tags (gated).",
   "Feeds the Contract for scheduled re-tagging."]},
 contract:{does:"The orchestrator — capture your tagging &amp; ACR policy once, arm it, and it runs the whole pack on a schedule.",caps:[
   "Enable agents, set a schedule, <b>arm</b> it — it runs the gated tag/ACR plan on a loop.",
   "Keeps durable run-history and a 'what changed since last cycle' diff.",
   "Authors ACR rules from plain English and drives the scheduled morning digest.",
   "Runs the <b>remove → wait 30 min → re-add</b> refresh so tags always reflect current reality."]},
 cisakev:{does:"The hound that always catches its quarry — tags every Known-Exploited vulnerability, already proven in the wild.",caps:[
   "Tags KEV assets off the <span class='mono'>CISA-KNOWN-EXPLOITED</span> xref — all KEV, by catalog date, or by month in one click.",
   "Uses navi's <span class='mono'>--xrefs/--xid</span> built-ins and refreshes ephemerally on each KEV release.",
   "Includes an NL→SQL KEV hunt.",
   "The exploitability signal for the whole pack — Fenrir footholds, Pythia AI×KEV, Heimdall correlation."]},
 postquantum:{does:"Watches the quantum horizon — flags the RSA/ECC crypto that won't survive it and builds a migration roadmap.",caps:[
   "Inventories cert crypto (RSA/ECC/DSA = broken by Shor) and builds a <b>harvest-now-decrypt-later</b> hit-list (long-lived certs × ACR).",
   "Reads transport signals (TLS/SSH KEX, weak MAC) and crypto-agility (OpenSSH/OpenSSL readiness).",
   "Correlates crown jewels, emits a migration roadmap CSV and a <b>CNSA 2.0</b> timeline.",
   "Tags <span class='mono'>PQC Risk:*</span>, <span class='mono'>PQC Harvest-Now</span>, <span class='mono'>PQC Transport:*</span>, <span class='mono'>PQC Priority</span> (gated)."]},
 attackpath:{does:"The capstone correlator — chains exploits, privilege escalation, account reuse, relay, domain flaws and failed controls into ranked paths to the crown jewels.",caps:[
   "Builds an attack graph from navi.db <b>vulns</b>, <b>compliance</b> results and <b>identities</b>: remote exploits → privilege escalation → account reuse / NTLM relay / domain admin → crown jewel (ACR ≥ 7).",
   "<b>Interactive attack map</b>, up to five diverse routes per crown jewel, with every step's evidence and ATT&amp;CK technique.",
   "<b>Fix first</b>: choke points and a greedy remediation bundle that cuts the most crown-jewel exposure; tags <span class='mono'>Attack Path : Entry Point | Pivot | Target | Choke Point</span> (gated).",
   "Consumes Laelaps (KEV), Janus (identities), Anubis (ACR targets), Minos (compliance) and EPSS.",
   "Honest caveat: reachability and domain membership are inferred, not observed; likelihoods rank routes, they are not breach probabilities."]},
 ex_assets:{does:"The finest tracker of the pack — find and profile any host across navi.db.",caps:[
   "Search assets by hostname, IP or UUID and open a full profile.",
   "See an asset's vulnerabilities, tags and platform links in one place."]},
 ex_vulns:{does:"Hunts findings in the dark — search vulnerabilities by plugin, CVE, severity or VPR.",caps:[
   "Query the vulns table by plugin, CVE, severity, state or VPR.",
   "Drill from a finding to its affected assets and plugin output."]},
 ex_plugins:{does:"The plugin explorer — find which plugins fired and on how many assets.",caps:[
   "Search plugins by id, name or family with asset counts.",
   "Pivot from a plugin to the assets it fired on."]},
 ex_routes:{does:"The route explorer — browse technology-level vuln routes.",caps:[
   "Search application / OS routes and their vuln totals.",
   "Feed route ids into ownership + custom-app tagging."]},
 ex_paths:{does:"The path explorer — search vulnerable filesystem / URL paths.",caps:[
   "Search paths by substring and see the assets + plugins behind them.",
   "Source data for custom-app discovery and ownership mapping."]},
 ex_tags:{does:"The tag explorer — browse every tag in navi.db and see exactly which assets carry it.",caps:[
   "Search tags by category or value, with a DISTINCT asset count per tag.",
   "Drill into any tag for its assets — joined to the assets table (host, IP, OS, ACR/AES, platform link, Argos deep-dive)."]},
 argos:{does:"Give it one asset — a UUID or an IP — and it tells the whole story on a single dashboard: risk band, the pack's tags deciphered, top CVEs, software and certs.",caps:[
   "Looks an asset up by <span class='mono'>UUID</span> or <span class='mono'>IP</span> (navi explore uuid takes either) and resolves it across every navi.db table.",
   "<b>Deciphers the pack's tags</b> — each tag shows what it means and which Hound raised it (Laelaps → CISA KEV, Certania → cert failure, Charon → EOL, Heimdall → post-quantum…).",
   "Scores 0–100 from the severity mix, KEV / exploitable findings and tag intelligence, with a severity breakdown, top CVEs, software and weak-crypto certs.",
   "Runs the live <span class='mono'>navi explore uuid</span> flag views on demand — <span class='mono'>-software</span>, <span class='mono'>-patches</span>, <span class='mono'>-details</span>, <span class='mono'>-cves</span>."]},
 advanced:{does:"The power-user search — write natural language or SQL that ranges across every navi.db table at once, joining and filtering the whole estate.",caps:[
   "Cross-table NL→SQL with joins over assets, vulns, routes and paths.",
   "For the questions the single-lens search hounds can't answer alone."]},
 email:{does:"The loop-closer — turns the pack's findings into email that lands with the right human, with deep-links back into the Tenable platform.",caps:[
   "<b>Owner-routed remediation</b> — reads Atlas <span class='mono'>Owner:</span> tags and emails each owner ONLY their assets, each with its Tenable deep-link.",
   "<b>KEV fire-alarms</b> (Laelaps), <b>cert countdowns</b> (Certania) and a leadership <b>morning briefing</b> (On the Scent).",
   "<b>Agent findings hand-off</b> — any Hound can send Gabriel the finding IDs that made up its search + the tagged assets; Gabriel emails the overview and says which Hound produced it.",
   "Board vs technical templates. Preview is read-only; sending is <b>double-gated</b> (writes + email + confirm) and logged as an accountability ledger."]},
};
function _introStyle(){
  if(document.getElementById('introStyle')) return;
  const st=document.createElement('style'); st.id='introStyle';
  st.textContent=
   '.codetoggle{cursor:pointer;background:var(--panel2,var(--bg-2));border:1px solid var(--line);border-radius:999px;padding:6px 14px;color:var(--ink);font-size:12.5px;font-weight:600;display:inline-flex;align-items:center;gap:7px;max-width:100%;flex-wrap:wrap}'
  +'.codetoggle:hover{border-color:var(--accent)}'
  +'.codetoggle img{width:22px;height:22px;border-radius:999px;object-fit:cover}'
  +'.cdchev{color:var(--ink-3);font-size:11px}'
  +'.introHead{display:flex;align-items:center;gap:8px;flex-wrap:wrap}'
  +'.introPanel{margin-top:10px;background:var(--panel2,var(--bg-2));border:1px solid var(--line);border-left:3px solid var(--accent);border-radius:14px;padding:18px 20px}'
  +'.introGrid{display:flex;gap:24px;align-items:flex-start;flex-wrap:wrap}'
  +'.introArt{flex:0 0 auto;text-align:center}'
  +'.introCrest{width:230px;height:230px;max-width:46vw;border-radius:16px;object-fit:cover;border:1px solid var(--line);box-shadow:0 10px 28px rgba(0,0,0,.5)}'
  +'.introName{margin-top:9px;font-weight:700;font-size:13px;color:var(--ink-2);letter-spacing:.02em}'
  +'.introBody{flex:1 1 360px;min-width:280px}'
  +'.introSec{margin:0 0 15px}'
  +'.introSec:last-child{margin-bottom:0}'
  +'.introSec h4{margin:0 0 6px;font-size:11px;text-transform:uppercase;letter-spacing:.07em;color:var(--accent)}'
  +'.introDoes{margin:0;font-size:14.5px;line-height:1.55;color:var(--ink)}'
  +'.introCaps{margin:0;padding:0;list-style:none;display:flex;flex-direction:column;gap:8px}'
  +'.introCaps li{position:relative;padding-left:18px;font-size:13px;line-height:1.5;color:var(--ink-2)}'
  +'.introCaps li:before{content:"\\203A";position:absolute;left:2px;top:-1px;color:var(--accent);font-weight:700}'
  +'.introLore{font-size:13px;line-height:1.55;color:var(--ink-2)}';
  document.head.appendChild(st);
}
/* Search / explorer agents are plain tools — no hound codename, crest, or origin story.
   They're too simple for the "agent" persona, so the whole codename block is skipped
   and only the plain page header (mountAgentHeader) shows. */
const _NO_CODENAME=new Set(['ex_assets','ex_vulns','ex_plugins','ex_routes','ex_paths','ex_tags','explore','advanced','advsearch']);
function _mountCodename(host){
  const id = window.__AGENT_ID||''; const cn = CODENAMES[id]; if(!cn) return;
  if(_NO_CODENAME.has(id)){ const ex=document.getElementById('agent-codename'); if(ex)ex.remove(); return; }
  _introStyle();
  const intro = (typeof AGENT_INTRO!=='undefined' && AGENT_INTRO[id]) || null;
  let cb=document.getElementById('agent-codename');
  if(!cb){ cb=document.createElement('div'); cb.id='agent-codename'; cb.className='codebanner'; cb.style.cssText='margin:0 0 12px'; host.insertAdjacentElement('afterend',cb); }
  const crestSm='<img src="'+esc(crestSrc(id))+'?v=5" alt="" data-fb="🐾">';
  const bigCrest='<img class="introCrest" src="'+esc(crestSrc(id))+'?v=5" alt="'+esc(cn.name)+'" data-fb="hide">';
  const doesHtml=(intro&&intro.does)?('<div class="introSec"><h4>What it does</h4><p class="introDoes">'+intro.does+'</p></div>'):'';
  const capsHtml=(intro&&intro.caps&&intro.caps.length)?('<div class="introSec"><h4>Key capabilities</h4><ul class="introCaps">'+intro.caps.map(c=>'<li>'+c+'</li>').join('')+'</ul></div>'):'';
  const loreHtml='<div class="introSec"><h4>What\'s in the name</h4><div class="introLore">'+cn.lore+'</div></div>';
  cb.innerHTML=
    '<div class="introHead"><button class="codetoggle" type="button">'+crestSm+' <b>'+esc(cn.name)+'</b> <span class="sub" style="font-weight:400">— what it does &amp; the name</span> <span class="cdchev">▸</span></button>'+deepDiveChips(id)+'</div>'
   +'<div class="introPanel" style="display:none"><div class="introGrid">'
     +'<div class="introArt">'+bigCrest+'<div class="introName">'+esc(cn.name)+'</div></div>'
     +'<div class="introBody">'+doesHtml+capsHtml+loreHtml+'</div>'
   +'</div></div>';
  const btn=cb.querySelector('.codetoggle'), panel=cb.querySelector('.introPanel'), chev=cb.querySelector('.cdchev');
  btn.onclick=()=>{const open=panel.style.display==='none'; panel.style.display=open?'block':'none'; chev.textContent=open?'▾':'▸';};
}

/* Hide NL/LLM-only UI (class "needs-llm") when the backend has no LLM configured. */
function applyLlmGate(){
  const on = !!window.__LLM_AVAILABLE;
  document.querySelectorAll('.needs-llm').forEach(el=>{ el.style.display = on ? '' : 'none'; });
  document.querySelectorAll('.no-llm-note').forEach(el=>{ el.style.display = on ? 'none' : ''; });
}

/* ===== applied-tag truth from navi.db `tags` table (NOT a local cache) =====
   loadAppliedTags() pulls the tags table via the shared explore service; tagApplied()
   tells a page whether a category+value is actually applied in navi.db. A tag a page
   just wrote shows a transient "awaiting navi sync" until the next navi.db sync. */
window.__APPLIED_TAGS = new Set();
const _SEP = '';
async function loadAppliedTags(){
  try{ const o = await agentApi('explore').post('applied');
    // a test-run tag ('Hounds-Lifecycle') also answers for its plain category (r.base)
    window.__APPLIED_TAGS = new Set((o.applied||[]).flatMap(r => [r.tag_key].concat(r.base?[r.base]:[]).map(k =>
      String(k||'').toLowerCase()+_SEP+String(r.tag_value||'').toLowerCase()))); }
  catch(e){ window.__APPLIED_TAGS = new Set(); }
  return window.__APPLIED_TAGS;
}
function tagApplied(cat,val){ return window.__APPLIED_TAGS.has(String(cat||'').toLowerCase()+_SEP+String(val||'').toLowerCase()); }
function tagBadge(cat,val,localSt){
  if(tagApplied(cat,val)) return {st:'applied',done:true,cls:'b-applied',label:'Applied ✔ (navi.db)'};
  if(localSt==='queued') return {st:'queued',done:false,cls:'b-appr',label:'Queued ⏳ — see Tagging log'};
  if(localSt==='applied') return {st:'submitted',done:false,cls:'b-appr',label:'Submitted — not in navi.db yet · Re-check'};
  if(localSt==='approved') return {st:'approved',done:false,cls:'b-appr',label:'Approved'};
  return {st:'pending',done:false,cls:'b-pending',label:'Pending'};
}

/* Two-step NL → SQL. nlTranslate() only generates SQL; runSql() executes a
   validated read-only SELECT. The page shows the SQL in an editable box with its
   own Execute button so the user can refine before running. */
async function nlTranslate(table, prompt){ return jpost('/api/explore/nl_translate', {table, prompt}); }
async function runSql(sql){ return jpost('/api/explore/run_sql', {sql}); }

function renderSqlResult(outEl, o){
  const el = typeof outEl==='string' ? document.getElementById(outEl) : outEl; if(!el) return;
  if(!o || !o.ok){ el.innerHTML = '<div class="callbox" style="color:var(--crit)">✗ '+esc((o&&(o.message||o.error))||'failed')+(o&&o.sql?'<div class="mono" style="font-size:11px;margin-top:6px;white-space:pre-wrap">'+esc(o.sql)+'</div>':'')+'</div>'; return; }
  const cols=o.columns||[], rows=o.rows||[];
  el.innerHTML = (rows.length ? '<div style="overflow-x:auto"><table><thead><tr>'+cols.map(c=>'<th>'+esc(c)+'</th>').join('')+'</tr></thead><tbody>'+
      rows.map(r=>'<tr>'+cols.map(c=>'<td class="mono" style="font-size:11px">'+esc(String(r[c]==null?'':r[c]))+'</td>').join('')+'</tr>').join('')+'</tbody></table></div><p class="sub" style="margin-top:6px">'+rows.length+' row(s).</p>'
      : '<p class="sub">No rows.</p>');
}
async function nlCols(table){ try{ const o=await jpost('/api/explore/columns',{table}); return (o&&o.ok&&o.columns)||[]; }catch(e){ return []; } }
/* Render the generated SQL as an editable textarea + an Execute button. When a
   `table` is given, show its columns as chips so a SELECT * can be narrowed. */
function renderSqlBox(outEl, sql, table){
  const el = typeof outEl==='string' ? document.getElementById(outEl) : outEl; if(!el) return;
  const id = el.id || ('nlbox'+Math.random().toString(36).slice(2));  el.id = id;
  el.innerHTML = '<div class="callbox" style="padding:10px">'
    +'<div class="sub" style="margin-bottom:6px">Generated SQL — review / refine, then ▶ Run SQL:</div>'
    +'<textarea id="'+id+'_sql" spellcheck="false" style="width:100%;min-height:88px;font-family:ui-monospace,monospace;font-size:12px;padding:8px;border-radius:8px;border:1px solid var(--line);background:var(--bg-2);color:var(--ink);box-sizing:border-box">'+esc(sql)+'</textarea>'
    +'<div id="'+id+'_cols" style="margin-top:8px"></div>'
    +'<div class="toolbar" style="margin-top:8px"><button class="btn run sm" id="'+id+'_go" data-run>▶ Run SQL</button><span class="sub">read-only · single SELECT · LIMIT ≤500 enforced</span></div>'
    +'<div id="'+id+'_res" style="margin-top:8px"></div></div>';
  document.getElementById(id+'_go').onclick = async () => {
    const sqlv = document.getElementById(id+'_sql').value;
    const res = document.getElementById(id+'_res');
    res.innerHTML = '<div class="callbox"><span class="spin"></span> running query…</div>';
    let o; try{ o = await runSql(sqlv); }catch(e){ o={ok:false,message:e.message}; }
    renderSqlResult(res, o);
  };
  if(table) _sqlColChips(id, table);
}
async function _sqlColChips(id, table){
  const cols = await nlCols(table);
  const box = document.getElementById(id+'_cols'); if(!box || !cols.length) return;
  box.innerHTML = '<div class="sub" style="margin-bottom:5px">Columns in <span class="mono">'+esc(table)+'</span> — click to pick the ones you want (none picked = all <span class="mono">*</span>):</div>'+
    cols.map(c=>'<button type="button" class="colchip" data-c="'+esc(c)+'" style="cursor:pointer;margin:0 5px 6px 0;padding:3px 10px;border-radius:999px;border:1px solid var(--line);background:var(--bg-2);color:var(--mut);font-size:11px;font-family:ui-monospace,monospace">'+esc(c)+'</button>').join('');
  box.querySelectorAll('.colchip').forEach(b=>b.onclick=()=>{
    const on=b.dataset.on==='1'; b.dataset.on=on?'':'1';
    b.style.background=on?'var(--bg-2)':'var(--accent,#d6f84c)'; b.style.color=on?'var(--mut)':'#1a1206'; b.style.borderColor=on?'var(--line)':'var(--accent,#d6f84c)';
    const chosen=[...box.querySelectorAll('.colchip')].filter(x=>x.dataset.on==='1').map(x=>x.dataset.c);
    const ta=document.getElementById(id+'_sql'); if(ta) ta.value=ta.value.replace(/select\s+[\s\S]*?\s+from\s/i,'SELECT '+(chosen.length?chosen.join(', '):'*')+' FROM ');
  });
}
/* ===== Shared widget + dashboard email (Gabriel) — ONE UX for the whole pack =====
   hMail(container, getPayload, opts)
     container  — element the 📧 button is appended to (usually a card's .toolbar)
     getPayload — mode 'data':      () => {title, note?, sql?, columns?, rows:[{...}]}
                  mode 'dashboard': () => {title, subject?, components:[{title,note,viz,
                                           columns,rows,label_col,value_col}]}
                  Return null / empty rows|components → "no data yet" message.
     opts       — {mode:'data'|'dashboard' (default 'data'), label}
   Double-gated server-side (confirm + NAVI_ALLOW_WRITES=1 + NAVI_EMAIL=1); a blocked
   send surfaces Gabriel's exact gate reason. Recipient remembered in localStorage. */
function _hmailStyle(){ if(document.getElementById('hmailStyle'))return;
  const st=document.createElement('style'); st.id='hmailStyle';
  st.textContent='.hmrow{display:none;gap:6px;align-items:center;flex-wrap:wrap;margin-top:6px;flex-basis:100%}'
   +'.hmrow input{padding:7px 9px;border-radius:8px;border:1px solid var(--line);background:var(--bg-2);color:var(--ink);min-width:210px;font-size:12.5px}'
   +'.hmrow .res{font-size:12px}';
  document.head.appendChild(st); }
function _hmailTo(v){ try{ if(v!==undefined)localStorage.setItem('naviMailTo',v); return localStorage.getItem('naviMailTo')||''; }catch(e){ return ''; } }
function hMail(container, getPayload, opts){
  opts=opts||{}; const mode=opts.mode==='dashboard'?'dashboard':'data';
  if(!container)return null; _hmailStyle();
  const EM=agentApi('email');
  const btn=document.createElement('button'); btn.className='btn ghost sm hmbtn';
  btn.textContent=opts.label||(mode==='dashboard'?'\ud83d\udce7 Email dashboard':'\ud83d\udce7');
  btn.title=mode==='dashboard'?'Email the whole dashboard via Gabriel (gated)':"Email this widget's data via Gabriel (gated)";
  const row=document.createElement('div'); row.className='hmrow';
  row.innerHTML='<input type="email" placeholder="recipient@company.com"><button class="btn run sm">\u25b6 Send</button><button class="btn ghost sm">\u2715</button><span class="res sub"></span>';
  container.appendChild(btn); container.appendChild(row);
  const inp=row.querySelector('input'), send=row.querySelectorAll('button')[0], cancel=row.querySelectorAll('button')[1], res=row.querySelector('.res');
  btn.onclick=()=>{ const show=row.style.display!=='flex'; row.style.display=show?'flex':'none'; if(show){ inp.value=inp.value||_hmailTo(); inp.focus(); } };
  cancel.onclick=()=>{ row.style.display='none'; res.innerHTML=''; };
  const go=async()=>{
    const to=(inp.value||'').trim(); if(!to){ res.innerHTML='<span style="color:var(--crit)">enter a recipient</span>'; return; }
    let payload=null; try{ payload=getPayload(); }catch(e){ payload=null; }
    const empty=!payload||(mode==='data'?!(payload.rows&&payload.rows.length):!(payload.components&&payload.components.length));
    if(empty){ res.innerHTML='<span style="color:var(--crit)">no data on this '+(mode==='dashboard'?'dashboard':'widget')+' yet \u2014 run the agent first</span>'; return; }
    if(!confirm('Email '+(mode==='dashboard'?'this dashboard ('+payload.components.length+' component(s))':'this widget ('+payload.rows.length+' row(s))')+' to '+to+'? This is a real send.')) return;
    if(mode==='data'&&!payload.columns&&payload.rows[0]&&typeof payload.rows[0]==='object') payload.columns=Object.keys(payload.rows[0]);
    _hmailTo(to);
    send.disabled=true; res.innerHTML='<span class="spin"></span> sending\u2026';
    let o; try{ o=await EM.post(mode, Object.assign({}, payload, {to:to, confirm:true})); }catch(e){ o={ok:false,error:e.message}; }
    send.disabled=false;
    if(o&&o.ok){ res.innerHTML='<span style="color:var(--ok)">\u2713 sent to '+esc(to)+(mode==='data'?(' \u2014 '+(o.mode==='attachment'?('CSV attached ('+esc(o.attached||'data.csv')+')'):((o.rows||payload.rows.length)+' row(s) inline'))):(' \u2014 '+(o.components||payload.components.length)+' component(s)'))+'</span>'; }
    else if(o&&o.blocked){ res.innerHTML='<span style="color:var(--cx-e7c66b,#e7c66b)">email disabled \u2014 '+esc(o.reason||'set NAVI_ALLOW_WRITES=1 and NAVI_EMAIL=1')+'</span>'; }
    else { res.innerHTML='<span style="color:var(--crit)">\u2717 '+esc((o&&(o.error||o.message))||'failed')+'</span>'; }
  };
  send.onclick=go; inp.addEventListener('keydown',e=>{ if(e.key==='Enter')go(); });
  return btn;
}
/* Read a RENDERED table into {title, columns, rows} for hMail — fallback for widgets
   without a data global. NOTE: captures only the rows currently in the DOM (one page of
   a paginated table) — prefer the page's data array when it exists. */
function hTableData(tblOrId, title){
  const t=(tblOrId&&tblOrId.querySelectorAll)?tblOrId:document.getElementById(tblOrId); if(!t)return null;
  const ths=[...t.querySelectorAll('thead th')].map((th,i)=>th.innerText.trim()||('col'+(i+1)));
  const rows=[...t.querySelectorAll('tbody tr')]
    .filter(tr=>tr.querySelectorAll('td').length>1)
    .map(tr=>{ const o={}; [...tr.querySelectorAll('td')].forEach((td,i)=>{ o[ths[i]||('col'+(i+1))]=td.innerText.replace(/\s+/g,' ').trim(); }); return o; });
  return rows.length?{title:title||tblId,columns:ths,rows:rows}:null;
}

/* Wire an explorer page's NL box. ids default to the page's local element ids. */
function wireNlBox(table, ids){
  ids = ids || {};
  const q = document.getElementById(ids.q || 'nlq');
  const btn = document.getElementById(ids.btn || 'nlgo');
  const out = ids.out || 'nlout';
  if(!btn || !q) return;
  const go = async () => { const p=(q.value||'').trim(); const el=document.getElementById(out);
    if(!p){ el.innerHTML='<div class="callbox" style="color:var(--crit)">Type a question first.</div>'; return; }
    el.innerHTML='<div class="callbox"><span class="spin"></span> turning your question into SQL…</div>';
    let o; try{ o=await nlTranslate(table, p); }catch(e){ o={ok:false,message:e.message}; }
    if(!o || !o.ok){ renderSqlResult(out, o); return; }
    renderSqlBox(out, o.sql, table); };
  btn.onclick = go; q.addEventListener('keydown', e=>{ if(e.key==='Enter') go(); });
}

/* ===== hMailAuto — uniform email for ANY agent page, zero per-page logic =====
   Reads the LIVE DOM (so it never needs a page's data model):
     • a "📧 Email dashboard" button on the header — collects every KPI row + every
       data table on the page into Gabriel `dashboard` components.
     • a per-widget 📧 on each table (next to its nearest heading) — sends just that
       table via Gabriel `data`.
   Re-scans on every click, so it reflects whatever the agent has rendered. Call once
   at the end of a page's script: hMailAuto({title:'<Agent> — <Codename>'}).
   opts.title    — email subject/title base (default: document.title)
   opts.header   — element to mount the dashboard button in (default: auto-detect)
   opts.tableSel — table selector to treat as widgets (default 'table')
   opts.skip     — array of table ids to ignore (e.g. tiny nested tables) */
function _hmAutoTitle(t){ return (t||document.title||'Dashboard').replace(/\s*·.*$/,'').trim()||'Dashboard'; }
function _hmNearestHeading(tbl){
  let n=tbl; for(let up=0; up<6 && n; up++){ n=n.parentElement; if(!n)break;
    const h=n.querySelector(':scope > h2, :scope > h3, :scope > .toolbar h2, :scope > .toolbar h3, :scope > .sechead');
    if(h) return h.innerText.replace(/\s+/g,' ').trim(); }
  return '';
}
function _hmKpiComponents(){
  const comps=[];
  document.querySelectorAll('.kpi').forEach((k,idx)=>{
    const tiles=[...k.querySelectorAll('.k')]; if(!tiles.length)return;
    const row={};
    tiles.forEach(t=>{ const v=t.querySelector('.v,.kv'), l=t.querySelector('.l,.kl');
      if(v&&l){ const lab=l.innerText.replace(/\s+/g,' ').trim(); if(lab)row[lab]=v.innerText.replace(/\s+/g,' ').trim(); } });
    if(Object.keys(row).length){ let title='Key metrics';
      const card=k.closest('.card'); const h=card&&card.querySelector('h2,h3'); if(h)title=h.innerText.replace(/\s+/g,' ').trim();
      comps.push({title:title,viz:'kpi',columns:Object.keys(row),rows:[row]}); }
  });
  return comps;
}
function _hmTableComponents(sel,skip){
  const comps=[]; skip=skip||[];
  document.querySelectorAll(sel||'table').forEach(t=>{
    if(t.id&&skip.indexOf(t.id)>=0)return;
    if(!t.querySelector('thead th'))return;                 // needs headers to be meaningful
    const d=hTableData(t, _hmNearestHeading(t)||'Table');
    if(d&&d.rows.length){ d.viz='table'; comps.push(d); }
  });
  return comps;
}
function hMailAuto(opts){
  opts=opts||{}; _hmailStyle();
  const base=_hmAutoTitle(opts.title);
  // dashboard button on the header
  let host=opts.header;
  if(!host){ const hdr=document.querySelector('#app-header, header.top, header');
    if(hdr){ host=hdr.querySelector('.toolbar')||hdr; } }
  if(host && !opts.noDash && !host.querySelector('.hmbtn')){
    hMail(host, ()=>{
      const comps=_hmKpiComponents().concat(_hmTableComponents(opts.tableSel,opts.skip));
      return comps.length?{title:base+' — dashboard',subject:'[Tenable] '+base,components:comps}:null;
    }, {mode:'dashboard', label:'📧 Email dashboard'});
  }
  // per-widget buttons — attach to each table's nearest heading container
  const attach=()=>{
    document.querySelectorAll(opts.tableSel||'table').forEach(t=>{
      if(t.id&&(opts.skip||[]).indexOf(t.id)>=0)return;
      if(!t.querySelector('thead th'))return;
      let head=null, n=t;
      for(let up=0; up<6 && n; up++){ n=n.parentElement; if(!n)break;
        const h=n.querySelector(':scope > .toolbar'); if(h){ head=h; break; }
        const h2=n.querySelector(':scope > h2, :scope > h3, :scope > .sechead'); if(h2){ head=h2.parentElement; break; } }
      if(!head||head.querySelector('.hmwbtn'))return;
      const title=_hmNearestHeading(t)||base;
      const btn=hMail(head, ()=>{ return hTableData(t, title); }, {mode:'data', label:'📧'});
      if(btn) btn.classList.add('hmwbtn');
    });
  };
  attach();
  // tables are usually rendered AFTER an agent runs — observe the DOM and re-attach
  // (debounced) so per-widget buttons appear on dynamically-injected tables too.
  try{
    let pend=0; const ob=new MutationObserver(()=>{ if(pend)return; pend=1;
      setTimeout(()=>{ pend=0; try{ attach(); }catch(e){} }, 120); });
    ob.observe(document.body, {childList:true, subtree:true});
  }catch(e){}
  return {rescan:attach};
}

/* ===== Shared top nav (same menu as the artifact) — auto-mounted on every page ===== */
// A nav item is [label, href] OR [label, [[subLabel, subHref], ...]] for a dropdown.
// Ownership Assignment + Software analyzer moved OUT of the nav → they live on the
// agent grid (Release the Hounds). Tags + MCP compare moved to header chips.
const _NAV_ITEMS = [
  ['🐾 On the Scent', '/agents/insights/page.html'],
  ['SEP'],
  ['<span class="hcrest sm" aria-hidden="true"></span>Release the Hounds', '/'],
  ['📜 AI Contract', '/agents/contract/page.html'],
  ['📧 Email · Gabriel', '/agents/email/page.html'],
  ['SEP'],
  ['📊 Dashboards', '/web/dashboards.html'],
  ['🔎 Search Hounds', '/web/search.html'],
  ['🛠 Tools', '/web/tools.html'],
];
function _navddStyle(){
  if(document.getElementById('navddStyle')) return;
  const st=document.createElement('style'); st.id='navddStyle';
  st.textContent='.navdd{position:relative;display:inline-block}'
   +'.navdd-menu{display:none;position:absolute;top:100%;left:0;z-index:60;min-width:200px;'
   +'background:var(--panel,#161616);border:1px solid var(--line,#333);border-radius:10px;padding:6px;'
   +'box-shadow:0 12px 30px rgba(0,0,0,.5);flex-direction:column;gap:2px;margin-top:4px}'
   +'.navdd.open .navdd-menu{display:flex}'
   +'.navdd-item{display:block;text-align:left;width:100%;background:transparent;border:0;'
   +'color:var(--ink-2,#cfcfcf);padding:8px 11px;border-radius:7px;font-size:12.5px;cursor:pointer;white-space:nowrap}'
   +'.navdd-item:hover{background:var(--panel2,var(--bg-2,#222));color:var(--ink,#fff)}'
   +'.navdd-item.active{color:var(--accent,#d6f84c)}'
   +'.navdd-caret{font-size:10px;opacity:.7;margin-left:2px}'
   +'.searchsub{display:flex;flex-wrap:wrap;align-items:center;gap:7px;margin:0 0 6px;padding:9px 12px;'
   +'background:var(--panel,#161616);border:1px solid var(--line,#333);border-radius:11px}'
   +'.searchsub .lbl{font-size:11px;font-weight:700;letter-spacing:.04em;text-transform:uppercase;color:var(--mut,#8a99ad);margin-right:4px}'
   +'.searchsub button{background:transparent;border:1px solid var(--line,#333);color:var(--ink-2,#cfcfcf);padding:6px 12px;border-radius:999px;font-size:12.5px;cursor:pointer;white-space:nowrap;transition:border-color .12s,background .12s}'
   +'.searchsub button:hover{border-color:var(--accent);color:var(--ink,#fff)}'
   +'.searchsub button.active{background:var(--accent);border-color:var(--accent);color:#fff;font-weight:600}';
  document.head.appendChild(st);
}
// The Dashboards shelf — horizontal sub-bar on every dashboard page + the hub.
const DASH_PAGES = [
  ['📊 Dashboard builder','/agents/dashboard/page.html'],
  ['🗂 Custom Dashboard', '/web/customdash.html'],
  ['⚖️ Compliance',       '/web/compliancedash.html'],
  ['🗺 Ownership Map',     '/web/ownermap.html'],
];
function mountDashboardsNav(){
  const p = location.pathname;
  const isDash = DASH_PAGES.some(s => p === s[1] || p.endsWith(s[1])) || p.endsWith('/web/dashboards.html');
  const old = document.getElementById('dashsub'); if(old) old.remove();
  if(!isDash) return;
  const bar = document.createElement('nav'); bar.className = 'searchsub'; bar.id = 'dashsub';
  bar.innerHTML = '<span class="lbl">📊 Dashboards</span>' + DASH_PAGES.map(s => {
    const a = (p === s[1] || p.endsWith(s[1]));
    return '<button class="' + (a ? 'active' : '') + '" data-href="' + s[1] + '">' + s[0] + '</button>';
  }).join('');
  const anchor = document.getElementById('topnav') || document.querySelector('header.top, #app-header, header');
  if(anchor && anchor.parentNode) anchor.insertAdjacentElement('afterend', bar);
  bar.querySelectorAll('button[data-href]').forEach(b => b.onclick = () => { location.href = b.dataset.href; });
}
// The Search-Hounds pack — shown as a horizontal sub-bar on every search page + the hub.
const SEARCH_PAGES = [
  ['🔦 Argos',   '/agents/argos/page.html'],
  ['🧠 Advanced','/web/advanced.html'],
  ['🔎 Assets',  '/agents/ex_assets/page.html'],
  ['🔎 Vulns',   '/agents/ex_vulns/page.html'],
  ['🔎 Plugins', '/agents/ex_plugins/page.html'],
  ['🔎 Tags',    '/agents/ex_tags/page.html'],
  ['🔎 Routes',  '/agents/ex_routes/page.html'],
  ['🔎 Paths',   '/agents/ex_paths/page.html'],
  ['🔎 Apps',    '/agents/ex_apps/page.html'],
  ['🔎 Fixed',   '/agents/ex_fixed/page.html'],
];
function mountSearchNav(){
  const p = location.pathname;
  const isSearch = SEARCH_PAGES.some(s => p === s[1] || p.endsWith(s[1])) || p.endsWith('/web/search.html');
  const old = document.getElementById('searchsub'); if(old) old.remove();
  if(!isSearch) return;
  const bar = document.createElement('nav'); bar.className = 'searchsub'; bar.id = 'searchsub';
  bar.innerHTML = '<span class="lbl">🔎 Search Hounds</span>' + SEARCH_PAGES.map(s => {
    const a = (p === s[1] || p.endsWith(s[1]));
    return '<button class="' + (a ? 'active' : '') + '" data-href="' + s[1] + '">' + s[0] + '</button>';
  }).join('');
  const anchor = document.getElementById('topnav') || document.querySelector('header.top, #app-header, header');
  if(anchor && anchor.parentNode) anchor.insertAdjacentElement('afterend', bar);
  bar.querySelectorAll('button[data-href]').forEach(b => b.onclick = () => { location.href = b.dataset.href; });
}
// The Tools shelf — same horizontal-bar treatment as Search Hounds. "Refresh
// navi.db" is an action (#refresh → naviRefresh), the rest navigate.
const TOOLS_PAGES = [
  ['↻ Refresh navi.db','#refresh'],
  ['🏷️ Tagging log',   '/web/tags-log.html'],
  ['🎯 ACR log',       '/web/acr-log.html'],
  ['🖥 C2 log',        '/web/c2-log.html'],
  ['⚖ Tag compare',    '/web/tags.html'],
  ['⚖ MCP compare',    '/agents/mcpcmp/page.html'],
  ['🧾 Runs & queries','/web/agent-runs.html'],
  ['⚙ Settings',       '/web/settings.html'],
];
function mountToolsNav(){
  const p = location.pathname;
  const isTools = TOOLS_PAGES.some(s => s[1] !== '#refresh' && (p === s[1] || p.endsWith(s[1]))) || p.endsWith('/web/tools.html');
  const old = document.getElementById('toolssub'); if(old) old.remove();
  if(!isTools) return;
  const bar = document.createElement('nav'); bar.className = 'searchsub'; bar.id = 'toolssub';
  bar.innerHTML = '<span class="lbl">🛠 Tools</span>' + TOOLS_PAGES.map(s => {
    const a = (s[1] !== '#refresh' && (p === s[1] || p.endsWith(s[1])));
    return '<button class="' + (a ? 'active' : '') + '" data-href="' + s[1] + '">' + s[0] + '</button>';
  }).join('');
  const anchor = document.getElementById('topnav') || document.querySelector('header.top, #app-header, header');
  if(anchor && anchor.parentNode) anchor.insertAdjacentElement('afterend', bar);
  bar.querySelectorAll('button[data-href]').forEach(b => b.onclick = () => {
    if(b.dataset.href === '#refresh'){ if(typeof naviRefresh === 'function') naviRefresh(b); return; }
    location.href = b.dataset.href;
  });
}
/* ===== Custom dashboards — up to DASH_MAX, saved per-browser ==================
   One store holds several named boards; the builder and the Custom Dashboard page
   both read/write the ACTIVE board's items, so pinned components land on whatever
   board is currently selected. The legacy single-array key is migrated + mirrored. */
const DASH_MAX = 5;
const DASH_STORE_KEY = 'navi-dashboards';
const DASH_LEGACY_KEY = 'navi-dashboard';
function _dashEsc(s){ return String(s==null?'':s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }
function _dashNewId(){ return 'd'+Date.now().toString(36)+Math.floor(Math.random()*1e4).toString(36); }
function dashLoadStore(){
  let s=null; try{ s=JSON.parse(localStorage.getItem(DASH_STORE_KEY)||'null'); }catch(e){}
  if(!s || !Array.isArray(s.list) || !s.list.length){
    let legacy=[]; try{ legacy=JSON.parse(localStorage.getItem(DASH_LEGACY_KEY)||'[]')||[]; }catch(e){}
    const id=_dashNewId();
    s={ v:2, active:id, list:[ {id, name:'Dashboard 1', items:Array.isArray(legacy)?legacy:[]} ] };
    dashSaveStore(s);
  }
  if(!s.list.some(d=>d.id===s.active)) s.active=s.list[0].id;
  return s;
}
function dashSaveStore(s){
  try{ localStorage.setItem(DASH_STORE_KEY, JSON.stringify(s)); }catch(e){}
  try{ const a=(s.list||[]).find(d=>d.id===s.active); localStorage.setItem(DASH_LEGACY_KEY, JSON.stringify(a?a.items:[])); }catch(e){}
}
function dashList(){ return dashLoadStore().list; }
function dashActive(){ const s=dashLoadStore(); return s.list.find(d=>d.id===s.active)||s.list[0]; }
function dashGetItems(){ return dashActive().items||[]; }
function dashSetItems(items){ const s=dashLoadStore(); const a=s.list.find(d=>d.id===s.active)||s.list[0]; a.items=items||[]; dashSaveStore(s); }
function dashSetActive(id){ const s=dashLoadStore(); if(s.list.some(d=>d.id===id)){ s.active=id; dashSaveStore(s); } }
function dashAdd(name){ const s=dashLoadStore(); if(s.list.length>=DASH_MAX) return null; const id=_dashNewId();
  s.list.push({id, name:(name||('Dashboard '+(s.list.length+1))), items:[]}); s.active=id; dashSaveStore(s); return id; }
function dashRename(id,name){ const s=dashLoadStore(); const d=s.list.find(x=>x.id===id); if(d && name && name.trim()){ d.name=name.trim(); dashSaveStore(s); } }
function dashRemove(id){ const s=dashLoadStore();
  if(s.list.length<=1){ s.list[0].items=[]; dashSaveStore(s); return; }
  s.list=s.list.filter(d=>d.id!==id); if(!s.list.some(d=>d.id===s.active)) s.active=s.list[0].id; dashSaveStore(s); }
/* Portability — Export downloads every board as one JSON backup; Import merges
   boards from a file back in (respecting the DASH_MAX cap), so dashboards move
   across ports, browsers, and machines. */
function dashExportDownload(){
  const s=dashLoadStore();
  const payload={ v:2, kind:'hounds-dashboards', exported:new Date().toISOString(),
                  list:s.list.map(d=>({name:d.name, items:d.items||[]})) };
  const blob=new Blob([JSON.stringify(payload,null,2)],{type:'application/json'});
  const u=URL.createObjectURL(blob); const a=document.createElement('a');
  a.href=u; a.download='hounds-dashboards-'+new Date().toISOString().slice(0,10)+'.json'; a.click();
  setTimeout(()=>URL.revokeObjectURL(u),2000);
}
function dashImportObj(obj){
  let boards=[];
  if(obj && Array.isArray(obj.list)) boards=obj.list;
  else if(Array.isArray(obj)){
    if(obj.length && obj[0] && (obj[0].items || obj[0].name)) boards=obj;   // array of boards
    else boards=[{name:'Imported', items:obj}];                            // bare component array
  }
  else if(obj && (obj.items || obj.name)) boards=[obj];
  else return {added:0, skipped:0, error:'unrecognized file'};
  let added=0, skipped=0, firstId=null;
  boards.forEach(b=>{
    const name=(b && b.name) ? String(b.name) : 'Imported';
    const items=(b && Array.isArray(b.items)) ? b.items : (Array.isArray(b) ? b : []);
    const id=dashAdd(name);
    if(!id){ skipped++; return; }
    dashSetItems(items); added++; if(!firstId) firstId=id;
  });
  if(firstId) dashSetActive(firstId);
  return {added, skipped};
}
function _dashPickFile(cb){
  let inp=document.getElementById('__dashImportInput');
  if(!inp){ inp=document.createElement('input'); inp.type='file'; inp.accept='application/json,.json';
    inp.id='__dashImportInput'; inp.style.display='none'; document.body.appendChild(inp); }
  inp.value='';
  inp.onchange=()=>{ const f=inp.files && inp.files[0]; if(!f) return;
    const r=new FileReader(); r.onload=()=>{ try{ cb(JSON.parse(r.result)); }catch(e){ alert('Could not read that file — is it a dashboard JSON export?\n\n'+e.message); } };
    r.readAsText(f); };
  inp.click();
}
/* Render the tab strip into container #id; onChange() fires after any switch/add/
   rename/delete so the page can reload its items and re-render. */
function mountDashTabs(containerId, onChange){
  const el=document.getElementById(containerId); if(!el) return;
  const s=dashLoadStore(); el.className='dashtabs';
  el.innerHTML='<span class="lbl">🗂 Dashboards</span>'+s.list.map(d=>{
    const a=d.id===s.active;
    return '<span class="dtab'+(a?' active':'')+'">'
      +'<button class="dtab-name" data-sw="'+esc(d.id)+'" title="Switch to this dashboard">'+_dashEsc(d.name)+'</button>'
      +(a?'<button class="dtab-ic" data-ren="'+esc(d.id)+'" title="Rename">✎</button>'
         +'<button class="dtab-ic" data-del="'+esc(d.id)+'" title="Delete this dashboard">✕</button>':'')
      +'</span>';
  }).join('')
  +(s.list.length<DASH_MAX
     ? '<button class="dtab-add" title="New dashboard">+ New</button>'
     : '<span class="dtab-max" title="Maximum reached">max '+DASH_MAX+'</span>')
  +'<span class="dsep"></span>'
  +'<button class="dtab-io" data-exp title="Download all dashboards as a JSON backup">⤓ Export</button>'
  +'<button class="dtab-io" data-imp title="Import dashboards from a JSON backup (merges, up to '+DASH_MAX+')">⤒ Import</button>';
  const done=()=>{ if(typeof onChange==='function') onChange(); };
  el.querySelectorAll('[data-sw]').forEach(b=>b.onclick=()=>{ dashSetActive(b.dataset.sw); done(); });
  el.querySelectorAll('[data-ren]').forEach(b=>b.onclick=()=>{ const cur=dashActive(); const n=prompt('Rename dashboard', cur.name); if(n!==null && n.trim()){ dashRename(b.dataset.ren, n); done(); } });
  el.querySelectorAll('[data-del]').forEach(b=>b.onclick=()=>{ const d=dashList().find(x=>x.id===b.dataset.del); const nm=d?d.name:'this dashboard';
    if(confirm('Delete “'+nm+'” and its pinned components?')){ dashRemove(b.dataset.del); done(); } });
  const addb=el.querySelector('.dtab-add'); if(addb) addb.onclick=()=>{ if(dashList().length>=DASH_MAX){ alert('You already have the maximum of '+DASH_MAX+' dashboards.'); return; }
    const n=prompt('Name the new dashboard', 'Dashboard '+(dashList().length+1)); if(n===null) return; dashAdd(n.trim()); done(); };
  const eb=el.querySelector('[data-exp]'); if(eb) eb.onclick=()=>dashExportDownload();
  const ib=el.querySelector('[data-imp]'); if(ib) ib.onclick=()=>_dashPickFile(obj=>{
    const r=dashImportObj(obj);
    alert(r.error ? ('Import failed — '+r.error+'.') : ('Imported '+r.added+' dashboard'+(r.added===1?'':'s')+(r.skipped?' · skipped '+r.skipped+' (the '+DASH_MAX+'-board max was reached)':'')+'.'));
    done();
  });
}
/* Left-sidebar navigation model — grouped, guided-flow order. Item: [iconHTML, label, href]. */
const _SIDE_GROUPS=[
  [null,[
    ['🐾','On the Scent','/agents/insights/page.html'],
    ['<span class="hcrest sm" aria-hidden="true"></span>','Release the Hounds','/'],
  ]],
  ['Fast signal',[
    ['🎯','MITRE ATT&CK','/agents/mitre/page.html'],
    ['🛡️','CISA KEV','/agents/cisakev/page.html'],
    ['🔩','EOL / Unsupported','/agents/eol/page.html'],
    ['🔐','Certificates','/agents/certificate/page.html'],
  ]],
  ['Deeper analysis',[
    ['🐾','IoT Discovery','/agents/iot_squad/page.html'],
    ['⚛️','Post-Quantum','/agents/postquantum/page.html'],
    ['🤖','AI Inventory','/agents/ai/page.html'],
    ['🪪','Identity','/agents/identity/page.html'],
    ['📦','Software','/agents/software/page.html'],
    ['🏷️','Custom Apps','/agents/customapp/page.html'],
    ['🕸️','Web Apps (WAS)','/agents/was/page.html'],
    ['⚖️','Compliance','/agents/compliance/page.html'],
    ['🕸️','Attack Paths','/agents/attackpath/page.html'],
    ['🩺','Scan Evaluations','/agents/scan_eval/page.html'],
  ]],
  ['Organize',[
    ['🛰️','Agent Groups','/agents/agentgroup/page.html'],
    ['📇','Asset Classification','/agents/classify/page.html'],
    ['🧭','Exposure Routes','/agents/exproute/page.html'],
    ['📌','Asset Ownership','/agents/asset_ownership/page.html'],
    ['⚖️','ACR Calibration','/agents/acr/page.html'],
  ]],
  ['Operationalize',[
    ['📜','Custom Audit','/agents/custom_audit/page.html'],
    ['⏱','SLA Adherence','/agents/sla/page.html'],
    ['📧','Email · Gabriel','/agents/email/page.html'],
    ['🐦‍⬛','Alert Raven','/agents/alert/page.html'],
    ['🗑️','Tag Removal','/agents/tagremoval/page.html'],
    ['🐺','Command & Control','/agents/c2/page.html'],
    ['📜','AI Contract','/agents/contract/page.html'],
  ]],
  ['Views',[
    ['🎯','Exposure Score','/agents/fused_score/page.html'],
    ['📊','Dashboards','/web/dashboards.html'],
    ['🔦','Argos Deep-Dive','/agents/argos/page.html'],
    ['🐾','Web App Recon','/agents/was_asset/page.html'],
    ['🔍','Compliance Deep-Dive','/agents/compliance_asset/page.html'],
  ]],
  ['System',[
    ['🔎','Search Hounds','/web/search.html'],
    ['🛠','Tools','/web/tools.html'],
  ]],
];
const _phoneNav = () => { try{ return window.matchMedia('(max-width:640px)').matches; }catch(e){ return false; } };
function mountTopNav(){
  const wrap = document.querySelector('.wrap'); if(!wrap) return;
  _navddStyle();   // injects .searchsub styling used by the Dashboards/Search/Tools sub-bars
  try{ if(localStorage.getItem('naviNavCollapsed')==='1') document.body.classList.add('navcollapsed'); }catch(e){}
  const old = document.getElementById('topnav'); if(old) old.remove();
  const p = location.pathname;
  const active = href => href === '/' ? (p === '/' || p === '/index.html')
                                      : (p === href || p.endsWith(href));
  const nav = document.createElement('nav'); nav.className = 'tabs'; nav.id = 'topnav';
  nav.innerHTML = _SIDE_GROUPS.map(g => {
    const head = g[0] ? '<div class="navgrp">' + g[0] + '</div>' : '';
    const items = g[1].map(it => {
      const lbl = String(it[1]).replace(/&/g,'&amp;');
      return '<button class="' + (active(it[2]) ? 'active' : '') + '" data-href="' + it[2] + '">' +
        '<span class="ico">' + it[0] + '</span><span class="lbl">' + lbl + '</span></button>';
    }).join('');
    return head + items;
  }).join('');
  const anchor = document.querySelector('header.top, #app-header, header');
  if(anchor && anchor.parentNode) anchor.insertAdjacentElement('afterend', nav);
  else wrap.prepend(nav);
  nav.querySelectorAll('button[data-href]').forEach(b => b.onclick = (e) => {
    e.stopPropagation(); location.href = b.dataset.href;
  });
  // collapse toggle lives in the top bar (header)
  const hdr = document.querySelector('header.top, #app-header');
  if(hdr && !hdr.querySelector('.side-collapse')){
    const cb = document.createElement('button');
    cb.className = 'side-collapse'; cb.type = 'button';
    // phone (≤640px): ☰ opens an overlay drawer · wider: ⇔ collapses the sidebar to icons.
    // Re-evaluated whenever the width crosses 640px, so a rotated/resized window stays right.
    const sync = () => { const ph=_phoneNav(); const t=ph?'Open navigation':'Collapse navigation';
      cb.textContent = ph ? '☰' : '⇔'; cb.title = t; cb.setAttribute('aria-label', t);
      if(!ph) document.body.classList.remove('navopen'); };
    sync();
    try{ const mq=window.matchMedia('(max-width:640px)'); (mq.addEventListener?mq.addEventListener('change',sync):mq.addListener(sync)); }catch(e){}
    cb.onclick = (e) => {
      e.stopPropagation();
      if(_phoneNav()){ document.body.classList.toggle('navopen'); return; }   // phone: open/close the drawer
      document.body.classList.toggle('navcollapsed');
      try{ localStorage.setItem('naviNavCollapsed', document.body.classList.contains('navcollapsed') ? '1' : '0'); }catch(e){}
    };
    hdr.insertBefore(cb, hdr.firstChild);
    // phone drawer: a tap outside it closes it (and only closes it — the tap doesn't also
    // activate whatever was underneath); Escape closes it too
    document.addEventListener('click', ev => {
      if(document.body.classList.contains('navopen') && !ev.target.closest('#topnav') && !ev.target.closest('.side-collapse')){
        document.body.classList.remove('navopen'); ev.preventDefault(); ev.stopPropagation(); }
    }, true);
    document.addEventListener('keydown', ev => {
      if(ev.key==='Escape' && document.body.classList.contains('navopen')) document.body.classList.remove('navopen');
    });
  }
  mountDashboardsNav();                 // horizontal Dashboards bar on dashboard pages + the hub
  mountSearchNav();                     // horizontal Search-Hounds bar on search pages + the hub
  mountToolsNav();                      // horizontal Tools bar on tool pages + the hub
  mountTestRunChip();                   // 🧪 test-run indicator (Settings → Test run)
}
/* ===== Test run (Settings → Test run · core/tagname.py) =====
   While it is on, every tag CATEGORY a Hound writes is '<phrase>-<category>'. The server
   applies it (core/navi_cli.tag); pages use tagCat() only to SHOW the name that will be
   written (confirm dialogs, previews). A small amber chip in the top bar says it is on. */
let _TR=null, _TRP=null;
function testRunStatus(force){
  if(force||!_TRP) _TRP=jget('/api/health').then(h=>{ _TR=(h&&h.tag_prefix)||null; return _TR; }).catch(()=>null);
  return _TRP;
}
function testRunOn(){ return !!(_TR&&_TR.enabled); }
/* the category a Hound will actually write (never double-prefixed; exact when off) */
function tagCat(c){
  c=String(c==null?'':c); const p=testRunOn()?String(_TR.prefix||''):'';
  return (!p||!c.trim()||c.toLowerCase().startsWith(p.toLowerCase()))?c:p+c;
}
/* Preset SQL that recognises a Hound's tag by name (tag_key='Owner') also matches its
   test-run name: tag_key IN ('Owner','Hounds-Owner') — the configured prefix, on or off
   (core/tagname.py reads the same way). Await testRunStatus() first. */
function tagKeySql(sql){
  const p=_TR&&_TR.configured_prefix; if(!p) return sql;
  const q=String(p).replace(/'/g,"''");
  const pl=String(p).toLowerCase();
  // tag_key IN ('IoT','Device Type') → each name plus its test-run name (already-prefixed names left alone)
  const out=String(sql||'').replace(/\btag_key(\s+IN\s*\()\s*('(?:[^']|'')*'(?:\s*,\s*'(?:[^']|'')*')*)\s*\)/gi,(m,inn,list)=>{
    const ks=list.match(/'(?:[^']|'')*'/g)||[]; const add=[];
    ks.forEach(t=>{ const k=t.slice(1,-1); if(k && !k.toLowerCase().startsWith(pl)) add.push("'"+q+k+"'"); });
    return 'tag_key'+inn+ks.concat(add.filter(x=>ks.indexOf(x)<0)).join(',')+')'; });
  return out.replace(/\btag_key\s*=\s*'((?:[^']|'')+)'/g,(m,k)=>k.toLowerCase().startsWith(pl)?m:"tag_key IN ('"+k+"','"+q+k+"')");
}
function mountTestRunChip(force){
  testRunStatus(force).then(t=>{
    const old=document.getElementById('testRunChip'); if(old) old.remove();
    if(!t||!t.enabled) return;
    const host=document.querySelector('#app-header #meta')||document.querySelector('header.top #meta')
      ||document.querySelector('#app-header, header.top'); if(!host) return;
    const a=document.createElement('a'); a.id='testRunChip'; a.className='chip'; a.href='/web/settings.html#trCard';
    a.title='Test run is ON — every tag the Hounds create is written as '+(t.prefix||'')+'<category>. Turn it off or change the phrase in Settings; clean up with Tag Removal.';
    a.style.cssText='text-decoration:none;background:rgba(251,191,36,.14);border-color:rgba(251,191,36,.45);color:var(--warn,#fbbf24);white-space:nowrap';
    a.textContent='🧪 test run · '+(t.prefix||'');
    host.prepend(a);
  });
}
if(document.readyState !== 'loading') mountTopNav();
else document.addEventListener('DOMContentLoaded', mountTopNav);

/* Reasoning-provider indicator — BRING YOUR OWN MODEL. The AI features
   (ask-which-agent, NL→SQL, contract policy, cert reasoning) run on whichever
   provider is configured: Claude, an OpenAI-compatible endpoint, a local Ollama,
   or Bedrock. Green with the provider + model when reachable; amber with the
   actionable reason when not. h.llm / h.llm_provider / h.llm_model / h.llm_why
   come from /api/health. */
const _LLM_LABEL={anthropic:'✦ Claude', openai:'✦ OpenAI-compatible',
                  ollama:'✦ Local · Ollama', bedrock:'✦ AWS Bedrock'};
function claudeChip(h){
  const ok=!!(h&&h.llm), prov=(h&&h.llm_provider)||'', model=(h&&h.llm_model)||'';
  if(ok){
    const label=(_LLM_LABEL[prov]||'✦ AI')+(model?(' · '+model):'');
    return `<span class="chip" title="Reasoning runs on ${esc(prov||'a configured provider')}${model?(' — model '+esc(model)):''}. AI features enabled." style="background:var(--ok-bg);border-color:var(--ok);color:var(--ok)">${esc(label)}</span>`;
  }
  const why=(h&&h.llm_why)||'No model configured. Pick a provider on the Settings page — Claude, any OpenAI-compatible endpoint, a local Ollama, or Bedrock.';
  return `<span class="chip" title="${esc(why)} The AI features (ask-which-agent, NL→SQL, contract policy, cert reasoning) are disabled; every detection, score and dashboard still works." style="background:rgba(251,191,36,.14);border-color:rgba(251,191,36,.45);color:var(--warn,#fbbf24)">⚠ AI: no model</span>`;
}

/* Mount the shared header (logo, title, live health chips). */
/* ===== Guided flow — a fixed order through the pack so each agent's header links to the
   next logical one. Highlight the Signal (fast → deeper) → Organize the Work → Operationalize,
   ending on the AI Contract. Agents not in the flow simply show no Next link. ===== */
const AGENT_FLOW=['mitre','cisakev','eol','certificate',
                  'iot_squad','postquantum',
                  'ai','identity','software','customapp','attackpath','scan_eval',
                  'agentgroup','classify','exproute','asset_ownership','acr',
                  'email','alert','tagremoval','c2','contract'];
const AGENT_FLOW_LABEL={mitre:'MITRE ATT&CK',cisakev:'CISA KEV',eol:'EOL / Unsupported',certificate:'Certificates',
  iot_squad:'IoT Discovery',postquantum:'Post-Quantum',
  ai:'AI Inventory',identity:'Identity Inventory',software:'Software Analyzer',customapp:'Custom Apps',
  attackpath:'Attack Paths',scan_eval:'Scan Evaluations',agentgroup:'Agent Groups',classify:'Asset Classification',
  exproute:'Exposure Routes',asset_ownership:'Asset Ownership',acr:'ACR Calibration',
  email:'Email & Reports',alert:'Alert Raven',tagremoval:'Tag Removal',c2:'Command & Control',contract:'AI Contract'};
function _flowCurrentId(){
  const m=(location.pathname||'').match(/\/agents\/([^\/]+)\//);
  return (m&&m[1])||window.__AGENT_ID||'';
}
function mountNextAgent(host){
  try{
    if(!host) return;
    const cur=_flowCurrentId(); const idx=AGENT_FLOW.indexOf(cur);
    const old=host.querySelector('.nextagent'); if(old) old.remove();
    const a=document.createElement('a'); a.className='nextagent';
    if(idx>=0 && idx<AGENT_FLOW.length-1){
      const nx=AGENT_FLOW[idx+1];
      a.href='/agents/'+nx+'/page.html';
      a.innerHTML='Next agent · <b>'+esc(AGENT_FLOW_LABEL[nx]||nx)+'</b> →';
      a.title='Guided flow · step '+(idx+2)+' of '+AGENT_FLOW.length+' — '+(AGENT_FLOW_LABEL[nx]||nx);
    } else if(cur==='contract'){
      a.href='/'; a.innerHTML='✓ End of the guided flow · <b>All agents</b>';
      a.title='You’ve reached the end of the pack — back to Release the Hounds';
    } else { return; }   // not part of the guided flow → no Next link
    host.appendChild(a);
  }catch(e){}
}
async function mountAgentHeader(opts){
  opts = opts || {};
  // Pages that create a second agentApi('explore') at load time clobber __AGENT_ID;
  // let a page pin its real agent id so the codename intro always resolves.
  if(opts.id) window.__AGENT_ID = opts.id;
  const host = document.getElementById('app-header') || (function(){
    const d = document.createElement('header'); d.id='app-header'; d.className='top';
    document.querySelector('.wrap').prepend(d); return d;
  })();
  const radar='<span class="hcrest brand" role="img" aria-label="The Hounds"></span>';
  host.innerHTML =
    `<a href="/" class="logo" title="All agents">${radar}</a>`+
    `<h1>${esc(opts.name||'Navi Agent')}</h1>`+
    `<div class="meta" id="meta"></div>`;
  _mountCodename(host);
  mountTopNav();
  mountNextAgent(host);
  try{
    const h = await jget('/api/health');
    window.__LLM_AVAILABLE = !!h.llm; applyLlmGate();
    const meta = document.getElementById('meta');
    const we = h.writes_enabled;
    meta.innerHTML =
      (h.version?`<span class="chip" title="The Hounds version — 1.&lt;agents&gt;.&lt;build&gt;"><b>v${esc(h.version)}</b></span>`:'')+
      dataSourceChip(h)+
      claudeChip(h)+
      (h.db_ok ? `<span class="chip">assets <b>${h.asset_total==null?'—':h.asset_total}</b></span>`+
                 (h.db_fresh?`<span class="chip">db <b>${String(h.db_fresh).slice(0,10)}</b></span>`:'')
               : `<span class="chip" style="color:var(--crit)">db: ${esc(h.error||'error')}</span>`)+
      `<span class="chip gate ${we?'':''}">writes: ${we?'enabled':'gated'}</span>`;
    _TR=h.tag_prefix||null; _TRP=Promise.resolve(_TR); mountTestRunChip();   // meta was just rewritten
    // Refresh / Tag compare / MCP compare / Runs & queries now live in the "🛠 Tools" nav dropdown.
  }catch(e){ /* no backend — header still shows */ }
}
/* Fire-and-forget navi.db refresh — kicks the sync server-side and returns at once.
   `el` is the nav dropdown item that triggered it (label doubles as a status readout). */
async function naviRefresh(el){
  const set = t => { if(el && el.dataset && el.dataset.href==='#refresh'){ el.textContent = t; } };
  set('↻ refreshing…');
  try{ const o=await agentApi('explore').post('navi_refresh',{kinds:['assets','vulns']});
    set((o&&o.started&&o.started.length)?('↻ refreshing '+o.started.join('+')+'…'):'↻ Refresh navi.db');
    alert((o&&o.started&&o.started.length)
      ? 'navi.db refresh started in the background ('+o.started.join(', ')+'). On large environments this can take several minutes — it runs on its own; reload the page when it finishes to see new tags/ACR.'
      : 'Could not start refresh: '+((o&&o.message)||'navi not available on this server.'));
  }catch(e){ alert('Refresh failed to start: '+e.message); }
  setTimeout(()=>set('↻ Refresh navi.db'), 8000);
}

/* Data-source chip: amber = crafted sample fixture, green = live navi.db. */
function dataSourceChip(h){
  const src = (h && h.data_source) || 'unknown';
  if(src==='fixture')
    return `<span class="chip" title="${esc((h&&h.provenance_note)||'crafted sample data')}" style="background:rgba(251,191,36,.14);border-color:rgba(251,191,36,.45);color:var(--warn,#fbbf24)">◆ SAMPLE data</span>`;
  if(src==='live')
    return `<span class="chip" title="${esc((h&&h.db_path)||'navi.db')}" style="background:var(--ok-bg);border-color:var(--ok);color:var(--ok)">● LIVE navi.db</span>`;
  return `<span class="chip" style="color:var(--mut)">data: unknown</span>`;
}

/* Tiny flash helper. el = element id or node. kind = ok|run|warn|crit. */
/* Shared client-side paginator for any DB-backed table. Drop-in:
 *   hPaginate('tblId', rowsArray, rowObj => '<tr>…</tr>', {wire: tb => …, empty: '…', cols: 6});
 * It slices to 50/page, auto-creates a "‹ Prev  a–b of N  Next ›" bar after the
 * table, and re-runs the optional wire() so per-row buttons keep working on each
 * page. Reset to the first page on a fresh load with hPageReset('tblId').  */
window.__hpg = window.__hpg || {};
function hPageReset(id){ window.__hpg[id] = 0; }
/* hPaginate — render rows into #tblId tbody, one page at a time, with a pager below.
   Default everywhere: 20 rows/page, Rows selector 10–50 (remembered per table).
   opts.per    default page size (20)
   opts.sizes  page-size choices, e.g. HPG_SIZES → adds a "Rows" selector; the choice is
               remembered per table (localStorage) and capped at the largest size
   opts.wire   fn(tbody) to bind row buttons after each render
   window.HPG_DEFAULT  page-wide defaults merged under opts (e.g. {per:20, sizes:HPG_SIZES})
   opts.empty / opts.cols   empty-state row */
const HPG_SIZES=[10,20,30,40,50];
function _hpgSize(tblId, opts){
  if(!opts.sizes) return opts.per || 50;
  let v=null; try{ v=parseInt(localStorage.getItem('hpgSize:'+location.pathname+':'+tblId),10); }catch(e){}
  const max=Math.max.apply(null, opts.sizes);
  return (v && opts.sizes.includes(v)) ? v : Math.min(opts.per || 20, max);
}
function hPaginate(tblId, rows, rowHtml, opts){
  // a page can set window.HPG_DEFAULT = {per:20, sizes:HPG_SIZES} to apply to all its tables
  opts = Object.assign({per:20, sizes:HPG_SIZES}, window.HPG_DEFAULT || {}, opts || {}); const PER = _hpgSize(tblId, opts); rows = rows || [];
  { const t=document.getElementById(tblId); if(t) t.dataset.paged='1'; }   // the auto-pager leaves managed tables alone
  const pages = Math.max(1, Math.ceil(rows.length / PER));
  let page = window.__hpg[tblId] || 0; if(page >= pages) page = pages - 1; if(page < 0) page = 0;
  window.__hpg[tblId] = page;
  const tb = document.querySelector('#' + tblId + ' tbody'); if(!tb) return;
  const slice = rows.slice(page * PER, (page + 1) * PER);
  tb.innerHTML = rows.length ? slice.map(rowHtml).join('')
    : (opts.empty || '<tr><td colspan="' + (opts.cols || 6) + '" class="sub">No rows.</td></tr>');
  if(opts.wire){ try{ opts.wire(tb); }catch(e){} }
  const pid = tblId + 'Pager';
  let pel = document.getElementById(pid);
  if(!pel){ const t = document.getElementById(tblId);
    if(t && t.parentNode){ pel = document.createElement('div'); pel.id = pid; pel.className = 'toolbar';
      pel.style.marginTop = '6px'; t.parentNode.insertBefore(pel, t.nextSibling); } }
  if(pel){
    const minSize = opts.sizes ? Math.min.apply(null, opts.sizes) : PER;
    if(pages <= 1 && rows.length <= minSize){ pel.style.display = 'none'; pel.innerHTML = ''; }
    else { pel.style.display = '';
      const a = rows.length ? page * PER + 1 : 0, b = Math.min(rows.length, (page + 1) * PER);
      pel.innerHTML = '<button class="btn ghost sm" ' + (page <= 0 ? 'disabled' : '') + ' data-hpv>‹ Prev</button>'
        + '<span class="sub" style="margin:0 10px">' + a + '–' + b + ' of ' + rows.length.toLocaleString()
        + (pages > 1 ? ' · page ' + (page + 1) + '/' + pages : '') + '</span>'
        + '<button class="btn ghost sm" ' + (page >= pages - 1 ? 'disabled' : '') + ' data-hnx>Next ›</button>'
        + (opts.sizes ? '<label class="sub" style="margin-left:auto;display:flex;align-items:center;gap:6px">Rows'
            + '<select data-hsz style="padding:3px 6px;border-radius:6px;border:1px solid var(--line);background:var(--bg-2);color:var(--ink)">'
            + opts.sizes.map(n => '<option value="' + n + '"' + (n === PER ? ' selected' : '') + '>' + n + '</option>').join('')
            + '</select></label>' : '');
      const pv = pel.querySelector('[data-hpv]'), nx = pel.querySelector('[data-hnx]'), sz = pel.querySelector('[data-hsz]');
      if(pv) pv.onclick = () => { window.__hpg[tblId] = page - 1; hPaginate(tblId, rows, rowHtml, opts); };
      if(nx) nx.onclick = () => { window.__hpg[tblId] = page + 1; hPaginate(tblId, rows, rowHtml, opts); };
      if(sz) sz.onchange = () => { try{ localStorage.setItem('hpgSize:'+location.pathname+':'+tblId, sz.value); }catch(e){}
        window.__hpg[tblId] = Math.floor(page * PER / parseInt(sz.value,10)); hPaginate(tblId, rows, rowHtml, opts); };
    }
  }
}
/* Page size for a hand-built pager (same setting + storage as hPaginate): 20 by default,
   10–50 via the Rows selector. hSizeControl(container, key, onChange) appends that selector. */
function hPageSize(key){ return _hpgSize(key, {per:20, sizes:HPG_SIZES}); }
function hSizeControl(container, key, onChange){
  if(!container) return;
  const cur=hPageSize(key);
  const lab=document.createElement('label'); lab.className='sub'; lab.style.cssText='margin-left:auto;display:inline-flex;align-items:center;gap:6px';
  lab.innerHTML='Rows<select style="padding:3px 6px;border-radius:6px;border:1px solid var(--line);background:var(--bg-2);color:var(--ink)">'+
    HPG_SIZES.map(n=>'<option value="'+n+'"'+(n===cur?' selected':'')+'>'+n+'</option>').join('')+'</select>';
  lab.querySelector('select').onchange=e=>{ try{ localStorage.setItem('hpgSize:'+location.pathname+':'+key, e.target.value); }catch(_){} onChange(parseInt(e.target.value,10)); };
  container.appendChild(lab);
}

/* Auto-pager — every plain data table on an agent page with more than 10 rows shows 20
   rows/page (Rows selector up to 50), whatever code rendered it. Extra rows are HIDDEN,
   not removed, so 📧 email / ⬇ CSV still export the whole table. Skipped: tables managed
   by hPaginate (data-paged), tables/ancestors marked .nopage, and tables with grouped or
   expandable rows (any colspan cell beyond a single empty-state row). */
(function(){
  if(!/^\/agents\//.test(location.pathname)) return;
  const st=document.createElement('style'); st.textContent='tr.ap-hide{display:none!important}'; document.head.appendChild(st);
  // page position survives a re-render (pages often rebuild their tables on every click):
  // keyed by table id, else by position on the page + header text
  const pageOf=new Map();
  function keyOf(t){ if(t.id) return t.id;
    const all=[...document.querySelectorAll('table')]; const th=t.tHead&&t.tHead.rows[0]?t.tHead.rows[0].textContent.trim().slice(0,40):'';
    return 't'+all.indexOf(t)+':'+th; }
  function anchorOf(t){ const p=t.parentElement; return (p && p.children.length===1 && /auto|scroll/.test(p.style.overflowX+p.style.overflow)) ? p : t; }
  function apply(t){
    if(t.dataset.paged==='1' || t.classList.contains('nopage') || t.closest('.nopage') || t.closest('#app-header')) return;
    const tb=t.tBodies[0]; if(!tb) return;
    const rows=[...tb.rows]; const key=keyOf(t);
    let pel=t.__apPager;
    const structured = rows.length>1 && rows.some(r=>[...r.cells].some(c=>c.colSpan>1));
    if(rows.length<=10 || structured){ rows.forEach(r=>r.classList.remove('ap-hide')); if(pel){ pel.remove(); t.__apPager=null; } return; }
    const per=hPageSize(key), pages=Math.ceil(rows.length/per);
    let page=pageOf.get(key)||0; if(page>=pages) page=pages-1; if(page<0) page=0; pageOf.set(key,page);
    rows.forEach((r,i)=>r.classList.toggle('ap-hide', i<page*per || i>=(page+1)*per));
    if(!pel){ pel=document.createElement('div'); pel.className='toolbar ap-pager'; pel.style.marginTop='6px';
      const an=anchorOf(t); an.parentNode.insertBefore(pel, an.nextSibling); t.__apPager=pel; }
    const a=page*per+1, b=Math.min(rows.length,(page+1)*per);
    pel.innerHTML='<button class="btn ghost sm" '+(page<=0?'disabled':'')+' data-p="-1">‹ Prev</button>'+
      '<span class="sub" style="margin:0 10px">'+a+'–'+b+' of '+rows.length.toLocaleString()+(pages>1?' · page '+(page+1)+'/'+pages:'')+'</span>'+
      '<button class="btn ghost sm" '+(page>=pages-1?'disabled':'')+' data-p="1">Next ›</button>';
    pel.querySelectorAll('[data-p]').forEach(btn=>btn.onclick=()=>{ pageOf.set(key, page+parseInt(btn.dataset.p,10)); apply(t); });
    hSizeControl(pel, key, ()=>{ pageOf.set(key,0); apply(t); });
  }
  let queued=false, dirty=new Set();
  function flush(){ queued=false; const ts=[...dirty]; dirty.clear(); ts.forEach(t=>{ if(t.isConnected) apply(t); }); }
  function mark(t){ dirty.add(t); if(!queued){ queued=true; requestAnimationFrame(flush); } }
  function scan(node){ if(!node || node.nodeType!==1) return;
    if(node.tagName==='TABLE') mark(node); else if(node.closest) { const t=node.closest('table'); if(t) mark(t); }
    if(node.querySelectorAll) node.querySelectorAll('table').forEach(mark); }
  const mo=new MutationObserver(ms=>ms.forEach(m=>{ if(m.target.closest && m.target.closest('.ap-pager')) return;
    m.addedNodes.forEach(scan); if(m.target.tagName==='TBODY'||m.target.tagName==='TABLE') scan(m.target); }));
  const start=()=>{ document.querySelectorAll('table').forEach(mark); mo.observe(document.body,{childList:true,subtree:true}); };
  if(document.body) start(); else document.addEventListener('DOMContentLoaded', start);
})();

function flash(el, html, kind){
  const n = typeof el==='string' ? document.getElementById(el) : el;
  if(!n) return;
  const map = {ok:['var(--okbg,rgba(52,211,153,.14))','var(--ok)'],
               run:['rgba(62,166,255,.12)','var(--accent)'],
               warn:['rgba(251,191,36,.12)','var(--warn)'],
               crit:['rgba(251,113,133,.12)','var(--crit)']};
  const [bg,co] = map[kind]||map.run;
  n.className='flash show'; n.style.background=bg; n.style.color=co; n.innerHTML=html;
}
function flashClear(el){ const n = typeof el==='string'?document.getElementById(el):el; if(n) n.className='flash'; }

/* ===== Hand-off to Gabriel (the email agent) — the pack's shared "second option" =====
   Any Hound calls emailFindings({source_agent, source_hound, headline, finding_ids,
   asset_uuids, tag}) after a search/tag. We stash the payload and open Gabriel, which
   picks it up, composes the "agent findings" email (overview + the finding IDs that made
   up the search + the tagged assets with Tenable deep-links) and previews it — send stays
   gated. finding_ids = the plugin IDs that drove the asset search; asset_uuids = the
   matched assets; tag = {category,value} that was (or would be) applied. */
function emailFindings(payload){
  try{ sessionStorage.setItem('gabriel_handoff', JSON.stringify(payload||{})); }catch(e){}
  location.href='/agents/email/page.html';
}
/* Convenience: an "📧 Email findings → Gabriel" button HTML string. Pass a JS expression
   (as a string) that evaluates to the payload at click time, e.g.
   emailFindingsBtn('buildEmailPayload()'). */
function emailFindingsBtn(exprOrPayload, label){
  const lab = label || '📧 Email findings → Gabriel';
  const k='efb'+(++_EFB_N); _EFB[k]=exprOrPayload;   // payload (or a global builder fn name) kept here, never inlined as JS
  return `<button class="btn ghost sm" data-efb="${k}" title="Hand these findings to Gabriel — email the finding IDs + tagged assets with Tenable deep-links">${lab}</button>`;
}
const _EFB={}; let _EFB_N=0;
document.addEventListener('click', e=>{ const b=e.target&&e.target.closest&&e.target.closest('[data-efb]'); if(!b) return;
  let v=_EFB[b.dataset.efb]; if(v===undefined) return;
  if(typeof v==='string'){ const m=/^\s*([A-Za-z_$][\w$]*)\s*(\(\s*\))?\s*$/.exec(v); const f=m&&window[m[1]]; v=(typeof f==='function')?f():null; }
  emailFindings(v); });
/* ===== Hand-off to Amarok (Command & Control) — "validate this path" / "remediate this vuln" =====
   c2Handoff({intent:'validate_path'|'diagnose'|'remediate', targets:[{ip,uuid,hostname}], path,
   plugin_id, cve, source}) stores the request in sessionStorage (same origin, this tab — NEVER the
   URL) and opens the C2 page, which reads + clears it, shows "Request from <source>", pre-fills
   the section and NEVER runs anything by itself (the operator clicks, then confirms).
   c2Link(intent, payload, label) returns a small link for a table row: the payload is kept in a
   page-local registry and the link carries only an opaque key (data-c2h) — no inline JS from data. */
function c2Handoff(req){
  const r=req||{}; const intent=['validate_path','diagnose','remediate'].includes(r.intent)?r.intent:'diagnose';
  const t=(Array.isArray(r.targets)?r.targets:[]).filter(x=>x&&x.ip).slice(0,256)
    .map(x=>({ip:String(x.ip),uuid:String(x.uuid||''),hostname:String(x.hostname||'')}));
  const out={intent, targets:t, source:String(r.source||document.title||'another hound').slice(0,60)};
  if(r.path) out.path=String(r.path).slice(0,1024);
  if(r.plugin_id!=null&&r.plugin_id!=='') out.plugin_id=String(r.plugin_id);
  if(r.cve) out.cve=String(r.cve);
  try{ sessionStorage.setItem('c2_handoff', JSON.stringify(out)); }catch(e){}
  location.href='/agents/c2/page.html';
}
const _C2H={}; let _C2H_N=0;
function c2Link(intent, payload, label){
  const k='c2h'+(++_C2H_N); _C2H[k]=Object.assign({}, payload||{}, {intent});
  const lab=label||(intent==='validate_path'?'🔎 Validate':'🛠 Remediate');
  const tip=intent==='validate_path'?'Hand this path + host to Amarok (Command & Control) to check it exists on the host — pre-filled, never run without your confirm'
    :'Hand this vulnerability + host(s) to Amarok (Command & Control) to plan a remediation — pre-filled, never run without your confirm';
  return `<a href="/agents/c2/page.html" class="applink c2h" data-c2h="${k}" title="${esc(tip)}" style="font-size:11.5px;white-space:nowrap">${esc(lab)}</a>`;
}
document.addEventListener('click', e=>{ const a=e.target&&e.target.closest&&e.target.closest('[data-c2h]'); if(!a) return;
  const v=_C2H[a.dataset.c2h]; if(!v) return; e.preventDefault(); c2Handoff(v); });
/* Uniform "second option" across the pack: an agent calls registerFindings(payload) after
   it runs/tags, and a floating "📧 Email findings → Gabriel" button appears bottom-right.
   payload = {source_agent, source_hound, headline, finding_ids:[plugins], asset_uuids:[…],
   tag:{category,value}}. Clicking hands the finding IDs that made up the search — plus the
   tagged assets with Tenable deep-links — to Gabriel. Skips the email agent's own page. */
let __FINDINGS = null;
function registerFindings(p){
  if(!p || (window.__AGENT_ID==='email')) return;
  const fids=(p.finding_ids||[]).map(String), uu=(p.asset_uuids||[]).map(String);
  const hasTag = p.tag && p.tag.value;               // Gabriel can resolve assets from a tag
  if(!fids.length && !uu.length && !hasTag) return;   // nothing to hand off yet
  __FINDINGS = Object.assign({}, p, {finding_ids:fids, asset_uuids:uu});
  let b=document.getElementById('gabrielFab');
  if(!b){ b=document.createElement('button'); b.id='gabrielFab'; b.type='button'; b.className='btn run';
    // sit ABOVE the fixed dark/light toggle (#naviTheme, bottom:16px) so they never overlap
    b.style.cssText='position:fixed;right:16px;bottom:64px;z-index:9998;box-shadow:0 8px 24px rgba(0,0,0,.45);border-radius:999px';
    b.onclick=()=>emailFindings(__FINDINGS); document.body.appendChild(b); }
  b.title='Email these findings to Gabriel — the finding IDs that made up this search + the tagged assets, with Tenable deep-links';
  b.innerHTML='📧 Email findings → Gabriel'+(uu.length?(' · '+uu.length):'');
}
function clearFindings(){ __FINDINGS=null; const b=document.getElementById('gabrielFab'); if(b) b.remove(); }

/* ===== Resizable + auto-expand/collapse table columns (all repo pages) =====
   drag a header edge to resize · double-click the edge to auto-fit · double-click
   a header to toggle collapse/expand. Cells never character-wrap. */
(function(){ if(document.getElementById('rszStyle'))return; const s=document.createElement('style'); s.id='rszStyle';
  s.textContent='table.rsztbl td,table.rsztbl th{white-space:nowrap;overflow:hidden;text-overflow:ellipsis;vertical-align:top} table.rsztbl th{position:relative} table.rsztbl .rz{position:absolute;top:0;right:0;width:7px;height:100%;cursor:col-resize;user-select:none;z-index:2} table.rsztbl .rz:hover{background:var(--accent)}';
  (document.head||document.documentElement).appendChild(s); })();
function _colCells(tbl,i){ const out=[]; if(tbl.tHead&&tbl.tHead.rows[0]&&tbl.tHead.rows[0].cells[i])out.push(tbl.tHead.rows[0].cells[i]); const tb=tbl.tBodies[0]; if(tb)for(const r of tb.rows){const c=r.cells[i]; if(c)out.push(c);} return out; }
function _setCol(tbl,i,px){ _colCells(tbl,i).forEach(c=>{c.style.width=px+'px';c.style.minWidth=px+'px';c.style.maxWidth=px+'px';}); }
function _clearCol(tbl,i){ _colCells(tbl,i).forEach(c=>{c.style.width='';c.style.minWidth='';c.style.maxWidth='';}); }
function _measureCol(tbl,i){ const cv=_measureCol._c||(_measureCol._c=document.createElement('canvas')); const ctx=cv.getContext('2d');
  let max=30,n=0; for(const c of _colCells(tbl,i)){ if(n++>80)break; ctx.font=getComputedStyle(c).font||'12px monospace'; max=Math.max(max,ctx.measureText((c.textContent||'').trim()).width); }
  return Math.min(860, Math.ceil(max)+26); }
function addColResizers(tbl){ if(!tbl||!tbl.tHead||!tbl.tHead.rows[0]||tbl.__rsz)return; if(tbl.classList&&tbl.classList.contains('norsz'))return; tbl.__rsz=1;
  tbl.classList.add('rsztbl'); tbl.style.tableLayout='auto';
  [...tbl.tHead.rows[0].cells].forEach((th,i)=>{
    const rz=document.createElement('span'); rz.className='rz'; rz.title='Drag to resize · double-click to auto-fit';
    rz.addEventListener('mousedown',e=>{ e.preventDefault(); e.stopPropagation(); const sx=e.pageX, sw=th.offsetWidth;
      const mm=ev=>_setCol(tbl,i,Math.max(44,sw+(ev.pageX-sx))); const mu=()=>{document.removeEventListener('mousemove',mm);document.removeEventListener('mouseup',mu);document.body.style.cursor='';};
      document.addEventListener('mousemove',mm); document.addEventListener('mouseup',mu); document.body.style.cursor='col-resize'; });
    rz.addEventListener('dblclick',e=>{ e.preventDefault(); e.stopPropagation(); _clearCol(tbl,i); _setCol(tbl,i,_measureCol(tbl,i)); th.dataset.col='e'; });
    th.appendChild(rz);
    th.addEventListener('dblclick',e=>{ if(e.target===rz)return; if(th.dataset.col==='c'){ _clearCol(tbl,i); _setCol(tbl,i,_measureCol(tbl,i)); th.dataset.col='e'; } else { _setCol(tbl,i,150); th.dataset.col='c'; } });
    const w=_measureCol(tbl,i); if(w>300){ _setCol(tbl,i,300); th.dataset.col='c'; }
  });
}
/* ===== CSV export — every data table gets a "⤓ CSV" button (no per-page wiring) =====
   Generic DOM→CSV. Mirrors the artifact's export; here it's attached automatically to
   any table with a <thead> and at least one data row, via the same enhancement queue. */
function _csvCell(v){ const num=(typeof v==='number'); v=(v==null?'':String(v));
  if(!num && /^[=+\-@\t\r]/.test(v) && !/^[+-]?(\d+\.?\d*|\.\d+)([eE][+-]?\d+)?$/.test(v)) v="'"+v;   // neutralise spreadsheet formulas (= + - @ TAB CR)
  return /[",\r\n]/.test(v)?'"'+v.replace(/"/g,'""')+'"':v; }
function _safeName(s){ return String(s||'export').replace(/[^\w.-]+/g,'_').slice(0,80); }
function downloadText(name,text,mime){ const blob=new Blob(['﻿'+text],{type:(mime||'text/csv')+';charset=utf-8'}); const u=URL.createObjectURL(blob); const a=document.createElement('a'); a.href=u; a.download=name; a.click(); setTimeout(()=>URL.revokeObjectURL(u),2000); }
function csvFromObjs(cols,rows){ return [cols.map(_csvCell).join(',')].concat((rows||[]).map(r=>cols.map(c=>_csvCell(r[c])).join(','))).join('\r\n'); }
function downloadCSV(name,cols,rows){ if(!rows||!rows.length){ alert('Nothing to export yet.'); return; } downloadText(_safeName(String(name).replace(/\.csv$/,''))+'.csv',csvFromObjs(cols,rows)); }
function csvFromTable(tbl){ if(!tbl) return ['',0];
  const heads=[...tbl.querySelectorAll('thead th')].map(th=>th.textContent.trim());
  const body=[...tbl.querySelectorAll('tbody tr')].filter(tr=>!tr.querySelector('td[colspan]')&&tr.cells.length);
  const lines=[heads.map(_csvCell).join(',')];
  body.forEach(tr=>{ const tds=[...tr.children]; lines.push(heads.map((_,i)=>_csvCell((tds[i]?tds[i].textContent:'').trim().replace(/\s+/g,' '))).join(',')); });
  return [lines.join('\r\n'),body.length];
}
function exportTable(tableId,fname){ const r=csvFromTable(document.getElementById(tableId)); if(!r[1]){ alert('Nothing to export yet — run a search first.'); return; } downloadText(_safeName(fname)+'.csv',r[0]); }
function addTableCsv(tbl){
  if(!tbl||tbl.__csv) return;
  // opt-out: pages with their own CSV/export button mark the table `nocsv` (or its
  // enclosing card) so we don't add a duplicate "floating" export next to it.
  if(tbl.classList&&tbl.classList.contains('nocsv')) return;
  if(tbl.closest&&tbl.closest('.nocsv')) return;
  if(!tbl.tHead||!tbl.tHead.rows.length) return;
  const tb=tbl.tBodies[0];
  const dataRows=tb?[...tb.rows].filter(r=>!r.querySelector('td[colspan]')&&r.cells.length):[];
  if(!dataRows.length) return;               // no rows yet — retry on next mutation
  tbl.__csv=1;
  let name='export';
  const sec=tbl.closest('section,.card,body');
  const h=sec&&sec.querySelector('h1,h2,h3'); if(h&&h.textContent.trim()) name=h.textContent.trim();
  else if(document.title) name=document.title.split('·')[0].trim();
  const wrap=document.createElement('div'); wrap.className='csvbar'; wrap.style.cssText='text-align:right;margin:0 0 6px';
  const b=document.createElement('button'); b.type='button'; b.className='btn ghost sm'; b.textContent='⤓ CSV'; b.title='Download this table as CSV';
  b.onclick=function(){ const r=csvFromTable(tbl); if(!r[1]){ alert('Nothing to export.'); return; } downloadText(_safeName(name)+'.csv',r[0]); };
  wrap.appendChild(b);
  let host=tbl;
  if(tbl.parentElement){ try{ if(/auto|scroll/.test(getComputedStyle(tbl.parentElement).overflowX)) host=tbl.parentElement; }catch(e){} }
  host.insertAdjacentElement('beforebegin',wrap);
}
let _rszQ=new Set(), _rszPending=false;
function _flushRsz(){ _rszPending=false; _rszQ.forEach(t=>{try{addColResizers(t);}catch(e){} try{addTableCsv(t);}catch(e){}}); _rszQ.clear(); }
function queueRsz(t){ if(!t)return; _rszQ.add(t); if(!_rszPending){_rszPending=true; (window.requestAnimationFrame||setTimeout)(_flushRsz,0);} }
try{
  new MutationObserver(muts=>{ muts.forEach(m=>m.addedNodes&&m.addedNodes.forEach(n=>{ if(n.nodeType!==1)return;
    if(n.tagName==='TABLE') queueRsz(n);
    if(n.querySelectorAll) n.querySelectorAll('table').forEach(queueRsz);
    const ct=n.closest&&n.closest('table'); if(ct) queueRsz(ct);
  })); }).observe(document.documentElement,{childList:true,subtree:true});
  document.addEventListener('DOMContentLoaded',()=>document.querySelectorAll('table').forEach(queueRsz));
  document.querySelectorAll('table').forEach(queueRsz);
}catch(e){}

/* ===== "Done so far" — what this tagging hound has already done ==================
   A compact dashboard at the top of every TAGGING agent page (manifest category Tagging
   or Discovery, or "status_panel": true — see core/activity.shows_panel): last run, run count, and — for
   hounds that write — the tag values it applied, how many assets carry them in navi.db
   right now, what's still awaiting a navi sync, failures, emails / pushes / ACR changes,
   plus tags already in navi.db for its categories that weren't applied from this install.
   Data: /api/explore/activity (core/activity.py) — the Hounds log + live navi.db. Never
   cached. Refreshes after a run, after a write, and every 15 s while jobs are queued. */
const _ACT_SKIP = new Set(['explore','hub','settings','_template']);
const _ACT_OP = {tag:['🏷️','tag'], remove:['🧹','removal'], acr:['⚖','ACR change'], mail:['📧','email'], push:['⚡','push']};
function _actAgo(t){ if(!t) return '—'; const s=Math.max(0, Date.now()/1000 - t);
  if(s<60) return 'just now'; if(s<3600) return Math.round(s/60)+' min ago'; if(s<86400) return Math.round(s/3600)+' h ago';
  if(s<86400*45) return Math.round(s/86400)+' d ago'; return new Date(t*1000).toISOString().slice(0,10); }
function _actN(n){ return (n==null?0:n).toLocaleString(); }
function _actStyle(){ if(document.getElementById('actvStyle')) return; const st=document.createElement('style'); st.id='actvStyle';
  st.textContent='.actv{padding:12px 16px}.actv-head{display:flex;align-items:center;gap:10px;flex-wrap:wrap}'+
  '.actv-head h3{margin:0;font-size:14px}.actv-head .sp{flex:1}'+
  '.actv-kpis{display:flex;flex-wrap:wrap;gap:8px;margin-top:10px}'+
  '.actv-k{border:1px solid var(--line);border-radius:10px;padding:7px 11px;background:var(--panel-2);min-width:118px}'+
  '.actv-k .v{font-size:17px;font-weight:700;color:var(--ink);line-height:1.15}.actv-k .l{font-size:11px;color:var(--mut)}'+
  '.actv-k.warn .v{color:var(--cx-e7c66b,#d9a400)}.actv-k.bad .v{color:var(--crit)}.actv-k.good .v{color:var(--ok)}.actv-k.dim .v{color:var(--mut)}'+
  '.actv-body{margin-top:12px}.actv-body table{width:100%}.actv-st{font-size:11px;padding:1px 7px;border-radius:7px;border:1px solid var(--line)}'+
  '.actv-st.on{color:var(--ok);border-color:var(--ok)}.actv-st.sync{color:var(--cx-e7c66b,#d9a400);border-color:var(--cx-e7c66b,#d9a400)}.actv-st.fail{color:var(--crit);border-color:var(--crit)}';
  document.head.appendChild(st); }
function _actOpen(id,v){ try{ if(v!==undefined) localStorage.setItem('actvOpen:'+id, v?'1':'0'); return localStorage.getItem('actvOpen:'+id)==='1'; }catch(e){ return false; } }
async function mountActivity(agentId){
  if(!agentId || _ACT_SKIP.has(agentId)) return;
  // fetch first: non-tagging hounds (show:false) get no panel at all — not even a flash of one
  let o; try{ o=await jpost('/api/explore/activity',{agent:agentId}); }catch(e){ o=null; }
  if(o && o.ok && o.show===false){ const old=document.getElementById('actv'); if(old) old.remove(); return; }
  _actStyle();
  let box=document.getElementById('actv');
  if(!box){ box=document.createElement('section'); box.id='actv'; box.className='card actv';
    // order at the top: header → nav → codename strip (info + links) → Done so far → page cards
    const wrap=document.querySelector('.wrap')||document.body;
    const first=[...wrap.children].find(e=>e.id!=='actv' && e.id!=='hcBanner' && e.classList.contains('card'));
    if(first) wrap.insertBefore(box, first); else wrap.appendChild(box); }
  if(!o || !o.ok){ box.innerHTML='<div class="actv-head"><h3>📋 Done so far</h3><span class="sub">activity unavailable</span></div>'; return; }
  const k=o.kpi||{}, r=o.runs||{}, ops=o.ops||[], tags=o.tags||[], other=o.other||[];
  const tagOp=ops.find(x=>x.op==='tag');
  const chip=(v,l,cls,title)=>'<div class="actv-k '+(cls||'')+'"'+(title?' title="'+esc(title)+'"':'')+'><div class="v">'+v+'</div><div class="l">'+l+'</div></div>';
  let kp='';
  const lst=r.last||{}, stp=(lst.steps&&lst.steps.length>1)?lst.steps.length+' steps':(/^(run|load|search|overview|build)$/.test(lst.action||'')?'':lst.action);
  kp += r.last_at ? chip(_actAgo(r.last_at),'last run'+(stp?' · '+esc(stp):'')+(lst.ok===0?' (failed)':''), lst.ok===0?'bad':'', new Date(r.last_at*1000).toLocaleString()+((lst.steps||[]).length>1?' — '+lst.steps.join(' → '):''))
                  : chip('never','last run on this install','dim');
  if(r.count) kp += chip(_actN(r.count),'run'+(r.count>1?'s':'')+' recorded','', (r.fresh||0)+' fresh, '+((r.count||0)-(r.fresh||0))+' served from the server cache');
  if(tagOp || tags.length){
    kp += chip(_actN(k.values_applied),'tag value'+(k.values_applied===1?'':'s')+' applied','', (k.categories||[]).join(', '));
    kp += chip(o.navi_db?_actN(k.assets_tagged):'—','assets carry them now', k.assets_tagged?'good':'', 'distinct assets in navi.db with any of these tag values (as of the last navi sync)');
    if(k.awaiting_sync) kp += chip(_actN(k.awaiting_sync),'awaiting navi sync','warn','applied OK but not in navi.db yet — run a navi.db update (Settings) to see them');
    if(k.running) kp += chip(_actN(k.running),'tag jobs queued','warn');
    if(k.failed) kp += chip(_actN(k.failed),'failed','bad','every attempt for these values failed — see the Tagging log');
    if(k.no_assets) kp += chip(_actN(k.no_assets),'matched no assets','dim','applied before the last navi.db sync but on 0 assets — the selector matched nothing');
    if(k.removed) kp += chip(_actN(k.removed),'since removed','dim','removed later (Tag Removal)');
    if(k.last_write) kp += chip(_actAgo(k.last_write),'last write','', new Date(k.last_write*1000).toLocaleString());
  }
  ops.filter(x=>x.op!=='tag').forEach(x=>{ const m=_ACT_OP[x.op]||['•',x.op]; kp += chip(m[0]+' '+_actN(x.ok), m[1]+(x.ok===1?'':'s')+(x.errors?' · '+x.errors+' failed':''), x.errors&&!x.ok?'bad':'', 'last '+_actAgo(x.last)); });
  if(k.other_values) kp += chip(_actN(k.other_values),'other values already in navi.db','dim', _actN(k.other_assets)+' asset-tags in '+(k.categories||[]).join(', ')+' — applied outside this Hounds install (navi CLI, Tenable UI, another install)');
  const nothing = !r.last_at && !ops.length && !other.length;
  const open=_actOpen(agentId);
  const hasDetail = tags.length || other.length;
  box.innerHTML='<div class="actv-head"><h3>📋 Done so far</h3><span class="sub">'+(nothing?'nothing recorded for this hound on this install yet':'this hound on this install · tags checked against navi.db')+'</span><span class="sp"></span>'+
    (hasDetail?'<button class="btn ghost sm" type="button" id="actvToggle">'+(open?'Hide details ▴':'Details ▾')+'</button>':'')+
    '<button class="btn ghost sm" type="button" id="actvRefresh" title="Refresh">↻</button></div>'+
    '<div class="actv-kpis">'+kp+'</div><div class="actv-body" id="actvBody"'+(open?'':' hidden')+'></div>';
  const body=document.getElementById('actvBody');
  if(hasDetail){
    const st=t=>t.status==='on assets'?'<span class="actv-st on">on assets</span>':t.status==='awaiting sync'?'<span class="actv-st sync">awaiting sync</span>':t.status==='failed'?'<span class="actv-st fail">failed</span>':(t.status==='removed'||t.status==='no assets')?'<span class="actv-st">'+esc(t.status)+'</span>':'<span class="actv-st sync">'+esc(t.status)+'</span>';
    let h='';
    if(tags.length) h+='<h4 style="margin:0 0 6px">Applied by this hound</h4><table id="actvTags"><thead><tr><th>Category</th><th>Value</th><th>Assets now</th><th>Times applied</th><th>Last</th><th>Status</th></tr></thead><tbody></tbody></table>';
    if(other.length) h+='<h4 style="margin:14px 0 6px">Already in navi.db, not applied from this install</h4><table id="actvOther"><thead><tr><th>Category</th><th>Value</th><th>Assets now</th></tr></thead><tbody></tbody></table>';
    if(!o.navi_db) h+='<p class="sub">navi.db tags table unavailable — asset counts not shown.</p>';
    else if(o.navi_db_synced) h+='<p class="sub" style="margin-top:8px">Asset counts are from navi.db as of its last update · '+_actAgo(o.navi_db_synced)+'.</p>';
    body.innerHTML=h;
    if(tags.length) hPaginate('actvTags', tags, t=>'<tr><td>'+esc(t.category)+'</td><td>'+esc(t.value)+'</td><td>'+_actN(t.assets)+'</td><td>'+_actN(t.applied)+(t.errors?' <span class="sub">('+t.errors+' failed)</span>':'')+'</td><td>'+_actAgo(t.last)+'</td><td>'+st(t)+'</td></tr>', {per:20, sizes:HPG_SIZES});
    if(other.length) hPaginate('actvOther', other, t=>'<tr><td>'+esc(t.category)+'</td><td>'+esc(t.value)+'</td><td>'+_actN(t.assets)+'</td></tr>', {per:20, sizes:HPG_SIZES});
    document.getElementById('actvToggle').onclick=()=>{ const v=body.hidden; body.hidden=!v; _actOpen(agentId, v); document.getElementById('actvToggle').textContent=v?'Hide details ▴':'Details ▾'; };
  }
  document.getElementById('actvRefresh').onclick=()=>mountActivity(agentId);
  clearTimeout(box.__poll);
  if(k.running || (tagOp && tagOp.busy)) box.__poll=setTimeout(()=>mountActivity(agentId), 15000);
}
(function(){
  const m=location.pathname.match(/^\/agents\/([^/]+)\//); if(!m || _ACT_SKIP.has(m[1])) return;
  const id=m[1]; let t=null; const again=()=>{ clearTimeout(t); t=setTimeout(()=>mountActivity(id), 600); };
  window.addEventListener('hounds:ran', again); window.addEventListener('hounds:wrote', again);
  if(document.readyState==='complete') mountActivity(id); else window.addEventListener('load', ()=>mountActivity(id));
})();

/* ===== Section navigator — "look ahead" without scrolling =========================
   Mark the page's widgets:  <section class="card" id="secPlan" data-nav="Planned asset tags" data-nav-icon="🏷️">
   and call mountSectionNav() once (it goes right after the first card — the metrics).
   Each chip jumps to its section; setNavCount(id, text) puts a live count on a chip
   (e.g. setNavCount('secPlan', '1,170')); each section gets a small "↑ Sections" link back.
   Reusable by every agent page. */
function _snStyle(){ if(document.getElementById('snStyle')) return; const st=document.createElement('style'); st.id='snStyle';
  st.textContent='.secnav{display:flex;flex-wrap:wrap;align-items:center;gap:8px;padding:10px 14px}'+
  '.secnav .lbl{font-size:11px;color:var(--mut);text-transform:uppercase;letter-spacing:.06em;margin-right:4px}'+
  '.secnav button{display:inline-flex;align-items:center;gap:7px;border:1px solid var(--line);background:var(--panel-2);color:var(--ink);border-radius:999px;padding:6px 12px;font-size:12.5px;cursor:pointer}'+
  '.secnav button:hover{border-color:var(--accent)}.secnav .cnt{font-weight:700;color:var(--accent)}.secnav .cnt:empty{display:none}'+
  '.sn-back{float:right;font-size:11.5px;font-weight:400;color:var(--mut);text-decoration:none;margin-left:10px}.sn-back:hover{color:var(--accent)}'+
  'section[data-nav]{scroll-margin-top:12px}.sn-flash{box-shadow:0 0 0 2px var(--accent);transition:box-shadow .3s}';
  document.head.appendChild(st); }
function mountSectionNav(){
  const secs=[...document.querySelectorAll('section[data-nav]')]; if(!secs.length) return;
  _snStyle();
  let nav=document.getElementById('secNav');
  if(!nav){ nav=document.createElement('section'); nav.id='secNav'; nav.className='card secnav';
    const wrap=document.querySelector('.wrap')||document.body;
    const firstCard=[...wrap.children].find(e=>e.classList&&e.classList.contains('card')&&!['actv','hcBanner','secNav'].includes(e.id)&&!e.hasAttribute('data-nav'));
    if(firstCard) firstCard.insertAdjacentElement('afterend', nav); else wrap.prepend(nav); }
  nav.innerHTML='<span class="lbl">Jump to</span>'+secs.map(s=>'<button type="button" data-go="'+esc(s.id)+'">'+
    (s.dataset.navIcon?'<span>'+esc(s.dataset.navIcon)+'</span>':'')+'<span>'+esc(s.dataset.nav)+'</span><span class="cnt" id="snc_'+esc(s.id)+'">'+esc(s.dataset.navCount||'')+'</span></button>').join('');
  nav.querySelectorAll('button[data-go]').forEach(b=>b.onclick=()=>{ const s=document.getElementById(b.dataset.go); if(!s) return;
    s.scrollIntoView({behavior:'smooth',block:'start'}); s.classList.add('sn-flash'); setTimeout(()=>s.classList.remove('sn-flash'),1200); });
  secs.forEach(s=>{ const h=s.querySelector('h2'); if(h && !h.querySelector('.sn-back')){ const a=document.createElement('a'); a.href='#'; a.className='sn-back'; a.textContent='↑ Sections';
    a.onclick=e=>{ e.preventDefault(); nav.scrollIntoView({behavior:'smooth',block:'start'}); }; h.appendChild(a); } });
}
/* ===== WAS cohorts — shared by the WAS Overview (Arachne) and Web App Recon (Beagle) =====
   A cohort is "kind:key": sev:critical · owasp:A3 · tech:PHP · scan:stale|fresh · clean · asset.
   The Overview links every widget to Recon with ?f=<cohort>; Recon narrows its app list to it.
   `sd` = the stale-scan threshold in days (the Overview's coverage.stale_days). */
const WAS_SEV_LABEL={critical:'Critical',high:'High',medium:'Medium',low:'Low',info:'Info'};
const WAS_OWASP={A1:'Injection',A2:'Broken Authentication',A3:'Sensitive Data Exposure',A4:'XML External Entities (XXE)',
  A5:'Broken Access Control',A6:'Security Misconfiguration',A7:'Cross-Site Scripting (XSS)',A8:'Insecure Deserialization',
  A9:'Using Components with Known Vulnerabilities',A10:'Insufficient Logging & Monitoring'};
function wasCohort(f){ f=String(f||''); const i=f.indexOf(':'); const kind=i<0?f:f.slice(0,i), key=i<0?'':f.slice(i+1);
  const label= kind==='sev'?(WAS_SEV_LABEL[key]||key)+' findings' : kind==='owasp'?('OWASP '+key+' · '+(WAS_OWASP[key]||key))
    : kind==='tech'?('Technology · '+key) : kind==='scan'?(key==='stale'?'Stale scans':'Fresh scans')
    : kind==='clean'?'Clean apps (no crit/high/med/low)' : kind==='asset'?'Apps with a Tenable asset' : '';
  return label?{f:f,kind:kind,key:key,label:label}:null; }
function wasAppMatch(a,f,sd){ const c=typeof f==='string'?wasCohort(f):f; if(!c) return true; a=a||{};
  // same reading as the server (core/was.py _SCAN_AGE): first 19 chars, as UTC, offset ignored
  const age=(()=>{ const r=String(a.scan_completed_time||'').replace('T',' ').slice(0,19); if(!r) return null;
    const t=Date.parse(r.replace(' ','T')+(r.length>10?'Z':'T00:00:00Z')); return isNaN(t)?null:(Date.now()-t)/86400000; })();
  switch(c.kind){
    case 'sev': return (+a[c.key]||0)>0;
    case 'owasp': return (+((a.owasp||{})[c.key])||0)>0;
    case 'tech': return (a.tech||[]).indexOf(c.key)>=0;
    case 'scan': { const fresh=age!=null&&age<=(+sd||30); return c.key==='stale'?!fresh:fresh; }
    case 'clean': return ((+a.critical||0)+(+a.high||0)+(+a.medium||0)+(+a.low||0))===0;
    case 'asset': return !!a.asset_uuid;
  } return true; }
function wasReconHref(f,sd,app){ const q=new URLSearchParams(); if(app) q.set('app',app); if(f) q.set('f',f); if(f&&sd) q.set('sd',String(sd));
  return '/agents/was_asset/page.html'+(q.toString()?'?'+q.toString():''); }

function setNavCount(id, text){ const s=document.getElementById(id); if(s) s.dataset.navCount=text==null?'':String(text);
  const c=document.getElementById('snc_'+id); if(c) c.textContent=text==null?'':String(text); }

/* ===== 📊 At a glance — the shared template (design C · headline + chips) =================
   renderGlance(target, groups, opts) → the root <div class="glx"> it put into target.
   target : an element or its id. Its content is replaced (call it again to re-render —
            e.g. after a filter changes, or when the page cache replays ▶ Run).
   groups : [{ title,                       // small uppercase group label
               t?,                          // tooltip on the label (a caption / footnote)
               hero?: METRIC,               // the headline: big number + label, then hero.u as a muted line
               bar?: [{label, value, color?}],   // stacked mini-bar + legend (legend:false hides it)
               legend?: false,
               chips?: [METRIC, …],         // number + label chips; chip.u goes in the tooltip
               ranked?: {title?, items:[{label, value, vt?, sev?, href|filter|onClick}], max?, sev?, empty?,
                         more?, moreHref?, moreClick?} }]   // vt = display text for value (e.g. '12%'); more = footer
   METRIC : { v,           // the value, already formatted (glanceNum(n) for counts) — text, escaped
              l,           // label (one line, ellipsis)
              u?,          // detail: muted line under a hero; tooltip on a chip
              t?,          // full tooltip (default "v l — u")
              sev?,        // crit | high | med | low | ok | info | none (chip left border; hero number colour)
              zero?,       // force/suppress the dimmed look (default: v parses to 0)
              v2?,         // small suffix next to the number (e.g. '44.5%' beside a count)
              href? | filter? | onClick? }  // what a click does; onClick + href → click runs the
                                            // handler, ctrl/cmd/middle-click opens the link
   Clicks: href → same-tab link through safeHref(); '#secX' smooth-scrolls to that section and
           flashes it. filter → opts.onFilter(filter, el, on) — the template toggles .on on the
           clicked element (one active per root; pass opts.active to mark several on re-render).
           onClick(el, ev) → custom handler. Clickable items are focusable (Enter/Space work).
   opts   : { onFilter?(filter, el, on), active?: string | string[] | (filter)=>bool, cls? }
   colours: bar/ranked colour = a severity name, s1…s8 (series palette, light+dark), or a
            var(--token); anything else falls back to the series palette. */
function glanceNum(n){ if(n==null||n==='') return '—'; const x=Number(n); return isNaN(x)?String(n):x.toLocaleString(); }
const _GLX_SEV=new Set(['crit','high','med','low','ok','info','none']);
function _glxSev(s){ s=String(s||'none'); return _GLX_SEV.has(s)?s:'none'; }
function _glxColor(c, i){ c=String(c==null?'':c).trim();
  if(_GLX_SEV.has(c)&&c!=='none') return 'var(--'+c+')';
  if(/^s[1-8]$/.test(c)) return 'var(--glx-'+c+')';
  if(/^var\(--[a-z0-9-]+\)$/i.test(c)) return c;
  return 'var(--glx-s'+((i||0)%8+1)+')'; }
function _glxZero(m){ if(m.zero!=null) return !!m.zero; const v=m.v;
  if(typeof v==='number') return v===0;
  const s=String(v==null?'':v).replace(/[,\s%]/g,''); return /^-?\d+(\.\d+)?$/.test(s) && Number(s)===0; }
function _glxActive(opts, f){ const a=opts&&opts.active; if(a==null||f==null) return false;
  if(typeof a==='function') return !!a(f); if(Array.isArray(a)) return a.indexOf(f)>=0; return String(a)===String(f); }
function glanceSetActive(root, filter){ root=typeof root==='string'?document.getElementById(root):root; if(!root) return;
  root.querySelectorAll('[data-glx-f]').forEach(e=>{ const on=filter!=null&&e.dataset.glxF===String(filter); e.classList.toggle('on',on); e.setAttribute('aria-pressed',on?'true':'false'); }); }
function _glxV2(m){ return m&&m.v2!=null&&m.v2!==''?'<small class="glx-v2">'+esc(m.v2)+'</small>':''; }
function renderGlance(target, groups, opts){
  opts=opts||{}; const host=typeof target==='string'?document.getElementById(target):target; if(!host) return null;
  const acts=[];   // index → {kind, val}
  // an item (hero / chip / ranked row): returns [tagOpen, tagClose, classes, attrs]
  const act=(m, base)=>{ let cls=base, at='';
    const href=m.href!=null&&m.href!==''?safeHref(m.href,''):'';
    if(href&&typeof m.onClick==='function'){ acts.push({kind:'fnhref',val:m.onClick,href:href});
      return {tag:'a', cls:cls+' glx-act', at:' href="'+esc(href)+'" data-glx-i="'+(acts.length-1)+'"'}; }
    if(href){ acts.push({kind:'href',val:href}); return {tag:'a', cls:cls+' glx-act', at:' href="'+esc(href)+'" data-glx-i="'+(acts.length-1)+'"'}; }
    if(m.filter!=null&&m.filter!==''){ acts.push({kind:'filter',val:String(m.filter)}); const on=_glxActive(opts,String(m.filter));
      return {tag:'span', cls:cls+' glx-act'+(on?' on':''), at:' role="button" tabindex="0" aria-pressed="'+(on?'true':'false')+'" data-glx-f="'+esc(m.filter)+'" data-glx-i="'+(acts.length-1)+'"'}; }
    if(typeof m.onClick==='function'){ acts.push({kind:'fn',val:m.onClick}); return {tag:'span', cls:cls+' glx-act', at:' role="button" tabindex="0" data-glx-i="'+(acts.length-1)+'"'}; }
    return {tag:'span', cls:cls, at:''}; };
  // the tooltip: t when given (plus the detail line u if t does not already carry it — a chip shows no u line)
  const tip=m=>{ const u=m.u!=null&&m.u!==''?String(m.u):'';
    if(m.t!=null&&m.t!==''){ const t=String(m.t); return u&&t.indexOf(u)<0?t+' — '+u:t; }
    return String(m.v==null?'':m.v)+(m.v2!=null&&m.v2!==''?' ('+m.v2+')':'')+' '+String(m.l||'')+(u?' — '+u:''); };
  const hero=m=>{ const a=act(m,'glx-h glx-sev-'+_glxSev(m.sev)+(_glxZero(m)?' glx-zero':''));
    return '<'+a.tag+' class="'+a.cls+'"'+a.at+' title="'+esc(tip(m))+'"><b>'+esc(m.v)+'</b>'+_glxV2(m)+'<span class="glx-l">'+esc(m.l||'')+'</span></'+a.tag+'>'
      +(m.u?'<div class="glx-d" title="'+esc(m.u)+'">'+esc(m.u)+'</div>':''); };
  const chip=m=>{ const a=act(m,'glx-c glx-sev-'+_glxSev(m.sev)+(_glxZero(m)?' glx-zero':''));
    return '<'+a.tag+' class="'+a.cls+'"'+a.at+' title="'+esc(tip(m))+'"><b>'+esc(m.v)+'</b>'+_glxV2(m)+'<span class="glx-l">'+esc(m.l||'')+'</span></'+a.tag+'>'; };
  const bar=(g)=>{ const b=(g.bar||[]).map((x,i)=>({label:x.label, n:Math.max(0,+x.value||0), raw:x.value, c:_glxColor(x.color,i)}));
    const tot=b.reduce((s,x)=>s+x.n,0); const t=g.t?' title="'+esc(g.t)+'"':'';
    return '<div class="glx-bar" role="img" aria-label="'+esc(b.map(x=>x.label+' '+glanceNum(x.raw)).join(', '))+'"'+t+'>'
      +(tot?b.filter(x=>x.n).map(x=>'<i style="width:'+(100*x.n/tot).toFixed(2)+'%;--glx-c:'+x.c+'" title="'+esc(x.label)+': '+esc(glanceNum(x.raw))+'"></i>').join(''):'')+'</div>'
      +(g.legend===false?'':'<div class="glx-lg">'+b.map(x=>'<span style="--glx-c:'+x.c+'">'+esc(x.label)+' <b>'+esc(glanceNum(x.raw))+'</b></span>').join('')+'</div>'); };
  const ranked=r=>{ const it=(r.items||[]); const mx=Math.max(1,+r.max||0,...it.map(x=>+x.value||0));
    let h='<div class="glx-rk">'+(r.title?'<div class="glx-rt">'+esc(r.title)+'</div>':'');
    if(!it.length) return h+(r.empty?'<div class="glx-empty">'+esc(r.empty)+'</div>':'')+'</div>';
    return h+it.map(x=>{ const a=act(x,'glx-r glx-sev-'+_glxSev(x.sev||r.sev)+(_glxZero({v:x.value,zero:x.zero})?' glx-zero':''));
      return '<'+a.tag+' class="'+a.cls+'"'+a.at+' title="'+esc(x.t||(x.label+': '+glanceNum(x.value)))+'"><span class="glx-l">'+esc(x.label)+'</span>'
        +'<span class="glx-t"><i style="width:'+Math.max(0,Math.min(100,100*(+x.value||0)/mx)).toFixed(0)+'%"></i></span><b>'+esc(x.vt!=null&&x.vt!==''?x.vt:glanceNum(x.value))+'</b></'+a.tag+'>'; }).join('')
      +(r.more?(()=>{ const a=act({href:r.moreHref, onClick:r.moreClick},'glx-more'); return '<'+a.tag+' class="'+a.cls+'"'+a.at+'>'+esc(r.more)+'</'+a.tag+'>'; })():'')+'</div>'; };
  const html=(groups||[]).filter(Boolean).map(g=>'<div class="glx-p">'
    +(g.title?'<div class="glx-k"'+(g.t?' title="'+esc(g.t)+'"':'')+'>'+esc(g.title)+'</div>':'')
    +(g.hero?hero(g.hero):'')
    +(g.bar&&g.bar.length?bar(g):'')
    +(g.chips&&g.chips.length?'<div class="glx-cs">'+g.chips.filter(Boolean).map(chip).join('')+'</div>':'')
    +(g.ranked?ranked(g.ranked):'')+'</div>').join('');
  const root=document.createElement('div'); root.className='glx'+(opts.cls?' '+String(opts.cls).replace(/[^\w -]/g,''):'');
  root.innerHTML=html;
  const fire=(el,ev)=>{ const a=acts[+el.dataset.glxI]; if(!a) return;
    if(a.kind==='fnhref'){ if(ev.ctrlKey||ev.metaKey||ev.shiftKey||ev.button===1) return;   // open-in-new-tab still works
      ev.preventDefault(); a.val(el, ev); return; }
    if(a.kind==='href'){ if(a.val.charAt(0)==='#'&&a.val.length>1&&!(ev.ctrlKey||ev.metaKey||ev.shiftKey||ev.button===1)){ const s=document.getElementById(a.val.slice(1)); if(s){ ev.preventDefault();
        s.scrollIntoView({behavior:'smooth',block:'start'}); s.classList.add('glx-flash'); setTimeout(()=>s.classList.remove('glx-flash'),1200); } }
      return; }   // other hrefs: the browser follows the link (same tab)
    ev.preventDefault();
    if(a.kind==='filter'){ const on=!el.classList.contains('on'); glanceSetActive(root, on?a.val:null); el.classList.toggle('on',on); el.setAttribute('aria-pressed',on?'true':'false');
      if(typeof opts.onFilter==='function') opts.onFilter(a.val, el, on);
      if(ev.type==='keydown'&&document.body&&!document.body.contains(el)){   // the page redrew the glance: keep keyboard focus on the same chip
        const q='[data-glx-f="'+a.val.replace(/["\\]/g,'\\$&')+'"]', box=host.id?document.getElementById(host.id):null;
        try{ const n=(box&&box.querySelector(q))||document.querySelector('.glx '+q); if(n) n.focus({preventScroll:true}); }catch(e){} }
      return; }
    if(a.kind==='fn') a.val(el, ev); };
  root.addEventListener('click', ev=>{ const el=ev.target.closest&&ev.target.closest('[data-glx-i]'); if(el&&root.contains(el)) fire(el,ev); });
  root.addEventListener('keydown', ev=>{ if(ev.key!=='Enter'&&ev.key!==' ') return; const el=ev.target.closest&&ev.target.closest('[data-glx-i]');
    if(!el||!root.contains(el)||el.tagName==='A') return; ev.preventDefault(); fire(el,ev); });
  // a re-render (e.g. the page's onFilter redrawing the glance) keeps keyboard focus on the same item
  const fe=document.activeElement, keep=fe&&host.contains(fe)&&fe.dataset?(fe.dataset.glxF!=null?'[data-glx-f="'+String(fe.dataset.glxF).replace(/["\\]/g,'\\$&')+'"]':(fe.dataset.glxI!=null?'[data-glx-i="'+(+fe.dataset.glxI)+'"]':'')):'';
  host.innerHTML=''; host.appendChild(root);
  if(keep){ try{ const n=root.querySelector(keep); if(n) n.focus({preventScroll:true}); }catch(e){} }
  return root;
}
/* ===== end At a glance ===== */

/* ===== External downloads — Settings → Auto-approve downloads (core/downloads.py) =====
   downloadsAutoApproved('<source id>') resolves to the registered source {id,name,urls,…}
   when the setting is ON — skip the "Human approval — external download" card and show
   "Auto-approved download: <url> (Settings)" — or null when it is OFF, unknown or
   unreachable (show the card as before). */
async function downloadsAutoApproved(id){
  try{ const o=await jpost('/api/settings/downloads',{id:id||''});
    return (o && o.ok && o.auto_approve) ? (o.source || {id:id, name:id, urls:[]}) : null; }
  catch(e){ return null; }
}

/* ===== hDrill — server-side paged table (the payload contract, core/payload.py, build 455) =====
   A hound's ▶ Run ships only the decision data (summary + top rows + totals) plus a `drill`
   handle {run, section}; the rest of a list is paged, searched and sorted ON THE SERVER through
   the hound's `drill` action with an opaque, signed keyset token (never OFFSET). Usage:
     const T = hDrill({api:API, table:'certTbl', run:o.drill.run, section:'certs', sort:'near',
                       cols:8, row:(r,i)=>'<tr>…'+esc(r.x)+'…</tr>', wire:(tbody,rows)=>{…},
                       empty:'<tr><td colspan="8" class="sub">Nothing.</td></tr>',
                       search:'certQ',            // optional <input id> → server-side search (debounced)
                       first:o});                 // optional: render ▶ Run's own top/page/total first
     T.set({filter:['expired'], q:''});            // new query → back to row 1
   The pager reads "‹ Prev  1–200 of 35,214  Next ›" (a capped total shows "10,000+"), keeps a
   Rows selector (remembered per table, as hPaginate), and every value is escaped with esc().
   Requests go through api.post, so the page cache records and replays them like any read. */
function hDrill(o){
  o = Object.assign({action:'drill', cols:6, filter:[], q:'', sort:''}, o||{});
  const st = {run:o.run, section:o.section, sort:o.sort||'', filter:(o.filter||[]).slice(), q:o.q||'',
              limit:Math.min(200, hPageSize(o.table)), toks:[null], idx:0, rows:[], total:null, start:0, next:null, seq:0, err:null};
  const tbl = () => document.getElementById(o.table);
  { const t=tbl(); if(t) t.dataset.paged='1'; }   // the auto-pager leaves this table alone
  function totalTxt(t){ if(!t) return '?'; const v=Number(t.value||0).toLocaleString(); return t.exact===false ? v+'+' : v; }
  function pagerEl(){ const id=o.table+'DPager'; let p=document.getElementById(id); const t=tbl();
    if(!p && t){ p=document.createElement('div'); p.id=id; p.className='toolbar hdrill-pager';
      const an=(t.parentElement && t.parentElement.children.length===1 && /auto|scroll/.test(t.parentElement.style.overflowX+t.parentElement.style.overflow)) ? t.parentElement : t;
      an.parentNode.insertBefore(p, an.nextSibling); }
    return p; }
  function render(){
    const t=tbl(); if(!t) return; const tb=t.tBodies[0]||t.appendChild(document.createElement('tbody'));
    if(st.err){ tb.innerHTML='<tr><td colspan="'+(+o.cols||1)+'" class="sub">'+esc(st.err)+'</td></tr>'; }
    else tb.innerHTML = st.rows.length ? st.rows.map((r,i)=>o.row(r, st.start+i)).join('')
      : (o.empty || '<tr><td colspan="'+(+o.cols||1)+'" class="sub">No rows.</td></tr>');
    if(o.wire && !st.err){ try{ o.wire(tb, st.rows); }catch(e){} }
    const p=pagerEl(); if(!p) return;
    const n=st.rows.length, a=n?st.start+1:0, b=st.start+n;
    if(!st.err && st.idx===0 && !st.next && (st.total?st.total.value:n)<=Math.min.apply(null,HPG_SIZES)){ p.style.display='none'; p.innerHTML=''; }
    else {
      p.style.display='';
      p.innerHTML='<button class="btn ghost sm" data-hdp '+(st.idx<=0?'disabled':'')+'>‹ Prev</button>'
        +'<span class="sub hdrill-count" style="margin:0 10px">'+esc(a.toLocaleString())+'–'+esc(b.toLocaleString())+' of '+esc(totalTxt(st.total))+'</span>'
        +'<button class="btn ghost sm" data-hdn '+(st.next?'':'disabled')+'>Next ›</button>';
      p.querySelector('[data-hdp]').onclick=()=>{ if(st.idx>0){ st.idx--; load(); } };
      p.querySelector('[data-hdn]').onclick=()=>{ if(st.next){ st.toks[st.idx+1]=st.next; st.idx++; load(); } };
      hSizeControl(p, o.table, v=>{ st.limit=Math.min(200,v); reset(); load(); });
    }
    if(o.onRender){ try{ o.onRender(api); }catch(e){} }
  }
  function apply(resp){
    if(!resp || resp.ok===false){ st.rows=[]; st.next=null;
      st.err = resp && resp.expired ? 'This run’s rows are no longer on the server — press ▶ Run again.' : '✗ '+((resp&&(resp.error||resp.message))||'could not load this page');
      return; }
    st.err=null; st.rows=resp.top||[]; st.total=resp.total||null;
    const pg=resp.page||{}; st.next=pg.next||null; st.start=+pg.start||0; }
  async function load(){
    const my=++st.seq;
    const body={run:st.run, section:st.section, limit:st.limit};
    if(st.sort) body.sort=st.sort; if(st.filter.length) body.filter=st.filter; if(st.q) body.q=st.q;
    if(st.toks[st.idx]) body.next=st.toks[st.idx];
    Object.assign(body, o.extra||{});
    let resp; try{ resp=await o.api.post(o.action, body); }catch(e){ resp={ok:false, error:e.message}; }
    if(my!==st.seq) return;                     // a newer query won
    apply(resp); render(); return resp; }
  function reset(){ st.toks=[null]; st.idx=0; }
  const api = {
    set(p){ p=p||{}; if('run' in p) st.run=p.run; if('section' in p) st.section=p.section; if('sort' in p) st.sort=p.sort||'';
      if('filter' in p) st.filter=(p.filter||[]).filter(Boolean); if('q' in p) st.q=String(p.q||'').trim();
      reset(); return load(); },
    reload(){ return load(); },
    get rows(){ return st.rows; }, get total(){ return st.total; }, get state(){ return st; },
  };
  if(o.search){ const inp=document.getElementById(o.search); if(inp && !inp.__hd){ inp.__hd=1; let tm=null;
    inp.addEventListener('input', ()=>{ clearTimeout(tm); tm=setTimeout(()=>api.set({q:inp.value}), 300); });
    st.q = st.q || String(inp.value||'').trim(); } }
  if(o.first && o.first.ok!==false && st.limit===((o.first.page||{}).limit||st.limit) && !st.q){ apply(o.first); render(); }
  else load();
  return api;
}
/* ===== end hDrill ===== */
