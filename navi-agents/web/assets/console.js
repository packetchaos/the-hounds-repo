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
  function markRun(btn){ S.ran=true; if(btn){ S.clickAt=Date.now(); if(btn.id) S.lastBtn=btn.id; } }
  // run-bg (may detach) only for the requests a ▶ click itself sets off — the page cache tags
  // them _run; pages without the page cache: fired within 2 s of the click. Drill-downs, paging
  // and status polls afterwards stay "run" (inline, never queued behind long runs).
  function isRunReq(body){ if(S.clickAt && Date.now()-S.clickAt<2000) return true;
    try{ const b=typeof body==='string'?JSON.parse(body):null; return !!(b && b._run); }catch(e){ return false; } }
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
    // after a ▶ Run on this page: "run-bg" — the server may DETACH a long run (core/launcher
    // _detached): it answers 202 {pending, job_id} and keeps going; RUNS below waits for it
    if(!h.has('X-Hounds-Budget')) h.set('X-Hounds-Budget', S.ran ? (isRunReq(init && init.body) ? 'run-bg' : 'run') : 'open');
    init = Object.assign({}, init, {headers:h});
    let r = await _fetch(input, init);
    if(r.status===202){
      let j=null; try{ j=await r.clone().json(); }catch(e){}
      if(j && j.pending && j.job_id!=null) r = await RUNS.wait(j, ap);
    }
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
      (bg?'<button class="btn sm" type="button" id="hbBg" title="Re-send this read as a background job (the 2-hour job budget applies); track it in the Runs log">⏳ Run in background</button>':'')+
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
  /* ---- detached runs: "still running · 12m 04s" until the server's job finishes ----
     A long ▶ Run keeps running on the server (2-hour budget) even if this page closes. While this
     page waits, the run's row shows its elapsed time (server clock) and a Cancel button; the
     original request then resolves with the job's result, so the page renders it as usual.
     The job ids are remembered per page (localStorage), so coming back to the page shows a run
     still in progress — and when it is done, "▶ Show results" re-runs the page's ▶ (served from
     the server's cache). Runs of this agent started from another tab show up too. */
  const RUNS = (function(){
    const SKEY='houndsRuns:'+location.pathname;
    const pageAgent=(location.pathname.match(/^\/agents\/([a-z0-9_]+)\//)||[])[1]||null;
    const rows={};
    function load(){ try{ const v=JSON.parse(localStorage.getItem(SKEY)||'[]'); return Array.isArray(v)?v:[]; }catch(e){ return []; } }
    function save(v){ try{ if(v.length) localStorage.setItem(SKEY, JSON.stringify(v.slice(-10))); else localStorage.removeItem(SKEY); }catch(e){} }
    // a job id is only meaningful with the server boot it came from (ids restart at 1) and its agent
    function remember(id, label, btn, boot, agent){ const v=load().filter(x=>x.id!==id); v.push({id, label, btn:btn||null, boot:boot||null, agent:agent||null, at:Date.now()}); save(v); }
    const same=(e,o)=>!!(o && o.job && (!e.boot || o.boot===e.boot) && (!e.agent || o.job.agent===e.agent));
    function forget(id){ save(load().filter(x=>x.id!==id)); }
    function fmt(sec){ sec=Math.max(0, Math.floor(sec||0)); const h=Math.floor(sec/3600), m=Math.floor(sec%3600/60), s2=sec%60;
      return h ? h+'h '+String(m).padStart(2,'0')+'m '+String(s2).padStart(2,'0')+'s' : (m ? m+'m '+String(s2).padStart(2,'0')+'s' : s2+'s'); }
    function box(){ let d=document.getElementById('hbRuns'); if(d||!document.body) return d;
      style(); d=document.createElement('div'); d.id='hbRuns'; d.setAttribute('role','status'); d.setAttribute('aria-live','polite');
      const wrap=document.querySelector('.wrap')||document.body;
      const first=[...wrap.children].find(e=>e.id!=='actv' && e.id!=='hcBanner' && e.id!=='hbBanner' && e.classList && e.classList.contains('card'));
      if(first) wrap.insertBefore(d, first); else wrap.prepend(d);
      return d; }
    function row(id){ if(rows[id] && rows[id].isConnected) return rows[id];
      const b=box(); if(!b) return null;
      const d=document.createElement('div'); d.className='hb-banner'; d.dataset.job=String(id);
      d.innerHTML='<span class="hb-msg"></span><span class="hb-acts"></span>'; b.appendChild(d); rows[id]=d; return d; }
    function drop(id){ const d=rows[id]; if(d) d.remove(); delete rows[id]; }
    function paint(id, j, now, label){
      const d=row(id); if(!d) return;
      const t0=j.started||j.created, sec=(now||0)-(t0||0);
      const q=j.status==='queued' && sec>=3;    // just submitted = "starting", not "queued"
      d.querySelector('.hb-msg').innerHTML='<span class="spin"></span> <b>'+(q?'Queued':'Still running')+'</b> · '+
        esc(label||j.label||j.action||'run')+' · <b class="mono">'+esc(fmt(sec))+'</b>'+
        (q?' — waiting for a free worker (another run is using it)':' — keeps running on the server if you leave this page')+
        ' · <a href="/web/agent-runs.html">Runs log</a>';
      const a=d.querySelector('.hb-acts');
      if(!a.firstChild){ a.innerHTML='<button class="btn ghost sm" type="button">✕ Cancel run</button>';
        a.firstChild.onclick=async()=>{ if(!confirm('Stop this run? Its partial work is discarded.')) return;
          a.innerHTML='<span class="spin"></span>';
          try{ await _fetch('/api/jobs/cancel',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({job_id:id})}); }catch(e){} }; }
    }
    async function poll(id){ try{ const o=await (await _fetch('/api/jobs/'+encodeURIComponent(id))).json(); return o||{}; }catch(e){ return null; } }
    const sleep=ms=>new Promise(r=>setTimeout(r, ms));
    function asResponse(body){ return new Response(JSON.stringify(body), {status:200, headers:{'Content-Type':'application/json'}}); }
    async function wait(start, ap){
      const id=start.job_id, label=start.label||(ap&&ap.action);
      remember(id, label, S.lastBtn, start.boot, start.agent);
      const me={boot:start.boot, agent:start.agent};
      try{ hJobBadge(); }catch(e){}
      let skew=(start.now||0)-Date.now()/1000, j={status:start.status, started:start.started, created:start.created, label};
      let lastPoll=0, misses=0;
      const tick=setInterval(()=>paint(id, j, Date.now()/1000+skew, label), 1000);
      paint(id, j, start.now, label);
      try{
        for(;;){
          await sleep(Math.min(5000, 1500+Math.floor(lastPoll/10)));
          lastPoll++;
          const o=await poll(id);
          if(!o){ if(++misses>30) return asResponse({ok:false, error:'lost contact with the server while waiting for the run'}); continue; }
          misses=0;
          if(!o.ok || !o.job || !same(me,o)){ forget(id); return asResponse({ok:false, error:'the run is gone (the server restarted?) — run it again'}); }
          j=o.job; if(o.now) skew=o.now-Date.now()/1000;
          if(j.status==='done' || j.status==='error'){
            forget(id); try{ hJobBadge(); }catch(e){}
            const res=(j.result && typeof j.result==='object') ? j.result : {ok:j.status==='done', error:j.message||'failed', message:j.message};
            return asResponse(res);
          }
        }
      } finally { clearInterval(tick); drop(id); }
    }
    // page open: runs this page started earlier (or this agent's runs from another tab)
    async function resume(){
      const mine=load(), seen=new Set();
      for(const e of mine){ seen.add(e.id); watch(e.id, e.label, e.btn, e); }
      if(!pageAgent) return;
      try{ const o=await (await _fetch('/api/jobs')).json();
        ((o&&o.jobs)||[]).forEach(x=>{ if(x.agent===pageAgent && x.pool==='run' && (x.status==='running'||x.status==='queued') && !seen.has(x.id))
          watch(x.id, x.label||x.action, null, {boot:o.boot, agent:pageAgent}); });
      }catch(e){}
    }
    async function watch(id, label, btn, e){
      let o=await poll(id); if(!o || !o.ok || !o.job || !same(e||{},o)){ forget(id); return; }
      let j=o.job, skew=(o.now||Date.now()/1000)-Date.now()/1000;
      if(j.status==='done' || j.status==='error'){ forget(id); return finished(id, j, label, btn); }
      const tick=setInterval(()=>paint(id, j, Date.now()/1000+skew, label), 1000);
      paint(id, j, o.now, label);
      for(;;){
        await sleep(3000);
        o=await poll(id); if(!o) continue;
        if(!o.ok || !o.job || !same(e||{},o)){ clearInterval(tick); drop(id); forget(id); return; }
        j=o.job; if(o.now) skew=o.now-Date.now()/1000;
        if(j.status==='done' || j.status==='error'){ clearInterval(tick); drop(id); forget(id); return finished(id, j, label, btn); }
      }
    }
    function finished(id, j, label, btn){
      const d=row(id); if(!d) return;
      const ok=j.status==='done' && !(j.result && j.result.ok===false);
      const sec=(j.finished||0)-(j.started||j.created||0);
      d.querySelector('.hb-msg').innerHTML=(ok?'✓ <b>Finished</b>':'✗ <b>Stopped</b>')+' · '+esc(label||j.label||'run')+
        (sec>0?' · took <b class="mono">'+esc(fmt(sec))+'</b>':'')+(ok?'':' · '+esc(j.message||''));
      const b=btn && document.getElementById(btn);
      const a=d.querySelector('.hb-acts');
      a.innerHTML=(ok && b?'<button class="btn run sm" type="button" data-show="1">▶ Show results</button>':'')+'<button class="btn ghost sm" type="button" data-x="1" aria-label="Dismiss">✕</button>';
      a.querySelector('[data-x]').onclick=()=>drop(id);
      const sh=a.querySelector('[data-show]'); if(sh) sh.onclick=()=>{ drop(id); const bb=document.getElementById(btn); if(bb) bb.click(); };
    }
    if(document.readyState==='loading') document.addEventListener('DOMContentLoaded', ()=>setTimeout(resume, 300)); else setTimeout(resume, 300);
    return { wait, fmt };
  })();
  return { tab:TAB, markRun, hasRun:()=>S.ran, show, hide, runs:RUNS };
})();

const HC = (function(){
  const ENABLED = location.pathname.startsWith('/agents/') &&
                  !(document.body && document.body.dataset.pageCache==='off') &&   // live-list pages opt out
                  !(function(){ try{ return localStorage.getItem('houndsCacheOff')==='1'; }catch(e){ return false; } })();
  const KEY = location.pathname + location.search;
  // build 484: no age cutoff — the last run is always shown (with its age) until a newer run or
  // ✕ Clear replaces it. A browser can still opt into one with localStorage houndsCacheTTLh.
  const TTL_MS = (function(){ try{ const v=parseFloat(localStorage.getItem('houndsCacheTTLh')); if(v>0) return v*3600e3; }catch(e){} return Infinity; })();
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
      // replaying a ▶ step whose answer this cache doesn't hold: never start the hound on page
      // open — the server serves its cached answer or says it isn't cached (launcher._cache_only)
      if(S.mode==='replay' && method==='POST') extra._cacheonly = true;
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
    const when=new Date(e.at||0), old=(Date.now()-(e.at||0))>86400e3;
    const stamp=when.toLocaleDateString(undefined,{month:'short',day:'numeric'})+' '+when.toLocaleTimeString(undefined,{hour:'2-digit',minute:'2-digit'});
    if(old) d.style.borderLeftColor='var(--warn,#d9a400)';
    d.title='Run saved '+when.toLocaleString();
    d.innerHTML='<span>'+(rel?'🐾 Released by <a href="/">Release the Hounds</a> · <b>':'↺ Restored your last run · <b>')+ago(e.at)+'</b>'+
      ' <span class="mono" style="font-size:12px">('+esc(stamp)+')</span>'+
      ' <span class="sub">— saved '+(S.src==='browser'?'in this browser':'on the server')+(misses?' ('+misses+' read'+(misses>1?'s':'')+' fetched live)':'')+
      (old?' · <b style="color:var(--warn,#d9a400)">over a day old</b>':'')+'</span></span>'+
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
    // past a TTL this browser opted into → don't replay it (the shared server copy stays; the
    // server never prunes a hound's own page)
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


/* ===== Background activity on a hound's page (build 484) =====================================
   A hound can be run by something other than this page: Release the Hounds (the home page's
   ▶, or its daily schedule in the AI Contract) or an AI Contract cycle running its discovery.
   /api/hub/bg_status says so; this bar shows it with the elapsed time. While a Release is
   working on THIS hound its ▶ Run buttons are held (a second run would duplicate the work),
   and when it finishes the page reloads to show the result the Release saved. */
const BG = (function(){
  const m=location.pathname.match(/^\/agents\/([a-z0-9_]+)\//), agent=m&&m[1];
  if(!agent || ['hub','settings','jobs','profile','explore'].indexOf(agent)>=0 || !window.fetch) return {};
  const st={rel:null, con:null, item0:undefined, held:false, skew:0, label:'', seq:0};
  const fmt=s=>{ s=Math.max(0,Math.round(s)); const h=Math.floor(s/3600), mi=Math.floor(s%3600/60), se=s%60;
    return (h?h+':'+String(mi).padStart(2,'0'):mi)+':'+String(se).padStart(2,'0'); };
  const now=()=>Date.now()/1000+st.skew;
  async function poll(){ try{ const r=await fetch('/api/hub/bg_status',{method:'POST',headers:{'Content-Type':'application/json','X-Hounds-Budget':'open'},body:JSON.stringify({agent})});
    return r.ok ? await r.json() : null; }catch(e){ return null; } }
  function bar(){ let d=document.getElementById('bgActivity'); if(d||!document.body) return d;
    if(!document.getElementById('hbStyle')){ const s2=document.createElement('style'); s2.id='hbStyle';
      s2.textContent='.hb-banner{display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin:0 0 12px;padding:8px 12px;border:1px solid var(--line);border-left:3px solid var(--accent);border-radius:var(--radius-sm,8px);background:var(--panel-2);font-size:13px;color:var(--ink-2,var(--ink));overflow-wrap:anywhere}.hb-banner b{color:var(--ink)}.hb-banner .hb-msg{flex:1 1 260px;min-width:0}';
      (document.head||document.documentElement).appendChild(s2); }
    d=document.createElement('div'); d.id='bgActivity'; d.className='hb-banner'; d.setAttribute('role','status'); d.setAttribute('aria-live','polite');
    d.innerHTML='<span class="hb-msg"></span>';
    const wrap=document.querySelector('.wrap')||document.body;
    const first=[...wrap.children].find(e=>e.classList && e.classList.contains('card') && ['actv','hcBanner','hbBanner','hbRuns'].indexOf(e.id)<0);
    if(first) wrap.insertBefore(d, first); else wrap.prepend(d);
    return d; }
  function drop(){ const d=document.getElementById('bgActivity'); if(d) d.remove(); }
  function runBtns(){ return document.querySelectorAll('button[data-run], button[data-run-all], #hcRerun'); }
  function hold(on){ st.held=on;
    runBtns().forEach(b=>{ if(on){ if(!b.disabled || b.dataset.bgHeld){ b.disabled=true; b.dataset.bgHeld='1'; } }
                           else if(b.dataset.bgHeld){ b.disabled=false; delete b.dataset.bgHeld; } }); }
  // a ▶ the page re-enabled itself, or one it drew later, is caught here while held
  document.addEventListener('click', ev=>{ if(!st.held) return;
    const b=ev.target && ev.target.closest && ev.target.closest('button[data-run],button[data-run-all],#hcRerun');
    if(b){ ev.preventDefault(); ev.stopImmediatePropagation(); paint(); } }, true);
  function paint(){
    const r=st.rel, c=st.con;
    if(!r && !c){ drop(); return; }
    const d=bar(); if(!d) return;
    let h='';
    if(r){
      const name=esc(r.label||agent);
      h = r.status==='running'
        ? '<span class="spin"></span> <b>Release the Hounds is running '+name+' now</b> · <b class="mono">'+fmt(now()-(r.started||now()))+'</b>'
        : '⏳ <b>'+name+' is queued in Release the Hounds</b>'+(r.ahead?' · '+r.ahead+' hound'+(r.ahead>1?'s':'')+' ahead':'')+
          ((r.now&&r.now.length)?' · running now: '+esc(r.now[0]):'');
      h += ' · release running <span class="mono">'+fmt(now()-(r.release_started||now()))+'</span>'+
           ' — ▶ Run is held until it finishes; this page then loads the result · <a href="/">Release the Hounds</a>';
      d.style.borderLeftColor='var(--accent)';
    } else {
      h='<span class="spin"></span> <b>The AI Contract is running this hound\'s discovery</b> for its tagging plan · <b class="mono">'+
        fmt(now()-(c.started||now()))+'</b> — it doesn\'t change this page; ▶ Run still works · <a href="/agents/contract/page.html">AI Contract</a>';
      d.style.borderLeftColor='var(--warn,#d9a400)';
    }
    d.querySelector('.hb-msg').innerHTML=h;
    if(r) hold(true);
  }
  function finished(item){
    hold(false);
    const d=bar(); if(!d) return;
    const ok=item && item.status==='done';
    d.querySelector('.hb-msg').innerHTML=ok
      ? '✓ <b>Release the Hounds finished '+esc(st.label||agent)+'</b> — loading the result…'
      : '✗ <b>Release the Hounds did not finish '+esc(st.label||agent)+'</b>'+(item&&item.status?' ('+esc(item.status)+')':'')+
        (item&&item.error?' · '+esc(item.error):'')+' — ▶ Run is free again.';
    d.style.borderLeftColor=ok?'var(--ok)':'var(--warn,#d9a400)';
    if(ok) setTimeout(()=>location.reload(), 1200);
  }
  async function tick(){
    const my=++st.seq, o=await poll(); if(my!==st.seq || !o || !o.ok) return;
    if(o.now) st.skew=o.now-Date.now()/1000;
    const was=st.rel;
    st.rel=o.release||null; st.con=o.contract||null;
    if(st.rel) st.label=st.rel.label||st.label;
    if(was && !st.rel){                      // the release stopped working on this hound
      const it=o.item||null;
      if(it && it.id===was.id){ finished(it); return 'done'; }
      finished({status:'stopped'}); return 'done';
    }
    paint();
  }
  let busy=false;
  async function loop(){
    if(busy) return; busy=true;
    try{
      for(;;){
        if(await tick()==='done') return;
        const active=!!(st.rel||st.con);
        await new Promise(r=>setTimeout(r, active?3000:20000));
        if(document.hidden && !active) await new Promise(r=>setTimeout(r, 20000));
      }
    } finally { busy=false; }
  }
  setInterval(()=>{ if(st.rel||st.con) paint(); }, 1000);   // the clock between polls
  if(document.readyState==='loading') document.addEventListener('DOMContentLoaded', loop); else loop();
  return { state:st };
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
/* ---- ⚙ settings gear (build 468): the right end of every page's header bar, after "📧 Email
   dashboard". Its light: red = key configurations required (navi.db unreadable / no assets / no
   findings), amber = optional configurations missing (certs, software, routes / paths, WAS,
   compliance, SLA, Fixed, EPSS, ⚡ Optimize, AI model), purple = all set. Hover lists what's
   missing; click opens Settings. Status: /api/hub/config_status, cached 60 s per tab. */
const _GEAR_SVG='<svg viewBox="0 0 24 24" width="17" height="17" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3.2"/><path d="M19.4 15a1.7 1.7 0 0 0 .34 1.87l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.7 1.7 0 0 0-1.87-.34 1.7 1.7 0 0 0-1.03 1.56V21a2 2 0 1 1-4 0v-.09a1.7 1.7 0 0 0-1.11-1.56 1.7 1.7 0 0 0-1.87.34l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.7 1.7 0 0 0 .34-1.87 1.7 1.7 0 0 0-1.56-1.03H3a2 2 0 1 1 0-4h.09a1.7 1.7 0 0 0 1.56-1.11 1.7 1.7 0 0 0-.34-1.87l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.7 1.7 0 0 0 1.87.34H9a1.7 1.7 0 0 0 1.03-1.56V3a2 2 0 1 1 4 0v.09a1.7 1.7 0 0 0 1.03 1.56 1.7 1.7 0 0 0 1.87-.34l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.7 1.7 0 0 0-.34 1.87V9c.26.6.86 1 1.51 1.03H21a2 2 0 1 1 0 4h-.09a1.7 1.7 0 0 0-1.51 1z"/></svg>';
function _gearStyle(){ if(document.getElementById('hGearCss')) return; const s=document.createElement('style'); s.id='hGearCss';
  s.textContent='.hgear{position:relative;display:inline-flex;align-items:center;justify-content:center;width:32px;height:30px;flex:0 0 auto;border:1px solid var(--line);border-radius:9px;color:var(--ink-2);background:var(--panel);text-decoration:none;transition:color .12s,border-color .12s}'
    +'.hgear:hover,.hgear:focus-visible{color:var(--ink);border-color:var(--accent)}'
    +'.hgear i{position:absolute;top:-3px;right:-3px;width:10px;height:10px;border-radius:50%;border:2px solid var(--panel);background:var(--ink-3)}'
    +'.hgear.lvl-red i{background:#e5484d;box-shadow:0 0 6px rgba(229,72,77,.8)}'
    +'.hgear.lvl-amber i{background:#f0a020;box-shadow:0 0 5px rgba(240,160,32,.6)}'
    +'.hgear.lvl-ok i{background:#8b5cf6;box-shadow:0 0 5px rgba(139,92,246,.6)}'
    +'.hgear.here{border-color:var(--accent);color:var(--accent)}'
    // phones: the bar is one fixed row — let "Next agent" and "Email dashboard" shrink, never the gear
    +'@media (max-width:700px){header.top .nextagent,#app-header .nextagent{flex:0 1 auto;min-width:0;overflow:hidden;text-overflow:ellipsis}'
    +'header.top>.hmbtn,#app-header>.hmbtn{flex:0 1 auto;min-width:34px;overflow:hidden;white-space:nowrap;text-overflow:ellipsis}}';
  document.head.appendChild(s); }
function _gearLast(){ const g=document.getElementById('hGear'); if(g&&g.parentNode&&g.parentNode.lastElementChild!==g) g.parentNode.appendChild(g);
  const s=document.getElementById('hSearch'); if(s&&g&&g.parentNode&&s.nextElementSibling!==g) g.parentNode.insertBefore(s,g); }
/* 🔎 Search icon (build 471) — just left of the gear: one click to the Search Hounds, to look at data fast. */
const _SEARCH_SVG='<svg viewBox="0 0 24 24" width="17" height="17" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="10.5" cy="10.5" r="6.5"/><path d="M15.5 15.5 21 21"/></svg>';
function _onSearchPage(){ const p=location.pathname; if(/\/web\/search\.html$/.test(p)) return true;
  try{ return SEARCH_PAGES.some(x=>p===x[1]||p.endsWith(x[1])); }catch(e){ return false; } }
function mountSearchIcon(hdr){
  let s=document.getElementById('hSearch');
  if(!s){ s=document.createElement('a'); s.id='hSearch'; s.className='hgear hsearch'; s.href='/web/search.html';
    s.title='Search Hounds — assets, vulns, plugins, tags, routes, paths, apps, fixed, compliance'; s.setAttribute('aria-label','Search Hounds'); s.innerHTML=_SEARCH_SVG; }
  s.classList.toggle('here',_onSearchPage());
  hdr.appendChild(s); }
function _gearPaint(o){ const g=document.getElementById('hGear'); if(!g||!o||!o.ok) return;
  g.classList.remove('lvl-red','lvl-amber','lvl-ok'); g.classList.add('lvl-'+(o.level||'ok'));
  const list=(o.items||[]).slice(0,10).map(i=>(i.level==='red'?'● ':'○ ')+i.label+(i.fix?' — '+i.fix:'')).join('\n');
  g.title=(o.title||'Settings')+(list?'\n'+list:'')+'\n\nClick to open Settings';
  g.setAttribute('aria-label','Settings — '+(o.title||'')); }
async function mountSettingsGear(){
  const hdr=document.getElementById('app-header')||document.querySelector('header.top'); if(!hdr) return;
  _gearStyle();
  let g=document.getElementById('hGear');
  if(!g){ g=document.createElement('a'); g.id='hGear'; g.className='hgear'; g.href='/web/settings.html';
    g.title='Settings'; g.setAttribute('aria-label','Settings'); g.innerHTML=_GEAR_SVG+'<i></i>'; }
  if(/\/web\/settings\.html$/.test(location.pathname)) g.classList.add('here');
  mountSearchIcon(hdr); hdr.appendChild(g); _gearLast();
  const onSettings=g.classList.contains('here'); let o=null;
  if(!onSettings){ try{ const c=JSON.parse(sessionStorage.getItem('houndsCfgStatus')||'null'); if(c&&Date.now()-c.t<60000) o=c.o; }catch(e){} }
  if(!o){ try{ o=await jpost('/api/hub/config_status',{}); }catch(e){ o=null; }
    if(o&&o.ok){ try{ sessionStorage.setItem('houndsCfgStatus',JSON.stringify({t:Date.now(),o})); }catch(e){} } }
  _gearPaint(o);
}
if(document.readyState!=='loading') mountSettingsGear(); else document.addEventListener('DOMContentLoaded',mountSettingsGear);

/* ---- evidence deep links (build 467): ?view=<filter> / ?cls=<class> / ?scope=<scope> ----
   An On the Scent card opens a hound ON its evidence: the page applies its own filter once its
   data is on screen (a release's cached run replays on open). hViewOnce(name, fn) runs fn(value)
   the first time it is called with that URL parameter present; if the page has no data yet
   (never run / not released), a note asks for ▶ Run and the filter applies after it. */
function hViewParam(name){ try{ return (new URLSearchParams(location.search).get(name||'view')||'').trim(); }catch(e){ return ''; } }
const _hViewDone={};
function hViewOnce(name, fn){
  const v=hViewParam(name); if(!v||_hViewDone[name]) return false;
  _hViewDone[name]=true; const n=document.getElementById('hViewNote'); if(n) n.remove();
  try{ fn(v); }catch(e){} return true; }
function _hViewHint(){
  const keys=['view','cls','scope'].filter(k=>hViewParam(k)); if(!keys.length) return;
  setTimeout(()=>{ if(keys.every(k=>_hViewDone[k])) return;
    const w=document.querySelector('.wrap'); if(!w||document.getElementById('hViewNote')) return;
    const d=document.createElement('div'); d.id='hViewNote'; d.className='flash';
    d.style.cssText='display:block;margin:10px 0;border-left:4px solid var(--amber,#e0a526)';
    d.innerHTML='🧾 You opened this hound on its evidence (<b>'+esc(keys.map(k=>hViewParam(k)).join(', '))+'</b>). It has no run on screen yet — press <b>▶ Run</b> and the list is filtered to it.';
    const h=w.querySelector('header'); if(h&&h.nextSibling) w.insertBefore(d,h.nextSibling); else w.prepend(d); }, 2500); }
if(document.readyState!=='loading') _hViewHint(); else document.addEventListener('DOMContentLoaded',_hViewHint);
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
  was:{name:'Arachne',lore:'<b>Arachne</b>, the weaver of Greek myth whom Athena turned into the first spider — here she walks your web apps\' hidden surface, the dynamic (DAST) findings that live behind the login and inside the request/response, mapping OWASP-class exposure a network scan never sees.'},
  sla:{name:'Sk\u00f6ll',lore:'<b>Sk\u00f6ll</b>, the wolf that forever chases the sun across the sky — here he chases every finding against its clock, surfacing the SLA breaches: what is overdue, by how long, and for whom, so remediation deadlines can\'t quietly slip.'},
  asset_ownership:{name:'Terminus',lore:'<b>Terminus</b>, the Roman god of boundary stones and property lines — he answers who owns each asset. Business leaders own groups of assets (Business Owner), technology owners hold routes &amp; paths (Owner, via Atlas), and a single Asset Owner can claim an asset\'s every route &amp; path. Surfaces what is unclaimed, what is blind, and what the pack knows about your crown jewels.'},
  fused_score:{name:'Nemesis',lore:'<b>Nemesis</b>, the goddess of retribution who brings the reckoning to what has earned it — here she fuses every Hound\'s signal into one exposure score per asset, surfaces the worst from each and where they converge, ranks the estate worst-first, and turns a remediation play into a projected reduction. The pack\'s convergence page.'},
  ex_apps:{name:'Vizsla',lore:'The <b>Vizsla</b> — a tireless pointer bred to range wide and mark its quarry — here it ranges the WAS inventory and points you at every web application navi has seen, so you can pick one and dig in.'},
  ex_software:{name:'Harrier',lore:'The <b>Harrier</b> — a pack hound bred to run fresh quarry down fast and stay on the line — here it runs down every <b>install</b> of a piece of software in navi.db, the moment a new zero-day names it.'},
  ex_compliance:{name:'Saluki',lore:'The <b>Saluki</b> — one of the oldest hound breeds, a sighthound that marks its quarry across open ground — here it ranges every <b>audit result</b> in navi.db, so you can find any check, on any asset, in one search.'},
  ex_fixed:{name:'Plott',lore:'The <b>Plott</b> — bays the moment it trees its quarry — here it trails the findings that have been <b>fixed</b> (closed / remediated), so you can prove what is actually put to bed versus what only looks quiet.'},
 certificate:{name:'Certania',lore:'Coined from <b>“certificate”</b> + the loyal hound. It stands watch over the chain of trust, sniffing out certificates about to expire.'},
 iot_squad:{name:'Cerberus Hound',lore:'<b>Cerberus</b>, the many-headed dog guarding the underworld’s gate. The IoT squad is a pack guarding the network edge — the unknown devices at the gate.'},
 acr:{name:'Anubis',lore:'<b>Anubis</b>, who weighs the heart against the feather of truth. ACR calibration weighs each asset’s <i>true</i> criticality.'},
 customapp:{name:'Cavall Hound',lore:'<b>Cavall</b>, King Arthur\'s hound, who left his pawprint in stone on the hunt — here he tracks the custom apps that left their print in routes and paths but never made your inventory.'},
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
 compliance_asset:{name:'Tiresias',lore:'<b>Tiresias</b>, the blind seer of Thebes who saw what others missed — point him at one asset and he lays out every audit check it passed, failed or warned (actual vs expected, the fix, the framework mappings), then infers the connection between a failed control and the real findings that back it, so a config gap and the vuln proving it can be tagged and routed together.'},
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
const _DD_SKIP = new Set(['ex_compliance','ex_software','ex_assets','ex_vulns','ex_plugins','ex_routes','ex_paths','ex_tags','postquantum','attackpath',
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
 /* generated by tools/hound_pages.py --intro from tools/hound_pages/<id>.json — edit those */
 acr:{does:"Anubis changes the ACR of every asset that carries a tag — set it to a value, or raise or lower it by N — with a business reason Tenable records alongside it. It shows exactly what navi will change before anything is written, logs every change, and can protect the assets it changed from later overwrites.",caps:[
   "<b>Set, +N or −N per tag<\/b> — pick any tag from the live Tenable tag list and calibrate every asset on it at once; ACR stays within 1–10.",
   "<b>Business case on every change<\/b> — Business Critical, In Scope For Compliance, Existing Mitigation Control or Dev Only, plus an optional note — sent to Tenable with the change.",
   "<b>Preview before you write<\/b> — per change: how many assets will change, how many are protected, how many have no ACR yet and will be skipped.",
   "<b>Bulk in plain English<\/b> — describe the calibration (\"production to 9, lab down 2\") and an optional AI model drafts the changes; only existing tags and scores 1–10 pass, and you approve each.",
   "<b>Protection with NO : UPDATE<\/b> — tag the assets the Hounds changed so later bulk changes leave them alone — navi skips any asset tagged exactly NO : UPDATE.",
   "<b>ACR log + CSV<\/b> — every change the Hounds made: asset, before and after, selector, business case — filterable and exportable."]},
 agentgroup:{does:"Sirius lists your Tenable agent groups live and tags every asset in each group Agent Group : &lt;group name&gt;, matching Tenable's own membership. Pick groups three ways: type a list of names, tick them in a list, or tag every group at once.",caps:[
   "<b>Live from Tenable<\/b> — agent groups pulled live through navi each time, not a stale copy.",
   "<b>Three ways to tag<\/b> — a typed list of group names, a checkbox per group, or every group at once.",
   "<b>Exact membership<\/b> — navi tags the assets in each group directly, so the tag matches Tenable's own membership.",
   "<b>One tag per group<\/b> — Agent Group : &lt;name&gt;, consistent across the estate and usable in scans, dashboards and exports."]},
 ai:{does:"Pythia finds AI across five data sources, gives each asset a role, flags endpoints that are exposed or unauthenticated, maps where data can leave (sanctioned vs shadow), checks KEV, critical and end-of-life risk, maps MITRE ATLAS techniques, and compares each asset's ACR with the ACR its role suggests.",caps:[
   "<b>Five-source discovery<\/b> — Tenable's Artificial Intelligence plugin family, the software and CPE inventories, plugin output, and network endpoints — one AI asset list.",
   "<b>Role and suggested ACR<\/b> — Model Serving, Vector DB / RAG, GPU / Training, MLOps, Notebook / Dev, AI Dev Tool, LLM API Client — each with a suggested ACR (e.g. Model Serving 9).",
   "<b>Exposed and unauthenticated endpoints<\/b> — AI services listening on inference, notebook or MLOps ports, with an unauthenticated check from the plugin output.",
   "<b>Data-egress governance<\/b> — egress capability and destinations seen in plugin output, split sanctioned vs shadow by an allowlist you edit.",
   "<b>Why + false-positive control<\/b> — every row shows its evidence (source, term, plugin, snippet); dismiss a false positive per asset, per framework or everywhere.",
   "<b>MITRE ATLAS map<\/b> — AI-specific adversary techniques implied by each asset's role, exposure and egress — click a technique or tactic to list and tag its assets.",
   "<b>Gated tags and ACR<\/b> — AI, AI Role, AI Software, AI Exposed, AI Priority, AI Egress and AI ATLAS tags; under-rated assets get AI ACR Raise and the role's suggested ACR."]},
 alert:{does:"Alert Raven watches navi.db for the conditions you choose and emails a digest when one newly fires. An alert is a number plus a condition: above or below a threshold, or a rise or drop since the last check. Start from a suggested pattern, or describe the alert in plain English, then test it before you save it.",caps:[
   "<b>Seven ready-made patterns<\/b> — credentialed-scan coverage, slow scans, new CISA KEV exposure, new criticals, certificates expiring within 30 days, ownerless assets, end-of-life software.",
   "<b>Alerts in plain English<\/b> — describe what to watch and Alert Raven drafts a read-only SQL metric, operator and threshold for review; without an AI model it builds the query from navi's tables.",
   "<b>Test before you save<\/b> — a dry run shows the current value and whether it would fire — nothing is stored and nothing is sent.",
   "<b>Fires on change<\/b> — an alert notifies when it goes from clear to firing, once, until it clears again — a lasting condition doesn't email every cycle.",
   "<b>One digest per check<\/b> — everything that newly fired in one email, with the affected hosts, to an allowed recipient.",
   "<b>History<\/b> — recent evaluations: what fired, what cleared, and the value each time."]},
 argos:{does:"Give Argos a UUID or an IP and he assembles one dossier: identity and host profile, the asset's Exposure Score and rank, open findings and CVEs, SLA clock, compliance, certificates, EOL software, owners, identities, scan confidence, and every tag the pack put on it — each explained, with the hound that raised it.",caps:[
   "<b>Identity and host profile<\/b> — hostname, IP, OS, network, ACR, AES, CPU / RAM / architecture from inventory plugins, last scan and its duration, and a Tenable link.",
   "<b>Exposure Score in context<\/b> — this asset's Nemesis score and band, and its rank in the estate.",
   "<b>Every tag deciphered<\/b> — what each tag means and which hound raised it — Laelaps for KEV, Certania for certificates, Charon for EOL, and the rest.",
   "<b>Findings with a fix path<\/b> — top findings and CVEs with plugin output on demand; each one can be sent to Amarok for remediation.",
   "<b>Owners and identities<\/b> — who owns the asset, with a link to assign one, and the accounts seen on the host.",
   "<b>Software, certificates, web pages<\/b> — installed software, certificates with expiry and weak crypto, and web pages captured by plugins.",
   "<b>Live views from navi<\/b> — per-asset software, patches and details pulled live from the navi CLI on demand."]},
 asset_ownership:{does:"Terminus answers ownership from the asset's side. For every asset he shows who owns it at three layers — Business Owner, the route and path owners from Atlas, and a single Asset Owner — how much of it is claimed, and what is left blind. You assign owners in plain English, preview the match, then tag.",caps:[
   "<b>Three ownership layers<\/b> — Business Owner (accountable leader), Owner (route / path owners from Atlas) and Asset Owner (one owner for the whole asset, or for whatever is left).",
   "<b>Coverage per asset<\/b> — how much of each asset is claimed, which assets are fully claimed, and which have no owner at any layer.",
   "<b>Crown jewels first<\/b> — assets with ACR ≥ 9 or a crown-jewel tag, unclaimed first, with what the other hounds already know about each one.",
   "<b>Risk without an owner<\/b> — unclaimed crown jewels, open critical and CISA KEV findings on unowned assets, and assets no hound has signaled on.",
   "<b>Owners in plain English<\/b> — \"assign Jane Smith to production\" — Terminus reads each asset's tags, previews who matches, and tags them on approval.",
   "<b>Built for large estates<\/b> — the per-asset table pages and searches on the server; owner tagging runs as a background job, so 150,000 assets tag as easily as 50."]},
 attackpath:{does:"Fenrir chains the weaknesses Tenable already found — remote exploits, default credentials, open unauthenticated services, local privilege escalation, accounts reused across hosts, NTLM relay, domain-controller flaws and failed controls like LAPS, SMB signing and LLMNR — into ranked routes to every crown jewel (ACR ≥ 7), then finds the fixes that cut the most exposure.",caps:[
   "<b>Chained steps with evidence<\/b> — exploit → privilege escalation → credential harvest → lateral move → crown jewel; every step names its finding and its ATT&amp;CK technique.",
   "<b>Failed controls as enablers<\/b> — failed compliance checks (LAPS, SMB signing, LLMNR, WDigest, LSASS protection, sudo, empty passwords) become the steps they make possible.",
   "<b>Honest credential pivots<\/b> — an account present on several hosts is a pivot; navi.db can't show a shared password, so Fenrir doesn't claim one — except local Administrator where LAPS has failed.",
   "<b>Interactive attack map<\/b> — attacker → crown jewels, with diverse routes per target; click any host or step for its evidence.",
   "<b>Fix first<\/b> — choke points and a remediation bundle ranked by how much crown-jewel exposure each fix removes, recalculated as fixes are applied.",
   "<b>Gated tags and CSV<\/b> — Attack Path : Entry Point, Pivot, Target or Choke Point on the exact assets; paths export to CSV."]},
 c2:{does:"Amarok checks Linux hosts read-only — health, login, \"does this path exist?\" and a strict pre-flight — and turns Tenable's own solution text into a remediation plan you review, then deploys it to one canary host and, after a separate click, rolls it out to the rest. Every button acts on one Target set and shows what will happen before you confirm. Every command on every host lands in a hash-chained log.",caps:[
   "<b>One Target set<\/b> — every action uses the same host list shown in a bar at the top; a preview built from the exact request lists the hosts, the policy and the undo story.",
   "<b>Inspect (read-only)<\/b> — one-confirm pre-flight with strict host keys — login, sudo, live OS group, package-manager lock and holds, installed → candidate vs fixed for every package, reboot state and whether a downgrade is still possible — plus health checks with a health verdict, login test and path check.",
   "<b>Remediation plan from Tenable's text<\/b> — the plugin's solution and output (rpm and dpkg package pairs, kernels, upstream versions) become one plan per OS group — every affected package in one transaction — checked by a deterministic allow-list validator.",
   "<b>Canary, then roll out<\/b> — two confirmed clicks: one non-crown canary first; roll out unlocks only when the canary reads Fixed. Crown jewels always run last.",
   "<b>Plain verdicts<\/b> — Fixed only when every package reaches its distro fixed build; otherwise Upgraded (fix not proven or still vulnerable), No change, Already fixed, Not installed, Held, Package manager busy, Step failed or Unknown state — with reboot and service-restart flags.",
   "<b>Commands and files<\/b> — free-form commands and file copies on the Target set, with a typed host count for any multi-host run and an abort switch."]},
 certificate:{does:"Certania finds every certificate that has already expired — month by month over the last 12 months, plus everything older that is still deployed — and every certificate expiring in the next 12 months, maps each to its assets, and lays them out on one timeline. Certania tags the assets with their exact expiry date so the renewal becomes routable work.",caps:[
   "<b>Expired and expiring inventory<\/b> — expired by month for the last 12 months and older, plus everything failing in the next 12 months, each with its assets.",
   "<b>One expiry timeline<\/b> — older, the last 12 months and the next 12 months on one axis, so renewals are planned by month, not found by outage.",
   "<b>Risk context<\/b> — crown jewels (ACR above 7) with an expired or expiring certificate, weak crypto (MD5 / SHA-1 signatures, RSA keys under 2048 bits), self-signed certificates, and days expired.",
   "<b>Cert failure : &lt;date&gt; tags<\/b> — the assets behind each expiry date you choose, tagged with that exact date — a dated, routable work item.",
   "<b>Cert Issue tags by plugin<\/b> — every certificate plugin firing in navi.db, with its asset count; tag its assets Cert Issue : &lt;plugin name&gt;.",
   "<b>Devices and apps from certificates<\/b> — device and application names identified from certificate subjects."]},
 cisakev:{does:"Laelaps finds every asset with a KEV finding from the CISA KEV reference Tenable attaches to each finding, joins it to CISA's catalog for due dates and ransomware use, and shows what is overdue, what is due soon, which crown jewels and vendors are involved — then tags the assets so the work can be routed.",caps:[
   "<b>KEV from your own findings<\/b> — Tenable marks each KEV finding with a CISA cross-reference and the date CISA added it; Laelaps reads that, so no memorized CVE list is involved.",
   "<b>Due dates and overdue<\/b> — CISA's remediation due date per KEV, on a month-by-month timeline of overdue vs due later.",
   "<b>Ransomware, crown jewels, vendors<\/b> — KEVs CISA links to ransomware campaigns, crown jewels (ACR above 7) carrying KEV, and the vendors and products involved.",
   "<b>Four tag schemes<\/b> — CISA KEV : Vulnerable, CISA KEV : &lt;date added&gt;, CISA KEV Due : &lt;due date&gt; and CISA KEV : Ransomware — each on the exact assets.",
   "<b>Hunt in plain English<\/b> — ask a KEV question and get the answer from one read-only SQL query over navi.db and its tags.",
   "<b>Approved downloads<\/b> — the CISA catalog is fetched only after you approve it (or auto-approve in Settings), with a bundled snapshot when offline."]},
 classify:{does:"Linnaeus classifies every asset from the tags the pack has written, and shows exactly what is still unclassified. From operating-system fingerprints and device signals he suggests classes for the untagged assets, groups them into cohorts you can approve, and writes the tags.",caps:[
   "<b>Classes from tags<\/b> — the pack's own taxonomy — Asset Inventory, IoT, Device Type, OS — rolled up into Windows, Linux, macOS, Server, Workstation, Mobile, IoT, OT, network, hypervisor, cloud and Unclassified.",
   "<b>Standard device types<\/b> — Server, Desktop, Laptop, Workstation, Phone / Tablet, Camera, Printer, NAS, VoIP, UPS / Power, Badge Reader, Switch, Router, Firewall, Wireless Access Point, Load Balancer, Hypervisor, PLC, HMI, RTU — offered as you tag, and each maps to its class.",
   "<b>OS and device signals<\/b> — untagged assets grouped by Nessus's own device type (printer, camera, switch, firewall …) or by detected OS (\"Windows Server 2022 — 40 assets\"), each cohort one approval away from a tag.",
   "<b>OS explorer<\/b> — OS families and versions for the untagged assets, with a confidence rating for each fingerprint.",
   "<b>Tag by OS in plain English<\/b> — \"tag all my assets by OS with a confidence over 70\" becomes a plan you review before anything is written.",
   "<b>Environment Explorer<\/b> — a zoomable sunburst of class → subnet → software and Docker, down to each asset (which opens in Argos).",
   "<b>Risk and ownership per class<\/b> — KEV and critical findings, cloud assets, and classified assets with no owner — so the unclassified bucket becomes a ranked worklist."]},
 compliance:{does:"Minos turns your audit results into one verdict: pass rate, results by status, the controls failing the most assets, how failures map to frameworks such as NIST 800-53, PCI, HIPAA, CIS and ISO, every audit benchmark, and a scorecard per asset. He can tag an Audit Owner on the assets failing a control.",caps:[
   "<b>Results by status<\/b> — passed, failed, warning and unknown across every check × asset, with pass rate = pass ÷ (pass + fail).",
   "<b>Controls failing the most assets<\/b> — the short list of controls whose fix moves the most assets.",
   "<b>Framework exposure<\/b> — failures rolled up by the frameworks and controls each check references (NIST, PCI, HIPAA, CIS, ISO …).",
   "<b>Audit benchmarks<\/b> — every audit file in navi.db, with its results.",
   "<b>Per-asset scorecards<\/b> — which assets pass least, which have warnings, which are clean.",
   "<b>Audit Owner tags<\/b> — assign an owner to the assets that fail one control — Audit Owner : &lt;owner&gt;.",
   "<b>One click to the evidence<\/b> — every card, bar, control, framework and benchmark opens the matching assets in Tiresias."]},
 compliance_asset:{does:"Tiresias investigates compliance two ways. By asset: every audit check the asset passed, failed or warned, with actual vs expected values and framework mappings, plus the inferred link between each failed control and real vulnerabilities on that host. By audit file: a benchmark leaderboard, each file's adherence, the checks and assets it covers, and the vulnerabilities behind its failing controls.",caps:[
   "<b>Every check on one asset<\/b> — status, actual vs expected value, and the frameworks and controls it maps to.",
   "<b>Audit ↔ vuln correlation<\/b> — compliance results carry no CVEs, so Tiresias infers the link by topic on the same asset — and shows the evidence.",
   "<b>Audit-file lens<\/b> — a leaderboard of benchmarks by adherence, then one file's checks, assets and the vulnerabilities behind its failures.",
   "<b>Estate-wide links<\/b> — the audit-to-vulnerability correlations across every asset, not just one.",
   "<b>Opened from Minos<\/b> — a Minos card (failed, a control, a framework, an audit file, under 50% pass) narrows the asset list and opens its worst asset.",
   "<b>Audit-Vuln Link tags<\/b> — tag the asset with a correlated topic you choose, so the joint fix can be routed."]},
 contract:{does:"Covenant turns your tagging history and a plain-English policy into a workflow: which hounds tag, with what logic, which ACR changes to make, which stale tags to clear first, and how often to run. It always shows the plan first; only when you arm it does the loop execute — every few hours, behind the same write gate as everything else.",caps:[
   "<b>Start from what you did<\/b> — build the contract from the Tagging log (or an exported tag-log CSV): the hounds you used and the ACR changes you made become the starting policy.",
   "<b>Per-hound policy<\/b> — 19 tagging hounds, each on or off with plain-English logic; without a policy a hound proposes its riskiest top 50.",
   "<b>ACR rules in plain English<\/b> — describe a calibration and Covenant writes the rule; optionally protect the changed assets with NO : UPDATE.",
   "<b>Garmr removal phase<\/b> — clear the tags you list at the top of a cycle, pause for Tenable to catch up, then re-tag — without deleting the tags themselves.",
   "<b>Plan first, armed to act<\/b> — disarmed, the loop only plans; armed (with writes enabled) it runs on a schedule, every 4 hours by default. A one-off cycle runs only when you confirm it.",
   "<b>Each cycle checked and reported<\/b> — a QA pass on what landed, the loop log, Alert Raven's checks, and a run-summary email through Gabriel.",
   "<b>Escape hatch<\/b> — export the plan as a runnable navi script for when writes must run somewhere else."]},
 custom_audit:{does:"Draco writes custom Tenable .audit files two ways: describe the check in plain English and an AI model drafts Nessus checks, or build each check field by field from a platform catalog. Every file is previewed live, syntax-validated and mapped to frameworks before you download it — and you can seed a whole CIS benchmark and adjust it in one prompt.",caps:[
   "<b>Describe it<\/b> — \"password minimum length must be 14 on Windows servers\" becomes drafted checks you can edit; with no AI model configured it says so and the builder still works.",
   "<b>Build it<\/b> — Windows config (registry, password, lockout and audit policy, user rights, services, REG_CHECK, WMI, PowerShell), Windows file content, and Unix / Linux / macOS (file, content, command, RPM, process, service).",
   "<b>CIS benchmark seeds<\/b> — start from the built-in control index for CIS Docker, Ubuntu Linux or RHEL and tighten sections in one prompt — \"create a CIS Docker benchmark and tighten 5.x\".",
   "<b>Validated before download<\/b> — the .audit grammar is checked so the file loads into a compliance scan.",
   "<b>Framework references<\/b> — NIST, PCI, HIPAA, CIS and ISO references suggested for each check.",
   "<b>Import and edit<\/b> — upload an existing .audit; each &lt;custom_item&gt; is kept verbatim and becomes editable."]},
 customapp:{does:"Cavall mines the application routes and filesystem paths in your findings, compares them with the software inventory, and lists the apps that appear only there as candidates to name. Say \"tag my custom app billing-portal\" and he finds the matching routes and paths, shows the assets, and — once you approve — tags them Custom App : &lt;name&gt;.",caps:[
   "<b>Route and path discovery<\/b> — finds software by where it lives and how it's served — evidence package lists miss.",
   "<b>Gap against the inventory<\/b> — keeps only what the software inventory doesn't already list.",
   "<b>Name it in plain English<\/b> — \"tag my custom app billing-portal\" searches both routes and paths and shows the matches before anything is written.",
   "<b>Tags across both sources<\/b> — Custom App : &lt;name&gt; on every asset with a matching path or route.",
   "<b>Ignore list<\/b> — drop noise terms once, or import a list from CSV."]},
 dashboard:{does:"Daedalus turns a plain-English request into one read-only query over navi.db and renders the answer as a chart, KPI or table. 34 starter metrics run with no AI model at all. Pin what you like to your own dashboard, rearrange and resize it, email it, or promote it to a standalone page.",caps:[
   "<b>Ask in plain English<\/b> — \"top 10 plugins by affected assets\" — the model writes one SQL SELECT, which you can see before it renders.",
   "<b>Read-only by design<\/b> — the query must be a single SELECT and navi.db is opened read-only, so nothing can be changed.",
   "<b>34 starter metrics, no model needed<\/b> — from findings by severity and VPR band to stale assets, weak-key certificates and the remediation funnel.",
   "<b>25 chart types<\/b> — KPI, bar, column, stacked, pie, donut, line, area, scatter, heatmap, Sankey, treemap, funnel, waterfall, Pareto, gauge, table and more.",
   "<b>Your dashboard<\/b> — pin components, drag to reorder, size each one, switch chart type, export CSV or show the SQL; saved in your browser.",
   "<b>Share it<\/b> — email the dashboard through Gabriel, or promote it to a standalone, refreshable Custom Dashboard page."]},
 email:{does:"Gabriel turns the pack's findings into email routed by owner: each owner gets only their assets, with links back into Tenable. He also sends CISA KEV fire alarms, certificate countdowns, the On the Scent morning briefing, Contract plans and results — and any chart, list or dashboard in the app. You always preview first; sending is gated.",caps:[
   "<b>Owner-routed remediation<\/b> — reads Owner tags from Atlas and emails each owner only their assets, each with its Tenable asset link and the plugin links for its findings.",
   "<b>Seven report types<\/b> — owner remediation, vulnerability detail, KEV fire alarm, certificate countdown, morning briefing, Contract plan and Contract result.",
   "<b>Board or technical<\/b> — summary counts for leadership, or per-asset, per-finding detail for the people who fix it.",
   "<b>Email anything on screen<\/b> — any widget's picture and its list (a CSV attachment at 100 rows or more), a Sankey graph, or a whole Custom Dashboard.",
   "<b>From any hound<\/b> — the Email findings button carries a hound's assets, finding IDs and the tag it applied straight into a draft.",
   "<b>Sends exactly what you previewed<\/b> — the exact previewed messages are sent, and every send is recorded in the Tagging log."]},
 eol:{does:"Charon finds every asset with an Unsupported or End-of-Life finding, groups them by product (operating system or application), reads the end-of-life date Tenable reports, and shows how long each has been out of support and where it overlaps with crown jewels, CISA KEV and critical findings. Then he tags the assets so replacement can be planned and owned.",caps:[
   "<b>Detection that keeps up<\/b> — matches lifecycle language in Tenable's plugin names (Unsupported, End of Life, SEoL …), so new EOL plugins are picked up with no rules to maintain.",
   "<b>Product view<\/b> — each EOL product, operating system or application, with its end-of-life date from the plugin output and years past support.",
   "<b>Why it matters<\/b> — EOL assets that are crown jewels (ACR above 7), carry a CISA KEV, or have critical findings.",
   "<b>Support timeline<\/b> — when support ended, by date, across the estate.",
   "<b>Lifecycle tags<\/b> — Lifecycle : Unsupported or End of Life on every affected asset, and Lifecycle EOL : &lt;date&gt; on exactly the assets whose output states that date."]},
 ex_apps:{does:"Vizsla searches every web application in navi.db and filters by name, target, technology, severity and how recently it was scanned. Each row shows critical, high and medium counts, total findings, technology, top OWASP category and last scan; click an app for Arachne's report.",caps:[
   "<b>Search and filter<\/b> — name, target, technology, severity presence and scan recency.",
   "<b>Severity at a glance<\/b> — critical, high and medium counts and total findings per app.",
   "<b>Context<\/b> — technology stack and top OWASP category.",
   "<b>Open the report<\/b> — an app opens Arachne's App Report.",
   "<b>Ask in plain English<\/b> — a question becomes one read-only SQL query over the web-app table that you can edit before it runs (needs an AI model).",
   "<b>CSV and email<\/b> — export the rows or send them through Gabriel."]},
 ex_assets:{does:"Bloodhound searches every asset by hostname, IP, OS or network. It is also where On the Scent's At a glance cards land: each card opens the exact assets behind its number — computed by the hound that owns it — riskiest (highest ACR) first, ready to page, search and export.",caps:[
   "<b>Search every asset<\/b> — hostname, IP, OS or network in one box.",
   "<b>Evidence lists<\/b> — KEV-exploitable assets, assets scored 60 or more, crown jewels (all, with KEV, or scanned without credentials), assets flagged by four or more hounds, EOL software, quantum-vulnerable crypto.",
   "<b>Same count as the card<\/b> — each list is computed with the owning hound's own rule — Laelaps, Nemesis, Charon or Heimdall.",
   "<b>Any size<\/b> — the list is stored on the server, so 50 or 150,000 assets page, search and export the same way.",
   "<b>One click to act<\/b> — every host opens Argos, where its findings can be remediated with Amarok or tagged; a Tenable link opens it in Tenable."]},
 ex_compliance:{does:"Saluki searches every audit result in navi.db by check name or ID, audit file, framework, status, or asset — hostname, IP or UUID — with failed results first. Each row opens to show actual vs expected, the fix, and the framework references; a check opens across every asset that ran it.",caps:[
   "<b>Search anything<\/b> — check name or ID, audit file, hostname, IP or asset UUID in one box.",
   "<b>Filter fast<\/b> — by status (failed, warning, passed, other), audit file and framework, with result counts in each list.",
   "<b>The whole filtered set<\/b> — results, assets, checks, pass rate, failed, warnings and assets failing a check — counted over every match, not just the page.",
   "<b>Detail on click<\/b> — actual vs expected, the solution, check info, a reference link, and the framework controls it maps to.",
   "<b>One check, every asset<\/b> — click a check ID to see it on every asset that ran it.",
   "<b>Into the deep-dives<\/b> — each asset opens Argos, or Tiresias for every check on that asset.",
   "<b>Ask in plain English<\/b> — a question becomes one read-only SQL query over the audit-result table that you can edit before it runs (needs an AI model).",
   "<b>CSV and email<\/b> — export the whole search (up to 50,000 rows) or send it through Gabriel."]},
 ex_fixed:{does:"Plott searches navi's remediation history: every fixed finding with each finding's first-seen and fixed dates, days to fix (computed, not trusted from navi's text field) and navi's own SLA Pass / Fail, SLA failures first.",caps:[
   "<b>Remediation history<\/b> — every fixed finding with plugin, name, severity and state.",
   "<b>Days to fix<\/b> — computed from first seen to fixed.",
   "<b>SLA verdict<\/b> — navi's own Pass / Fail, from navi's SLA calculation.",
   "<b>Worst first<\/b> — SLA failures first, then by severity; the asset opens Argos.",
   "<b>Ask in plain English<\/b> — a question becomes one read-only SQL query over the remediation-history table that you can edit before it runs (needs an AI model).",
   "<b>CSV and email<\/b> — export the rows or send them through Gabriel."]},
 ex_paths:{does:"Greyhound searches the filesystem paths found on assets by path text, with the plugin that found each and the host and IP. Tag applies Path : &lt;name&gt; to every asset carrying that exact path.",caps:[
   "<b>Search paths<\/b> — by any part of the path.",
   "<b>Where it was found<\/b> — the plugin, host and IP for each path; the host opens Argos.",
   "<b>Tag a path<\/b> — Path : &lt;name&gt; on every asset with that exact path, with an editable value, behind the write gate and a confirm.",
   "<b>Email the result<\/b> — send the rows through Gabriel."]},
 ex_plugins:{does:"Foxhound lists every distinct plugin in navi.db with its family and the number of assets it fires on, searchable by ID, name or family. Any plugin on assets can be handed to Amarok for a remediation plan.",caps:[
   "<b>Every distinct plugin<\/b> — ID, name and family, with how many assets it fires on.",
   "<b>Search<\/b> — by ID, name or family.",
   "<b>Open the detail<\/b> — a linked row opens the plugin's full detail.",
   "<b>Fix from here<\/b> — Fix sends the plugin to Amarok's remediation planner, pre-filled."]},
 ex_routes:{does:"Wolfhound searches the application routes in navi.db by app name or vulnerability type, with each route's total findings and plugins. Tag applies Route : &lt;name&gt; to every asset on that route.",caps:[
   "<b>Search routes<\/b> — by app name or vulnerability type.",
   "<b>Route detail<\/b> — total findings and the plugins behind each route.",
   "<b>Tag a route<\/b> — Route : &lt;name&gt; on every asset on that route, with an editable value, behind the write gate and a confirm.",
   "<b>Email the result<\/b> — send the rows through Gabriel."]},
 ex_software:{does:"Harrier searches the software inventory in navi.db by product name, one version, or an affected version range, and shows where the software is installed: assets, versions, operating systems, networks and asset criticality, with every asset sorted into in range, distro build, no version, or not in range. Its ✨ zero-day lookup reads the affected products and versions from NVD, CVE.org, OSV or an advisory page — only from the sites you approve — and counts each product in your inventory.",caps:[
   "<b>Where it's installed<\/b> — assets, distinct versions and products for any search, with breakdowns by version, operating system, network and asset criticality — counted over the whole search, not just the page.",
   "<b>Affected-range check<\/b> — give a range like <span class='mono'>&gt;=2.0 &lt;2.17.1; &gt;=2.18 &lt;2.18.2<\/span> and every asset is sorted into in range, distro build, no version or not in range, with crown jewels in range called out.",
   "<b>Honest about distro builds<\/b> — a RHEL, Ubuntu, Debian or SUSE package inside the range is flagged \"distro build\", because distros back-port fixes without changing the version; confirm those against the distro's advisory.",
   "<b>Most exposed first<\/b> — every asset carries its Nemesis exposure score, so a zero-day's affected assets can be ranked by what else they carry; the score comes from the last whole-estate Exposure Score run and is left blank, with a note, once navi.db has changed since.",
   "<b>✨ Zero-day lookup<\/b> — type a CVE id, a product (\"new Ivanti Connect Secure bug\") or paste an advisory URL; Harrier proposes NVD, CVE.org and OSV, or an NVD search of the last 120 days, and reads only the sites you tick.",
   "<b>Every site approved, every time<\/b> — nothing is fetched until you approve it, the approval is never remembered, and the lookup only reaches public addresses — never your internal network.",
   "<b>Affected products, counted for you<\/b> — each product and version range from the lookup — with CISA KEV, CVSS and the fixed versions — is counted in your inventory in one pass; one click searches it.",
   "<b>Versions compared properly<\/b> — 2.4.9 &lt; 2.4.10, 1.0.2k &lt; 1.0.2u, 2.0-rc1 &lt; 2.0, epochs ignored — the same way for every product.",
   "<b>CSV and email<\/b> — export every install in the search (up to 50,000) or send it through Gabriel; each asset opens in Argos."]},
 ex_tags:{does:"Basset lists every tag in navi.db — one row per category : value with its asset count — searchable by category or value. Click a tag to see exactly which assets carry it, each linking to Argos and to the asset in Tenable.",caps:[
   "<b>Every tag<\/b> — one row per category : value, with its asset count and when it was first and last applied.",
   "<b>Search<\/b> — by category or value.",
   "<b>Who carries it<\/b> — every asset carrying the tag — host, IP, OS, ACR, AES, when it was tagged, and a Tenable link.",
   "<b>Deep-dive<\/b> — every host opens Argos.",
   "<b>Email the result<\/b> — send the list through Gabriel."]},
 ex_vulns:{does:"Hellhound searches every finding in navi.db, one row each, by plugin name or ID, CVE, severity or finding ID, and shows each finding with its asset and VPR. A finding ID opens it in Tenable, the asset opens Argos, and a fix can be handed to Amarok.",caps:[
   "<b>Search by anything<\/b> — plugin name, plugin ID, CVE, severity or finding ID.",
   "<b>Findings in context<\/b> — asset, severity and VPR on every row.",
   "<b>Open in Tenable<\/b> — a finding ID opens that finding in Tenable.",
   "<b>Deep-dive and fix<\/b> — the asset opens Argos; Remediate hands the plugin and host to Amarok, pre-filled, never auto-run.",
   "<b>Email the result<\/b> — send the rows to an owner through Gabriel."]},
 exproute:{does:"Atlas maps every application route and filesystem path to an owner, in plain English — \"give the payment routes to VM Team, put /opt under Networking, ignore the ICMP route\" — and tags every asset on a matched route or path Owner : &lt;route or path&gt;: &lt;owner&gt;. He measures coverage honestly: an asset is closed only when every route it sits on has an owner.",caps:[
   "<b>Owners in plain English<\/b> — describe the mapping; Atlas resolves each owner against your Tenable users and groups and previews it before tagging.",
   "<b>Owners from Tenable<\/b> — users, user groups and agent groups pulled live through navi (the Tenable MCP as a backup), cached so the page stays fast.",
   "<b>Tags on the right assets<\/b> — Owner tags on every asset on a matched route or with a matched path, never removing anything.",
   "<b>Decisions, not just owners<\/b> — mark a route ignored, accepted or mitigated, and the coverage counts it as handled.",
   "<b>Coverage you can defend<\/b> — routes owned, partial or unowned; paths owned; assets fully closed; ownerless risk by VPR.",
   "<b>Ownership Sankey and map<\/b> — routes and paths flowing to their owners, the gaps, and each owner's load; drill into any new path."]},
 fused_score:{does:"Nemesis gives every asset one 0–100 Exposure Score built from 16 signals — exploitability (KEV and EPSS), Tenable AES and VPR, ACR, attack paths, identity, compliance, web-app findings, EOL, internet exposure, AI risk, weak or expiring crypto, SLA aging, finding volume, ownership and ATT&amp;CK — then shows what to act on now, the worst asset from each hound, and where their signals converge.",caps:[
   "<b>16 signals, one number<\/b> — weights sum to 100, so a score reads as the share of the most danger one asset can carry; dispositions discount it, and Chronos's coverage flags how far to trust it.",
   "<b>Your weighting<\/b> — drag any weight to re-rank the estate to what matters to you; each weighting is cached separately.",
   "<b>Your assets, or the whole estate<\/b> — score one tag's assets — an owner, a business tier, an environment — and every count, band, act-now set and leaderboard re-builds over just them, with each asset's score unchanged. Tag views keep their own cache, so you switch between a tag and the whole estate without rebuilding either.",
   "<b>Act now<\/b> — the assets over 80, 60 or 40 today, with one-click hand-offs: tag Priority, tag owners (Terminus), email owners (Gabriel), raise ACR (Anubis) or add to the Contract.",
   "<b>Worst from each hound<\/b> — the top asset each hound's signal points at — and the assets where several converge.",
   "<b>Explained<\/b> — every asset's score broken down by factor, and how widespread each signal is across the estate.",
   "<b>Priority tags<\/b> — Priority : P1 to P4 on the act-now set, recomputed on the server from navi.db — not taken from the browser."]},
 identity:{does:"Janus builds an inventory of the accounts Tenable found on your hosts and classifies each as human, service / non-human (NHI) or machine. He flags privileged and non-expiring accounts, the same account on many hosts, SSH password logins and default credentials, ranks identities sitting on KEV, critical or crown-jewel hosts, and shows the hosts he can't see into because the scan had no credentials.",caps:[
   "<b>Identities from the scan<\/b> — local-user enumeration plugins (Linux user list, SMB local users and more) parsed into accounts, each with the hosts it lives on.",
   "<b>Classified<\/b> — human, service / NHI or machine — from well-known Windows SIDs, AD machine accounts ($), Linux UID conventions and known service names.",
   "<b>Risk flags<\/b> — privileged, non-expiring passwords, account reuse across five or more hosts, SSH password auth, default credentials, on a KEV, critical or crown-jewel host.",
   "<b>Honest about reuse<\/b> — the same account name on many hosts is reported as account reuse — never claimed as a shared password.",
   "<b>Coverage<\/b> — credentialed vs blind hosts by the pack's single credentialed rule, and the scan credentials themselves.",
   "<b>Tags that route the work<\/b> — Identity / NHI / Machine ID : &lt;account&gt; on its hosts, Identity Risk : Account Reuse, Identity Coverage : No Credentials, Owner : &lt;name&gt;; an AI model can propose more."]},
 insights:{does:"Sphinx reads what the whole pack found on its last release and puts it on one page, On the Scent: how exposed the estate is, where risk concentrates, what is converging, what is on the clock, the blind spots, and the next moves — including a recommended play and how much exposure it would remove. Every number opens the exact assets behind it.",caps:[
   "<b>At a glance, actionable<\/b> — every card opens its evidence: the exact assets (KEV, score ≥ 60, crown jewels, with KEV or blind, EOL, quantum-vulnerable …) or the owning hound, already filtered.",
   "<b>Coverage funnel<\/b> — all assets → seen by a hound → credentialed → classified → owned → business-tiered, each step linked to the hound that owns the gap.",
   "<b>Dark matter<\/b> — assets no hound saw, blind hosts, unclassified, unowned, no business tier, shadow AI.",
   "<b>Who's barking<\/b> — the worst assets by fused score, with each hound's points on each host; the estate as one square per asset.",
   "<b>Converging signals<\/b> — signal stacks, the overlap map and cross-hound surprises — where several hounds fire on the same assets.",
   "<b>Recommended play<\/b> — patch KEV / critical, replace EOL, renew certificates, segment exposure or assign owners — with the exposure it would remove and the signals it neutralizes.",
   "<b>What changed<\/b> — the digest of what moved since the last release."]},
 iot_squad:{does:"Cerberus is four cooperating agents. One confirms known devices from a detection registry; one finds the plugins on each confirmed host that carry the device's name; one sweeps those plugins across the estate and proposes new detections; one runs the loop and keeps a ledger of everything tested. You approve at two gates: tagging devices, and adding detections to the registry.",caps:[
   "<b>Registry detections<\/b> — known devices matched by plugin, plugin name or output — the registry grows as you approve new detections.",
   "<b>Signal fusion<\/b> — device type, network-card vendor (OUI), local-network service announcements (mDNS) and certificates find devices the registry doesn't know yet.",
   "<b>Carrier-plugin harvest<\/b> — host by host, the plugins whose name or output carries the device term.",
   "<b>Learning loop<\/b> — a device term found in a carrier plugin on enough assets (at least 2, rising with the size of the estate) becomes a proposed detection — confirm, cross-reference or new.",
   "<b>Exposure on devices<\/b> — critical, high and KEV findings and AES for each device.",
   "<b>Coverage you can trust<\/b> — a QA ledger of every plugin-term combination tested, and which of the seven identity signals your scans collect.",
   "<b>Two human gates<\/b> — Gate 1 tags devices Asset Inventory : &lt;facet&gt;: &lt;device&gt;; Gate 2 adds approved detections to the registry, exportable."]},
 mcpcmp:{does:"The Pointer is a routing matrix: for each job — lookups, tagging small or at scale, OS / app / device tagging, ACR and AES, exports, SQL, scans, agents, policies, WAS, dashboards — which tool does it best, which can do it, and why. It lists the limits that force a hand-off and shows a navi-side snapshot to check what navi is pointed at.",caps:[
   "<b>Capability and routing matrix<\/b> — 15 common jobs, each routed to navi, the Tenable MCP, or either — with the reason.",
   "<b>Limits that force a hand-off<\/b> — rule-based tags cap at about 1,024 IPs / 1,999 UUIDs; OS, app and device tagging needs plugin-output fingerprinting; only navi writes ACR; native dashboards are Tenable-only.",
   "<b>When they disagree<\/b> — suspect a stale navi.db first; different tenants are the rare case; navi can tell you which key and container it holds.",
   "<b>navi-side snapshot<\/b> — the tag categories, asset count and freshness navi sees right now."]},
 mitre:{does:"Orthrus fetches the public ATT&amp;CK-to-CVE mapping from MITRE's Center for Threat-Informed Defense, matches it to the CVEs in your findings, and shows the techniques and tactics your unpatched estate enables on an ATT&amp;CK matrix. He tags the affected assets with each CVE's primary impact, secondary impact and exploit technique.",caps:[
   "<b>Public mapping, approved download<\/b> — the Center for Threat-Informed Defense ATT&amp;CK→CVE mapping, fetched after you approve it (or auto-approve in Settings), with a bundled snapshot offline.",
   "<b>Only what's in your estate<\/b> — by default only CVEs present in navi.db, so every tag lands on real assets.",
   "<b>ATT&amp;CK matrix<\/b> — techniques and tactics your findings enable, by mapping type; full screen and email from the widget.",
   "<b>Mitre tags<\/b> — Mitre : Primary Impact: &lt;technique&gt;, Secondary Impact: &lt;technique&gt; and Exploit Technique: &lt;technique&gt; on the assets carrying each CVE, via navi's tag-by-CVE.",
   "<b>Honest coverage<\/b> — not every CVE has a mapped technique; an unmapped CVE simply gets no Mitre tag."]},
 postquantum:{does:"Heimdall finds the quantum-vulnerable surface three ways — certificates (RSA, ECC and DSA are all vulnerable to Shor's algorithm, whatever the key length), on-the-wire transport crypto from TLS and SSH plugins, and Tenable's Post-Quantum Cipher Analysis plugins — scores crypto agility from OpenSSH and OpenSSL versions, and ranks a migration roadmap by ACR and CISA KEV against the CNSA 2.0 deadlines.",caps:[
   "<b>Certificate quantum risk<\/b> — every certificate by algorithm family, with how many are still valid at each CNSA 2.0 / NIST milestone and the long-lived harvest-now set.",
   "<b>Transport crypto<\/b> — TLS and SSH key exchange without ML-KEM or a hybrid group, SHA-1 MACs and deprecated protocol versions.",
   "<b>Tenable's PQC plugins<\/b> — services not using post-quantum ciphers, the target cipher inventory, and services already using them.",
   "<b>Crypto-agility tiers<\/b> — each host PQC-ready, Upgradable or Legacy from its OpenSSH / OpenSSL versions.",
   "<b>Migration roadmap<\/b> — assets ranked by crypto risk weighted by ACR and KEV, crown jewels first; export to CSV.",
   "<b>Tags that route the migration<\/b> — Post-Quantum : Cipher Analysis on the quantum-vulnerable set, plus PQC Risk, Transport, Priority, Harvest-Now and Agility tags from the roadmap."]},
 scan_eval:{does:"Chronos reads Tenable's scan-information and credential-status plugins to show which assets were scanned with a working login, which were blind and why, how fresh each scan is, which crown jewels sit in a blind spot, and how scanners, policies and scans perform. Every set can be tagged so the fix gets routed.",caps:[
   "<b>One credentialed rule<\/b> — credentialed = the scan-information plugin reports credentialed checks, or a valid-credentials plugin is present; blind = scanned without credentials. Every hound in the pack uses this rule.",
   "<b>Why a host is blind<\/b> — credential failed, insufficient privilege, intermittent, or no credentials at all — and credentialed hosts that still have a credential issue.",
   "<b>Freshness<\/b> — scanned in the last 7 days, 8–30, 31–90, over 90, never, or date unknown; network vs agent scans.",
   "<b>Crown-jewel blind spots<\/b> — crown jewels (ACR ≥ 7) that are uncredentialed or failed, or not scanned in over 90 days.",
   "<b>Performance and scanners<\/b> — average scan time, slow scans, slow scanners, policies and scans; scanner load; scanners on an old plugin feed; safe-checks scans.",
   "<b>Scan Health tags<\/b> — Cred Failure, Insufficient Privilege, Intermittent Auth, Uncredentialed, Patch Assessment Failed, Stale Scan 30d+ / 90d+, Never Scanned, Slow Scan, Crown Jewel Blind Spot, and by scanner, policy or scan."]},
 sla:{does:"Sköll measures adherence three ways: navi's own Pass / Fail SLA verdict, open findings aged against your per-severity SLA days, and fixed findings — were they fixed in time, and how long did it take. Every view can be segmented by any tag (Owner by default), and a daily snapshot builds the trend.",caps:[
   "<b>Three lenses<\/b> — navi's verdict (after <span class='mono'>navi config sla calculate<\/span>), open-finding aging (needs only your SLA days), and remediation of fixed findings.",
   "<b>Segment by anything<\/b> — Owner by default, or any tag category and value.",
   "<b>Where the breaches are<\/b> — open breaches by owner or tag, by severity, and the worst assets by open breaches.",
   "<b>Breach outlook<\/b> — open findings due within 7, 14 and 30 days, and already past SLA, by severity — before they breach.",
   "<b>Monthly trend charts<\/b> — adherence, backlog, new vs fixed, breaches opened, days to fix — each its own widget, full screen on demand.",
   "<b>Daily history<\/b> — an unscoped run records the day's point, so trends build without extra work.",
   "<b>Email the dashboard<\/b> — send it to the people who need it through Gabriel."]},
 software:{does:"Mimir reconciles the software and CPE inventories into one product list, shows version sprawl, the most-deployed and the single-install products, checks versions against endoflife.date, flags the software that makes a host a crown jewel, and ranks a risk leaderboard by the KEV and critical exposure on the hosts that run each product.",caps:[
   "<b>One product list, two sources<\/b> — software and CPE inventories reconciled, each product badged with the source that saw it, and a delta view of what one source missed.",
   "<b>Sprawl, common, single-install<\/b> — the product on fourteen versions, the package on half the estate, the one-off install nobody owns.",
   "<b>Lifecycle check<\/b> — products matched to endoflife.date (on demand, cached) — assets on end-of-life or behind-latest versions.",
   "<b>Crown-jewel software<\/b> — domain controllers, certificate authorities, databases, hypervisors, backup, security tooling, remote access — each role with a suggested ACR.",
   "<b>Risk leaderboard<\/b> — products ranked by KEV, critical findings and VPR on their hosts and in their own plugins; full screen and email from the widget.",
   "<b>Ask in plain English<\/b> — a question becomes one read-only SQL query over software, assets and findings that you review before it runs.",
   "<b>Software tags<\/b> — Software : &lt;product&gt; (or a version, EOL set or crown role) — the server rebuilds the exact assets from navi.db."]},
 tagremoval:{does:"Garmr lists every tag navi can remove — the tags in navi.db with the number of assets carrying each — and removes the ones you choose through the same background queue every hound uses. He also explains why some tags in Tenable are out of navi's reach, and can hand your choices to the Contract to clear at the start of every cycle before re-tagging.",caps:[
   "<b>Only what navi can remove<\/b> — the tags navi.db knows about, with asset counts — a tag that exists only in Tenable is shown separately, never offered.",
   "<b>Tags navi can't reach<\/b> — navi.db assets compared with Tenable's licensed and stale assets.",
   "<b>Deliberate removal<\/b> — pick the tags, confirm, and each is queued as a removal — marked as a removal in the Tagging log.",
   "<b>The pack's only remover<\/b> — every other hound only adds tags; removal lives here and in the Contract's removal phase.",
   "<b>Hand-off to the Contract<\/b> — the Contract removes your chosen tags first, pauses (30 minutes by default) for Tenable, runs navi update, then re-tags — without deleting the tags themselves."]},
 was:{does:"Arachne turns navi's WAS data into two dashboards: an overview of every web app — findings by severity, the OWASP Top 10 summed across apps, the technology inventory, scan coverage and apps ranked by risk — and a per-app report. Every bar, category and chip opens the matching apps in Beagle, and cohorts can be tagged on each app's Tenable asset.",caps:[
   "<b>WAS overview<\/b> — severity totals, OWASP Top 10 profile, technology inventory, crawl depth and recency, apps ranked by risk.",
   "<b>Per-app report<\/b> — one app's severity, OWASP profile, tech stack and findings, with each plugin's raw stored output.",
   "<b>Click through to the apps<\/b> — every metric, bar and chip opens Beagle filtered to that group (a severity, an OWASP category, a technology, stale scans).",
   "<b>WAS tags<\/b> — WAS OWASP : &lt;category&gt;, WAS Severity : &lt;level&gt; and WAS Technology : &lt;tech&gt; on each matching app's Tenable asset."]},
 was_asset:{does:"Point Beagle at a web app and it lays out the terrain from navi's WAS info plugins — sitemap, scan telemetry, target facts, screenshot, external URLs, cookies and allowed methods — plus the app's other informational and security findings. Every plugin opens its raw stored output, proof and request / response headers.",caps:[
   "<b>Recon at a glance<\/b> — sitemap, scan telemetry, target facts, screenshot, external URLs, cookies and allowed methods from WAS info plugins.",
   "<b>Raw output on demand<\/b> — each plugin's stored output, proof and request / response headers.",
   "<b>Security findings too<\/b> — the app's non-informational findings, alongside the other info plugins.",
   "<b>Opened from Arachne<\/b> — a dashboard link (a severity, an OWASP category, a technology, stale scans) narrows the app list to that group.",
   "<b>Pick any app<\/b> — by app or asset UUID, or the riskiest app by default."]},
 advanced:{does:"The power-user search — write natural language or SQL that ranges across every navi.db table at once, joining and filtering the whole estate.",caps:[
   "Cross-table NL→SQL with joins over assets, vulns, routes and paths.",
   "For the questions the single-lens search hounds can't answer alone."]},
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
  opts=opts||{}; const mode=opts.mode==='dashboard'?'dashboard':opts.mode==='widget'?'widget':'data';
  if(!container)return null; _hmailStyle();
  const EM=agentApi('email');
  const btn=document.createElement('button'); btn.className='btn ghost sm hmbtn';
  btn.textContent=opts.label||(mode==='dashboard'?'\ud83d\udce7 Email dashboard':'\ud83d\udce7');
  btn.title=mode==='dashboard'?'Email the whole dashboard via Gabriel (gated)':mode==='widget'?"Email this widget via Gabriel — the picture (attached) and the list (gated)":"Email this widget's data via Gabriel (gated)";
  const row=document.createElement('div'); row.className='hmrow';
  row.innerHTML='<input type="email" placeholder="recipient@company.com"><button class="btn run sm">\u25b6 Send</button><button class="btn ghost sm">\u2715</button><span class="res sub"></span>';
  container.appendChild(btn); container.appendChild(row);
  if(mode==='dashboard') _gearLast();            // the ⚙ settings gear stays right of "Email dashboard"
  const inp=row.querySelector('input'), send=row.querySelectorAll('button')[0], cancel=row.querySelectorAll('button')[1], res=row.querySelector('.res');
  btn.onclick=()=>{ const show=row.style.display!=='flex'; row.style.display=show?'flex':'none'; if(show){ inp.value=inp.value||_hmailTo(); inp.focus(); } };
  cancel.onclick=()=>{ row.style.display='none'; res.innerHTML=''; };
  const go=async()=>{
    const to=(inp.value||'').trim(); if(!to){ res.innerHTML='<span style="color:var(--crit)">enter a recipient</span>'; return; }
    if(mode==='widget') res.innerHTML='<span class="spin"></span> rendering the widget\u2026';
    let payload=null; try{ payload=await getPayload(); }catch(e){ payload=null; }
    if(mode==='widget') res.innerHTML='';
    const empty=!payload||(mode==='dashboard'?!(payload.components&&payload.components.length)
      :mode==='widget'?!((payload.rows&&payload.rows.length)||payload.png||payload.html):!(payload.rows&&payload.rows.length));
    if(empty){ res.innerHTML='<span style="color:var(--crit)">no data on this '+(mode==='dashboard'?'dashboard':'widget')+' yet \u2014 run the agent first</span>'; return; }
    if(!confirm('Email '+(mode==='dashboard'?'this dashboard ('+payload.components.length+' component(s))'
        :mode==='widget'?'this widget \u2014 the picture ('+(payload.png?'PNG':'HTML')+' attached) and the list ('+(payload.rows||[]).length+' row(s))'
        :'this widget ('+payload.rows.length+' row(s))')+' to '+to+'? This is a real send.')) return;
    if(mode!=='dashboard'&&!payload.columns&&payload.rows&&payload.rows[0]&&typeof payload.rows[0]==='object') payload.columns=Object.keys(payload.rows[0]);
    _hmailTo(to);
    send.disabled=true; res.innerHTML='<span class="spin"></span> sending\u2026';
    let o; try{ o=await EM.post(mode, Object.assign({}, payload, {to:to, confirm:true})); }catch(e){ o={ok:false,error:e.message}; }
    send.disabled=false;
    if(o&&o.ok){ res.innerHTML='<span style="color:var(--ok)">\u2713 sent to '+esc(to)+(mode==='widget'?(' \u2014 '+esc(o.attached||'picture')+' attached \u00b7 '+(o.rows_inline||0)+' row(s) inline'):mode==='data'?(' \u2014 '+(o.mode==='attachment'?('CSV attached ('+esc(o.attached||'data.csv')+')'):((o.rows||payload.rows.length)+' row(s) inline'))):(' \u2014 '+(o.components||payload.components.length)+' component(s)'))+'</span>'; }
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
/* ===== Widget tools (build 462): ⛶ full screen + 📧 email (picture + list) for a chart widget =====
   hWidget(section, {title, visual:()=>Element, rows:()=>[{…}], columns:[…], note, grow:'#sel', onResize})
   adds two small buttons to the widget's top-right corner:
     ⛶  full screen (Fullscreen API; an in-page overlay where the browser has none, e.g. iPhone).
        `grow` names an element whose height should fill the screen (the attack map's svg); the
        page's onResize() is called after entering / leaving so a chart can re-fit.
     📧  Gabriel: the widget's picture as an attachment (PNG, rendered in the browser; a
        self-contained HTML snapshot where the browser can't rasterise it) + its list inline in
        the email body (a CSV rides along when it is long). Gated like every send.
   hSnapshot(el) → Promise<{png|null, html}> renders an element (HTML or SVG) with its computed
   styles inlined, so the picture matches the page in the current theme. */
const _SVG_PROPS=['fill','fill-opacity','stroke','stroke-width','stroke-opacity','stroke-dasharray','stroke-linecap','opacity','font-family','font-size','font-weight','font-style','text-anchor','dominant-baseline','letter-spacing','visibility','display','color','marker-end','marker-start'];
function _inlineStyles(src, dst){
  const cs=getComputedStyle(src);
  if(src instanceof SVGElement){ _SVG_PROPS.forEach(k=>{ const v=cs.getPropertyValue(k); if(v) dst.style.setProperty(k, v); }); }
  else { for(let i=0;i<cs.length;i++){ const k=cs[i]; if(k.startsWith('transition')||k.startsWith('animation')) continue; dst.style.setProperty(k, cs.getPropertyValue(k)); } }
  const a=src.children, b=dst.children;
  for(let i=0;i<a.length && i<b.length;i++) _inlineStyles(a[i], b[i]);
}
function hSnapshot(el, opts){
  opts=opts||{};
  return new Promise(resolve=>{
    try{
      if(!el){ resolve({png:null, html:''}); return; }
      const w=Math.ceil(Math.max(el.scrollWidth, el.getBoundingClientRect().width)), h=Math.ceil(Math.max(el.scrollHeight, el.getBoundingClientRect().height));
      const clone=el.cloneNode(true); _inlineStyles(el, clone);
      clone.style.width=w+'px'; clone.style.height=h+'px'; clone.style.maxWidth='none'; clone.style.maxHeight='none'; clone.style.overflow='visible'; clone.style.margin='0';
      clone.querySelectorAll('[id]').forEach(n=>n.removeAttribute('id')); clone.removeAttribute('id');
      const bg=getComputedStyle(document.body).backgroundColor||'#ffffff';
      const xml=new XMLSerializer().serializeToString(clone);
      const html='<!DOCTYPE html><html><head><meta charset="utf-8"><title>'+esc(opts.title||'widget')+'</title></head>'
        +'<body style="margin:0;padding:20px;background:'+bg+';font-family:system-ui,Segoe UI,Arial,sans-serif">'
        +(opts.title?'<div style="font-weight:800;font-size:18px;margin:0 0 4px;color:'+getComputedStyle(document.body).color+'">'+esc(opts.title)+'</div>':'')
        +'<div style="font-size:12px;opacity:.7;margin:0 0 14px;color:'+getComputedStyle(document.body).color+'">The Hounds · '+esc(document.title||'')+' · '+esc(new Date().toLocaleString())+'</div>'
        +'<div style="overflow:auto">'+xml+'</div></body></html>';
      const svg='<svg xmlns="http://www.w3.org/2000/svg" width="'+w+'" height="'+h+'"><foreignObject x="0" y="0" width="100%" height="100%">'
        +'<div xmlns="http://www.w3.org/1999/xhtml">'+xml+'</div></foreignObject></svg>';
      const img=new Image();
      img.onload=()=>{ try{
          const sc=Math.min(2, 4000/Math.max(w,1), 6000/Math.max(h,1)), c=document.createElement('canvas');
          c.width=Math.max(1,Math.round(w*sc)); c.height=Math.max(1,Math.round(h*sc));
          const ctx=c.getContext('2d'); ctx.fillStyle=bg; ctx.fillRect(0,0,c.width,c.height); ctx.setTransform(sc,0,0,sc,0,0); ctx.drawImage(img,0,0);
          resolve({png:c.toDataURL('image/png'), html}); }        // Safari taints foreignObject canvases → HTML only
        catch(e){ resolve({png:null, html}); } };
      img.onerror=()=>resolve({png:null, html});
      img.src='data:image/svg+xml;charset=utf-8,'+encodeURIComponent(svg);
    }catch(e){ resolve({png:null, html:''}); }
  });
}
function _hwStyle(){ if(document.getElementById('hwStyle')) return;
  const st=document.createElement('style'); st.id='hwStyle';
  st.textContent='.hw-acts{float:right;display:flex;gap:6px;align-items:flex-start;flex-wrap:wrap;justify-content:flex-end;margin:0 0 6px 10px;max-width:100%;position:relative;z-index:2}'
   +'.hw-acts .hmrow{flex-basis:100%;justify-content:flex-end}'
   +'section.hw-full:fullscreen,section.hw-fs{background:var(--bg,#0b0f17);overflow:auto;padding:24px;margin:0;border-radius:0;max-width:none;width:100%;box-sizing:border-box}'
   +'section.hw-fs{position:fixed;inset:0;z-index:9000}'
   +'section.hw-full:fullscreen::backdrop{background:var(--bg,#0b0f17)}'
   +'@media (max-width:560px){.hw-acts{float:none;justify-content:flex-start;margin:0 0 6px}}';
  document.head.appendChild(st); }
function hFull(section, opts){
  opts=opts||{}; _hwStyle();
  const b=document.createElement('button'); b.type='button'; b.className='btn ghost sm hwfs'; b.textContent='⛶'; b.title='Full screen (Esc to leave)'; b.setAttribute('aria-label','Full screen');
  let saved=null;
  const grow=on=>{ const g=opts.grow&&section.querySelector(opts.grow); if(!g) return;
    if(on){ saved=g.style.height; g.style.height='calc(100vh - '+(opts.growOffset||200)+'px)'; } else { g.style.height=saved||''; } };
  const after=on=>{ section.classList.toggle('hw-on',on); b.textContent=on?'✕':'⛶'; b.title=on?'Leave full screen':'Full screen (Esc to leave)'; grow(on);
    setTimeout(()=>{ try{ window.dispatchEvent(new Event('resize')); }catch(e){} if(opts.onResize) try{ opts.onResize(on); }catch(e){} }, 60); };
  section.classList.add('hw-full');
  document.addEventListener('fullscreenchange', ()=>after(document.fullscreenElement===section));
  document.addEventListener('keydown', e=>{ if(e.key==='Escape' && section.classList.contains('hw-fs')){ section.classList.remove('hw-fs'); after(false); } });
  b.onclick=()=>{
    if(document.fullscreenElement===section){ document.exitFullscreen(); return; }
    if(section.classList.contains('hw-fs')){ section.classList.remove('hw-fs'); after(false); return; }
    if(section.requestFullscreen && document.fullscreenEnabled!==false){ section.requestFullscreen().catch(()=>{ section.classList.add('hw-fs'); after(true); }); }
    else { section.classList.add('hw-fs'); after(true); }
  };
  return b;
}
function hWidget(section, opts){
  if(typeof section==='string') section=document.getElementById(section);
  if(!section || section.querySelector(':scope > .hw-acts')) return;
  opts=opts||{}; _hwStyle(); _hmailStyle();
  const box=document.createElement('div'); box.className='hw-acts';
  box.appendChild(hFull(section, opts));
  section.insertBefore(box, section.firstChild);
  hMail(box, async()=>{
    const rows=(opts.rows?opts.rows():[])||[];
    const el=opts.visual?opts.visual():null;
    const snap=el?await hSnapshot(el,{title:opts.title}):{png:null,html:''};
    return {title:opts.title||document.title, note:(typeof opts.note==='function'?opts.note():opts.note)||'',
            columns:opts.columns||null, rows, png:snap.png, html:snap.png?'':snap.html};
  }, {mode:'widget', label:'📧'});
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
      if(t.closest('section.hw-full'))return;          // a hWidget section emails picture + list itself
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
  ['🔎 Compliance','/agents/ex_compliance/page.html'],
  ['🔎 Software','/agents/ex_software/page.html'],
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
  mountSettingsGear();                           // innerHTML above wiped it — put it back, last
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
               crit:['rgba(251,113,133,.12)','var(--crit)'],
               idle:['var(--panel-2)','var(--ink-2,var(--mut))']};   // "nothing loaded yet — click ▶ Load"
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
/* build 485 (sec R3): a hand-off carries single hosts only — an `ip` with a CIDR, whitespace or a comma could
   widen the set on the C2 page, so it is dropped here (and again on the C2 page) and counted as `ignored`. */
function _c2Single(s){ s=String(s==null?'':s); if(!s||s!==s.trim()||s.charAt(0)==='-'||/[\s,\/;'"`$&|<>(){}\[\]\\*?!#=~^%]/.test(s)) return false;
  return s.indexOf(':')>=0 ? /^[0-9a-fA-F:.]+$/.test(s)
    : /^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*\.?$/.test(s); }
function c2Handoff(req){
  const r=req||{}; const intent=['validate_path','diagnose','remediate'].includes(r.intent)?r.intent:'diagnose';
  const all=(Array.isArray(r.targets)?r.targets:[]).filter(x=>x&&x.ip).slice(0,256);
  const t=all.filter(x=>_c2Single(String(x.ip).trim()))
    .map(x=>({ip:String(x.ip).trim(),uuid:String(x.uuid||''),hostname:String(x.hostname||'')}));
  const out={intent, targets:t, ignored:all.length-t.length, source:String(r.source||document.title||'another hound').slice(0,60)};
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
