/* Navi Agents — shared front-end helpers used by the hub and every agent page. */

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
const esc = s => String(s==null?'':s).replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));

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
/* Deep-scan a run/tag response for asset UUIDs, plugin (finding) IDs, and a tag
   category:value, then registerFindings() so any agent gets the Gabriel hand-off for free.
   Named the email agent's own calls are ignored. */
const _UUID_RE=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
function _harvestFindings(agentId, action, resp, reqBody){
  if(agentId==='email' || !resp || typeof resp!=='object') return;
  if(/^(status|recipients|preview|send|meta|health|schema)$/.test(action||'')) return;
  const uu=new Set(), fids=new Set(); let tag=null;
  (function walk(o,depth){
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
  })(resp,0);
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
 certificate:{name:'Certania Hound',lore:'Coined from <b>“certificate”</b> + the loyal hound. It stands watch over the chain of trust, sniffing out certificates about to expire.'},
 iot_squad:{name:'Cerberus Hound',lore:'<b>Cerberus</b>, the many-headed dog guarding the underworld’s gate. The IoT squad is a pack guarding the network edge — the unknown devices at the gate.'},
 acr:{name:'Anubis Hound',lore:'<b>Anubis</b>, who weighs the heart against the feather of truth. ACR calibration weighs each asset’s <i>true</i> criticality.'},
 customapp:{name:'Argus Hound',lore:'<b>Argus Panoptes</b>, the giant with a hundred ever-open eyes. It sees the custom apps your inventory misses.'},
 mitre:{name:'Orthrus Hound',lore:'<b>Orthrus</b>, the two-headed dog and brother of Cerberus. It links two worlds — mapping CVEs to adversary ATT&CK techniques.'},
 eol:{name:'Charon Hound',lore:'<b>Charon</b>, the ferryman across the Styx. It ferries end-of-life and unsupported software to its reckoning.'},
 dashboard:{name:'Daedalus Hound',lore:'<b>Daedalus</b>, the master craftsman who built the Labyrinth. The dashboard builder crafts a custom view from one plain-English request.'},
 ai:{name:'Pythia Hound',lore:'<b>Pythia</b>, the Oracle of Delphi. It finds the oracles in your estate — the AI/ML software and model hosts.'},
 identity:{name:'Janus Hound',lore:'<b>Janus</b>, the two-faced god of doorways. Identity guards the doorways — accounts human and non-human, two faces each.'},
 scan_eval:{name:'Chronos Hound',lore:'<b>Chronos</b>, the embodiment of time. Scan Evaluations measures where your scans spend their time.'},
 insights:{name:'Sphinx Hound',lore:'<b>The Sphinx</b>, who guarded Thebes with riddles. “Unknown Unknowns” poses the gaps in your coverage back to you.'},
 exproute:{name:'Atlas Hound',lore:'<b>Atlas</b>, the Titan who gave his name to the <i>atlas</i> — the book of maps. It maps exposure routes and paths to their owners.'},
 software:{name:'Mimir Hound',lore:'<b>Mimir</b>, the Norse keeper of the well of wisdom. It remembers every software version in the estate and shows you the sprawl.'},
 tagremoval:{name:'Garmr Hound',lore:'<b>Garmr</b>, the blood-stained hound at the gates of Hel who howls at Ragnarök — the world’s cleansing. The tag-removal agent unmakes tags, clearing what no longer belongs before the pack re-tags.'},
 agentgroup:{name:'Sirius Hound',lore:'<b>Sirius</b>, the Dog Star — brightest in the sky, that marshals the lesser stars. It musters every Tenable agent into its group and tags it <span class="mono">Agent Group:&lt;name&gt;</span>.'},
 contract:{name:'Covenant Hound',lore:'A <b>covenant</b> is a binding promise. It captures your tagging &amp; ACR policy once, then keeps it — planning first, executing only when armed, looping every few hours.'},
 cisakev:{name:'Laelaps Hound',lore:'<b>Laelaps</b>, the hound fated to always catch its quarry. It hunts down every <b>Known Exploited Vulnerability</b> — already proven caught in the wild — and tags it <span class="mono">CISA KEV:&lt;date&gt;</span>.'},
 postquantum:{name:'Heimdall Hound',lore:'<b>Heimdall</b>, the ever-watchful guardian who sees to the ends of the world and hears the grass grow. It watches the <b>quantum horizon</b> — flagging the RSA/ECC crypto that won’t survive it.'},
 attackpath:{name:'Fenrir Hound',lore:'<b>Fenrir</b>, the great wolf the gods chained until, at Ragnarök, he breaks free and runs down his prey. The attack-path agent traces how a breach slips its chains — <b>foothold → lateral move → crown jewel</b>.'},
 ex_assets:{name:'Bloodhound',lore:'The <b>Bloodhound</b> — finest tracker of the pack. The asset explorer tracks any host across navi.db.'},
 ex_vulns:{name:'Hellhound',lore:'The <b>Hellhound</b> — a beast that hunts in the dark. The vulnerability explorer hunts findings by plugin, CVE, severity, VPR.'},
 ex_plugins:{name:'Foxhound',lore:'The <b>Foxhound</b> — bred to flush quarry from cover. The plugin explorer flushes out every distinct plugin.'},
 ex_routes:{name:'Wolfhound',lore:'The <b>Wolfhound</b> — large enough to run down a wolf. The route explorer runs down application routes.'},
 ex_paths:{name:'Greyhound',lore:'The <b>Greyhound</b> — fastest of the hounds. The path explorer sprints through filesystem paths.'},
 argos:{name:'Argos Hound',lore:'<b>Argos</b>, Odysseus’s faithful hound — the only one who knew his master’s true identity after twenty years. Give it one UUID or IP and it recognizes that asset across every table, telling its whole story.'},
 advanced:{name:'Deerhound',lore:'The <b>Deerhound</b> — a great sighthound bred to run down big game over vast open ground. The advanced search ranges across every table at once, joining and filtering the whole estate.'},
 email:{name:'Gabriel Hound',lore:'<b>Gabriel</b>, the messenger — the one who carries the word to those who need it. The email agent closes the loop: it takes what the pack found and delivers it to the humans who own it, with deep-links back into Tenable.'},
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
const _DD_SKIP = new Set(['ex_assets','ex_vulns','ex_plugins','ex_routes','ex_paths','postquantum','attackpath',
  'advsearch','advanced','explore','dash','dashboard','mcpcmp','customdash','tags','tagdetail','taglog','tags-log','asset','vuln']);  /* search / explorer / generic tools — no hound origin story */
function deepDive(id){ if(_DD_SKIP.has(id)) return null; return (typeof DEEP_DIVE!=='undefined') && (DEEP_DIVE[id] || DEEP_DIVE._fallback) || null; }
function deepDiveChips(id){
  const d = deepDive(id); if(!d) return '';
  let h='';
  if(d.year) h+='<span class="sub" style="font-size:11px;color:var(--ink-3);align-self:center;white-space:nowrap">📖 Origin story · '+d.year+'</span>';
  if(d.article&&d.article.url) h+='<a class="btn ghost sm" href="'+d.article.url+'" target="_blank" rel="noopener" title="'+esc(d.article.title||'Read the origin article')+'">Deep dive ↗</a>';
  if(d.code&&d.code.url) h+='<a class="btn ghost sm" href="'+d.code.url+'" target="_blank" rel="noopener" title="'+esc(d.code.label||'Source code')+'">‹ › Code</a>';
  return h;
}
/* just the origin-story date + article link (shown under the agent name on cards) */
function deepDiveMeta(id){ const d=deepDive(id); if(!d) return '';
  let h='';
  if(d.year) h+='<span class="sub" style="font-size:11px;color:var(--ink-3)">📖 Origin story · '+d.year+'</span>';
  if(d.article&&d.article.url) h+='<a href="'+d.article.url+'" target="_blank" rel="noopener" title="'+esc(d.article.title||'')+'" style="font-size:12px;color:var(--accent);font-weight:600;text-decoration:none">Deep dive ↗</a>';
  return h?('<div class="ddmeta" style="display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin:2px 0 0">'+h+'</div>'):''; }
/* just the code link (shown with Execute / Open in the actions row) */
function deepDiveCode(id){ const d=deepDive(id); if(!d||!d.code||!d.code.url) return '';
  return '<a class="btn ghost sm" href="'+d.code.url+'" target="_blank" rel="noopener" title="'+esc(d.code.label||'Source code')+'">‹ › Code</a>'; }
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
   "Correlates crown-jewel identities, credential reuse, default/blank creds and AD attack paths.",
   "Tags the hosting assets — Fenrir's single biggest source of credential pivots."]},
 scan_eval:{does:"Measures where your scans spend their time — and, crucially, what they can't see: the blind and uncredentialed hosts.",caps:[
   "Cleans up <span class='mono'>navi scan evaluate</span>: average scan time by scanner, policy and scan.",
   "Reports <b>credential coverage</b> and surfaces blind / uncredentialed hosts.",
   "Tags problem areas so scanning gaps become actionable.",
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
 attackpath:{does:"The capstone correlator — chains exploitability × identity × reachability into ranked attack paths.",caps:[
   "Chains <b>foothold</b> (exploitable / weak-auth) → <b>lateral movement</b> (same-subnet + credential pivots) → <b>high-ACR crown-jewel target</b>.",
   "KPIs, a 3-stage path table and CSV export; tags <span class='mono'>Attack Path:Entry Point</span> / <span class='mono'>Attack Path:Target</span>.",
   "Consumes Laelaps (KEV), Janus (weak auth), Anubis (ACR targets), Charon/Mimir (exploitable software).",
   "Honest caveat: reachability is inferred from subnet adjacency + credential signals, not observed traffic."]},
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
   '.codetoggle{cursor:pointer;background:var(--panel2,var(--bg-2));border:1px solid var(--line);border-radius:999px;padding:6px 14px;color:var(--ink);font-size:12.5px;font-weight:600;display:inline-flex;align-items:center;gap:7px}'
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
const _NO_CODENAME=new Set(['ex_assets','ex_vulns','ex_plugins','ex_routes','ex_paths','explore','advanced','advsearch']);
function _mountCodename(host){
  const id = window.__AGENT_ID||''; const cn = CODENAMES[id]; if(!cn) return;
  if(_NO_CODENAME.has(id)){ const ex=document.getElementById('agent-codename'); if(ex)ex.remove(); return; }
  _introStyle();
  const intro = (typeof AGENT_INTRO!=='undefined' && AGENT_INTRO[id]) || null;
  let cb=document.getElementById('agent-codename');
  if(!cb){ cb=document.createElement('div'); cb.id='agent-codename'; cb.className='codebanner'; cb.style.cssText='margin:0 0 12px'; host.insertAdjacentElement('afterend',cb); }
  const crestSm='<img src="/static/crests/'+id+'.png?v=3" alt="" onerror="this.replaceWith(document.createTextNode(\'🐾\'))">';
  const bigCrest='<img class="introCrest" src="/static/crests/'+id+'.png?v=3" alt="'+esc(cn.name)+'" onerror="this.style.display=\'none\'">';
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
    window.__APPLIED_TAGS = new Set((o.applied||[]).map(r =>
      String(r.tag_key||'').toLowerCase()+_SEP+String(r.tag_value||'').toLowerCase())); }
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
    +'<div class="sub" style="margin-bottom:6px">Generated SQL — review / refine, then execute:</div>'
    +'<textarea id="'+id+'_sql" spellcheck="false" style="width:100%;min-height:88px;font-family:ui-monospace,monospace;font-size:12px;padding:8px;border-radius:8px;border:1px solid var(--line);background:var(--bg-2);color:var(--ink);box-sizing:border-box">'+esc(sql)+'</textarea>'
    +'<div id="'+id+'_cols" style="margin-top:8px"></div>'
    +'<div class="toolbar" style="margin-top:8px"><button class="btn run sm" id="'+id+'_go">▶ Execute SQL</button><span class="sub">read-only · single SELECT · LIMIT ≤500 enforced</span></div>'
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
  ['🏷 Tagging log', '/web/tags-log.html'],
  ['SEP'],
  ['📊 Dashboards', [
    ['📊 Dashboard builder', '/agents/dashboard/page.html'],
    ['🗂 Custom Dashboard', '/web/customdash.html'],
    ['🗺 Ownership Map', '/web/ownermap.html'],
  ]],
  ['🔎 Search Hounds', [
    ['🔦 Asset deep-dive · Argos', '/agents/argos/page.html'],
    ['🧠 Advanced search', '/web/advanced.html'],
    ['🔎 Assets', '/agents/ex_assets/page.html'],
    ['🔎 Vulns', '/agents/ex_vulns/page.html'],
    ['🔎 Plugins', '/agents/ex_plugins/page.html'],
    ['🔎 Routes', '/agents/ex_routes/page.html'],
    ['🔎 Paths', '/agents/ex_paths/page.html'],
  ]],
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
   +'.navdd-caret{font-size:10px;opacity:.7;margin-left:2px}';
  document.head.appendChild(st);
}
function mountTopNav(){
  const wrap = document.querySelector('.wrap'); if(!wrap) return;
  _navddStyle();
  const old = document.getElementById('topnav'); if(old) old.remove();
  const p = location.pathname;
  const active = href => href === '/' ? (p === '/' || p === '/index.html')
                                      : (p === href || p.endsWith(href));
  const nav = document.createElement('nav'); nav.className = 'tabs'; nav.id = 'topnav';
  nav.innerHTML = _NAV_ITEMS.map(it => {
    if(it[0] === 'SEP') return '<span class="navsep"></span>';
    if(Array.isArray(it[1])){
      const anyActive = it[1].some(s => active(s[1]));
      const menu = it[1].map(s => '<button class="navdd-item' + (active(s[1]) ? ' active' : '') +
        '" data-href="' + s[1] + '">' + s[0] + '</button>').join('');
      return '<span class="navdd"><button class="navdd-btn' + (anyActive ? ' active' : '') +
        '">' + it[0] + ' <span class="navdd-caret">▾</span></button>' +
        '<div class="navdd-menu">' + menu + '</div></span>';
    }
    const cls = (it[2] ? 'lens ' : '') + (active(it[1]) ? 'active' : '');
    return '<button class="' + cls.trim() + '" data-href="' + it[1] + '">' + it[0] + '</button>';
  }).join('');
  const anchor = document.querySelector('header.top, #app-header, header');
  if(anchor && anchor.parentNode) anchor.insertAdjacentElement('afterend', nav);
  else wrap.prepend(nav);
  nav.querySelectorAll('button[data-href]').forEach(b => b.onclick = (e) => { e.stopPropagation(); location.href = b.dataset.href; });
  nav.querySelectorAll('.navdd-btn').forEach(b => b.onclick = (e) => {
    e.stopPropagation(); const dd = b.parentNode; const wasOpen = dd.classList.contains('open');
    nav.querySelectorAll('.navdd').forEach(x => x.classList.remove('open'));
    if(!wasOpen) dd.classList.add('open');
  });
  if(!window.__navddDocClose){ window.__navddDocClose = true;
    document.addEventListener('click', () => { const n=document.getElementById('topnav'); if(n) n.querySelectorAll('.navdd').forEach(x=>x.classList.remove('open')); });
  }
}
if(document.readyState !== 'loading') mountTopNav();
else document.addEventListener('DOMContentLoaded', mountTopNav);

/* Claude API-key indicator. The AI features (ask-which-agent, NL→SQL, contract
   policy, cert reasoning) call Claude, which needs ANTHROPIC_API_KEY on the server.
   Green when a key is present; amber warning when it's missing so the operator knows
   why the ✨ features are greyed out. h.llm comes from /api/health. */
function claudeChip(h){
  const ok = !!(h && h.llm);
  if(ok) return `<span class="chip" title="Claude API key detected — AI features enabled" style="background:rgba(52,211,153,.14);border-color:rgba(52,211,153,.4);color:var(--ok,#34d399)">✦ Claude AI</span>`;
  return `<span class="chip" title="No ANTHROPIC_API_KEY on the server — AI features (ask-which-agent, NL→SQL, contract policy, cert reasoning) are disabled. Set ANTHROPIC_API_KEY and restart." style="background:rgba(251,191,36,.14);border-color:rgba(251,191,36,.45);color:var(--warn,#fbbf24)">⚠ Claude: no API key</span>`;
}

/* Mount the shared header (logo, title, live health chips). */
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
    `<h1>${esc(opts.name||'Navi Agent')}<small>${esc(opts.sub||'')}</small></h1>`+
    `<div class="meta" id="meta"></div>`;
  _mountCodename(host);
  mountTopNav();
  try{
    const h = await jget('/api/health');
    window.__LLM_AVAILABLE = !!h.llm; applyLlmGate();
    const meta = document.getElementById('meta');
    const we = h.writes_enabled;
    meta.innerHTML =
      dataSourceChip(h)+
      claudeChip(h)+
      (h.db_ok ? `<span class="chip">assets <b>${h.asset_total}</b></span>`+
                 (h.db_fresh?`<span class="chip">db <b>${String(h.db_fresh).slice(0,10)}</b></span>`:'')
               : `<span class="chip" style="color:var(--crit)">db: ${esc(h.error||'error')}</span>`)+
      `<span class="chip gate ${we?'':''}">writes: ${we?'enabled':'gated'}</span>`+
      `<a class="chip" id="naviRefreshChip" title="Pull freshly-applied tags/ACR into navi.db (runs in the background)" style="text-decoration:none;cursor:pointer">↻ Refresh navi.db</a>`+
      // Tag compare sits right next to Refresh (same chip design)
      `<a class="chip" href="/web/tags.html" title="Compare tags: Tenable ⇄ navi.db" style="text-decoration:none">⚖ Tag compare</a>`+
      // MCP compare — purple chip, last in the row (just before the light/dark toggle)
      `<a class="chip" href="/agents/mcpcmp/page.html" title="navi vs Tenable MCP command coverage" style="text-decoration:none;background:rgba(139,92,246,.16);border-color:rgba(139,92,246,.5);color:#a78bfa">⚖ MCP compare</a>`;
    const rc=document.getElementById('naviRefreshChip'); if(rc) rc.onclick=naviRefresh;
  }catch(e){ /* no backend — header still shows */ }
}
/* Fire-and-forget navi.db refresh — kicks the sync server-side and returns at once. */
async function naviRefresh(){
  const rc=document.getElementById('naviRefreshChip');
  if(rc){ rc.textContent='↻ refreshing…'; }
  try{ const o=await agentApi('explore').post('navi_refresh',{kinds:['assets','vulns']});
    if(rc){ rc.textContent = (o&&o.started&&o.started.length)?('↻ refreshing '+o.started.join('+')+'…'):'↻ Refresh navi.db'; }
    alert((o&&o.started&&o.started.length)
      ? 'navi.db refresh started in the background ('+o.started.join(', ')+'). On large environments this can take several minutes — it runs on its own; reload the page when it finishes to see new tags/ACR.'
      : 'Could not start refresh: '+((o&&o.message)||'navi not available on this server.'));
  }catch(e){ alert('Refresh failed to start: '+e.message); }
  setTimeout(()=>{ if(rc) rc.textContent='↻ Refresh navi.db'; }, 8000);
}

/* Data-source chip: amber = crafted sample fixture, green = live navi.db. */
function dataSourceChip(h){
  const src = (h && h.data_source) || 'unknown';
  if(src==='fixture')
    return `<span class="chip" title="${esc((h&&h.provenance_note)||'crafted sample data')}" style="background:rgba(251,191,36,.14);border-color:rgba(251,191,36,.45);color:var(--warn,#fbbf24)">◆ SAMPLE data</span>`;
  if(src==='live')
    return `<span class="chip" title="${esc((h&&h.db_path)||'navi.db')}" style="background:rgba(52,211,153,.14);border-color:rgba(52,211,153,.4);color:var(--ok,#34d399)">● LIVE navi.db</span>`;
  return `<span class="chip" style="color:var(--mut)">data: unknown</span>`;
}

/* Tiny flash helper. el = element id or node. kind = ok|run|warn|crit. */
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
  if(typeof exprOrPayload === 'string')
    return `<button class="btn ghost sm" onclick="emailFindings(${exprOrPayload})" title="Hand these findings to Gabriel — email the finding IDs + tagged assets with Tenable deep-links">${lab}</button>`;
  return `<button class="btn ghost sm" onclick='emailFindings(${JSON.stringify(exprOrPayload)})'>${lab}</button>`;
}
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
function _csvCell(v){ v=(v==null?'':String(v)); return /[",\r\n]/.test(v)?'"'+v.replace(/"/g,'""')+'"':v; }
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
