// Capture each hound's "At a glance" (or its nearest equivalent) for the Meet-the-Hound one-pagers.
// Run with the console up (python3 app_stdlib.py) and the pack released once, then:
//   node tools/hound_pages_capture.js [ids…]      → tools/hound_pages/glance/<id>.png
//   python3 tools/hound_pages.py                  → rebuild web/hounds/*.html
// Needs Node + Playwright (npm i playwright; npx playwright install chromium).
// Env: BASE (default http://localhost:8000), OUT, ARGOS_TARGET (an asset uuid or IP for Argos).
// Screenshots show your navi.db's real hostnames / IPs in some widgets — review before sharing.
const { chromium } = require('playwright');
const BASE=process.env.BASE||'http://localhost:8000', OUT=process.env.OUT||require('path').join(__dirname,'hound_pages','glance');
const G=(id,extra)=>Object.assign({target:'#'+id},extra||{});
const C={
 acr:G('glxAcr',{click:['#runAcr'],wait:6000}), ai:G('glxAi',{click:['#run']}), argos:G('glanceBody',{q:process.env.ARGOS_TARGET?'?target='+encodeURIComponent(process.env.ARGOS_TARGET):''}),
 asset_ownership:G('glance',{click:['#load']}), attackpath:G('glxAp',{click:['#run']}), c2:G('glance'),
 certificate:G('glxCert',{click:['#run']}), cisakev:G('glxKev',{click:['#load','#approveBtn']}), classify:{target:'.glx',click:['#run']},
 compliance:G('glxComp'), customapp:G('glxCapp',{click:['#run']}), eol:G('glxEol',{click:['#run']}), exproute:G('glxEr',{click:['#load']}),
 fused_score:G('glxFs'), identity:G('glxIdent',{click:['#run']}), insights:G('glance'), iot_squad:G('glxIot',{click:['#run']}),
 mitre:G('glxMitre',{click:['#run','#approveBtn']}), postquantum:G('glxPq',{click:['#run']}), scan_eval:G('glxScan',{click:['#run']}),
 sla:G('glxSla',{click:['#refresh'],wait:30000}), was:G('glxWas'),
 alert:{target:'#suggest',card:1,click:['#refreshSug'],wait:4000}, contract:{target:'#planOut',card:1,click:['#planBtn'],wait:8000},
 custom_audit:{target:'#buildCard',card:1,click:['#modeSeg [data-m=build]']}, dashboard:{target:'#presetCard',card:1}, email:{target:'#recipCard',click:['#recipBtn']},
 mcpcmp:{target:'#matrix',card:1}, tagremoval:{target:'#tbl',card:1,click:['#loadBtn']},
 compliance_asset:{target:'#body',maxh:900}, ex_assets:{target:'#evCard',q:'?evidence=kev',wait:5000},
 ex_vulns:{target:'#tbl',card:1,fill:['#q','KEV'],click:['#go']}, ex_plugins:{target:'#tbl',card:1,fill:['#q','SSL'],click:['#go']},
 ex_routes:{target:'#tbl',card:1,click:['#go']}, ex_paths:{target:'#tbl',card:1,click:['#go']}, ex_tags:{target:'#tbl',card:1,click:['#go']},
 ex_fixed:{target:'#tbl',card:1,click:['#go']}, ex_compliance:{target:'#kpi',wait:3000}, agentgroup:{target:'#grpTbl',card:1,click:['#load']},
 ex_apps:{target:'table',card:1}, was_asset:{target:'#body',maxh:900},
 // Harrier: the Log4Shell range NVD gives for CVE-2021-44228 (the ✨ lookup fills the same box)
 ex_software:{target:'#swGlance',q:'?q=log4j&range='+encodeURIComponent('>=2.0.1 <2.3.1; >=2.4.0 <2.12.2; >=2.13.0 <2.15.0; 2.0-beta9; 2.0-rc1'),wait:3000},
};
(async()=>{ const b=await chromium.launch(); const ids=process.argv.slice(2).length?process.argv.slice(2):Object.keys(C);
 for(const a of ids){ const c=C[a]; if(!c){console.log(a,'no config');continue;}
  const ctx=await b.newContext({viewport:{width:1600,height:1100},deviceScaleFactor:2,colorScheme:'light'}); const pg=await ctx.newPage(); const errs=[];
  pg.on('pageerror',e=>errs.push(e.message)); pg.on('dialog',d=>d.dismiss());
  try{
   await pg.goto(`${BASE}/agents/${a}/page.html${c.q||''}`); await pg.waitForLoadState('networkidle'); await pg.waitForTimeout(1200);
   if(c.fill){ await pg.fill(c.fill[0],c.fill[1]).catch(()=>{}); }
   for(const s of (c.click||[])){ const el=await pg.$(s); if(el&&await el.isVisible()){ await el.click().catch(()=>{}); await pg.waitForTimeout(1500); await pg.waitForLoadState('networkidle').catch(()=>{}); } }
   await pg.waitForTimeout(c.wait||2500);
   if(c.target.startsWith('#glx')||['#glance','#glanceBody','.glx'].includes(c.target)){ await pg.waitForSelector(c.target+' .glx-p, .glx-p',{timeout:90000}).catch(()=>{}); await pg.waitForTimeout(800); }
   await pg.evaluate(()=>{ for(const el of document.querySelectorAll('body *')){ const cs=getComputedStyle(el); if(cs.position==='fixed'&&!el.closest('header')&&el.id!=='app-header'&&el.id!=='topnav') el.style.visibility='hidden'; } });
   let el=await pg.$(c.target);
   if(el&&c.card){ el=(await el.evaluateHandle(e=>e.closest('section.card,.card')||e)).asElement(); }
   if(!el||!(await el.isVisible())){ console.log(a,'NO TARGET',errs[0]||''); await ctx.close(); continue; }
   await el.scrollIntoViewIfNeeded(); const bb=await el.boundingBox();
   const opt={path:`${OUT}/${a}.png`}; if(bb&&bb.height>(c.maxh||1150)){ await pg.screenshot({...opt, clip:{x:bb.x,y:bb.y,width:bb.width,height:c.maxh||1150}, fullPage:true}); }
   else await el.screenshot(opt);
   console.log(a,'ok',bb&&Math.round(bb.height),errs.length?('ERR '+errs[0]):'');
  }catch(e){ console.log(a,'FAIL',e.message.slice(0,120)); }
  await ctx.close(); }
 await b.close(); })();
