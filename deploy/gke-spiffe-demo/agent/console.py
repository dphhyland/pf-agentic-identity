"""The live demo console served at GET / by the agent. A single self-contained HTML string.

Every "Run" click makes the pod fetch fresh platform evidence, mint a real Client Attestation, and
call the live PingFederate — then the page decodes and displays every JWT. It is genuinely live: the
tokens shown are the ones just minted inside GCP.
"""

CONSOLE_HTML = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Client Attestation — live demo</title>
<style>
  :root {
    --paper:#F7F8F7; --ink:#1A2228; --soft:#4A5560; --line:#DDE3E1;
    --a:#0F766E; --a-bg:#0F766E14; --g:#3B6FD4; --g-bg:#3B6FD414; --p:#B23A48; --p-bg:#B23A4814;
    --card:#FFF; --code:#EEF1F0;
  }
  @media (prefers-color-scheme:dark){:root{
    --paper:#10171C; --ink:#E4E9EC; --soft:#93A1AC; --line:#263239;
    --a:#2DB5A5; --a-bg:#2DB5A522; --g:#7BA3F0; --g-bg:#7BA3F022; --p:#E07A88; --p-bg:#E07A8822;
    --card:#161F26; --code:#1C262E;}}
  *{box-sizing:border-box}
  body{margin:0;background:var(--paper);color:var(--ink);
    font-family:'Avenir Next',Avenir,Seravek,'Segoe UI',system-ui,sans-serif;line-height:1.5}
  .wrap{max-width:56rem;margin:0 auto;padding:2.5rem 1.25rem 5rem}
  h1{font-size:1.7rem;margin:.3rem 0 .4rem;letter-spacing:-.01em}
  .eyebrow{text-transform:uppercase;letter-spacing:.14em;font-size:.7rem;font-weight:700;color:var(--a);margin:0}
  .lede{color:var(--soft);font-size:1.02rem;max-width:44rem}
  .bar{display:flex;flex-wrap:wrap;gap:.6rem;align-items:center;margin:1.4rem 0 .5rem}
  button{font:inherit;font-weight:600;border:none;border-radius:8px;padding:.6em 1.1em;cursor:pointer}
  .run{background:var(--a);color:#fff}
  .run:hover{filter:brightness(1.08)}
  .ghost{background:var(--card);color:var(--ink);border:1px solid var(--line)}
  .ghost:hover{border-color:var(--a)}
  button:disabled{opacity:.5;cursor:default}
  .meta{font-size:.82rem;color:var(--soft)}
  .meta code{background:var(--code);padding:.1em .4em;border-radius:4px;font-size:.92em}
  .steps{list-style:none;margin:1.5rem 0 0;padding:0;display:flex;flex-direction:column;gap:.7rem}
  .step{border:1px solid var(--line);border-radius:10px;background:var(--card);overflow:hidden;
    opacity:.5;transition:opacity .3s}
  .step.active,.step.done{opacity:1}
  .step-h{display:flex;align-items:center;gap:.7rem;padding:.7rem .9rem;cursor:pointer}
  .n{width:1.7rem;height:1.7rem;flex:none;border-radius:50%;display:flex;align-items:center;
    justify-content:center;font-size:.85rem;font-weight:700;background:var(--a-bg);color:var(--a);
    border:1px solid var(--a)}
  .step.g .n{background:var(--g-bg);color:var(--g);border-color:var(--g)}
  .step.p .n{background:var(--p-bg);color:var(--p);border-color:var(--p)}
  .step-t{font-weight:600;flex:1}
  .step-s{font-size:.78rem;color:var(--soft)}
  .pill{font-size:.72rem;font-weight:700;padding:.15em .6em;border-radius:999px;white-space:nowrap}
  .pill.ok{background:var(--a-bg);color:var(--a)} .pill.err{background:var(--p-bg);color:var(--p)}
  .pill.wait{background:var(--code);color:var(--soft)}
  .body{display:none;padding:0 .9rem .9rem;border-top:1px dashed var(--line)}
  .step.open .body{display:block}
  .kv{font-size:.8rem;color:var(--soft);margin:.5rem 0 .2rem}
  pre{background:var(--code);border-radius:8px;padding:.7rem .8rem;overflow-x:auto;margin:.3rem 0 0;
    font-family:ui-monospace,'SF Mono',Menlo,Consolas,monospace;font-size:.76rem;line-height:1.45;
    white-space:pre-wrap;word-break:break-word}
  .tok{font-family:ui-monospace,Menlo,monospace;font-size:.72rem;color:var(--soft);word-break:break-all;
    margin-top:.35rem}
  .verdict{margin-top:1.4rem;padding:.9rem 1.1rem;border-radius:10px;border:1px solid var(--line);
    background:var(--card);display:none}
  .verdict.show{display:block}
  .verdict.pass{border-left:4px solid var(--a)} .verdict.fail{border-left:4px solid var(--p)}
  .verdict h3{margin:.1rem 0 .3rem;font-size:1.05rem}
  .verdict p{margin:0;color:var(--soft);font-size:.9rem}
  a{color:var(--a)}
  .foot{margin-top:2.5rem;font-size:.82rem;color:var(--soft);border-top:1px solid var(--line);padding-top:1rem}
</style>
</head>
<body>
<div class="wrap">
  <p class="eyebrow">Live demo · running in GCP</p>
  <h1>Watch a workload authenticate with no shared secret</h1>
  <p class="lede">Each run makes <em>this pod</em> fetch fresh platform evidence, mint a Client
  Attestation, and call the live PingFederate. The JWTs below are the real ones, minted just now.</p>

  <div class="bar">
    <button class="run" id="run">▶ Run the attestation chain</button>
    <button class="ghost" id="over">Try an over-ceiling request</button>
    <span class="meta" id="meta"></span>
  </div>

  <ol class="steps" id="steps"></ol>
  <div class="verdict" id="verdict"></div>

  <div class="foot" id="foot"></div>
</div>

<script>
const STEPS = [
  {k:'discover', cls:'',  t:'Discover the attester',       s:'GET /.well-known/client-attester'},
  {k:'evidence', cls:'g', t:'Prove what I am',             s:'platform-signed identity token'},
  {k:'mint',     cls:'a', t:'Mint the Client Attestation', s:'POST /federation/attestation'},
  {k:'token',    cls:'p', t:'Authenticate to PingFederate',s:'POST /as/token.oauth2'},
];
const el = id => document.getElementById(id);
function b64urlDecode(s){s=s.replace(/-/g,'+').replace(/_/g,'/');while(s.length%4)s+='=';
  try{return decodeURIComponent(escape(atob(s)))}catch(e){return atob(s)}}
function decodeJwt(j){try{const p=j.split('.');return JSON.stringify(JSON.parse(b64urlDecode(p[1])),null,1)}
  catch(e){return '(could not decode)'}}
function render(){
  el('steps').innerHTML = STEPS.map((st,i)=>`
    <li class="step ${st.cls}" id="st-${st.k}">
      <div class="step-h" onclick="this.parentElement.classList.toggle('open')">
        <span class="n">${i+1}</span>
        <span class="step-t">${st.t}</span>
        <span class="step-s">${st.s}</span>
        <span class="pill wait" id="pill-${st.k}">·</span>
      </div>
      <div class="body" id="body-${st.k}"></div>
    </li>`).join('');
}
render();
function setPill(k,cls,txt){const p=el('pill-'+k);p.className='pill '+cls;p.textContent=txt;}
function activate(k){el('st-'+k).classList.add('active');}
function done(k,openIt){const s=el('st-'+k);s.classList.add('done');if(openIt)s.classList.add('open');}
function setBody(k,html){el('body-'+k).innerHTML=html;}

async function run(overCeiling){
  el('run').disabled = el('over').disabled = true;
  el('verdict').className='verdict'; render();
  el('meta').textContent = 'running…';
  const body = overCeiling ? {authorization_details:[{type:'sales_agent',sales_regions:['APAC']}]} : {};
  let r;
  try{
    const resp = await fetch('/invoke',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify(body)});
    r = await resp.json();
  }catch(e){ el('meta').textContent='error: '+e; el('run').disabled=el('over').disabled=false; return; }

  el('meta').innerHTML = 'evidence type <code>'+(r.evidence_mode||'?')+'</code>';

  // 1 discover
  activate('discover');
  if(r.discovery){ setPill('discover','ok','200');
    setBody('discover','<div class="kv">the attester advertises its contract</div><pre>'+
      JSON.stringify({evidence_type:r.discovery.evidence_type,evidence_audience:r.discovery.evidence_audience,
        attestation_endpoint:r.discovery.attestation_endpoint,
        authorization_details_types:r.discovery.authorization_details_types},null,1)+'</pre>');
    done('discover'); }
  else { setPill('discover','err','fail'); }

  // 2 evidence
  activate('evidence');
  if(r.evidence){ const c=decodeJwt(r.evidence); setPill('evidence','ok','signed');
    setBody('evidence','<div class="kv">Google/SPIRE signed this — the pod cannot forge it</div><pre>'+c+
      '</pre><div class="tok">'+r.evidence.slice(0,88)+'…</div>');
    done('evidence',true); }

  // 3 mint
  activate('mint');
  if(r.mint_status===200){ const att=r.attestation; const c=decodeJwt(att); setPill('mint','ok','200');
    setBody('mint','<div class="kv">the attester vouches: identity + instance key (cnf) + entitlement</div><pre>'+
      c+'</pre>'); done('mint',true); }
  else { setPill('mint','err',r.mint_status||'fail');
    setBody('mint','<pre>'+(r.mint_body||'').replace(/</g,'&lt;')+'</pre>'); done('mint',true);
    return finish(r,overCeiling); }

  // 4 token
  activate('token');
  if(r.pf_status===200){ setPill('token','ok','200');
    setBody('token','<div class="kv">PingFederate verified the attestation + PoP and issued a token</div><pre>'+
      (r.pf_body||'')+'</pre>'); done('token',true); }
  else { setPill('token','err',r.pf_status||'fail');
    setBody('token','<pre>'+(r.pf_body||'').replace(/</g,'&lt;')+'</pre>'); done('token',true); }
  finish(r,overCeiling);
}

function finish(r,overCeiling){
  const v=el('verdict');
  if(overCeiling){
    v.className='verdict show fail';
    v.innerHTML='<h3>Denied at mint — exactly as designed</h3><p>The request asked for a region outside '+
      'the attested entitlement ceiling, so the attester refused before any token could exist '+
      '(<code>'+ (r.mint_status||'') +' '+ (JSON.parse(r.mint_body||'{}').error||'') +'</code>).</p>';
  } else if(r.pf_status===200){
    v.className='verdict show pass';
    v.innerHTML='<h3>Authenticated — no shared secret involved</h3><p>This pod proved what it is with a '+
      'platform-signed token, and walked away with a PingFederate access token. Nothing reusable was '+
      'provisioned anywhere.</p>';
  } else {
    v.className='verdict show fail';
    v.innerHTML='<h3>Chain stopped</h3><p>See the step above for the response.</p>';
  }
  el('run').disabled = el('over').disabled = false;
}

el('run').onclick = ()=>run(false);
el('over').onclick = ()=>run(true);

fetch('/identity').then(r=>r.json()).then(d=>{
  el('foot').innerHTML = 'Served from a GKE pod · evidence <code style="font-family:monospace">'+(d.evidence_mode||'')+
    '</code> · instance key <code style="font-family:monospace">'+((d.instance_key_kid||'').slice(0,16))+
    '…</code><br>Explainer: <a href="https://gke-spiffe-demo-production.up.railway.app">'+
    'gke-spiffe-demo-production.up.railway.app</a> · Source: '+
    '<a href="https://github.com/dphhyland/pf-agentic-identity">github.com/dphhyland/pf-agentic-identity</a>';
}).catch(()=>{});
</script>
</body>
</html>
"""
