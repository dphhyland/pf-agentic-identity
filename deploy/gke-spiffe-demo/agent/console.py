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
  .ask{font-size:.86rem;color:var(--soft);max-width:44rem;margin:.1rem 0 0}
  .ask code{background:var(--code);padding:.1em .4em;border-radius:4px}
  .req{background:var(--g-bg);border:1px solid var(--g);border-radius:8px;padding:.5rem .7rem;
    margin:.5rem 0 0;font-size:.8rem}
  .req b{color:var(--g)}
  .curl{margin:.6rem 0 0}
  .curl summary{cursor:pointer;font-size:.78rem;color:var(--a);font-weight:600;list-style:none}
  .curl summary::-webkit-details-marker{display:none}
  .curl summary:before{content:'▸ ';font-weight:400}
  .curl[open] summary:before{content:'▾ '}
  .curl pre{background:#0d1117;color:#d5e0ea;border:1px solid var(--line);font-size:.72rem;
    line-height:1.5;max-height:22rem;overflow:auto;white-space:pre;word-break:normal}
  .curl .cp{float:right;font-size:.7rem;font-weight:600;border:1px solid var(--line);
    background:var(--card);color:var(--ink);border-radius:6px;padding:.15em .5em;cursor:pointer}
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
  <h1>Watch a workload authenticate with a platform-attested identity</h1>
  <p class="lede">Each run makes <em>this pod</em> fetch fresh platform evidence and present it —
  <strong>with no client_id</strong> — to the attester, which maps the identity to an OAuth client, then
  calls the live PingFederate. The JWTs below are the real ones, minted just now.</p>
  <p class="ask" style="margin-top:.6rem">Note the <code>client_secret</code> in step 4. PingFederate
  requires one of its own client-authentication methods for the <code>client_credentials</code> grant, and
  <code>attest_jwt_client_auth</code> is not yet one of them — so the attestation is enforced as an
  additional gate rather than as the client authentication itself. Both are checked: a wrong secret fails
  before the attestation is read, and a valid secret with no attestation fails too.</p>

  <div class="bar">
    <button class="run" id="run">▶ Run the chain</button>
    <button class="ghost" id="emea">Ask for EMEA</button>
    <button class="ghost" id="apac">Ask for APAC</button>
    <span class="meta" id="meta"></span>
  </div>
  <p class="ask">This workload is attested for <strong>sales_agent</strong> in
  <strong>EMEA only</strong> — that ceiling comes from the resolver plugin's mapping, not from anything the
  workload says. The buttons send an RFC 9396 <code>authorization_details</code> request along with the
  mint call: <em>Ask for EMEA</em> is inside the ceiling, <em>Ask for APAC</em> is outside it.</p>

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

// Shows the RFC 9396 authorization_details the workload sent with the mint call — the thing the
// ceiling is checked against. Without this the allow/deny outcome has no visible cause.
// The exact HTTP request the workload made for this step, as a runnable curl.
function curlBlock(r, step){
  const c=(r.calls||[]).find(x=>x.step===step);
  if(!c) return '';
  const id='curl-'+step;
  return '<details class="curl"><summary>show the exact request '+
    '<button class="cp" onclick="copyCurl(event,\''+id+'\')">copy</button></summary>'+
    '<pre id="'+id+'">'+c.curl.replace(/&/g,'&amp;').replace(/</g,'&lt;')+'</pre></details>';
}
function copyCurl(e,id){
  e.preventDefault(); e.stopPropagation();
  navigator.clipboard.writeText(el(id).textContent);
  e.target.textContent='copied'; setTimeout(()=>e.target.textContent='copy',1200);
}

function reqBlock(r){
  if(!r._requested) return '<div class="req">No <b>authorization_details</b> requested — the attester '+
    'grants the workload\'s full attested ceiling.</div>';
  return '<div class="req">Sent with the mint request — <b>authorization_details</b>:'+
    '<pre style="margin-top:.4rem">'+JSON.stringify(r._requested,null,1)+'</pre></div>';
}

const BUTTONS=['run','emea','apac'];
function setBusy(b){ BUTTONS.forEach(id=>el(id).disabled=b); }

// mode: null = no explicit request (grants the full ceiling); otherwise the RAR request we send.
function requestFor(mode){
  if(mode==='emea') return [{type:'sales_agent',sales_regions:['EMEA']}];
  if(mode==='apac') return [{type:'sales_agent',sales_regions:['APAC']}];
  return null;
}

async function run(mode){
  setBusy(true);
  el('verdict').className='verdict'; render();
  el('meta').textContent = 'running…';
  const requested = requestFor(mode);
  const body = requested ? {authorization_details:requested} : {};
  let r;
  try{
    const resp = await fetch('/invoke',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify(body)});
    r = await resp.json();
  }catch(e){ el('meta').textContent='error: '+e; setBusy(false); return; }
  r._requested = requested;

  el('meta').innerHTML = 'evidence type <code>'+(r.evidence_mode||'?')+'</code>';

  // 1 discover
  activate('discover');
  if(r.discovery){ setPill('discover','ok','200');
    const d=r.discovery;
    const plugins = (d.resolver_plugins_active||[]).length
      ? '<div class="kv">resolver plugins active (they map identity → client at mint): <code>'+
        (d.resolver_plugins_active||[]).join('</code> <code>')+'</code></div>' : '';
    setBody('discover', curlBlock(r,'discover')+
      '<div class="kv">a static document — note it carries no client_id</div>'+plugins+
      '<pre>'+JSON.stringify({evidence_audience:d.evidence_audience,
        evidence_types_supported:d.evidence_types_supported,
        attestation_endpoint:d.attestation_endpoint,
        resolver_plugins_active:d.resolver_plugins_active},null,1)+'</pre>');
    done('discover'); }
  else { setPill('discover','err','fail'); }

  // 2 evidence
  activate('evidence');
  if(r.evidence){ const c=decodeJwt(r.evidence); setPill('evidence','ok','signed');
    const how = r.evidence_mode==='gke-sa-token'
      ? '<details class="curl"><summary>how this token was obtained</summary><pre># Kubernetes projects it into the pod; the workload just reads the file:\ncat /var/run/secrets/tokens/attester-token</pre></details>'
      : (r.evidence_mode==='spiffe-jwt'
        ? '<details class="curl"><summary>how this token was obtained</summary><pre># from the SPIRE Workload API (aud = the attester the discovery doc named):\nspire-agent api fetch jwt -audience https://attester.example.com</pre></details>'
        : '');
    setBody('evidence', how+'<div class="kv">Google/SPIRE signed this — the pod cannot forge it</div><pre>'+c+
      '</pre><div class="tok">'+r.evidence.slice(0,88)+'…</div>');
    done('evidence',true); }

  // 3 mint
  activate('mint');
  if(r.mint_status===200){ const att=r.attestation; const c=decodeJwt(att); setPill('mint','ok','200');
    // The client id is the ATTESTER's conclusion — the request carried none.
    const assigned = r.client_id ? '<div class="kv">the attester resolved this identity to client '+
      '<code style="font-family:ui-monospace,Menlo,monospace">'+r.client_id+'</code>'+
      ' — the request carried no client_id</div>' : '';
    const sel = (()=>{ try{ const w=JSON.parse(b64urlDecode(att.split('.')[1])).workload||{};
        const s=(w.attributes||{}).selectors;
        return s&&s.length ? '<div class="kv">SPIRE selectors introspected: <code>'+s.join('</code> <code>')+
          '</code></div>' : ''; }catch(e){ return ''; } })();
    setBody('mint', curlBlock(r,'challenge') + curlBlock(r,'mint') + reqBlock(r) + assigned + sel +
      '<div class="kv">the attester vouches: identity + instance key (cnf) + entitlement</div><pre>'+
      c+'</pre>'); done('mint',true); }
  else { setPill('mint','err',r.mint_status||'fail');
    setBody('mint', curlBlock(r,'mint') + reqBlock(r) +
      '<div class="kv">the attester refused — the request exceeded what this workload is attested for</div>'+
      '<pre>'+(r.mint_body||'').replace(/</g,'&lt;')+'</pre>'); done('mint',true);
    return finish(r,mode); }

  // 4 token
  activate('token');
  if(r.pf_status===200){ setPill('token','ok','200');
    let extra='';
    try{
      const at=JSON.parse(r.pf_body||'{}').access_token||'';
      if(at.split('.').length===3){
        extra='<div class="kv">the access token is a JWT — decoded payload:</div><pre>'+
          JSON.stringify(JSON.parse(b64urlDecode(at.split('.')[1])),null,1)+'</pre>'+
          '<div class="kv">note <code>sub</code>: the resource server sees the attested workload, '+
          'and <code>act</code> records which platform attested it</div>';
      }
    }catch(e){}
    setBody('token', curlBlock(r,'token')+
      '<div class="kv">PingFederate verified the attestation + PoP and issued a token</div><pre>'+
      (r.pf_body||'')+'</pre>'+extra); done('token',true); }
  else { setPill('token','err',r.pf_status||'fail');
    setBody('token','<pre>'+(r.pf_body||'').replace(/</g,'&lt;')+'</pre>'); done('token',true); }
  finish(r,mode);
}

function finish(r,mode){
  const v=el('verdict');
  if(r.mint_status && r.mint_status!==200){
    v.className='verdict show fail';
    v.innerHTML='<h3>Denied at mint — before any token existed</h3><p>The workload asked for '+
      '<code>sales_regions: ["APAC"]</code>, but it is only attested for <code>["EMEA"]</code>. The '+
      'attester enforces <em>requested &sube; attested</em> and refused '+
      '(<code>'+ (r.mint_status||'') +' '+ (JSON.parse(r.mint_body||'{}').error||'') +'</code>) — so no '+
      'access token was ever issued for APAC, anywhere.</p>';
  } else if(r.pf_status===200){
    v.className='verdict show pass';
    v.innerHTML='<h3>Authenticated with a platform-attested identity</h3><p>This workload presented '+
      'only <em>what it is</em> — no client_id. The attester resolved that identity to '+
      (r.client_id ? '<code>'+r.client_id+'</code>' : 'an OAuth client')+' via its resolver plugins, '+
      'applied that client\'s entitlement ceiling, and PingFederate issued the token. The static '+
      'client_secret is a PingFederate requirement for this grant type, not part of the attestation '+
      'design — it carries no workload identity and no entitlement.</p>';
  } else {
    v.className='verdict show fail';
    v.innerHTML='<h3>Chain stopped</h3><p>See the step above for the response.</p>';
  }
  setBusy(false);
}

el('run').onclick  = ()=>run(null);
el('emea').onclick = ()=>run('emea');
el('apac').onclick = ()=>run('apac');

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
