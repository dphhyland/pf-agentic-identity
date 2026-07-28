"""A GKE chain agent. Plays agent A (originator) or agent C (delivery) by ROLE.

Both roles do the same two things, which is the point of the demo: a workload proves what it is with
platform evidence, turns that into a Client Attestation at its LOCAL attester, and then presents that
attestation as its only credential to whichever Authorization Server it needs to talk to — its own or
another cloud's. The attestation travels; only the PoP is minted per target, using the audience that
target advertises.

  ROLE=A  originator. Gets a token for itself (client_credentials) and hands it to agent B, the
          Bedrock AgentCore agent, over the AWS control API.
  ROLE=C  delegate. Receives a token issued by another cloud's AS, exchanges it (RFC 8693) at the AS
          named by EXCHANGE_BASE_URL, and calls the resource server with the result.
"""
import base64
import hashlib
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

ROLE = os.environ.get("ROLE", "A")
ATTESTER_BASE_URL = os.environ.get("ATTESTER_BASE_URL", "http://pingfederate.pf:9080")
TOKEN_FILE = os.environ.get("TOKEN_FILE", "/var/run/secrets/tokens/attester-token")
# Role A: the AS that issues its own token. Role C: the FOREIGN AS it exchanges at.
EXCHANGE_BASE_URL = os.environ.get("EXCHANGE_BASE_URL", "")
NEXT_HOP_URL = os.environ.get("NEXT_HOP_URL", "")
AGENTCORE_ARN = os.environ.get("AGENTCORE_ARN", "")
AWS_REGION = os.environ.get("AWS_REGION", "ap-southeast-2")


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


class InstanceKey:
    """The per-instance key the attestation is bound to (cnf) and the PoP is signed with."""

    def __init__(self):
        self.private = ec.generate_private_key(ec.SECP256R1())
        numbers = self.private.public_key().public_numbers()
        self.jwk = {"kty": "EC", "crv": "P-256",
                    "x": b64url(numbers.x.to_bytes(32, "big")),
                    "y": b64url(numbers.y.to_bytes(32, "big"))}
        canonical = json.dumps({k: self.jwk[k] for k in ("crv", "kty", "x", "y")},
                               separators=(",", ":"), sort_keys=True)
        self.jwk["kid"] = b64url(hashlib.sha256(canonical.encode()).digest())

    def sign(self, header: dict, claims: dict) -> str:
        signing_input = b64url(json.dumps(header, separators=(",", ":")).encode()) + "." + \
            b64url(json.dumps(claims, separators=(",", ":")).encode())
        der = self.private.sign(signing_input.encode(), ec.ECDSA(hashes.SHA256()))
        r, s = decode_dss_signature(der)
        return signing_input + "." + b64url(r.to_bytes(32, "big") + s.to_bytes(32, "big"))


INSTANCE_KEY = InstanceKey()


def http(method, url, body=None, form=None, headers=None, timeout=25):
    data = None
    hdrs = dict(headers or {})
    if body is not None:
        data = json.dumps(body).encode()
        hdrs["Content-Type"] = "application/json"
    elif form is not None:
        data = urllib.parse.urlencode(form).encode()
        hdrs["Content-Type"] = "application/x-www-form-urlencoded"
    req = urllib.request.Request(url, data=data, method=method, headers=hdrs)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()
    except Exception as e:  # noqa: BLE001
        return -1, str(e)


def claims_of(compact_jwt: str) -> dict:
    part = compact_jwt.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))


def attest(target_pop_audience: str) -> tuple:
    """Mint a Client Attestation at the LOCAL attester and a PoP bound to `target_pop_audience`.

    The attestation is target-independent — the same one would be accepted by any AS in the
    federation. The PoP is what pins this presentation to one AS.
    """
    status, body = http("GET", ATTESTER_BASE_URL + "/.well-known/client-attester")
    doc = json.loads(body)
    with open(TOKEN_FILE) as handle:
        evidence = handle.read().strip()

    now = int(time.time())
    challenge = None
    status, body = http("POST", doc["challenge_endpoint"])
    if status == 200:
        challenge = json.loads(body).get("attestation_challenge")
    proof_claims = {"aud": doc["evidence_audience"], "jti": str(uuid.uuid4()), "iat": now}
    if challenge:
        proof_claims["challenge"] = challenge
    proof = INSTANCE_KEY.sign(
        {"alg": "ES256", "typ": "oauth-attestation-instance-proof+jwt", "kid": INSTANCE_KEY.jwk["kid"]},
        proof_claims)

    status, body = http("POST", doc["attestation_endpoint"],
                        body={"instance_key": INSTANCE_KEY.jwk, "svid": evidence, "proof": proof})
    if status != 200:
        raise RuntimeError("attestation minting failed: %s %s" % (status, body[:200]))
    attestation = json.loads(body)["attestation"]
    client_id = claims_of(attestation)["sub"]
    pop = INSTANCE_KEY.sign(
        {"alg": "ES256", "typ": "oauth-client-attestation-pop+jwt", "kid": INSTANCE_KEY.jwk["kid"]},
        {"iss": client_id, "aud": target_pop_audience, "jti": str(uuid.uuid4()), "iat": now})
    return attestation, pop, client_id


def discovery_of(base_url: str) -> dict:
    status, body = http("GET", base_url + "/.well-known/client-attester")
    return json.loads(body)


def run_role_a() -> dict:
    """Originator: get a token for myself, then hand it to agent B in AWS."""
    local = discovery_of(ATTESTER_BASE_URL)
    attestation, pop, client_id = attest(local["pop_audience"])
    status, body = http("POST", local["token_endpoint"], form={"grant_type": "client_credentials"},
                        headers={"OAuth-Client-Attestation": attestation,
                                 "OAuth-Client-Attestation-PoP": pop})
    trace = {"agent": "A (GKE payment agent)", "client_id": client_id,
             "token_status": status, "as": local["pop_audience"]}
    if status != 200:
        trace["error"] = body[:300]
        return {"ok": False, "trace": [trace]}
    token1 = json.loads(body)["access_token"]
    trace["token_claims"] = {k: claims_of(token1).get(k) for k in ("sub", "client_id", "act", "iss")}

    # Hand off to agent B. AgentCore runtimes are reachable only through the AWS API, so this hop
    # is a signed AWS call rather than plain HTTP — the delegation still rides in subject_token.
    import boto3
    client = boto3.client("bedrock-agentcore", region_name=AWS_REGION)
    response = client.invoke_agent_runtime(
        agentRuntimeArn=AGENTCORE_ARN,
        payload=json.dumps({"subject_token": token1}).encode(),
        contentType="application/json")
    downstream = json.loads(response["response"].read())
    return {"ok": downstream.get("ok", False),
            "trace": [trace] + downstream.get("trace", []),
            "resource": downstream.get("resource")}


def run_role_c(subject_token: str) -> dict:
    """Delegate: exchange a foreign-issued token at the foreign AS, then call the resource."""
    foreign = discovery_of(EXCHANGE_BASE_URL)
    attestation, pop, client_id = attest(foreign["pop_audience"])
    status, body = http(
        "POST", foreign["token_endpoint"],
        form={"grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
              "subject_token": subject_token,
              "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
              "requested_token_type": "urn:ietf:params:oauth:token-type:access_token"},
        headers={"OAuth-Client-Attestation": attestation, "OAuth-Client-Attestation-PoP": pop})
    trace = {"agent": "C (GKE delivery agent)", "client_id": client_id,
             "exchange_status": status, "as": foreign["pop_audience"]}
    if status != 200:
        trace["error"] = body[:300]
        return {"ok": False, "trace": [trace]}
    token3 = json.loads(body)["access_token"]
    trace["token_claims"] = {k: claims_of(token3).get(k) for k in ("sub", "client_id", "act", "iss")}

    status, body = http("POST", NEXT_HOP_URL, body={"amount": 250, "currency": "AUD"},
                        headers={"Authorization": "Bearer " + token3})
    try:
        resource_result = json.loads(body)
    except Exception:  # noqa: BLE001
        resource_result = {"raw": body[:300]}
    trace["resource_status"] = status
    return {"ok": status == 200, "trace": [trace], "resource": resource_result}


CONSOLE_HTML = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Cross-cloud agent chain - live demo</title><style>
:root{--bg:#fbfbfa;--fg:#1a1a1a;--mut:#666;--line:#e3e3e0;--gcp:#4285f4;--aws:#ff9900;--ok:#0a7c42;--no:#b3261e;--card:#fff}
@media(prefers-color-scheme:dark){:root{--bg:#16171a;--fg:#e8e8e6;--mut:#9a9a96;--line:#2c2d31;--card:#1e1f23}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);
font:16px/1.6 ui-serif,Georgia,serif;padding:2rem 1.25rem 4rem}
.w{max-width:60rem;margin:0 auto}h1{font-size:1.6rem;margin:0 0 .3rem}
.lede{color:var(--mut);margin:0 0 1.5rem}
button{font:600 15px ui-sans-serif,system-ui;background:var(--fg);color:var(--bg);border:0;
border-radius:7px;padding:.7rem 1.3rem;cursor:pointer}button[disabled]{opacity:.5;cursor:default}
.diagram{margin:1.5rem 0 .4rem;overflow-x:auto}
.diagram svg{min-width:34rem}
.t{font-family:ui-sans-serif,system-ui;fill:var(--fg)}
.t.b{font-size:14px;font-weight:650}
.t.s{font-size:11.5px;fill:var(--mut)}
.t.lane{font-size:11px;font-weight:700;letter-spacing:.09em}
.cap{color:var(--mut);font-size:13px;margin:0 0 1.4rem}
.hops{display:flex;flex-wrap:wrap;gap:.5rem;align-items:center;margin:1.5rem 0}
.hop{border:1px solid var(--line);border-radius:8px;padding:.5rem .8rem;background:var(--card);
font:13px ui-sans-serif,system-ui;min-width:9rem}
.hop b{display:block;font-size:12px;letter-spacing:.04em;text-transform:uppercase;color:var(--mut)}
.gcp{border-left:3px solid var(--gcp)}.aws{border-left:3px solid var(--aws)}
.arw{color:var(--mut)}
.card{border:1px solid var(--line);border-radius:10px;background:var(--card);padding:1rem 1.1rem;margin:.7rem 0}
.card h3{margin:0 0 .5rem;font-size:1rem}
code,pre{font:13px ui-monospace,SFMono-Regular,Menlo,monospace}
pre{overflow-x:auto;background:rgba(127,127,127,.09);padding:.7rem;border-radius:6px;margin:.4rem 0}
.kv{color:var(--mut);font:12px ui-sans-serif,system-ui;letter-spacing:.03em;text-transform:uppercase}
.ok{color:var(--ok);font-weight:700}.no{color:var(--no);font-weight:700}
.chain{list-style:none;padding:0;margin:.3rem 0}
.chain li{padding:.25rem 0 .25rem 1.1rem;border-left:2px solid var(--line);margin-left:.5rem}
.foot{color:var(--mut);font-size:13px;margin-top:2rem;border-top:1px solid var(--line);padding-top:1rem}
</style></head><body><div class="w">
<h1>Cross-cloud agent chain</h1>
<p class="lede">One request, four parties, two clouds, two Authorization Servers - and no agent holds a secret.
Each agent proves what it is to its own cloud's attester, then presents that attestation to whichever
Authorization Server it needs.</p>
<div class="diagram"><svg viewBox="0 0 880 500" width="100%" role="img"
 aria-label="Swimlane diagram: agents in Google Cloud and AWS, with a federation controller above both">
 <defs><marker id="a" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7"
  orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="var(--mut)"/></marker></defs>
 <!-- federation controller, above both clouds -->
 <rect x="270" y="8" width="340" height="46" rx="8" fill="var(--card)" stroke="#7b5cff" stroke-width="2"/>
 <text x="440" y="27" text-anchor="middle" class="t b">OpenID Federation controller</text>
 <text x="440" y="44" text-anchor="middle" class="t s">trust anchor &middot; vouches for each member's keys</text>
 <path d="M400,54 L250,92" stroke="#7b5cff" stroke-width="1.5" stroke-dasharray="4 3" fill="none"/>
 <path d="M480,54 L640,92" stroke="#7b5cff" stroke-width="1.5" stroke-dasharray="4 3" fill="none"/>
 <!-- cloud lanes -->
 <rect x="20" y="92" width="400" height="392" rx="10" fill="none" stroke="var(--gcp)" stroke-width="1.5" opacity=".55"/>
 <rect x="460" y="92" width="400" height="392" rx="10" fill="none" stroke="var(--aws)" stroke-width="1.5" opacity=".55"/>
 <text x="34" y="112" class="t lane" fill="var(--gcp)">GOOGLE CLOUD</text>
 <text x="474" y="112" class="t lane" fill="var(--aws)">AWS</text>
 <!-- nodes -->
 <rect x="50" y="130" width="180" height="46" rx="7" fill="var(--card)" stroke="var(--gcp)" stroke-width="2"/>
 <text x="140" y="149" text-anchor="middle" class="t b">Agent A</text>
 <text x="140" y="166" text-anchor="middle" class="t s">GKE payment-agent</text>
 <rect x="600" y="130" width="200" height="46" rx="7" fill="var(--card)" stroke="var(--aws)" stroke-width="2"/>
 <text x="700" y="149" text-anchor="middle" class="t b">Agent B</text>
 <text x="700" y="166" text-anchor="middle" class="t s">Bedrock AgentCore</text>
 <rect x="200" y="250" width="180" height="46" rx="7" fill="var(--card)" stroke="var(--gcp)" stroke-width="2"/>
 <text x="290" y="269" text-anchor="middle" class="t b">Agent C</text>
 <text x="290" y="286" text-anchor="middle" class="t s">GKE delivery-agent</text>
 <rect x="50" y="400" width="230" height="46" rx="7" fill="var(--card)" stroke="#ea4335" stroke-width="2"/>
 <text x="165" y="419" text-anchor="middle" class="t b">Google Authorization Server</text>
 <text x="165" y="436" text-anchor="middle" class="t s">also hosts the controller</text>
 <rect x="600" y="330" width="220" height="46" rx="7" fill="var(--card)" stroke="#ea4335" stroke-width="2"/>
 <text x="710" y="349" text-anchor="middle" class="t b">AWS Authorization Server</text>
 <text x="710" y="366" text-anchor="middle" class="t s">federation leaf</text>
 <rect x="600" y="420" width="220" height="46" rx="7" fill="var(--card)" stroke="#0a7c42" stroke-width="2"/>
 <text x="710" y="439" text-anchor="middle" class="t b">Mock resource</text>
 <text x="710" y="456" text-anchor="middle" class="t s">verifies + decides</text>
 <!-- steps -->
 <path d="M110,176 L110,400" stroke="var(--mut)" stroke-width="1.5" fill="none" marker-end="url(#a)"/>
 <text x="118" y="350" class="t s">1 &middot; token for itself</text>
 <path d="M230,148 L600,148" stroke="var(--mut)" stroke-width="1.5" fill="none" marker-end="url(#a)"/>
 <text x="415" y="141" text-anchor="middle" class="t s">2 &middot; call</text>
 <path d="M640,176 Q470,250 280,405" stroke="var(--mut)" stroke-width="1.5" fill="none" marker-end="url(#a)"/>
 <text x="452" y="243" text-anchor="middle" class="t s">3 &middot; exchange, AWS-attested &rarr; act {B,{A}}</text>
 <path d="M600,168 L380,262" stroke="var(--mut)" stroke-width="1.5" fill="none" marker-end="url(#a)"/>
 <text x="470" y="205" text-anchor="middle" class="t s">4 &middot; call</text>
 <path d="M300,296 Q450,315 600,345" stroke="var(--mut)" stroke-width="1.5" fill="none" marker-end="url(#a)"/>
 <text x="425" y="313" text-anchor="middle" class="t s">5 &middot; exchange, GCP-attested &rarr; act {C,{B,{A}}}</text>
 <path d="M280,296 Q400,430 600,440" stroke="var(--mut)" stroke-width="1.5" fill="none" marker-end="url(#a)"/>
 <text x="420" y="415" text-anchor="middle" class="t s">6 &middot; Bearer + act chain</text>
</svg></div>
<p class="cap">Every arrow that crosses a lane is an agent authenticating to the <em>other</em> cloud's
Authorization Server with a credential attested in its own. Steps 3 and 5 are the exchanges; the dashed
lines are what makes them checkable.</p>
<div class="card" style="border-left:3px solid #7b5cff">
<h3>Behind all of it: a federation controller</h3>
<p style="margin:.2rem 0 .6rem">None of these agents were pre-registered with the other cloud's
Authorization Server. What makes a foreign attestation checkable is an <b>OpenID Federation
controller</b> - the trust anchor - which publishes a signed statement about every member carrying
<em>that member's own</em> keys. A verifier walks the chain rather than trusting a pasted key file.
In this deployment the GCP Authorization Server plays that role; the AWS one is a leaf beneath it.</p>
<div class="kv">the controller's endpoints</div>
<pre>GET /.well-known/openid-federation   the anchor's own entity statement
GET /federation/list                 who is in the federation
GET /federation/fetch?iss=&amp;sub=      the anchor's statement about a member
GET /federation/resolve?sub=         the assembled trust chain</pre>
<div class="kv" style="margin-top:.5rem">each member also publishes its attester's keys</div>
<pre>metadata.oauth_client_attester.jwks</pre>
<p style="margin:.5rem 0 0;color:var(--mut);font-size:13px">Remove a member from the controller and
its agents stop resolving everywhere in the federation - the revocation point for cross-cloud trust.</p>
</div>
<button id="go">Run the chain</button>
<div id="out"></div>
<p class="foot">Every hop is real: live attestation against each cloud's platform evidence, RFC 8693
token exchange at each Authorization Server, and a resource that verifies the token against the
issuer's published keys before deciding.</p>
</div><script>
const esc=s=>String(s).replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));
function chainList(a){if(!a||!a.length)return '<em>none</em>';
 return '<ul class="chain">'+a.map((x,i)=>'<li>'+(i===0?'presented by ':'via ')+'<code>'+esc(x.sub)+'</code></li>').join('')+'</ul>';}
document.getElementById('go').onclick=async e=>{
 const b=e.target,o=document.getElementById('out');
 b.disabled=true;b.textContent='Running the chain...';o.innerHTML='';
 try{
  const r=await fetch('/run',{method:'POST'});const d=await r.json();
  let h='';
  (d.trace||[]).forEach(t=>{
   const cloud=(t.agent||'').includes('AgentCore')?'aws':'gcp';
   const c=t.token_claims||{};
   h+='<div class="card '+cloud+'"><h3>'+esc(t.agent||'')+'</h3>'
    +'<div class="kv">authenticated as</div><code>'+esc(t.client_id||'-')+'</code>'
    +'<div class="kv" style="margin-top:.5rem">authorization server</div><code>'+esc(t.as||'-')+'</code>'
    +(t.attested_by?'<div class="kv" style="margin-top:.5rem">attested at</div><code>'+esc(t.attested_by)+'</code>':'')
    +'<div class="kv" style="margin-top:.5rem">token it received</div>'
    +'<pre>sub: '+esc(c.sub||'-')+'\\nact: '+esc(c.act||'-')+'</pre></div>';});
  const R=d.resource;
  if(R){const al=R.decision&&R.decision.allowed;
   h+='<div class="card aws"><h3>Resource decision (AWS)</h3>'
    +'<div class="kv">on behalf of</div><code>'+esc(R.on_behalf_of||'-')+'</code>'
    +'<div class="kv" style="margin-top:.5rem">actor chain</div>'+chainList(R.actor_chain)
    +'<div class="kv" style="margin-top:.5rem">decision</div>'
    +'<span class="'+(al?'ok':'no')+'">'+(al?'ALLOWED':'DENIED')+'</span> '
    +'<span style="color:var(--mut)">- '+esc((R.decision||{}).reason||'')+'</span>'
    +(R.settled?'<pre>settled '+esc(JSON.stringify(R.settled))+'</pre>':'')+'</div>';}
  o.innerHTML=h||'<div class="card">No trace returned.</div>';
 }catch(err){o.innerHTML='<div class="card"><span class="no">Failed</span> '+esc(err)+'</div>';}
 b.disabled=false;b.textContent='Run the chain again';};
</script></body></html>"""


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, obj):
        payload = json.dumps(obj, indent=1).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        if ROLE != "A":
            self._send(200, {"role": ROLE, "healthy": True})
            return
        page = CONSOLE_HTML.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(page)))
        self.end_headers()
        self.wfile.write(page)

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b"{}"
        try:
            request = json.loads(raw or b"{}")
        except Exception:  # noqa: BLE001
            request = {}
        try:
            if ROLE == "A":
                self._send(200, run_role_a())
            else:
                subject_token = request.get("subject_token")
                if not subject_token:
                    self._send(400, {"error": "subject_token required"})
                    return
                self._send(200, run_role_c(subject_token))
        except Exception as e:  # noqa: BLE001
            self._send(500, {"error": str(e)})

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    ThreadingHTTPServer(("", 8080), Handler).serve_forever()
