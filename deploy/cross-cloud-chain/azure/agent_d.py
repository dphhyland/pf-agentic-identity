"""Agent D — the Azure hop, and the last agent before the resource.

Receives a token issued by another cloud's Authorization Server, proves what it is with Azure-native
evidence (an AKS Workload Identity Federation projected SA token, or an Entra-signed managed-identity
token from Azure IMDS), attests at its LOCAL (Azure) attester, exchanges the token it was handed, and
forwards the request to the resource. Same shape as agent B: attest local, exchange foreign.

**It is a transparent interposer.** It accepts exactly the call agent C already makes to the resource —
`Authorization: Bearer <token>` plus the request body — and forwards exactly the call the resource
already expects. So inserting D between C and the resource is pure rewiring: point C's NEXT_HOP_URL at
D and give D the real RESOURCE_URL. No existing chain code changes.

**The Azure-specific bit.** Copilot Studio agents share one Microsoft-owned blueprint per tenant, so an
individual Copilot agent has no cryptographic evidence of its own — only THIS workload does. A Copilot
agent identity can therefore only ever be *asserted*. When an asserted Entra Agent ID `oid` is present
(request header `X-Copilot-Agent-Id`, else the ASSERTED_COPILOT_AGENT_ID default), D sends it as
`asserted_context` on the mint, and the attester's EntraDirectoryAssertedContextResolver resolves it
against its directory to NARROW — never extend — what D is entitled to. The narrowing therefore lands
mid-delegation, on a real chain, which is the point: it is not a special case bolted on at the edge.

Runs on AKS (projected token, see ../k8s/agent-d.yaml) or Azure Container Apps (IMDS). Evidence is
auto-detected in that order, so the same image serves both.
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

ATTESTER_BASE_URL = os.environ["ATTESTER_BASE_URL"]        # D's own (Azure) attester
EXCHANGE_BASE_URL = os.environ["EXCHANGE_BASE_URL"]        # the AS it exchanges at
NEXT_HOP_URL = os.environ.get("NEXT_HOP_URL", "")          # the real resource
TOKEN_FILE = os.environ.get("TOKEN_FILE", "/var/run/secrets/tokens/attester-token")
# Default asserted Entra Agent ID, when the caller does not supply one per-request. Unset means D
# presents only its own evidenced identity (no directory narrowing) — the honest default.
ASSERTED_COPILOT_AGENT_ID = os.environ.get("ASSERTED_COPILOT_AGENT_ID", "")
# Azure IMDS, for the Container Apps / VM / Functions deployment shape (no projected token file).
AZURE_IMDS_TOKEN = "http://169.254.169.254/metadata/identity/oauth2/token"
AZURE_IMDS_API_VERSION = "2018-02-01"
AZURE_CLIENT_ID = os.environ.get("AZURE_CLIENT_ID", "")    # selects a specific user-assigned identity


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


def claims_of(token: str) -> dict:
    part = token.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))


def azure_evidence(audience: str) -> tuple:
    """This workload's Azure-native evidence, and which shape produced it.

    AKS first (a projected SA token file, read fresh so kubelet rotation is picked up — the same
    mechanism GKE and EKS use), then Azure IMDS for non-Kubernetes compute. IMDS returns a JSON
    envelope rather than a raw JWT, which is the one place Azure's evidence differs in shape from
    GCP's metadata server.
    """
    if os.path.exists(TOKEN_FILE):
        with open(TOKEN_FILE) as handle:
            return handle.read().strip(), "aks-sa-token"
    params = {"api-version": AZURE_IMDS_API_VERSION, "resource": audience}
    if AZURE_CLIENT_ID:
        params["client_id"] = AZURE_CLIENT_ID
    status, body = http("GET", AZURE_IMDS_TOKEN + "?" + urllib.parse.urlencode(params),
                        headers={"Metadata": "true"}, timeout=10)
    if status != 200:
        raise RuntimeError("no Azure evidence: no %s and IMDS returned %s %s"
                           % (TOKEN_FILE, status, body[:200]))
    return json.loads(body)["access_token"], "azure-mi-token"


def handle(subject_token: str, asserted_oid: str, request_body: dict) -> tuple:
    """Attest with Azure evidence, exchange the token we were handed, forward to the resource.

    Returns (http_status, response_dict). The response mirrors what the resource returns, with D's own
    hop merged into a `trace` list so the chain console can render it.
    """
    local = json.loads(http("GET", ATTESTER_BASE_URL + "/.well-known/client-attester")[1])
    foreign = json.loads(http("GET", EXCHANGE_BASE_URL + "/.well-known/client-attester")[1])

    evidence, evidence_mode = azure_evidence(local["evidence_audience"])

    now = int(time.time())
    challenge = None
    status, body = http("POST", local["challenge_endpoint"])
    if status == 200:
        challenge = json.loads(body).get("attestation_challenge")
    proof_claims = {"aud": local["evidence_audience"], "jti": str(uuid.uuid4()), "iat": now}
    if challenge:
        proof_claims["challenge"] = challenge
    proof = INSTANCE_KEY.sign(
        {"alg": "ES256", "typ": "oauth-attestation-instance-proof+jwt", "kid": INSTANCE_KEY.jwk["kid"]},
        proof_claims)

    issuance = {"instance_key": INSTANCE_KEY.jwk, "svid": evidence, "proof": proof}
    if asserted_oid:
        # The unverified half. The attester labels it as such and may only narrow D's ceiling by it.
        issuance["asserted_context"] = {"type": "entra-copilot-agent-oid", "value": asserted_oid}
    status, body = http("POST", local["attestation_endpoint"], body=issuance)
    trace = {"agent": "D (Azure)", "evidence_mode": evidence_mode,
             "attested_by": local["pop_audience"], "as": foreign["pop_audience"],
             "asserted_copilot_agent_id": asserted_oid or None}
    if status != 200:
        trace["mint_status"] = status
        trace["error"] = body[:300]
        return 502, {"ok": False, "trace": [trace]}
    attestation = json.loads(body)["attestation"]
    attestation_claims = claims_of(attestation)
    client_id = attestation_claims["sub"]
    trace["client_id"] = client_id
    # What the attester actually vouched for, after any asserted-context narrowing — the honest record
    # of "evidenced identity here, asserted context there", kept distinguishable in the trace.
    trace["attested_authorization_details"] = attestation_claims.get("authorization_details")
    workload = attestation_claims.get("workload") or {}
    trace["asserted_by_attester"] = (workload.get("attributes") or {}).get("asserted")

    # The PoP is minted for the AS we are about to present at — the only per-target artifact.
    pop = INSTANCE_KEY.sign(
        {"alg": "ES256", "typ": "oauth-client-attestation-pop+jwt", "kid": INSTANCE_KEY.jwk["kid"]},
        {"iss": client_id, "aud": foreign["pop_audience"], "jti": str(uuid.uuid4()), "iat": now})

    status, body = http(
        "POST", foreign["token_endpoint"],
        form={"grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
              "subject_token": subject_token,
              "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
              "requested_token_type": "urn:ietf:params:oauth:token-type:access_token"},
        headers={"OAuth-Client-Attestation": attestation, "OAuth-Client-Attestation-PoP": pop})
    trace["exchange_status"] = status
    if status != 200:
        trace["error"] = body[:300]
        return 502, {"ok": False, "trace": [trace]}
    token4 = json.loads(body)["access_token"]
    trace["token_claims"] = {k: claims_of(token4).get(k) for k in ("sub", "client_id", "act", "iss")}

    if not NEXT_HOP_URL:
        return 200, {"ok": True, "trace": [trace]}
    status, body = http("POST", NEXT_HOP_URL, body=request_body,
                        headers={"Authorization": "Bearer " + token4}, timeout=60)
    try:
        downstream = json.loads(body)
    except Exception:  # noqa: BLE001
        downstream = {"error": body[:300]}
    # Pass the resource's own response through unchanged (the console reads on_behalf_of / actor_chain
    # / decision / settled off it) and add D's hop alongside it.
    downstream["trace"] = [trace] + (downstream.get("trace") or [])
    return status, downstream


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, obj):
        payload = json.dumps(obj, indent=1).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        self._send(200, {"agent": "D (Azure)", "healthy": True,
                         "attester": ATTESTER_BASE_URL, "exchanges_at": EXCHANGE_BASE_URL,
                         "asserted_copilot_agent_id": ASSERTED_COPILOT_AGENT_ID or None})

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b"{}"
        authorization = self.headers.get("Authorization") or ""
        if not authorization.startswith("Bearer "):
            self._send(401, {"error": "bearer token required"})
            return
        try:
            request_body = json.loads(raw or b"{}")
        except Exception:  # noqa: BLE001
            request_body = {}
        # Per-request beats the env default, so one deployment can demo both the narrowed and the
        # un-narrowed path without a redeploy.
        asserted = self.headers.get("X-Copilot-Agent-Id") or ASSERTED_COPILOT_AGENT_ID
        try:
            status, response = handle(authorization[7:].strip(), asserted, request_body)
            self._send(status, response)
        except Exception as e:  # noqa: BLE001
            self._send(500, {"error": str(e)})

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    ThreadingHTTPServer(("", 8080), Handler).serve_forever()
