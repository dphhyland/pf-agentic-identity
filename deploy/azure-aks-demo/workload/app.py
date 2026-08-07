"""AKS workload that authenticates to PingFederate with its Workload Identity Federation identity.

The AKS analogue of the GKE/EKS agents. The pod mounts a projected service-account token with the attester
as its audience (see workload.yaml). That token is a JWT signed by the AKS cluster's OIDC issuer; the
attester validates it against the cluster's public JWKS and maps system:serviceaccount:<ns>:<sa> to a
SPIFFE ID — the identical shape GKE/EKS use, so a resource-side policy written against that shape already
works across all three clouds.

Same chain as every other workload: discover, present evidence with no client_id, mint, then call the token
endpoint with the two attestation headers and nothing else. Serves a tiny JSON endpoint at POST /invoke.

This is the PLAIN evidence-only demo (no A2A, no asserted context) — see ../agent-runtime/gateway.py for
the A2A-fronted gateway that also threads an asserted Entra Agent ID through.
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

ATTESTER_BASE_URL = os.environ["ATTESTER_BASE_URL"].rstrip("/")
PF_TOKEN_AUD = os.environ.get("PF_TOKEN_AUD", "https://localhost:9031")
TOKEN_FILE = os.environ.get("AKS_TOKEN_FILE", "/var/run/secrets/tokens/attester-token")
PORT = int(os.environ.get("PORT", "8080"))


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


class InstanceKey:
    def __init__(self):
        self.private = ec.generate_private_key(ec.SECP256R1())
        n = self.private.public_key().public_numbers()
        self.jwk = {"kty": "EC", "crv": "P-256",
                    "x": b64url(n.x.to_bytes(32, "big")), "y": b64url(n.y.to_bytes(32, "big"))}
        canon = json.dumps({k: self.jwk[k] for k in ("crv", "kty", "x", "y")},
                           separators=(",", ":"), sort_keys=True)
        self.jwk["kid"] = b64url(hashlib.sha256(canon.encode()).digest())

    def sign(self, header, claims):
        signing_input = b64url(json.dumps(header, separators=(",", ":")).encode()) + "." + \
            b64url(json.dumps(claims, separators=(",", ":")).encode())
        der = self.private.sign(signing_input.encode(), ec.ECDSA(hashes.SHA256()))
        r, s = decode_dss_signature(der)
        return signing_input + "." + b64url(r.to_bytes(32, "big") + s.to_bytes(32, "big"))


INSTANCE_KEY = InstanceKey()


def http_json(method, url, body=None, headers=None, form=None):
    data, hdrs = None, dict(headers or {})
    if body is not None:
        data = json.dumps(body).encode()
        hdrs["Content-Type"] = "application/json"
    elif form is not None:
        data = urllib.parse.urlencode(form).encode()
        hdrs["Content-Type"] = "application/x-www-form-urlencoded"
    req = urllib.request.Request(url, data=data, method=method, headers=hdrs)
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()
    except Exception as e:  # noqa: BLE001
        return -1, str(e)


def aks_projected_token() -> str:
    """The AKS Workload Identity Federation evidence: a projected SA token, read fresh so kubelet rotation
    is picked up. Its audience is set to the attester on the pod's serviceAccountToken volume."""
    with open(TOKEN_FILE, "r", encoding="utf-8") as handle:
        return handle.read().strip()


def _sub(compact_jwt: str) -> str:
    payload = compact_jwt.split(".")[1]
    payload += "=" * (-len(payload) % 4)
    return json.loads(base64.urlsafe_b64decode(payload)).get("sub")


def invoke(requested_details=None) -> dict:
    status, body = http_json("GET", ATTESTER_BASE_URL + "/.well-known/client-attester")
    if status != 200:
        return {"step": "discover", "status": status, "body": body}
    doc = json.loads(body)
    audience = doc["evidence_audience"]

    evidence = aks_projected_token()

    challenge = None
    status, body = http_json("POST", doc["challenge_endpoint"])
    if status == 200:
        challenge = json.loads(body).get("attestation_challenge")

    now = int(time.time())
    proof_claims = {"aud": audience, "jti": str(uuid.uuid4()), "iat": now}
    if challenge:
        proof_claims["challenge"] = challenge
    proof = INSTANCE_KEY.sign(
        {"alg": "ES256", "typ": "oauth-attestation-instance-proof+jwt", "kid": INSTANCE_KEY.jwk["kid"]},
        proof_claims)

    issuance = {"instance_key": INSTANCE_KEY.jwk, "svid": evidence, "proof": proof}
    if requested_details:
        issuance["authorization_details"] = requested_details
    mint_status, mint_body = http_json("POST", doc["attestation_endpoint"], body=issuance)
    result = {"evidence_mode": "aks-sa-token", "mint_status": mint_status, "mint_body": mint_body}
    if mint_status != 200:
        return result

    attestation = json.loads(mint_body)["attestation"]
    client_id = _sub(attestation)
    pop_aud = doc.get("pop_audience") or PF_TOKEN_AUD
    pop = INSTANCE_KEY.sign(
        {"alg": "ES256", "typ": "oauth-client-attestation-pop+jwt", "kid": INSTANCE_KEY.jwk["kid"]},
        {"iss": client_id, "aud": pop_aud, "jti": str(uuid.uuid4()), "iat": now})
    token_endpoint = doc.get("token_endpoint") or (ATTESTER_BASE_URL + "/as/token.oauth2")
    pf_status, pf_body = http_json(
        "POST", token_endpoint, form={"grant_type": "client_credentials"},
        headers={"OAuth-Client-Attestation": attestation, "OAuth-Client-Attestation-PoP": pop})
    result.update({"client_id": client_id, "pf_status": pf_status, "pf_body": pf_body})
    return result


class Handler(BaseHTTPRequestHandler):
    def _json(self, code, obj):
        b = json.dumps(obj, indent=2).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        self._json(200, {"status": "up", "evidence_mode": "aks-sa-token"})

    def do_POST(self):
        if self.path.startswith("/invoke"):
            length = int(self.headers.get("Content-Length") or 0)
            requested = None
            if length:
                try:
                    requested = json.loads(self.rfile.read(length)).get("authorization_details")
                except Exception:  # noqa: BLE001
                    pass
            return self._json(200, invoke(requested))
        return self._json(404, {"error": "not_found"})

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    print(f"[aks-workload] attester={ATTESTER_BASE_URL} token_file={TOKEN_FILE} · POST /invoke", flush=True)
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
