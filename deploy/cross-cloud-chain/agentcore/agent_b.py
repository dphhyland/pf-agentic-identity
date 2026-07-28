"""Agent B — the Bedrock AgentCore runtime, the AWS hop in the middle of the chain.

Receives a token issued by the GCP Authorization Server, proves what it is with AWS-native evidence
(sts:GetWebIdentityToken), attests at its LOCAL attester, and then presents that attestation to the
GCP Authorization Server to exchange the token it was given. Nothing about B is registered in GCP
beyond its client record: the attestation is what makes it recognisable there, and the trust in the
attester comes through the federation.

AgentCore's contract: GET /ping and POST /invocations on 8080, ARM64 container, HTTP protocol.
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

import boto3
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

ATTESTER_BASE_URL = os.environ["ATTESTER_BASE_URL"]      # B's own (AWS) attester
EXCHANGE_BASE_URL = os.environ["EXCHANGE_BASE_URL"]      # the GCP AS it exchanges at
NEXT_HOP_URL = os.environ.get("NEXT_HOP_URL", "")        # agent C
AWS_REGION = os.environ.get("AWS_REGION", "ap-southeast-2")


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


class InstanceKey:
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


def handle(subject_token: str = None) -> dict:
    """With a subject_token, act as chain agent B. Without one, run the standalone AWS attestation
    demo (client_credentials at the local AS) that this runtime served before it joined the chain —
    so `invoke_agent_runtime` with an empty payload keeps working as documented."""
    local = json.loads(http("GET", ATTESTER_BASE_URL + "/.well-known/client-attester")[1])
    foreign = json.loads(http("GET", EXCHANGE_BASE_URL + "/.well-known/client-attester")[1])

    # AWS-native evidence: an AWS-signed OIDC token for this agent's execution role.
    sts = boto3.client("sts", region_name=AWS_REGION)
    evidence = sts.get_web_identity_token(
        Audience=[local["evidence_audience"]], SigningAlgorithm="RS256")["WebIdentityToken"]

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
    status, body = http("POST", local["attestation_endpoint"],
                        body={"instance_key": INSTANCE_KEY.jwk, "svid": evidence, "proof": proof})
    if status != 200:
        return {"ok": False, "trace": [{"agent": "B (Bedrock AgentCore)", "mint_status": status,
                                        "error": body[:300]}]}
    attestation = json.loads(body)["attestation"]
    client_id = claims_of(attestation)["sub"]

    if not subject_token:
        # Standalone: get a token for myself at my OWN AS, no delegation involved.
        pop = INSTANCE_KEY.sign(
            {"alg": "ES256", "typ": "oauth-client-attestation-pop+jwt", "kid": INSTANCE_KEY.jwk["kid"]},
            {"iss": client_id, "aud": local["pop_audience"], "jti": str(uuid.uuid4()), "iat": now})
        status, body = http("POST", local["token_endpoint"], form={"grant_type": "client_credentials"},
                            headers={"OAuth-Client-Attestation": attestation,
                                     "OAuth-Client-Attestation-PoP": pop})
        return {"ok": status == 200, "mode": "standalone", "mint_status": 200, "pf_status": status,
                "client_id": client_id, "as": local["pop_audience"]}

    # The PoP is minted for the FOREIGN AS — that is the only per-target artifact.
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
    trace = {"agent": "B (Bedrock AgentCore)", "client_id": client_id,
             "exchange_status": status, "as": foreign["pop_audience"],
             "attested_by": local["pop_audience"]}
    if status != 200:
        trace["error"] = body[:300]
        return {"ok": False, "trace": [trace]}
    token2 = json.loads(body)["access_token"]
    trace["token_claims"] = {k: claims_of(token2).get(k) for k in ("sub", "client_id", "act", "iss")}

    if not NEXT_HOP_URL:
        return {"ok": True, "trace": [trace]}
    status, body = http("POST", NEXT_HOP_URL, body={"subject_token": token2}, timeout=60)
    try:
        downstream = json.loads(body)
    except Exception:  # noqa: BLE001
        downstream = {"ok": False, "trace": [{"agent": "C", "error": body[:300]}]}
    return {"ok": downstream.get("ok", False),
            "trace": [trace] + downstream.get("trace", []),
            "resource": downstream.get("resource")}


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, obj):
        payload = json.dumps(obj, indent=1).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        if self.path == "/ping":
            self._send(200, {"status": "healthy"})
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self):
        if self.path != "/invocations":
            self._send(404, {"error": "not found"})
            return
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b"{}"
        try:
            request = json.loads(raw or b"{}")
        except Exception:  # noqa: BLE001
            request = {}
        try:
            self._send(200, handle(request.get("subject_token")))
        except Exception as e:  # noqa: BLE001
            self._send(500, {"error": str(e)})

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    ThreadingHTTPServer(("", 8080), Handler).serve_forever()
