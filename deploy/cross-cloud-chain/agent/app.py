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


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, obj):
        payload = json.dumps(obj, indent=1).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        self._send(200, {"role": ROLE, "healthy": True})

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
