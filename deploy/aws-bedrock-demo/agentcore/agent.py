"""Bedrock AgentCore agent that authenticates to PingFederate with an AWS-attested identity.

AgentCore's own workload access token is opaque and first-party only, so it cannot be presented to an
external authorization server. What an AgentCore agent DOES have is an IAM execution role, so it calls
`sts:GetWebIdentityToken` (AWS Outbound Identity Federation) to obtain an AWS-signed OIDC JWT whose `sub`
is the role ARN. That JWT is the evidence.

The chain is the same as every other workload: discover the attester, present evidence with no client_id,
mint a Client Attestation, then call PF's token endpoint with the two attestation headers and nothing else.

Prerequisites (once per account): `aws iam enable-outbound-web-identity-federation`, and the agent's
execution role needs `sts:GetWebIdentityToken`.
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

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

ATTESTER_BASE_URL = os.environ["ATTESTER_BASE_URL"].rstrip("/")
PF_TOKEN_AUD = os.environ.get("PF_TOKEN_AUD", "https://localhost:9031")
AWS_REGION = os.environ.get("AWS_REGION", "us-east-1")


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


class InstanceKey:
    """A fresh P-256 key the workload generates; the attestation is bound to it via cnf."""

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


def web_identity_token(audience: str) -> str:
    """The AWS evidence: an AWS-signed OIDC JWT for the agent's IAM execution role, with our attester as
    the audience. Works on any AWS runtime that has ambient IAM credentials, AgentCore included."""
    import boto3
    sts = boto3.client("sts", region_name=AWS_REGION)
    # AWS Outbound Identity Federation. The token's sub is the caller's role ARN; aud is what we pass here.
    # Audience is a list and SigningAlgorithm is required (RS256 or ES384).
    response = sts.get_web_identity_token(Audience=[audience], SigningAlgorithm="RS256")
    return response["WebIdentityToken"]


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

    evidence = web_identity_token(audience)

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
    result = {"evidence_mode": "aws-sts-web-identity", "mint_status": mint_status, "mint_body": mint_body}
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


if __name__ == "__main__":
    out = invoke(requested_details=[{"type": "sales_agent", "sales_regions": ["EMEA"]}])
    print(json.dumps({k: out.get(k) for k in ("evidence_mode", "client_id", "mint_status", "pf_status", "pf_body")},
                     indent=2))
