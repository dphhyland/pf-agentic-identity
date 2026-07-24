"""Railway-hosted demo workload — the same evidence-first chain, but off Google entirely.

Railway gives a workload no SPIFFE/SPIRE or Google identity, so this workload plays the SPIRE role
itself: it signs a JWT-SVID for a demo trust domain (railway.demo) with a key whose PUBLIC half the
attester trusts via the CIMD document. It then runs the identical chain — evidence → mint → token —
presenting NO client_id; the attester maps spiffe://railway.demo/workload/payment-agent → its OAuth
client via the CIMD. Serves the live console at GET /.

This shows the model is portable: any platform that can vouch for a workload's identity plugs in the
same way; here the "platform" is a demo trust-domain key, but the attester side is unchanged.
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

ATTESTER_BASE_URL = os.environ.get("ATTESTER_BASE_URL", "http://35.223.142.97")
PF_TOKEN_ENDPOINT = os.environ.get("PF_TOKEN_ENDPOINT", ATTESTER_BASE_URL + "/as/token.oauth2")
PF_TOKEN_AUD = os.environ.get("PF_TOKEN_AUD", "https://localhost:9031")
CLIENT_SECRET = os.environ.get("CLIENT_SECRET", "demo-secret-123")
SPIFFE_ID = os.environ.get("SPIFFE_ID", "spiffe://railway.demo/workload/payment-agent")
# The demo trust-domain PRIVATE JWK (JSON). Its public half is in the CIMD the attester trusts.
TD_PRIVATE_JWK = os.environ.get("TD_PRIVATE_JWK", "")
PORT = int(os.environ.get("PORT", "8080"))


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_int(v: str) -> int:
    pad = v + "=" * (-len(v) % 4)
    return int.from_bytes(base64.urlsafe_b64decode(pad), "big")


class EcSigner:
    """Signs compact ES256 JWS from an inline EC private JWK."""

    def __init__(self, jwk: dict):
        d = _b64url_int(jwk["d"])
        self.kid = jwk.get("kid")
        self.key = ec.derive_private_key(d, ec.SECP256R1())

    def sign(self, header: dict, claims: dict) -> str:
        si = b64url(json.dumps(header, separators=(",", ":")).encode()) + "." + \
            b64url(json.dumps(claims, separators=(",", ":")).encode())
        der = self.key.sign(si.encode(), ec.ECDSA(hashes.SHA256()))
        r, s = decode_dss_signature(der)
        return si + "." + b64url(r.to_bytes(32, "big") + s.to_bytes(32, "big"))


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
        si = b64url(json.dumps(header, separators=(",", ":")).encode()) + "." + \
            b64url(json.dumps(claims, separators=(",", ":")).encode())
        der = self.private.sign(si.encode(), ec.ECDSA(hashes.SHA256()))
        r, s = decode_dss_signature(der)
        return si + "." + b64url(r.to_bytes(32, "big") + s.to_bytes(32, "big"))


TD_SIGNER = EcSigner(json.loads(TD_PRIVATE_JWK)) if TD_PRIVATE_JWK else None
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


def _sub(compact_jwt):
    p = compact_jwt.split(".")[1]
    p += "=" * (-len(p) % 4)
    return json.loads(base64.urlsafe_b64decode(p)).get("sub")


def make_svid(audience: str) -> str:
    """This workload IS its own SPIFFE issuer: a JWT-SVID for railway.demo signed by the demo TD key."""
    now = int(time.time())
    return TD_SIGNER.sign(
        {"alg": "ES256", "typ": "JWT", "kid": TD_SIGNER.kid},
        {"sub": SPIFFE_ID, "aud": [audience], "iat": now, "exp": now + 300})


def discovery() -> dict:
    status, body = http_json("GET", ATTESTER_BASE_URL + "/.well-known/client-attester")
    if status != 200:
        raise RuntimeError(f"attester discovery failed: HTTP {status} {body}")
    doc = json.loads(body)
    if "evidence_audience" not in doc:
        raise RuntimeError("attester advertises no evidence_audience")
    return doc


def invoke(requested_details=None) -> dict:
    doc = discovery()
    audience = doc["evidence_audience"]
    now = int(time.time())
    evidence = make_svid(audience)

    challenge = None
    status, body = http_json("POST", doc["challenge_endpoint"])
    if status == 200:
        challenge = json.loads(body).get("attestation_challenge")
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
    result = {"evidence_mode": "spiffe-jwt", "evidence": evidence, "discovery": doc,
              "challenge": challenge, "proof": proof, "mint_status": mint_status, "mint_body": mint_body}
    if mint_status != 200:
        return result

    attestation = json.loads(mint_body)["attestation"]
    client_id = _sub(attestation)
    pop = INSTANCE_KEY.sign(
        {"alg": "ES256", "typ": "oauth-client-attestation-pop+jwt", "kid": INSTANCE_KEY.jwk["kid"]},
        {"iss": client_id, "aud": PF_TOKEN_AUD, "jti": str(uuid.uuid4()), "iat": now})
    pf_status, pf_body = http_json(
        "POST", PF_TOKEN_ENDPOINT,
        form={"grant_type": "client_credentials", "client_id": client_id, "client_secret": CLIENT_SECRET},
        headers={"OAuth-Client-Attestation": attestation, "OAuth-Client-Attestation-PoP": pop})
    result.update({"client_id": client_id, "attestation": attestation, "pop": pop,
                   "pf_status": pf_status, "pf_body": pf_body})
    return result


class Handler(BaseHTTPRequestHandler):
    def _json(self, code, obj):
        b = json.dumps(obj, indent=2).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def _html(self, html):
        b = html.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        if self.path == "/" or self.path.startswith("/?"):
            from console import CONSOLE_HTML
            return self._html(CONSOLE_HTML)
        if self.path.startswith("/identity"):
            return self._json(200, {"status": "up", "evidence_mode": "spiffe-jwt", "spiffe_id": SPIFFE_ID,
                                    "instance_key_kid": INSTANCE_KEY.jwk["kid"],
                                    "trust_domain_key_configured": TD_SIGNER is not None})
        return self._json(200, {"status": "up", "evidence_mode": "spiffe-jwt"})

    def do_POST(self):
        if self.path.startswith("/invoke"):
            length = int(self.headers.get("Content-Length") or 0)
            requested = None
            if length:
                try:
                    requested = json.loads(self.rfile.read(length)).get("authorization_details")
                except Exception:  # noqa: BLE001
                    pass
            if TD_SIGNER is None:
                return self._json(500, {"error": "TD_PRIVATE_JWK not configured"})
            try:
                return self._json(200, invoke(requested))
            except Exception as e:  # noqa: BLE001
                return self._json(500, {"error": str(e)})
        return self._json(404, {"error": "not_found"})

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    print(f"[railway-workload] spiffe_id={SPIFFE_ID} attester={ATTESTER_BASE_URL} · POST /invoke", flush=True)
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
