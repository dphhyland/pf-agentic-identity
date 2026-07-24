"""GKE demo agent workload.

Bootstraps from PF's attester discovery document (/.well-known/client-attester, then the per-client
configuration endpoint it advertises), obtains
identity evidence — a SPIRE JWT-SVID from the Workload API (spiffe-jwt) or a GKE-projected
service-account token read from a file (gke-sa-token) — exchanges it at /federation/attestation for a
Client Attestation bound to a locally-generated instance key, and presents attestation + PoP to the
PingFederate token endpoint. POST /invoke runs the whole chain and returns every artifact.

Unlike the Railway harness agent this NEVER self-mints the attestation: the attester key lives only in
PF's client config, and this workload holds nothing but its own instance key and its platform identity.
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

ATTESTER_BASE_URL = os.environ.get("ATTESTER_BASE_URL", "http://pingfederate.pf:9080")
CLIENT_ID = os.environ.get("CLIENT_ID", "demo-attest-gke")
CLIENT_SECRET = os.environ.get("CLIENT_SECRET", "demo-secret-123")
PF_TOKEN_ENDPOINT = os.environ.get("PF_TOKEN_ENDPOINT", ATTESTER_BASE_URL + "/as/token.oauth2")
# PF validates the PoP `aud` against its configured base URL (the one inside data.zip), NOT the URL the
# request arrived on — the classic aud trap. Override if the archive's base differs.
PF_TOKEN_AUD = os.environ.get("PF_TOKEN_AUD", "https://localhost:9031")
EVIDENCE_MODE = os.environ.get("EVIDENCE_MODE")  # spiffe-jwt | gke-sa-token; default from discovery
TOKEN_FILE = os.environ.get("TOKEN_FILE", "/var/run/secrets/tokens/attester-token")
SPIFFE_SOCKET = os.environ.get("SPIFFE_ENDPOINT_SOCKET", "unix:///spiffe-workload-api/spire-agent.sock")
PORT = int(os.environ.get("PORT", "8080"))


# ── minimal JOSE (ES256 compact JWS with a locally-generated P-256 instance key) ─────────────────

def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


class InstanceKey:
    def __init__(self):
        self.private = ec.generate_private_key(ec.SECP256R1())
        numbers = self.private.public_key().public_numbers()
        self.jwk = {
            "kty": "EC", "crv": "P-256",
            "x": b64url(numbers.x.to_bytes(32, "big")),
            "y": b64url(numbers.y.to_bytes(32, "big")),
        }
        # RFC 7638 thumbprint as the kid.
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


# ── HTTP helpers ─────────────────────────────────────────────────────────────────────────────────

def http_json(method: str, url: str, body: dict | None = None, headers: dict | None = None,
              form: dict | None = None):
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
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()
    except Exception as e:  # noqa: BLE001
        return -1, str(e)


def discovery() -> dict:
    # Step 1: the static, parameterless well-known document → the per-client config endpoint.
    status, body = http_json("GET", ATTESTER_BASE_URL + "/.well-known/client-attester")
    if status != 200:
        raise RuntimeError(f"attester discovery failed: HTTP {status} {body}")
    doc = json.loads(body)
    # Step 2: the per-client view (issuer, evidence_audience, evidence_type, RAR types).
    cfg_url = doc["client_configuration_endpoint"] + "?client_id=" + urllib.parse.quote(CLIENT_ID)
    status, body = http_json("GET", cfg_url)
    if status != 200:
        raise RuntimeError(f"client configuration failed: HTTP {status} {body}")
    doc.update(json.loads(body))
    return doc


# ── evidence ─────────────────────────────────────────────────────────────────────────────────────

def fetch_spiffe_svid(audience: str) -> str:
    """A JWT-SVID from the SPIRE Workload API (the spiffe-csi socket). Tolerates both py-spiffe APIs."""
    try:
        from spiffe import WorkloadApiClient  # the consolidated `spiffe` package
        with WorkloadApiClient(SPIFFE_SOCKET) as client:
            # audience takes a collection — a bare string would be iterated char-by-char
            svid = client.fetch_jwt_svid(audience={audience})
            return svid.token
    except ImportError:
        from pyspiffe.workloadapi.default_workload_api_client import DefaultWorkloadApiClient
        client = DefaultWorkloadApiClient(spiffe_socket=SPIFFE_SOCKET)
        svid = client.fetch_jwt_svid(audiences=[audience])
        return svid.token()


def fetch_evidence(mode: str, audience: str) -> str:
    if mode == "gke-sa-token":
        with open(TOKEN_FILE, encoding="ascii") as f:
            return f.read().strip()
    return fetch_spiffe_svid(audience)


# ── the chain: discovery → evidence → attestation → token ────────────────────────────────────────

def invoke(requested_details=None) -> dict:
    doc = discovery()
    mode = EVIDENCE_MODE or doc.get("evidence_type", "spiffe-jwt")
    audience = doc["evidence_audience"]
    now = int(time.time())

    evidence = fetch_evidence(mode, audience)

    # Challenge (always used when the endpoint offers one — replay-protects the proof).
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

    issuance_body = {"client_id": CLIENT_ID, "instance_key": INSTANCE_KEY.jwk,
                     "svid": evidence, "proof": proof}
    if requested_details:
        issuance_body["authorization_details"] = requested_details
    mint_status, mint_body = http_json("POST", doc["attestation_endpoint"], body=issuance_body)
    result = {"evidence_mode": mode, "evidence": evidence, "discovery": doc,
              "challenge": challenge, "proof": proof,
              "mint_status": mint_status, "mint_body": mint_body}
    if mint_status != 200:
        return result

    attestation = json.loads(mint_body)["attestation"]
    pop = INSTANCE_KEY.sign(
        {"alg": "ES256", "typ": "oauth-client-attestation-pop+jwt", "kid": INSTANCE_KEY.jwk["kid"]},
        {"iss": CLIENT_ID, "aud": PF_TOKEN_AUD, "jti": str(uuid.uuid4()), "iat": now})
    pf_status, pf_body = http_json(
        "POST", PF_TOKEN_ENDPOINT,
        form={"grant_type": "client_credentials", "client_id": CLIENT_ID, "client_secret": CLIENT_SECRET},
        headers={"OAuth-Client-Attestation": attestation, "OAuth-Client-Attestation-PoP": pop})
    result.update({"attestation": attestation, "pop": pop,
                   "pf_status": pf_status, "pf_body": pf_body})
    return result


# ── HTTP surface ─────────────────────────────────────────────────────────────────────────────────

class Handler(BaseHTTPRequestHandler):
    def _send(self, code, obj):
        payload = json.dumps(obj, indent=2).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _send_html(self, html):
        payload = html.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        if self.path == "/" or self.path.startswith("/?"):
            try:
                from console import CONSOLE_HTML
                return self._send_html(CONSOLE_HTML)
            except Exception as e:  # noqa: BLE001
                return self._send(500, {"error": str(e)})
        if self.path.startswith("/identity"):
            try:
                doc = discovery()
                mode = EVIDENCE_MODE or doc.get("evidence_type", "spiffe-jwt")
                evidence = fetch_evidence(mode, doc["evidence_audience"])
                return self._send(200, {"status": "up", "client_id": CLIENT_ID, "evidence_mode": mode,
                                        "evidence": evidence, "instance_key_kid": INSTANCE_KEY.jwk["kid"],
                                        "discovery": doc})
            except Exception as e:  # noqa: BLE001
                return self._send(500, {"error": str(e)})
        return self._send(200, {"status": "up", "client_id": CLIENT_ID})

    def do_POST(self):
        if self.path.startswith("/invoke"):
            length = int(self.headers.get("Content-Length") or 0)
            requested = None
            if length:
                try:
                    requested = json.loads(self.rfile.read(length)).get("authorization_details")
                except Exception:  # noqa: BLE001
                    pass
            print(f"[agent] /invoke — running the attested token exchange as {CLIENT_ID}", flush=True)
            try:
                result = invoke(requested)
            except Exception as e:  # noqa: BLE001
                return self._send(500, {"error": str(e)})
            print(f"[agent] mint HTTP {result.get('mint_status')} · PF HTTP {result.get('pf_status')}",
                  flush=True)
            return self._send(200, result)
        return self._send(404, {"error": "not_found"})

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    print(f"[agent] client_id={CLIENT_ID} attester={ATTESTER_BASE_URL} · POST /invoke to run the chain",
          flush=True)
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
