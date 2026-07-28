"""The mock resource server on AWS — the end of the chain, and the only party that has to decide.

It receives a token that no single agent could have minted alone: `sub` names the workload the chain
started from, and `act` is the nested list of everyone who has handled the request since. The
resource verifies that token against the AS that issued it (keys resolved through the OpenID
Federation chain, not pinned locally), then decides.

The decision is delegated to a PingAuthorize AuthZEN PDP when AUTHZEN_PDP_URL is set; otherwise the
built-in rule below stands in, so the demo runs without a PDP. Both paths receive the SAME inputs —
subject, action, resource, and the full actor chain as context — so swapping one for the other does
not change what the resource is asserting.
"""
import base64
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from cryptography.hazmat.primitives.asymmetric.ec import ECDSA, EllipticCurvePublicNumbers, SECP256R1
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature

# The AS whose tokens this resource accepts (its federation entity id / issuer).
TRUSTED_ISSUER = os.environ.get("TRUSTED_ISSUER", "")
AUTHZEN_PDP_URL = os.environ.get("AUTHZEN_PDP_URL", "")
# Only this actor may be the one presenting the token (the last hop). A chain that ends anywhere
# else is a token being replayed by a party that was not given it.
REQUIRED_FINAL_ACTOR = os.environ.get("REQUIRED_FINAL_ACTOR", "demo-attest-gke-delivery")

_JWKS_CACHE = {"fetched": 0, "keys": {}}


def b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def jwks_keys() -> dict:
    """The issuer's signing keys. Cached briefly; refreshed on an unknown kid."""
    if time.time() - _JWKS_CACHE["fetched"] < 300 and _JWKS_CACHE["keys"]:
        return _JWKS_CACHE["keys"]
    with urllib.request.urlopen(TRUSTED_ISSUER + "/pf/JWKS", timeout=15) as response:
        document = json.loads(response.read())
    keys = {}
    for key in document.get("keys", []):
        if key.get("kty") == "RSA":
            numbers = RSAPublicNumbers(
                int.from_bytes(b64url_decode(key["e"]), "big"),
                int.from_bytes(b64url_decode(key["n"]), "big"))
            keys[key["kid"]] = ("RSA", numbers.public_key())
        elif key.get("kty") == "EC" and key.get("crv") == "P-256":
            numbers = EllipticCurvePublicNumbers(
                int.from_bytes(b64url_decode(key["x"]), "big"),
                int.from_bytes(b64url_decode(key["y"]), "big"), SECP256R1())
            keys[key["kid"]] = ("EC", numbers.public_key())
    _JWKS_CACHE.update({"fetched": time.time(), "keys": keys})
    return keys


def verify_token(token: str) -> dict:
    """Signature, issuer and expiry. Raises ValueError with the reason on any failure."""
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("malformed token")
    header = json.loads(b64url_decode(parts[0]))
    claims = json.loads(b64url_decode(parts[1]))
    signature = b64url_decode(parts[2])
    signing_input = (parts[0] + "." + parts[1]).encode()

    keys = jwks_keys()
    entry = keys.get(header.get("kid"))
    if entry is None:
        _JWKS_CACHE["fetched"] = 0
        entry = jwks_keys().get(header.get("kid"))
    if entry is None:
        raise ValueError("unknown signing key: %s" % header.get("kid"))
    kind, public_key = entry
    try:
        if kind == "RSA":
            public_key.verify(signature, signing_input, PKCS1v15(), hashes.SHA256())
        else:
            from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
            half = len(signature) // 2
            der = encode_dss_signature(int.from_bytes(signature[:half], "big"),
                                       int.from_bytes(signature[half:], "big"))
            public_key.verify(der, signing_input, ECDSA(hashes.SHA256()))
    except InvalidSignature:
        raise ValueError("signature does not verify against the issuer's keys")

    if claims.get("iss") != TRUSTED_ISSUER:
        raise ValueError("wrong issuer: %r (this resource trusts %r)" % (claims.get("iss"), TRUSTED_ISSUER))
    if claims.get("exp", 0) < time.time():
        raise ValueError("token expired")
    return claims


def actor_chain(claims: dict) -> list:
    """Flatten the nested `act` claim into [most recent actor, …, first actor]."""
    chain = []
    node = claims.get("act")
    if isinstance(node, str) and node.strip():
        node = json.loads(node)
    while isinstance(node, dict):
        chain.append({k: v for k, v in node.items() if k != "act"})
        nested = node.get("act")
        if isinstance(nested, str) and nested.strip():
            nested = json.loads(nested)
        node = nested
    return chain


def decide(claims: dict, chain: list, action: str) -> dict:
    """Authorize, via the AuthZEN PDP when configured, otherwise the built-in rule."""
    if AUTHZEN_PDP_URL:
        request = {
            "subject": {"type": "workload", "id": claims.get("sub")},
            "action": {"name": action},
            "resource": {"type": "payment", "id": "mock-settlement"},
            "context": {"actor_chain": chain, "client_id": claims.get("client_id"),
                        "issuer": claims.get("iss")},
        }
        body = json.dumps(request).encode()
        req = urllib.request.Request(AUTHZEN_PDP_URL, data=body, method="POST",
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=15) as response:
            verdict = json.loads(response.read())
        return {"allowed": bool(verdict.get("decision")), "decided_by": "pingauthorize-authzen",
                "pdp_response": verdict}

    # Built-in stand-in: the token must have travelled (a chain at all), and the party actually
    # presenting it must be the delegate this resource expects to hear from.
    if not chain:
        return {"allowed": False, "decided_by": "builtin",
                "reason": "no actor chain — token was not delegated"}
    final_actor = chain[0].get("sub")
    if final_actor != REQUIRED_FINAL_ACTOR:
        return {"allowed": False, "decided_by": "builtin",
                "reason": "final actor %r is not the expected delegate %r"
                          % (final_actor, REQUIRED_FINAL_ACTOR)}
    return {"allowed": True, "decided_by": "builtin",
            "reason": "delegated by %s on behalf of %s" % (final_actor, claims.get("sub"))}


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, obj):
        payload = json.dumps(obj, indent=1).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        self._send(200, {"resource": "mock settlement API (AWS)", "trusted_issuer": TRUSTED_ISSUER})

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b"{}"
        authorization = self.headers.get("Authorization") or ""
        if not authorization.startswith("Bearer "):
            self._send(401, {"error": "bearer token required"})
            return
        try:
            claims = verify_token(authorization[7:].strip())
        except ValueError as e:
            self._send(401, {"error": "invalid_token", "detail": str(e)})
            return

        chain = actor_chain(claims)
        decision = decide(claims, chain, "settle_payment")
        try:
            request = json.loads(raw or b"{}")
        except Exception:  # noqa: BLE001
            request = {}
        response = {
            "on_behalf_of": claims.get("sub"),
            "presented_by": claims.get("client_id"),
            "actor_chain": chain,
            "token_issuer": claims.get("iss"),
            "decision": decision,
            "request": request,
        }
        if not decision["allowed"]:
            self._send(403, response)
            return
        response["settled"] = {"reference": "MOCK-%d" % int(time.time()), **request}
        self._send(200, response)

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    ThreadingHTTPServer(("", 8080), Handler).serve_forever()
