#!/usr/bin/env python3
"""Capture a Trust Anchor's public Federation Entity Keys, for pinning.

OpenID Federation 1.0 §4 distributes a Trust Anchor's public keys "in some secure out-of-band way",
and the product refuses to validate any trust chain until they are configured
(OIDF_FEDERATION_TRUST_ANCHOR_JWKS for PingFederate's token endpoint and registration,
OIDF_TRUST_ANCHOR_JWKS for the attestation issuer's wallet-provider trust). This script reads the
`jwks` claim of the anchor's entity configuration and prints it in the form those variables take.

Read this before trusting its output. Fetching the keys over HTTPS from the anchor itself is
trust-on-first-use: it is exactly the channel the pinned keys exist to stop relying on. It is
acceptable at provisioning time, from a network position you trust, and only once you have
compared the printed thumbprints with the key the anchor actually holds (for go-oidfed lighthouse,
the key file under LH_SIGNING_FILESYSTEM_KEY_DIR on its volume; for a PingFederate anchor, its
signing key in the admin console). Section 11.3 of the spec recommends the Federation Operator
publish the keys through a channel independent of the entity configuration - use that when there
is one.

It does not verify the entity configuration's signature: the Python standard library has no ECDSA,
and a configuration verified against keys it carries itself proves nothing anyway. The product does
verify it, against the pinned set, on first use (§10.2) - a wrong capture fails there, loudly.

Usage:
    tools/pin-trust-anchor.py https://anchor.example
    tools/pin-trust-anchor.py https://anchor.example --base-url https://anchor.internal/oidf
    tools/pin-trust-anchor.py https://anchor.example --env-file deploy/pingfederate/vars.staging.env

With --env-file the OIDF_FEDERATION_TRUST_ANCHOR_JWKS line is replaced, or appended if absent
(--var names a different variable). Without it the JWKS is printed to stdout and everything else to
stderr, so the output can be piped straight into a secret store or `kubectl set env`.
"""

import argparse
import base64
import hashlib
import json
import pathlib
import ssl
import sys
import urllib.request

# RFC 7638 §3.2: the required members, per key type, that a thumbprint is computed over.
THUMBPRINT_MEMBERS = {"EC": ("crv", "kty", "x", "y"), "RSA": ("e", "kty", "n"), "OKP": ("crv", "kty", "x")}
# Private-key members (RFC 7518 §6.2.2, §6.3.2) and the symmetric key value (§6.4.1).
PRIVATE_MEMBERS = ("d", "p", "q", "dp", "dq", "qi", "oth", "k")


def fail(message):
    print(f"pin-trust-anchor: {message}", file=sys.stderr)
    sys.exit(1)


def b64url_decode(segment):
    return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))


def thumbprint(jwk):
    members = THUMBPRINT_MEMBERS.get(jwk.get("kty"))
    if members is None:
        return None
    canonical = json.dumps({m: jwk[m] for m in members}, separators=(",", ":"), sort_keys=True)
    return base64.urlsafe_b64encode(hashlib.sha256(canonical.encode()).digest()).rstrip(b"=").decode()


def fetch_entity_configuration(url, insecure):
    request = urllib.request.Request(url, headers={"Accept": "application/entity-statement+jwt"})
    context = ssl._create_unverified_context() if insecure else None
    try:
        with urllib.request.urlopen(request, timeout=20, context=context) as response:
            return response.read().decode().strip()
    except Exception as e:  # noqa: BLE001 - any failure here ends the run with the reason
        fail(f"could not fetch {url}: {e}")


def public_jwks(entity_id, jwt):
    parts = jwt.split(".")
    if len(parts) != 3:
        fail("the response is not a compact JWS - is this really an entity configuration endpoint?")
    try:
        header = json.loads(b64url_decode(parts[0]))
        claims = json.loads(b64url_decode(parts[1]))
    except ValueError as e:
        fail(f"the entity configuration does not decode: {e}")
    if header.get("typ") != "entity-statement+jwt":
        print(f"warning: typ is {header.get('typ')!r}, not 'entity-statement+jwt' (§3 requires it)", file=sys.stderr)
    if claims.get("iss") != entity_id or claims.get("sub") != entity_id:
        fail(f"iss/sub are {claims.get('iss')!r}/{claims.get('sub')!r}, not {entity_id!r}: this is not that entity's "
             "configuration, or the entity identifier you passed is wrong")
    keys = (claims.get("jwks") or {}).get("keys")
    if not isinstance(keys, list) or not keys:
        fail("the entity configuration carries no jwks keys (§3.1.1 requires them)")
    kids = set()
    for key in keys:
        if not isinstance(key, dict):
            fail(f"a jwks entry is not a JWK object: {key!r}")
        leaked = [m for m in PRIVATE_MEMBERS if m in key]
        if leaked:
            fail(f"key {key.get('kid')!r} carries private or symmetric material {leaked} - the anchor is publishing a "
                 "secret. Do not pin it; rotate that key")
        kid = key.get("kid")
        if not isinstance(kid, str) or not kid.strip() or kid in kids:
            fail(f"key has a missing or duplicate kid {kid!r} (§3.1.1: every key needs a unique one)")
        kids.add(kid)
    return {"keys": keys}, claims


def write_env_file(path, var, value):
    lines = path.read_text().splitlines() if path.exists() else []
    replaced = False
    for i, line in enumerate(lines):
        if line.startswith(var + "="):
            lines[i] = f"{var}={value}"
            replaced = True
    if not replaced:
        lines.append(f"{var}={value}")
    path.write_text("\n".join(lines) + "\n")
    return replaced


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("entity_id", help="the Trust Anchor's entity identifier (iss of its statements)")
    parser.add_argument("--base-url", help="where to reach it, when that differs from the identifier (e.g. a context path)")
    parser.add_argument("--insecure", action="store_true", help="skip TLS verification (a dev anchor only; makes the capture worthless as evidence)")
    parser.add_argument("--env-file", type=pathlib.Path, help="KEY=value file to write the pinned JWKS into")
    parser.add_argument("--var", default="OIDF_FEDERATION_TRUST_ANCHOR_JWKS", help="variable name for --env-file")
    args = parser.parse_args()

    base = (args.base_url or args.entity_id).rstrip("/")
    url = base + "/.well-known/openid-federation"
    jwks, claims = public_jwks(args.entity_id, fetch_entity_configuration(url, args.insecure))

    print(f"Captured from {url} (exp {claims.get('exp')}).", file=sys.stderr)
    print("Compare each thumbprint with the key the anchor actually holds before you pin it:", file=sys.stderr)
    for key in jwks["keys"]:
        print(f"  kid={key['kid']}  kty={key.get('kty')}  alg={key.get('alg', '-')}  "
              f"RFC 7638 thumbprint={thumbprint(key) or '(unsupported kty)'}", file=sys.stderr)
    value = json.dumps(jwks, separators=(",", ":"))
    if args.env_file:
        replaced = write_env_file(args.env_file, args.var, value)
        print(f"{'Replaced' if replaced else 'Appended'} {args.var} in {args.env_file}.", file=sys.stderr)
    else:
        print(value)


if __name__ == "__main__":
    main()
