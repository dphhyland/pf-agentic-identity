#!/usr/bin/env bash
# Generate the attest_jwt_client_auth bridge keypair and wire it into the demo.
#
# The bridge key is how ClientAttestationAuthFilter authenticates a verified workload to PingFederate:
# the filter signs a private_key_jwt client_assertion with the PRIVATE half, and each demo client trusts
# the PUBLIC half via its registered JWKS. It is NOT a workload credential — it lives only in the PF
# deployment (the pf-bridge-key secret) and authenticates on a workload's behalf once its attestation has
# verified. Rotate it by re-running this and re-applying Terraform + rolling PF.
#
# Outputs:
#   - creates/updates the k8s secret pf-bridge-key (namespace pf) with the private JWK
#   - prints the public JWKS to stdout — pass it to Terraform as TF_VAR_bridge_public_jwks
#
# Usage:
#   TF_VAR_bridge_public_jwks="$(./gen-bridge-key.sh)"    # generate + capture public JWKS
#   ( cd pf/terraform && terraform apply ... )            # register it on the clients
#   kubectl -n pf rollout restart deploy/pingfederate     # pick up the new secret
set -euo pipefail

NS="${PF_NAMESPACE:-pf}"
work="$(mktemp -d)"; trap 'rm -rf "$work"' EXIT

openssl ecparam -name prime256v1 -genkey -noout -out "$work/bridge.pem"
openssl ec -in "$work/bridge.pem" -text -noout 2>/dev/null | python3 - "$work" <<'PY'
import sys, re, json, base64, hashlib
work = sys.argv[1]; txt = sys.stdin.read()
def hexblock(label):
    m = re.search(label + r":\s*\n((?:\s+[0-9a-f:]+\n)+)", txt)
    return bytes.fromhex(re.sub(r"[\s:]", "", m.group(1)))
priv = hexblock("priv")[-32:].rjust(32, b"\x00")
pubraw = hexblock("pub")                       # 0x04 || X || Y
assert pubraw[0] == 4 and len(pubraw) == 65
x, y = pubraw[1:33], pubraw[33:65]
def b64u(b): return base64.urlsafe_b64encode(b).rstrip(b"=").decode()
pub = {"kty": "EC", "crv": "P-256", "x": b64u(x), "y": b64u(y)}
canon = json.dumps({q: pub[q] for q in ("crv", "kty", "x", "y")}, separators=(",", ":"), sort_keys=True)
pub.update(kid=b64u(hashlib.sha256(canon.encode()).digest()), use="sig", alg="ES256")
privj = dict(pub); privj["d"] = b64u(priv)
open(work + "/private.jwk", "w").write(json.dumps(privj))
open(work + "/public.jwks", "w").write(json.dumps({"keys": [pub]}))
PY

kubectl -n "$NS" create secret generic pf-bridge-key \
  --from-file=private-jwk="$work/private.jwk" \
  --dry-run=client -o yaml | kubectl apply -f - >&2

# The public JWKS goes to stdout so it can be captured into TF_VAR_bridge_public_jwks.
cat "$work/public.jwks"
