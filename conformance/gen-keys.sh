#!/usr/bin/env bash
# Generate the conformance suite's key pairs and certificates, and the rig's three generated secrets.
#
# Eight key pairs: the suite's five clients, each authenticating by private_key_jwt - two FAPI 2.0
# clients (the plan needs a second one to prove a code or a token is bound to the first), one SSF
# receiver and two CIBA clients - and, for the OpenID Federation OP plan, the suite's own trust anchor,
# its relying party's entity keys and that RP's client keys. PF holds only the PUBLIC half
# (terraform/clients.tf reads keys/*.public.jwks.json; the federation-op profile pins the anchor's); the
# private half goes into the suite configuration and nowhere else. Then an mTLS CA with two client
# certificates the FAPI-CIBA plan's configuration insists on, a TLS CA and certificate for a suite run
# with suite/suite-compose.yml, and secrets.env: the test user's password and two client secrets (the SSF
# introspection client's and the event operator's). Nothing written here is committed.
#
# Idempotent: an existing key or secret is kept, because regenerating one silently invalidates the
# archive already exported with its public half in it. Delete keys/ or secrets.env to rotate, then
# re-apply terraform and re-export.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
KEYS="$HERE/keys"
mkdir -p "$KEYS"; chmod 700 "$KEYS"
command -v node >/dev/null || { echo "ERROR: node is required (it exports JWKs natively)" >&2; exit 1; }

# The suite-* keys are the suite's own federation, for the OpenID Federation OP plan: its trust anchor, its RP's
# entity keys and its RP's client keys. The suite signs with the private halves; PF pins the anchor's public half.
for name in fapi2-client1 fapi2-client2 ssf-receiver ciba-client1 ciba-client2 suite-trust-anchor suite-rp-ec suite-rp-client; do
  if [[ -f "$KEYS/$name.private.jwks.json" ]]; then
    echo "kept      keys/$name.*"
    continue
  fi
  ( umask 177
    KEY_NAME="$name" KEYS_DIR="$KEYS" node -e '
      const { generateKeyPairSync, createHash } = require("crypto");
      const fs = require("fs");
      const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
      const pub = publicKey.export({ format: "jwk" });
      // RFC 7638 thumbprint as the kid, so the same key always gets the same name.
      const kid = createHash("sha256").update(JSON.stringify({ e: pub.e, kty: pub.kty, n: pub.n })).digest("base64url");
      const meta = { kid, use: "sig", alg: "PS256" };
      const dir = process.env.KEYS_DIR, name = process.env.KEY_NAME;
      fs.writeFileSync(`${dir}/${name}.private.jwks.json`, JSON.stringify({ keys: [{ ...privateKey.export({ format: "jwk" }), ...meta }] }, null, 2));
      fs.writeFileSync(`${dir}/${name}.public.jwks.json`, JSON.stringify({ keys: [{ ...pub, ...meta }] }, null, 2));
    ' )
  chmod 644 "$KEYS/$name.public.jwks.json"
  echo "generated keys/$name.*"
done

# mTLS material for the FAPI-CIBA plan: a throwaway CA and a client certificate for each client. The
# suite's static-client configuration insists on mtls/mtls2 (cert, key, ca) whatever the client
# authentication method, and reads the key as PKCS#8 RSA - hence genpkey, not genrsa. PingFederate is
# never given any of it: FAPI-CIBA's certificate binding is a product gap on 13.x (README.md), and
# private_key_jwt is the authentication method under test.
if [[ -f "$KEYS/mtls-ca.crt" ]]; then
  echo "kept      keys/mtls-*"
else
  ( umask 177; cd "$KEYS"
    openssl req -x509 -newkey rsa:2048 -nodes -days 397 -keyout mtls-ca.key -out mtls-ca.crt \
      -subj "/CN=pf-agentic-identity conformance mTLS CA" >/dev/null 2>&1
    for c in mtls-client1 mtls-client2; do
      openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$c.key" >/dev/null 2>&1
      openssl req -new -key "$c.key" -subj "/CN=$c" -out "$c.csr" >/dev/null 2>&1
      openssl x509 -req -in "$c.csr" -CA mtls-ca.crt -CAkey mtls-ca.key -CAcreateserial -days 397 -out "$c.crt" >/dev/null 2>&1
      rm -f "$c.csr"
    done
    rm -f mtls-ca.srl )
  chmod 644 "$KEYS"/mtls-*.crt
  echo "generated keys/mtls-* (a CA and two client certificates)"
fi

# TLS for a conformance suite run with suite/docker-compose.yml, for the OpenID Federation OP plan. PF fetches
# the suite RP's jwks_uri itself and checks the certificate like any other, so the suite's certificate has to
# name the host PF reaches it by and chain to a CA PF trusts: this CA, which the federation-op profile imports.
if [[ -f "$KEYS/suite-tls-ca.crt" ]]; then
  echo "kept      keys/suite-tls-*"
else
  ( umask 177; cd "$KEYS"
    openssl req -x509 -newkey rsa:2048 -nodes -days 397 -keyout suite-tls-ca.key -out suite-tls-ca.crt \
      -subj "/CN=pf-agentic-identity conformance suite CA" >/dev/null 2>&1
    openssl req -new -newkey rsa:2048 -nodes -keyout suite-tls.key -subj "/CN=host.docker.internal" -out suite-tls.csr >/dev/null 2>&1
    printf 'subjectAltName=DNS:host.docker.internal,DNS:localhost.emobix.co.uk,DNS:localhost\nextendedKeyUsage=serverAuth\n' > suite-tls.ext
    openssl x509 -req -in suite-tls.csr -CA suite-tls-ca.crt -CAkey suite-tls-ca.key -CAcreateserial -days 397 \
      -extfile suite-tls.ext -out suite-tls.crt >/dev/null 2>&1
    rm -f suite-tls.csr suite-tls.ext suite-tls-ca.srl )
  chmod 644 "$KEYS"/suite-tls-ca.crt "$KEYS"/suite-tls.crt "$KEYS"/suite-tls.key
  echo "generated keys/suite-tls-* (a CA and the suite's certificate)"
fi

SECRETS="$HERE/secrets.env"
if [[ -f "$SECRETS" ]]; then
  echo "kept      secrets.env"
else
  ( umask 177
    rand() { openssl rand -base64 36 | tr -d '/+=\n' | cut -c1-"$1"; }
    {
      echo "# Generated by gen-keys.sh. Never committed. Sourced by apply.sh as TF_VAR_*."
      echo "TF_VAR_test_user_password=$(rand 24)"
      echo "TF_VAR_ssf_introspection_client_secret=$(rand 40)"
      echo "TF_VAR_ssf_emitter_client_secret=$(rand 40)"
    } > "$SECRETS" )
  echo "generated secrets.env"
fi
# A secret added after secrets.env was first generated: appended, never regenerated, so the ones the
# archive already carries stay valid.
if ! grep -q '^TF_VAR_ssf_emitter_client_secret=' "$SECRETS"; then
  ( umask 177; echo "TF_VAR_ssf_emitter_client_secret=$(openssl rand -base64 36 | tr -d '/+=\n' | cut -c1-40)" >> "$SECRETS" )
  echo "added     TF_VAR_ssf_emitter_client_secret to secrets.env"
fi
