# The chain as raw curl

The five steps the workload runs, as curl. The live consoles show these same requests with real values
filled in — each step has a **show the exact request** toggle — so this file is the annotated version.

Run the PF-facing calls **in-cluster**, so the request URL matches what PF expects for the PoP `aud`:

```bash
kubectl run curl -n demo --rm -it --image=curlimages/curl --restart=Never -- sh
PF=http://pingfederate.pf:9080
```

The workload never sends a `client_id`. It presents evidence; the attester decides which OAuth client
that identity maps to and returns it in the attestation's `sub`.

## 1. Discover the attester

```bash
curl -s -X GET "$PF/.well-known/client-attester"
```

A static, parameterless document (RFC 8615). The fields that matter to a workload:

```json
{
  "attestation_endpoint": "http://pingfederate.pf:9080/federation/attestation",
  "challenge_endpoint": "http://pingfederate.pf:9080/federation/attestation-challenge",
  "evidence_audience": "https://attester.example.com",
  "evidence_types_supported": ["spiffe-jwt", "gke-sa-token", "gcp-id-token"],
  "resolver_plugins_active": ["cimd", "pf-client-metadata"],
  "instance_proof_typ": "oauth-attestation-instance-proof+jwt"
}
```

`resolver_plugins_active` shows where the SPIFFE-ID → client mapping comes from. There is no
`client_id` anywhere in this document.

## 2. Get platform evidence

The `aud` must be the `evidence_audience` from step 1.

```bash
# Phase 1 — SPIRE JWT-SVID from the Workload API:
spire-agent api fetch jwt -audience https://attester.example.com

# Phase 2 — GKE projects a service-account token into the pod; just read it:
cat /var/run/secrets/tokens/attester-token

# Phase 3 — a Google-signed ID token for the runtime service account:
curl -s -X POST \
  "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/${SA_EMAIL}:generateIdToken" \
  -H "Authorization: Bearer $(gcloud auth print-access-token)" \
  -H 'Content-Type: application/json' \
  -d '{"audience":"https://attester.example.com","includeEmail":true}'
```

Decoded, a Phase-2 token has `iss: https://container.googleapis.com/v1/projects/…`,
`sub: system:serviceaccount:demo:payment-agent`, `aud: ["https://attester.example.com"]`.

## 3. Get a challenge

```bash
curl -s -X POST "$PF/federation/attestation-challenge"
# → {"attestation_challenge":"…","expires_in":300}
```

## 4. Mint the Client Attestation

The `proof` is a JWS signed by a **fresh P-256 instance key the workload generates**: header
`{"alg":"ES256","typ":"oauth-attestation-instance-proof+jwt","kid":"<thumbprint>"}`, claims
`{"aud":"<evidence_audience>","jti":"<uuid>","iat":<now>,"challenge":"<step 3>"}`.

```bash
curl -s -X POST "$PF/federation/attestation" \
  -H 'Content-Type: application/json' \
  -d '{
  "instance_key": { "kty":"EC","crv":"P-256","x":"…","y":"…","kid":"…" },
  "svid": "<step 2>",
  "proof": "<the instance-key proof JWS>",
  "authorization_details": [ {"type":"sales_agent","sales_regions":["EMEA"]} ]
}'
# → {"attestation":"<jwt>","expires_in":300}
```

`authorization_details` is optional (RFC 9396). Omit it and the full attested ceiling is granted;
include it and the attester enforces *requested ⊆ attested*.

The minted attestation decodes to:

```json
{
  "iss": "https://attester.example.com",
  "sub": "demo-attest-gke-native",          // the client the ATTESTER chose
  "cnf": { "jwk": { …the instance key… } },
  "workload": {
    "spiffe_id": "spiffe://<project>.svc.id.goog/ns/demo/sa/payment-agent",
    "attested_by": "spiffe",
    "attributes": { "selectors": ["k8s:ns:demo", "k8s:sa:payment-agent"] }
  },
  "authorization_details": [ …granted… ]
}
```

Failure cases worth demonstrating:

| Change | Result |
|---|---|
| `"sales_regions":["APAC"]` | `403 access_denied` — above the ceiling |
| resend the same `proof` | `401 invalid_instance_proof` — jti replay |
| evidence for an unmapped SPIFFE ID | `403 spiffe_id_not_authorized` |
| evidence signed by an untrusted key | `401 invalid_svid` — no plugin accepts it |

## 5. Authenticate to the token endpoint

`attest_jwt_client_auth`: the request carries **only** the two attestation headers and
`grant_type` — no `client_id`, no `client_secret`. The PoP is a second JWS by the instance key:
`typ: oauth-client-attestation-pop+jwt`, claims
`{"iss":"<sub>","aud":"https://localhost:9031","jti":"…","iat":…}`. Its `iss` names the client (read
from the attestation `sub`); its `aud` is PF's **configured base URL**, not the URL you dialled.

```bash
curl -s -X POST "$PF/as/token.oauth2" \
  -H 'OAuth-Client-Attestation: <step 4 attestation>' \
  -H 'OAuth-Client-Attestation-PoP: <the PoP JWS>' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'grant_type=client_credentials'
```

PingFederate has no native support for `attest_jwt_client_auth`, so this endpoint sits behind
`ClientAttestationAuthFilter` (registered in `pf-runtime.war`'s web.xml over `/as/token.oauth2`). The
filter verifies the two headers with the same code as the issuance criterion, resolves the client from
the attestation `sub`, and forwards the request authenticated to PF as that client with a
`private_key_jwt` `client_assertion` signed by a deployment-held **bridge key** — whose public half is
registered in each client's JWKS. The workload never holds that key or any secret. If the attestation is
absent the filter passes the request through untouched; if it is present but invalid the filter rejects
with `invalid_client_attestation` and PF is never reached.

The access token is a JWT (`typ: at+jwt`). Decoded:

```json
{
  "sub": "spiffe://<project>.svc.id.goog/ns/demo/sa/payment-agent",
  "act": {"sub": "demo-attest-gke-native", "attested_by": "spiffe"},
  "client_id": "demo-attest-gke-native",
  "jti": "…", "iat": …, "exp": …
}
```

`sub` is the attested workload, so a resource server receiving this token can see which workload the
call came from, and `act` records the client and the platform that attested it.

---

Or run the whole thing at once: `curl -s -X POST <agent>/invoke | jq .` returns every artifact plus a
`calls` array containing exactly these curl commands with the real values substituted.
