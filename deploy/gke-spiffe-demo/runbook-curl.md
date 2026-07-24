# The chain as raw curl — five steps

The same flow the agent's `/invoke` runs, narrated step by step. Run the PF-facing curls **in-cluster**
(so the request URL is stable) via:

```bash
kubectl run curl -n demo --rm -it --image=curlimages/curl --restart=Never -- sh
PF=http://pingfederate.pf:9080
```

JWT-minting steps (the proof and PoP need the instance private key) are easiest done through the agent
pod's debug surface — or locally with `harness/AttestationFlowHarness.java live` in pf-oidf-modules,
which prints ready-to-run curl. This runbook shows the wire shapes.

## 1. Discover the attester

```bash
# The well-known document is static and parameterless — it advertises the endpoints:
curl -s "$PF/.well-known/client-attester" | jq .
# then the per-client view from the endpoint it points at:
curl -s "$PF/federation/attester-configuration?client_id=demo-attest-gke" | jq .
```

The well-known doc carries `attestation_endpoint`, `challenge_endpoint`, `client_configuration_endpoint`,
`evidence_types_supported`, proof/attestation `typ`s and algorithms. The per-client doc adds `issuer`,
`evidence_audience` (the `aud` the SVID must carry), `evidence_type`, the pinned trust domain, and
`authorization_details_types`.

## 2. Get identity evidence

**Phase 1 (SPIRE):** from inside the agent pod, the Workload API answers with a JWT-SVID whose
`aud` = `evidence_audience`:

```bash
kubectl -n demo exec deploy/payment-agent -- \
  python -c "from app import fetch_spiffe_svid; print(fetch_spiffe_svid('https://attester.example.com'))"
```

**Phase 2 (Google-native):** the projected token is just a file:

```bash
kubectl -n demo exec deploy/payment-agent -- cat /var/run/secrets/tokens/attester-token
```

Decode either at jwt.io: Phase 1 has `sub: spiffe://gke.banking.demo/ns/demo/sa/payment-agent`
(SPIRE-signed); Phase 2 has `sub: system:serviceaccount:demo:payment-agent` and
`iss: https://container.googleapis.com/v1/projects/…` (Google-signed).

## 3. Challenge (replay protection)

```bash
curl -s -X POST "$PF/federation/attestation-challenge" | jq .
# → {"attestation_challenge":"…","expires_in":300}
```

## 4. Mint the Client Attestation

The instance-key proof is a JWS: header `{"alg":"ES256","typ":"oauth-attestation-instance-proof+jwt"}`,
claims `{"aud":"<evidence_audience>","jti":"<uuid>","iat":<now>,"challenge":"<step 3>"}`, signed by the
**instance key** (a fresh P-256 keypair the workload holds).

```bash
curl -s -X POST "$PF/federation/attestation" -H 'Content-Type: application/json' -d '{
  "client_id":   "demo-attest-gke",
  "instance_key": { "kty":"EC","crv":"P-256","x":"…","y":"…","kid":"…" },
  "svid":        "<step 2>",
  "proof":       "<the instance-key proof JWS>",
  "authorization_details": [{"type":"sales_agent","sales_regions":["EMEA"]}]
}' | jq .
# → {"attestation":"<jwt>","expires_in":300}
```

Decode the attestation: `iss` = attester, `sub` = client_id, `cnf.jwk` = the instance key,
`workload.spiffe_id` + `workload.attestor`, and the **granted** `authorization_details` (the requested
set, contained within the binding's ceiling).

Negative variants worth showing:
- `"sales_regions":["APAC"]` → `403 access_denied` (over the ceiling)
- re-send the same `proof` → `401 invalid_instance_proof` (jti replay)
- an SVID for an unbound SPIFFE ID → `403 spiffe_id_not_authorized`

## 5. Authenticate to the token endpoint

The PoP is a second JWS by the instance key: header `typ: oauth-client-attestation-pop+jwt`, claims
`{"iss":"demo-attest-gke","aud":"https://localhost:9031","jti":"…","iat":…}` — `aud` must be **PF's
configured base URL**, not the URL you dialled.

```bash
curl -s -X POST "$PF/as/token.oauth2" \
  -H "OAuth-Client-Attestation: <step 4>" \
  -H "OAuth-Client-Attestation-PoP: <the PoP JWS>" \
  -d 'grant_type=client_credentials&client_id=demo-attest-gke&client_secret=demo-secret-123' | jq .
# → {"access_token":"…","token_type":"Bearer",…}
```

The token-endpoint gate (`validateClientAttestation` OGNL issuance criterion) verified: the attestation's
signature against the trusted attester key, the PoP against the attestation's `cnf` key, freshness,
replay — and published the attested context for downstream RAR/PAZ policy.

One-shot equivalent: `curl -s -X POST <agent>/invoke | jq .` returns every artifact from all five steps.
