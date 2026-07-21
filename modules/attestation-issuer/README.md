# attestation-issuer

> **Part of the [pf-agentic-identity](https://github.com/dphhyland/pf-agentic-identity) monorepo** — build from the repo root with `mvn package`. Extracted with history from `pf-oidf-modules` 2026-07-21; see [docs/PROVENANCE.md](https://github.com/dphhyland/pf-agentic-identity/blob/main/docs/PROVENANCE.md).

The **Client Attestation issuer** — the issuing side of OAuth Attestation-Based Client
Authentication (verification lives in [`client-attestation`](../client-attestation)):

- **`AttestationIssuanceServlet`** (`/federation/attestation`) — a SPIFFE workload presents its
  JWT-SVID and instance-key proof; the servlet validates the SVID against the client's registered
  SPIFFE bindings and mints a Client Attestation bound to the instance key (`cnf`), signed by the
  client's own attester key.
- **`AttesterSigningKey` / `JwsSigner`** — per-client attester keys: **OpenBao transit** (key never
  leaves the vault; `OpenBaoTransitSigner`) or an inline JWK (`LocalJwkSigner`).
- **`SpiffeSvidValidator` / `SpiffeBinding`** — one-to-many SPIFFE-ID bindings per client, with
  bound metadata carried into the attestation's `workload` claam-free claims.
- **`ClientAttestationChallengeServlet`** — the challenge endpoint (`Cache-Control: no-store`,
  one-time challenges) backing PoP freshness.
- **`AttestationMinter`** — claim layout: `iss`/`sub`/`cnf`/`workload`/`authorization_details`
  (the attested RAR entitlement envelope).

Configuration via `AttestationIssuanceConfig` (issuer id, TTLs, per-client key + binding config,
required claims). PF-side client resolution through `PfIssuanceClientResolver` (PF SDK, provided).
