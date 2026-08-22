# Attestation-based client authentication — design

How a verified Client Attestation becomes a credential PingFederate accepts, why the current shape has
two defects, and what replaces it.

Status: **implemented 2026-08-22** — per-client signing in `a27e711`, verify-once below. The one thing
deliberately left as-is: `attestationClaim`/`delegationActChain` still decode the header rather than
reading the published context, because the filter now guarantees a present-but-invalid attestation is
rejected before they run. Worth doing anyway; not load-bearing once the filter is mandatory.

## The constraint everything follows from

PingFederate has no native `attest_jwt_client_auth` token-endpoint auth method, and no SDK extension
point for adding one. A verified attestation must therefore be handed to PF as some credential PF
already understands. That translation is what `ClientAttestationAuthFilter` does, and why it exists.

## Current shape

```
agent  ──OAuth-Client-Attestation + PoP──▶  ClientAttestationAuthFilter
                                              verifies attestation + PoP
                                              mints private_key_jwt (iss=sub=client_id)
                                              signed with ONE deployment-held BRIDGE KEY
                                            ──▶ PingFederate native client auth
                                                  validates against the client's JWKS,
                                                  which registration seeded with the
                                                  bridge PUBLIC key (withBridgeKeys)
                                            ──▶ OGNL issuance criterion
                                                  verifies attestation + PoP AGAIN
```

### Defect 1 — one key authenticates every agent

`BridgeKey` is a single deployment-held key whose public half `RegistrationService.withBridgeKeys()`
merges into *every* attestation client's JWKS. Its own javadoc calls it "the highest-value secret in
the system - it can mint an assertion for any client whose JWKS carries it."

It also creates a registration-ordering trap: a client registered before the key exists does not carry
it, and never will unless re-registered — `automaticRegister` refreshes auto-registered clients but
returns early for anything else (`RegistrationService.java:194`).

### Defect 2 — the attestation is verified twice, and the second verify destroys the first

`enforceChallenge` and `enforceNoReplay` both live inside `ClientAttestationVerifier.verify()`
(`:209`, `:212`, `:237`, `:238`), and **both** the filter and the OGNL criterion call `verify()` on the
same request.

- Challenges are single-use. Two verifies consume one challenge twice.
- The PoP `jti` replay cache is single-use per `(clientId, jti)`.

Today this is latent only because `challengeRequired` defaults false
(`ClientAttestationConfig.java:113`, never set by `ClientAttestationUtils.defaultConfig`) and because
the two classloaders get *separate in-memory stores*. Set a Redis URL and they share one —
`AttestationSupport` says so explicitly: "a single shared `RedisAttestationStore` backs both roles …
immune to the servlet-vs-hook classloader split". Then the second `verify()` reports "Replay detected"
and **no token is issued to anyone**.

So the current design cannot have challenges enabled, and is incompatible with a shared replay store.
Both are things you want in production.

## Target shape

```
agent  ──attestation + PoP──▶  filter: verify ONCE (challenge + jti consumed exactly once)
                                       publish the VERIFIED context as a request attribute
                                       mint private_key_jwt signed with THAT CLIENT'S key
                             ──▶ PF native client auth (client's own registered JWKS)
                             ──▶ OGNL criterion: read the published context.
                                       absent ⇒ deny. Never re-verifies.
```

### Change 1 — per-client signing key, configurable backing

The bridge signs with a key belonging to **that client**, not one belonging to the deployment.

`AttesterSigningKey` in `servlets/attestation-issuer` already solves exactly this on the issuing side —
"resolves a client's attester signing key (OpenBao transit or inline JWK) into a `JwsSigner`", with a
per-client transit reference so the private half never enters the process, and a signer cache. Reuse
that model rather than inventing a second one.

**Backing is a configuration setting**, not a compile-time choice:

| Setting | Values | Meaning |
|---|---|---|
| `OIDF_BRIDGE_SIGNER_BACKING` | `vault` \| `config` | where per-client private keys come from |
| `OIDF_BRIDGE_VAULT_ADDR` / `_TOKEN` | — | when `vault`; one vault serves all clients |
| per-client `bridge_signing_key_ref` | transit key name | when `vault` |
| per-client `bridge_signing_jwk` | inline private JWK | when `config` (dev/demo) |

Exactly one per-client source must resolve, mirroring `AttesterSigningKey`'s "exactly one must be set"
rule. Missing key for a client ⇒ that client cannot authenticate. Fail closed, per client, rather than
the current all-or-nothing boot failure.

**`withBridgeKeys()` is deleted.** The client's own registered JWKS already holds the public half —
from its federation entity statement, or from whatever an administrator registered. Nothing needs
injecting at registration, which removes the ordering trap in Defect 1 entirely.

### Change 2 — verify once, publish, read

The filter is the only place `ClientAttestationVerifier.verify()` runs. It publishes the verified
result as a request attribute of plain types — the mechanism the two classloaders already use, per the
Dockerfile: "the webapp and engine copies communicate only via request attributes with string keys".

`validateClientAttestation` stops re-verifying and instead asserts the attribute is present and
well-formed. Absent ⇒ return false ⇒ no token. That makes the criterion's presence *meaningful*: it
checks the filter actually ran, which is the property it was reaching for anyway.

Consequences, all wanted:

- Challenges become usable — enable `challengeRequired` without breaking the flow.
- A shared Redis store becomes correct rather than fatal, so replay protection can be cluster-wide.
- `attestationClaim` and `delegationActChain` read the *verified* context instead of base64-decoding an
  unverified header (`ClientAttestationUtils.java:398`, `:479`). Their javadoc currently justifies
  reading unverified input by pointing at a sibling criterion on the same mapping — a promise the code
  cannot enforce.

## Pre-registered clients

No difference, and less machinery than the federation path.

`withBridgeKeys` is reachable only from `explicitRegister` (`:103`) and `automaticRegister` (`:207`), so
a pre-registered client never had the bridge key injected. It works today only if an administrator hand-
added it.

Under the target shape, a pre-registered client is the ordinary case: register a JWKS for the client,
give the signing service the matching private key (vault reference or inline), done. Federation clients
differ only in that their JWKS arrived from an entity statement rather than an administrator.

## What this does not change

The attestation still proves an attester vouched for the client. The PoP still proves the instance
holds the `cnf`-bound key — the only key in the flow no service holds. Per-client PF policy still
applies, because the minted assertion carries `iss = sub = client_id` and PF authenticates that client.

## Known adjacent issues, deliberately out of scope

- The attestation's `aud` is not validated (`JwtCodec.java:63` sets `setSkipDefaultAudienceValidation`),
  so an attestation minted for another AS in the same federation is accepted here.
- `attestation_required` is written at registration (`RegistrationService.java:329`) and read nowhere.
- Setting a bridge key today breaks any client registered with a secret: the filter drops
  `client_secret` and substitutes an assertion. Under the target shape this is unchanged and still
  needs a per-client answer.
