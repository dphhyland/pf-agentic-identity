# Attestation-based client authentication — design

How a verified Client Attestation becomes a credential PingFederate accepts, why the shape this
replaced had two defects, and what replaced it.

Status: **implemented 2026-08-22** — per-client signing in `a27e711`, verify-once below, and
`attestationClaim`/`delegationActChain` now read the published context rather than decoding the header.
That last one was going to be left as-is, on the grounds that the filter rejects a present-but-invalid
attestation before they run. It got done because that is a property of how a deployment is configured,
not of the code: see "Claims come from the verified context" below.

## The constraint everything follows from

PingFederate has no native `attest_jwt_client_auth` token-endpoint auth method, and no SDK extension
point for adding one. A verified attestation must therefore be handed to PF as some credential PF
already understands. That translation is what `ClientAttestationAuthFilter` does, and why it exists.

## Shape before 2026-08-22 (superseded)

The diagram and the two defects below describe the code as it was *before* `a27e711` and `8c5ad55`;
they are kept as the rationale. The "Target shape" that follows is what the code does now.

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
  unverified header. See below.

### Change 3 — claims come from the verified context

`attestationClaim` base64-decoded the `OAuth-Client-Attestation` header and put the result into the
issued access token. Its javadoc justified that: a sibling `validateClientAttestation` issuance
criterion rejects a bad attestation, so no token is issued, so an unverified read is harmless.

The reasoning is sound and the conclusion still doesn't hold, because it is a claim about a
deployment's PingFederate configuration made in Java that Java cannot check. It is true only for
mappings that carry the criterion, and only where the filter is active — and
`OIDF_ATTESTATION_REQUIRE_BRIDGE_KEY=false` with nothing configured is a supported way to run without
it. Same shape as the rest of this document: a security property that holds because of how something
is configured rather than because the code makes it hold.

So the value now comes from `VERIFIED_ATTESTATION_ATTRIBUTE`, published by the filter after verifying.
Restoring the old behaviour makes the test suite fail with the attacker's values in the token
(`spiffe://banking.demo/workload/treasury-admin`, and an act chain naming
`iss=https://attester.attacker.example`), which is what the defect actually looked like.

Three details worth keeping:

- **No fallback to the header.** Verifying on demand would re-consume the challenge and burn the PoP
  `jti` — the exact double-verification Change 2 removed. A filter-less deployment therefore issues
  tokens *without* these claims rather than with unverified ones, and logs why.
- **`iss` had to be added to the context**, which previously carried it only in a log line. `agent_id`
  and `client_id` are unique only within an issuing authority, so the acting party is the pair.
- **Only scalars map.** The context also holds the entitlement list and the workload map; a Java
  `toString` of those in a token would be meaningless, so they resolve to nothing.

The one unverified read left is `delegationActChain`'s `act` claim from the caller's `subject_token`.
That has a different justification — the token-exchange processor validates the subject token before
issuance, which is a property of the grant type rather than of a configurable criterion.

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
applies, because the minted assertion carries `iss = sub = client_id` and PF authenticates that client. So
does the client's attestation policy: from 0.6.0 the filter verifies under the server's policy tightened by
the client's `attestation_*` properties, the same policy the criterion applies (`AttestationPolicyResolver`,
plan item S4c), and publishes its fingerprint, which the criterion checks when it reuses the verification.

## Where the filter runs, and what it forwards

From 0.6.0 (plan item S4d, F-0032) the filter is mapped over every PingFederate endpoint that authenticates a client
- the token endpoint, PAR, CIBA's backchannel endpoint (`/as/bc-auth.ciba`), the device authorization endpoint
(`/as/device_authz.oauth2`), introspection and revocation - and over the authorization endpoint. RFC 9126 §2.1 has PAR
"Authenticate the client in the same way as at the token endpoint (Section 2.3 of [RFC6749])", and RFC 8628 §3.1 says
the same of the device endpoint, so a client whose only credential is its attestation needs the bridge at each.
PingFederate 13.1.3 accepted the bridge assertion at all six on the rig (U-0020, 2026-09-30).

Authentication was the smaller half. PingFederate issues the `authorization_details` stored at PAR and CIBA, and
ignores the token request's parameter on the code and CIBA grants in both directions (U-0019, the rig, 2026-09-30);
the device grant is taken to do the same (F-0032; not driven on the rig, U-0330). So a check at the token endpoint alone held nothing: a client left the parameter out and received what it
had pushed. The filter therefore holds details where they arrive:

```
agent ──attestation + PoP, authorization_details──▶ filter (token, PAR, CIBA, device)
                                                     verify ONCE; grant = authorize(requested, ceiling, INHERIT)
                                                     forward the GRANTED details (+ verified _agent_id),
                                                     never the client's; none asked, none forwarded
                                                   ──▶ PF stores / issues the granted details
agent ──signed request object──▶ filter: contains(ceiling, object's details) strictly, or 400
agent ──/as/authorization.oauth2 with details, attestation_required client──▶ filter: error page, no redirect
```

`INHERIT` fills a constrained field the request leaves out with the attestation's value; the model checks that what it
grants is within the attestation's details. Only a caller that forwards the grant may ask for it: the OGNL criterion,
which cannot rewrite what PingFederate issues, and `oidf_requested_access`, which is forwarded as sent, stay strict.
At introspection and revocation the filter authenticates and bridges only. What PingFederate then puts in the token -
the response belt and the issuance criterion on `context.OAuthAuthorizationDetails` - is plan item S4d's other half
(S4D3).

## Known adjacent issues, deliberately out of scope

- The attestation's `aud` is not validated (`JwtCodec.verifyAgainstKeys` sets
  `setSkipDefaultAudienceValidation`). This is by specification, not an omission: ABCA-10 §4 defines the
  Client Attestation JWT's claims as `sub`, `exp`, `cnf` and optionally `iat` — no `aud` — and says "The
  JWT MAY contain other claims. All claims that are not understood by implementations MUST be ignored."
  The audience lives on the PoP (§5.1: `aud` REQUIRED, the AS's issuer identifier), which the verifier
  holds to the issuer alone since 0.4.0; in DPoP mode `htu` binds the proof to the endpoint URL
  PingFederate advertises, from configuration rather than the `Host` header.
  An attestation is meant to be presentable to any AS; what binds a presentation to *this* AS is the
  proof. `ClientAttestationVerifierTest` pins both halves so the absence is not "fixed" into a check
  the draft does not define.
- `attestation_required` is written at registration (`FederationClientBuilder`) and, from 0.6.0, enforced by the
  filter: a request for such a client without an attestation is refused wherever it authenticates, and its
  `authorization_details` at the authorization endpoint without PAR are refused with a page (plan items S4c and S4d;
  the pf-integration README's "Each client's attestation policy").
- Setting a bridge key today breaks any client registered with a secret: the filter drops
  `client_secret` and substitutes an assertion. Under the target shape this is unchanged and still
  needs a per-client answer.
