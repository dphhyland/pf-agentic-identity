# oidf-jose

> **Part of the [pf-agentic-identity](https://github.com/dphhyland/pf-agentic-identity) monorepo** — build from the repo root with `mvn package`. Absorbed with history from [`dphhyland/oidf-jose`](https://github.com/dphhyland/oidf-jose) on 2026-07-21; that repo is backports-only and its copy still uses the pre-split `.common` package. See [docs/PROVENANCE.md](../../docs/PROVENANCE.md).

The shared **JOSE/JWT foundation** the rest of the reactor signs and verifies through.
Package `com.pingidentity.ps.oidf.jose`. Depends on `platform` (JDK only), `jose4j`, `jackson-databind` and
`commons-logging` only — no PingFederate, servlet, federation or attestation types — which is what lets it sit
near the bottom of the dependency graph and on every classpath (PF's shared classpath, `oidf.war`, the
standalone services).

## What's here

| Class | Role |
|---|---|
| `JwtCodec` | jose4j wrappers for the verification shapes the repo needs: unverified claim/header inspection; verification against an inline JWKS or a resolved key list (`iss`/`sub`/`exp` required, 60 s skew, audience not checked, a `VerificationPolicy` for `kid`, `iat` and `typ`); a signature-only check for JWTs whose claims the caller holds to its own rules; Client Attestation PoP verification against a `cnf` key (`jti` + `iat` required); `typ` enforcement that tolerates the `application/` prefix. Every verifier refuses `none` and the MAC algorithms whatever the caller's algorithm set names, and tries only asymmetric keys not marked `"use": "enc"` (RFC 8725 §3.1-3.2; since 0.6.0). Every verifier takes a `VerificationPolicy`: the overloads without one were removed in 0.6.0 (plan item H-FED-10) |
| `UnverifiedClaims` | What `JwtCodec.parseUnverifiedClaims` returns: the claims of a JWT whose signature nobody has checked. Not a `JwtClaims` and hands none out, so it cannot be passed where verified claims are expected; every accessor says `unverified` in its name, and `toString` names no claim. Since 0.6.0 (plan item H-JOSE-1) - see "Reading a JWT before its signature is checked" below |
| `Jwks` | JWK-as-map helpers: RFC 7638 thumbprints, `assertSameKey` (bind a presented key to a `cnf`), `assertPublicOnly` (rejects `oct` and any private member — `d`, `p`, `q`, `dp`, `dq`, `qi`, `k`), `publicKey` |
| `JwsSigner` | The signing seam: `alg`, `kid`, public JWK, and raw JWS signature bytes over a signing input (fixed-width `r‖s` for ECDSA, per RFC 7515 §3.4). One interface for an in-process key and a vault key |
| `LocalJwkSigner` | `JwsSigner` over an inline private JWK — EC P-256/384/521 → ES256/384/512 (a declared `alg` must be the curve's), RSA of 2048 bits or more → RS256/384/512 or PS256/384/512 (RFC 7518 §3.3-3.5; the size, the curve check and PS since 0.6.0, F-0112). Refused when it is built, never when it first signs. Dev/demo: the private key lives in the JVM |
| `OpenBaoTransitSigner` | `JwsSigner` over an OpenBao/Vault transit key (`ecdsa-p256/384/521`). Signs with `marshaling_algorithm=jws`; pins the key version read at construction so a concurrent rotation cannot make the emitted `kid` lie; fails closed (`IllegalStateException`) when the vault is unreachable. From 0.6.0 its calls go through libs/platform's `OutboundHttp` (plan item S5d): connecting within 1 s and each call, body included, within 2.5 s (`CONNECT_TIMEOUT`, `TOTAL_TIMEOUT`), since a signature is made while a client waits for its attestation, and at most platform's default 256 KiB read. The vault is internal by design, so the address it is configured at is exempt from the scheme and address rules - pinned to that URL's scheme, host, port and path, so a key name with a `..` segment is not - and nothing else is; the JVM's trust store decides its certificate, which must name its host. A failure's message names the reason (`HEADER_TIMEOUT`, `DEADLINE`, `TLS` and the rest). No client library |
| `CompactJws` | Assembles `BASE64URL(header).BASE64URL(payload).BASE64URL(signature)` over a `JwsSigner`. Header carries `alg`, `typ`, `kid` — keys are referenced by id, never embedded, so a verifier resolves them through a trust path |
| `SigningKeyProvider` | RSA key pair + `kid` SPI that `FederationService` signs entity statements with; the host (PF) implements it |
| `dpop.DpopProofValidator` / `dpop.DpopProof` | RFC 9449 §4.3 proof checks every receiver shares - the token endpoint's attestation combined mode, rs-validation and platform-pf's operator authenticator: `typ` `dpop+jwt`, a public `jwk` and the signature under it, the algorithm allowlist, `htm` compared exactly (RFC 9110 §9.1: "The method token is case-sensitive"), `htu` after RFC 3986 syntax- and scheme-based normalisation with the query and fragment ignored, `jti` required and `iat` inside the window. Replay, `ath`, the key binding and nonces are the caller's. Moved here from client-attestation in 0.6.0 (F-0225, F-0226) |
| `Claims` | Null-safe accessors over verified `JwtClaims` and nested maps — empty map instead of `null` |
| `HttpGetClient` / `JdkHttpGetClient` | Minimal GET seam for fetching federation artefacts. Every fetch is screened by `OutboundUrlPolicy` first, then subject to 8 s connect / 15 s request timeouts and forced HTTP/1.1, so a stalled remote entity fails fast on the caller's thread instead of outliving the client's own timeout. Response bodies are read through the policy's byte cap rather than buffered whole. The `ignoreSslErrors` constructor (`OIDF_FEDERATION_IGNORE_SSL_ERRORS`) trusts any certificate chain through libs/platform's `InsecureTls` - a dev trust controller only. The JDK client still checks that the certificate names the host dialled unless the JVM-wide `jdk.internal.httpclient.disableHostnameVerification` is set (`JdkHttpClientInsecureTlsTest`) |
| `OutboundUrlPolicy` | What the process is willing to fetch, applied before every outbound request: HTTPS only (`OIDF_FETCH_ALLOW_HTTP` opts into plaintext), no credentials in the URL, and no address that resolves to a private/link-local/loopback/CGN/IETF-reserved range unless the host is named in `OIDF_FETCH_HOST_ALLOWLIST` or `OIDF_FETCH_ALLOW_PRIVATE_NETWORKS=true`. `trusting(...)` exempts specific operator-configured origin+path-prefix endpoints (a trust controller, a SPIRE agent) from the scheme/address rules without opening the exemption to other ports or paths on the same host. Body size capped at `OIDF_FETCH_MAX_BODY_BYTES` (default 256 KiB). Exists because a client-supplied `trust_chain`'s `authority_hints` are attacker-controlled URLs this process fetches |

## Reading a JWT before its signature is checked

Some reads have to come first: an attestation's `iss` says whose keys to fetch, a chain's statements say which
superior signed which. RFC 8725 §3.1 requires that libraries "MUST enable the caller to specify a supported set of
algorithms and MUST NOT use any other algorithms", and §3.2 that "applications MUST only allow the use of
cryptographically current algorithms that meet the security requirements of the application"; the other half is that
what the sender wrote decides nothing until the signature over it is checked. Since 0.6.0 (plan item H-JOSE-1, F-0063)
`JwtCodec.parseUnverifiedClaims` returns an `UnverifiedClaims`, so every such read is visible in the code and none can
flow into a place that takes verified claims. Each call site on `main` at 0.6.0, and what it is:

- **routing**: the value chooses which key, registration or statement to look up, and the verified value is compared
  with it later (named);
- **refuse-first**: a check that can only refuse, on bytes whose signature is verified before anything is accepted
  (named);
- **logging**: reported, never trusted;
- **bug**: a decision rested on it with no later check - each is a finding, and is fixed.

| Call site | Reads | Class | Where the verified value is checked |
|---|---|---|---|
| `client-attestation` `ClientAttestationVerifier.verifyAttestation` | the attestation's `iss` | routing | the attester's keys are resolved for it, and `verifyAgainstKeys` requires the verified `iss` to be the same |
| `openid-federation` `TrustChainValidator.Statement.parse` | every statement's `iss`, `sub`, `iat`, `exp`, `jwks`, `authority_hints` | routing, refuse-first | the search follows them; `EntityStatementChecks.check` refuses on them; every statement on the route is verified (`verifyWithAnchor`, `verifyInline`) before a chain is returned |
| `openid-federation` `TrustChainValidator.selectLeafEntityStatement` | which statement of a presented chain is the leaf | routing | the chain is then validated, and the registration uses the validated leaf |
| `openid-federation` `EntityStatementChecks.check` (takes `UnverifiedClaims`), its `trust_marks` and `trust_chain` checks | a mark's `trust_mark_type`, the `trust_chain` header's first `sub` | refuse-first | the statement is verified by the chain validator; each mark by `TrustMarkValidator` |
| `openid-federation` `TrustMarkValidator.validateOne` | the mark's `iss`, `sub`, `iat`, `trust_mark_type` | routing, refuse-first | `iss` chooses whose chain to resolve; `verify` then checks the mark under that issuer's keys, and `iat`, `exp` and `delegation` are read from the claims it returns (since 0.6.0) |
| `openid-federation` `TrustMarkValidator.delegation` | the delegation's claims | refuse-first | every check only refuses; the owner's signature over the same bytes is verified last |
| `openid-federation` `TrustMarkValidator.unverifiedIssuer` | a mark's `iss` | logging | the `Rejected` entry and the debug line name it; nothing is decided on it |
| `openid-federation` `TrustMarkValidator.anchorConfiguration` | the chain's last statement | routing | verified here against the anchor's pinned keys (since 0.6.0; before, it re-read a statement the chain validator had verified but not handed on) |
| `openid-federation` `EndpointClientAuthentication.authenticate` | the client assertion's `iss`, `sub`, `aud`, `exp`, `iat`, `jti` | routing, refuse-first | `iss` chooses the client whose chain is resolved; `verifySignature` then checks the same bytes under that client's Federation Entity Keys before the `jti` is spent or the client returned |
| `openid-federation` `FederationService.trustMarkStatus` | the mark's `iss` | routing | a mark this entity did not issue is 404; its status is decided on the claims `verifySignature` returns under this entity's own key (since 0.6.0; before, on the unverified claims once the signature had verified) |
| `openid-federation` `FederationService.refreshSubordinateJwks` | a configured subordinate's `jwks` and `metadata` | **bug, fixed (F-0415)** | the keys this entity asserts for the subordinate are taken only once its Entity Configuration verifies under one of them (`VerificationPolicy.entityStatement()`); until 0.6.0 they were taken as fetched. This is OpenID Federation §3.2 conformance and proof of possession, not proof the keys are the subordinate's: a party that answers at its URL signs with the keys it lists. That trust-on-fetch stays open as F-0012 (pinned subordinate keys, plan item S-7) |
| `openid-federation` `HttpTrustControllerGateway.authorityConfiguration` / `configurationOf` | an authority's `federation_fetch_endpoint` | routing | where a Subordinate Statement is fetched from; the statement is verified under the keys its superior asserts, or the anchor's pinned keys |
| `openid-federation` `HttpTrustControllerGateway.tryExtractExpEpochSeconds` / `tryExtractIatEpochSeconds` | a fetched statement's `exp`, `iat` | routing | how long the statement cache keeps it; a cached statement is verified every time a chain uses it |
| `openid-federation` `TrustMarkType.requireDelegationFor`, `TrustMarkClaims.isMarkOfType` | a configured delegation's or mark's `trust_mark_type` | refuse-first | the operator's own configuration, held to its shape at start; a receiver verifies each |
| `pf-integration` `ExplicitRegistrationRequest.verifySelfSigned` | the request's `iss` and `jwks` | routing | `verifyAgainstInlineJwks` verifies it under that `jwks` with the verified `iss` required to match, and the verified claims are used |
| `pf-integration` `ExplicitRegistrationRequest.fromTrustChainJson`, `isOwnConfiguration` | which statement is the RP's own | routing | the chain presented is validated by the chain validator |
| `pf-integration` `RegistrationService.presentsChange`, `predatesRegistration` | the offered configuration's `iat`, `jwks`, `metadata` | routing | whether a renewal is attempted and from which chain; the renewal validates like any other |
| `pf-integration` `RegistrationService.immediateSuperior` | the second statement's `iss` | routing | a statement of the chain the validator has just verified |
| `pf-integration` `RequestObject.read` / `checkProfile` / `trustChain` | a request object's or client assertion's claims | routing, refuse-first | `verify` checks the signature under the RP's keys; the replay window reads `exp` and `jti` from the claims it returns (since 0.6.0) |
| `pf-integration` `FrontChannelAutoRegistrationFilter.clientIdOf`, `TokenEndpointAutoRegistrationFilter.unverifiedSubject` | the assertion's or attestation's `sub` | routing | which registration is looked up or renewed; the request is then authenticated by PingFederate or the attestation filter |
| `pf-integration` `ClientAttestationAuthFilter.unverifiedSubject` / `unverifiedClaim` | the attestation's `sub`; the assertion's `sub` and `iss` | routing, logging | the client whose policy the attestation is verified under, held to the verified `sub` afterwards (`subjectChanged`); the names the S9b gate considers, which can only refuse; the refusal log |

The signature checks that do not go through `JwtCodec`'s claim verifiers, and why each is safe:

| Call site | Algorithm | Key | `typ` |
|---|---|---|---|
| `JwtCodec.verifySignature` callers: `TrustMarkValidator.verify`, `EndpointClientAuthentication`, `FederationService.signedWithOwnKey`, `RpKeyMaterial.verifiedSignedJwks`, `RequestObject.verify` | the caller's set, never `none` or a MAC | the one the `kid` names exactly, asymmetric and not `enc`; or with no `kid`, whichever such key verifies | checked by each caller first (`TrustMarkValidator.signedHeader`, `RequestObject.checkProfile`, `RpKeyMaterial`'s `jwk-set+jwt`) or not defined for it (a client assertion) |
| `rs-validation` `DelegatedTokenValidator` | one of the configured set (default ES256, PS256, RS256), pinned to the header's | the validator's JWKS by `kid`, public keys only | the configured access-token type |
| `oidf-jose` `DpopProofValidator` | the configured set | the proof's own `jwk` header, public only | `dpop+jwt` |
| `openid-federation` `SelfSignedEntityConfigurations` | ES256/384/512, PS256, RS256, EdDSA | a key the authority registered, by `kid` | `entity-statement+jwt` |
| `shared-signals` `SetVerifier` | asymmetric only (`SetVerifier.ALGORITHMS`) | the transmitter's JWKS | `secevent+jwt` |
| `attestation-issuer` `InstanceKeyProofValidator`, `CloudTokenValidator`, `WalletInstanceAttestationValidator`, `SpiffeSvidValidator` | `ClientAttestationConfig.DEFAULT_ASYMMETRIC_ALGORITHMS`, pinned to the header's | the presented instance key, or an asymmetric trust-bundle or provider key by `kid` | the instance proof's and the wallet attestation's own; an SVID and a cloud token have none checked |
| `device-enrolment` `PingOneIdTokenVerifier`, `EnclaveKeyProofValidator` | RS256; ES256 | PingOne's JWKS by `kid`; the enclave's key | none for the ID token; the proof's, when it has one |
| `harness` `SsfSelfVerify` | the harness's own SET, minted in the same process | its own key | `secevent+jwt` |

`JwtCodecAlgorithmTest` and `UnverifiedClaimsTest` hold the codec's side; each call site's own tests hold its part.

## Mutation testing

`mvn -Pmutation verify -pl libs/oidf-jose -Djacoco.skip=true` runs pitest over the JOSE decisions (`JwtCodec`,
`UnverifiedClaims`, `VerificationPolicy`, `Claims`, `Jwks`, `LocalJwkSigner`, `CompactJws`, `OutboundUrlPolicy`,
`dpop`), failing below 85% killed, as openid-federation's and pf-integration's profiles do. The HTTP clients are left
out: their tests wait on sockets and deadlines. The first run, on 2026-10-01 (JDK 20, from `prod/p3-jose-hardening`):
349 mutations, 322 killed (92%), 15 survived, 12 with no coverage (most in `OutboundUrlPolicy`, whose fetch tests are
the HTTP clients' and are left out); test strength 96%. The weekly Mutation workflow does not run it yet: plan item
R-CI8 makes it a gate in Phase 7.

## Configuration

`OutboundUrlPolicy.fromEnvironment()` reads `OIDF_FETCH_ALLOW_HTTP`, `OIDF_FETCH_ALLOW_PRIVATE_NETWORKS`,
`OIDF_FETCH_HOST_ALLOWLIST` and `OIDF_FETCH_MAX_BODY_BYTES` through their entries in the `outbound-fetch` settings
catalogue ([docs/configuration/outbound-fetch.md](../../docs/configuration/outbound-fetch.md)) -
`JdkHttpGetClient`'s single-arg constructor builds one from it. From 0.6.0 they are parsed strictly (plan item
ST-5): a switch that is not `true` or `false`, a body cap that is not a whole number of at least 1, or an allow-list
of nothing is refused, naming the setting, where the reader before took anything but `true` as `false` and a bad cap
as the default; under development a legacy spelling such as `yes` is still read as it was, with a warning. The
federation runtime reads `OIDF_FETCH_ALLOW_HTTP` from the same entry (`OutboundUrlPolicy.settings`), for a
plaintext development PDP. Nothing else here reads a setting: vault address, token and key
name are constructor arguments to `OpenBaoTransitSigner`; the callers do that env resolution
(`RegistryHostedEntitySigner.fromEnvironment()` in `openid-federation`,
`AttesterSigningKey.fromEnvironment()` in `servlets/attestation-issuer`).

## Build

```sh
mvn -pl libs/oidf-jose -am package     # or `mvn package` at the repo root; tests run with the build
```

Shared dependency versions come from the repo BOM (`bom/pom.xml`, imported with `scope=import`; there
is no parent pom). Consumers, by pom: `client-attestation`, `openid-federation`, `device-instance`,
`servlets/pf-integration`, `servlets/attestation-issuer`, `servlets/ssf`, `services/device-enrolment`,
`services/demo-rs`, `services/harness`. Ships into PingFederate both ways: `build/pingfederate/stage-modules.sh`
stages the jar into `build/pingfederate/modules/` for the pf-runtime.war merge, and `servlets/oidf-war`
bundles it into `oidf.war`'s `WEB-INF/lib`.
