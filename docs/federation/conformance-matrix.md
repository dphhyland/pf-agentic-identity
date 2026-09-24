# OpenID Federation 1.0 - conformance matrix

One row per requirement of [OpenID Federation 1.0 Final](https://openid.net/specs/openid-federation-1_0.html)
(17 February 2026) that this repo implements, and where. The coverage report reads this file: each row's
id is joined to the tests tagged with it (`@Requirement("OIDFED §x.y")`), so a row nothing pins shows up on
the [coverage dashboard](../coverage-dashboard.md) as unpinned.

How the ids are written:

- `OIDFED §x.y` is a section of the Final text. A requirement in a section's own paragraphs takes the
  paragraph number from the published anchors: `OIDFED §3(2)` is `#section-3-2`, and a list item takes both
  numbers, so `OIDFED §3.2(2.11)` is `#section-3.2-2.11` (the eleventh validation step). Those anchors were
  checked against the published Final HTML on 2026-09-24.
- A section that has subsections is never used bare for a new row: it would count every subsection's pins as
  covering it. The older bare rows below (`§4`, `§12.1`, `§12.2`) are being split into paragraph rows as the
  tests they pin are rewritten.
- A behaviour that departs from the text on purpose is tagged with its divergence (`UNVERIFIED item N`),
  never with the clause it departs from.

Rows exist only for behaviour that is implemented. What is not implemented yet is in the plan, not here.

| Id | Requirement | Where | Status |
|---|---|---|---|
| `OIDFED §1.2` | A non-HTTPS entity identifier is refused before any fetch; an Entity Identifier is an https URL with a host | `TrustChainValidator`, `EntityId` | Implemented |
| `OIDFED §2.1` | Web PKI / TLS is not the basis of signing-key trust: a key the anchor serves over HTTPS is not trusted unless it was pinned | `TrustAnchor`, `TrustChainValidator` | Implemented |
| `OIDFED §3(2)` | An entity statement without `typ: entity-statement+jwt` is rejected - every statement in a route, every entity configuration the gateway reads for a fetch endpoint (including the pinned anchor's, before its signature is checked), the explicit-registration request body, and the entity configuration the attester reads its client bindings from | `EntityStatementType`, `TrustChainValidator`, `HttpTrustControllerGateway`, `ExplicitRegistrationRequest`, `OpenIdFederationClientResolver` | Implemented |
| `OIDFED §3.1.1` | `jwks` is required and is a set of Federation Entity Keys: public, asymmetric, each with a unique `kid`; a superior statement without one cannot vouch for the statement below it | `Jwks.parseFederationKeySet`, `TrustChainValidator`, `TrustAnchor` | Implemented |
| `OIDFED §3.1.3` | `metadata_policy_crit` invalidates a statement naming an unknown operator | `MetadataPolicy` | Implemented |
| `OIDFED §3.2` | An entity configuration is genuinely self-signed | `TrustChainValidator` | Implemented |
| `OIDFED §3.2(2.2)` | Validation step 2: the `typ` header is `entity-statement+jwt` | `JwtCodec` (`VerificationPolicy.entityStatement()`) | Implemented in the verification policy |
| `OIDFED §3.2(2.7)` | Validation step 7: `iat` is present and in the past, with a small leeway | `JwtCodec.requireIssuedAtInPast` | Implemented in the verification policy |
| `OIDFED §3.2(2.8)` | Validation step 8: `exp` is in the future, judged against the verifier's clock | `JwtCodec` | Implemented |
| `OIDFED §3.2(2.11)` | Validation step 11: the `kid` header is a non-empty string that exactly matches a key in the issuer's JWK Set; the key is selected by that match, never guessed | `JwtCodec.selectByKid`, `TrustAnchor.verify` | Implemented in the verification policy |
| `OIDFED §3.2(2.12)` | Validation step 12: the signature validates with the key the `kid` identifies | `JwtCodec` | Implemented |
| `OIDFED §4` | The Trust Anchor's keys are distributed out of band, and verify its Subordinate Statement (ES[i-1]); each other statement is verified with a key from the `jwks` of the statement above it | `TrustAnchor`, `TrustChainValidator`, `FederationRuntimeConfig` | Implemented |
| `OIDFED §6.1.3.1` | The metadata-policy operator set | `MetadataPolicy` | Implemented |
| `OIDFED §6.1.4.1` | Operators applied in the specified order | `MetadataPolicy` | Implemented |
| `UNVERIFIED item 11` | `metadata_policy` merge outcomes - narrow-only, fails closed | `MetadataPolicy.composeWith` | Partial - two operators (`add`, an empty `subset_of`) are stricter than the Final text; aligning them is scheduled |
| `OIDFED §8.9` | Every federation error carries the code and HTTP status §8.9 gives it | `FederationError` | Implemented as a type; the endpoints adopt it as they are rewritten |
| `OIDFED §9(1)` | A trailing `/` is removed from an Entity Identifier before `/.well-known/openid-federation` is appended | `EntityId` | Implemented as a type; the gateway adopts it as it is rewritten |
| `OIDFED §10.2` | ES[i], the anchor's entity configuration, validates with a public key of the Trust Anchor | `HttpTrustControllerGateway` | Implemented - checked where the gateway reads it for the fetch endpoint |
| `OIDFED §10.3` | Of several trusted anchors, the one a caller asks for is preferred, and a caller can never widen the set | `TrustAnchorSet`, `FederationRuntimeConfig.trustAnchors` | Implemented as configuration; the validator adopts it as it is rewritten |
| `OIDFED §11.3` | A mismatch between the out-of-band keys and the anchor's entity configuration is retrieved again before it is treated as a problem | `HttpTrustControllerGateway` | Partial - compares by verifying the configuration's signature with a pinned key rather than by key-set equality, so an in-progress §11.2 rollover is not a mismatch; a second failure is refused |
| `OIDFED §12.1` | Automatic registration against the trust controller | `RegistrationService`, `TokenEndpointAutoRegistrationFilter` | Implemented at the token endpoint |
| `OIDFED §12.2` | Explicit registration against the trust controller | `ExplicitRegistrationRequest`, `RegistrationService` | Implemented |
