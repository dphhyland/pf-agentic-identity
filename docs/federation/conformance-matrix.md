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
- A row may name a section or paragraph that the tests pin more finely: the dashboard counts `OIDFED §6.1.3.1.1(8.1)`
  as pinning the row `OIDFED §6.1.3.1.1`. So each metadata-policy operator, each constraint and each §3.2
  validation step has one row, and the tests carry the paragraph.
- A section that has subsections is never used bare for a new row: it would count every subsection's pins as
  covering it. The older bare rows below (`§4`, `§12.1`, `§12.2`) are being split into paragraph rows as the
  tests they pin are rewritten.
- A behaviour that departs from the text on purpose is tagged with its divergence (`UNVERIFIED item N`),
  never with the clause it departs from.

Rows exist only for behaviour that is implemented. What is not implemented yet is in the plan, not here.

| Id | Requirement | Where | Status |
|---|---|---|---|
| `OIDFED §1.2` | A non-HTTPS entity identifier is refused before any fetch; an Entity Identifier is an https URL with a host and no query or fragment, and a hint that is not one is never fetched | `TrustChainValidator`, `EntityId` | Implemented |
| `OIDFED §2.1` | Web PKI / TLS is not the basis of signing-key trust: a key the anchor serves over HTTPS is not trusted unless it was pinned | `TrustAnchor`, `TrustChainValidator` | Implemented |
| `OIDFED §3(2)` | An entity statement without `typ: entity-statement+jwt` is rejected - every statement in a route, every entity configuration the gateway reads for a fetch endpoint (including the pinned anchor's, before its signature is checked), the explicit-registration request body, and the entity configuration the attester reads its client bindings from | `EntityStatementType`, `VerificationPolicy.entityStatement()`, `HttpTrustControllerGateway`, `ExplicitRegistrationRequest`, `OpenIdFederationClientResolver` | Implemented |
| `OIDFED §3.1.1` | The claims every Entity Statement carries: `iss`, `sub`, `iat`, `exp` required; `jwks` required and a set of Federation Entity Keys (public, asymmetric, unique `kid`); `metadata` an object of objects; a superior's `metadata` overrides the subject's for the types it has; `crit` never lists a claim the specification defines | `EntityStatementChecks`, `Jwks.parseFederationKeySet`, `TrustChainValidator` | Implemented |
| `OIDFED §3.1.2` | Entity-Configuration-only claims: `authority_hints` and `trust_anchor_hints` are non-empty arrays of Entity Identifiers; each `trust_marks` entry names the type its Trust Mark JWT carries | `EntityStatementChecks` | Implemented (syntax; Trust Mark trust is §7, not yet implemented) |
| `OIDFED §3.1.3` | `metadata_policy_crit` lists only additional operators; one this implementation does not understand invalidates the statement and its chain. Every Subordinate Statement this entity issues names its `source_endpoint` | `EntityStatementChecks`, `MetadataPolicy`, `FederationService` | Implemented - no additional operator is understood, so any listed refuses |
| `OIDFED §3.2` | An entity configuration is genuinely self-signed | `TrustChainValidator` | Implemented |
| `OIDFED §3.2(2.2)` | Validation step 2: the `typ` header is `entity-statement+jwt` | `VerificationPolicy.entityStatement()`, `TrustChainValidator` | Implemented |
| `OIDFED §3.2(2.4)` | Validation step 4: `sub` is the Entity Identifier of the entity the statement is about | `EntityStatementChecks`, `TrustChainValidator` | Implemented |
| `OIDFED §3.2(2.5)` | Validation step 5: `iss` is a valid Entity Identifier | `EntityStatementChecks` | Implemented |
| `OIDFED §3.2(2.6)` | Validation step 6: a Subordinate Statement's issuer is one of its subject's `authority_hints` - statements by anyone else are passed over | `TrustChainValidator` | Implemented |
| `OIDFED §3.2(2.7)` | Validation step 7: `iat` is present and in the past, with a small leeway | `JwtCodec.requireIssuedAtInPast`, `TrustChainValidator` | Implemented |
| `OIDFED §3.2(2.8)` | Validation step 8: `exp` is in the future, judged against the verifier's clock | `JwtCodec`, `TrustChainValidator` | Implemented |
| `OIDFED §3.2(2.9)` | Validation step 9: `jwks` is present and a valid JWK Set | `EntityStatementChecks` | Implemented |
| `OIDFED §3.2(2.11)` | Validation step 11: the `kid` header is a non-empty string that exactly matches a key in the issuing entity's key set - including an Intermediate's own configuration when the route has it; the key is selected by that match, never guessed | `JwtCodec.selectByKid`, `TrustChainValidator` | Implemented |
| `OIDFED §3.2(2.12)` | Validation step 12: the signature validates with the key the `kid` identifies | `JwtCodec` | Implemented |
| `OIDFED §3.2(2.13)` | Validation step 13: `crit` names only extension claims, each of which must be understood - none is, so any refuses | `EntityStatementChecks` | Implemented |
| `OIDFED §3.2(2.14)` | Validation step 14: `authority_hints` only in an Entity Configuration, syntactically correct | `EntityStatementChecks` | Implemented |
| `OIDFED §3.2(2.15)` | Validation step 15: `trust_anchor_hints` only in an Entity Configuration, syntactically correct | `EntityStatementChecks` | Implemented |
| `OIDFED §3.2(2.16)` | Validation step 16: `metadata` syntactically correct, with no `null` values | `EntityStatementChecks` | Implemented |
| `OIDFED §3.2(2.17)` | Validation step 17: `metadata_policy` only in a Subordinate Statement, and a valid policy | `EntityStatementChecks`, `MetadataPolicy` | Implemented |
| `OIDFED §3.2(2.18)` | Validation step 18: `metadata_policy_crit` only in a Subordinate Statement, naming no standard operator | `EntityStatementChecks` | Implemented |
| `OIDFED §3.2(2.19)` | Validation step 19: `constraints` only in a Subordinate Statement, syntactically correct | `EntityStatementChecks`, `Constraints` | Implemented |
| `OIDFED §3.2(2.20)` | Validation step 20: `trust_marks` only in an Entity Configuration; each entry's type matches its Trust Mark's | `EntityStatementChecks` | Implemented (syntax) |
| `OIDFED §3.2(2.21)` | Validation step 21: `trust_mark_issuers` only in an Entity Configuration, mapping types to arrays of Entity Identifiers | `EntityStatementChecks` | Implemented (syntax) |
| `OIDFED §3.2(2.22)` | Validation step 22: `trust_mark_owners` only in an Entity Configuration, each owner a `sub` and a key set | `EntityStatementChecks` | Implemented (syntax) |
| `OIDFED §3.2(2.23)` | Validation step 23: `source_endpoint` only in a Subordinate Statement, and a URL | `EntityStatementChecks` | Implemented |
| `OIDFED §3.2(2.24)` | Validation step 24: a `trust_chain` header is a Trust Chain beginning with this entity's own configuration (accepted only on an Explicit Registration request) | `EntityStatementChecks` | Implemented |
| `OIDFED §3.2(2.25)` | Validation step 25: a `peer_trust_chain` is a Trust Chain to a configured anchor | `EntityStatementChecks`, `TrustChainValidator` | Implemented |
| `OIDFED §3.2(2.26)` | Validation step 26: `aud` only in an Explicit Registration request, naming the OP and nothing else | `EntityStatementChecks` | Implemented |
| `OIDFED §3.2(2.27)` | Validation step 27: `trust_anchor` only in an Explicit Registration response, so never in a chain | `EntityStatementChecks` | Implemented |
| `OIDFED §4` | The Trust Anchor's keys are distributed out of band, and verify its Subordinate Statement (ES[i-1]); each other statement is verified with a key from the `jwks` of the statement above it | `TrustAnchor`, `TrustChainValidator`, `FederationRuntimeConfig` | Implemented |
| `OIDFED §4(3)` | A validated chain comes back in §4 shape: the subject's Entity Configuration, the Subordinate Statements up to the anchor's, and the anchor's Entity Configuration when it was presented or asked for (the one part §4 lets a chain omit) | `TrustChainValidator`, `TrustChainValidationResult.trustChain` | Implemented |
| `OIDFED §4(8.1)` | ES[0] is signed with a key in its own `jwks`, as well as one its superior asserts | `TrustChainValidator` | Implemented |
| `OIDFED §4(9)` | The anchor's keys verify ES[i] and ES[i-1]; each anchor's statements only with its own keys, however many anchors share a gateway | `TrustChainValidator`, `HttpTrustControllerGateway` | Implemented |
| `OIDFED §4.1` | A chain begins with its subject's Entity Configuration and ends at a configured anchor - which may be the subject itself, or have superiors of its own that are never followed | `TrustChainValidator` | Implemented |
| `OIDFED §4.3(2)` | Entity Configurations and Subordinate Statements in a chain carry no `trust_chain` header | `EntityStatementChecks` | Implemented |
| `OIDFED §4.4` | A `peer_trust_chain` about the OP is validated alongside, ending at the same anchor; statements in a chain never carry one | `TrustChainValidator`, `EntityStatementChecks` | Implemented - the same anchor is required by default, see `docs/unverified.md` item 15 when it lands |
| `OIDFED §5(3)` | Metadata never uses `null` as a value | `EntityStatementChecks`, `MetadataPolicy` | Implemented |
| `OIDFED §5.1.1` | The entity's `federation_entity` metadata: fetch and list endpoints only when it has subordinates (a leaf MUST NOT publish them), the resolve endpoint only when a resolver is configured, and `organization_name` when set | `FederationService`, `FederationConfiguration` | Implemented |
| `OIDFED §5.1.3` | The OP metadata: `issuer` is the entity's identifier, `client_registration_types_supported` is what the deployment accepts, and `federation_registration_endpoint` appears exactly when explicit registration does | `FederationService`, `FederationConfiguration` | Implemented |
| `OIDFED §6.1.3(2.2)` | An operator refuses a metadata parameter of a JSON type it does not support | `MetadataPolicy` | Implemented |
| `OIDFED §6.1.3(2.4)` | An operator refuses an operand of a JSON type it does not support | `MetadataPolicy` | Implemented |
| `OIDFED §6.1.3(2.5)` | Operators combine only as each one declares - checked on every parsed and every merged policy | `MetadataPolicy` | Implemented |
| `OIDFED §6.1.3(2.8)` | No operator outputs a metadata parameter with the value `null` | `MetadataPolicy` | Implemented |
| `OIDFED §6.1.3.1.1` | `value`: sets the parameter (`null` removes it); merges only when equal; its combinations; applied first | `MetadataPolicy` | Implemented |
| `OIDFED §6.1.3.1.2` | `add`: adds what is missing; merges as the union; its combinations; applied after `value` | `MetadataPolicy` | Implemented |
| `OIDFED §6.1.3.1.3` | `default`: fills an absent parameter; merges only when equal; applied after `add` | `MetadataPolicy` | Implemented |
| `OIDFED §6.1.3.1.4` | `one_of`: checks a present single value; merges as the intersection, empty being an error; applied after `default` | `MetadataPolicy` | Implemented |
| `OIDFED §6.1.3.1.5` | `subset_of`: keeps the intersection, which may be empty; merges as the intersection; applied after `one_of` | `MetadataPolicy` | Implemented |
| `OIDFED §6.1.3.1.6` | `superset_of`: requires every listed value when the parameter is present; merges as the union; applied after `subset_of` | `MetadataPolicy` | Implemented |
| `OIDFED §6.1.3.1.7` | `essential`: requires the parameter when true; merges as logical OR; applied last | `MetadataPolicy` | Implemented |
| `OIDFED §6.1.3.1.8` | `scope` is processed as an array of values and written back as a string; the `essential`/`subset_of` table | `MetadataPolicy` | Implemented |
| `OIDFED §6.1.3.2` | An additional operator is ignored unless it is critical | `MetadataPolicy` | Implemented |
| `OIDFED §6.1.4.1` | The chain's policy is merged from the anchor's statement down: parameters only one side has are copied, operators both have merge by their own rule, and a merge that fails or yields a forbidden combination refuses the chain | `MetadataPolicy.composeWith`, `TrustChainValidator` | Implemented |
| `OIDFED §6.1.4.2` | The immediate superior's `metadata` is applied first, then the merged policy, operator by operator in order, to the Entity Types the subject has; metadata the policy rejects is not used | `TrustChainValidator`, `MetadataPolicy.apply` | Implemented |
| `OIDFED §6.1.5` | The specification's worked example merges and resolves to its own published results | `MetadataPolicy` | Implemented (example fixtures extracted from the Final text) |
| `OIDFED §6.2(4)` | An unknown constraint parameter is ignored | `Constraints` | Implemented |
| `OIDFED §6.2(7)` | Every Subordinate Statement's constraints apply independently; one failing invalidates the chain | `TrustChainValidator`, `Constraints` | Implemented |
| `OIDFED §6.2.1` | `max_path_length`: an integer of zero or more, counting the Intermediates between the setter and the subject | `Constraints` | Implemented |
| `OIDFED §6.2.2` | `naming_constraints`: RFC 5280 domain name constraints on the host of every entity below the setter; excluded wins over permitted | `Constraints` | Implemented - an empty `permitted` permits nothing, an IP host matches only itself |
| `OIDFED §6.2.3` | `allowed_entity_types`: other types are removed from the subject's metadata after its superior's metadata and before policy; `federation_entity` is never removed and may not be listed | `Constraints`, `TrustChainValidator` | Implemented |
| `OIDFED §8(2)` | A request parameter an endpoint does not define is ignored: fetch accepts the `iss` draft-era clients send, and this entity sends it too for draft-era fetch endpoints | `FederationService`, `HttpTrustControllerGateway` | Implemented |
| `OIDFED §8.1.1` | Fetch takes `sub`; `iss` is optional and must name this entity | `FederationService.fetchSubordinateStatement`, `OpenIdFederationServlet` | Implemented |
| `OIDFED §8.1.2` | Fetch answers `application/entity-statement+jwt`; `invalid_request` when `sub` is missing or names this entity itself, `not_found` for a subject it has no statement about | `FederationService`, `OpenIdFederationServlet` | Implemented |
| `OIDFED §8.2.1` | List filters: `entity_type` repeats and every one must match; `intermediate=true` lists only subordinates known to have their own; `trust_marked` and `trust_mark_type` answer `unsupported_parameter` until this entity issues Trust Marks | `FederationService.listSubordinates`, `OpenIdFederationServlet` | Implemented - Trust Mark filters follow §7 |
| `OIDFED §8.2.2` | List answers a JSON array of Entity Identifiers | `OpenIdFederationServlet` | Implemented |
| `OIDFED §8.3(1)` | Resolve assembles a chain from the subject's configuration to the requested anchor's, validates it and applies its policies - this entity's own statements produced in-process, not fetched from itself | `FederationService.resolve`, `LocalFirstTrustControllerGateway`, `TrustChainValidator` | Implemented |
| `OIDFED §8.3.1` | Resolve needs `sub` and at least one `trust_anchor` (which repeats); `entity_type` narrows the metadata returned | `FederationService.resolve`, `OpenIdFederationServlet` | Implemented |
| `OIDFED §8.3.2` | The resolve response: a signed `resolve-response+jwt` with `kid`, served as `application/resolve-response+jwt`, whose `exp` is the chain's and whose `trust_chain` ends with the anchor's configuration; no Trust Mark appears unverified | `FederationService.resolve` | Implemented - no `aud` until §8.8 client authentication |
| `OIDFED §8.9` | Every federation error is `{"error", "error_description"}` as `application/json` with the status §8.9 gives its code; a fault of ours shows nothing of itself | `FederationError`, `TrustChainValidationException`, `FederationErrors`, `OpenIdFederationServlet`, `OpenIdRegistrationServlet` | Implemented |
| `OIDFED §9(1)` | A trailing `/` is removed from an Entity Identifier before `/.well-known/openid-federation` is appended | `EntityId`, `HttpTrustControllerGateway` | Implemented |
| `OIDFED §10(1)` | Several trusted anchors: chains to each are validated independently, and a subject resolves through whichever validates | `TrustChainValidator` | Implemented |
| `OIDFED §10.1` | Route discovery: hints ending at an unknown anchor are skipped, the configured anchors are tried first, and a loop is never followed | `TrustChainValidator` | Implemented |
| `OIDFED §10.2` | Every §10.2 check per statement: required claims, `iat` past and `exp` future, `iss` of each is `sub` of the next, each verified by the next one's keys, ES[0] by its own keys too, ES[i] by the anchor's | `TrustChainValidator`, `HttpTrustControllerGateway` | Implemented |
| `OIDFED §10.3` | Of several trusted anchors, the one a caller asks for is preferred, and a caller can never widen the set; otherwise configuration order decides. Registration and the token-endpoint checks validate against the whole pinned set | `TrustAnchorSet`, `TrustChainValidator`, `FederationRuntimeConfig.trustAnchors`, `RegistrationService`, `OIDFederationUtils` | Implemented |
| `OIDFED §10.4` | A chain expires with its earliest statement | `TrustChainValidationResult.expiresAt` | Implemented |
| `OIDFED §10.5` | A failure to reach an entity is reported as temporary, not as an invalid chain | `TrustChainValidator` | Implemented |
| `OIDFED §11.3` | A mismatch between the out-of-band keys and the anchor's entity configuration is retrieved again before it is treated as a problem | `HttpTrustControllerGateway` | Partial - compares by verifying the configuration's signature with a pinned key rather than by key-set equality, so an in-progress §11.2 rollover is not a mismatch; a second failure is refused |
| `OIDFED §12.1` | Automatic registration against the trust controller | `RegistrationService`, `TokenEndpointAutoRegistrationFilter` | Implemented at the token endpoint |
| `OIDFED §12.2` | Explicit registration against the trust controller | `ExplicitRegistrationRequest`, `RegistrationService` | Implemented |
| `OIDFED §12.2.1` | An Explicit Registration request's `aud` is the OP and nothing else, and its `trust_chain` header begins with its own configuration | `EntityStatementChecks`, `ExplicitRegistrationRequest` | Implemented |
| `OIDFED §13.4` | `crit` is a non-empty array of extension claim names; a JWT listing one the recipient does not understand is invalid | `EntityStatementChecks` | Implemented |
| `OIDFED §18.1(3)` | One validation's network work is bounded: a fetch budget across every anchor and any peer chain, and a route depth limit | `TrustChainValidator`, `ValidatorOptions` | Implemented |
| `OIDFED §18.1(4)` | Only a limited number of `authority_hints` is inspected per entity | `TrustChainValidator`, `ValidatorOptions.maxAuthorityHints` | Implemented |
| `OIDFED §18.1(5)` | A complete presented chain is validated with the anchor's keys and nothing is fetched | `TrustChainValidator` | Implemented |
| `OIDFED §18.1(7)` | Without client authentication the resolve endpoint resolves only this entity, its subordinates and the entities it hosts, unless discovery is switched on | `FederationService.resolve`, `FederationConfiguration.ResolveDiscovery` | Implemented - `OIDF_FEDERATION_RESOLVE_DISCOVERY=any` opens it |
