# Dead federation code is removed, and the test-only reset hooks are no longer public

## Changelog

- Removed the federation code nothing called (plan item H-FED-10, F-0052): `ClientEntityAuthorizer`; the trust
  controller gateway's `fetchEntityConfiguration()`, `fetchMembers()` (its client for `/list`) and both
  `fetchEntityConfigurationOf` overloads; `BridgeSigners.require`; and the deprecated overloads with no caller -
  `JwtCodec.verifyAgainstInlineJwks` and `verifyAgainstKeys` without a `VerificationPolicy`,
  `FederationService.fetchEntityStatement(String, String, String)` and `listSubordinates(String)`, and
  `TrustChainValidationResult.leafMetadata()`. The federation list endpoint itself is unchanged.
- `resetForTests` on `TrustMarkSupport`, `AuthoritySupport`, `KeyHistorySupport`, `FederationRuntimeConfig` and
  `FederationPolicySupport` is package-private, so production code cannot reset process-wide federation state. Tests
  in other packages call `<Class>TestAccess.reset()`, published in openid-federation's test-jar and in a new
  pf-integration test-jar.
- The deprecated members that still have production callers stay, and their javadoc names the release that removes
  them, 1.0.0: the federation event façades (`FederationEvent`, `FederationEvents`, `FederationEventSink`,
  `LoggingEventSink`, the federation `LogSafe`, `PfAuditEventSink`; F-0430) and `AttestationReplayCache.record` and
  `firstSeen` (F-0431).

## Before you deploy

1. **Removed public methods: move any code of your own that calls them to the replacement.** What: public members of
   the openid-federation, oidf-jose and pf-integration jars are gone; nothing in this repository called them. Why:
   dead code that nobody tests drifts from the code that runs (H-FED-10). How to tell: code of your own that uses one
   stops compiling against 0.6.0 - a deployment that only runs the image or the released jars is not affected. What to
   change, member by member:
   - `ClientEntityAuthorizer.authorize` - no replacement; read the metadata from
     `TrustChainValidationResult.resolvedMetadata()` or `metadataFor("oauth_client")` and decide in your own code.
   - `TrustControllerGateway.fetchEntityConfiguration()` and `fetchMembers()` - drop them from your own
     implementation (an `@Override` of either no longer compiles). To read an Entity Configuration, call
     `fetchEntityStatement(issuer)`; to list an authority's subordinates, request its list endpoint.
   - `TrustControllerGateway.fetchEntityConfigurationOf(issuer)` and `(issuer, pendingWrites)` - call
     `fetchEntityStatement(issuer)` (or `fetchEntityStatement(issuer, -1L, pendingWrites)`), check the type with
     `JwtCodec.requireType(JwtCodec.getJwtHeaders(jwt), "entity-statement+jwt")`, then `JwtCodec.parseUnverifiedClaims(jwt)`.
   - `JwtCodec.verifyAgainstInlineJwks(jwt, jwks, issuer)` - `verifyAgainstInlineJwks(jwt, jwks, issuer, Set.of(),
     VerificationPolicy.legacy())`; the four-argument form and `verifyAgainstKeys(jwt, keys, issuer, algorithms)` take
     `VerificationPolicy.legacy()` as a fifth argument, which is what they did. Prefer the policy for what you verify
     (`VerificationPolicy.entityStatement()` for an Entity Statement).
   - `FederationService.fetchEntityStatement(issuer, subject, oidcIssuer)` - `fetchSubordinateStatement(issuer,
     subject, oidcIssuer)`.
   - `FederationService.listSubordinates(entityType)` - `listSubordinates(new ListRequest(List.of(entityType), null,
     null, null))`, or `ListRequest.all()` for no filter.
   - `TrustChainValidationResult.leafMetadata()` - `metadataFor("openid_relying_party")`.
   - `BridgeSigners.require(clientId)` - `BridgeSigners.forClient(clientId)`, which is empty when the client has no
     bridge key.
   - `resetForTests()` on the five classes above - in a test, `<Class>TestAccess.reset()` from the
     `openid-federation` or `pf-integration` artefact of type `test-jar`.

   There is no development-profile escape: these are compile-time removals, with no setting or runtime behaviour to
   choose.

## Notes

- How each item was shown dead, on origin/main e377dbae (2026-10-01): `/usr/bin/grep` over the main code of every
  reactor module found no caller, and none of pf-oidf-modules (55629cc), idp-agentic-demo (9eee704),
  idp-fed-agentic-connector (87d166e) or pf-agentic-identity-domain-authority (46fdcc3) imports one - their mentions
  are in prose, comments and their own JavaScript. The compiler is the second check: the whole reactor builds with them
  gone. `fetchEntityConfigurationOf` had no production caller once S5B moved the gateway's one read to the private
  `configurationOf`; the openid-federation coverage gate now names `configurationOf` in place of the three removed
  methods, so the refusal of an untyped Entity Configuration (OpenID Federation 1.0 §3) stays gated.
- Kept: `RarEntitlement`, deprecated since 0.4.0 with no caller, because F-0100 records that its deletion removes a
  test class and public members of client-attestation and waits for the owner's say-so in a pull request of its own.
  The event façades and the relative replay methods have production callers (F-0430, F-0431). `ProfileRefusals.resetForTests`
  (libs/platform) and three other public test seams in pf-integration are F-0432.
- The showcase: the limitation that said the overloads without a `VerificationPolicy` remain is gone, and the citations
  into every file this package edits were re-pointed, the `JwtCodec` and `FederationService` ones by reading the lines.
- For whoever folds the fragments: HJOSE's fragment says the `JwtCodec` overloads without a `VerificationPolicy` are
  deprecated and "go in a later release"; this package removes them in the same release, 0.6.0. Its changelog bullet
  and its Before-you-deploy item on `UnverifiedClaims` should say they are removed, and point at this fragment's
  **Removed public methods** item for the replacement.
- Plan decisions this package builds on as the plan recommends, not yet confirmed by the owner: decision 16 (H-* is
  Phase 3, grouped by module; H-FED-10's rest is HFEDD, last).
