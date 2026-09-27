# The containment model wired into the token gate and the attester (S1b)

## Changelog

- Plan item S1b (design S-1, blocker B1): the authorization server's token gate and the attester compare every
  `authorization_details` field with `libs/rar-model`, a refused request is 400 `invalid_authorization_details`,
  and an instance ceiling keeps what its client's constrains. Closes [F-0034](../../findings/F-0034.yaml) and
  [F-0038](../../findings/F-0038.yaml); [F-0001](../../findings/F-0001.yaml) stays open until S1c; adds
  [F-0100](../../findings/F-0100.yaml) (#37).

## Before you deploy

1. **Token and PAR requests are compared field by field with the attestation's `authorization_details`.** The
   attestation filter, and the issuance criterion where the filter does not run, compare a request's
   `authorization_details` (or `oidf_requested_access`) with the verified Client Attestation's using
   [libs/rar-model](../../../libs/rar-model/README.md): every field by its type's rule. 0.3.0 compared `type` and
   five array fields, so an amount above the attestation's, another creditor account or a later `validUntil` was
   granted; it is now refused. A field the type's model does not declare, a type no model names and a value of the
   wrong shape are refused too. idp-agentic-demo's payment fields in the built-in tables pass; what it sends beyond
   them is [U-0057](../../findings/U-0057.yaml). A type with fields of its own needs a models document that
   `extends` the built-in: see **Give every PingFederate node the same models document, or none**.
2. **A token request restates every field its attestation constrains.** The token gate compares strictly: a field
   the attestation's details constrain and the request leaves out is not within them, and the request is refused.
   0.3.0 granted it, and PingFederate issued the detail without the field, which reads as unconstrained - wider
   than the attestation. The filter forwards the request's own details, so the gate cannot fill a field in. The
   0.4.0 notes' item on this wiring says a constrained field the request omits is filled from the ceiling: that is
   the attester, at issuance, not the token endpoint. What to change: for every field an attestation's detail
   carries, send that value or a narrower one. An attestation of
   `[{"type":"sales_agent","sales_regions":["EMEA"],"max_txn_eur":5000}]` needs a request that names
   `sales_regions` and `max_txn_eur`. How to tell: 400 with `authorization_details exceeds what the client
   attestation allows`.
3. **A refused request is 400 `invalid_authorization_details`, not 401 `access_denied`.** CAS §7.1: an
   authorization server "MUST reject requests exceeding it with `invalid_authorization_details`". The filter
   answers 400, the status RFC 6749 §5.2 gives the token endpoint's errors, with a fixed description:
   `authorization_details is malformed`, `authorization_details exceeds a size limit`, `authorization_details
   carries a field its type does not define`, `authorization_details names a type this server does not support`,
   or `authorization_details exceeds what the client attestation allows`. An attestation whose own details this
   server's model refuses - a type it has no model for, say - is 401 `invalid_client`, `the client attestation's
   authorization_details cannot be evaluated by this server`. The log line names the detail and the field; no
   response carries a value. On the criterion path PingFederate answers a refusal with the Error Result configured
   on the criterion (400 `invalid_grant`). What to change: a client that read 401 `access_denied` as "outside my
   attestation" reads 400 `invalid_authorization_details`.
4. **Give every PingFederate node the same models document, or none.** `OIDF_RAR_MODELS_FILE` (a path) or
   `OIDF_RAR_MODELS` (the document inline), environment variables only, not both. It is read once per classloader:
   when the attestation filter or the attester starts, and on the criterion's first call. Its fingerprint is logged
   (`RAR containment models loaded: fingerprint=...`) and published in the attestation context as
   `rar_models_fingerprint`, which the RAR plugin compares with its own from S1c, so the plugin must see the same
   variables. A document the library refuses, an unreadable file, or both set: with attestation authentication
   configured the filter refuses to start, which takes `pf-runtime.war` and PingFederate's runtime down with it, as
   a broken bridge configuration does (plan item S-9 changes that in Phase 3); the attester fails from its first
   request; the criterion refuses every attested token. How to tell: `server.log` says `RAR containment models
   could not be loaded`, naming the reason.
5. **Stage `rar-model-<version>.jar` beside the other modules.** `build/pingfederate/stage-modules.sh` stages it:
   nine jars in production, ten in conformance. A deployment that copies jars by hand puts it in both
   `pf-runtime.war`'s `WEB-INF/lib` and `server/default/deploy`: without it the attestation filter does not start,
   and the criterion and the attester fail with `NoClassDefFoundError`. `oidf.war` and
   `services/device-enrolment` take it as a dependency.
6. **The attester holds configured ceilings to the model, and an instance ceiling keeps what its client's
   constrains.** `attestation_entitlement` and each instance's `entitlement` must be details the model accepts. A
   client whose ceiling it refuses is skipped by the PingFederate client store, with a warning naming it; a CIMD or
   federation source refuses its whole mapping list, as it does for any invalid entry. An instance ceiling under a
   client ceiling is now `authorize(instance, client, INHERIT)`, kept: an instance that left out a field its client
   constrains gets the client's value (F-0034). Its attestations carry that field, so **A token request restates
   every field its attestation constrains** applies to them. How to tell: `server.log` says `Skipping attestation
   client with invalid config`.
7. **The attester mints the fitted grant, and narrows an asserted context to the overlap.** A requested detail is
   minted with every field its ceiling entry constrains and the request leaves out, for every rule; an empty
   request still gets the full ceiling. A request outside the ceiling is 403 `access_denied`; one the model cannot
   compare is 400 `invalid_request`, naming the detail and the field; `_principal_sub` and `_agent_id` in an
   issuance request are refused. An asserted-context ceiling narrows with the model's meet: an evidenced
   EMEA-and-APAC entry under an asserted EMEA one is minted as EMEA, where 0.3.0 dropped it - more than before,
   never more than both allow.
8. **Code that builds a `ClientAttestationVerifier` or reads its result has new members.**
   `ClientAttestationVerifier.withRarModels(...)` takes a model set; the public constructor takes the
   classloader's and throws `IllegalStateException` when it could not be loaded. `ClientAttestationResult` gains
   `rarModelsFingerprint()` and a ten-argument constructor, and `grantedAuthorizationDetails()` is the request's own
   details without the two markers, no longer filled from the attestation. `RarEntitlement` is deprecated for
   removal (F-0100), and `rar-model` is a new dependency of `client-attestation`.

## Notes

What changed, in short (the module READMEs have the detail): `AuthorizationDetailsGate` in `libs/client-attestation`
is the token gate - the request's details, without the `_principal_sub` and `_agent_id` markers, strictly within
the attestation's, which it reads from the verified payload with the model's own reader. `AttestationRarModels`
holds each classloader's model set. `servlets/pf-integration` loads it when the filter starts, maps the refusal to
400 and publishes `rar_models_fingerprint`; the criterion loads it on its first call. `servlets/attestation-issuer`
mints `authorize(requested, ceiling, INHERIT)`, narrows an asserted context with `intersect`, and parses both
ceilings with the model. The flow harness's in-entitlement request restates `privileges`.

Verification, 2026-09-27, on branch `prod/p1-rar-wire-cas-as`:

- `mvn -o -B clean verify` of `client-attestation`, `pf-integration` and `attestation-issuer` with their
  dependencies, on JDK 20 and on JDK 17.0.11: every test and every coverage gate passed. The gates gained
  `AuthorizationDetailsGate.check`, `withoutMarkers`, `ceilingOf` and `describe`, `AttestationRarModels.get` and
  `require`, `ClientAttestationUtils.attestationContext` and `refusalDetail`, `AttestationIssuanceServlet.grant`,
  `intersectCeilings`, `rarModels` and `init`, and `AttestationIssuanceConfig.instanceCeiling` and
  `clientCeiling`, all at 100% line and branch.
- The shared vector file ran through two more surfaces. `AsVectorRunnerTest` put 189 of its cases through
  `ClientAttestationVerifier.verify` with the ceiling in a signed attestation, and three of them are answered
  differently on purpose: the two marker cases and a malformed ceiling under an empty request. `CasVectorRunnerTest`
  put 81 case-surface pairs through the mint, the configuration parse and the asserted context, three answered
  differently on purpose (CAS §7 rule 2 and §6.1), and presented every minted attestation to the token gate.
- `services/harness`: `AttestationFlowHarness selfverify` passed 5 of 5 after its request restated `privileges`
  (4 of 5 before), and `AttestationIssuanceHarness` passed its 3 checks.

Residual risk:

- A token request with no `authorization_details` is not checked at the token endpoint, and what PingFederate
  issues from details stored at PAR or the authorization endpoint is plan item S4d ([F-0032](../../findings/F-0032.yaml)).
- An attestation that carries a type the authorization server has no model for is refused (`invalid_client`) even
  when the request names only modelled types: the attester and every authorization server need one models
  document.
- The attestation context's `entitlement` is still jose4j's parse, whose decimals are doubles; the gate compares
  the payload exactly. The RAR plugin reads the context from S1c.
- A refused request is logged, not emitted as an audit event (plan item O-2), and the fingerprint is not in a
  health endpoint yet (O-4).
- As in 0.3.0, the proof's `jti` is spent before the ceiling check, so a refused request needs a fresh proof.
