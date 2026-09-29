# The operator authenticator, and DpopProofValidator in oidf-jose

## Changelog

- `OperatorAuthenticator` in libs/platform-pf decides who may use an operator API: a PingFederate-issued access
  token, verified against PingFederate's JWKS or at its introspection endpoint, whose `iss` is PingFederate's, whose
  `aud` holds `OIDF_OPERATOR_AUDIENCE`, carrying the route's scope, and in production bound by DPoP (`htu` from
  `OIDF_OPERATOR_BASE_URL`, never the `Host` header) or a client certificate. The actor is the token's `sub`. Each
  decision is an `admin.request.authorised` or `admin.request.refused` event from the new `operator` catalogue.
  Failed authentications are limited to 10 a minute per client address and changes to 60 a minute per operator
  (plan item S8a). Its settings are the new `operator-auth` catalogue; see
  [docs/operator/operator-authentication.md](../../operator/operator-authentication.md).
- `TokenIntrospector` in libs/platform asks an RFC 7662 endpoint within 1 s to connect, 2.5 s in all and 64 KiB, and
  reads `cnf` and `token_type`; an active answer is kept at most 30 s.
- rs-validation's `DelegatedTokenValidator` takes an introspection endpoint in place of a JWKS, reports what each
  token was bound to, and, under the development profile only, accepts a token bound to nothing.
- `DpopProofValidator` and `DpopProof` move from client-attestation to oidf-jose, as
  `com.pingidentity.ps.oidf.jose.dpop`, and compare `htm` exactly (F-0225, F-0226). rs-validation no longer depends
  on client-attestation.
- rs-validation's jar is staged into PingFederate beside platform-pf.
- `EventsCataloguedTest` checks platform's `Events.event(component, code)` calls as it does the façade's.

## Before you deploy

1. **Deploy rs-validation beside platform-pf.** `build/pingfederate/stage-modules.sh` now stages
   `rs-validation-<version>.jar`, and the image carries it. A deployment that copies the module jars into
   PingFederate itself, rather than building the image, copies this one too; without it the operator APIs fail at
   first use with `NoClassDefFoundError` once S8b puts them on the authenticator.
2. **DpopProofValidator moved.** Code that imports `com.pingidentity.ps.oidf.clientattestation.DpopProofValidator`
   or `DpopProof` imports `com.pingidentity.ps.oidf.jose.dpop.DpopProofValidator` and `DpopProof` from oidf-jose
   instead; the methods are unchanged, except that a proof whose `htm` differs from the request's method in case is
   now refused. The one consumer known outside this repository is pf-agentic-identity-connector's
   `services/demo-rs` (`DelegatedTokenValidator`, checked 2026-09-30).

## Notes

**Nothing uses the authenticator yet.** Every operator surface still takes the static bearer
`OIDF_AUTHORITY_ADMIN_TOKEN` in this release; plan item S8b moves them onto `OperatorAuthenticator` with a scope
each, and F-0008 and F-0194 stay open until then. Setting `OIDF_OPERATOR_*` now changes nothing.

**PingFederate returns the binding at introspection.** On the conformance rig (PingFederate 13.1.3.0, 2026-09-29),
introspecting a DPoP-bound client-credentials token answered `cnf.jkt` - the proof key's thumbprint - and
`token_type` `DPoP`, for JWT and reference tokens, so introspection mode checks the binding as jwt mode does
(U-0030, U-0038). The reference token's answer has no `iss`, which RFC 7662 §2.2 makes optional. On 2026-09-30 the
authenticator let PingFederate's own DPoP-bound tokens through in both modes on JDK 17, 20 and 21.

**Two limits.** The failed-authentication limit counts the address the container reports, never
`X-Forwarded-For`, so behind a proxy PingFederate does not see through every caller shares one counter (F-0275;
HATT2's trusted-proxy rule later in Phase 3 moves the limits onto it). The authenticator does not ask for DPoP
nonces, so a proof's freshness rests on its `iat` window and its `jti` (F-0276).

**`OIDF_OPERATOR_ACCESS_TOKEN_TYP`.** PingFederate's JWT access token manager sends no `typ` unless its Type Header
Value is set, and rs-validation requires `at+jwt` by default (RFC 9068 §4), so the setting names what the manager
sends: `at+jwt`, `none`, or another value.
