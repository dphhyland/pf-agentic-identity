# Every operator surface on the operator authenticator

## Changelog

- The federation administration API (`/federation/admin/*`), hosted-entity enrolment (`POST /federation/agents`,
  `/federation/resources`) and revocation (`DELETE .../<id>`), `/federation/registered-clients`, and the health
  detail and `/agentic-identity/info` are operator routes on `OperatorAuthenticator` (plan item S8b): each needs a
  PingFederate-issued access token with its own scope, DPoP-bound in production, and every request - let through or
  refused - is an `admin.request.*` event labelled with its route. The route list is in
  [docs/operator/operator-authentication.md](../../operator/operator-authentication.md#the-routes); tests in each
  module fail on a mapped path that has no route.
- The actor every change records - in Trust Mark grants, hosted entities' histories, key revocations, the federation
  events and the policy decision point's enrolment questions - is the token's `sub`. `X-Federation-Actor` names
  nobody: it is only the operator event's `claimed_label`, and inside PingFederate server.log carries a digest of it
  (F-0165). The federation events' `actor` is classed `PSEUDONYMOUS_ID`.
- A hosted-entity revocation through `DELETE` records its actor and emits `federation.hosted_entity.revoked`.
- The static bearer `OIDF_AUTHORITY_ADMIN_TOKEN` is one rule in `OperatorAuthenticator`: accepted in development,
  with a WARN per request, never in production. `HealthAccess` and `AdminBearer` are gone (F-0008, F-0194).
- SSF's receiver and provisioner tokens are checked through platform's `TokenIntrospector`
  (`PfIntrospectionReceiverAuthenticator`), whose own HTTP client is gone.
- device-enrolment enrols agents with a DPoP-bound client-credentials token for `oidf.admin.entities`: new settings
  `PF_AUTHORITY_CLIENT_ID`, `PF_AUTHORITY_CLIENT_JWK`, `PF_AUTHORITY_CLIENT_SECRET` and
  `PF_AUTHORITY_TOKEN_ENDPOINT`.
- platform-pf publishes a test-jar with `OperatorTestKit`, for the operator surfaces' tests.

## Before you deploy

1. **Operator APIs now need a PingFederate-issued, DPoP-bound access token in production.** What to do: in
   PingFederate, create the scopes (exclusive) and an operator client for each person or automation - client
   credentials, "Require DPoP" on, only the scopes it needs, a token manager whose tokens carry
   `OIDF_OPERATOR_AUDIENCE` in `aud` - and set `OIDF_OPERATOR_AUDIENCE`, `OIDF_OPERATOR_BASE_URL` and
   `OIDF_OPERATOR_JWKS_URL` (or introspection mode's settings), as
   [operator-authentication.md](../../operator/operator-authentication.md#what-pingfederate-needs) lists. The scope
   each route needs: `oidf.admin.read` for every GET of `/federation/admin/*`; `oidf.admin.trust_marks` for
   `POST /federation/admin/trust-marks` and `/trust-marks/revoke`; `oidf.admin.keys` for `POST /federation/admin/keys/revoke`
   and `/entities/rotate-key`; `oidf.admin.entities` for `POST /federation/admin/entities/suspend`, `/reactivate`,
   `/revoke`, `/metadata` and `/metadata-policy`, and for `POST /federation/agents`, `POST /federation/resources` and
   `DELETE` of one of their entities; `oidf.admin.clients.read` for `GET /federation/registered-clients`;
   `oidf.health.read` for `GET /agentic-identity/health` and `/agentic-identity/info`. Why: the static bearer was
   one shared secret for every surface (F-0008). How to tell: a call with the old bearer answers 401 with a
   `WWW-Authenticate: DPoP algs=...` challenge (503 while the bearer is still set: see **Remove `OIDF_AUTHORITY_ADMIN_TOKEN` from production**), and PingFederate's
   audit log records `admin.request.refused`. Development-profile escape: `OIDF_DEPLOYMENT_PROFILE=development` still
   accepts `OIDF_AUTHORITY_ADMIN_TOKEN` as `Authorization: Bearer`, with a WARN per request, and a token bound to
   nothing, with a WARN.
2. **Remove `OIDF_AUTHORITY_ADMIN_TOKEN` from production.** What to do: unset it, the `oidf.authority.admin_token`
   system property and any `adminToken` init-param. Why: production never accepts it, and while it is set the
   operator API component is `REFUSED` and every operator route - hosted-entity enrolment, the registered clients and
   the health detail included - answers 503, so an upgrade with the token in place fails at once instead of leaving
   an operator believing it still protects something (Phase 3 decision 20). How to tell: the health detail (or
   server.log) shows `OPERATOR_API` `REFUSED` with "OIDF_AUTHORITY_ADMIN_TOKEN is set, and production never accepts
   the static bearer: remove it". Unset with `OIDF_OPERATOR_API_ENABLED` unset beside it, production reports the
   component `FAILED_CONFIG` naming the switch instead (F-0312); the fix is the same. Development-profile escape: the
   token keeps working in development.
3. **Give device-enrolment a PingFederate client.** What to do: in PingFederate, a client with the client credentials
   grant, the `oidf.admin.entities` scope, "Require DPoP" and `private_key_jwt` (or a secret); in device-enrolment,
   set `PF_AUTHORITY_CLIENT_ID` with `PF_AUTHORITY_CLIENT_JWK` or `PF_AUTHORITY_CLIENT_SECRET` (exactly one), and
   `PF_AUTHORITY_TOKEN_ENDPOINT` if the token endpoint is not `<PF_AUTHORITY_URL>/as/token.oauth2`; remove
   `PF_AUTHORITY_ADMIN_TOKEN`. `OIDF_OPERATOR_BASE_URL` on the PingFederate side must be the origin of
   `PF_AUTHORITY_URL`, because the proof's `htu` is built from it. Why: `POST /federation/agents` is an operator
   route. How to tell: with `PF_AUTHORITY_ENTITY_ID` set and neither client nor (in development) static bearer,
   device-enrolment does not start, naming the settings; in production it does not start while
   `PF_AUTHORITY_ADMIN_TOKEN` is set; a client PingFederate does not bind is an enrolment error "not a DPoP-bound
   one". Development-profile escape: `PF_AUTHORITY_ADMIN_TOKEN` alone still works in development, with a WARN per
   enrolment.
4. **The health detail and /info need `oidf.health.read`.** What to do: give the monitoring client that reads
   `/agentic-identity/health` or `/agentic-identity/info` a DPoP-bound token with `oidf.health.read`; live and ready
   stay open. Why: the detail's reasons can name settings, paths and exception messages, and it used a second copy
   of the static-bearer rule with no limit on guesses (F-0194). How to tell: these now answer 401 with a challenge
   (403 for a token without the scope, 429 after ten failures a minute from one address) where they answered 404.
   gm-api.war's detail and info answer 503, since that war carries no rs-validation (F-0310). Development-profile
   escape: the static bearer, as for every operator route.
5. **SSF receiver tokens are checked through the shared introspection client.** What changed: introspection now
   has deadlines (1 s to connect, 2.5 s in all; no answer is a 503), reads the answer strictly (`scope` must be a
   space-separated string, as RFC 7662 §2.2 has it; a JSON array is no answer, a 503), and holds an active token to
   its `exp` and `nbf`, to carrying a `client_id`, and - when it carries an `aud` - to naming `OIDF_SSF_ISSUER` in it;
   a token bound to a key or certificate (`cnf`) is refused, because these endpoints take bearer tokens only. What to
   do: check that the access token manager behind receivers' and provisioners' tokens either sets no audience or
   includes the transmitter's issuer, and that their clients are not set to "Require DPoP". How to tell: a receiver
   that worked before and now gets 401 `invalid_token` has a token with another `aud`, no `client_id`, or a DPoP
   binding; server.log's `SSF refused an active token:` line says which. There is no development-profile escape: the
   rule is the same in both profiles, because none of it depends on the deployment.

## Notes

**Verify first (2026-09-30).** PingFederate 13.1.3's introspection returns `cnf.jkt` and `token_type` `DPoP` for a
DPoP-bound token (U-0030, closed by S8A on 2026-09-29), so SSF could check a binding. The SSF receivers this
repository knows send `Bearer`: the conformance suite's `conformance-ssf-receiver` is created without DPoP
(conformance/terraform/clients.tf: "Not DPoP-bound: the SSF servlet takes a plain bearer token"), and pf-oidf-modules'
`harness/probe-ssf.sh` sends `Authorization: Bearer`. So SSF keeps bearer receiver tokens and refuses a bound one it
has no proof for; its callers are the transmitter's receivers and provisioners, not operators.

**No route yet** for `oidf.admin.subordinates`, `oidf.admin.subordinates.approve` (no subordinate administration API
is served from this repository), `ssf.admin` (every SSF path is a receiver's own stream or a provisioner's) or
`oidf.metrics.read`. The RAR models' fingerprint is not served over HTTP.

**Consumers that send the static bearer today** (owner actions): pf-oidf-modules' probes and bootstrap,
idp-agentic-demo's admin calls, and the connector each need an operator client and a DPoP-bound token for production,
or the development profile.
