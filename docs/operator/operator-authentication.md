# Operator authentication

How the operator APIs decide who may use them: a PingFederate-issued OAuth access token, bound to the caller's key
(DPoP) or certificate in production, carrying the scope of the route it is used on. The actor recorded for a change is
the token's subject. This is `OperatorAuthenticator` in libs/platform-pf (plan item S8a, 0.6.0); plan item S8b (0.6.0)
put every operator surface on it, each route with its own scope ([the routes](#the-routes)).

The static bearer `OIDF_AUTHORITY_ADMIN_TOKEN` is development's escape and nothing else
([the static bearer](#the-static-bearer)): production never accepts it, and refuses the operator APIs while it is set.

## What PingFederate needs

1. **The scopes.** One per surface, as exclusive scopes (Authorization Server Settings, Scopes), so that a client
   is given only the surfaces it uses:

   | Scope | Surface |
   |---|---|
   | `oidf.admin.read` | read the federation administration API: hosted entities, trust marks, keys, subordinates |
   | `oidf.admin.entities` | create, change and remove hosted entities |
   | `oidf.admin.trust_marks` | grant and revoke trust marks |
   | `oidf.admin.keys` | rotate and revoke hosted entities' keys |
   | `oidf.admin.subordinates` | manage subordinate statements |
   | `oidf.admin.subordinates.approve` | approve a pending subordinate, apart from managing them, so two people can hold the two |
   | `oidf.admin.clients.read` | read the registered clients |
   | `ssf.admin` | the Shared Signals transmitter's administration |
   | `oidf.metrics.read` | read `/metrics` |
   | `oidf.health.read` | read the health detail and `/agentic-identity/info` |

2. **An access token manager whose tokens name the operator APIs as their audience.** A JWT manager: set its
   Audience Claim Value to the value of `OIDF_OPERATOR_AUDIENCE`, and its Type Header Value to `at+jwt` (RFC 9068;
   left blank, set `OIDF_OPERATOR_ACCESS_TOKEN_TYP=none`). A reference (internally managed) manager, for
   introspection mode: add an `aud` attribute to its contract and fulfil it with the same text in the client
   credentials mapping. For a client-credentials token PingFederate makes `sub` the client id; that is the actor.
3. **One client per operator or automation**, client credentials, with "Require DPoP" on (production refuses an
   unbound token), the scopes it may use and nothing else, and the manager above as its default.
4. **For introspection mode, a client with the Access Token Validation grant** for the operator APIs to introspect
   as (`client_secret_basic`).

## Settings

The `operator-auth` catalogue, `libs/platform-pf/src/main/resources/META-INF/oidf-settings/operator-auth.json`:

| Setting | Default | What it is |
|---|---|---|
| `OIDF_OPERATOR_AUTH_MODE` | `jwt` | `jwt`: verify the token against PingFederate's keys. `introspection`: ask PingFederate's introspection endpoint (RFC 7662) |
| `OIDF_OPERATOR_AUDIENCE` | - | the audience a token must carry in `aud`; required in production |
| `OIDF_OPERATOR_BASE_URL` | - | the origin operators address the APIs at (`https://pf.example.com`); a DPoP proof's `htu` must be this followed by the request's path. Required in production, and https there |
| `OIDF_OPERATOR_JWKS_URL` | - | jwt mode: PingFederate's JWKS, `https://pf.example.com/pf/JWKS` for the central signing key |
| `OIDF_OPERATOR_ACCESS_TOKEN_TYP` | `at+jwt` | jwt mode: the `typ` the manager sends; `none` when its Type Header Value is blank |
| `OIDF_OPERATOR_INTROSPECTION_ENDPOINT` | - | introspection mode: `https://pf.example.com/as/introspect.oauth2` |
| `OIDF_OPERATOR_INTROSPECTION_CLIENT_ID`, `OIDF_OPERATOR_INTROSPECTION_CLIENT_SECRET` | - | introspection mode: the client above |
| `OIDF_OPERATOR_INSECURE_TLS` | `false` | trust any certificate on the JWKS and introspection calls; forbidden in production |
| `OIDF_OPERATOR_AUTH_FAILURES_PER_MINUTE` | 10 | failed authentications one client address may make in a minute |
| `OIDF_OPERATOR_MUTATIONS_PER_MINUTE` | 60 | changes one operator may make in a minute |

A configuration that cannot authenticate anyone - no audience, no base URL, no key source for its mode, insecure TLS
in production, or no Redis in production without the `in-memory-state` accepted risk - does not stop PingFederate
starting: the authenticator logs the reason once at WARN and answers every request 503.

**A JWKS or introspection endpoint under a private CA.** The JWKS and introspection calls trust what the JVM's default
TLS trust trusts, and inside PingFederate 13.1.3 that is PingFederate's Trusted CAs as they were when the JVM started:
`-Djavax.net.ssl.trustStore` is not honoured, and a CA imported through the admin API counts only after a restart.
Import the CA as a PingFederate Trusted CA, in the configuration archive or through the admin API followed by a
restart. Seen on the conformance rig in production on 2026-10-01 by the v0.6.0 release package
([U-0321](../findings/U-0321.yaml)).

`OIDF_OPERATOR_BASE_URL` is configured rather than read from the request on purpose: the `Host` header is the
caller's to choose, so a proof checked against a URL built from it proves nothing about where the caller meant to
send it.

## The routes

Every operator route, by surface, with the scope a token must carry and the `route` its events are labelled with.
HEAD is served wherever GET is, with the same route. A path or method no table names is answered 404 (405 for the
health endpoints) before any token is looked at.

`/federation/admin/*` (FederationAdminServlet; the table is `OperatorApi.FEDERATION_ADMIN` in pf-integration):

| Method and path | Scope | Route |
|---|---|---|
| `GET /federation/admin/trust-marks` | `oidf.admin.read` | `federation-admin.trust-marks.list` |
| `GET /federation/admin/trust-marks/audit` | `oidf.admin.read` | `federation-admin.trust-marks.audit` |
| `GET /federation/admin/keys` | `oidf.admin.read` | `federation-admin.keys.list` |
| `GET /federation/admin/entities` | `oidf.admin.read` | `federation-admin.entities.list` |
| `GET /federation/admin/entities/audit` | `oidf.admin.read` | `federation-admin.entities.audit` |
| `POST /federation/admin/trust-marks` | `oidf.admin.trust_marks` | `federation-admin.trust-marks.grant` |
| `POST /federation/admin/trust-marks/revoke` | `oidf.admin.trust_marks` | `federation-admin.trust-marks.revoke` |
| `POST /federation/admin/keys/revoke` | `oidf.admin.keys` | `federation-admin.keys.revoke` |
| `POST /federation/admin/entities/suspend` | `oidf.admin.entities` | `federation-admin.entities.suspend` |
| `POST /federation/admin/entities/reactivate` | `oidf.admin.entities` | `federation-admin.entities.reactivate` |
| `POST /federation/admin/entities/revoke` | `oidf.admin.entities` | `federation-admin.entities.revoke` |
| `POST /federation/admin/entities/metadata` | `oidf.admin.entities` | `federation-admin.entities.metadata` |
| `POST /federation/admin/entities/metadata-policy` | `oidf.admin.entities` | `federation-admin.entities.metadata-policy` |
| `POST /federation/admin/entities/rotate-key` | `oidf.admin.keys` | `federation-admin.entities.rotate-key` |

Hosted-entity enrolment and revocation (HostedEntityServlet; `OperatorApi.HOSTED_ENTITIES`):

| Method and path | Scope | Route |
|---|---|---|
| `POST /federation/agents`, `POST /federation/resources` | `oidf.admin.entities` | `hosted-entities.enrol` |
| `DELETE /federation/agents/<id>`, `DELETE /federation/resources/<id>` | `oidf.admin.entities` | `hosted-entities.revoke` |

The same servlet's `GET` (a hosted entity's Entity Configuration, which resolvers fetch with no credentials) and
`PUT .../entity-configuration` (a SELF_SIGNED entity publishing its own configuration, authorised by its federation
key's signature) are not operator routes (`OperatorApi.NOT_OPERATOR`).

`/federation/registered-clients` (RegisteredClientsServlet, still off unless `OIDF_REGISTERED_CLIENTS_ENABLED=true`;
`OperatorApi.REGISTERED_CLIENTS`):

| Method and path | Scope | Route |
|---|---|---|
| `GET /federation/registered-clients` | `oidf.admin.clients.read` | `registered-clients.list` |

The health detail and info (HealthServlet in platform-pf; `HealthServlet.ROUTES`); `/agentic-identity/health/live`
and `/ready` stay open:

| Method and path | Scope | Route |
|---|---|---|
| `GET /agentic-identity/health` | `oidf.health.read` | `health.detail` |
| `GET /agentic-identity/info` | `oidf.health.read` | `health.info` |

The other scopes have no route in this release: `oidf.admin.subordinates` and `oidf.admin.subordinates.approve`
(no subordinate administration API is served from this repository), `ssf.admin` (every SSF path is a receiver's own
stream or a provisioner's, on SSF's own scopes - `SsfRoutes` in servlets/ssf), and `oidf.metrics.read` (`/metrics`
is not served yet). The RAR models' fingerprint is not served over HTTP at all. The tests `OperatorApiRoutesTest`,
`HealthServletTest` and `SsfRoutesTest` read every `@WebServlet` mapping in their modules and fail on a path or method
that has no route and is not listed as not being one.

## The static bearer

`OIDF_AUTHORITY_ADMIN_TOKEN` - or the `oidf.authority.admin_token` system property, or a servlet's `adminToken`
init-param - is the one static credential left, and one rule, in `OperatorAuthenticator`, decides what it does:

- **Development** (`OIDF_DEPLOYMENT_PROFILE=development`): a request whose `Authorization: Bearer` credential is
  exactly the token, compared in constant time, is let through for any route, beside the OAuth path, with a WARN per
  request naming the route. Its actor is `admin:` and the first eight hex digits of the token's SHA-256 - the label the
  admin API recorded before - its binding `static-bearer`. A wrong credential goes on to the access-token checks, and
  a refusal there counts against the failed-authentication limit like any other; so does a change against the change
  limit.
- **Production**: never accepted. While it is set, every operator request is a 503 and the operator API component is
  `REFUSED`, with the reason "OIDF_AUTHORITY_ADMIN_TOKEN is set, and production never accepts the static bearer:
  remove it ..." (Phase 3 decision 20): an operator who upgrades with the old token in place finds out at once,
  instead of believing it still protects something. Its catalogue entry is classed `forbidden-in-production`.

The health endpoints used to hold a second copy of this rule (`HealthAccess`, finding
[F-0194](../findings/F-0194.yaml)); it is gone, as is pf-integration's `AdminBearer`.

device-enrolment, which enrols agents through `POST /federation/agents`, gets a DPoP-bound client-credentials token
of its own (`PF_AUTHORITY_CLIENT_ID`, see docs/configuration/device-enrolment.md); its `PF_AUTHORITY_ADMIN_TOKEN` is
the same development escape.

## What each request goes through

In this order; the first that fails decides the answer.

1. **The failed-authentication limit.** A client address that has failed authentication 10 times in the current
   minute is answered 429 with `Retry-After`, before its token is looked at. Every 400 and 401 below counts one.
2. **The token.** Exactly one `Authorization` header, scheme `DPoP` or `Bearer`, and no `access_token` in the query.
   In jwt mode the token is a JWS signed by a key in PingFederate's JWKS, with the configured `typ`; in introspection
   mode PingFederate says it is `active`. In jwt mode `iss` must be PingFederate's issuer (for this request's
   virtual host, through `PfInternals.issuer`); in introspection mode it is compared when the answer carries one,
   and may be absent (see [Introspection and the binding](#introspection-and-the-binding)). Either way `aud` contains `OIDF_OPERATOR_AUDIENCE`, and
   `exp` and `nbf` hold.
3. **The binding.** A token whose `cnf` has `jkt` needs a DPoP proof, checked by rs-validation and oidf-jose's
   `DpopProofValidator` against RFC 9449's list. The key's thumbprint must equal `cnf.jkt`, `htm` must equal the
   request's method exactly, `htu` must be the base URL plus the path, `ath` must be this token's hash, and the
   `jti` must not have been seen before. A token whose `cnf` has `x5t#S256` is accepted where the servlet container
   presents the client certificate it names (RFC 8705 §3). A token bound to nothing is refused in production;
   development accepts it with a WARN.
4. **The actor.** The token's `sub`, or its `client_id` when it has no subject. Never a header: `X-Federation-Actor`
   is recorded only as the event's `claimed_label`, cut to 128 characters and made safe for a log.
5. **The scope.** The route's scope must be among the token's.
6. **The change limit.** A route that changes something counts against the actor's 60 a minute.

RFC 9449 §4.3, the checks a server "MUST ensure", include "The htm claim matches the HTTP method of the current
request" and, with an access token, "ensure that the value of the ath claim equals the hash of that access token,
and confirm that the public key to which the access token is bound matches the public key from the DPoP proof."
RFC 9449 §4.2 defines `ath`: "Hash of the access token. The value MUST be the result of a base64url encoding (as
defined in Section 2 of [RFC7515]) the SHA-256 [SHS] hash of the ASCII encoding of the associated access token's
value." RFC 9110 §9.1: "The method token is case-sensitive", so a proof for `get` is not a proof for `GET`
(finding [F-0226](../findings/F-0226.yaml), fixed in this release).

## Answers

| Status | When | `WWW-Authenticate` |
|---|---|---|
| 401, no error | no credentials, or a scheme other than DPoP and Bearer | `DPoP algs="ES256 PS256 RS256"` and `Bearer realm="<base URL>"`, neither with an error |
| 400 `invalid_request` | two `Authorization` headers, a token in the query as well, or credentials that are not token68 | both challenges, both with the error |
| 401 `invalid_token` | the token fails a check in step 2, is bound to nothing in production, or its binding does not hold | both challenges, the error in the scheme the client used |
| 401 `invalid_dpop_proof` | the DPoP proof fails a check: `htm`, `htu`, `ath`, its signature, its age, or a replayed `jti` | the same |
| 403 `insufficient_scope` | the token lacks the route's scope | the error and `scope="<the scope>"` in the scheme used |
| 429 | a rate limit | none; `Retry-After` in whole seconds |
| 503 | not configured, PingFederate's issuer, keys, introspection endpoint or Redis could not answer | none |

Every answer carries `Cache-Control: no-store` and no body. RFC 6750 §3: "If the protected resource request does not
include authentication credentials or does not contain an access token that enables access to the protected
resource, the resource server MUST include the HTTP "WWW-Authenticate" response header field". A 503 is never a
pass: nothing that could not answer lets a request through, and an outage is not counted as the caller's failure.

## Introspection and the binding

RFC 7662 defines no `cnf`. Its §2.2 allows it: "Specific implementations MAY extend this structure with their own
service-specific response names as top-level members of this JSON object." RFC 9449 §6.2 is the extension for
DPoP: "For a DPoP-bound access token, the hash of the public key to which the token is bound is conveyed to the
protected resource as metainformation in a token introspection response. The hash is conveyed using the same cnf
content with jkt member structure as the JWK Thumbprint confirmation method, described in Section 6.1, as a
top-level member of the introspection response JSON." It goes on: "the resource server uses the data of the
introspection response to validate the access token binding itself locally", and "If the token_type member is
included in the introspection response, it MUST contain the value DPoP."

PingFederate 13.1.3 does this. On the conformance rig on 2026-09-29 (`GET /pf-admin-api/v1/version`:
`13.1.3.0`), a client-credentials token minted with a DPoP proof and introspected by a client with the Access Token
Validation grant answered, for a reference token (`jkt` shortened here):

```json
{"sub": "s8a-dpop-cc", "aud": "https://operator.example/agentic-identity", "scope": "profile", "active": true,
 "cnf": {"jkt": "nvGETWOWstcIZ9T7..."}, "token_type": "DPoP", "exp": 1790655173, "client_id": "s8a-dpop-cc"}
```

and for a JWT token the same members plus `"iss": "https://localhost:31031"`, with `cnf.jkt` equal to the
thumbprint of the proof's key. So introspection mode verifies the binding as jwt mode does. The reference answer has
no `iss`; RFC 7662 §2.2 makes `iss` "OPTIONAL", so in introspection mode `iss` is compared when present, and the
answer's source - the configured endpoint, over TLS, as an authenticated client - is what says who issued it. On
2026-09-30 the authenticator itself let through a DPoP-bound JWT (jwt and introspection modes) and a DPoP-bound
reference token (introspection mode) minted by the same rig, on JDK 17, 20 and 21
(`OperatorAuthenticatorRigTest`).

The authenticator does not cache answers: every request in introspection mode asks PingFederate, so a token revoked
there is refused from the next request on. (platform's `TokenIntrospector` can keep an active answer for at most 30
seconds, never past the token's `exp`, for a caller that turns its cache on; this one does not.) Every
introspection call is bounded: 1 second to connect, 2.5 seconds in all, 64 KiB.

## Replay and the limits across nodes

With Redis configured (`OIDF_REDIS_URL`), DPoP proofs are remembered under `oidf:admin:dpop:` and both limits are
counted under `oidf:admin:limit:auth:` and `oidf:admin:limit:mutation:`, shared by every node. Without Redis each
node keeps its own. For the limits that only makes each node's limit its own, so standalone deployments may run
without Redis. For replay it means a proof accepted by one node can be replayed to another within its lifetime,
so production allows it only with the accepted risk `in-memory-state` (`OIDF_ACCEPTED_RISKS`).

**Which address counts.** The failed-authentication limit counts the client address platform's trusted-proxy rule
gives (plan item H-ATT-3, `platform.net.TrustedProxies`, from 0.6.0): the address the servlet container reports
(`getRemoteAddr()`), or, when that is a proxy `OIDF_TRUSTED_PROXIES` lists, the right-most `X-Forwarded-For` (or
RFC 7239 `Forwarded`) hop it does not list. With the list unset no forwarding header is believed, and behind a load
balancer every caller shares the proxy's counter, so ten failures from anyone lock out everyone for the rest of the
minute ([F-0275](../findings/F-0275.yaml)): name your proxies in `OIDF_TRUSTED_PROXIES`
([trusted-proxies](../configuration/trusted-proxies.md)). The platform README's "net" section says how that sits
with PingFederate's own incoming proxy settings.

## Audit

Every request let through and every one refused emits an event from the `operator` catalogue
(`libs/platform-pf/src/main/resources/META-INF/oidf-events/operator.json`), which PingFederate's audit log records and
`oidf_events_total` counts:

- `admin.request.authorised`: `route`, `scope`, `actor`, `claimed_label`, `client_address`, `binding`.
- `admin.request.refused`: the same but `binding`, with `status`, and the reason (`invalid_token`,
  `insufficient_scope`, `too_many_failures`, ...) as the event's reason. `actor` is present only when the token was
  believed.

`claimed_label` is classed `DIRECT_ID`, because a caller can put a person's name in it; `client_address` is
`NETWORK`. PingFederate's audit log keeps the label as sent; server.log, usually shipped more widely, carries
`sha256:` and twelve hex digits of it instead (platform-pf's `PfAuditSink.PROCESS_POLICY`, finding
[F-0165](../findings/F-0165.yaml)), so two lines with the same label still match. The federation events' `actor` -
on Trust Mark grants, hosted-entity changes, key revocations and the policy decision point's enrolment questions - is
the token's subject, never the header.

## What it does not do yet

- **DPoP nonces.** RFC 9449 §8 lets a resource server require a server-provided nonce; this authenticator does not,
  so a proof is fresh by its `iat` (rs-validation's window: 300 s, with 60 s of skew) and its `jti`
  ([F-0276](../findings/F-0276.yaml)).
- **Subordinate, SSF and metrics administration.** Their scopes are defined; no route uses them yet
  ([the routes](#the-routes)).
