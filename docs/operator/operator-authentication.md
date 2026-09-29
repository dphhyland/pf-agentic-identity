# Operator authentication

How the operator APIs will decide who may use them: a PingFederate-issued OAuth access token, bound to the caller's
key (DPoP) or certificate in production, carrying the scope of the surface it is used on. The actor recorded for a
change is the token's subject. This is `OperatorAuthenticator` in libs/platform-pf (plan item S8a, 0.6.0).

**Nothing uses it yet.** In this release every operator surface - the federation administration API, the hosted
entities and registered clients APIs, the health detail and `/agentic-identity/info`, the SSF administration - still
takes the static bearer `OIDF_AUTHORITY_ADMIN_TOKEN` (finding [F-0008](../findings/F-0008.yaml)). Plan item S8b
(the next wave of Phase 3) moves each surface onto this authenticator with the scope below, after which the static
bearer is development-only. Setting the variables on this page now changes nothing; setting up PingFederate for them
now means S8b's upgrade is only a switch.

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

`OIDF_OPERATOR_BASE_URL` is configured rather than read from the request on purpose: the `Host` header is the
caller's to choose, so a proof checked against a URL built from it proves nothing about where the caller meant to
send it.

## What each request goes through

In this order; the first that fails decides the answer.

1. **The failed-authentication limit.** A client address that has failed authentication 10 times in the current
   minute is answered 429 with `Retry-After`, before its token is looked at. Every 400 and 401 below counts one.
2. **The token.** Exactly one `Authorization` header, scheme `DPoP` or `Bearer`, and no `access_token` in the query.
   In jwt mode the token is a JWS signed by a key in PingFederate's JWKS, with the configured `typ`; in introspection
   mode PingFederate says it is `active`. Either way `iss` is PingFederate's issuer (for this request's virtual host,
   through `PfInternals.issuer`), `aud` contains `OIDF_OPERATOR_AUDIENCE`, and `exp` and `nbf` hold.
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

An active answer is kept for at most 30 seconds and never past the token's `exp`; an inactive one is not kept. So a
token revoked in PingFederate keeps working on a node that has just asked about it for at most 30 seconds. Every
introspection call is bounded: 1 second to connect, 2.5 seconds in all, 64 KiB.

## Replay and the limits across nodes

With Redis configured (`OIDF_REDIS_URL`), DPoP proofs are remembered under `oidf:admin:dpop:` and both limits are
counted under `oidf:admin:limit:auth:` and `oidf:admin:limit:mutation:`, shared by every node. Without Redis each
node keeps its own. For the limits that only makes each node's limit its own, so standalone deployments may run
without Redis. For replay it means a proof accepted by one node can be replayed to another within its lifetime,
so production allows it only with the accepted risk `in-memory-state` (`OIDF_ACCEPTED_RISKS`).

**Which address counts.** The failed-authentication limit counts the address the servlet container reports
(`getRemoteAddr()`), never `X-Forwarded-For`. Behind a load balancer that does not preserve the client's address,
every caller shares one counter, and ten failures from anyone lock out everyone for the rest of the minute. A
trusted-proxy rule (plan item H-ATT-3) comes later; until then, configure PingFederate's own proxy settings so the
container reports the client's address, or raise `OIDF_OPERATOR_AUTH_FAILURES_PER_MINUTE`.

## Audit

Every request let through and every one refused emits an event from the `operator` catalogue
(`libs/platform-pf/src/main/resources/META-INF/oidf-events/operator.json`), which PingFederate's audit log records and
`oidf_events_total` counts:

- `admin.request.authorised`: `route`, `scope`, `actor`, `claimed_label`, `client_address`, `binding`.
- `admin.request.refused`: the same but `binding`, with `status`, and the reason (`invalid_token`,
  `insufficient_scope`, `too_many_failures`, ...) as the event's reason. `actor` is present only when the token was
  believed.

`claimed_label` is classed `DIRECT_ID`, because a caller can put a person's name in it; `client_address` is
`NETWORK`.

## What it does not do yet

- **DPoP nonces.** RFC 9449 §8 lets a resource server require a server-provided nonce; this authenticator does not,
  so a proof is fresh by its `iat` (rs-validation's window) and its `jti`.
- **Who a surface is for.** The route table (`OperatorRoutes`) and each route's scope arrive with S8b.
