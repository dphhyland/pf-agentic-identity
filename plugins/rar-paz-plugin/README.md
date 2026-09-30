# pf-rar-paz-plugin

> **Part of the [pf-agentic-identity](https://github.com/dphhyland/pf-agentic-identity) monorepo** — build from the repo root with `mvn package`. Formerly a standalone local repo, absorbed with history 2026-07-21; see [docs/PROVENANCE.md](../../docs/PROVENANCE.md).

A PingFederate **`AuthorizationDetailProcessor`** (RFC 9396 Rich Authorization Requests) that acts as a
Policy Enforcement Point at token issuance: it works out who the decision is about, holds each requested
`authorization_details` entry to the RAR containment model, refuses the types that need a person when there
is none, forwards the entry - together with the client attestation's vouched subject / entitlement / workload -
to a PDP decision, **denies unless the decision is PERMIT**, applies any returned statements (downscoping /
obligations), and refuses a result the model does not find within the request: **the PDP may narrow a
request, never widen it**. A refresh must stay within the grant by the same model. Two PDP dialects:
PingAuthorize's native governance engine, or an OpenID AuthZEN 1.0 PDP.

Modelled on Ping's reference `RARAuthDetailsProcessor` but closes its gaps: it honours the decision (the
reference read only `statements` and could never deny), maps a real principal rather than a hardcoded
`"joe"`, passes the attested entitlement so policy can enforce `requested ⊆ attested`, confines the
insecure-TLS switch to development deployments, and answers `isEqualOrSubset` for refresh-time narrowing with
the containment model's strict `contains`.

Status: unit-tested (the count is in the coverage dashboard a Build run publishes), and client credentials,
CIBA, refresh, token exchange and the code flow driven against it on the rig on 2026-09-27 (PingFederate
13.1.3.0, this jar at 0.4.0-SNAPSHOT) by
[`conformance/verify-rar-principal.sh`](../../conformance/verify-rar-principal.sh), with an upgrade from the
v0.3.0 jar rehearsed on the way - the evidence is under "Verified on the rig" below. The device flow and the
JWT-bearer grant were not driven (U-0066, U-0017). The containment model's narrowing, widening and refresh answers
were driven on the rig on 2026-09-27 as well ("Verified on the rig"). The earlier live verification against
PingAuthorize (2026-08-15, on the agentic demo's PingFederate 13.0.3) still describes the governance-engine dialect.

**PingFederate 13.1 only.** The plugin reads the request through
`AuthorizationDetailContext.getJakartaRequest()` and the user key through `getUserKey()`, which 13.0 does not
have, so it does not link there. The last build for 13.0.x is v0.1.5.

## Layout

| Path | What |
|---|---|
| [`src/`](src) · [`pom.xml`](pom.xml) | the plugin (`com.pingidentity.ps.oidf.rar`) + tests; `PF-INF` marker; shaded jackson and [`libs/rar-model`](../../libs/rar-model/README.md) |
| [`paz/`](paz) | reference PingAuthorize policies for the three built-in types (`paz/policies`), the script that authors them, their decision tests and a Policy Editor compose file; see its README |
| [`probe-decision.sh`](probe-decision.sh) | POSTs the plugin's exact governance-engine request shape to a PDP; the secret from `PAZ_PDP_SECRET` or `PAZ_PDP_SECRET_FILE`, no default; the PDP's certificate verified (its CA in `PAZ_CA_FILE`), unverified only on `localhost` |
| [`../../conformance/verify-rar-principal.sh`](../../conformance/verify-rar-principal.sh) | boots the rig with this jar and drives every flow at a stub PDP; the evidence below |
| [`.claude/skills/pf-rar-paz-plugin/`](.claude/skills/pf-rar-paz-plugin) | build/deploy/configure knowledge as a reusable skill |

## How it loads

A PF SDK plugin: `src/main/resources/PF-INF/authorization-detail-processors` names the class, the jar is
`pf.plugins.pf-rar-paz-plugin.jar` (PF only picks up `pf.plugins.*` in `server/default/deploy`), and PF
loads it on a per-plugin **isolated** classloader. That is why jackson is shaded and relocated into
`com.pingidentity.ps.oidf.rar.shaded.jackson` — a bare jackson jar beside the plugin would fail to link — and
why the containment model, `libs/rar-model`, is shaded and relocated into
`com.pingidentity.ps.oidf.rar.shaded.rarmodel`: the jar carries its own copy under its own package, never the
library's package, so it can never be the class another jar's code links to. `ShadedJarCheck` holds the built
jar to that after `package` (no entry and no class reference under `com/pingidentity/ps/oidf/rar/model/`, and
the relocated copy computes the library's fingerprint), and `tools/pf-linkcheck.py` against the 13.1.3 jars
finds nothing unresolved in it (1,141 own classes, 2026-09-27).
The PF SDK and servlet API are `provided`. HTTP is libs/platform's `OutboundHttp` (from 0.6.0; the JDK's
`java.net.http` before), shaded with platform under `com.pingidentity.ps.oidf.rar.shaded.platform`, and platform
carries its own relocated HttpCore, so the jar holds no `org/apache/hc/` class (`ShadedJarCheck`). The package
name is in the descriptor, so it was left alone by the split-package unwind that renamed the libraries.

**What the jar carries** (0.6.0, counted 2026-09-30): the plugin's own classes (50 under
`com.pingidentity.ps.oidf.rar`, and `au.idp.rar.FedRar`, the short plugin id), and three libraries, each relocated
under `com.pingidentity.ps.oidf.rar.shaded`: Jackson (`jackson-core`, `-databind`, `-annotations`; 1,100 classes, as
`.shaded.jackson`), `libs/rar-model` (15, `.shaded.rarmodel`) and `libs/platform` (190, `.shaded.platform`, with the
165 classes of the HttpCore it carries relocated inside it, `.shaded.platform.http.internal.hc5`). Resources: the
`PF-INF` marker, the catalogues of this plugin and of the bundled libraries (`META-INF/oidf-settings`,
`META-INF/oidf-events`, the two event indexes appended into one so the relocated platform reads both), Jackson's two
service files renamed and rewritten to the relocated classes, and the libraries' `LICENSE`, `NOTICE` (merged) and
third-party notices. Nothing else: no Maven descriptor of a bundled artefact, and none of Jackson's multi-release
classes (`META-INF/versions`), which sat under their unrelocated names in a jar whose manifest is not
`Multi-Release`, so no JVM loaded them. `ShadedJarCheck` holds the jar to exactly that - every class the plugin's or
under one of the three relocated packages, no class naming `com/fasterxml/` or another package of this repository,
each service file relocated, no resource twice - and `tools/pf-linkcheck.py` against PingFederate 13.1.3's jars
finds nothing unresolved in it (1,520 own classes, 2026-09-30).

## Architecture

```
authorization_details entry ─▶ AttestationAwareRarProcessor.enrich()
   ├─ AttestationSubject   ← request attribute com.pingidentity.ps.oidf.rar.attestation_context
   ├─ strip _principal_sub / _agent_id from the detail, after reading them
   ├─ PrincipalResolver    ← context.getUserKey() read per flow (grant_type, request path):
   │                          client credentials -> client · refresh -> authenticated · CIBA -> identity_hint
   │                          token exchange -> subject_token (a filter-verified attribute) else none
   │                          any other non-blank key -> authenticated · blank -> none
   │                          login_hint / _principal_sub -> client_asserted, in development only
   ├─ ModelGate: the context's rar_models_fingerprint must be this plugin's, when there is a context
   ├─ ModelGate: the detail must be one its type's RAR model reads    (refused before any PDP call)
   ├─ types requiring an authenticated principal: refused before any PDP call when none or client
   ├─ GovernanceEngineRequestBuilder | AuthZenRequestBuilder   (PDP Dialect field)
   ├─ PdpDecisions: the request's memo, the decision cache (types listed), else the AuthZEN batch or one call
   ├─ GovernanceEngineClient | AuthZenPdpClient  ─POST─▶ PDP    (PdpClient seam)
   │     CircuitBreaker.Guarded ▶ PdpTransport: platform OutboundHttp, 2.5 s total, 64 KiB, 32 at once
   ├─ deny unless decision.isPermit()   (fail-open only when the PDP is unreachable, and only if configured)
   ├─ StatementApplier: merge statements/obligations into a deep copy of the detail (dot-path)
   └─ ModelGate: the result must be within the request               (the PDP may narrow, never widen)

isEqualOrSubset(requested, granted) ─▶ ModelGate: contains(granted, requested), strict, markers stripped
```

Only `AttestationAwareRarProcessor` touches the SDK; the resolver, the builders, clients, `DecisionResponse`,
`StatementApplier` and `ModelGate` are plain code, tested without PF.

## The containment model

Every containment question the plugin asks goes to [`libs/rar-model`](../../libs/rar-model/README.md), shaded
into this jar (plan item S1c, which closes blocker B1 with S1b). `RarContainment`, which compared `type` and five
array fields and let every other value through, is gone with its contract test.

| When | What the plugin asks the model | A no, or a question the model cannot answer |
|---|---|---|
| `validate`, where the detail arrives | is the detail, markers stripped, one its type's model reads (`ModelGate.conformance`) | `invalid_authorization_details` at once, with the model's reason: at PAR, the authorization endpoint, CIBA's backchannel request, the device authorization endpoint, token exchange (except one that requests an ID-JAG, F-0325) and the token endpoint |
| `enrich`, before the PDP | is the requested detail, markers stripped, one its type's model reads | refused before any PDP call: an unmodelled type, an undeclared field, a value of the wrong shape (a flat `amount` without its `currency`, a negative limit, an empty array), a size limit |
| `enrich`, after a PERMIT | is the detail the PDP's statements produced within the request (the model's `contains`, the request as the ceiling) | refused: the PDP may narrow a request, never widen it |
| `isEqualOrSubset` | is the refresh's detail within the detail already granted (`contains`, the grant as the ceiling) | `false`, which PingFederate answers with `invalid_authorization_details` |

- **Narrowing.** A statement that lowers an amount, drops a region, or sets a limit the request left open is
  granted: RFC 9396 section 7.1 lets the token's details differ from the request's ("there are some use cases
  where the AS enriches the data in an authorization details object"), and the type's model says how. A
  statement that raises an amount, changes the currency, adds a region, changes the type or writes a field the
  type does not declare is refused. The refusal and its WARNING line name the type and, when the model refused,
  the field - never a value - and the principal hashed.
- **The grant is built on a deep copy of the request.** `StatementApplier` writes into nested maps in place, and
  with the shallow copy `enrich` used to take, a statement such as `instructedAmount.amount` rewrote the request
  it would then be compared with (`ModelContainmentTest.aNestedStatementCannotRewriteTheRequestItIsComparedWith`).
- **The markers.** `_principal_sub` and `_agent_id` are read - by the principal resolver, and for the PAR-carried
  agent - and then stripped before anything is asked; the model declares both forbidden, so a detail that reached
  it with either would be malformed.
- **Failing open** grants only a detail the model has checked, since the check comes before the PDP call.
- **At `validate`, where the detail arrives.** PingFederate 13.1.3 calls the processor's `validate` at PAR and the
  authorization endpoint (`AuthorizationRequestSupport.checkAuthorizationDetails`), at CIBA's backchannel request,
  the device authorization endpoint, token exchange and the token endpoint, and on the JWT-bearer grant
  (`javap`, 13.1.3.0), each time with a copy of the detail and an empty parameter map, and answers an invalid result
  with `invalid_authorization_details` and its reason. The exception is a token exchange whose
  `requested_token_type` is `urn:ietf:params:oauth:token-type:id-jag`: there PingFederate 13.1.3 calls neither
  `validate` nor `enrich` and copies the request's `authorization_details` into the ID-JAG it signs (F-0325, read with
  `javap`, not yet driven on the rig: U-0335). This plugin cannot refuse them there; until F-0325 is fixed, do not
  enable ID-JAG on an SP connection's token exchange settings while a client that may send these types can use token
  exchange. From 0.6.0 `validate` strips the two markers and asks the
  model, so a detail that does not conform is refused there - a PAR with an undeclared field fails at PAR, not at
  the token endpoint after the user has logged in. RFC 9396 section 5 (RFC 9396, May 2023): "The AS MUST refuse to
  process any unknown authorization details type or authorization details not conforming to the respective type
  definition." `validate` is a shape check and nothing more: no PDP call, no principal, no attestation-context
  fingerprint - `enrich` does those where PingFederate calls it. In order it refuses a detail with no `type`, a
  detail bound to an instance whose `configure` threw, every detail when the models document did not load (the
  client is told only that the model did not load; the reason is in the SEVERE line), a type the JWT-bearer grant
  may not carry (below), and a detail the model refuses: an unmodelled type (in development the common-fields model
  stands in, as it does for `enrich`), an undeclared field, a value of the wrong JSON type, a size limit. The reason
  names the type and the field, never a value, and each refusal is logged at INFO as
  `RAR validate: refusing type=<type> flow=<grant or endpoint> path=<path>: <reason>`.
- **The JWT-bearer grant** (RFC 7523 section 2.1, `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer`).
  PingFederate calls `validate` on it and never `enrich`, so the PDP is never asked there (U-0017, driven on the
  rig below). A detail of a type this processor holds is refused by `validate` with "authorization_details of this
  type are not accepted on the JWT-bearer grant" unless "Types allowed on the JWT-bearer grant" lists the type
  (default: none; F-0108). A listed type passes `validate`'s model check and is issued without a PDP decision.
  The field refuses, on save and at configure, a type "Types requiring an authenticated principal" lists: no
  principal can be established on that grant from inside the processor. What PingFederate 13.1.3 does on the grant,
  read with `javap` and driven on the rig on 2026-09-30: on the plain RFC 7523 profile the token endpoint calls
  `validate` on the request's `authorization_details` parameter before it looks at the assertion (a forged
  assertion still reached `validate`), and the token it issues carries none of them (`"authorization_details": []`);
  on the ID-JAG profile (an assertion whose `typ` is `oauth-id-jag+jwt`) the token endpoint skips the parameter,
  `JwtGrantProcessor` verifies the assertion's signature and then calls `validate` on the assertion's own
  `authorization_details` claim (a forged one never reached it), and the token carries those details as they are.
  So the ID-JAG profile of the JWT-bearer grant, where this server receives an ID-JAG, is where a listed type is
  issued, as the assertion's issuer wrote it. The other direction, this server issuing an ID-JAG by token exchange,
  is F-0325 above: nothing in this plugin runs there.
- **Types.** `OIDF_RAR_EXTRA_TYPES` still decides which types PingFederate may bind to the processor. A type
  named there without a model is refused in production (`UNMODELLED_TYPE`); with
  `OIDF_DEPLOYMENT_PROFILE=development` the library's common-fields model stands in. A type a models document
  declares must also be named there before PingFederate will bind it.

### The model set and its fingerprint

The model set is read once per classloader from `OIDF_RAR_MODELS_FILE` or `OIDF_RAR_MODELS` - the settings the
attestation filter reads, so one document serves the whole PingFederate process - and logged when PingFederate
first instantiates the processor:
`RAR models loaded: fingerprint=<64 hex> types=[...] commonFieldsFallback=false source=built-in`. Each instance's
configure line repeats it as `rarModels=`. A document the library refuses leaves the plugin with no model: a
SEVERE line says why, and every request is refused (`enrich` throws, `isEqualOrSubset` answers `false`) until the
document is fixed and PingFederate restarted. Refusing only the owning component, with a 503 and health DOWN,
is plan item S-9 (Phase 3).

The attestation filter publishes its own model set's fingerprint in the attestation context as
`rar_models_fingerprint` (plan item S1b). When a request carries that context, the plugin compares it with its
own before it asks the model anything:

- the same fingerprint: decided as above;
- another fingerprint, or a context without the member (a filter from before 0.4.0), or a context that is not a
  map: refused before any PDP call, and `isEqualOrSubset` answers `false`;
- no context at all - a client the filter did not verify, the authorization endpoint's resume and CIBA's
  backchannel request, which the filter never sees, and PingFederate's consent and grant-reuse checks, which pass
  no request: nothing to compare, and the plugin decides as 0.4.0's principal work (PR #29) left it - the PDP is
  asked about the request alone, with no attested ceiling - with the model's checks above.

The filter runs over the token endpoint and PAR. At PAR PingFederate calls only `validate`, which holds the
detail to the model and compares no fingerprint; at the token endpoint it asks this processor to decide for client credentials and token exchange
(`enrich`) and for a refresh that restates `authorization_details` (`enrich`, then `isEqualOrSubset`). So this
plugin beside an attestation filter from before 0.4.0 refuses those requests from every attested client, before
the PDP is asked, with `invalid_authorization_details`: deploy the two from one release.

### What PingFederate 13.1.3 asks on a refresh

Read with `javap -c` from `pf-protocolengine` and `pingfederate-sdk` 13.1.3.0 on 2026-09-27
(`RefreshTokenGrantProcessor.processGrant`, `AuthorizationDetailsServiceImpl.isEqualOrSubset`,
`AuthorizationDetailsUtil.isEqualOrSubset`):

- Only a refresh that carries `authorization_details` is compared. PingFederate parses it
  (`new AuthorizationDetails(String)`, its own Jackson: a fraction becomes a `double`, a large integer a
  `BigInteger`, and an entry that is not an object, or whose `type` is not a string, fails the parse), enriches
  it with the grant's user key and the mapped attributes, then requires every requested detail to be within
  some stored detail of the same type. It compares the types itself and asks the processor about each same-type
  pair - copies of both details, a context with the request, the client id and the scope and no user key, and an
  empty parameter map - taking the first yes. A `false` or an `AuthorizationDetailProcessingException` makes it
  answer `invalid_authorization_details`; on success the token carries the requested (enriched) details.
- A refresh without `authorization_details` reissues the stored details, and the PDP is not asked (F-0105). No
  processor is called either, unless approved consent is reused: with "bypass authorization for approved
  consents" on and a client that does not bypass the approval page, PingFederate asks `isEqualOrSubset`, through
  `OAuthConsentManagerDefaultImpl.isGranted`, whether the stored details are within the user's approved consent,
  and on a no revokes the grant and answers `invalid_scope` ("revoked, or expired consent").
- An empty requested list (`[]`) asks no processor either, and issues no details.

PingFederate also asks `isEqualOrSubset` outside refresh, and the strict answer applies there too: whether
approved consent covers a request (`OAuthConsentManagerDefaultImpl.isGranted`, also asked on a refresh as above),
which consent records an updated consent covers and which it revokes (`createOrUpdate`), which requested details
are already approved at the authorization endpoint
(`PingFederateAuthorizationProcessor.getApprovedAuthorizationDetails`), and which stored grant a request can
reuse (`getByAccessGrantCriteria`: the SDK's default method on `AccessGrantManager`, which
`AccessGrantManagerMapImpl` inherits, and the overrides in `AccessGrantManagerJdbcImpl`,
`AccessGrantManagerLDAPADImpl` - and so `AccessGrantManagerLDAPOracleImpl`, which extends it - and
`pf-dynamodb-integrations`' `AccessGrantManagerDynamoDBImpl`). The consent and grant-reuse callers pass a
context with no request, so the plugin sees no attestation context there and compares no fingerprint. Read from
the bytecode of `pf-protocolengine`, `pingfederate-sdk` and `pf-dynamodb-integrations` 13.1.3.0 only; none of
these was driven (U-0115).

### The vectors on the refresh path

`RefreshVectorsTest` is the fourth of the plan's four runners over `libs/rar-model`'s vector file: each of its
148 `contains` cases is sent through PingFederate's parse and the refresh loop above, to this plugin's
`isEqualOrSubset`, and must answer as the library does - with the library's refusal reason wherever the plugin
was the one asked. Six cases answer differently, each listed in the test with its reason, and the test fails if
one of them stops differing: the three bookkeeping-marker cases (the plugin strips the markers by design), the
empty-request case (PingFederate asks no processor), and two number cases that PingFederate's parse changes
before the plugin is asked (`100e2147483647` becomes an infinite double, which PingFederate's own copy of the
detail writes back as the string `"Infinity"`; `1e-999999999` becomes `0.0`). In none of them does PingFederate
issue more than the grant: what the plugin compares is what PingFederate then issues.

## Who the decision is about

`AuthorizationDetailContext.getUserKey()` is a different thing in each flow, so the plugin labels it. What
PingFederate 13.1.3 passes, read with `javap` from `pf-protocolengine` (the callers of
`AuthorizationDetailsUtil.enrich`, 2026-09-27) and then driven on the rig the same day:

| Flow | PingFederate passes as the user key | `principal_source` | Rig, 2026-09-27 |
|---|---|---|---|
| client credentials | the client id (`ClientCredentialsGrantProcessor`) | `client` | user key = the client id; `sales_agent` reaches the PDP as `subject {type: client}`; `payment_initiation` refused before the PDP, 400 `invalid_authorization_details` |
| refresh, with `authorization_details` in the request | the grant's unique user identifier (`RefreshTokenGrantProcessor`) | `authenticated` | user key = `suite-user`; the grant's attributes arrive under the SDK's `IN_PARAMETER_AUTH_DETAILS_USER_INFO` parameter |
| refresh, without | - (the stored details are reissued; plan "Found" item 2) | - | the plugin is not called |
| CIBA, at `/as/bc-auth.ciba` (the request URI read as the container maps it: path parameters, escapes and dot segments resolved; U-0094) | the request policy's `IDENTITY_HINT_SUBJECT` (`CibaAuthenticationRequestHandler`) | `identity_hint` | user key = `suite-user` from `login_hint`; then the ciba-sim approves, the poll issues a token and a refresh token |
| token exchange | `null` (`TokenExchangeRequest`; and enrich is skipped when the requested token type is `id-jag`) | `subject_token` only when the token-endpoint filter published `verified_subject_token_sub` in the attestation context, else `none` | user key none. From 0.6.0 the filter and the criterion publish `verified_subject_token_sub` when the subject token verifies as one PingFederate signed (its signing keys, its issuer, an `exp` not passed; F-0074), and the principal is that `sub`; any other subject token, or none, is `principal_source: none` and `payment_initiation` refused before the PDP. Not yet driven on the rig |
| authorization code | the authentication result's `subject` attribute, once, at the resume after login (`OAuthResumableRequestHandlerBase`, path `/as/<id>/resume/as/authorization.ping`); PAR does not enrich, and there is no second pass at consent | `authenticated`, or `none` when the contract has no `subject` | as the rig ships (an HTML-form adapter with `username` and no `subject`): user key none, the payment refused after the user signed in; with `subject` mapped on the adapter by expression from `username`: user key = `suite-user`, decided about `suite-user`, token issued for `suite-user` |
| device flow | the approving user, as far as `javap` shows: `UserAuthorizationRequestHandler` enriches at the user's approval with the mapped attributes | `authenticated` (assumed; U-0066) | not driven |
| JWT bearer | `JwtGrantProcessor` has no call to enrich (`javap`) | - | not driven (U-0017) |

Two names are the caller's own: the `login_hint` request parameter and the `_principal_sub` marker a
front-end folds into `authorization_details`. They are used only when the resolution above found nobody,
"Trust a client-asserted principal" is on, AND `OIDF_DEPLOYMENT_PROFILE=development` - labelled
`client_asserted`, and gone at 1.0 (plan decision 9). In production the switch is refused, on save and at configure
(below).
`_principal_sub` is stripped from the detail on every path. The request attribute
`com.pingidentity.ps.oidf.rar.resource_owner_sub` is no longer read.

**Give the authentication contract a `subject`.** The one thing a deployment does to give the plugin a
principal in the browser flow: the user key at resume is the `subject` attribute of the authentication result,
so an adapter or policy contract without one leaves the plugin knowing nobody after the user has signed in,
and the payment and account types are refused. The mapped attributes also reach `enrich` under
`AuthorizationDetailProcessor.IN_PARAMETER_AUTH_DETAILS_USER_INFO`; the plugin does not read them, because
which of a deployment's attributes names the person is the deployment's decision, said by mapping `subject`.

**Types requiring an authenticated principal** (default `payment_initiation,account_information`) are refused
before any PDP call when the principal is `none` or `client`. `identity_hint`, `subject_token` and (in
development) `client_asserted` pass, labelled, so policy can be stricter. A single `-` empties the list.

The principal is logged hashed: `principal=sha256:<first 16 hex>` and `userKey=` likewise, so a server log
never carries a user key, and the same person still matches across lines. The same goes for a refusal's text:
PingFederate 13.1.3 logs a processor's exception with every cause at ERROR (seen on the rig, 2026-09-27), and a
PDP's error body can name whom it was asked about, so the plugin carries a failure as text with the principal
and the user key replaced by their hashes, and chains no PDP exception. The plugin logs through
`java.util.logging`, which PingFederate writes to `server.log` as `ERROR [SystemErr]` whatever the level
(F-0075).

## What fails open, and what does not

"Fail open on engine error" grants the cleaned detail through exactly one failure class, the PDP being
unreachable (`PdpUnavailableException`): a connection refused or reset, an unresolved name, the connect or
total deadline, all 32 call places taken until the deadline, the circuit breaker open, or HTTP 429, 502, 503
or 504. Everything else refuses whatever the switch says:

| Answer | Result |
|---|---|
| 2xx, `application/json` (or `+json`), a decision | the decision - PERMIT or not |
| 429, 502, 503, 504 | unavailable: fails open when configured, else denied |
| any other status - 401/403 from a wrong secret, 400, 404, 500, a redirect | denied |
| 2xx with another content type, an empty or malformed body, no boolean `decision` (AuthZEN), a `decision` that is not a string or an `authorised` that is not a boolean (governance engine) | denied |
| a body with content after the JSON object, or a member named twice | denied |
| a status line or header platform's client cannot parse (`MALFORMED_RESPONSE`), whatever text it carries | denied |
| a body over 64 KiB (`BODY_TOO_LARGE`) | denied |
| TLS failure (`TLS`), a certificate that does not name the PDP URL's host included, even before a byte is sent | denied |

`PdpTransport.classify` sorts platform's `OutboundHttpException` by its reason: `UNRESOLVED`, `BULKHEAD_FULL`,
`CONNECT_FAILED`, `CONNECT_TIMEOUT`, `HEADER_TIMEOUT`, `DEADLINE` and `BUDGET_EXHAUSTED` are unreachable, and
an `IO` or `MALFORMED_RESPONSE` failure is unreachable only when its cause chain says the peer reset or closed
the connection - a `SocketException`, `EOFException` or `ClosedChannelException`, HttpCore's
`NoHttpResponseException` or `ConnectionClosedException` by simple name, or a message that starts with the
JDK's own "Connection reset". It never searches a message for wire text: before 0.4.0 a DENY carrying a header
named `connection reset` was granted with fail-open on (F-0093, found in review on 2026-09-27 and closed in the
same change).

## The PDP call

From 0.6.0 (plan item S2c, and S5d's call site in this plugin) each processor instance calls its PDP through
platform's `OutboundHttp` ([libs/platform#http](../../libs/platform/README.md#http)), in these layers:

- **Deadlines and a cap.** "Request timeout (ms)" is the call's total deadline, from connecting to the last
  byte of the answer: 2500 by default, held to 1000-10000. Connecting, TLS included, gets at most 1 s of it.
  The JDK client this replaced stopped timing when the headers arrived, so a PDP that sent its headers and then
  dribbled the body held the token request as long as it liked (F-0010). An answer over 64 KiB is refused.
  HTTP/1.1, one request per connection, no redirects.
- **Host names, always.** Platform's transport sets HTTPS endpoint identification on every connection and has
  no switch to turn it off: the PDP's certificate must name the host in the PDP URL in every trust mode (below).
- **A bulkhead of 32.** At most 32 PDP calls at once per instance, the batch URL's included. A call that finds
  every place taken waits for one until its own deadline and is then unreachable, so a PDP that stops answering
  holds at most 32 of PingFederate's request threads for longer than a moment.
- **A circuit breaker.** After "Circuit breaker failures" (5) unreachable calls in a row it opens for "Circuit
  breaker open (s)" (30): the PDP is not called and every decision is unreachable at once. Then one trial call
  goes through; its success closes the breaker and its failure opens it again. Only a transport failure counts,
  the set `classify` reads as unreachable (above). Any HTTP answer - 429 and 502-504 included, which still read as
  unreachable for fail-open - a malformed or oversized answer and a TLS failure fail as before, never trip the
  breaker, and end the run of failures (plan item S2a's rule).
- **One decision per question per request.** PingFederate calls `enrich` once per detail, in order, on the
  request's thread (`AuthorizationDetailsUtil.enrich` runs a `List.forEach` over the details; javap of
  pf-protocolengine 13.1.3.0, 2026-09-29). A memo kept as a request attribute, one per instance, answers any
  repeat of the same question - the type, the detail with its keys sorted, the principal and how it was
  established, the client and the whole attestation context - from the first answer, a failure included, so
  PingFederate asking twice never makes two calls.
- **The AuthZEN batch.** With "AuthZEN batch URL" set (the `authzen` dialect only; the PDP's
  `/access/v1/evaluations`), the first `enrich` of a request whose `authorization_details` parameter carries
  two or more details this processor would ask about sends them all in one Access Evaluations call, and the
  memo answers the rest. The request is `{"evaluations": [...]}`, each element the evaluation a single call
  would send. OpenID AuthZEN Authorization API 1.0 (Final, 11 January 2026), section 7.2: the response "adds an
  evaluations array that lists the decisions in the same order they were provided in the evaluations array in
  the request". So an answer with no `evaluations` array, with more or fewer decisions than were asked, or with
  one that is not an object holding a boolean `decision`, is malformed: every detail of that request is denied,
  and the breaker is not touched. Position is the only correlation AuthZEN 1.0 gives, so a PDP that answered the
  right number in another order cannot be told apart ([F-0290](../../docs/findings/F-0290.yaml)). At the
  authorization endpoint PingFederate reads the details from the pushed request, not a parameter, so there each
  detail is asked on its own. The governance-engine dialect is unchanged: one call per detail.
- **An optional decision cache.** "Decision cache types" lists the types whose decisions may be reused, for
  "Decision cache TTL (s)" (30, at most 60), across requests; blank, the default, caches nothing. The key is the
  memo's question with the PDP URL and the RAR models fingerprint, so an attester, a principal, a client or a
  model set that differs is a different entry; at most 1024 entries. `payment_initiation` and every type in
  "Types requiring an authenticated principal" are refused, on save and again at configure: those are decided on
  every request.

**Metrics.** `oidf_rar_pdp_calls_total{mode, outcome}` (mode `evaluation` or `evaluations`; outcome
`answered`, `unreachable`, `failed` or `breaker_open`), `oidf_rar_pdp_answers_total{source}` (`pdp`, `memo` or
`cache`) and the gauge `oidf_rar_pdp_breakers{state}` (instances whose breaker is `closed`, `open` or
`half_open`). No label carries a principal, a client or a detail value. The plugin shades platform, so they are in
the plugin's own registry, not the webapp's: in a JMX console, the MBean
`com.pingidentity.ps.oidf:type=Metrics,copy="com.pingidentity.ps.oidf.rar.shaded.platform.metrics from <the jar's
location>"`, attribute `Samples`. `oidf_rar_context_dropped_total{form}` counts the AuthZEN context members dropped
because the allow-list does not name them (below), `form` `member` or `statement`.

**Events.** From 0.6.0 `enrich`'s decision step emits one event per detail it decides, catalogued in
[`META-INF/oidf-events/rar.json`](src/main/resources/META-INF/oidf-events/rar.json): `rar.decision.permitted`,
`rar.decision.denied` (the reason is the class: `pdp_deny`, `pdp_widened`, `pdp_unreachable` or `pdp_failed`) and
`rar.decision.failopen`, each with the `type`, the `principal_source`, the `principal` hashed as the log lines hash it
(`sha256:` and sixteen hex characters) and the `client_id`; never a detail value, a PDP message or a secret. A refusal
before any PDP call (the model's, a missing principal) is not a decision and emits none. They go through the plugin's
own relocated copy of `platform.events`, which has no audit sink (platform-pf is not in the jar), so they reach
`server.log` under the logger `com.pingidentity.ps.oidf.rar.event` and are not audit events; each is counted in the
same relocated registry as the metrics above, `oidf_events_total{code, outcome}` in the plugin's own MBean.

The switch that turned deny-unless-PERMIT off ("Deny unless PERMIT") is gone; the decision is always
deny-unless-PERMIT. A value stored under the old name is carried by PingFederate and never read: 13.1.3
hands an instance with no parent its stored configuration as it is (`ConfigurationUtil.createCompositeConfiguration`)
and the admin API's `PluginConfigTranslator` raises no error for an undeclared field - both read with `javap`,
2026-09-27. On the rig the same day, an archive exported under 0.3.0 (the instance held the field, `true`)
imported under this jar, the instance on disk still held it beside the declared fields, the plugin configured
and decided, and saving the instance again dropped it. From 0.6.0 the settings catalogue lists it as a removed plugin
field (release 0.4.0, nothing replaces it), so the settings scan and the generated
[configuration page](../../docs/configuration/rar-pdp-processor.md) show it; the plugin still ignores a stored value
rather than refusing it, so a 0.3.0 archive still imports and decides. The generated page's sentence that a removed
name is refused is the generator's for every catalogue and is wrong for this one field
([F-0375](../../docs/findings/F-0375.yaml)).

## Reserved attribute names (governance-engine dialect)

The requested fields are written first and the server's attributes last, so nothing requested can overwrite
them; and a requested field whose attribute name is one the server writes is refused outright, which turns
into a denial. Reserved: `UserID`, `principal_source`, `actor`, `actor_iss`, `client_id`,
`attestation.entitlement`, `attestation.workload`, `attestation.cnf_thumbprint`, `attestation.iss`, and the
`req_<field>` and `att_<field>` mirror of every set-valued field (`actions`, `locations`, `datatypes`,
`privileges`, `sales_regions`) - in every request, whether or not it writes that mirror, because an
`att_actions` the builder leaves unwritten (the attestation constrains no actions) would otherwise reach the
PDP as the caller's own ceiling (F-0073). With the default attribute prefix (`idp`, prefixed with the type) a
requested field never lands on those names; with an empty prefix and the type prefix off it could, and
`"UserID": "alice"` inside a detail would otherwise have named the principal. The AuthZEN dialect keeps the
requested fields under `resource.properties` and has nothing to reserve.

## Attestation-context bridge

`servlets/pf-integration`'s `ClientAttestationUtils` publishes the verified attestation as a request
attribute after `attest_jwt_client_auth` succeeds; this plugin reads it via
`AuthorizationDetailContext.getJakartaRequest()`. A string-keyed plain `Map`, so neither module depends on
the other across classloaders:

- **key:** `com.pingidentity.ps.oidf.rar.attestation_context` (`AttestationSubject.REQUEST_ATTRIBUTE`)
- **value:** `sub` and `client_id` (both the registered client / agent *type*), `agent_id` (the
  attester-minted instance identifier, when one was minted), `iss` (the attester that minted it - an
  `agent_id` is unique only within its issuing authority), `entitlement` (the attested
  `authorization_details` ceiling), `workload` (SPIFFE id / attestor / selectors, plus flat `spiffe_id`
  and `attested_by`), `cnf_thumbprint`, `rar_models_fingerprint` (the filter's `RarModels.fingerprint()`,
  lower-case hex, published from S1b on and compared with the plugin's own: "The model set and its fingerprint"
  above); and, for a token exchange whose subject token verifies as one PingFederate signed (from 0.6.0),
  `verified_subject_token_sub` (`AttestationSubject.VERIFIED_SUBJECT_TOKEN_KEY`), the only thing the `subject_token`
  principal source reads.

Absent context (a non-attestation client) falls back to `context.getClientId()` and sends no
entitlement — policy decides on the request alone, and the model's checks still apply.

## PDP dialects

Selected by the **PDP Dialect** field (`governance-engine`, default, or `authzen`). Enforcement,
fail-open, timeout and the shared-secret header are dialect-independent.

| | `governance-engine` | `authzen` |
|---|---|---|
| Wire | `{domain: <prefix>.<type>, service, action, attributes}` — values JSON-stringified for the Trust Framework, plus flat `req_<field>` / `att_<field>` mirrors (attribute names cannot contain `.`) | AuthZEN 1.0 `{subject, action, resource, context}`; point **PDP URL** at `/access/v1/evaluation` |
| Principal / agent | `UserID` = the resolved principal, else client id; `principal_source`; `actor` = `agent_id` when minted and distinct, with `actor_iss` | `subject = {type: user\|client, id}` (`client` when the principal source is `client`, or the client was the fallback); `context.principal_source`; `context.actor = {type: agent, id: agent_id, iss}` (RFC 8693 delegation) |
| Attested ceiling | `attestation.entitlement / workload / cnf_thumbprint / iss` | `context.attestation.{entitlement, workload, cnf_thumbprint, iss}` |
| Decision | `decision: PERMIT\|DENY\|…` (a string) + `authorised` (a boolean, which wins when present) | boolean `decision`, required |
| Obligations | `statements: [{name, payload}]` | response `context` mapped into the same statement pipeline: `context.statements` and every other member one statement each, held to "AuthZEN context members merged into details" for the detail's type (below); `id` / `reason_*` never merged |

## Configuration (PF admin fields — same names the config-as-code sets)

| Field | Default | When it is wrong |
|---|---|---|
| PDP Dialect | `governance-engine` | `authzen` for an AuthZEN PDP; anything else is the governance engine |
| PDP URL | required, `https://` (a placeholder the validator refuses) | must be `https`; `http` only with `OIDF_DEPLOYMENT_PROFILE=development` (unset is production). The admin console and API refuse the field. An archive import runs no validator, so there `configure` throws, and the plugin refuses every request that reaches the instance with `invalid_authorization_details`; what PingFederate itself does with such an instance is U-0068 |
| PDP Domain Prefix / PDP Service / PDP Action | `idpartners.authorization_details` / `Authorization` / `authorize` | governance-engine dialect only |
| Attribute Prefix / Prefix Attributes with Type | `idp` / on | an empty prefix with the type prefix off lets a requested field reach a reserved name, which is then refused |
| Shared Secret Header / Shared Secret | `CLIENT-TOKEN` / required, **stored encrypted** | the same field name as before; a value stored in the clear by an older jar still works (below) but re-save it |
| Types requiring an authenticated principal | `payment_initiation,account_information` | refused before any PDP call with `principal_source` `none` or `client`; comma- or space-separated; a single `-` means none |
| Fail open on engine error | off | grants through an unreachable PDP only (above); never a wrong secret, a bad answer or a TLS failure. In production it needs `pdp-fail-open` in `OIDF_ACCEPTED_RISKS`: refused on save and at configure without it |
| Trust a client-asserted principal | off | `login_hint` / `_principal_sub` as the subject when nobody else is known - development only: refused on save and at configure in production; gone at 1.0 |
| Trust the PAR-carried agent marker | off | where the attestation is not in the request (the authorization endpoint), take the agent instance from the `_agent_id` the attestation filter put in each entry at PAR; only for clients that must use PAR |
| Skip TLS verification (dev only) | off | trusts any PDP certificate, development only: refused on save and at configure in production. The host name is checked either way (below) |
| Request timeout (ms) | 2500 | the call's total deadline, connect to last byte, held to 1000-10000; past it the PDP is unreachable. Was 10000 per call, not counting the body, before 0.6.0 |
| PDP TLS trust | `jvm-default` | `jvm-default`, `pingfederate-trusted-cas` or `pinned-ca` (below); anything else is refused on save and at configure |
| PDP CA certificates (PEM) | blank | the CAs `pinned-ca` trusts; blank or not a certificate with `pinned-ca` is refused |
| AuthZEN batch URL | blank | `authzen` only; https unless development; refused with the governance-engine dialect |
| Decision cache types / Decision cache TTL (s) | blank / 30 | never `payment_initiation` or a type requiring an authenticated principal; TTL 1-60 |
| Circuit breaker failures / Circuit breaker open (s) | 5 / 30 | 1-1000 / 1-3600 |
| AuthZEN context members merged into details | `sales_agent: @model; account_information: @model` | `authzen` only: per type, the members of a decision's `context` that may reach the detail (below); refused on save and at configure when it cannot be read |
| Types allowed on the JWT-bearer grant | blank (none) | the types a JWT-bearer token request may carry; any other of this processor's types is refused by `validate` there. A listed type passes `validate`'s model check and is issued without a PDP decision. Never a type requiring an authenticated principal: refused on save and at configure |

A switch missing from a stored configuration - an instance saved before the field existed (a 0.3.0 instance
has no "Types requiring an authenticated principal"), or an archive written by hand that leaves it out -
reads as the default above, which is the secure value for every switch. The admin API fills a missing field
with the descriptor's default when it creates an instance: the rig's probe instance, posted with five fields,
was stored with all fifteen (2026-09-27). The version PingFederate shows for the plugin is the jar's
`Implementation-Version`, the project version it was built as.

One setting is not a field: `OIDF_RAR_EXTRA_TYPES` (the system property `oidf.rar.extra.types` first), the
types PingFederate may bind to the processor beyond the three built in, whitespace- or comma-separated. PingFederate
reads the supported types from the descriptor before any instance is configured, so it cannot be an instance
field. The fields, their defaults, profile classes and what a wrong value does are in the
[rar-pdp-processor](src/main/resources/META-INF/oidf-settings/rar-pdp-processor.json) settings catalogue, with the
removed "Deny unless PERMIT" under `removed` ([F-0231](../../docs/findings/F-0231.yaml), closed in 0.6.0).

**The production profile's refusals** (plan item PR-3; 0.6.0). Under the production profile (an unset
`OIDF_DEPLOYMENT_PROFILE` is production) the processor refuses a configuration with "Skip TLS verification (dev
only)" or "Trust a client-asserted principal" on, and one with "Fail open on engine error" on unless `pdp-fail-open`
is in `OIDF_ACCEPTED_RISKS` - the catalogue's classes for those fields (`forbidden-in-production`,
`accepted-risk:pdp-fail-open`), applied by platform's read-time rule (`ProfileRules`, through `Settings.parse`), so
the message names the field, the value, the fix and the development escape. A plaintext PDP URL or AuthZEN batch URL
(classed `forbidden-in-production` for `http`) keeps its own rule, `PdpUrlPolicy`, and a decision cache type that is
`payment_initiation` or needs an authenticated principal is refused in either profile. Each is checked twice: the
descriptor's validators run when the admin console or the admin API saves the instance (a 422 with the message), and
`configure` runs the same rules on a stored configuration, which is all an imported archive gets - a refusal there
leaves the instance unconfigured, and it refuses every request that reaches it. In development the switches save and
take effect as before. What PingFederate 13.1.3 does with an instance whose `configure` throws, seen on the rig on
2026-09-30 (U-0068): the import succeeds (HTTP 200 from `/configArchive/import`, and a drop-in archive deploys at
start), the admin API reads the instance back with its fields and no sign of the failure, PingFederate configures it
lazily at its first use and logs `Unexpected exception thrown attempting to configure plugin` at ERROR with the
plugin's message, and does so again after the next import, not per request; a token request carrying one of its types
is answered `400 invalid_authorization_details` ("the processor bound to it is not configured"), while client
credentials without details, discovery and PingFederate's other flows keep serving.

**The AuthZEN context allow-list** (plan item H-RAR-1, [F-0065](../../docs/findings/F-0065.yaml); 0.6.0). Until 0.6.0
every member of an AuthZEN decision's `context` but `id`, `reason_admin` and `reason_user` became a statement merged
into the detail. Now "AuthZEN context members merged into details" names, per type, the members that may be: `type:
member, member` entries separated by `;` or new lines, `@model` for every member the type's model declares (the two
markers left out), `-` for none. An entry splits at its last colon, so a URI type is named as it is (`urn:example:transfer:
amount`). A type it does not name merges nothing. The default, `sales_agent: @model;
account_information: @model`, merges nothing into a `payment_initiation` detail. A member it does not name is dropped,
counted in `oidf_rar_context_dropped_total` and logged once by name (a name that is not a plain member name is logged
as a placeholder), and never merged; the symmetric form, `context.statements: [{name, payload}]`, is held to the same
list by the first dot-separated part of each name. A member it names that would widen the detail is still refused by
the model's `within`, as before. Dropping is not refusing: a PDP that permits on condition of a narrowing it writes
through a member the field does not name gets the detail granted without that narrowing, so list every member such a
policy narrows through. The field does not touch the governance-engine dialect's `statements`, which a
PingAuthorize policy author writes. A field that cannot be read - an entry without `:`, a type named twice, a member
with a dot, or `type`, `_principal_sub` or `_agent_id` listed - is refused on save and at configure.

`OIDF_DEPLOYMENT_PROFILE` is read through libs/platform's `DeploymentProfile` (plan item PR-1), shaded into
the jar under `com.pingidentity.ps.oidf.rar.shaded.platform`; `development` (trimmed, any case) is development,
anything else including unset is production.
The RAR model set reads the same variable through the library, which takes exactly `development` (whitespace
trimmed) for its common-fields fallback, so `Development` relaxes the plugin's own switches and not the model.

The model set's own settings are process environment, not instance fields, and the same for every component
that loads the model: `OIDF_RAR_MODELS_FILE` (a models document, read once, UTF-8) or `OIDF_RAR_MODELS` (the
document inline; not both). Unset, the model is the three built-in types. What a document may say is the
library's README, "A models document".

Supported RAR types are declared in code (`sales_agent`, `payment_initiation`, `account_information`),
plus any the deployment names in `OIDF_RAR_EXTRA_TYPES` or the `oidf.rar.extra.types` system property
(comma- or space-separated; the property wins). PingFederate 13.1 binds a type to a processor instance
under OAuth Server → Authorization Detail Types (`/oauth/authorizationDetailTypes`, field
`authorizationDetailProcessorRef`) and a client lists the types it may use (`authorizationDetailTypes`,
the type names); the rig script does both through the admin API.

**Choosing the encrypted field.** The secret is an encrypted `TextFieldDescriptor` (the three-argument
constructor, `javap` on the 13.1.3 SDK) rather than a `SecretReferenceFieldDescriptor`: the latter holds a
reference into a configured secret manager, which neither the rig nor any consumer runs, and the encrypted
field gives the archive the same treatment PingFederate gives its own client secrets - obfuscated under the
master key, handed to the plugin in the clear. S2c can add the reference form once the platform library's
secret handling exists.

**Upgrade rehearsal, plan to-verify item 7 (2026-09-27, 13.1.3.0; U-0022).** The rig was booted with the
v0.3.0 jar from the GitHub release, an instance created through the admin API with a plaintext "Shared Secret",
one decision made (the stub PDP received the secret header), and the archive exported: it holds
`<urn:Field name="Shared Secret">` in the clear. The container was then restarted on this jar and the archive
imported (`POST /configArchive/import?forceImport=true`, 200). What followed:

- the admin API reads the field back as an `encryptedValue` (`OBF:JWE:...`), while the instance on disk still
  holds the plaintext, and the undeclared "Deny unless PERMIT" beside it;
- PingFederate logged one ERROR after the import, `[PluginConfigUtil] There was a problem deobfuscating the
  value for the field: Shared Secret`, and none at the decisions that followed;
- the plugin was handed the value as stored: the stub PDP received the same secret header as before;
- saving the instance again (a `PUT` of what the admin API read back) stored the secret encrypted - on disk a
  191-character value beginning `eyJhbGci`, a JOSE header, and no plaintext - dropped "Deny unless PERMIT", and the next decision sent the same header
  with no new ERROR.

So a stored plaintext value survives the switch; save each instance again after upgrading to store it
encrypted. `OLD_PLUGIN_JAR=<the v0.3.0 jar> conformance/verify-rar-principal.sh` repeats the rehearsal and
prints each of those facts, never the secret.

**TLS to the PDP.** Give the PDP a certificate whose subject alternative name is the host PF dials: the
plugin checks it on every call, in every trust mode and with "Skip TLS verification" on, and nothing turns
that off. "PDP TLS trust" chooses whom the certificate must chain to:

| Mode | Trusts |
|---|---|
| `jvm-default` (default) | the CA certificates of the JVM PingFederate runs on |
| `pingfederate-trusted-cas` | PingFederate's trust anchors as the SDK hands them to a plugin, `com.pingidentity.access.TrustedCAAccessor.getAllTrustAnchors()` (public in pingfederate-sdk 13.1.3.0; javap, 2026-09-29): the CAs under Security, Trusted CAs, and the JVM's own (`TrustedCAsManagerImpl.loadConfig` adds both; javap of pf-protocolengine 13.1.3.0). Read on every call, so a CA added in the console is used without saving the instance again ([U-0300](../../docs/findings/U-0300.yaml)) |
| `pinned-ca` | only the CA certificates in "PDP CA certificates (PEM)", nothing from the JVM |

The JVM-wide `-Djdk.internal.httpclient.disableHostnameVerification=true`, which older notes for this plugin
recommended, is neither needed nor wanted. It only ever governed the JDK's `java.net.http` client, which this
plugin no longer uses, and it switches the check off for every `java.net.http` client in that PingFederate at
once (read from the JDK in the 13.1.3 image, OpenJDK 21.0.12.1: `AbstractAsyncSSLConnection` takes the flag from
a static field, 2026-09-26). From 0.6.0 a production deployment refuses it (plan item PR-5; F-0035). The
trust-all behind "Skip TLS verification" is libs/platform's `InsecureTls` (plan item PR-1), shaded into the
jar: the first instance configured with it honoured logs one WARN naming the field, and the use is recorded for
the start-up audit. `PdpTlsTest` holds each mode, and the trust-all, to a certificate for the wrong name, and
refuses it.

## Verified on the rig

`conformance/verify-rar-principal.sh` boots the rig on its own slot (by default `PF_RIG_NAME=pfai-rar`, ports
45031/45080/45999) with this jar lent to it by `conformance/docker-compose.rar-plugin.yml` (a bind mount under
`/opt/in`, which the base image copies over `/opt/out` at start; `OIDF_DEPLOYMENT_PROFILE=development` so the
plugin may dial the stub over plain http), starts `conformance/rar-principal/stub-pdp.py` on the host (an
AuthZEN PDP that answers PERMIT and appends every request to a JSONL file), configures a processor instance,
the three built-in types, a bearer-token exchange policy and a secret-authenticated client through the
admin API, drives client credentials, CIBA, refresh, token exchange and the code flow, prints per flow the user key PingFederate passed (matched by
SHA-256 against the plugin's log line) and the `principal_source` the PDP received, removes what it
configured and takes the rig down, image included. `SKIP_UP=1 KEEP_RIG=1` reuses a running rig;
`ONLY_CONFIGURE=1` leaves the configuration in place for driving a flow by hand. The evidence in the table and
the upgrade rehearsal above are its run of 2026-09-27T03:40Z, on this plugin at commit b497275
(`conformance/.rar-principal/summary.txt`, `pdp-requests.jsonl` and PingFederate's `server.log`, git-ignored).
That `server.log` carries neither the test user's name nor the shared secret: the plugin's lines hash the
principal, and the refusals PingFederate logs with their causes carry only the plugin's own text.

**The containment model on the rig (2026-09-27T09:33Z, PingFederate 13.1.3.0, this jar at 0.4.0-SNAPSHOT,
commit 6bca441).** The rig above on its own slot (`PF_RIG_NAME=pfai-s1c`), configured by
`ONLY_CONFIGURE=1 conformance/verify-rar-principal.sh`, with the stub PDP swapped for one that answers PERMIT
with an AuthZEN `context` (each member becomes a statement). The plugin logged `RAR models loaded:
fingerprint=bbedb1a7...` with `commonFieldsFallback=true`, the rig being a development deployment, and its
configure line carried the same `rarModels=`. Then:

| Request | PDP context | Token endpoint |
|---|---|---|
| client credentials, `sales_agent` EMEA | `{"max_txn_eur": 100}` (a limit the request left open) | 200, granted EMEA with `max_txn_eur` 100 |
| client credentials, `sales_agent` EMEA and APAC | `{"sales_regions": ["EMEA"], "max_txn_eur": 50}` | 200, granted EMEA with `max_txn_eur` 50 |
| client credentials, `sales_agent` EMEA | `{"sales_regions": ["EMEA", "APAC"]}` (wider) | 400 `invalid_authorization_details`; WARNING "refusing the PDP's answer ... it is not within the request" |
| client credentials, `sales_agent` EMEA | `{"trace": "x"}` (undeclared) | 400; WARNING names `'trace'` as a field `sales_agent` does not declare |
| client credentials, `sales_agent` with `"tier": "gold"` | - | 400, and the PDP was not asked |
| refresh of a CIBA grant for 42.00 AUD to Acme, asking for 43.00 | none | 400 `invalid_authorization_details`; "RAR refresh: ... not within the grant" |
| the same refresh, asking for 42.00 to Mallory | none | 400 |
| the same refresh, asking for 41.00 to Acme | none | 200, granted 41.00 |
| the same grant, refreshed without `authorization_details` | none | 200, the stored 42.00 reissued; the PDP was not asked (F-0105) |

PingFederate logged each refusal at ERROR as "Error during enrichment of authorization detail: sales_agent",
with nothing of the PDP's answer: `APAC` appears nowhere in `server.log`. The attestation-context fingerprint
was not exercised there: the probe client is secret-authenticated, and the filter publishes the fingerprint only
from S1b on (U-0116).

**The AuthZEN batch on the rig (2026-09-30, PingFederate 13.1.3.0, this jar at 0.6.0-SNAPSHOT).** The rig on
slot 5 (`PF_RIG_NAME=pfai-p3-s2c`), configured by `ONLY_CONFIGURE=1 conformance/verify-rar-principal.sh`, with the
instance switched through the admin API to a stub AuthZEN PDP on the host that answers both
`/access/v1/evaluation` and `/access/v1/evaluations` (one `{"decision": true}` per evaluation, in order) and
"AuthZEN batch URL" set. The admin API filled the instance's seven new fields with their defaults, and the
configure line read `tlsTrust=jvm-default totalMillis=5000 batch=true cacheTypes=[] breaker=5/30s`. One
client-credentials token request with three `sales_agent` details (EMEA, APAC, AMER): 200, the token carrying all
three; PingFederate called `enrich` three times (three `RAR governance: type=sales_agent` lines), and the PDP
received exactly one request, a `POST /access/v1/evaluations` with three evaluations in the order asked, and
nothing on the single-evaluation path. PingAuthorize's own AuthZEN servlet could not be run: the licence in the
`paz/` profile expired on 2026-08-12 ([U-0302](../../docs/findings/U-0302.yaml)).

**`validate` and the JWT-bearer grant on the rig (2026-09-30T06:38-06:50Z, PingFederate 13.1.3.0, this jar at
0.6.0-SNAPSHOT).** The rig on slot 2 (`PF_RIG_NAME=pfai-p3-s4d2`), configured by `ONLY_CONFIGURE=1
conformance/verify-rar-principal.sh`, with the probe client given the `EXTENSION` grant and an IdP connection added
through the admin API for a test JWT issuer (an X.509 verification certificate, and `sub` mapped from the assertion
to the access token manager). First, before any change, a jar that only logged each `validate` call: a signed plain
JWT-bearer request with a `payment_initiation` parameter was issued a token whose `authorization_details` was `[]`,
an ID-JAG assertion carrying the same detail was issued a token carrying it, and each logged one `validate` call and
no `RAR governance: type=` line (no `enrich`); a forged plain assertion still reached `validate`, a forged ID-JAG one
did not. Then this jar, with the field empty:

| Request | Answer | Plugin |
|---|---|---|
| plain JWT-bearer, `payment_initiation` in the request | 400 `invalid_authorization_details`, "authorization_details of this type are not accepted on the JWT-bearer grant", no token | one `RAR validate: refusing` line; no `enrich`, no PDP call |
| ID-JAG, `payment_initiation` in the assertion | the same | the same |
| ID-JAG, `sales_agent` in the assertion | the same | the same |
| plain JWT-bearer, no `authorization_details` | 200 | nothing asked |
| PAR, `payment_initiation` with an undeclared `colour` | 400 at PAR: "... does not conform to its type's model (UNDECLARED_FIELD): requested authorization_details[0] carries 'colour', which type 'payment_initiation' does not declare" | refused at PAR |
| PAR, `amount` a boolean | 400 at PAR, `MALFORMED`: "...amount must be a number or a plain decimal string" | refused at PAR |
| PAR, a conforming `payment_initiation` | 201 | nothing refused |
| CIBA backchannel request, `sales_agent` with an undeclared `tier` | 400 at `/as/bc-auth.ciba`, `UNDECLARED_FIELD` | refused there |
| client credentials, a conforming `sales_agent` | 200, granted | `enrich` and one PDP call, as before |
| client credentials, `sales_agent` with `tier` | 400 `UNDECLARED_FIELD` | refused by `validate`; no `enrich`, no PDP call |

Saving the instance through the admin API with "Types allowed on the JWT-bearer grant" set to
`sales_agent,payment_initiation` was refused (422, `plugin_validation_error`, naming `payment_initiation`); with
`sales_agent` it saved, the configure line read `jwtBearerTypes=[sales_agent]`, an ID-JAG assertion carrying a
`sales_agent` detail was issued a token carrying it with no `enrich` and no PDP call, one carrying an undeclared
`tier` was refused with `UNDECLARED_FIELD`, and a plain JWT-bearer request with a `sales_agent` parameter was issued
a token with `"authorization_details": []`. An instance created before the field existed read it back from the
admin API as blank after the upgrade. The plugin's lines in `server.log` carry no detail value.

**The production refusals on the rig (2026-09-30, PingFederate 13.1.3.0, this jar at 0.6.0-SNAPSHOT, package PLG,
slot 2 `pfai-p3-plg`).** In development an instance with "Skip TLS verification (dev only)" on saved (201), was bound
to `sales_agent` with a client-credentials client, and the configuration was exported. The same rig, recreated with
`OIDF_DEPLOYMENT_PROFILE=production` and booting from that archive (age-encrypted, as production requires), read the
instance back with the switch on; a client-credentials request carrying `sales_agent` got `400
invalid_authorization_details` ("the processor bound to it is not configured"), the same request without details got
a token, and `server.log` held `Unexpected exception thrown attempting to configure plugin: plgSkipTls
(au.idp.rar.FedRar)` with the refusal's text. Through the admin API, saving a new instance with the switch on, or with
"Fail open on engine error" on and no accepted risk, was refused 422 with the refusal's text; with every switch off it
saved (201). Importing the development archive again through `/configArchive/import` answered 200 and left the same
state. Discovery answered 200 throughout.

Not verified there: the device flow's user key (U-0066) and the `subject` recipe on an authentication *policy*
contract rather than an adapter mapping (U-0067).

## Build, test, deploy

```bash
mvn -pl plugins/rar-paz-plugin -am package     # → target/pf.plugins.pf-rar-paz-plugin.jar (tests on)
```

Versions come from the repo BOM (`bom/pom.xml`); the two `provided` PF jars must be in `~/.m2` — the
`install:install-file` lines in `.github/actions/pf-provided-jars/action.yml`. Deploy recipe in
[`idp-agentic-demo/pingfederate/rar-paz/`](https://github.com/dphhyland/idp-agentic-demo/blob/main/pingfederate/rar-paz) — the config-as-code moved there on 2026-08-21, beside the PingAuthorize services that answer it. Its
`Dockerfile.fragment` still adds the JVM-wide hostname flag the TLS note above says to take out (checked
2026-09-26): this plugin does not need it from 0.6.0, and a production deployment refuses it. Removing it is that
repo's change (F-0035). Note this repo's own `build/pingfederate/` image is
the OIDF-only AS and deliberately does **not** bake this plugin; the rig borrows it through the compose
override above.
