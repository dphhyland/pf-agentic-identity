# rs-validation

> **Part of the [pf-agentic-identity](https://github.com/dphhyland/pf-agentic-identity) monorepo** - build from the repo root with `mvn package`. Written here, no upstream; see [docs/PROVENANCE.md](../../docs/PROVENANCE.md).

The resource-server end of the loop: what a resource server must check before it believes an agent is acting for a
human. It validates a sender-constrained JWT access token issued by PingFederate - bound to a DPoP key (RFC 9449) or
to a TLS client certificate (RFC 8705) - and reads the RFC 8693 `act` chain to see which agent instance is acting for
whom. Package `com.pingidentity.ps.oidf.rs`. Formerly `services/demo-rs`, which is now a relocation POM (plan item
X-D01).

It is a library: a resource server embeds `DelegatedTokenValidator`, directly or through `ResourceServerFilter`, a
`jakarta.servlet.Filter`. From 0.6.0 its jar is staged into PingFederate's image beside platform-pf, whose operator
authenticator verifies the operator APIs' tokens through it (plan item S8a); `ResourceServerFilter` is not used there.

## What it checks

`DelegatedTokenValidator.validate(Presentation)` refuses the request unless all of this holds:

1. **The token is the authorisation server's.** A JWS whose `typ` is what `AccessTokenType` says (RFC 9068's
   `at+jwt` by default - see below), whose `alg` is permitted (`ES256`, `PS256`, `RS256` by default; never `none` or
   an HMAC), whose `kid` names exactly one of the server's public keys - a token without a `kid`, or naming one the
   server does not publish, is refused; there is no fallback to trying every key - and whose signature verifies.
   `iss` is the issuer, `aud` contains this resource, `exp` has not passed and `nbf`, when present, has (60 s
   leeway by default).
2. **The sender proves the binding.** The token's `cnf` must carry `jkt`, `x5t#S256` or both; a token with neither
   is refused, because there is no bearer mode.
   - `cnf.jkt`, under `Authorization: DPoP`: exactly one `DPoP` header, holding a proof that passes oidf-jose's
     `DpopProofValidator` (type `dpop+jwt`, a public `jwk`, the signature, `htm`, `htu` after RFC 3986
     normalisation, `iat` within the window) and whose key's RFC 7638 thumbprint is `jkt`, whose `ath` is this
     token's hash and, with `DpopNonces` on, whose `nonce` this server issued.
   - `cnf.x5t#S256`: the SHA-256 of the TLS client certificate is that value. Under `Authorization: Bearer`, which
     is accepted only when `mtls(true)` is set and only for a token with no `jkt`; RFC 9449 §7.2 says a
     DPoP-bound token received as a bearer token must be rejected.
3. **The `act` claim is an RFC 8693 actor chain.** `ActChain` parses it; a chain that is not a JSON object at every
   level, names no actor at a level, or nests more than 10 deep is refused. Only `currentActor()`, the outermost
   actor, is single-valued: RFC 8693 §4.1 says prior actors "are informational only and are not to be considered in
   access control decisions". For this platform `sub` is the human and `act.sub` the opaque agent instance
   identifier.
4. **The proof is new.** Last of all, the `ReplayStore` records the proof and refuses one it has seen: RFC 9449 §11.1
   has servers "store the jti value of each DPoP proof for the time window in which the respective DPoP proof JWT
   would be accepted to prevent multiple uses of the same DPoP proof".

Refusals are `DelegatedTokenValidator.RsException` with `error()` and `status()`:

| `error()` | Status | When |
|---|---|---|
| `invalid_token` | 401 | anything wrong with the token, its binding or its `act`; a DPoP-bound token without a proof |
| `invalid_dpop_proof` | 401 | a proof that fails RFC 9449 §4.3, more than one `DPoP` header, a wrong or missing `ath`, a replay |
| `use_dpop_nonce` | 401 | nonces on, and the proof has none or one this server did not issue; `dpopNonce()` is the one to use |
| `invalid_request` | 400 | from the filter: more than one `Authorization` header, a query `access_token` too, a credential that is not token68 |
| null | 401 | a scheme this resource does not take: RFC 6750 §3.1 sends no error for it |
| null | 503 | the replay store or the key source could not answer; the request is refused, never let through |

## Using it

```java
RedisClient redis = new RedisClient(RedisConfig.current());      // platform.redis
OutboundHttp http = OutboundHttp.builder(AddressPolicy.strict()).build();   // platform.http

DelegatedTokenValidator validator = DelegatedTokenValidator.builder("https://pf.example.com", "https://rs.example.com")
        .keys(new RemoteJwks(http, "https://pf.example.com/pf/JWKS"))
        .replayStore(new RedisReplayStore(redis.keyspace("oidf:rs:dpop")))
        .nonces(new DpopNonces(secret))          // optional: 32 random bytes, the same on every node
        .build();

servletContext.addFilter("rs", new ResourceServerFilter(validator, "https://rs.example.com"))
        .addMappingForUrlPatterns(null, false, "/api/*");
```

A request that passes carries the `Result` in the request attribute `com.pingidentity.ps.oidf.rs.Result`:
`subject()`, `actingInstance()`, `scopes()`, `claims()`, `binding()` (`DPOP`, `MTLS` or, in development only,
`NONE`), and `describe()`, which is what a demo endpoint can echo
(no raw token, no `cnf`). Authorising on the result - which scopes, which actor - is the resource's job; the library
only establishes who is asking and who is acting.

### The builder

| Method | Default | What it does |
|---|---|---|
| `keys(JwksSource)` / `keys(Collection<JsonWebKey>)` | this or `introspection` | the authorisation server's public keys |
| `introspection(TokenIntrospector)` | this or `keys` | ask the authorisation server about each token (RFC 7662) instead of verifying a JWT - see [Introspection](#introspection) |
| `replayStore(ReplayStore)` | required | where accepted proofs are remembered; `build()` refuses without one |
| `accessTokenType(AccessTokenType)` | `RFC9068` | `at+jwt` or `application/at+jwt`; `ABSENT` for no `typ`; `exactly("...")` |
| `tokenAlgorithms(Set)` / `proofAlgorithms(Set)` | `ES256 PS256 RS256` | ES, RS and PS algorithms only |
| `clockSkew(Duration)` | 60 s | leeway for `exp`, `nbf` and a proof's `iat`; at most 5 minutes |
| `proofMaxAge(Duration)` | 300 s | how long after `iat` a proof is accepted; 1 s to 1 hour |
| `nonces(DpopNonces)` | off | require resource-server nonces (RFC 9449 §9) |
| `dpop(boolean)` / `mtls(boolean)` | on / off | which schemes are accepted; at least one |
| `allowLegacyStringAct()` | off | accept `act` as a string holding JSON; reads this process's profile, and `build()` throws unless it is development |
| `allowUnbound()` / `allowUnbound(DeploymentProfile)` | off | accept a token with no `cnf` under `Authorization: Bearer`, reported as `Binding.NONE`; `build()` throws unless the profile is development. A DPoP-bound token sent as a bearer token is still refused (RFC 9449 §7.2) |

The library reads no environment variable or system property of its own: the embedding application builds it from
its own configuration, and `RedisConfig.current()` (the platform's catalogued `OIDF_REDIS_*` settings) is one way to
build the Redis client.

### Introspection

With `introspection(TokenIntrospector)` (platform.auth: RFC 7662 over `OutboundHttp`, 1 s to connect, 2.5 s in
all, 64 KiB) the token is not parsed at all: the authorisation server says whether it is active, and its answer's
members stand in for the JWT's claims and go through the same checks - `iss`, `aud`, `exp`, `nbf`, the `act` chain
and the binding - with two differences. RFC 7662 §2.2 makes `iss` and `exp` OPTIONAL, and PingFederate 13.1.3 leaves
`iss` out for a reference token (seen on the rig on 2026-09-29, [U-0030](../../docs/findings/U-0030.yaml)), so an
answer without them is accepted on the configured server's word; one that carries them is checked. The binding comes
from the answer's `cnf`: RFC 9449 §6.2, "For a DPoP-bound access token, the hash of the public key to which the token
is bound is conveyed to the protected resource as metainformation in a token introspection response", and "If the
token_type member is included in the introspection response, it MUST contain the value DPoP" - an answer with
`cnf.jkt` and another `token_type` is refused. The proof is then checked against that `jkt` and its `ath` against the
opaque token exactly as for a JWT. An inactive token is `invalid_token` (401); an endpoint that gives no usable
answer is a 503.

### Replay stores

`ReplayStore.firstUse(key, window)` answers whether a key is new. The key is base64url(SHA-256(`jkt` ":" `jti`)) -
a hash, so an outsized `jti` costs nothing to store, and scoped to the proof's key, so a party that sees another
client's `jti` cannot spend it first. It is not scoped to the target URI: a `jti` is refused everywhere once seen,
which is stricter than RFC 9449 §11.1 requires. The window is how much longer the proof would pass the freshness
check - until `iat` + max age + skew, plus a second for `iat`'s rounding.

- `RedisReplayStore` - `SET <prefix>:<key> 1 NX PX <window>` through `platform.redis`: shared by every node, and
  what a resource served by more than one node must use.
- `InMemoryReplayStore` - one JVM's bounded map (100,000 keys by default); when it is full of unexpired keys it
  answers as unavailable (503) rather than let a proof through. One node only.

### Keys

- `RemoteJwks` fetches the `jwks_uri` through `platform.http` - pinned to checked addresses, a 5 s deadline, a
  capped body - and caches the keys by `kid`. An unknown `kid` fetches again, at most once every 30 s; the whole
  set is fetched again once it is 10 minutes old, so a withdrawn key stops verifying at the next fetch that
  succeeds. A failed fetch keeps the keys it has, but not once they are 20 minutes (twice the maximum age) old:
  past that, while fetches keep failing, every token is a 503. A `kid` it does not have, when the last fetch
  failed, is a 503, not a 401.
- `StaticJwks` holds a fixed set. Both keep only public signing keys with a `kid`, and refuse a key with private
  parameters.

### PingFederate's `typ`

RFC 9068 §4: "The resource server MUST verify that the "typ" header value is "at+jwt" or "application/at+jwt" and
reject tokens carrying any other value." PingFederate's JWT access token manager does not send it unless its
"Type Header Value" field is set: the field's description reads "Indicates the value of the Type (typ) header in the
JWT (omitted, if blank)", and it is blank by default (read 2026-09-28 with javap from
`JwtBearerAccessTokenManagementPlugin` in PingFederate 13.1.3's `pf-core-plugins.jar`). The conformance rig sets it
to `at+jwt` ([conformance/terraform/tokens.tf](../../conformance/terraform/tokens.tf)). A deployment whose manager
leaves it blank uses `AccessTokenType.ABSENT`, which requires the header to be missing. The same manager includes
`kid` by default ("Include Key ID Header Parameter" defaults to on), which the exact-`kid` rule needs.

### Nonces

`DpopNonces` issues the base64url HMAC-SHA256, under a secret of at least 32 bytes, of the current time window's
number (a minute by default). Nodes that share the secret issue and accept the same nonces without storing any. A
nonce is accepted in its window and the next; one from the previous window passes, and the response carries the
current one in `DPoP-Nonce`.

### The filter

`ResourceServerFilter` answers a refusal with the status and the `WWW-Authenticate` challenges:

- no credentials, or a scheme not taken: 401, `DPoP algs="ES256 PS256 RS256"` (and `Bearer realm="<base URL>"` when
  mTLS is on), with no error - RFC 6750 §3.1;
- a refused token or proof: 401, the `error` and `error_description` in the challenge of the scheme used - RFC 9449
  §7.2's rule for a resource that takes both;
- ambiguous or malformed: 400 `invalid_request` in every challenge (RFC 9449 figure 19);
- `use_dpop_nonce`: 401 with `DPoP-Nonce`;
- unavailable: 503, no challenge.

Every refusal and every response carrying `DPoP-Nonce` has `Cache-Control: no-store`. An `error_description` keeps
only the characters RFC 6750 §3 allows and at most 200 of them. The `htu` a proof must name is the configured base
URL plus the request's path, never the `Host` header. The client certificate comes from the container's
`jakarta.servlet.request.X509Certificate` attribute, so a deployment behind a TLS-terminating proxy must have the
container take the certificate from the proxy for mTLS-bound tokens to pass.

## Build and test

```bash
mvn -pl libs/rs-validation -am verify
```

Versions come from the repo BOM; depends on `oidf-jose` (for `DpopProofValidator`, since 0.6.0: F-0225),
`platform` (redis, http, auth, json, profile), jose4j and Jackson; `jakarta.servlet-api` is provided. Every refusal test an RFC
requires quotes the sentence it enforces, with its `@Requirement` id where the RFC has a declared prefix (RFC 8705
and RFC 9068 have none yet, F-0227); the refusals that are this library's own policy - the exact `kid`, a shared
`kid`, the `act` depth cap, no bearer mode, the 503s - say so in their javadoc. The jacoco gate holds the decision methods at 100% line and branch.
`RedisReplayStoreLiveTest` runs against a real Redis when `OIDF_TEST_REDIS_URL` names one, as CI's java job does.

## Caveats

- Introspection answers are not cached here: `TokenIntrospector.Builder.cacheFor` can keep an active one for up to
  30 s (never past its `exp`), which is the caller's choice of liveness against load.
- The actor is reported, not authorised: nothing here checks it against a registry or `may_act`.
