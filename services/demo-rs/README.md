# demo-rs

> **Part of the [pf-agentic-identity](https://github.com/dphhyland/pf-agentic-identity) monorepo** — build from the repo root with `mvn package`. Written here, no upstream; see [docs/PROVENANCE.md](../../docs/PROVENANCE.md).

The resource-server end of the loop: what an RS must check before it believes an agent is acting for
a human. It validates a **DPoP sender-constrained** access token (RFC 9449) issued by PingFederate and
reads the **RFC 8693 `act` chain** to see which agent instance is acting for whom.

Two classes, package `com.pingidentity.ps.oidf.rs`, no PingFederate. There is no HTTP listener or
`main` here — this is the validation core a resource server embeds; the tests drive it directly.

## What it checks

`DelegatedTokenValidator.validate(accessToken, dpopProof, method, url)` — four things, in order, and the
third is the one people skip:

1. the access token is a JWS signed by one of the AS keys it was given (`ES256`/`RS256`/`PS256`, `kid`
   selected), with the expected `iss` and `aud`, unexpired within the clock skew;
2. the DPoP proof is well-formed, fresh, and covers this `htm`/`htu` —
   `com.pingidentity.ps.oidf.clientattestation.DpopProofValidator`, reused from
   [`libs/client-attestation`](../../libs/client-attestation) on purpose (the pom says why: it already
   implements RFC 9449, with tests, and there is no reason to write it twice);
3. **the proof's key is the key the token is bound to** — `cnf.jkt` must equal the RFC 7638 thumbprint
   of the proof's `jwk`, and the proof's `ath` must be the hash of *this* token. Without the first,
   sender-constraining is decorative; without the second, a captured proof works against any token
   bound to the same key;
4. the `act` claim, parsed by `ActChain`.

There is no bearer fallback: a missing proof is `invalid_token`, not "try Bearer". Replay of the proof
`jti` is the caller's to own, as it is in `DpopProofValidator` — the `Result` reports it, the RS decides
which cache it belongs in.

`ActChain` enforces two RFC 8693 §4.1 rules that are security bugs when got wrong: `act` is a JSON
object (the legacy string form this platform once emitted is still parsed but flagged
`legacyStringForm`, so a deployment can see it is on a deviation), and **only the outermost actor may be
authorised on** — `currentActor()` is the single-valued accessor; `priorActors()` is history, returned
only as a list. Nesting is bounded at 16 hops. For this platform `sub` is the human and `act.sub` is the
opaque agent instance identifier — an RS can risk-assess on it and learn nothing more without the
instance registry.

`Result.describe()` is what a demo endpoint can safely echo: subject, `delegated`, `acting_instance`,
`prior_actors`, scopes — no device data, no raw token. Refusals are `RsException(error, status, message)`
with the OAuth error code a `WWW-Authenticate` header should carry (`invalid_token`,
`invalid_dpop_proof`, 401).

## Build and test

```bash
mvn -pl services/demo-rs -am test      # 29 tests
```

Versions come from the repo BOM (`bom/pom.xml`); depends on `oidf-jose`, `client-attestation`, jose4j,
jackson. Test LOC exceeds main LOC by design — the contract is the product. The two tests that would
matter in an incident are `aProofFromADifferentKeyIsRejected` and
`aProofCapturedForAnotherTokenIsRejected`.

## Caveats

- Not deployed anywhere in this repo: no `deploy/` entry, no Dockerfile. It is a library-shaped
  reference an RS wires behind its own endpoint.
- The AS keys are passed in as a `List<JsonWebKey>`; fetching and rotating PF's JWKS is the embedding
  service's job.
