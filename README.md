# pf-agentic-identity

**Agentic / workload identity on PingFederate, as one platform.** An agent *type* is an OpenID
Federation entity a trust anchor vouches for; an ephemeral *instance* authenticates with a Client
Attestation bound to its own key; the AS registers and authorizes the client **live against the
trust controller** on every call; its authority is carried as fine-grained RAR entitlements and
evaluated post-issuance through Grant Management. Revoke the type at the anchor and the very next
token fails — governance is real-time, not a credential expiry.

One `mvn package` at the root builds every PF-side artifact; the Go Grant-Evaluation service builds
with `go build ./...` under `services/gm-api`.

## Modules

| Path | What it is | Artifact |
|---|---|---|
| `modules/oidf-jose` | Foundation JOSE SDK — JWT codec, JWKS, claims, HTTP | `oidf-jose.jar` |
| `modules/client-attestation` | **Client Attestation authenticator** (AS side): verifier, DPoP, challenge/replay (Redis-backed), RAR containment — draft-ietf-oauth-attestation-based-client-auth | `client-attestation.jar` |
| `modules/openid-federation` | **OpenID Federation** core: trust-chain validation, entity statements, trust-controller gateway, client entity authorizer (draft-10 metadata) | `openid-federation.jar` |
| `modules/pf-integration` | The PF glue (only module with the PF SDK dep): **federation servlet** + §12.1 automatic / §12.2 explicit **registration against the trust controller**, OGNL hooks, client store | `oidf.jar` + `oidf.war` |
| `modules/attestation-issuer` | **Client Attestation issuer**: `/federation/attestation` (SPIFFE SVID → minted attestation), per-client attester keys (OpenBao transit or inline JWK), challenge servlet | `attestation-issuer.jar` |
| `modules/ssf` | Shared Signals Framework 1.0 transmitter + receiver (CAEP/RISC, SET mint/verify, PF audit-log source, grant-revocation action) | `ssf.jar` |
| `modules/rar-paz-plugin` | **RAR plugin**: RFC 9396 `AuthorizationDetailProcessor` → PingAuthorize governance engine (principal as `UserID`, agent as `actor` — RFC 8693 delegation) | `pf.plugins.pf-rar-paz-plugin.jar` |
| `services/gm-api` | **Grant Management / AuthZEN Grant Evaluation API** — Go service + PF servlet (`gm-api.war`): is this grant, intersected with what the subject holds, still enough — right now? | binary + `gm-api.war` |

`deploy/` is the environment-as-code tree (Railway; per-service Dockerfile + `vars.<env>.env` +
path-filtered workflows). Push to `main` deploys **staging**; production is an explicit
`workflow_dispatch`. The demo UI / harness lives in
[pf-oidf-modules](https://github.com/dphhyland/pf-oidf-modules).

## Building

```
mvn package                      # all Java modules, tests on
cd services/gm-api && go build ./...
```

The two `provided` PF jars (`pf-protocolengine`, `pingfederate-sdk` 13.0.0.3) are extracted from the
public `pingidentity/pingfederate` image — see `.github/workflows/build.yml` for the exact steps, or
run its `install:install-file` lines once locally. Nothing licensed or secret is committed.

## Provenance

This repo absorbed several repos **with their history** (git subtree / filter-repo). The originals
remain live; **this monorepo is canonical** — changes flow back only as deliberate backports.
Full map: [docs/PROVENANCE.md](docs/PROVENANCE.md).

## License

Apache-2.0.
