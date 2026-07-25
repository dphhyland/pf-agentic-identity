# pf-agentic-identity

**Agentic / workload identity on PingFederate, as one platform.** An agent *type* is an OpenID
Federation entity a trust anchor vouches for; an ephemeral *instance* authenticates with a Client
Attestation bound to its own key; the AS registers and authorizes the client **live against the
trust controller** on every call; its authority is carried as fine-grained RAR entitlements and
evaluated post-issuance through Grant Management. Revoke the type at the anchor and the very next
token fails — governance is real-time, not a credential expiry.

One `mvn package` at the root builds every PF-side artifact, including the gm-api servlet
(`gm-api.war`). The authorization-server-agnostic **Go** reference implementation of the Grant
Evaluation API lives in its own repo,
[grant-evaluation-api](https://github.com/dphhyland/grant-evaluation-api) — it is not tied to
PingFederate, so it does not live here.

## Layout — organized by *how it loads into PingFederate*

PF has two very different extension mechanisms, and the tree mirrors them. **Servlets** are plain
`@WebServlet` classes: they ship inside a war, PF's web container annotation-scans them, and they run
on the webapp classloader. **Plugins** implement a PF SDK SPI: discovered via a `PF-INF/` descriptor,
must be named `pf.plugins.*.jar`, and load on a per-plugin *isolated* classloader (which is why the
RAR plugin shades its jackson). Pure **libs** know nothing about PF at all.

### `libs/` — pure libraries (no PingFederate)

| Path | What it is | Artifact |
|---|---|---|
| `libs/oidf-jose` | Foundation JOSE SDK — JWT codec, JWKS, claims, HTTP | `oidf-jose.jar` |
| `libs/client-attestation` | **Client Attestation authenticator** (AS side): verifier, DPoP, challenge/replay (Redis-backed), RAR containment — draft-ietf-oauth-attestation-based-client-auth | `client-attestation.jar` |
| `libs/openid-federation` | **OpenID Federation** core: trust-chain validation, entity statements, trust-controller gateway, client entity authorizer (draft-10 metadata) | `openid-federation.jar` |

### `servlets/` — webapp extensions (annotation-scanned, ship in `oidf.war` / `WEB-INF/lib`)

| Path | What it is | Artifact |
|---|---|---|
| `servlets/pf-integration` | The PF glue: **federation servlet** + §12.1 automatic / §12.2 explicit **registration against the trust controller**, OGNL hooks, client store, and **`ClientAttestationAuthFilter`** — a token-endpoint filter that implements `attest_jwt_client_auth` (the attestation becomes the client's only credential; see `deploy/pingfederate/build/assemble-pf-runtime-war.sh`) | `oidf.jar` + `oidf.war` |
| `servlets/attestation-issuer` | **Client Attestation issuer**: `/federation/attestation` (SPIFFE SVID → minted attestation), per-client attester keys (OpenBao transit or inline JWK), challenge servlet | `attestation-issuer.jar` |
| `servlets/ssf` | Shared Signals Framework 1.0 transmitter + receiver (CAEP/RISC, SET mint/verify, PF audit-log source, grant-revocation action) | `ssf.jar` |

### `plugins/` — PF SDK plugins (`PF-INF/` descriptor, isolated classloader)

| Path | What it is | Artifact |
|---|---|---|
| `plugins/rar-paz-plugin` | **RAR plugin**: RFC 9396 `AuthorizationDetailProcessor` → PingAuthorize governance engine (principal as `UserID`, agent as `actor` — RFC 8693 delegation) | `pf.plugins.pf-rar-paz-plugin.jar` |

### `services/` — standalone services

| Path | What it is | Artifact |
|---|---|---|
| `services/gm-api` | **Grant Management / AuthZEN Grant Evaluation API** as a PingFederate servlet + `/mcp` agent add-on: is this grant, intersected with what the subject holds, still enough — right now? Reads grants in-process via the PF SDK. (AS-agnostic Go reference: [grant-evaluation-api](https://github.com/dphhyland/grant-evaluation-api).) | `gm-api.war` |

`deploy/` is the environment-as-code tree (Railway; per-service Dockerfile + `vars.<env>.env` +
path-filtered workflows). Push to `main` deploys **staging**; production is an explicit
`workflow_dispatch`. The demo UI / harness lives in
[pf-oidf-modules](https://github.com/dphhyland/pf-oidf-modules).

## Building

```
mvn package                      # all Java modules (incl. gm-api.war), tests on
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
