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
**grant-evaluation-api** (a sibling checkout - not yet published to GitHub) — it is not tied to
PingFederate, so it does not live here.

## Layout — organized by *how it loads into PingFederate*

PF has two very different extension mechanisms, and the tree mirrors them. **Servlets** are plain
`@WebServlet` classes: they ship inside a war, PF's web container annotation-scans them, and they run
on the webapp classloader. **Plugins** implement a PF SDK SPI: discovered via a `PF-INF/` descriptor,
must be named `pf.plugins.*.jar`, and load on a per-plugin *isolated* classloader (which is why the
RAR plugin shades its jackson). Pure **libs** know nothing about PF at all; **services** are
standalone processes PF trusts or calls. Sixteen reactor modules, `bom/` included — the one place a
shared dependency version is written down, imported by every module pom except the vendored
`services/gm-api`.

### `libs/` — pure libraries (no PingFederate)

| Path | What it is | Artifact |
|---|---|---|
| `libs/oidf-jose` | Foundation JOSE SDK — JWT codec, JWKS, claims, HTTP | `oidf-jose-0.1.0.jar` |
| `libs/client-attestation` | **Client Attestation authenticator** (AS side): verifier, DPoP, challenge/replay (Redis-backed), RAR containment — draft-ietf-oauth-attestation-based-client-auth | `client-attestation-0.1.0.jar` |
| `libs/openid-federation` | **OpenID Federation** core: trust-chain validation, entity statements, trust-controller gateway, client entity authorizer (draft-10 metadata) | `openid-federation-0.1.0.jar` |
| `libs/app-attest` | **Apple App Attest** verification to Apple's root — attests the app and device, never the user; binding the app's own Secure Enclave key is the caller's job via `clientDataHash` | `app-attest-0.1.0.jar` |
| `libs/device-instance` | The **agent instance registry** — the only place an opaque instance id resolves to a human — and the **device Client Attestation minter** (subject = that id, never the user). Owns the Postgres schema | `device-instance-0.1.0.jar` |
| `libs/agent-registry` | Mints/resolves **`agent_id`**: a random, never-derived per-running-instance identifier, for runtimes with no enrolment step of their own (a SPIFFE workload) | `agent-registry-0.1.0.jar` |

### `servlets/` — webapp extensions (annotation-scanned; ship in `oidf.war`, or merged into `pf-runtime.war` at root context by the deploy image)

| Path | What it is | Artifact |
|---|---|---|
| `servlets/pf-integration` | The PF glue: **federation servlet** + §12.1 automatic / §12.2 explicit **registration against the trust controller**, OGNL hooks, client store, and the `/as/token.oauth2` filters — **`ClientAttestationAuthFilter`** (implements `attest_jwt_client_auth`: the attestation becomes the client's only credential) and **`TokenEndpointAutoRegistrationFilter`** — registered by the deploy image's `web.xml` surgery (`deploy/pingfederate/build/assemble-pf-runtime-war.sh`) | `oidf.jar` |
| `servlets/attestation-issuer` | **Client Attestation issuer**: `/federation/attestation` (platform evidence — SPIFFE SVID, GKE/EKS/AKS, AWS, Azure — → minted attestation), per-client attester keys (OpenBao transit or inline JWK), challenge servlet | `attestation-issuer-0.1.0.jar` |
| `servlets/oidf-war` | The **`oidf.war` assembly**: pf-integration + attestation-issuer with their libraries in `WEB-INF/lib` (jose4j excluded — PF ships it; a second copy is a `LinkageError`). Its own module so it can depend on every servlet module without a reactor cycle | `oidf.war` |
| `servlets/ssf` | Shared Signals Framework 1.0 transmitter + receiver (CAEP/RISC, SET mint/verify, PF audit-log source, grant-revocation action) | `ssf-0.1.0.jar` |

### `plugins/` — PF SDK plugins (`PF-INF/` descriptor, isolated classloader)

| Path | What it is | Artifact |
|---|---|---|
| `plugins/rar-paz-plugin` | **RAR plugin**: RFC 9396 `AuthorizationDetailProcessor` → PingAuthorize governance engine (principal as `UserID`, agent as `actor` — RFC 8693 delegation) | `pf.plugins.pf-rar-paz-plugin.jar` |
| `plugins/instance-registry-datasource` | **`CustomDataSourceDriver`** over the instance registry: an access-token mapping resolves an instance id to owner, status, compliance and user-verification recency at issuance — where revocation and the time-box bite | `pf.plugins.instance-registry-datasource.jar` |

### `services/` — standalone services

| Path | What it is | Artifact |
|---|---|---|
| `services/gm-api` | **Grant Management / AuthZEN Grant Evaluation API** as a PingFederate servlet + `/mcp` agent add-on: is this grant, intersected with what the subject holds, still enough — right now? Reads grants in-process via the PF SDK. (AS-agnostic Go reference: **grant-evaluation-api**, sibling checkout.) | `gm-api.war` |
| `services/device-enrolment` | The **agent platform backend** — Client Attester for device-resident agents: enrolment ceremony (App Attest + PingOne passkey + Secure Enclave key), owns the instance registry, mints Client Attestations, enforces the user-verification time-box server-side. Not a PF extension | `device-enrolment-0.1.0.jar` |
| `services/demo-rs` | **Resource-server validation** that closes the loop: AS signature, DPoP proof, `cnf.jkt` equals the proof key's thumbprint (the check people skip), then the RFC 8693 `act` chain. A library, no HTTP surface | `demo-rs-0.1.0.jar` |

`deploy/` is the environment-as-code tree (Railway; per-service Dockerfile + `railway.json` +
`vars.<env>.env` + path-filtered workflows — [deploy/README.md](deploy/README.md)). Push to `main`
deploys **staging**; production is an explicit `workflow_dispatch`. `deploy/pingfederate` builds the
AS image from the reactor's **modular jars** (`build/stage-modules.sh` → `modules/`, merged into
`pf-runtime.war` at root context and onto the engine classpath — the `pf-oidf-modules.jar` monolith
is gone); `deploy/device-enrolment` has config but no workflow yet (manual). **Demos:**
[docs/DEMOS.md](docs/DEMOS.md) indexes every demo and how to bring it up. The demo UI / harness lives
in [pf-oidf-modules](https://github.com/dphhyland/pf-oidf-modules); the cross-platform rigs — the
GKE/EKS/Azure legs, the cross-cloud chain, the phone simulator — in
**pf-agentic-identity-domain-authority** (private, so named rather than linked; extracted 2026-08-08
with history; consumes this repo as a sibling checkout).

## Building

```
mvn package                      # all Java modules (incl. gm-api.war), tests on
```

The two `provided` PF jars (`pf-protocolengine`, `pingfederate-sdk` 13.0.0.3) are extracted from the
public `pingidentity/pingfederate` image — see `.github/workflows/build.yml` for the exact steps, or
run its `install:install-file` lines once locally. Nothing licensed or secret is committed.

## Provenance

This repo absorbed several repos **with their history** (git subtree / filter-repo). The originals
remain live; **this monorepo is canonical** — changes flow back only as deliberate backports (and, since
the 2026-08-15 split-package unwind gave each module its own packages, with package translation).
Full map: [docs/PROVENANCE.md](docs/PROVENANCE.md).

## License

Apache-2.0.
