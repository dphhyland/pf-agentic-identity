# pf-agentic-identity

**Agentic / workload identity on PingFederate, as one platform.** An agent *type* is an OpenID
Federation entity a trust anchor vouches for; an ephemeral *instance* authenticates with a Client
Attestation bound to its own key; the AS registers and authorizes the client **against the trust
controller**, validating trust chains from statements it caches until shortly before they expire; its
authority is carried as fine-grained RAR entitlements and evaluated post-issuance through Grant
Management. Revoke the type at the anchor and its clients stop authenticating once the statements the
anchor already signed run out — they live an hour, a verifier serves a cached one until five minutes
before that, a registration lasts no longer than its chain, and a renewal that fails leaves it standing
only until then — so governance is bounded by statement lifetime, not credential expiry.

One `mvn package` at the root builds every PF-side artifact, including the gm-api servlet
(`gm-api.war`). The authorization-server-agnostic **Go** reference implementation of the Grant
Evaluation API lives in its own repo, **grant-evaluation-api** (private, so named rather than linked;
checked out as a sibling) - it is not tied to PingFederate, so it does not live here.

## Layout — organized by *how it loads into PingFederate*

PF has two very different extension mechanisms, and the tree mirrors them. **Servlets** are plain
`@WebServlet` classes: they ship inside a war, PF's web container annotation-scans them, and they run
on the webapp classloader. **Plugins** implement a PF SDK SPI: discovered via a `PF-INF/` descriptor,
must be named `pf.plugins.*.jar`, and load on a per-plugin *isolated* classloader (which is why the
RAR plugin shades its jackson). Pure **libs** know nothing about PF at all; **services** are
standalone processes PF trusts or calls. Nineteen reactor modules, `bom/` included — the one place a
shared dependency version is written down, imported by every module pom except the vendored
`services/gm-api`. `libs/conformance` is the odd one out: a single annotation, test-scoped everywhere
and deliberately absent from `stage-modules.sh`, so nothing it carries reaches the PF image. Artefact
names below carry the project version, written `<version>`.

### `libs/` — pure libraries (no PingFederate)

| Path | What it is | Artifact |
|---|---|---|
| `libs/oidf-jose` | Foundation JOSE SDK — JWT codec, JWKS, claims, HTTP | `oidf-jose-<version>.jar` |
| `libs/client-attestation` | **Client Attestation authenticator** (AS side): verifier, DPoP, challenge/replay (Redis-backed), RAR containment — draft-ietf-oauth-attestation-based-client-auth | `client-attestation-<version>.jar` |
| `libs/openid-federation` | **OpenID Federation 1.0** (Final): trust-chain validation against pinned anchors, metadata policy, constraints, Trust Marks (verify and issue), the federation endpoints' logic, hosted entities and their key history, the AuthZEN policy decision client, and the event API - no PingFederate code | `openid-federation-<version>.jar` |
| `libs/app-attest` | **Apple App Attest** verification to Apple's root — attests the app and device, never the user; binding the app's own Secure Enclave key is the caller's job via `clientDataHash` | `app-attest-<version>.jar` |
| `libs/device-instance` | The **agent instance registry** — the only place an opaque instance id resolves to a human — and the **device Client Attestation minter** (subject = that id, never the user). Owns the Postgres schema | `device-instance-<version>.jar` |
| `libs/agent-registry` | Mints/resolves **`agent_id`**: a random, never-derived per-running-instance identifier, for runtimes with no enrolment step of their own (a SPIFFE workload) | `agent-registry-<version>.jar` |
| `libs/conformance` | The `@Requirement` annotation that ties a test to the specification clause it pins. Test scope everywhere | `conformance-<version>.jar` |

### `servlets/` — webapp extensions (annotation-scanned; ship in `oidf.war`, or merged into `pf-runtime.war` at root context by the image build)

| Path | What it is | Artifact |
|---|---|---|
| `servlets/pf-integration` | The PF glue: **federation servlets** (entity configuration, fetch, list, resolve, Trust Mark and historical keys endpoints, hosted-entity admin) + §12.1 automatic registration at the token, authorization and PAR endpoints and §12.2 explicit **registration**, OGNL hooks, client store, and the filters over PF's own endpoints — **`ClientAttestationAuthFilter`** (implements `attest_jwt_client_auth`: the attestation becomes the client's only credential), **`TokenEndpointAutoRegistrationFilter`**, and **`Fapi2ProfileFilter`** (two FAPI 2.0 rules PF can't apply per client - issuer-only `aud` on client assertions, which 13.1 can switch on only for the whole server, and PS256/ES256/EdDSA-only DPoP proofs, which it has no setting for; applied only to the clients `OIDF_FAPI2_CLIENTS` lists) — registered by the image build's `web.xml` surgery (`build/pingfederate/assemble-pf-runtime-war.sh`) | `oidf.jar` |
| `servlets/attestation-issuer` | **Client Attestation issuer**: `/federation/attestation` (platform evidence — SPIFFE SVID, GKE/EKS/AKS, AWS, Azure — → minted attestation), per-client attester keys (OpenBao transit or inline JWK), challenge servlet | `attestation-issuer-<version>.jar` |
| `servlets/oidf-war` | The **`oidf.war` assembly**: pf-integration + attestation-issuer with their libraries in `WEB-INF/lib` (jose4j excluded — PF ships it; a second copy is a `LinkageError`). Its own module so it can depend on every servlet module without a reactor cycle | `oidf.war` |
| `servlets/ssf` | Shared Signals Framework 1.0 transmitter + receiver (CAEP/RISC, SET mint/verify, PF audit-log source, grant-revocation action) | `ssf-<version>.jar` |

### `plugins/` — PF SDK plugins (`PF-INF/` descriptor, isolated classloader)

| Path | What it is | Artifact |
|---|---|---|
| `plugins/rar-paz-plugin` | **RAR plugin**: RFC 9396 `AuthorizationDetailProcessor` → PingAuthorize governance engine (principal as `UserID`, agent as `actor` — RFC 8693 delegation) | `pf.plugins.pf-rar-paz-plugin.jar` |
| `plugins/instance-registry-datasource` | **`CustomDataSourceDriver`** over the instance registry: an access-token mapping resolves an instance id to owner, status, compliance and user-verification recency at issuance — where revocation and the time-box bite | `pf.plugins.instance-registry-datasource.jar` |
| `plugins/ciba-sim` | **CIBA authentication device for the conformance rig**: an `OOBAuthPlugin` that waits for an allow or deny recorded at `POST /ciba-sim/decision`, plus that servlet, in one jar. Answers 404 unless `OIDF_CIBA_SIM_ENABLED=true` | `pf.plugins.ciba-sim.jar` |

### `services/` — standalone services

| Path | What it is | Artifact |
|---|---|---|
| `services/gm-api` | **Grant Management / AuthZEN Grant Evaluation API** as a PingFederate servlet + `/mcp` agent add-on: is this grant, intersected with what the subject holds, still enough — right now? Reads grants in-process via the PF SDK. (AS-agnostic Go reference: **grant-evaluation-api**, sibling checkout.) | `gm-api.war` |
| `services/device-enrolment` | The **agent platform backend** — Client Attester for device-resident agents: enrolment ceremony (App Attest + PingOne passkey + Secure Enclave key), owns the instance registry, mints Client Attestations, enforces the user-verification time-box server-side. Not a PF extension | `device-enrolment-<version>.jar` |
| `services/demo-rs` | **Resource-server validation** that closes the loop: AS signature, DPoP proof, `cnf.jkt` equals the proof key's thumbprint (the check people skip), then the RFC 8693 `act` chain. A library, no HTTP surface | `demo-rs-<version>.jar` |
| `services/harness` | **Verification CLIs run by hand** over the real classes - attestation issuance and verification, a CAEP SET - with each self-verify walk also run as a smoke test under `mvn test`. Not shipped | `harness-<version>.jar` |

`build/pingfederate/` builds the AS image from the reactor's **modular jars**
(`stage-modules.sh` → `modules/`, merged into `pf-runtime.war` at root context and onto the engine
classpath — the `pf-oidf-modules.jar` monolith is gone), and [`conformance/`](conformance/README.md)
configures and runs it (below). What this repo does not do is **deploy**: every hosting project, its
platform configuration and its per-environment variables belong to the repo that owns that environment -
see [build/pingfederate/README.md](build/pingfederate/README.md) for what a deployment supplies on top.
**Client attestation
end to end** — how issuance, verification, the PF token-endpoint filter and the RAR consumer fit
together, what is implemented, standards alignment, test coverage and the open gaps:
[docs/client-attestation-architecture.md](docs/client-attestation-architecture.md). **OpenID Federation** -
what PingFederate does in a federation, how, how to run it and how it is tested, in plain language:
[docs/federation](docs/federation/README.md). **Demos:**
[docs/DEMOS.md](docs/DEMOS.md) indexes every demo and how to bring it up. The demo UI / harness lives
in [pf-oidf-modules](https://github.com/dphhyland/pf-oidf-modules); the cross-platform rigs — the
GKE/EKS/Azure legs, the cross-cloud chain, the phone simulator — in
**pf-agentic-identity-domain-authority** (private, so named rather than linked; extracted 2026-08-08
with history; consumes this repo as a sibling checkout).

## Running PingFederate

```bash
conformance/up.sh
```

One command from a clone to a PingFederate 13.1.3 with every module in it on `https://localhost:9031`,
configured as code (Terraform) to pass the OpenID Foundation conformance suite's FAPI 2.0 and Shared
Signals plans - and, with `PF_PROFILE=federation` or `federation-op`, its OpenID Federation plans. You bring your own licence details - your Ping DevOps credentials in
`~/.pingidentity/config`; the image bakes no licence and the repo commits nothing licensed or secret.
What it does, what it configures, how to point a conformance suite at it and what the suite says:
[conformance/README.md](conformance/README.md).

## Product showcase

Open [showcase/index.html](showcase/index.html) in a browser for the servlet and plugin catalogue, shared libraries,
ecosystem architecture and interactive policy simulation. No build step is required. See
[showcase/README.md](showcase/README.md) for the local preview command and simulation boundaries.

## Building

```
mvn package                      # all Java modules (incl. gm-api.war), tests on
```

The two `provided` PF jars (`pf-protocolengine`, `pingfederate-sdk` 13.1.3.0) are extracted from the
public `pingidentity/pingfederate` image, and so are the jars gm-api and the tests name under
`local.pingfederate` - see `.github/actions/pf-provided-jars/action.yml` for the exact steps, or run its
`install:install-file` lines once locally. Nothing licensed or secret is committed.

The PingFederate version is pinned in one place, `build/pf-version.env`: the image tag and its digest,
the SDK version the reactor compiles against, and the product version the Terraform provider is told.
`tools/pf-version-check.py` checks that the places which name the version agree with it, and
`tools/set-version.py` keeps every pom on the one project version.

This repo runs on PingFederate **13.1.3**, whose servlet container is `jakarta.servlet`. From 0.2.0
every servlet, filter and war here is compiled against it and does not load on 13.0.x. The SDK plugins
are built and supported for 13.1 only, and the RAR plugin no longer links on 13.0 at all: it reads the
request through `getJakartaRequest()`, which 13.0 does not have. `v0.1.5` is the last release for
13.0.x, on the `pf-13.0` branch, which is frozen and takes no backports. The first release for 13.1.3
is v0.3.0, and upgrades are supported from it: move to PingFederate 13.1.3 and v0.3.0 together. What
moved, what did not, and the evidence:
[docs/pf-13_1-jakarta-migration-plan.md](docs/pf-13_1-jakarta-migration-plan.md).

## Provenance

This repo absorbed several repos **with their history** (git subtree / filter-repo). The originals
remain live; **this monorepo is canonical** — changes flow back only as deliberate backports (and, since
the 2026-08-15 split-package unwind gave each module its own packages, with package translation).
Full map: [docs/PROVENANCE.md](docs/PROVENANCE.md).

## License

Apache-2.0.
