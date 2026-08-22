# oidf-jose

> **Part of the [pf-agentic-identity](https://github.com/dphhyland/pf-agentic-identity) monorepo** — build from the repo root with `mvn package`. Absorbed with history from [`dphhyland/oidf-jose`](https://github.com/dphhyland/oidf-jose) on 2026-07-21; that repo is backports-only and its copy still uses the pre-split `.common` package. See [docs/PROVENANCE.md](../../docs/PROVENANCE.md).

The shared **JOSE/JWT + SD-JWT foundation** the rest of the reactor signs and verifies through.
Package `com.pingidentity.ps.oidf.jose`. Depends on `jose4j`, `jackson-databind` and `commons-logging`
only — no PingFederate, servlet, federation or attestation types — which is what lets it sit at the
bottom of the dependency graph and on every classpath (PF's shared classpath, `oidf.war`, the
standalone services).

## What's here

| Class | Role |
|---|---|
| `JwtCodec` | jose4j wrappers for the verification shapes the repo needs: unverified claim/header inspection; verification against an inline JWKS or a resolved key list (`iss`/`sub`/`exp` required, 60 s skew, audience not checked); Client Attestation PoP verification against a `cnf` key (`jti` + `iat` required, algorithms constrained); `typ` enforcement that tolerates the `application/` prefix |
| `Jwks` | JWK-as-map helpers: RFC 7638 thumbprints, `assertSameKey` (bind a presented key to a `cnf`), `assertPublicOnly` (rejects `oct` and any private member — `d`, `p`, `q`, `dp`, `dq`, `qi`, `k`), `publicKey` |
| `JwsSigner` | The signing seam: `alg`, `kid`, public JWK, and raw JWS signature bytes over a signing input (fixed-width `r‖s` for ECDSA, per RFC 7515 §3.4). One interface for an in-process key and a vault key |
| `LocalJwkSigner` | `JwsSigner` over an inline private JWK — EC P-256/384/521 → ES256/384/512, RSA RS256/384/512. Dev/demo: the private key lives in the JVM |
| `OpenBaoTransitSigner` | `JwsSigner` over an OpenBao/Vault transit key (`ecdsa-p256/384/521`). Signs with `marshaling_algorithm=jws`; pins the key version read at construction so a concurrent rotation cannot make the emitted `kid` lie; fails closed (`IllegalStateException`) when the vault is unreachable. JDK `HttpClient`, no client library |
| `CompactJws` | Assembles `BASE64URL(header).BASE64URL(payload).BASE64URL(signature)` over a `JwsSigner`. Header carries `alg`, `typ`, `kid` — keys are referenced by id, never embedded, so a verifier resolves them through a trust path |
| `SigningKeyProvider` | RSA key pair + `kid` SPI that `FederationService` signs entity statements with; the host (PF) implements it |
| `SdJwt` (+ `SdJwtException`) | SD-JWT split, digest and reconstruction (`_sd` object properties, `{"...": digest}` array elements) plus disclosure builders. Kept as a library primitive; the AS-side verifier in `client-attestation` no longer accepts SD-JWT presentations |
| `Claims` | Null-safe accessors over `JwtClaims` and nested maps — empty map instead of `null` |
| `HttpGetClient` / `JdkHttpGetClient` | Minimal GET seam for fetching federation artefacts. Every fetch is screened by `OutboundUrlPolicy` first, then subject to 8 s connect / 15 s request timeouts and forced HTTP/1.1, so a stalled remote entity fails fast on the caller's thread instead of outliving the client's own timeout. Response bodies are read through the policy's byte cap rather than buffered whole. The `ignoreSslErrors` constructor is trust-all — a dev trust controller only |
| `OutboundUrlPolicy` | What the process is willing to fetch, applied before every outbound request: HTTPS only (`OIDF_FETCH_ALLOW_HTTP` opts into plaintext), no credentials in the URL, and no address that resolves to a private/link-local/loopback/CGN/IETF-reserved range unless the host is named in `OIDF_FETCH_HOST_ALLOWLIST` or `OIDF_FETCH_ALLOW_PRIVATE_NETWORKS=true`. `trusting(...)` exempts specific operator-configured origin+path-prefix endpoints (a trust controller, a SPIRE agent) from the scheme/address rules without opening the exemption to other ports or paths on the same host. Body size capped at `OIDF_FETCH_MAX_BODY_BYTES` (default 256 KiB). Exists because a client-supplied `trust_chain`'s `authority_hints` are attacker-controlled URLs this process fetches |

## Configuration

`OutboundUrlPolicy.fromEnvironment()` reads `OIDF_FETCH_ALLOW_HTTP`, `OIDF_FETCH_ALLOW_PRIVATE_NETWORKS`,
`OIDF_FETCH_HOST_ALLOWLIST` and `OIDF_FETCH_MAX_BODY_BYTES` directly — `JdkHttpGetClient`'s single-arg
constructor builds one from it. Nothing else here reads the environment: vault address, token and key
name are constructor arguments to `OpenBaoTransitSigner`; the callers do that env resolution
(`RegistryHostedEntitySigner.fromEnvironment()` in `openid-federation`,
`AttesterSigningKey.fromEnvironment()` in `servlets/attestation-issuer`).

## Build

```sh
mvn -pl libs/oidf-jose -am package     # or `mvn package` at the repo root; tests run with the build
```

Shared dependency versions come from the repo BOM (`bom/pom.xml`, imported with `scope=import`; there
is no parent pom). Consumers, by pom: `client-attestation`, `openid-federation`, `device-instance`,
`servlets/pf-integration`, `servlets/attestation-issuer`, `servlets/ssf`, `services/device-enrolment`,
`services/demo-rs`, `services/harness`. Ships into PingFederate both ways: `build/pingfederate/stage-modules.sh`
stages the jar into `build/pingfederate/modules/` for the pf-runtime.war merge, and `servlets/oidf-war`
bundles it into `oidf.war`'s `WEB-INF/lib`.
