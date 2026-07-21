# oidf-jose

The shared **JOSE/JWT + SD-JWT SDK** — the crypto foundation that the
[`client-attestation`](https://github.com/dphhyland/client-attestation) and
[`openid-federation`](https://github.com/dphhyland/openid-federation) libraries build on.

No PingFederate, servlet, federation, or attestation dependencies — just `jose4j` + `jackson`.

## What's in it

| Class | Purpose |
|---|---|
| `JwtCodec` | Parse/verify JWTs against inline JWKS or explicit keys; PoP verification; header helpers |
| `Jwks` | Build `JsonWebKey` from a map; RFC 7638 thumbprints; same-key / public-only assertions |
| `SdJwt` (+ `SdJwtException`) | SD-JWT disclosure encoding/decoding (`_sd` digests, array placeholders, reconstruction) |
| `Claims` | Null-safe nested-map/claim accessors over `JwtClaims` |
| `HttpGetClient` / `JdkHttpGetClient` | Minimal GET abstraction (trust-all option for dev) |
| `SigningKeyProvider` | SPI for a signing key + kid (implemented by hosts, e.g. PF) |

## Build

```sh
mvn clean install       # 11 tests, produces com.pingidentity.ps.oidf:oidf-jose
```

## Publish

Versioned artifact consumed by the downstream repos. Defaults to GitHub Packages —
`mvn deploy` needs a `settings.xml` server `github` with a `write:packages` token.
(The `groupId` `com.pingidentity.ps.oidf` matches the Java packages; adjust for a different registry namespace.)
