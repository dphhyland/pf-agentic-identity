# pf-integration

> **Part of the [pf-agentic-identity](https://github.com/dphhyland/pf-agentic-identity) monorepo** — build from the repo root with `mvn package`. Formerly the standalone repo [`dphhyland/pf-integration`](https://github.com/dphhyland/pf-integration) — still live for existing consumers, **backports only**. Absorbed with history 2026-07-21; see [docs/PROVENANCE.md](https://github.com/dphhyland/pf-agentic-identity/blob/main/docs/PROVENANCE.md).


The PingFederate integration layer that wires [`client-attestation`](https://github.com/dphhyland/client-attestation)
and [`openid-federation`](https://github.com/dphhyland/openid-federation) into a running PingFederate, and
is the PingFederate glue (federation entity servlet, §12 registration, OGNL hooks). The deployable `oidf.war` is assembled by the sibling `oidf-war` module
(scope `provided`).

## What's here

- **`ClientAttestationUtils` / `OIDFederationUtils`** — OGNL issuance-criteria hooks PF invokes at the
  token endpoint: authenticate a client by attestation, and authorize a federation client entity
  (`authorizeClientEntity` — membership + policy + status + requested scope, via the trust controller).
- **`FederationAttesterKeyResolver`** — bridges attester trust to OpenID Federation, so an attester's keys
  are trusted only when its trust chain resolves to the anchor.
- **Explicit registration** — `OpenIdRegistrationServlet` validates a presented entity statement / trust
  chain and provisions a real PF client through `PfMgmtClientStore`.
- **`OpenIdFederationServlet` + `PfJwksSigningKeyProvider`** — the federation entity endpoints, signed with
  PF's own JWKS key.

## Build

```bash
mvn -o clean package     # offline; requires client-attestation + openid-federation + oidf-jose 0.1.0
                         # and the PingFederate SDK (pf-protocolengine) in ~/.m2
```

The deployable war is built by `oidf-war` (which depends on this module + `attestation-issuer`).
jars. Deploy it via PF's drop-in deployer; the `oidf` filename maps to the `/oidf` context path.

## Note

Because it compiles against the PingFederate SDK (a `provided` dependency not published to public Maven),
this module builds only where that SDK is available in your local `~/.m2`.
