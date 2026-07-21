# pf-integration

The PingFederate integration layer that wires [`client-attestation`](https://github.com/dphhyland/client-attestation)
and [`openid-federation`](https://github.com/dphhyland/openid-federation) into a running PingFederate, and
assembles the deployable **`oidf.war`**. This is the only module that depends on the PingFederate SDK
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

This produces `target/oidf.war`, bundling the `client-attestation`, `openid-federation`, and `oidf-jose`
jars. Deploy it via PF's drop-in deployer; the `oidf` filename maps to the `/oidf` context path.

## Note

Because it compiles against the PingFederate SDK (a `provided` dependency not published to public Maven),
this module builds only where that SDK is available in your local `~/.m2`.
