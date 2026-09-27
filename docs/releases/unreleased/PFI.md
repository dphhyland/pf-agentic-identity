# PfInternals: one facade over the PingFederate internals the repository calls

## Changelog

- Plan item F-1, its platform-pf part: `libs/platform-pf` gains `platform.pf.internals.PfInternals`, the one class
  that calls PingFederate's internal services - the issuer lookup, the client manager, the token endpoint base URL
  and the discovery document handlers - and `ClientManager.isBackendDatabase()`, which C-1 will read. Every caller
  in pf-integration and attestation-issuer goes through it, and a test keeps any other production class from
  naming those internals again. platform-pf's README lists every PingFederate class and member the reactor links,
  by kind. New in the register: F-0215.

## Before you deploy

None.

## Notes

Nothing to change: no setting, endpoint, log line or deployed jar is new or different. Each caller makes the same
PingFederate call as before, through one more method, at the same moment; `platform-pf` is already deployed beside
`pf-integration` (F1), in the war and on the engine's classpath where the OGNL criterion that resolves the issuer
runs.

How it was verified, on 2026-09-28. `ClientManager.isBackendDatabase()` was read with javap on the pinned 13.1.3
image's `pf-protocolengine.jar`. `PfInternalsTest` checks each member's one call against PingFederate's replaced
statics, except the issuer lookup, whose final class cannot be replaced in a test. `tools/pf-linkcheck.py` against
13.1.3.0's jars reports nothing unresolved, and the reactor links the same PingFederate members as before the
change, from platform-pf where the callers named them, plus `ClientManager.isBackendDatabase()`.

Residual risk. servlets/ssf's `PfIdTokenVerifier` still resolves the issuer directly, outside this package's scope
([F-0215](../../findings/F-0215.yaml)).
