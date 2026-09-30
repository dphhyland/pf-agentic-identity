# The interop run

`run.sh` drives the Swift kit against the enrolment service's own Java over HTTP. `Interop.java` starts
`EnrolmentHttpServer` on a free port with the classes the service's `Main` wires - `EnrolmentService`,
`AppAttestVerifier`, `PingOneIdTokenVerifier`, `DeviceAttestationMinter`, the in-memory registry, challenge store
and replay cache, as `REGISTRY=memory` and `REQUIRE_COMPLIANT_DEVICE=false` would - and beside it an oracle on the
loopback address that stands in for the two parties no test can reach:

- **Apple.** `generateKey`, `attestKey` and `generateAssertion`, minted in the shapes `libs/app-attest`'s
  `AppAttestFixtures` mints (the assertion's authenticator data in the macOS 27.2 shape), under a root the process
  makes and the verifier is constructed to trust. The service itself has no setting that trusts another root.
- **PingOne.** RS256 ID tokens with `auth_time`, `acr` and the nonce the kit asked for, signed by a key the
  verifier's JWKS source serves.

The oracle also moves two things in the registry: it ages an instance's user verification, and it records a
higher App Attest counter for the device, as a renewal that won a race would. The oracle listens on the loopback
address only; the service listens on every interface, as `EnrolmentHttpServer` does, for the seconds the run
takes, and trusts no root but the one this process made.

```sh
clients/ios/tools/interop/run.sh
```

`InteropTests` then enrols, re-mints, recovers from `user_verification_required` through `POST /user-verification`,
recovers from a lost counter race, and checks that another key cannot re-mint the instance. It skips itself
unless the run sets `AGENTIDENTITYKIT_INTEROP_SERVICE`, `AGENTIDENTITYKIT_INTEROP_ORACLE` and
`AGENTIDENTITYKIT_INTEROP_AUDIENCE`, which is why CI, which does not build the Java reactor on its macOS runner,
reports it as skipped. Passed on 2026-09-27 against the service at `ab74038` (macOS 27.2, Swift 6.4, Java 20).

What it cannot show: that Apple's real objects from an iPhone parse
([U-0063](../../../../docs/findings/U-0063.yaml)), or that a real PingOne tenant issues the token the verifier
wants (the contract's "What is not yet known").
