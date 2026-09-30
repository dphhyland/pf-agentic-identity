# The vectors program

`run.sh` prints the values the enrolment service computes for a fixed instance key, challenge and build, with
the service's own classes: `Jwks.thumbprint` for the RFC 7638 thumbprints and, through reflection,
`EnrolmentService.clientDataHash` and `EnrolmentService.enrolmentNonce`. It also reads the real App Attest objects
captured on macOS 27.2 (`libs/app-attest/src/test/resources/fixtures`) with the server's CBOR reader and
`AppAttestVerifier`'s nonce extractor, so the kit can check its commitments against what a real device signed.
`VectorTests` in [AgentIdentityKit](../../AgentIdentityKit/README.md) pins every line it prints, and
[docs/device/ios-client-contract.md](../../../../docs/device/ios-client-contract.md) tabulates them.

```sh
clients/ios/tools/vectors/run.sh
```

It compiles `services/device-enrolment` and its libraries offline (`mvn -o ... compile`, from `~/.m2`, nothing
installed), so run it from a checkout whose dependencies have been fetched once. It is not in the reactor and no
workflow runs it: when the server's derivations change, run it again and move the Swift constants, and the
contract's table, with the output. Last run 2026-09-27 at `ab74038`; its output is the contract's table.
