# The iOS client

The device side of the enrolment protocol that [services/device-enrolment](../../services/device-enrolment/README.md)
serves, as a Swift package and a sample app (plan item X-I01a; the full protocol is X-I01b). What the client does,
request by request, is written down in [docs/device/ios-client-contract.md](../../docs/device/ios-client-contract.md);
the code follows the contract, and the contract cites the Java.

| Path | What it is |
|---|---|
| [AgentIdentityKit](AgentIdentityKit/README.md) | The Swift package: a pure protocol layer (the request and reply types, the enrol, re-mint and user-verification state machine, the commitments, the key proof) behind four platform protocols, and the real implementations of three of them (App Attest, the Secure Enclave, PingOne). `swift build` and `swift test` on a Mac |
| [SampleApp](SampleApp/README.md) | A minimal SwiftUI app that drives the kit against a base URL you give it, and captures App Attest vectors. Needs an Apple Developer team, an App ID with the App Attest capability, a physical iPhone and a PingOne application; its README says what to supply |
| [tools/vectors](tools/vectors/README.md) | A Java program that prints the protocol's values with the server's own classes, for the kit's tests to pin |
| [tools/interop](tools/interop/README.md) | The service's own classes over HTTP beside an oracle for Apple and PingOne, and the kit driven against them |

The macOS job in [.github/workflows/ios.yml](../../.github/workflows/ios.yml) builds and tests the package and
builds the sample app for the simulator, which needs no signing. App Attest, the Secure Enclave and a PingOne
sign-in exist on no runner, so the tests use fakes for them, and a physical iPhone is the open item
([U-0063](../../docs/findings/U-0063.yaml)).

The client is a skeleton until X-I01b: it speaks today's protocol, which X-A05 to X-A11 will change (the nonce
binding, key proofs with required claims, assertions on every renewal, `/v1`). Nothing here is staged into
PingFederate or the enrolment service's image; the app that embeds the kit is its owner's to build and ship.
