# AgentIdentityKit

The device side of the enrolment protocol that [services/device-enrolment](../../../services/device-enrolment/README.md)
serves, as a Swift package for iOS 17 and macOS 14 (plan item X-I01a; the full protocol is X-I01b). What it
sends, request by request, and why, is [docs/device/ios-client-contract.md](../../../docs/device/ios-client-contract.md);
the code follows the contract and the contract cites the Java. No dependencies: CryptoKit, DeviceCheck, Security,
LocalAuthentication and AuthenticationServices are the platform's.

## What is here

The protocol layer, `Sources/AgentIdentityKit/Protocol`, is pure and runs under test:

- **`DeviceAgent`** - the state machine: `enrol()`, `remint()`, `currentAttestation()`,
  `refreshUserVerification()`, `forget()`. A re-mint recovers from `user_verification_required` (the owner signs
  in again), a lost App Attest counter race and a spent challenge, each once, with new values every time
  (`RemintRecovery`); concurrent callers share one ceremony.
- **`EnrolmentClient`** and **`Messages`** - the four requests under the server's field names, and the refusal
  shape (`ServerRefusal`, `ServerCode`).
- **`Commitments`** - the attestation's `clientDataHash`, the assertion's, and the enrolment nonce.
- **`KeyProof`**, **`PublicJWK`**, **`ES256`** - the instance-key proof over the exact JWS Signing Input, the
  four-member JWK and its RFC 7638 thumbprint, and DER to R || S.
- **`OpenIDConnect`** - the PingOne request with PKCE and `max_age=0`, the callback, the token request, and the
  two checks the kit makes on an ID token (its nonce, and `auth_time`).

The platform, `Sources/AgentIdentityKit/Platform`, is behind four protocols:

| Protocol | Real implementation | Under test |
|---|---|---|
| `AttestationProvider` | `AppAttestProvider`, `DCAppAttestService` | a fake; `isSupported` is false on a simulator and a runner |
| `InstanceKey` | `SecureEnclaveInstanceKey`, `SecKey` with `kSecAttrTokenIDSecureEnclave` | a CryptoKit software key |
| `Authenticator` | `PingOneAuthenticator`, `ASWebAuthenticationSession` | a fake that issues unsigned tokens |
| `DeviceTokenProvider` | `UnavailableDeviceTokenProvider`, which throws | - |

The three real implementations compile for iOS and macOS and run only in an app on a device; the
[sample app](../SampleApp/README.md) is where they run. The Entra device token waits for the `deviceid` spike
([U-0064](../../../docs/findings/U-0064.yaml)) and X-A17, and MSAL is not declared
([U-0065](../../../docs/findings/U-0065.yaml)).

## Using it

```swift
let key = try SecureEnclaveInstanceKey.create(tag: "com.example.app.instance-key", gate: .userPresence)
let agent = DeviceAgent(
    client: EnrolmentClient(baseURL: URL(string: "https://enrolment.example.com")!),
    audience: "https://enrolment.example.com",          // the service's ENROLMENT_ISSUER
    instanceKey: key, appAttest: AppAttestProvider(),
    authenticator: PingOneAuthenticator(configuration: .init(
        issuer: URL(string: "https://auth.pingone.com/<environment>/as")!, clientID: "<client id>",
        redirectURI: URL(string: "com.example.app:/callback")!)),
    device: .current(agentBuild: "app/1.0"))
let enrolment = try await agent.enrol()                // keep it: it is how the next launch resumes
let attestation = try await agent.currentAttestation() // re-minted within a minute of expiry
```

Keep the `Enrolment` between launches and pass it back as `state: .enrolled(...)`. After `unknown_instance` or
`instance_not_active`, `forget()`, delete the key and enrol again with a new one: the key's thumbprint is the
attestation's `cnf`, so a key reused across instances would link them. App Attest keys do not survive a
reinstall, a device migration or a restore from backup (Apple, "Establishing your app's integrity", read
2026-09-27), so after any of those the enrolment is spent too.

## Build and test

```sh
swift build --package-path clients/ios/AgentIdentityKit
swift test --package-path clients/ios/AgentIdentityKit
```

66 tests, one of them skipped: the protocol against fakes; the vectors the server's own classes print
([tools/vectors](../tools/vectors/README.md)); the real macOS 27.2 App Attest objects in `libs/app-attest`, which
the kit's commitments reproduce; RFC 7515's and RFC 7636's worked examples. The skipped one, `InteropTests`, runs
the kit against the service's own Java over HTTP when [tools/interop](../tools/interop/README.md) starts it; it
passed on 2026-09-27. [.github/workflows/ios.yml](../../../.github/workflows/ios.yml) runs build and test on
macOS for every change under `clients/ios`.
