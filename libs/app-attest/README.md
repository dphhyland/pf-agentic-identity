# app-attest

**Apple App Attest verification**: the one-time attestation object from `DCAppAttestService.attestKey`
and the per-request assertion from `generateAssertion`, validated to Apple's App Attestation Root CA.
Package `com.pingidentity.ps.oidf.appattest`. Pure verification — no HTTP, no servlet, no PingFederate;
depends on `jackson-dataformat-cbor` (the attestation's wire format), `jackson-databind`, `jose4j` (JWK
shaping of the attested key) and `commons-logging`. Consumed by `services/device-enrolment`, where it
gates enrolment before an instance is registered in `device-instance`.

App Attest attests the **app and the device, never the user**, and the key it attests is its own.
Binding an independently generated Secure Enclave key is the caller's job — commit that key's
thumbprint into `clientDataHash` — and the binding is only as strong as that commitment. See
[docs/claim-dictionary.md](../../docs/claim-dictionary.md).

## What's here

- **`AppAttestVerifier`** — stateless, thread-safe; construct one per configuration.
  `verifyAttestation(attestationObject, clientDataHash, expectedKeyId)` runs Apple's documented checks
  in order: `fmt == apple-appattest`; the `x5c` chain validates to the configured root; the credCert
  nonce extension (OID `1.2.840.113635.100.8.2`) equals `SHA-256(authenticatorData ‖ clientDataHash)`;
  `SHA-256(attested public key)` equals the credential id (and the key id the client claimed, if given);
  `rpIdHash == SHA-256("<teamID>.<bundleID>")`; the `aaguid` names an accepted environment; the sign
  counter is zero. `verifyAssertion(assertionObject, clientDataHash, attestedKey, lastSignCount)` checks
  `rpIdHash`, the ECDSA signature over `authenticatorData ‖ clientDataHash`, and that the counter
  strictly advanced — returning the new counter for the caller to persist.
- **`AppAttestConfig`** — the policy: `production(teamId, bundleId)` accepts production attestations
  only; `allowingDevelopment(...)` opts development in, deliberately visible in configuration;
  `withTrustRoot(...)` for tests. The default root is the bundled
  `apple/Apple_App_Attestation_Root_CA.pem`, pinned rather than taken from the JVM trust store: the
  chain must end at Apple's App Attest root specifically, not at any CA the platform happens to trust.
- **`AppAttestAttestation`** — the verified outcome: key id (SHA-256 of the key — persist this, per
  Apple, not the attestation object), the attested `ECPublicKey`, environment, counter, receipt.
- **`AppAttestEnvironment`** — `PRODUCTION` (`appattest`) / `DEVELOPMENT` (`appattestdevelop`), read
  from the 16-byte `aaguid`. A security control, not a label.
- **`AuthenticatorData`** — parser for the packed (not CBOR) authenticator-data struct: `rpIdHash`,
  flags, `signCount`, and for attestations the `aaguid` and credential id. Stops there — it does not
  decode the trailing CBOR `credentialPublicKey`; the verifier gets the attested key from the credCert
  (`x5c[0]`'s public key) instead, since that is what the nonce and the rest of the chain vouch for.
- **`AppAttestException`** — every failure carries a stable `reason`: `malformed_attestation`,
  `unsupported_format`, `untrusted_certificate_chain`, `nonce_mismatch`, `key_id_mismatch`,
  `app_id_mismatch`, `environment_not_accepted`, `bad_counter`, `bad_signature`,
  `counter_not_advanced`. Branch audit events on it; treat the codes as contract.

## Configuration

Nothing is read from the environment. Team id, bundle id and the accepted environments are constructor
inputs — `services/device-enrolment`'s `Main` chooses `production` or `allowingDevelopment`.

## Security posture

Development attestations are refused unless explicitly allowed. The trust root is pinned. Digest
comparisons are constant-time (`MessageDigest.isEqual`). Jackson's lenient CBOR reader is guarded —
anything that is not a CBOR map at the top level is `malformed_attestation`, not a decode of whatever
scalar the bytes happen to form.

## Build and test

```sh
mvn -pl libs/app-attest -am package     # or `mvn package` at the repo root; tests run with the build
```

Tests use **`AppAttestFixtures`** (test scope), which mints a synthetic Apple-shaped chain — root,
intermediate, leaf credCert carrying the nonce extension — with BouncyCastle (test scope only, never on
the runtime classpath), because the JDK has no public API for issuing a certificate with a custom
extension. The fixtures are published as a `test-jar` and consumed by `services/device-enrolment`'s
tests. What a synthetic chain cannot prove is that Apple's real objects parse; only a physical device
closes that gap. Versions come from `bom/pom.xml`. Not staged into PingFederate — verification runs in
the enrolment service, not the AS.
