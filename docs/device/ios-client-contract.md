# The iOS client contract

The device side of the enrolment protocol, as `services/device-enrolment` implements it: every request the
client makes, in order, with its fields, where each value comes from on the device, the errors and what the
client does on each, and what is not yet known. Written from the Java at commit `ab74038` on 2026-09-27 and cited
by file and symbol. The Swift package that implements it is
[clients/ios/AgentIdentityKit](../../clients/ios/AgentIdentityKit/README.md) (plan item X-I01a; the full protocol
is X-I01b), and [the interop run](#the-interop-run) drove it against the service's own classes over HTTP on the
same day. Where this page and the Java disagree, the Java is right and this page is stale.

The service's own account of the ceremony, and why three primitives are needed and none stands in for another,
is in [services/device-enrolment/README.md](../../services/device-enrolment/README.md). This page does not repeat
it.

## The routes

`EnrolmentHttpServer` registers its contexts in its constructor. There is no version prefix: the programme plan
writes "against `/v1`", which arrives with X-A11, and at `ab74038` the service has no such path. The client posts
to the routes below under whatever base URL it is given, so a prefix, when it comes, is the base URL's.

| Route | What it does | Where |
|---|---|---|
| `POST /enrol/challenge` | a one-time challenge | `EnrolmentService.issueChallenge` |
| `POST /enrol` | the ceremony; the first attestation | `EnrolmentService.enrol` |
| `POST /attestation` | re-mint, the hot path; the time-box is enforced here | `EnrolmentService.reissue` |
| `POST /user-verification` | refresh the time-box from a fresh sign-in | `EnrolmentService.refreshUserVerification` |

The client never calls `/compliance` (plan item M-2 removes it), `/.well-known/jwks.json` (PingFederate's) or
`/health`. The JDK server's contexts do not check the method; the client always posts, with a JSON body and
`Content-Type: application/json`, and a body that is not JSON is `invalid_request`
(`EnrolmentHttpServer.readJson`). Every reply is JSON with `Cache-Control: no-store`. A refusal is
`{"error": "<code>", "error_description": "<prose>"}` with the status `EnrolmentException` gives the code, and
anything the service did not expect is `500` `server_error` "unexpected failure" (`EnrolmentHttpServer.route`).
`error` is the contract; the prose is for a log, with one exception named under
[the counter race](#the-counter-race-and-the-retry). The prose can carry registry detail, the device id among it
([F-0085](../findings/F-0085.yaml)).

Binary values travel as base64url. The service decodes them with Java's `Base64.getUrlDecoder`, which accepts
padding and refuses `+` and `/` (`EnrolmentHttpServer.binary`), and writes them without padding; the client
sends them without padding too.

## Where each value comes from on the device

### The instance key

A P-256 key in the Secure Enclave, made once per enrolment and never outside it. The kit makes it with the
Security framework, `SecKeyCreateRandomKey` with `kSecAttrTokenIDSecureEnclave`, as a permanent keychain item
under an application tag the app names, with an access control the app chooses: key usage alone, user presence,
or the current biometry set (`SecureEnclaveInstanceKey`).

Its public key travels as a JWK with four members, `{"kty": "EC", "crv": "P-256", "x": "...", "y": "..."}`, `x`
and `y` the 32-byte big-endian coordinates as base64url, taken from `SecKeyCopyExternalRepresentation`, which for
an EC public key is the X9.62 uncompressed point `0x04 || X || Y`. Its RFC 7638 thumbprint, `jkt`, is base64url of
the SHA-256 over exactly `{"crv":"P-256","kty":"EC","x":"…","y":"…"}`: RFC 7638 §3.2 names the members for an EC
key "in lexicographic order" as `crv`, `kty`, `x`, `y`. That is what the server computes. `Jwks.thumbprint`
(libs/oidf-jose) calls jose4j's `calculateBase64urlEncodedThumbprint`, and jose4j 0.9.6's
`EllipticCurveJsonWebKey.produceThumbprintHashInput` re-encodes `x` and `y` from the parsed point to the curve's
32 bytes before hashing (read in the sources jar), so a coordinate whose first byte is zero goes out padded to 32
bytes, as the kit sends it. A `kid` member does not change the thumbprint (the vectors program prints
`thumbprint_ignores_kid=true`) and the kit sends none, because `DeviceAttestationMinter.mint` echoes the object
into every attestation's `cnf.jwk`.

The thumbprint is the instance's identity in three places: the App Attest commitment, the nonce, and the
registry's `cnf_jkt`, which every later key proof is matched against (`EnclaveKeyProofValidator.validate`).

Signing is ES256. `SecKeyCreateSignature` with `.ecdsaSignatureMessageX962SHA256` hashes the input with SHA-256
and returns the DER `SEQUENCE { INTEGER r, INTEGER s }`. A JWS wants R and S "in big-endian order, with each array
being be 32 octets long", concatenated, and "The JWS Signature value MUST be a 64-octet sequence" (RFC 7518 §3.4),
which is what jose4j verifies; the kit converts (`ES256.rawSignature(fromDER:)`) and refuses to send anything
that is not 64 bytes.

### The App Attest key

A second key, Apple's, made by `DCAppAttestService.shared.generateKey()` and never used to sign anything the client
composes: `attestKey(_:clientDataHash:)` gives the one-time attestation object (CBOR) and
`generateAssertion(_:clientDataHash:)` a per-request assertion (CBOR), each over a 32-byte `clientDataHash` the
client computes. The kit calls each through `AttestationProvider`; `AppAttestProvider` is the real one.

`generateKey()` returns a string of which Apple's page says only "An identifier that you use to refer to the key."
and nothing about its encoding (developer.apple.com, `generateKey(completionHandler:)`, read 2026-09-27). On macOS
27.2 the helper that captured the fixtures in `libs/app-attest/src/test/resources/fixtures` decoded it as standard
base64, and the server's check that it is SHA-256 of the attested key's X9.62 point passed
(`MacOsAttestationTest`), so the kit decodes standard base64 first, base64url second, and refuses anything that is
not 32 bytes. The service wants the 32 bytes as base64url, so the kit re-encodes. Whether an iPhone's identifier
decodes the same way waits for a real device ([U-0063](../findings/U-0063.yaml)).

Apple's rules, and what the kit does with each (developer.apple.com, "Establishing your app's integrity" and the
`DCAppAttestService` pages, read 2026-09-27):

- "Not all devices can use the App Attest service, so it’s important to have your app run a compatibility check
  before accessing the service." The kit reads `isSupported` first. Apple then says to bypass the service; the kit
  refuses to enrol instead, because the service requires the attestation.
- "Create a unique key for each user account on a device." Each enrolment makes its own key.
- Of `clientDataHash`: "Should be at least 16 bytes in length." The kit's is a SHA-256, 32 bytes, over a challenge
  of 32 random bytes.
- On `serverUnavailable`: "retry attestation again using the same key and client data hash later to avoid
  unnecessarily generating new keys". `AppAttestProvider` retries once, two seconds later, inside the challenge's
  life.
- "For any other error, discard the key identifier and create a new key when you want to try again." and "If your
  server fails to verify the attestation object, discard the key identifier." A failed enrolment keeps nothing;
  the next `enrol()` makes a new key.
- "be sure to persistently store the key identifier — not the attestation object — in your app for future use in signing server requests". The kit's `Enrolment` holds the identifier and never the object.
- "The keys that you generate remain valid through regular app updates, but don’t survive app reinstallation, device migration, or restoration of a device from a backup." After any of those, the enrolment is spent and the app enrols again.

The environment is the entitlement's: `com.apple.developer.devicecheck.appattest-environment` is `development` or
`production`, and "After distributing your app through TestFlight, the App Store, or the Apple Developer Enterprise
Program, your app ignores the entitlement you set and uses the production environment." (Apple, "App Attest
Environment", read 2026-09-27). The service accepts only production attestations unless `APPLE_ALLOW_DEVELOPMENT`
is `true` (`Main`, `AppAttestConfig.production` and `allowingDevelopment`).

### The owner's authentication

A PingOne ID token, obtained in the app with `ASWebAuthenticationSession` through the authorization code flow with
PKCE `S256` (the application [the service README](../../services/device-enrolment/README.md#pingone) names is
registered `S256_REQUIRED`), `scope=openid`, a `nonce`, a `state`, and `max_age=0`; with `acr_values` when the app
is told a sign-on policy. The kit's `Authenticator` protocol returns the token as PingOne issued it;
`PingOneAuthenticator` is the real one, and its pure parts (the request URL, the callback, the token request, the
claims) are `OpenIDConnect.swift`.

`max_age=0` is deliberate. `PingOneIdTokenVerifier.verifyToken` requires `auth_time` and the time-box is measured
from it, and OpenID Connect Core 1.0 (incorporating errata set 2) §3.1.2.1 says of `max_age`: "When max_age is
used, the ID Token returned MUST include an auth_time Claim Value. Note that max_age=0 is equivalent to
prompt=login." The alternative, `auth_time` as an essential claim, is closed: the environment's discovery document
says `claims_parameter_supported: false`, and also lists `auth_time` and `acr` under `claims_supported`, `RS256` as
the only ID token algorithm, `plain` and `S256` for PKCE, and no `acr_values_supported` (fetched 2026-09-27). A
stale single sign-on session would refresh nothing anyway: the server records the token's `auth_time`, not the
time it arrived.

What the server checks, in `PingOneIdTokenVerifier.verifyToken`, in order: a compact JWS with `alg` `RS256`; a
`kid` naming a key in the environment's JWKS (`<issuer>/jwks`); the signature; `iss` equal to `PINGONE_ISSUER`;
`aud` containing `PINGONE_CLIENT_ID`; `exp` not passed (60 s skew); `auth_time` present and not in the future;
`nonce` equal to the expected one only when the caller gave one, and on the iOS path nobody does
([the nonce](#the-nonce)); `sub` present; `acr` mapped to an assurance level through `PINGONE_ACR_AAL2`, where
anything unmapped is AAL1, which `enrol` and `refreshUserVerification` refuse as `insufficient_assurance`
(`EnrolmentService.REQUIRED_ASSURANCE` is AAL2). The token carries no `amr`, so `acr` is the only assurance
signal there is.

The kit checks three things itself before a token goes anywhere, so a misconfigured tenant fails in the app with a
message that names the problem: the discovery document's `issuer` is the one it was fetched for; the token's
`nonce` is the one sent, because §3.1.3.7 says "If a nonce value was sent in the Authentication Request, a nonce
Claim MUST be present and its value checked to verify that it is the same value as the one that was sent in the
Authentication Request."; and `auth_time` is present. It does not verify the signature: the service is the
verifier of record, offline against the JWKS.

### The Entra device token

The programme's device-correlation design wants an Entra-signed access token carrying `deviceid`, obtained through
MSAL and the Microsoft Authenticator broker on an Intune-managed iPhone (the plan, "Workstream X", "Device
correlation"). At `ab74038` no request to the service carries such a token: `EnrolmentService.EnrolmentRequest`
has no field for it, and nothing reads one. The kit declares the seam, `DeviceTokenProvider`, and ships
`UnavailableDeviceTokenProvider`, which throws `notImplemented` and says why. MSAL is not a dependency of the
package: the SwiftPM cache on the machine this was written on holds no clone of it (2026-09-27), so an offline
resolution cannot succeed, and the package brief made that the condition ([U-0065](../findings/U-0065.yaml)).
Whether Entra emits `deviceid` at all is the spike only David can run ([U-0042](../findings/U-0042.yaml),
[U-0064](../findings/U-0064.yaml)); X-A17 adds the field once it has.

## The requests, in order

### 1. A challenge

`POST /enrol/challenge`. The handler never reads the body (`EnrolmentHttpServer.challenge`); the kit sends `{}`.

Reply: `{"challenge": "<43 characters>", "expires_in": 300}`. The challenge is 32 bytes from `SecureRandom` as
base64url without padding, valid for `AttestationChallengeService.DEFAULT_TTL_SECONDS` (300), and spent by the
first request that names it (`InMemoryAttestationChallengeService.issue` and `consume`; the store keeps at most
8192 and drops the oldest). The client treats it as an opaque string and never re-encodes it: it goes into the
commitment and the nonce exactly as received.

Everything below has to finish inside those 300 seconds, the owner's sign-in included. A challenge that ages out
is `invalid_challenge`.

### 2. The owner signs in

Not a request to the service. The kit computes the nonce from the challenge and the instance key's thumbprint
([below](#the-nonce)), runs `Authenticator.authenticate(nonce:)`, checks what comes back, and keeps the ID token
for step 4. It signs the owner in before it attests, so that a slow human does not leave a finished attestation
waiting; the attestation is a network round trip to Apple and no prompt.

### 3. The App Attest attestation

`generateKey()`, then `attestKey(keyID, clientDataHash:)` with the
[attestation commitment](#clientdatahash-for-the-attestation). The kit keeps Apple's key identifier with the
enrolment: every later assertion needs it, and there is no way to get it back.

### 4. Enrol

`POST /enrol`, read by `EnrolmentHttpServer.enrol` into `EnrolmentService.EnrolmentRequest`:

| Field | On the wire | From | The server |
|---|---|---|---|
| `appattest_object` | base64url of the CBOR from `attestKey` | step 3 | `AppAttestVerifier.verifyAttestation`, through `EnrolmentService.verifyEvidence` |
| `appattest_key_id` | base64url of the key identifier's 32 bytes | step 3, re-encoded | the `expectedKeyId` cross-check in `verifyAttestation` (its step 4); optional on the wire, always sent |
| `enclave_public_jwk` | the four-member JWK | the instance key | `EnrolmentService.thumbprint`, which becomes `cnf_jkt`; echoed into the attestation's `cnf.jwk` |
| `challenge` | the string from step 1, verbatim | step 1 | spent (`enrol` step 2) |
| `user_authentication` | the ID token, verbatim | step 2 | `PingOneIdTokenVerifier.verify`; AAL2 required |
| `platform` | `ios`, or `macos` on a Mac | the OS | recorded on the device row; on a Mac compared with the OS Apple wrote into the credential certificate (`AppAttestPlatform`) |
| `model` | e.g. `iPhone16,2` | `utsname.machine` | recorded; never in a token |
| `os_version` | e.g. `18.5` | `ProcessInfo` | recorded |
| `agent_build` | the app's build identifier | the app | the attestation's `agent_build` claim |

`instance_public_jwk` is accepted as another name for `enclave_public_jwk`; the kit uses the original. The
connector's fields (`federation_public_jwk`, `key_proofs`, `evidence`) are the Mac connector's and the kit sends
none: without `federation_public_jwk` the server takes the request as the iOS shape and requires `appattest_object`.

`EnrolmentService.enrol` checks in an order that matters to the client: the required fields and the JWK's
thumbprint; (1) the human, so a failed sign-in writes nothing and leaves the challenge unspent; (2) the challenge;
(3) key proofs, connector path only; (4) the App Attest evidence, by which time the challenge is spent; (5) the
registry rows, the mint, the owner's notification.

Reply: `{"instance_id": "<43 characters>", "attestation": "<compact JWS>", "expires_in": 900, "appattest_key_id":
"<base64url>"}`. `instance_id` is 256 random bits (`InstanceIdentifiers.newInstanceId`), the client's handle from
here on and the attestation's `agent_id` (and its `sub`, unless `OIDF_ATTESTATION_SUB=client_id` puts the client id
there); the client never learns a device id by design, bar [F-0085](../findings/F-0085.yaml). The attestation is
`typ` `oauth-client-attestation+jwt`, 15 minutes (`DeviceAttestationMinter.DEFAULT_LIFETIME`), `iss` the service's
`ENROLMENT_ISSUER`, `cnf.jwk` the instance key. `appattest_key_id` is the verified key identifier as the server
encodes it: the bytes the client sent.

### 5. Re-mint

`POST /attestation`, read by `EnrolmentHttpServer.attestation` into `EnrolmentService.ReissueRequest`. The kit
fetches a fresh challenge first (step 1 again) and names it in the proof.

| Field | On the wire | From | The server |
|---|---|---|---|
| `instance_id` | the string from step 4 | the enrolment | `findInstance`; must be `ACTIVE` |
| `key_proof` | a compact JWS, [below](#the-key-proof) | the instance key | `EnclaveKeyProofValidator.validate`; its `challenge` spent, its `jti` replay-checked |
| `app_attest_assertion` | base64url of the CBOR from `generateAssertion` over the [assertion commitment](#clientdatahash-for-an-assertion) | the App Attest key from step 3 | `EnrolmentService.verifyRenewalAssertion`; optional on the wire, always sent |

`EnrolmentService.reissue`, in order: the instance exists and can obtain tokens; the key proof verifies against the
instance's `cnf_jkt` and the service's audience; the proof's `challenge`, when it names one, is spent; the proof's
`jti` has not been seen for this instance in 300 s; the device is `COMPLIANT` when `REQUIRE_COMPLIANT_DEVICE` is
true (the default, and `UNKNOWN`, which every new device starts as, fails too); the owner's last verification is
younger than `UV_MAX_AGE_SECONDS` (default 300); when the device enrolled with App Attest and an assertion is
given, it verifies under the attested key with a counter above the one on record, and
`InstanceRegistry.recordAppAttestCounter` advances the counter; then the mint, whose `cnf.jwk` is the proof's `jwk`
header. The assertion is required only for a connector (`APPLE_REQUIRE_RENEWAL_ASSERTION`) and verified whenever
given; X-A08 makes it required on this path too, so the kit sends it on every re-mint.

Reply: `{"attestation": "<compact JWS>", "expires_in": 900}`.

Two consequences for a deployment, both stated because the sample app meets them. With the default
`REQUIRE_COMPLIANT_DEVICE=true` a newly enrolled iPhone cannot re-mint until a compliance signal reaches the
registry, and at `ab74038` nothing sends one on a real deployment ([F-0004](../findings/F-0004.yaml); X-A15 and
X-A17); a rig sets `REQUIRE_COMPLIANT_DEVICE=false`, as `EnrolmentHttpEndToEndTest` does. And the enrolment
records the owner's `auth_time` as the instance's last verification, so the first re-mint more than
`UV_MAX_AGE_SECONDS` after the sign-in needs step 6 first; the kit does that when the service asks.

### 6. Refresh user verification

`POST /user-verification`, read by `EnrolmentHttpServer.userVerification`:

| Field | On the wire | From | The server |
|---|---|---|---|
| `instance_id` | as above | the enrolment | `findInstance` |
| `user_authentication` | a fresh ID token, verbatim | step 2 again, with a random nonce | `PingOneIdTokenVerifier.verify` (no nonce check); AAL2; its `sub` must be the owner's |

`EnrolmentService.refreshUserVerification` records the token's `auth_time` as the instance's
`uv_last_verified_at`: nothing the device asserts about the human moves it, only a token PingOne signed. A token
whose `sub` is not the owner's is `user_authentication_failed`, so someone else's sign-in cannot extend an
instance. The route takes no key proof and no assertion at `ab74038`; X-A08 adds the assertion. Reply:
`{"status": "ok"}`.

## The commitments, byte for byte

### clientDataHash for the attestation

`EnrolmentService.clientDataHash(String, String)`:

```
clientDataHash = SHA-256( UTF-8( jkt + "|" + challenge ) )
```

`jkt` the instance key's thumbprint, `challenge` the string from step 1. The connector's three-segment form,
`clientDataHash(String, String, String)`, appends `"|" + build` and is not an iOS value. The server recomputes the
hash from the JWK and the challenge in the request and gives it to `AppAttestVerifier.verifyAttestation`, which
compares the credential certificate's nonce with `SHA-256(authenticatorData || clientDataHash)`. A JWK that is not
the one the app committed to therefore fails as `invalid_attestation`, with Apple's `nonce_mismatch` in the prose,
never as a bad key.

### clientDataHash for an assertion

`EnrolmentService.verifyRenewalAssertion`:

```
clientDataHash = SHA-256( UTF-8( key_proof ) )
```

over the compact serialisation of the key proof exactly as it is sent, all three segments and both dots. The
assertion therefore signs the proof it travels with, and a captured assertion cannot be paired with another
proof. `AppAttestVerifier.verifyAssertion` checks `rpIdHash` against `SHA-256("<teamID>.<bundleID>")`, the signature
over `SHA-256(authenticatorData || clientDataHash)` under the attested key, and that the counter rose.

### The nonce

`EnrolmentService.enrolmentNonce(String, String, String)`:

```
nonce = base64url( SHA-256( UTF-8( challenge + "|" + instanceJkt + "|" + federationJkt ) ) )
```

without padding. That is the only nonce the server computes, and it checks it on the connector path alone:
`EnrolmentService.enrol` passes no expected nonce for a request without `federation_public_jwk`, and
`PingOneIdTokenVerifier` skips the check then. An iOS enrolment's ID token is bound to neither its challenge nor its
key today ([F-0084](../findings/F-0084.yaml)); plan item X-A05 ("PingOne binding: nonce; single-use ID token;
`auth_time` maximum age and `azp`") closes that.

The kit derives its nonce with the same digest, separator and encoding over the two segments an iOS enrolment has,
`challenge + "|" + instanceJkt` (`Commitments.enrolmentNonce` without a federation thumbprint). That value is a
proposal for X-A05 to adopt or change, not something the server computes: it is pinned against SHA-256 in Java
over the same string, and the three-segment form against the server's own method, so the digest and the encoding
are proven and only the segments are open. The kit sends it on every enrolment regardless, and checks it in the
token it gets back. A refresh's nonce is 32 random bytes, checked by the kit alone.

### The key proof

A compact JWS (RFC 7515 §7.1). The header, as the kit writes it:

```
{"alg":"ES256","jwk":{"crv":"P-256","kty":"EC","x":"…","y":"…"},"typ":"oauth-attestation-instance-proof+jwt"}
```

The payload, keys sorted:

```
{"aud":"<ENROLMENT_ISSUER>","challenge":"<step 1>","exp":<iat+120>,"iat":<seconds>,"jti":"<UUID>"}
```

The bytes the enclave signs are the JWS Signing Input, `ASCII( BASE64URL(header) || "." || BASE64URL(payload) )`
(RFC 7515 §5.1), and the signature is R || S. Member order in either object is the kit's choice and nothing on the
server depends on it; the values are the contract.

`EnclaveKeyProofValidator.validate`, in order: the proof parses as a compact JWS; `typ`, when present, is exactly
`oauth-attestation-instance-proof+jwt` (`EnclaveKeyProofValidator.TYP`); a `jwk` header is present and an object;
`alg` is `ES256`, because "a Secure Enclave does P-256 and nothing else"; the `jwk` carries no private member
(`Jwks.assertPublicOnly`); its thumbprint equals the instance's `cnf_jkt`; the signature verifies under it; the
claims parse; `aud` contains the service's identifier, the `ENROLMENT_ISSUER` it was started with; `jti` is not
blank; `iat`, when present, is no more than 360 s old and no more than 60 s ahead of the server's clock; the
`challenge` is read and, when present, spent by `reissue`. `exp` is not read at `ab74038`; the kit sends it because
X-A06 ("`typ`/`iat`/`exp`/`jti`/`challenge` required") will read it, and a validator that ignores it loses
nothing.

### Vectors

Printed on 2026-09-27 by the program in [clients/ios/tools/vectors](../../clients/ios/tools/vectors/README.md) with
the server's own classes, compiled from this repository at `ab74038`: `Jwks.thumbprint` for the thumbprints,
`EnrolmentService.clientDataHash` and `enrolmentNonce` through reflection, and the real macOS 27.2 objects read with
the server's CBOR reader and `AppAttestVerifier`'s nonce extractor. The instance key is RFC 7515 Appendix A.3.1's
P-256 key and the federation key RFC 7517 Appendix A.1's first key. `VectorTests` pins every row.

| Value | Input | Result |
|---|---|---|
| instance `jkt` | RFC 7515 A.3.1 `x`, `y` | `oKIywvGUpTVTyxMQ3bwIIeQUudfr_CkLMjCE19ECD-U` |
| federation `jkt` | RFC 7517 A.1's first key | `cn-I_WNMClehiVp51i_0VpOENW1upEerA8sEam5hn-s` |
| the thumbprint with a `kid` added | as above | unchanged |
| challenge | fixed | `Kf8-TzQb1x0yJ3v2wE5tN7oP9aR4sU6dV8gH1jL0mZc` |
| `clientDataHash(jkt, challenge)` | the two above | `8fa9fc8a2ab60ed015e58b73a2281f3c1557aca1458ee1b13c3fdf9a8e9fe38c` |
| `clientDataHash(jkt, challenge, build)` | build `b4x-3Zq9vP1Ls8Kj7Hn6Md5Fc4Vb3Nx2Za1Qw0Er9Ty` | `a2fb0d3910887863c9f9d2fc7a0cbb4a82a6c1504bc8bf2d155cb7fac744b80e` |
| `enrolmentNonce(challenge, jkt, federationJkt)` | the three above | `WpH_t8uLcoVBEIrrFg3knPbZADPJUtxusB4E586FTj4` |
| the kit's iOS nonce, SHA-256 in Java over `challenge + "\|" + jkt`; not a server method | the two above | `DmMGWbB6TJpfTCoLrMXtcM7xaSsk_7SKy0iBkZLig6k` |
| `SHA-256(key_proof)` for an assertion | the made-up proof `eyJhbGciOiJFUzI1NiJ9.eyJhdWQiOiJodHRwczovL2Vucm9sIn0.c2ln` | `a10dcc630c8d8f271e0b7cc707f1e7971d6377af857859e2bb1eaaeaf1c412f4` |
| macOS 27.2 attestation: `SHA-256(authData \|\| clientDataHash(jkt, challenge))` | the fixture's `jkt` and `challenge` (`spike-challenge-001`) | the credential certificate's nonce, `28484b8f51a5e870e7e3695c67732fc0e8dcadb525cabeae652b6d751db928a8` |
| macOS 27.2 assertions: the signature over `SHA-256(authenticatorData \|\| SHA-256("renewal key proof"))` | the fixture's attested key and both assertions | verifies; counters 1 and 2; authenticator data 73 bytes |

Hashes are hexadecimal; thumbprints and the nonce are base64url as the server emits them. The last two rows are
the evidence that the kit's two App Attest commitments are what a real device signed, not only what the Java
computes; they are a Mac's, and an iPhone's are [U-0063](../findings/U-0063.yaml).

## Errors and what the client does

The codes are `EnrolmentException`'s constants; the status is the one its factory method sets. "Reported" means
the kit throws `AgentIdentityError.refused` with the status, code and description, and the app decides.

| `error` | Status | Raised by | The client |
|---|---|---|---|
| `invalid_request` | 400 | a missing or malformed field, a JWK that is not public or not usable, a body that is not JSON | reported: a bug in the client |
| `invalid_challenge` | 400 | a challenge unknown, older than 300 s or already spent (`enrol` step 2, `reissue`) | enrolment: reported, and `enrol()` again starts over with a new challenge, sign-in and App Attest key; re-mint: a new challenge, proof and assertion, once |
| `invalid_attestation` | 401 | App Attest verification failed (`verifyEvidence`, `verifyRenewalAssertion`), or App Attest is not configured | enrolment: reported, and the next `enrol()` uses a new App Attest key, as Apple says; a development attestation on a production verifier is configuration. Re-mint: a lost counter race is retried once ([below](#the-counter-race-and-the-retry)); anything else is reported |
| `user_authentication_failed` | 401 | the ID token did not verify, or its `sub` is not the owner's (`refreshUserVerification`) | reported; if it recurs, the issuer or client id is wrong |
| `insufficient_assurance` | 403 | the token's `acr` is not in `PINGONE_ACR_AAL2` | reported: the app's `acr_values` and the service's list disagree |
| `invalid_key_proof` | 401 | a check in `EnclaveKeyProofValidator` failed, or the `jti` was seen before | reported: the wrong key, a device clock more than a minute ahead, or a bug |
| `unknown_instance` | 404 | no such instance | reported; the app forgets the enrolment and enrols again with a new key |
| `instance_not_active` | 403 | suspended or revoked | reported; a suspended instance resumes only from the registry side, a revoked one never |
| `device_not_compliant` | 403 | the device is not `COMPLIANT`, never assessed included | reported; nothing the device does changes it |
| `user_verification_required` | 401 | the owner's last verification is older than `UV_MAX_AGE_SECONDS` | the one the kit recovers: the owner signs in again, `POST /user-verification`, then a new re-mint, once |
| `server_error` | 500 | a registry or dependency failure, or anything unhandled | reported; the app tries later, and every call builds new values |

A status the table does not have, or a body that is not the error shape, is `unexpectedResponse` with the status
and the start of the body; a request that got no HTTP answer is `transport`. Neither is retried.

## The counter race and the retry

Every `generateAssertion` advances the App Attest counter on the device, and the service accepts only a counter
above the one on record. `IomInstanceRegistry.recordAppAttestCounter` makes that a compare-and-set, one `UPDATE …
WHERE … < ?`, so two concurrent re-mints of one instance cannot both advance it; `InMemoryInstanceRegistry` compares
and stores. The loser is answered `invalid_attestation` with one of two descriptions, depending on where it lost:
"App Attest assertion counter did not advance: …" when the registry refused the compare-and-set, or "App Attest
assertion failed (counter_not_advanced): …" when `AppAttestVerifier` saw a counter at or below the stored one
(`AppAttestException.COUNTER_NOT_ADVANCED`, a reason `libs/app-attest` says to treat as contract). By then the
proof's challenge and `jti` are spent.

So the retry is never a resend. The kit builds a new proof (a new challenge and `jti`) and a new assertion (a higher
counter) and sends once more, at most once, and only when the description contains one of those two fragments:
`invalid_attestation` is shared with every other assertion failure, and this is the one place the prose is read.
X-A08, which moves the compare-and-set into the mint transaction, should give the race a code of its own. A
second refusal is reported.

The recoveries compose and each happens at most once per re-mint (`RemintRecovery`): the time-box, a lost race, a
spent challenge. A re-mint is at most four requests to `/attestation`.

The kit also keeps itself out of the race. Concurrent calls to `DeviceAgent.remint()` or `currentAttestation()`
share one ceremony, and so do concurrent enrolments: two re-mints of one instance from one app would race the
counter against each other.

## The interop run

[clients/ios/tools/interop](../../clients/ios/tools/interop/README.md) starts the service's own classes as `Main`
wires them (`REGISTRY=memory`, `REQUIRE_COMPLIANT_DEVICE=false`) beside an oracle that stands in for Apple (App Attest
objects in the shapes `AppAttestFixtures` mints, under a root the verifier is constructed to trust) and PingOne
(RS256 ID tokens the verifier's JWKS source can check), and the kit's `InteropTests` drives `DeviceAgent` against
it over HTTP. On 2026-09-27, at `ab74038`: the enrolment was accepted, with the thumbprint, key identifier, platform,
model and OS version recorded as sent and `cnf.jwk` the kit's JWK; a re-mint was accepted and the counter recorded;
after the oracle aged the verification, the service answered `user_verification_required`, the kit signed the owner
in again, `POST /user-verification` took the token and the re-mint went through; after the oracle recorded a
higher counter, the service refused the kit's assertion as `counter_not_advanced` and the retry went through; a
second key was refused `invalid_key_proof`. What it cannot show is the real Apple and the real PingOne, below.

## What is not yet known

1. **The iOS nonce.** The server checks no nonce on the iOS path ([F-0084](../findings/F-0084.yaml)). The kit's
   two-segment value is a proposal; when X-A05 lands, the server adopts it or the kit changes, and the vector
   above says which shape the tests hold today.
2. **Entra `deviceid`.** Whether Entra emits it through the broker on an Intune-managed iPhone is David's two-day
   spike ([U-0042](../findings/U-0042.yaml)); what the kit would send and where is
   [U-0064](../findings/U-0064.yaml); MSAL as a dependency is [U-0065](../findings/U-0065.yaml). No request carries
   the token today.
3. **Real App Attest objects from an iPhone.** The kit's commitments were checked against the service's synthetic
   shapes and against real macOS 27.2 objects. Open until three attestations and three assertions per
   environment exist from an iPhone ([U-0063](../findings/U-0063.yaml), feeding X-A07): the key identifier's
   encoding on iOS, whether an iOS credential certificate carries the OS and key-policy extensions macOS 27
   writes, and the assertion's authenticator data (73 bytes on macOS, with an extensions map after the counter).
   The sample app captures them.
4. **PingOne with `max_age=0` and a passkey policy.** The discovery document advertises `auth_time` and `acr`; no
   sign-in has been run from the kit, and whether `acr_values` selects the policy is not verified
   ([U-0081](../findings/U-0081.yaml)).
5. **A stable code for the counter race**, so the kit stops reading prose (X-A08).
6. **Compliance on a real deployment.** With the defaults a new iPhone cannot re-mint until X-A15 and X-A17 deliver
   a compliance source ([F-0004](../findings/F-0004.yaml)); a rig runs with `REQUIRE_COMPLIANT_DEVICE=false`.
7. **Clock skew.** A proof whose `iat` is more than 60 s ahead of the server, or more than 360 s behind, is
   `invalid_key_proof`. The kit uses the device's clock and does not correct it.

## What this page rests on

Read at commit `ab74038` on 2026-09-27: `services/device-enrolment` (`EnrolmentHttpServer`, `EnrolmentService`,
`EnclaveKeyProofValidator`, `EnrolmentException`, `PingOneIdTokenVerifier`, `UserAuthenticationVerifier`, `Main`,
`EnrolmentHttpEndToEndTest`, the README), `libs/device-instance` (`InstanceRegistry`, `InMemoryInstanceRegistry`,
`IomInstanceRegistry`, `DeviceAttestationMinter`, `InstanceIdentifiers`, `AgentInstance`, `Device`),
`libs/app-attest` (`AppAttestVerifier`, `AuthenticatorData`, `AppAttestConfig`, `AppAttestFixtures`,
`MacOsAssertionTest`, `MacOsAttestationTest` and the macOS 27.2 fixtures), `libs/client-attestation`
(`AttestationChallengeService`, `InMemoryAttestationChallengeService`, `InMemoryAttestationReplayCache`) and
`libs/oidf-jose` (`Jwks`); jose4j 0.9.6's sources (`EllipticCurveJsonWebKey`, `JsonWebKey`). Apple's pages for
`DCAppAttestService` (`generateKey`, `attestKey`, `generateAssertion`, `isSupported`), "Establishing your app's
integrity" and "App Attest Environment"; OpenID Connect Core 1.0 incorporating errata set 2, §3.1.2.1 and §3.1.3.7;
RFC 7515 §5.1 and Appendix A.3, RFC 7518 §3.4, RFC 7636 Appendix B and RFC 7638 §3.2 from rfc-editor.org; the
discovery document of the PingOne environment the service README names; all read or fetched 2026-09-27. The
Secure Enclave helper in the connector's repository (`helpers/se-signer`), which captured the macOS fixtures, for
how it decoded the key identifier. The vectors program and the interop run, both 2026-09-27.
