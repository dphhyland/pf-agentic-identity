# shared-signals

> **Part of the [pf-agentic-identity](https://github.com/dphhyland/pf-agentic-identity) monorepo** - build from the
> repo root with `mvn package`. Split out of [`servlets/ssf`](../../servlets/ssf) in 0.5.0 (plan item X-A14).

**Security Event Tokens without PingFederate**: the parts of a Shared Signals transmitter and receiver that need
neither PingFederate nor the network, so a service outside PingFederate can mint and verify SETs with the same code
the PingFederate module uses. Package `com.pingidentity.ps.oidf.signals`. Depends on
[`oidf-jose`](../oidf-jose) (its signer abstractions) and jose4j. No servlet API, no HTTP client, no PingFederate
SDK. [`servlets/ssf`](../../servlets/ssf) is the PingFederate transmitter and receiver built on it.

## What is here

- **`SecurityEventToken`** - an unsigned SET carrying one event: `iss`, `aud`, `iat`, `jti`, `sub_id` (absent for
  the verification event), `events` keyed by the event-type URI, and an optional `txn`. No `exp`: SSF 1.0 §4.1.7
  says "The "exp" claim MUST NOT be used in SETs".
- **`SetMinter`** - signs a SET as a compact JWS with `typ` `secevent+jwt`, behind one of `oidf-jose`'s signer
  abstractions: a `SigningKeyProvider` (an RSA key pair and its id, under RS256 or PS256 - in PingFederate,
  `servlets/ssf` hands over PingFederate's active JWKS key) or a `JwsSigner` (a key in a vault or in process; its
  algorithm and key id go in the header).
- **`SetVerifier`** - verifies an inbound SET against a supplied key set (a `JwksSource`; this library makes no
  network call - `servlets/ssf`'s `JwksHttpSource` fetches one). It accepts a SET only when:
  - `typ` is `secevent+jwt`, with or without `application/`, in any case (RFC 8417 §2.3, SSF 1.0 §4.1.1, RFC 7515
    §4.1.9);
  - `alg` is an asymmetric signature algorithm (RS, PS and ES families, EdDSA) and the signature verifies against
    a key with the header's `kid` (once more after a refresh, for key rotation);
  - `iss` is the expected issuer; `aud`, a string or an array, contains the expected audience when one is set;
  - `iat` is a number and `jti` a non-blank string (RFC 8417 §2.2: both "REQUIRED");
  - `exp`, if present, is a number and not past, with 60 seconds' leeway (RFC 8417 §2.2: "the time after which the
    JWT MUST NOT be accepted for processing");
  - `events` is an object with at least one member, each value an object (RFC 8417 §2 and §2.2);
  - `sub_id`, if present, parses as a subject in a format the verifier accepts.

  A failure is a `SetVerificationException` carrying the RFC 8935 error code for a push response
  (`invalid_request`, `invalid_key`, `invalid_issuer`, `invalid_audience`).
- **`ReceivedSet`** - a verified SET: issuer, `jti`, `iat`, subject, the `events` map and the raw JWS.
- **`SubjectId`** - a SET subject, parsed from and written to its JSON object:
  - RFC 9493 §3.2's eight formats: `account`, `email`, `iss_sub`, `opaque`, `phone_number`, `did`, `uri` and
    `aliases` (one or more identifiers of one entity, never nested);
  - SSF 1.0 §3.5's three: `jwt_id`, `saml_assertion_id`, `ip-addresses`;
  - SSF 1.0 §3.3's complex subject - "a JSON [RFC7159] object that has a format field, and one or more Simple
    Subject Members", the format being `complex` and each member (`user`, `device`, `session`, `application`,
    `tenant`, `org_unit`, `group`, or another name) a Subject Identifier;
  - `matches`, SSF 1.0 §8.1.3.1's rule: simple subjects match when identical, complex ones when every member either
    side defines is identical on the other side or undefined there;
  - `canonicalKey`, a stable string for a store or Kafka key: the five formats `servlets/ssf` stored before 0.5.0
    keep the keys they had, and the others key on their members as JSON in name order.

  `fromMap(json, accepted)` limits the formats accepted at the top level; `servlets/ssf` keeps to the five it has
  always handled until plan item H-SSF-1 (Phase 3). Members a format does not describe are dropped, not refused.
- **`CaepRiscEvents`** - the event payloads the transmitter emits (CAEP session-revoked, credential-change,
  device-compliance-change, assurance-level-change; RISC account-disabled and account-enabled), with `reason_admin`
  as an object keyed by language tag (CAEP 1.0 §2).
- **`EventTypes`** - the CAEP 1.0, RISC 1.0 and SSF verification event-type URIs. Which of them a transmitter
  advertises is the transmitter's business (`servlets/ssf`'s `SsfEventTypes`).

## Coverage gate

The verifier's decisions, the subject parsing, keys and matching, and `SetMinter.sign` are held to 100% line and
branch coverage per method by the module's jacoco `coverage-gate` ([pom.xml](pom.xml)).

## Packaging

`shared-signals-<version>.jar` goes wherever `ssf-<version>.jar` goes: `build/pingfederate/stage-modules.sh` stages
it in both profiles, so the image merges it into `pf-runtime.war` and copies it to `server/default/deploy`, and the
`MANIFEST` names it. A deployment that copies jars itself adds it beside `ssf`'s.
