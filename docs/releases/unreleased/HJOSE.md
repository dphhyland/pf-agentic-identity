# Unverified claims get their own type, every verifier refuses none, MACs and encryption keys, and signing keys are held to RFC 7518

## Changelog

- `JwtCodec.parseUnverifiedClaims` returns an `UnverifiedClaims` (plan item H-JOSE-1,
  [F-0063](../../findings/F-0063.yaml)): the claims of a JWT whose signature nobody has checked, typed so that they
  cannot be passed where verified claims are expected, every accessor named `unverified...`. Every call site is
  classed in the oidf-jose README ("Reading a JWT before its signature is checked"): routing, refuse-first or logging.
- Every `JwtCodec` verifier - the claim verifiers, `verifySignature` and `verifyAttestationPop` - refuses `none` and
  the MAC algorithms whatever the caller's algorithm set names, and tries only asymmetric keys not marked
  `"use": "enc"` (RFC 8725 §3.1, §3.2; RFC 7517 §4.2). The `verifyAgainstKeys` and `verifyAgainstInlineJwks` overloads
  that take no `VerificationPolicy` are deprecated for removal; no code in this repository calls them.
- A configured subordinate's keys are asserted in a Subordinate Statement only once its Entity Configuration verifies
  under one of them ([F-0415](../../findings/F-0415.yaml)). The trust mark status endpoint decides on the verified
  mark, the Trust Mark validator verifies the anchor configuration it reuses against the anchor's pinned keys, and a
  request object's replay window reads its verified `exp` and `jti`.
- `LocalJwkSigner` (plan item H-JOSE-2, [F-0064](../../findings/F-0064.yaml), [F-0112](../../findings/F-0112.yaml))
  signs `PS256`, `PS384` and `PS512` with an RSA key, and refuses, when it is built, an RSA key under 2048 bits, an EC
  key off P-256, P-384 and P-521, and an EC key whose declared `alg` is another curve's.
- The attestation filter's start function builds every client's bridge signing key, and again every ten minutes; a
  key that does not build is a `DEGRADED` part of `ATTESTATION_AUTH`, `BridgeSigners`, naming the client.
- `SdJwt` and `SdJwtException` are removed from oidf-jose: nothing used them, and the attestation verifier refuses
  SD-JWT presentations.
- oidf-jose has a `mutation` profile, as openid-federation and pf-integration do.

## Before you deploy

1. **Signing keys under 2048 bits (RSA) or on other curves are refused.** What to do: check every private JWK this
   release signs with in-process - each `"jwk"` entry of the file `OIDF_BRIDGE_SIGNING_KEYS` names (with
   `OIDF_BRIDGE_SIGNER_BACKING=config`), each attestation client's `attestation_signing_jwk` extended property, and
   device-enrolment's `ENROLMENT_SIGNING_JWK`. An RSA key needs a modulus of 2048 bits or more: its `n` is at least 342
   base64url characters (`jq -r '.[].jwk.n // empty' bridge-keys.json | awk '{print length($0) * 6}'` prints the bits,
   near enough). An EC key's `crv` must be `P-256`, `P-384` or `P-521`, and an `alg`, if the JWK carries one, must be
   `ES256`, `ES384` or `ES512` respectively. Why: RFC 7518 §3.3 and §3.5 each say "A key of size 2048 bits or larger
   MUST be used", §3.4 defines ECDSA on those three curves only, and RFC 8725 §3.1 says "each key MUST be used with
   exactly one algorithm"; before 0.6.0 `LocalJwkSigner` signed with any RSA key and trusted a declared `alg` it did
   not check. How to tell: a bridge key is named in the health detail (see "A bridge key that cannot sign is reported at start-up"); the attester answers that
   client's issuance request `invalid_client`, and PingFederate's server log has "attestation_signing_jwk is invalid:
   an RSA signing key must be 2048 bits or larger; this one is 1024 (RFC 7518 §3.3, §3.5)", or "an EC key on P-256
   signs ES256, not ES384 ..."; device enrolment does not start, with the same sentence. What to change: generate a new key of 2048 bits or more (or on one of the three curves),
   register its public half where the old one was (the client's JWKS for a bridge key, the attester's published keys
   for the attester), and replace the private JWK; or drop the wrong `alg`. Development-profile escape: none - the
   sizes and curves are the RFC's MUST, in both profiles, and a key that breaks them is replaced once.
2. **A bridge key that cannot sign is reported at start-up.** What to do: after the upgrade, read the health detail
   at `/agentic-identity/health`: `ATTESTATION_AUTH`'s part `BridgeSigners` is `READY` when every entry of
   `OIDF_BRIDGE_SIGNING_KEYS` builds, and `DEGRADED` "n client(s) whose bridge signing key does not build, refused at
   the token endpoint until it is fixed (see the log): ..." naming the clients otherwise. PingFederate's server log
   names each client once with the reason, at WARN, under `BridgeSigners`. Why: before 0.6.0 a key that could not sign
   was found by its client's first bridged request, which answered `500 server_error` after the attestation had
   verified ([F-0112](../../findings/F-0112.yaml)). The check runs when the attestation filter starts and every ten
   minutes, so a vault that was down at start, or a file you mend, is found again. How to tell: the part, and
   `attest_jwt_client_auth` requests for a named client, which are still refused as before. What to change: fix or
   replace the key the log names ("Signing keys under 2048 bits (RSA) or on other curves are refused" says how for
   size and curve; a `"key_ref"` needs a transit key
   the vault describes as `ecdsa-p256`, `-p384` or `-p521`). A `DEGRADED` part keeps the component ready, so nothing is
   taken out of rotation for it. Development-profile escape: none needed - the check reports and refuses nothing the
   first request did not already refuse.
3. **`SdJwt` is gone.** What to do: if your own code imports `com.pingidentity.ps.oidf.jose.SdJwt` or `SdJwtException`
   from the `oidf-jose` artefact, move to a maintained SD-JWT library before taking 0.6.0. Why: the class was unused
   here, the reviewers of 2026-09-26 found it non-conformant ([F-0064](../../findings/F-0064.yaml)), and the
   attestation verifier refuses SD-JWT presentations. How to tell: the build fails with `cannot find symbol: class SdJwt`. No
   consumer in this repository imports it, and none outside it is known. What to change: the import. Development-profile
   escape: none - it is a compile-time removal.
4. **Code that calls `JwtCodec` directly changes.** What to do: if your own code uses oidf-jose, `parseUnverifiedClaims`
   now returns `UnverifiedClaims` and throws `JwtVerificationException`: read `unverifiedIssuer()`,
   `unverifiedSubject()`, `unverifiedClaim(name)` and the others instead of the `JwtClaims` getters, and take any value
   a decision rests on from the claims a verifier returns. Why: a value read before its signature is checked is what
   the sender wrote (RFC 8725 §3.2). How to tell: the build fails where a `JwtClaims` was expected; a token signed
   with `HS256` or `none`, or checked with a key marked `"use": "enc"`, is now refused `ALGORITHM` or `KEY` by every
   verifier. What to change: the types; and pass a `VerificationPolicy` to `verifyAgainstKeys` and
   `verifyAgainstInlineJwks` - the overloads without one are deprecated and go in a later release. Development-profile
   escape: none - these are library types, not settings.

## Notes

- PS256 bridge keys now work: a client whose token endpoint signing algorithm is PS256 can be given an RSA bridge key
  declared `"alg": "PS256"` (RFC 7518 §3.5). Checked on 2026-10-01 by unit tests (`LocalJwkSignerTest`,
  `BridgeSignersCheckTest`) on JDK 17 and 20, and with the PingFederate 13.1.3 image's own java (BellSoft 21.0.12.1),
  which signed PS256, PS384 and PS512 that jose4j verified and refused a 1024-bit key; not on a booted PingFederate -
  the rig was not re-run for this package.
- The oidf-jose mutation profile's first run, on 2026-10-01 (JDK 20), killed 322 of 349 mutations (92%, test strength
  96%); the oidf-jose README has the breakdown. The weekly Mutation workflow does not run it yet (plan item R-CI8,
  Phase 7).
- Plan decisions this package builds on as the plan recommends, not yet confirmed by the owner: decision 16 (H-* is
  Phase 3, grouped by module).
