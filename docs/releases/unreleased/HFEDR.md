# Registration hardening: encrypted first registrations, expiry without client_id, explicit relying parties

## Changelog

- An encrypted request object, or an encrypted client assertion at PAR, no longer registers or renews a relying party
  at the authorization or PAR endpoint under the production profile: it is refused with 400 `invalid_request_object`
  (plan item H-FED-1, F-0020). Development registers it with a warning. A relying party whose registration is current
  still sends encrypted request objects on to PingFederate.
- `request_object_signing_alg` is never set from a JWE `alg` such as `RSA-OAEP` or `ECDH-ES`: a client is registered
  with its declared algorithm, else its signed proof's, and only when that is an asymmetric JWS algorithm (`RS256`-`RS512`,
  `PS256`-`PS512`, `ES256`-`ES512`, `EdDSA`). Anything else leaves it unset, and PingFederate's default applies.
- The token endpoint names an attested request's client from the `OAuth-Client-Attestation` header's `sub` when the
  request carries neither a client assertion nor `client_id`, so that client's registration expiry is enforced
  (H-FED-2, F-0021).
- An explicitly registered `openid_relying_party` gets OpenID Connect Registration 1.0 §2's defaults for what its
  metadata omits - `response_types` `["code"]`, `grant_types` `["authorization_code"]`, `id_token_signed_response_alg`
  `RS256` - is restricted to its response types, requires PKCE unless `OIDF_AUTO_REGISTRATION_REQUIRE_PKCE=false`, and
  its registration response reports the defaults (H-FED-5, F-0047).

## Before you deploy

1. **A first registration by encrypted request object is refused in production.** From 0.6.0, under the production
   profile (`OIDF_DEPLOYMENT_PROFILE` unset or anything but `development`), a relying party that PingFederate does not
   know yet, and that sends an encrypted request object (a JWE) to `/as/authorization.oauth2` or `/as/par.oauth2`, is
   not registered: the request is refused with 400 `invalid_request_object` and "an encrypted request object cannot
   register a client" - an error page at the authorization endpoint, JSON at PAR. The same goes for an encrypted
   client assertion at PAR, and for a relying party whose registration is due for renewal (its last
   `OIDF_REGISTRATION_REFRESH_BEFORE_EXPIRY_SECONDS`, 300 by default) or has expired. Why: OpenID Federation 1.0
   §12.1.1 says "Authentication requests MUST demonstrate that the requesting Entity controls the Entity's RP keys,
   using one of the methods described below. Attempted authentication requests that do not do so MUST be rejected."
   An encrypted request object is encrypted to PingFederate, so this module cannot read the signed request inside;
   PingFederate decrypts and checks it only after the registration has been written, on the word of a request that
   showed nothing. How to tell: before upgrading, look in server.log for "Automatically registered federation client"
   lines for relying parties that send encrypted request objects, or ask each relying party whether it encrypts its
   request objects; after upgrading, look for `invalid_request_object` refusals at the two endpoints. What to change:
   the relying party registers (and renews) with a signed request object, or at the PAR endpoint with its
   `private_key_jwt` client assertion, and may encrypt its later requests while its registration is current.
   `OIDF_AUTO_REGISTRATION_ENCRYPTED_REQUEST_OBJECTS=allow` (the default) now means only that a registered relying
   party's encrypted request objects go on to PingFederate; `refuse` still turns every one away. Development:
   under `OIDF_DEPLOYMENT_PROFILE=development` the encrypted request object registers the relying party, as before,
   with a warning in server.log naming it.

2. **Explicitly registered relying parties now require PKCE.** From 0.6.0 a client registered at
   `POST /federation/register` from `openid_relying_party` metadata requires PKCE (RFC 7636) on every authorization
   request, as a relying party registered at the authorization endpoint always has, and gets OpenID Connect
   Registration 1.0 §2's defaults for the metadata it omits: `response_types` `["code"]` ("If omitted, the default is
   that the Client will use only the code Response Type."), `grant_types` `["authorization_code"]` ("If omitted, the
   default is that the Client will use only the authorization_code Grant Type.") and `id_token_signed_response_alg`
   `RS256` ("The default, if omitted, is RS256."). Why: before 0.6.0 such a client was registered with no response
   type and no grant when its metadata named none - it could not complete an authorization-code flow at all - and was
   never held to PKCE, which FAPI 2.0 §5.3.1.2 requires. The registration response now reports the three defaults.
   How to tell: in the admin console or API, a relying party registered explicitly (its extended property
   `status` is `registered`) shows "Require Proof Key for Code Exchange (PKCE)" ticked after it
   registers again; an authorization request from it without a `code_challenge` is refused by PingFederate. The
   change takes effect for each relying party the next time it registers - an existing registration keeps what it
   has until then. What to change: relying parties send `code_challenge` (S256) on every authorization request and
   `code_verifier` at the token endpoint; one that relied on no `response_types` meaning something else declares
   what it uses. A deployment that must let explicit relying parties skip PKCE sets
   `OIDF_AUTO_REGISTRATION_REQUIRE_PKCE=false`, which also turns PKCE off for relying parties registered at the
   authorization endpoint and which production allows only with `pkce-off` in `OIDF_ACCEPTED_RISKS`. Development: the
   same setting turns it off with no risk to accept.

3. **An attested token request is now held to its client's registration expiry.** From 0.6.0 a token request that
   carries an `OAuth-Client-Attestation` header and neither a `client_assertion` nor `client_id` is taken to name the
   client in the attestation's `sub`, so an expired federation registration for that client is refused with 401
   `invalid_client` ("the client's explicit registration has expired", or the automatic registration's equivalent),
   or renewed when it can be, as a request naming the client by `client_id` always was. Before, such a request went
   on to the attestation bridge and PingFederate with no expiry check. The `sub` is read before the attestation is
   verified, only to choose which registration to check; ClientAttestationAuth still refuses the request unless the
   verified `sub` is the same. How to tell: 401 `invalid_client` at `/as/token.oauth2` for attested agents whose
   federation registration has expired, with a `federation.registration.expired` event. What to change: the agent
   registers again (explicitly), or its automatic registration renews from a presented chain or discovery.
   There is no development-profile escape: a registration's expiry is enforced in both profiles, and
   `OIDF_REGISTRATION_EXPIRY_ENFORCEMENT=log` is the setting that relaxes it.

## Notes

Plan items H-FED-1, H-FED-2 and H-FED-5; findings F-0020, F-0021 and F-0047 closed, F-0340 and F-0341 and U-0350 and
U-0351 recorded.

What the code does with an encrypted request object's inner JWS: nothing. `RequestObject.read` keeps only the JWE's
protected header, `checkProfile` holds it to its size and `verify` returns at once, because the object is encrypted
to PingFederate's key, which this module does not hold. PingFederate decrypts it later, against the keys the relying
party was registered with; that it then verifies the inner signature is U-0350, not shown on 13.1.3. That is why a
registration is never written from one in production.

The production refusal is made where the client is built (`FederationClientBuilder.relyingParty`), which cannot tell a
first registration from a renewal - `RegistrationService` knows, and this package may not edit it. So a renewal that
falls due while the relying party's request is encrypted is refused too (F-0340): consistent with §12.1.1, but a
relying party that only encrypts must send a signed request or use PAR once per registration. It is a request
failure, never remembered against the relying party, so a stranger's encrypted request cannot hold back the relying
party's own signed one (`RegistrationServiceFrontChannelTest`).

The attestation's `sub` is read unverified at the token endpoint. A lie names another client, which `client_id` could
always do; the request is then refused, or fails authentication, as that client, and ClientAttestationAuth - mapped
after this filter - refuses it unless the verified `sub` is the one it read.

Normative text was quoted from OpenID Federation 1.0 Final (17 February 2026) §12.1.1 and §12.1.1.1.2, OpenID Connect
Dynamic Client Registration 1.0 incorporating errata set 2 §2, and RFC 7516 §4.1.1, each fetched 2026-09-30. The
explicit relying party's `token_endpoint_auth_method` stays `private_key_jwt`: §2's default is `client_secret_basic`,
but no secret is issued here. The `@Requirement` vocabulary gains `OIDC-REG`.

Verified 2026-09-30 by `mvn verify` of pf-integration on JDK 20 and JDK 17 (800 tests, the coverage gates met with
the new decision methods added), and by the clientregistration package's 524 tests on the PingFederate image's JDK
21.0.12 (JUnit's console launcher in the pfai-latest image): 521 passed; RarContextKeyTest's two read the
rar-paz-plugin source, which was not mounted, and RegistrationExpirySweeperTest's executor test failed in that
single-JVM run and passed on its own - neither touches this package's code. The conformance rig was not re-run: the rig sets the development profile, where
none of these changes alters what the OpenID Federation plans exercise, and it registers no relying party explicitly.
