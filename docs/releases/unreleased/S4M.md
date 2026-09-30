# The authorization server's attestation members are published wherever its metadata is, and the attester's document points at them

## Changelog

- PingFederate's `/.well-known/openid-configuration` and `/.well-known/oauth-authorization-server` now carry the
  authorization server's attestation members (plan item S-4, F-0115): `attest_jwt_client_auth` and
  `attest_jwt_client_auth_dpop` appended to `token_endpoint_auth_methods_supported`,
  `client_attestation_signing_alg_values_supported`, `client_attestation_pop_signing_alg_values_supported`,
  `client_attestation_pop_methods_supported` and `challenge_endpoint`. A new filter, `AttestationMetadata`
  (`AttestationMetadataFilter`, registered by `build/pingfederate/filters.xml`), adds them; PingFederate's own members
  are kept first, in its order and with its values.
- The Entity Configuration's `oauth_authorization_server` block carries the same members, added to PingFederate's own
  RFC 8414 document; its `openid_provider` block carries them as before.
- With `OIDF_ATTESTATION_AUTH_ENABLED=false`, or no `attest_jwt_client_auth*` method in `tokenEndpointAuthMethodsSupported`,
  none of the four documents advertises an attestation member.
- `/.well-known/client-attester` names the authorization server: `authorization_servers` (its issuer, RFC 9728 §2's
  member) and `authorization_server_metadata` (the issuer's RFC 8414 metadata URL), where a client finds the
  challenge endpoint the token endpoint accepts (F-0118). Its own `challenge_endpoint` is still the attester's.
- A discovery document the filter cannot extend goes out as PingFederate wrote it, and every answer is counted in
  `oidf_discovery_attestation_members_total{document, outcome}`.

## Before you deploy

1. **PingFederate's discovery documents now advertise attestation client authentication.** What to do: nothing, unless
   a client picks its authentication method from discovery; check such clients against the new lists. Why: ABCA-10 §6.1
   says an authorization server that offers a challenge endpoint and supports RFC 8414 metadata "MUST signal support
   for the challenge endpoint by including the metadata entry challenge_endpoint", and before 0.6.0 only the Entity
   Configuration's `openid_provider` block did. How to tell: `curl https://<pf>/.well-known/oauth-authorization-server`
   now ends with `client_attestation_signing_alg_values_supported`, `client_attestation_pop_signing_alg_values_supported`,
   `client_attestation_pop_methods_supported` and `challenge_endpoint` (`<issuer>/federation/attestation-challenge`), and
   its `token_endpoint_auth_methods_supported` ends with `attest_jwt_client_auth` and `attest_jwt_client_auth_dpop`; the
   same for `/.well-known/openid-configuration` and the Entity Configuration's `oauth_authorization_server` block. Both
   PingFederate documents are now written as compact JSON, not indented; their content is otherwise PingFederate's.
   What to change: a client that takes the first method it recognises from `token_endpoint_auth_methods_supported` is
   unaffected, because the two methods come last; one that treats an unknown member as an error must learn to ignore
   it (RFC 8414 §3.2: the response's members are "a subset of the metadata values defined in Section 2. Other claims
   MAY also be returned"). To advertise nothing, switch attestation off with `OIDF_ATTESTATION_AUTH_ENABLED=false`, which also
   stops the token endpoint accepting it. There is no development-profile escape: this is what the documents say, not
   a check that refuses anything.
2. **With attestation switched off, no document advertises it.** What to do: nothing, unless you run with
   `OIDF_ATTESTATION_AUTH_ENABLED=false` and a federation relying party reads attestation from the Entity Configuration.
   Why: plan item S9b's rule for a disabled component is that it advertises nothing, and a switched-off component
   verifies no attestation. How to tell: with the switch off, the Entity Configuration's `openid_provider` block has
   no `client_attestation_*` member and no `challenge_endpoint`, and its `token_endpoint_auth_methods_supported` is the
   configured list less `attest_jwt_client_auth` and `attest_jwt_client_auth_dpop` (by default, `["private_key_jwt"]`);
   before 0.6.0 it advertised them whatever the switch said. What to change: nothing; a relying party that wants
   attestation needs the component on. There is no development-profile escape, for the same reason.

## Notes

Which document names which challenge endpoint:

| Document | `challenge_endpoint` |
|---|---|
| PingFederate's `/.well-known/openid-configuration` and `/.well-known/oauth-authorization-server` | The authorization server's, `POST <issuer>/federation/attestation-challenge`, for the PoP or combined-mode DPoP proof at the token endpoint |
| The Entity Configuration's `openid_provider` and `oauth_authorization_server` blocks | The authorization server's, as above |
| `/.well-known/client-attester` and `/.well-known/client-attestation-service` | The attester's, `GET /federation/attestation/challenge`, for the instance-key proof at `/federation/attestation`; the first also names the authorization server's metadata, whose `challenge_endpoint` is the one the token endpoint accepts |

Verified first on the rig (slot 4, pfai-p3-s4m, PingFederate 13.1.3, origin/main 6815222e, 2026-10-01): the stock
`pf-runtime.war` maps both documents to PingFederate's `controller` servlet by exact path, so the filter needs no
`<path-exception>`; both answer 200 `application/json` with `Cache-Control: no-cache, no-store`, pretty-printed (6218
and 4778 bytes), and are never compressed, whatever `Accept-Encoding` asks, over HTTP/2 and HTTP/1.1 and on the plain
listener (U-0029's answer holds for them); a `;x` path parameter and a `/./` dot segment reach the same documents. With
this branch's image and `OIDF_ATTESTATION_AUTH_ENABLED=true`, the assembler printed both chains as PingFederate's
request-wide filters, then `AttestationMetadata`, then `noCacheFilter`, and both documents came back with the members
added, every PingFederate member unchanged and in its order, `Content-Length` the new length, and `HEAD` answering the
same length with no body; the `;x`, `/./` and plain-listener requests were extended too.

Tests: `AttestationMetadataConfigTest` (the set, its order, the document's own members kept, a document without a
method list, one that cannot be extended, the switch), `FederationServiceMetadataTest` (both blocks carry the same
members, none switched off), `AttestationMetadataFilterTest` (a PingFederate-shaped document through the writer and
the stream, the context path, switched off, an unreadable configuration, unparseable, compressed, another status or
type, past the size limit, committed past the filter, `HEAD`, other methods), `ChallengeEndpointAdvertisementTest`
(the four documents carry one set, none switched off, and the attester's document leads to the authorization server's
challenge), `AttesterConfigurationServletTest` (RFC 8414 §3's URL), and the war assembler's chain, declaration and
golden descriptor against 13.1.3's stock war. `SurfaceMatrix` in servlets/ssf and servlets/attestation-issuer names the
filter as no component's: it never refuses, and what it adds follows `ATTESTATION_AUTH`'s switch.

Residual: the Entity Configuration's `openid_provider` block still replaces PingFederate's `token_endpoint_auth_methods_supported`
and `dpop_signing_alg_values_supported` with the configured lists, where the other three documents extend PingFederate's
(F-0410). The attester's document names only `attest_jwt_client_auth` as the token endpoint's method (F-0411).
