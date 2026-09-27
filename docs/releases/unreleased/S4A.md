# S4A - the attestation PoP audience and the DPoP htu

## Changelog

- Plan item S4a (its audience and `htu` parts; the ceiling refusal code is S1B's): a Client Attestation PoP must
  name this server's issuer and nothing else, and a combined-mode DPoP proof the endpoint URL PingFederate
  advertises, never one rebuilt from the `Host` header. Closes F-0110 and F-0111 (PR #34).

## Before you deploy

1. **A client attestation PoP must be addressed to PingFederate's issuer, and to nothing else.** The token
   endpoint URL, another server's identifier, or an `aud` array with a second member is refused with 401
   `invalid_client` and the description "Client Attestation PoP 'aud' must be this server's issuer identifier
   and nothing else". The issuer as a string, or as the one member of an array, is accepted.
   draft-ietf-oauth-attestation-based-client-auth-10 §5.1 asks for exactly this: "When the JWT is presented to
   an Authorization Server, the [RFC8414] issuer identifier URL of the Authorization Server MUST be used. [...] A
   Client Attestation PoP JWT is intended for a single audience". How to tell: the token or PAR response carries
   that description, and PingFederate's `server.log` has `attest_jwt_client_auth: rejected [invalid_client]` with
   it (on the OGNL criterion route, where there is no filter, the client gets 400 `invalid_grant` and the log line
   is `Attestation-based client authentication failed [invalid_client]`). What to change: address the PoP to the
   `issuer` of PingFederate's `/.well-known/openid-configuration`, which the attester also publishes as
   `pop_audience` in `/.well-known/client-attester`. The workloads in pf-oidf-modules already do (read on
   2026-09-27: `bootstrap.py` sends `OP_ISSUER`, `agent-workload/app.py` sends PF's base URL).

2. **A combined-mode DPoP proof must name the endpoint URL PingFederate advertises.** The `htu` is compared with
   `token_endpoint` at the token endpoint (PingFederate's token endpoint base URL when one is set, otherwise the
   issuer, then `/as/token.oauth2`) and with `pushed_authorization_request_endpoint` at PAR (the issuer, then
   `/as/par.oauth2`), after RFC 3986 normalisation. The `Host` header, `X-Forwarded-*` and the request URL no
   longer count. A client that reaches PingFederate by a name other than its base URL - a compose service name, or
   a proxy whose public name PingFederate does not have as its base URL or a virtual host name - is refused with
   401 `invalid_client` and "DPoP proof verification failed: DPoP 'htu' mismatch: got '<the proof's htu>',
   expected '<the configured URL>'" (on the OGNL route, 400 `invalid_grant` and that text in `server.log`). What
   to change: make PingFederate's base URL (Server Settings > Federation Info) the URL clients use, which the
   issuer in its tokens and discovery needs anyway, or add that name to its virtual host names; on the OGNL route
   only, `extproperties.attestation_expected_htu` still pins one client's `htu`, if the deployment declares that
   extended property. idp-agentic-demo is affected as it stands (read on 2026-09-27): its concierge sends `htu`
   `https://pingfederate:9031/as/token.oauth2`, the compose default of `PF_TOKEN_URL`, while its PingFederate
   advertises `https://localhost:9031`.

3. **`ClientAttestationConfig` takes one expected audience.** For code that builds the verifier from
   libs/client-attestation: `Builder.acceptedAudiences(Set)` and `Builder.addAcceptedAudience(String)` are
   replaced by `Builder.expectedAudience(String)`, and `acceptedAudiences()` by `expectedAudience()`. Code that
   calls the old methods no longer compiles. Pass the one identifier the verifying server answers to: an
   authorization server's issuer, or a resource server's resource identifier. DPoP combined mode is refused
   ("Server misconfigured: no expected DPoP htu") when neither `expectedHtu` nor the `requestUri` argument names
   the endpoint.

4. **`DpopProofValidator` compares the `htu` after normalisation, and refuses more.** For code that uses the
   validator directly, as `services/demo-rs` does: the scheme and host are compared in lower case, a default or
   empty port is dropped, percent-encoded unreserved characters are decoded and dot-segments removed, and the
   query and fragment are ignored (RFC 9449 §4.3 and the RFC 3986 sections it names). An `htu` carrying user
   information, or one that is not an absolute http or https URI, is now refused where it used to be matched on
   its host and path. How to tell: "DPoP 'htu' mismatch" in the refusal. What to change: send the endpoint's URL
   as the endpoint advertises it.

## Notes

What changed. `ClientAttestationUtils.defaultConfig` (the token-endpoint filter) and `buildConfig` (the OGNL
criterion) set the PoP audience to the issuer `OAuthIssuerUtils.getIssuerValue` returns and the DPoP `htu` to
`ClientAttestationUtils.endpointUrl`: the issuer, or at the token endpoint PingFederate's token endpoint base URL
when one is set, followed by the path the container routed on. Neither reads `getRequestURL()` any more. Until
0.4.0 both accepted the request URL, which the container rebuilds from the `Host` header, so a PoP or proof minted
for another server - and every PingFederate's token endpoint is `/as/token.oauth2` - passed with a `Host` header
naming that server (F-0110, high; F-0111, medium). `ClientAttestationVerifier` refuses any PoP `aud` but the
expected one, which jose4j's own check did not (it passes an array that merely contains an accepted value), and
refuses combined mode with no expected `htu`, which `DpopProofValidator` would have skipped. The harness's live
mode addresses its PoP to the target's `issuer` from discovery, or `OIDF_POP_AUDIENCE`.

Verification, 2026-09-27. Read with javap from PingFederate 13.1.3's `pf-protocolengine`:
`OAuthIssuerUtils.getIssuerValue` returns the configured base URL, or a configured virtual host name or issuer
when the request's host is one of them, and the base URL for a host it does not know;
`ProviderConfigurationInfoHandler` builds `token_endpoint` from the token endpoint base URL or the issuer, and
`pushed_authorization_request_endpoint` from the issuer; `pf-runtime.war` maps `*.oauth2` to its controller, so
the servlet path is the whole path. `ReceivingServerBindingTest`, `HtuComparisonTest`,
`ClientAttestationAuthFilterEndpointTest` and `EndpointUrlTest` pin the rules (`@Requirement` ABCA-10 §5.1 and
§7.2(7), RFC7519 §2 and §4.1.3, RFC9449 §4.3(8) and §4.3(9)); the new decision methods are in their modules'
100% METHOD gates; the modules pass `mvn -o -B verify` on JDK 20 and JDK 17.

Residual risk. When PingFederate matches the request's host to one of its virtual host names or issuers, it takes
the port from the request (`BaseUrlUtil.getPort`), so a PoP or proof for another port of that same host name is
accepted - a server a client trusts on another port of one of this server's own names. PingFederate's own DPoP
check, which still judges the proof a client sends beside a PoP JWT, is looser than the filter's: it accepts an
`htu` whose host is the request's or one of its own names and whose path ends with the endpoint's. A host that is
not a valid DNS name (an underscore, say) cannot be an expected `htu`, so combined mode is refused there. The
token endpoint base URL is read from PingFederate internals (`MgmtFactory.getAuthzServerManager()`); if it cannot
be read, the token endpoint stays under the issuer and a proof naming the base URL is refused. On the OGNL route
`extproperties.attestation_expected_htu` can point the `htu` wherever an administrator writes; S4c makes per-client
attestation properties tighten-only.
