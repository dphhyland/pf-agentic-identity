# Every outbound call on platform's client: SSF, OpenBao, device-enrolment and gm-api get deadlines on the whole exchange

## Changelog

- SSF's push delivery sends each SET through libs/platform's `OutboundHttp`: 2 s to connect and 10 s for the whole
  exchange, the body included (S-10's values), at most 64 KiB of the answer read, and the endpoint's host resolved
  once and the connection pinned to a checked address (plan item S5d; F-0010).
- The SSF receiver's poll, stream management and token calls (1 s to connect, 5 s in all) and its JWKS fetch (1 s and
  2.5 s, at most 64 KiB) go through `OutboundHttp`, with `OIDF_SSF_RECEIVER_INSECURE_TLS` through `TlsTrust.insecureIf`.
- OpenBao's transit signer (1 s and 2.5 s), device-enrolment's calls to the federation authority, its token endpoint
  and PingOne's JWKS (5 s and 10 s), and gm-api's PDP client (`pdpTimeoutMs`, 10 s by default, now on the whole call)
  go through `OutboundHttp`.
- Each failure keeps its caller's outcome - a push retry, a receiver `FAILED_DEPENDENCY`, an enrolment
  `server_error`, a PDP 503 - and its message or log line now names the reason: `HEADER_TIMEOUT`, `DEADLINE`, `TLS`,
  `BODY_TOO_LARGE`, `CONNECT_FAILED` and the rest.
- No shipped module builds its own `java.net.http` client or `HttpURLConnection` for an outbound call any more.

## Before you deploy

1. **Outbound calls from SSF, OpenBao, device-enrolment and gm-api now have deadlines.** Before 0.6.0 these calls
   used the JDK's `HttpClient` (or, in gm-api, `HttpURLConnection`), whose timeouts stop at the response headers or
   bound each read apart, so a peer that answered a byte at a time held the call for as long as it liked. From 0.6.0
   each call has a deadline on the whole exchange, the body included, and a cap on what it reads:

   | Call | Connect | Whole exchange | Most read | Set by |
   |---|---|---|---|---|
   | SSF push delivery | 2 s | 10 s | 64 KiB | constants (S-10 catalogues them in 0.7.0) |
   | SSF receiver: poll | 1 s | 5 s | 4 MiB | constants |
   | SSF receiver: stream management, token | 1 s | 5 s | 256 KiB | constants |
   | SSF receiver: JWKS | 1 s | 2.5 s | 64 KiB | constants |
   | OpenBao transit (hosted entities, bridge and attestation signing) | 1 s | 2.5 s | 256 KiB | constants |
   | device-enrolment: the authority's API and token endpoint, PingOne's JWKS | 5 s | 10 s | 256 KiB | constants |
   | gm-api: the PDP | 5 s | `pdpTimeoutMs` (10 s) | 256 KiB | `pdpTimeoutMs` |

   What a slow peer now sees: its connection closed at the deadline. What the caller does is what it did for any
   failure before: a push is retried on the stream's backoff and dead-letters after `pushRetryMaxAttempts`; a poll
   is asked again next tick; a stream or token call in the receiver's start leaves `SSF_RECEIVER` in
   `FAILED_DEPENDENCY`, retried; a JWKS fetch that fails refuses the SET it was for; an OpenBao call that fails
   refuses the signature (the attestation or hosted-entity statement is not issued); an enrolment fails with
   `server_error` or `user_authentication_failed`; gm-api answers 503. A push receiver that answers 202 with a body
   over 64 KiB is now a failed attempt, retried - RFC 8935 §2.2: "The body of the response MUST be empty". A gm-api
   `pdpTimeoutMs` of zero or below, which meant no timeout, now means the 10 s default. How to tell: the log line or
   message names `HEADER_TIMEOUT` or `DEADLINE` (or `BODY_TOO_LARGE`) with the peer's origin. What to change: make the
   peer answer within its deadline - an OpenBao or PDP that takes longer than its deadline is too slow for the request
   a person is waiting on - and for gm-api, raise `pdpTimeoutMs` if the PDP needs longer. The other deadlines are not
   settings in this release. There is no development-profile escape, because the deadlines apply in every profile.
2. **Certificates must name their host.** Every call in the table above now checks that the peer's certificate
   names the host its URL names, on every connection, and nothing turns that off: not
   `OIDF_SSF_RECEIVER_INSECURE_TLS` or `PF_AUTHORITY_INSECURE_TLS`, which in development trust any chain but not a
   certificate for another name, and not the JVM-wide `jdk.internal.httpclient.disableHostnameVerification`, which
   governed `java.net.http` alone. The JDK client already checked names at every site but gm-api, unless that JVM
   flag was set, and then it checked none at any site; gm-api's `HttpURLConnection` checked them through the JDK's
   default hostname verifier. So what fails now is a peer whose certificate does not name its host, reached from a
   PingFederate started with the flag (idp-agentic-demo's image sets it, for the RAR plugin's PingAuthorize call) or,
   for gm-api, from a JVM whose default hostname verifier had been replaced. How to tell: the failure names `TLS` and
   carries `No subject alternative DNS name matching <host>` (or `... IP address ...`). What to change: reissue the
   peer's certificate with a subject alternative name for the host PingFederate or device-enrolment dials, or dial the
   name the certificate carries. The trust stores are unchanged: the JVM's for push delivery, OpenBao, PingOne, the
   authority and the PDP; the JVM's or trust-all under the two development switches. There is no escape from the name
   check in either profile, because that check is what stops a certificate for one host passing for another.
3. **These calls go straight to the address they checked, never through a JVM proxy.** The JDK's `HttpClient` and
   `HttpURLConnection` took the JVM's proxy settings (`https.proxyHost`, `http.proxyHost`);
   platform's client resolves the host itself and connects to the address it checked, as federation fetches have since
   0.5.0. Which addresses each call may reach: push delivery and PingOne's JWKS keep the `outbound-fetch` rules
   (https, public addresses only; `OIDF_FETCH_ALLOW_HTTP`, `OIDF_FETCH_HOST_ALLOWLIST` and
   `OIDF_FETCH_ALLOW_PRIVATE_NETWORKS` widen them) - which for PingOne's JWKS is new, since the JDK client fetched
   whatever `PINGONE_ISSUER` named; OpenBao, the PDP and the authority are internal by design, so the URL each is
   configured at (`OIDF_OPENBAO_URL` or `openBaoUrl`, `OIDF_BRIDGE_VAULT_ADDR`, `pdpUrl`, `PF_AUTHORITY_URL` and
   `PF_AUTHORITY_TOKEN_ENDPOINT`) is exempt from the scheme and address rules, pinned to its scheme, host, port and
   path, and nothing else is; the SSF receiver's transmitter may be at any address, since the operator names it, with
   the scheme left to the settings that already govern it. How to tell: a call that went through a proxy fails with
   `CONNECT_FAILED` or `CONNECT_TIMEOUT` where the host is reachable only through the proxy; a development PingOne
   issuer over http or on a private address fails enrolment with `REFUSED_URL` or `REFUSED_ADDRESS`. What to change:
   give PingFederate (or device-enrolment) a direct route to each peer, and for a development IdP set the
   `OIDF_FETCH_*` setting that admits it. On 2026-10-01 neither pf-oidf-modules nor idp-agentic-demo sets a proxy
   property in its repository ([U-0216](../../findings/U-0216.yaml)). There is no development-profile escape for the
   proxy, because there is no proxy support to fall back to.

## Notes

Package S5D (plan item S5d), 2026-10-01. F-0010 stays open as the umbrella for S-5; with S2C, S5B, S5C and this
package merged, no shipped module sends an outbound HTTP request except through libs/platform's `OutboundHttp`.

What moved, each through its caller's existing seam so that no wiring changed: `PushDeliveryService.httpClient`,
`PollReceiverClient.httpTransport`, `ReceiverStreamClient.httpTransport`, `ClientCredentialsToken.httpTransport`
(the send only; the spec's "beyond the send" left it open, and it was the last `java.net.http` client in SSF),
`JwksHttpSource.of`, `OpenBaoTransitSigner`, `HostedEntityRegistrar.PingFederate` with `AuthorityCredentials`
(the registrar hands its client to the token request, so both moved together), `PingOneIdTokenVerifier.HttpJwksSource`
and `PdpClient`. oidf-jose's `OutboundUrlPolicy` makes `addressPolicy()` and `refusal()` public, so push delivery and
PingOne's JWKS send through the same rules the federation fetches do.

Tested on JDK 20 and 17 (the reactor's `mvn clean verify`, 2026-10-01), each site against a peer that stalls before
its headers and one that sends its head and then a byte every 100 ms, each given up on at its deadline - the
shipped deadlines for the receiver's JWKS (2.5 s), poll (5 s), stream and token calls (5 s) and OpenBao (2.5 s), and
through each site's test seam for the others - with the connection seen closed by the peer; the body cap, declared
and chunked; TLS against a CA made by `keytool` for the run with a certificate for another name refused and the JVM's
own store refusing the test CA; each failure's mapping (push: retry, drop on a policy refusal, drop on a 400 with its
body clipped to 4096 characters; the receiver: a dependency, never `Misconfigured`; OpenBao and the enrolment calls:
the reason in the message; gm-api: `PdpUnavailableException`); an interrupt ending a push attempt within platform's
250 ms read slice with the interrupt kept; the configured OpenBao, PDP and authority URLs exempt and a `..` path
under them not. The jacoco METHOD gates hold; ssf's gate now names `PushDeliveryService.deliver` in place of the
removed `send` and `CappedBody.onNext`.

IMAGE_JAVA_RESULT

Two things this package kept as they were and recorded: a push endpoint whose host does not resolve is refused, not
retried, so its SET is dropped ([F-0405](../../findings/F-0405.yaml), for S-10); and request bodies are written
without a deadline, as everywhere on `OutboundHttp` ([U-0195](../../findings/U-0195.yaml)) - the bodies here are a
SET, a poll's acknowledgements, a transit sign request, an enrolment and an AuthZEN request, each well under the 14 KiB
U-0195 found can wait on a peer that does not read. OpenBao has no CA setting of its own; its certificate is the JVM
trust store's, as before. Whether PingFederate 13.1.3 replaces `HttpsURLConnection`'s default hostname verifier,
which decided gm-api's name check before, was not checked.

Owner actions (Phase 3 decisions 1-20 are unconfirmed): this package builds what the plan recommends, including
decision 17 (the SSF sites move in Phase 3 though S-10 rewrites push delivery in Phase 4).
