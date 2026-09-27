# Federation fetches connect only to the address they checked, and one peer gets at most 32 at once

## Changelog

- oidf-jose's `JdkHttpClient` (and `JdkHttpGetClient`, which delegates to it) sends through platform's
  `OutboundHttp` instead of the JDK's `java.net.http` client. `OutboundUrlPolicy` resolves the host once, checks
  every address, and the connection goes to one of those addresses and nowhere else, with TLS still checking the
  certificate against the URL's host. A name that answers publicly for the check and privately for the connection
  (DNS rebinding) now reaches nothing; before, the JDK client resolved the name again and connected where the second
  answer said (finding F-0070, closed). Every federation fetch, entity statement, JWKS, trust mark status and AuthZEN
  PDP request made through these classes is covered; the public API, the 8 s connect and 15 s request timeouts,
  HTTP/1.1, no redirects and the body cap are unchanged.
- The 15 s request timeout now bounds the whole exchange, the body included. The JDK client's stopped once the
  headers arrived, so a peer could trickle a body for as long as it liked.
- A per-origin bulkhead: at most 32 requests to one `scheme://host:port` run at once in each loaded copy of
  oidf-jose. A request that finds all 32 places taken waits for one until its own deadline and then fails as a
  failed fetch (platform's `OutboundHttpException`, reason `BULKHEAD_FULL`), which every caller already handles as
  it handles a timeout. `platform.http.HostBulkhead` is the implementation; there is no setting.
- `OutboundUrlPolicy`'s scheme and address rules are now platform's `AddressPolicy`, so federation fetches refuse
  the addresses platform refuses and the old policy did not: 0.0.0.0/8, 240.0.0.0/4, the three IPv4
  documentation ranges, all of IPv6 ::/96, discard-only 100::/64, Teredo 2001::/32, 2001:db8::/32, and the
  IPv4-translated, NAT64 and 6to4 forms that embed a non-public IPv4 address. A path with a dot segment, a backslash
  or a percent sign left after one decoding is never inside a `trusting()` exemption. The `OIDF_FETCH_*` settings
  mean what they meant.
- A platform `OutboundHttp` read on a silent peer now ends when its thread is interrupted, as the JDK client's did,
  so closing the subordinate refresher's executor still stops a fetch in progress (finding F-0205, closed).

## Before you deploy

1. **Check whether federation fetches go through a proxy set for the JVM.** `OutboundHttp` connects directly to
   the checked address and ignores `https.proxyHost`, `http.proxyHost` and `socksProxyHost`; the JDK client used
   the JVM's default proxy selector, which reads them. A PingFederate that reaches federation peers, JWKS URIs or
   an AuthZEN PDP only through such a proxy will find those fetches fail to connect. Neither pf-oidf-modules nor
   idp-agentic-demo sets one (read 2026-09-28). If yours does, allow direct egress to those peers before upgrading.
2. **Check that certificates name the hosts you fetch from, even with OIDF_FEDERATION_IGNORE_SSL_ERRORS on.** The
   JVM-wide `-Djdk.internal.httpclient.disableHostnameVerification=true` governs the JDK client only, and nothing
   here turns host name checking off. idp-agentic-demo's `pingfederate/Dockerfile:73` sets that property (finding
   F-0035), so a federation peer, trust controller or PDP whose certificate does not name the host in the URL it is
   fetched by - an IP address, or an internal name the certificate lacks - worked there before and is now refused
   as a TLS failure. Fix the certificate or the URL.
3. **Check that no peer is served from a newly refused address.** Federation fetches now refuse the ranges listed
   in the Changelog. A name that resolves to both a public and a private address was refused before as well, and
   still is. A trust controller or other operator-configured endpoint on such an address still passes when it is
   exempted by `trusting()` or named in `OIDF_FETCH_HOST_ALLOWLIST`.
4. **Check that no single peer needs more than 32 requests from one node at once.** Only a peer that is slow as well
   as busy can fill the 32 places: a request waits for a place up to its own 15 s deadline before it fails. A
   trust controller answering in a few hundred milliseconds serves about a hundred requests a second from each
   node before anything waits.

## Notes

- Also new, and not expected to matter: a POST body over 1 MiB, a request header outside printable ASCII, and the
  framing headers (`Connection`, `Keep-Alive`, `TE`, `Trailer`, `Upgrade`, `Expect`, `Transfer-Encoding`) are
  refused before sending; a response with both `Transfer-Encoding` and `Content-Length`, more than 100 headers or a
  header line over 8192 bytes is a malformed response; requests carry `User-Agent: pf-agentic-identity` instead of
  the JDK's `Java-http-client/<version>`. No caller in the repository sends any of the refused headers.
- A host that does not resolve is still a refusal (an `IllegalArgumentException`) where the address rule applies,
  and still a transport failure where it does not (`OIDF_FETCH_ALLOW_PRIVATE_NETWORKS`, an allow-listed host or a
  `trusting()` endpoint), as before.
- `OutboundUrlPolicy.check` on its own still only checks. The SSF push delivery screens with it and then sends
  through its own JDK client, which resolves the name again; S5d moves it and the other call sites that bypass
  platform's client, and closes F-0010 with them.
- The bulkhead limits sockets and load on one peer, not the threads waiting to reach it: a request waiting for a
  place holds its caller's thread until its deadline.
- Verified 2026-09-28 on JDK 17, 20 and the pinned image's java 21.0.12.1: a name the policy's resolver answers
  publicly and the system resolver answers with loopback reached a loopback server through the old client (one hit)
  and reaches nothing through the new one (`JdkHttpClientPinningTest`).
