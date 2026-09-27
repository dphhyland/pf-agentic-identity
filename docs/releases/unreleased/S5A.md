# Outbound HTTP pinned to checked addresses, with deadlines, budgets and capped bodies

## Changelog

- `platform.http`: an outbound HTTP/1.1 client (`OutboundHttp`) that resolves a host once, checks every address
  it resolves to, and connects only to one of those, with the host name kept as TLS SNI and checked against the
  certificate. Every read is bounded by what is left of a connect, header or total deadline, and the body by a
  cap, whether its length is declared, chunked or delimited by close. GET, POST, PUT, PATCH and DELETE, headers on
  every method, the status always returned, no redirects. With it: `Deadline`, `Budget` (a wall clock and a
  request count, with child budgets), `AddressPolicy` (oidf-jose's URL rules, plus 0.0.0.0/8, 240.0.0.0/4,
  Teredo, and the IPv6 forms that embed a non-public IPv4 address), `TlsTrust` and a `Bulkhead` seam
  (plan item S5a, part 1). Nothing calls it yet.
- The platform jar now carries Apache HttpComponents Core 5.4.4, relocated under
  `com.pingidentity.ps.oidf.platform.http.internal.hc5` and minimised; it grows from 227 KB to 448 KB.

## Before you deploy

None.

## Notes

Nothing uses `platform.http` in this release's part: S5AR moves oidf-jose's `JdkHttpClient` and `OutboundUrlPolicy`
onto it next and closes F-0070; F-0010 waits for S5d, which moves the remaining call sites. The platform jar is
staged and shaded exactly as before - only its size changes - and HttpCore inside it is relocated, so it cannot
meet the httpcore5 5.3.4 PingFederate 13.1.3 ships in `server/default/lib`.

The plan asked for `java.net.http` with a capped subscriber and connect-time address pinning; the JDK client
resolves the host itself and has no per-client resolver on JDK 17 or 21, so pinning is done on a socket platform
opens, with HttpCore's HTTP/1.1 message layer on it. `libs/platform/README.md` ("http") has the evidence, the
comparison with httpclient5 and Jetty, and the address rules. Two blocking steps stay outside every deadline -
name resolution and request writes - recorded as U-0195; U-0196 records the one address rule that can refuse
wrongly (a NAT64 local-use prefix whose own bits read as a private address).

Verified 2026-09-28: the platform tests (a local HTTP and HTTPS server with a CA made for the run, a stub
resolver, slow and malformed peers, and 600 randomised responses) on JDK 17 and 20 in the reactor, and the TLS
tests on the pinned image's own java 21.0.12.1.
