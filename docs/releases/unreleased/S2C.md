# The RAR plugin's PDP call: deadlines, TLS trust, a bulkhead, a circuit breaker, a memo, a cache and the AuthZEN batch

## Changelog

- The RAR plugin calls its PDP through libs/platform's `OutboundHttp` instead of the JDK's `java.net.http`: a 2.5 s
  total deadline by default (connect at most 1 s of it, the body included), a 64 KiB answer cap, HTTP/1.1 and no
  redirects, with the host name always checked (plan item S2c, and S5d's call site in this plugin; F-0010).
- New "PDP TLS trust" field: `jvm-default` (default), `pingfederate-trusted-cas` (PingFederate's trusted CAs through
  the SDK's `TrustedCAAccessor`) or `pinned-ca` with "PDP CA certificates (PEM)".
- At most 32 PDP calls at once per processor instance, and a circuit breaker ("Circuit breaker failures", 5;
  "Circuit breaker open (s)", 30) that counts only transport failures.
- One PDP decision per question per HTTP request, however often PingFederate asks; an optional per-type decision
  cache ("Decision cache types", "Decision cache TTL (s)", at most 60 s) that never holds `payment_initiation` or a
  type requiring an authenticated principal.
- With "AuthZEN batch URL" set (the `authzen` dialect), every detail of a token request is decided in one OpenID
  AuthZEN 1.0 Access Evaluations call; an answer that does not list one decision per evaluation is refused.
- Metrics `oidf_rar_pdp_calls_total`, `oidf_rar_pdp_answers_total` and `oidf_rar_pdp_breakers` in the plugin's own
  metrics MXBean.
- The README and the plugin's skill no longer mention `jdk.internal.httpclient.disableHostnameVerification` as a
  workaround: the plugin does not need it.

## Before you deploy

1. **The PDP call now has a 2.5 s total deadline.** Before 0.6.0 "Request timeout (ms)" defaulted to 10000 and
   bounded the connection and the wait for the response headers, not the body. From 0.6.0 the same field is the
   deadline for the whole exchange, from connecting to the last byte of the answer, defaults to 2500 and is held to
   1000-10000; an instance that stored 10000 keeps 10000, now as a total. A PDP that answers slower than the
   deadline is unreachable: the detail is refused, or granted without the PDP's narrowing where "Fail open on
   engine error" is on (the `pdp-fail-open` accepted risk). How to tell: the server log carries `PDP unreachable
   (HEADER_TIMEOUT)` or `PDP unreachable (DEADLINE)` for the type, and
   `oidf_rar_pdp_calls_total{outcome="unreachable"}` rises. What to change: measure the PDP's slowest answers and set "Request timeout (ms)" above them, at most
   10000. There is no development-profile escape, because the deadline applies in every profile; the field is the
   control.
2. **Choose how the plugin trusts the PDP's certificate.** The new "PDP TLS trust" field defaults to `jvm-default`,
   the JVM's CA certificates, which is what 0.5.0 trusted. `pingfederate-trusted-cas` trusts the CAs under
   Security, Trusted CAs as well as the JVM's; `pinned-ca` trusts only the CA certificates pasted into "PDP CA
   certificates (PEM)". In every mode the PDP's certificate must now name the host in the PDP URL (and in the
   AuthZEN batch URL): platform's client checks it on every call and nothing turns that off, so a PDP certificate
   that does not name its host, which a JVM started with the hostname flag below used to accept, now fails. How to
   tell: every decision is refused, the server log's `PDP call failed` line carries `the TLS handshake with
   <origin> failed`, and fail-open does not apply. What
   to change: reissue the PDP certificate with a subject alternative name for the host PingFederate dials, and pick
   the mode that holds its CA. In development "Skip TLS verification (dev only)" still trusts any chain, but not a
   certificate for another name: there is no escape from the host-name check, because that check is what stops a
   certificate for one host passing for another.
3. **The JVM-wide hostname flag is no longer needed or wanted.** Older notes for this plugin, and
   idp-agentic-demo's `Dockerfile.fragment`, add `-Djdk.internal.httpclient.disableHostnameVerification=true`.
   The plugin no longer uses `java.net.http`, so the flag does nothing for it, while it still turns host-name
   checks off for every other `java.net.http` client in that PingFederate. How to tell: `ps` or the image's
   `JAVA_OPTS` shows the property. What to change: remove it wherever the image sets it (in idp-agentic-demo,
   `pingfederate/Dockerfile` and `pingfederate/rar-paz/Dockerfile.fragment`), and give the PDP a certificate that
   names its host ("Choose how the plugin trusts the PDP's certificate"). A production
   deployment refuses the property from 0.6.0 (plan item PR-5, F-0035); a development deployment is not refused,
   but nothing in this repository needs the flag there either.

## Notes

Package S2C (plan item S2c, and S5d's RAR call site), 2026-09-29/30.

Verified before any code, 2026-09-29: pingfederate-sdk 13.1.3.0 has `public final class
com.pingidentity.access.TrustedCAAccessor` with `public java.util.Set<java.security.cert.TrustAnchor>
getAllTrustAnchors()` (javap), which `pingfederate-trusted-cas` reads; PingFederate calls `enrich` once per detail,
in order, on the request's thread - `AuthorizationDetailsUtil.enrich` runs `List.forEach` over the details (javap of
pf-protocolengine 13.1.3.0) - which the per-request memo and the batch rest on; and OpenID AuthZEN Authorization API
1.0 (Final, 11 January 2026) section 7 defines the `evaluations` request and section 7.2 a response that "lists the
decisions in the same order they were provided in the evaluations array in the request". The batch correlates by
position alone ([F-0290](../../findings/F-0290.yaml)).

Tested on JDK 20 and 17 (`mvn verify` of the plugin, 2026-09-30): deadlines against a server that stalls before its
headers and one that dribbles its body, the 64 KiB cap, each trust mode against a CA made in the test with a name
mismatch refused in each, the bulkhead full, the breaker's open, half-open and close on a fake clock and which
failures trip it, the memo across repeated `enrich` calls, the cache's refusal of payment and principal-required
types with its TTL and key, the batch's happy path and each malformed answer; `ShadedJarCheck` finds platform only
relocated, with its HttpCore inside it; the jacoco METHOD gate holds the new classes at 100%.

On the rig, 2026-09-30 (slot 5, PingFederate 13.1.3.0, `ONLY_CONFIGURE=1 conformance/verify-rar-principal.sh`, the
instance pointed at a stub AuthZEN PDP with "AuthZEN batch URL" set): one client-credentials token request with
three `sales_agent` details answered 200 with all three, PingFederate called `enrich` three times, and the PDP
received one `POST /access/v1/evaluations` with three evaluations and no single evaluation. PingAuthorize's own
AuthZEN servlet in `plugins/rar-paz-plugin/paz` could not be booted: the profile's licence expired on 2026-08-12
([U-0302](../../findings/U-0302.yaml)).

Tested on the pinned image's Java, OpenJDK 21.0.12.1: the TLS, transport, breaker, decision and processor
resilience tests, 53 of 53. `tools/pf-linkcheck.py` against the 13.1.3.0 libraries: nothing unresolved.

Not seen on a running PingFederate: the `pingfederate-trusted-cas` mode with a CA added in the console
([U-0300](../../findings/U-0300.yaml)) and the metrics in PingFederate's JMX ([U-0301](../../findings/U-0301.yaml)).

F-0010 stays open as the umbrella for S-5; this package moves the RAR plugin's call site, S5d's last in this plugin.
