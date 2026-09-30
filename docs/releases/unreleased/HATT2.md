# Forwarding headers are believed only from your proxies, and the attester's issuance endpoint is capped, limited and quiet about its internals

## Changelog

- New platform rule, `platform.net.TrustedProxies` (plan item H-ATT-3): `OIDF_TRUSTED_PROXIES` lists, as CIDR ranges,
  the proxies whose forwarding headers are believed; unset (the default), none is. From a listed proxy the client
  address is the right-most forwarding hop it does not list, and the scheme and host are what it says.
  `OIDF_TRUSTED_PROXIES_HEADERS` chooses `x-forwarded` (the default) or RFC 7239 `forwarded`. The catalogue is
  [`trusted-proxies`](../../configuration/trusted-proxies.md).
- Both attestation challenge endpoints, the attester's issuance endpoint and the operator APIs' failed-authentication
  limit count callers by that client address, so behind a listed proxy each client has its own allowance
  ([F-0116](../../findings/F-0116.yaml), [F-0275](../../findings/F-0275.yaml)).
- `POST /federation/attestation` (plan item H-ATT-2, [F-0060](../../findings/F-0060.yaml)) reads at most
  `OIDF_ATTESTER_MAX_BODY_BYTES` (32768, 4096 to 262144) and answers `413 invalid_request` beyond it; allows each client
  address `OIDF_ATTESTER_ISSUANCE_REQUESTS_PER_MINUTE` (60) requests a minute, in Redis when `OIDF_REDIS_URL` is set,
  and answers `429 temporarily_unavailable` with `Retry-After` past it; answers every failure with a CAS §4.6 code and
  an `X-Correlation-Id` header, a `5xx` or `invalid_client` with a fixed description instead of the exception's text;
  and answers other methods `405`.
- The attester matches evidence against a cached index of PingFederate's attestation clients, rebuilt every
  `OIDF_ATTESTER_CLIENT_INDEX_REFRESH_SECONDS` (30) and after a miss at most once every 5 s, instead of reading every
  PingFederate client on every request.
- `/.well-known/client-attester` and `/federation/attester-configuration` build their URLs from `X-Forwarded-*` only
  when a listed proxy sent them, and send `Access-Control-Allow-Origin` only to the origins
  `OIDF_ATTESTER_CORS_ORIGINS` lists, none by default, for `GET` ([F-0061](../../findings/F-0061.yaml)).

## Before you deploy

1. **Name your proxies in `OIDF_TRUSTED_PROXIES`.** What to do: if PingFederate sits behind a load balancer, reverse
   proxy or TLS terminator, set `OIDF_TRUSTED_PROXIES` to the addresses PingFederate sees them connect from, as CIDR
   ranges or single addresses, space- or comma-separated (`10.0.0.0/8`, `2001:db8:1::/48`), and set
   `OIDF_TRUSTED_PROXIES_HEADERS=forwarded` if they write RFC 7239 `Forwarded` rather than `X-Forwarded-For`. Your
   proxies must append to `X-Forwarded-For` (or `Forwarded`) and set or overwrite `X-Forwarded-Proto` and
   `X-Forwarded-Host`. Why: before 0.6.0 the attester's configuration document took `X-Forwarded-Proto` and
   `X-Forwarded-Host` from any caller, so anyone could make it advertise a host of their choosing, while the challenge
   endpoints read no forwarding header at all, so every caller behind a proxy shared one allowance. From 0.6.0 forwarding
   headers are ignored from anyone not listed. How to tell: with the list unset behind a proxy, the challenge endpoints
   answer `429 slow_down` to everyone once 60 requests a minute arrive in all, the issuance endpoint answers
   `429 temporarily_unavailable` the same way, the operator APIs lock everyone out after ten failed authentications,
   and `/.well-known/client-attester` names PingFederate's own host and scheme (`http://...:9031`) instead of your
   public one. A value that is not a CIDR list leaves both challenge endpoints and the attester's issuance and
   configuration servlets `FAILED_CONFIG` at deploy, naming `OIDF_TRUSTED_PROXIES`. What to change: set the list. If
   you configured PingFederate's own incoming proxy settings (a client IP header), read the platform README's "net"
   section: PingFederate believes that header from any sender, so use it only with index `LAST` and a network where
   every request reaches PingFederate through your proxy. Development-profile escape: none - the default believes no
   header, which is the safe reading in both profiles; on a rig without a proxy nothing changes.
2. **The attester's issuance endpoint is rate-limited and caps its body.** What to do: check that no single client
   address sends more than 60 issuance requests a minute - a workload normally asks once per attestation lifetime -
   and that no request body exceeds 32 KiB; raise `OIDF_ATTESTER_ISSUANCE_REQUESTS_PER_MINUTE` (up to 100000) for many
   workloads behind one NAT address, or `OIDF_ATTESTER_MAX_BODY_BYTES` (up to 262144) for very large
   `authorization_details` or evidence. Why: before 0.6.0 the endpoint read a body of any size and served requests
   without limit, each one reading every PingFederate client. How to tell: `429 temporarily_unavailable` with
   `Retry-After` for the limit, `413 invalid_request` "the request body is larger than 32768 bytes" for the cap. Every
   error now carries an `X-Correlation-Id` header; a `5xx` or `invalid_client` no longer carries the exception's text
   in `error_description` but a fixed sentence naming that id, and PingFederate's server log has the detail at WARN
   under it, so search the log for the id rather than reading the response. A client disabled or deleted in
   PingFederate stops being issued attestations within `OIDF_ATTESTER_CLIENT_INDEX_REFRESH_SECONDS` (30) rather than
   at once. What to change: the settings above; lower the refresh interval if a client must stop sooner. Without
   `OIDF_REDIS_URL` each node counts for itself, which needs no accepted risk. Development-profile escape: none; the
   settings apply in both profiles.
3. **The attester configuration no longer answers browsers from any origin.** What to do: if a browser application,
   such as an operator console or a developer portal, reads `/.well-known/client-attester` or
   `/federation/attester-configuration` with `fetch` from another origin, list its origin in
   `OIDF_ATTESTER_CORS_ORIGINS` (`https://console.example`, space- or comma-separated; `*` is refused). Why: before
   0.6.0 every origin got `Access-Control-Allow-Origin: *`, so any web page could read the documents through a
   visitor's browser, including where the browser can reach an attester the page's author cannot. Workloads and SDKs
   fetch the documents from servers, which CORS does not restrict, so they need nothing. How to tell: the browser's
   console reports a CORS failure; the server answers 200 as before, without the header. A value that is not a list
   of origins leaves the configuration servlet `FAILED_CONFIG`, naming the setting. What to change: set the variable.
   Development-profile escape: none; list the rig's origin if a browser there needs it.

## Notes

What PingFederate does with forwarding headers was read, not assumed (HATT2's "verify first", 2026-09-30): the
pinned 13.1.3 image's `bin/run.properties` has only outbound proxy properties, and
`com.pingidentity.appserver.jetty.server.customizer.ForwardedRequestCustomizer` (in `server/default/lib/pf-appserver-ext.jar`,
added to the runtime connector by `etc/jetty-runtime.xml`) takes the header its incoming proxy settings name, first or
last value, as the remote address from any sender, and changes nothing when none is named, its default. PingFederate
cannot be told its proxies, so `TrustedProxies` does not defer to it; [U-0400](../../findings/U-0400.yaml) asks for the
rig to exercise the configured case. F-0116's 2026-09-27 rig result is the unset case.

CAS §4.6 says "Errors use HTTP 400 (or the status noted: 401, 403, 500 or 503)". The body cap answers `413` and the
limit `429`, each with a §4.6 code (`invalid_request`, `temporarily_unavailable`), since RFC 9110 and RFC 6585 name
those conditions; the draft's table may want the two statuses added.

Built on JDK 17 and 20 and run on 21; the Redis test of the shared limit runs where `OIDF_TEST_REDIS_URL` is set (CI's
java job). Not exercised on the rig. [F-0390](../../findings/F-0390.yaml) records the other discovery documents that
still answer every origin, and [F-0391](../../findings/F-0391.yaml) that an IPv6 client is keyed by its full address.
F-0275 (the operator limit behind a proxy, S8A's) is fixed by this change and left for its owner to close.
