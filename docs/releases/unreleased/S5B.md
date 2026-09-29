# One budget of time and requests for each trust chain resolution

## Changelog

- A trust chain resolution spends one `ResolutionBudget`: a wall clock and a number of requests, over platform's
  `Budget`, thread-safe. Every request the resolution causes spends one request from it and is made by its
  deadline: each statement the validator asks for, and the gateway's own requests - an authority's Entity
  Configuration fetched to find its fetch endpoint, and the second retrieval of an anchor's Entity Configuration
  that did not verify (OpenID Federation 1.0 §11.3). A peer chain spends from a child of the same budget. A
  resolution that runs out is refused as `invalid_trust_chain`, saying whether it ran out of time or of requests,
  and never naming what it was fetching (plan item S5b; F-0010 stays open for S5c and S5d).
- `TrustMarkValidator.validate(chain, budget)` holds a Trust Mark validation to one budget: the anchor's
  configuration and each issuer are resolved from children of it, and each status call spends one request and ends
  by its deadline. `validate(chain)` makes a budget from the issuers' validator's options.
- `ValidationRequest.budget(...)` lets a caller hand a validation its own budget; the validation spends from a
  child of it holding at most the request's `maxFetches`.
- `HttpGetClient.get(url, accept, deadline)` and `HttpPostClient.post(..., deadline)` / `postForm(..., deadline)`
  take a `Deadline`. `JdkHttpClient` ends the exchange, the body included, by the sooner of it and its own 15 s
  request timeout, so a slow peer spends the resolution's time rather than a fresh timeout for each request.
- `TrustControllerGateway` gains overloads of `fetchEntityStatement`, `fetchSubordinateStatement` and
  `anchorConfiguration` that take the budget; their defaults forward to the overloads without it, so a gateway
  written before this compiles and behaves as it did.
- `ValidatorOptions.defaults()` reads a new settings catalogue, `federation-resolution`:
  `OIDF_FEDERATION_RESOLUTION_WALL_CLOCK_SECONDS` (45), `OIDF_FEDERATION_RESOLUTION_MAX_REQUESTS` (24),
  `OIDF_FEDERATION_RESOLUTION_MAX_AUTHORITY_HINTS` (10), `OIDF_FEDERATION_RESOLUTION_MAX_ROUTE_ATTEMPTS` (8) and
  `OIDF_FEDERATION_RESOLUTION_CLOCK_SKEW_SECONDS` (60). `ValidatorOptions` gains a seventh component,
  `resolutionWallClock`, and `withResolutionWallClock`; the package-private `TrustChainValidator.FetchBudget` is gone.
- U-0195 is closed: on the image's java 21.0.12.1 a lookup against a resolver that never answers gives up after
  about 5 s, and a connected socket's send buffer is larger than the 1 MiB request-body cap.

## Before you deploy

1. **A federation resolution now has a wall-clock budget.** From this release a trust chain resolution - automatic
   and explicit registration, the resolve endpoint, a client attestation's attester chain, and the Trust Mark
   issuers a registration checks - must finish on the network within `OIDF_FEDERATION_RESOLUTION_WALL_CLOCK_SECONDS`,
   45 seconds by default (1 to 300), counted from when it starts. Before it, each request had its own 15 s timeout
   and 24 requests could hold a request thread for six minutes. A peer slower than the budget gets its registration
   refused with `invalid_trust_chain` and the description "trust chain resolution ran out of time: its wall-clock
   budget of 45000 ms is spent; refusing to keep resolving"; the request that caused it fails rather than hangs. To
   tell, search the PingFederate server log for the WARN from
   `com.pingidentity.ps.oidf.federation.TrustChainValidator` that reads "Trust chain resolution for ... refused: it
   ran out of time", which gives how long the resolution took, how many requests it spent and both settings. If a
   federation you join is legitimately slower, raise `OIDF_FEDERATION_RESOLUTION_WALL_CLOCK_SECONDS` on every node.
   There is no development-profile escape, because this is tuning with a range, not a switch: the setting itself is
   the way out, up to 300 seconds.
2. **The trust controller's own lookups now count against the request budget.** The 24 requests a resolution may
   spend (`OIDF_FEDERATION_RESOLUTION_MAX_REQUESTS`, 1 to 256) used to count only the statements the validator asked
   for. They now also count each authority Entity Configuration the gateway fetches, uncached, to find a fetch
   endpoint, and each second retrieval of a trust anchor's Entity Configuration that did not verify, so one statement
   can cost up to three requests. A deep chain whose authorities are not yet cached can run out where it did not
   before. To tell, look for the same WARN reading "ran out of requests", or a refusal whose description reads "trust
   chain resolution ran out of requests: its budget of 24 requests is spent". Raise
   `OIDF_FEDERATION_RESOLUTION_MAX_REQUESTS` if your federations are that deep. The description also changed: it
   used to read "exceeded its fetch budget of 24 (last: ...)", naming the last fetch; anything that matches on the
   old text should match on "ran out of" instead. There is no development-profile escape, for the reason the item
   **A federation resolution now has a wall-clock budget** gives.
3. **Out-of-range federation-resolution settings stop a validator being built.** Each `OIDF_FEDERATION_RESOLUTION_*`
   setting is read, and refused naming the setting, when a trust chain validator is built: at start-up for most of
   them, and on the first request that needs one for the rest. A value
   outside its range, or one that is not a whole number, fails that start-up or request instead of being ignored.
   Nothing set these before this release, so a deployment that sets none of them sees no change; one that adds them
   checks them against [docs/configuration/federation-resolution.md](../../configuration/federation-resolution.md)
   first. The development profile does not relax a range: a range is a safety bound on how much work a stranger's
   chain can cause.
4. **Code that constructs `ValidatorOptions` passes the wall clock.** `ValidatorOptions` is a record whose canonical
   constructor now takes a seventh argument, `Duration resolutionWallClock`. Code built against an earlier release
   that calls `new ValidatorOptions(...)` with six arguments does not compile, and a jar compiled against it fails
   with `NoSuchMethodError` when it runs. Nothing in this repository does; a consumer that does - a sibling repository
   building its own validator - changes to `ValidatorOptions.defaults()` and the `with...` methods, or passes
   `ValidatorOptions.DEFAULT_RESOLUTION_WALL_CLOCK`. This is an API change, so there is no profile escape.

## Notes

**The measurements behind the wall clock's default** (2026-09-29, this branch at 2e9242d5, DEBUG on
`TrustChainValidator`). On the conformance rig (`PF_PROFILE=federation-op`, PingFederate 13.1.3, the suite at
release-v5.3.1 on the same Docker host) the successful resolutions took 179 ms (the suite's relying party, 4
requests, cold, plan `g3wLhsJueO2zv`), 85 ms (the same relying party, next run's keys, plan `kP63AXqiOpCZx`) and 5 ms
(PingFederate's own chain, plan `xyVeQDsQoS533`); the three plans finished with no failure. That is loopback. Against
a federation on the internet - this validator on this machine in Australia, resolving ten entities chosen at random
from the list of the Italian public-sector anchor `https://oidc.registry.servizicie.interno.gov.it` - eight took 4.3 s
to 14.5 s before a check that has nothing to do with time refused them (each `trust_marks` entry carries `id` where
§3.1.2 has `trust_mark_type`), and two stopped at 2.2 s and 9.7 s on leaves that did not answer. The default is three
times the longest, 14.5 s, rounded up: 45 s. It is a ceiling on one request thread, not a target. U-0290 records
that it has not been checked against a deployment's own federations.

**The bound the budget cannot enforce** (2026-09-30, the image's java 21.0.12.1, `docker run --dns 10.255.255.1`):
`InetAddress.getAllByName` against a resolver that never answers gave up after 5017 ms, and a connected loopback
socket's send buffer was 1,313,280 bytes, above the 1 MiB request-body cap. `OutboundHttp` refuses to start a request
once its deadline has passed, so a resolution overruns its wall clock by at most one lookup, about 5 s. U-0195 is
closed with these figures.

**Tuning and safety bounds.** The five settings are tuning. `TrustChainValidator.MAX_ROUTE_STATEMENTS` (16),
`MAX_SEARCH_STEPS` (128), `TrustMarkValidator.MAX_MARKS_EXAMINED` (16) and `MAX_ISSUERS_RESOLVED` (8) stay constants:
they are safety bounds on the work a presented chain causes at no request at all, and nothing measured says they
must move.

**Not done here.** `FederationService.resolve` and the registration paths still validate a chain on one budget and
its Trust Marks on a second (F-0280); S5c passes one budget through registration. F-0010 stays open as the umbrella
for S5c and S5d. U-0215 (whether 32 places an origin are enough) was not measured.

**Tests.** `TrustChainValidatorBudgetTest` (a slow-body peer across a multi-hop chain cut off at the wall clock, the
gateway's authority-configuration and key-mismatch fetches counted, a peer chain sharing the budget),
`TrustMarkValidatorTest` (several issuers bounded by one parent budget, the status call spent),
`ResolutionBudgetTest` (concurrent spends, children, what ran out), `ValidatorOptionsSettingsTest` (defaults and
ranges) and `JdkHttpClientDeadlineTest` (a caller's deadline ends a slow body). Run on JDK 17 and 20, and the
networking tests on the image's java 21.
