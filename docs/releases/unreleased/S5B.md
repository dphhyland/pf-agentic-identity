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
- `TrustMarkValidator` rejects a Trust Mark larger than 8192 bytes (`MAX_STATUS_MARK_BYTES`) rather than send it to
  its issuer's status endpoint: a socket write has no timeout, and a larger body could wait past the budget on an
  endpoint that never reads. A Trust Mark check whose budget runs out while it resolves the anchor's configuration
  now says so in each mark's reason. U-0195 stays open: other `OutboundHttp` writes above about 14 KiB can still wait
  on a peer that does not read.

## Before you deploy

1. **A federation resolution now has a wall-clock budget.** From this release a trust chain resolution - automatic
   and explicit registration, the resolve endpoint, a client attestation's attester chain, and the Trust Mark
   issuers a registration checks - must finish on the network within `OIDF_FEDERATION_RESOLUTION_WALL_CLOCK_SECONDS`,
   45 seconds by default (1 to 300), counted from when it starts. Before it, each request had its own 15 s timeout
   and 24 requests could hold a request thread for six minutes. A peer slower than the budget gets its registration
   refused with `invalid_trust_chain` and the description "trust chain resolution ran out of time: its wall-clock
   budget of 45000 ms is spent; refusing to keep resolving"; the request that caused it fails rather than hangs. To
   tell, search the PingFederate server log for the WARN from
   `com.pingidentity.ps.oidf.federation.TrustChainValidator` that reads "Trust chain resolution for ... refused after
   ... ms and ... requests: trust chain resolution ran out of time", which gives how long the resolution took, how
   many requests it spent and both settings. If a
   federation you join is legitimately slower, raise `OIDF_FEDERATION_RESOLUTION_WALL_CLOCK_SECONDS` on every node.
   There is no development-profile escape, because this is tuning with a range, not a switch: the setting itself is
   the way out, up to 300 seconds.
2. **The trust controller's own lookups now count against the request budget.** The 24 requests a resolution may
   spend (`OIDF_FEDERATION_RESOLUTION_MAX_REQUESTS`, 1 to 256) used to count only the statements the validator asked
   for. They now also count each authority Entity Configuration the gateway fetches, uncached, to find a fetch
   endpoint, and each second retrieval of a trust anchor's Entity Configuration that did not verify, so one statement
   can cost up to three requests. A deep chain whose authorities are not yet cached can run out where it did not
   before. To tell, look for the same WARN with "ran out of requests" in it, or a refusal whose description reads
   "trust chain resolution ran out of requests: its budget of 24 requests is spent". Raise
   `OIDF_FEDERATION_RESOLUTION_MAX_REQUESTS` if your federations are that deep. The description also changed: it
   used to read "exceeded its fetch budget of 24 (last: ...)", naming the last fetch; anything that matches on the
   old text should match on "ran out of" instead. There is no development-profile escape, for the reason the item
   **A federation resolution now has a wall-clock budget** gives.
3. **A Trust Mark check now shares one request budget across all its issuers.** Before this release each Trust
   Mark issuer was resolved on a fresh budget of 24 requests and each status call was not counted at all. Now
   `TrustMarkValidator.validate(chain)`, which registration and the resolve endpoint call, makes one budget of
   `OIDF_FEDERATION_RESOLUTION_MAX_REQUESTS` (24 by default) and the wall clock for the whole check: the anchor's
   configuration, every issuer it resolves (up to 8) and every status call spend from it. An entity carrying marks
   from several issuers, with status checking on, can now have marks rejected that verified before, and if
   `TrustMarkPolicy` requires one of those marks the registration is refused. To tell, look for a rejected mark
   whose reason reads "its issuer ... was not resolved: trust chain resolution ran out of requests", "the trust
   anchor's configuration, which says whose Trust Marks it recognises, was not read: trust chain resolution ran out
   of requests" or "its status was not asked: trust chain resolution ran out of requests". Raise `OIDF_FEDERATION_RESOLUTION_MAX_REQUESTS` if
   your entities carry marks from many issuers. There is no development-profile escape, for the reason the item
   **A federation resolution now has a wall-clock budget** gives.
4. **A Trust Mark larger than 8 KiB is no longer sent to a status endpoint.** With Trust Mark status checking on
   and an issuer that publishes `federation_trust_mark_status_endpoint`, a mark whose JWT is larger than 8192 bytes
   is now rejected, with the reason "its status was not asked: it is larger than the 8192 bytes a status request
   carries", and is never sent. Before this release it was posted whatever its size. A write has no timeout, so a
   large body sent to an endpoint that accepts and never reads - one a self-issued mark can name - could hold a
   request thread past the resolution's wall clock. To tell whether your marks are affected, look for that reason
   among the rejected marks, or measure the `trust_mark` values in your entities' configurations. The limit is a constant, a safety bound, so there is no setting and no development-profile escape.
5. **Out-of-range federation-resolution settings stop a validator being built.** Each `OIDF_FEDERATION_RESOLUTION_*`
   setting is read, and refused naming the setting, when a trust chain validator is built: at start-up for most of
   them, and on the first request that needs one for the rest. A value
   outside its range, or one that is not a whole number, fails that start-up or request instead of being ignored.
   Nothing set these before this release, so a deployment that sets none of them sees no change; one that adds them
   checks them against [docs/configuration/federation-resolution.md](../../configuration/federation-resolution.md)
   first. The development profile does not relax a range: a range is a safety bound on how much work a stranger's
   chain can cause.
6. **Code that constructs `ValidatorOptions` passes the wall clock.** `ValidatorOptions` is a record whose canonical
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

**The rig on the final code** (2026-09-30, the image built from this branch at d3d8934c, slot 3,
`PF_PROFILE=federation-op`, the suite at release-v5.3.1): `openid-federation-entity-joined-to-test-federation-op-test-plan`,
plan `1IagM1TIgHkl4`, 20 modules, 20 WARNING, 0 FAILED, PingFederate resolving the suite relying party's chain and
registering it automatically; `openid-federation-deployed-entity-test-plan`, plan `1xjZtsQkLc3B2`, 5 modules, 5
WARNING, 0 FAILED. The warning is the suite's note on PingFederate's vendor metadata, as on 0.5.0.

**The bound the budget cannot enforce** (2026-09-30). On the image's java 21.0.12.1 with `docker run --dns
10.255.255.1`, `InetAddress.getAllByName` against a resolver that never answers gave up after 5017 ms; `OutboundHttp`
refuses to start a request once its deadline has passed, so a lookup costs at most about 5 s past it. A write has no
timeout either. A connected loopback socket's send buffer on Docker Desktop was 1,313,280 bytes, but that is
loopback's: between two python:3.13-alpine containers on a Docker bridge with MTU 1500 it was 46,080 bytes at connect
(MSS 1448), and writing 1 KiB at a time to a peer that never read, the first write to wait came after 611,328 bytes
with the peer's receive buffer at its default, 27,648 with it at 4096 and 14,336 with it at 1 (MSS 576). A 9 KiB
write returned at once in all three. The resolution's one request body, the Trust Mark status call, is held to a
mark of 8192 bytes, so a resolution overruns its wall clock by at most one lookup. U-0195 stays open for the other
`OutboundHttp` writes.

**Tuning and safety bounds.** The five settings are tuning. `TrustChainValidator.MAX_ROUTE_STATEMENTS` (16),
`MAX_SEARCH_STEPS` (128), `TrustMarkValidator.MAX_MARKS_EXAMINED` (16) and `MAX_ISSUERS_RESOLVED` (8) stay constants:
they are safety bounds on the work a presented chain causes at no request at all, and nothing measured says they
must move.

**Not done here.** `FederationService.resolve` and the registration paths still validate a chain on one budget and
its Trust Marks on a second (F-0280); S5c passes one budget through registration. F-0010 stays open as the umbrella
for S5c and S5d. U-0215 (whether 32 places an origin are enough) was not measured.

**Tests.** `TrustChainValidatorBudgetTest` (a slow-body peer across a multi-hop chain cut off at the wall clock, a body still
arriving at the deadline cut off there, every gateway request carrying the resolution's deadline and paid from the
caller's budget - directly and through `LocalFirstTrustControllerGateway`, a refresh of a presented statement and a
requested anchor configuration retrieved twice included - the gateway's authority-configuration and key-mismatch
fetches counted, a peer chain sharing the budget),
`TrustMarkValidatorTest` (several issuers bounded by one parent budget, the status call spent, the anchor's
configuration refused saying the budget ran out, a mark too large to send never sent),
`ResolutionBudgetTest` (concurrent spends, children, what ran out), `ValidatorOptionsSettingsTest` (defaults and
ranges) and `JdkHttpClientDeadlineTest` (a caller's deadline ends a slow body). On 2026-09-30 at the final code
the two modules' whole suites passed on JDK 17 with their coverage gates, and `TrustChainValidatorBudgetTest`,
`TrustMarkValidatorTest`, `ResolutionBudgetTest` and `JdkHttpClientDeadlineTest` passed on JDK 20.0.2 and on Temurin
21.0.12 (the image's java line).
