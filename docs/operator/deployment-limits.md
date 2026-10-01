# Deployment limits

What a release built from this repository does not support yet, and what goes wrong if you deploy it that way
anyway. One section per limit; each names the release expected to lift it.

## One PingFederate node, until 0.7.0

0.6.0, like 0.4.0 and 0.5.0, supports **a single PingFederate engine node**. Several pieces of state the modules keep are per node - in
memory, or behind a loop that assumes it is the only one - and the cluster story that makes them shared is
Phase 4 of the production programme, release 0.7.0: Redis-backed state through one platform client, leases for
background work such as SSF push, JDBC client storage, and a cluster verification suite run on reference
stacks ([F-0007](../findings/F-0007.yaml)). Until then, run one engine node, and do not put two behind a load
balancer.

Some of the state below can be shared today by configuring a store - Redis for the attestation stores, a JDBC
data store for SSF and the federation authority - and that removes the in-memory half of the problem. It does
not make a cluster supported: the SSF push loop has no lease, the SSF receiver's dedupe and the challenge
endpoints' caps stay per node, and nobody has run the modules on two nodes. The SSF module's boot log calls a
JDBC-backed store "cluster-safe"; in 0.4.0 and 0.5.0 it is not ([F-0125](../findings/F-0125.yaml)); 0.5.0's
reactor build logged it again on 2026-09-29 (`SSF store: JDBC data store 'pf-ds', dialect 'tables'
(cluster-safe, durable)`, from the SSF tests).

What goes wrong on two nodes today, read from the code on 2026-09-27 (origin/main `714e7ce`) and not driven on a
cluster. Phase 2 (0.5.0) moved none of it: the platform Redis client (C-2) keeps 0.4.0's keys and adds nothing
shared, and the managed executors' one-of-each-job claim (C-3) is per JVM, not per cluster, so each node still
runs its own SSF push loop. Phase 3 (0.6.0) moved none of it either: from 0.6.0 the production profile refuses a
component whose security state would be kept in one node's memory unless `OIDF_ACCEPTED_RISKS` names
`in-memory-state` (Phase 3 plan decision 9), which says the node is standalone and does not make the state shared,
and HSSF2's verification limit and HSSF3's logout replay memory are per node too (F-0385, F-0402):

| State | Where it lives in 0.4.0 | On two nodes |
|---|---|---|
| Attestation challenges, for the token endpoint (`oidf:as:challenge:*`) and the attester (`oidf:cas:challenge:*`) | In memory, per node, unless `OIDF_REDIS_URL` (or `REDIS_URL`) names a Redis (`AttestationSupport`) | A challenge fetched from one node is unknown at the other: the token endpoint answers 400 `use_attestation_challenge`, and the attester 401 `invalid_instance_proof` ("challenge is unknown, expired, or already used"). With Redis the challenge is shared. |
| Spent proof `jti`s - attestation PoPs and DPoP proofs at the token endpoint, instance-key proofs at the attester, client assertions at the federation endpoints (`oidf:fed:endpoint:*`) | The same | A proof spent at one node can be presented once more at the other until it expires: up to 360 s at the token endpoint, 300 s at the attester and 660 s at a federation endpoint. |
| Spent request objects and client assertions at automatic registration (`oidf-registration:*`) | The same (`FrontChannelAutoRegistrationFilter`, `RequestObject`) | A request object or client assertion spent at one node can be presented once more at the other until its `exp` plus 60 s of skew, capped at 86,400 s (`MAX_REPLAY_WINDOW_SECONDS`). |
| Evidence bindings (`oidf:cas:*`) | The same | Evidence bound to its first presenter at one node is unbound at the other, so a second presenter who reaches that node first takes the binding there. |
| The challenge endpoints' per-caller cap | Always per node: each endpoint's `ChallengeRateLimiter` is a field of its servlet, with no store behind it | Each node grants a caller its own allowance, 60 requests a minute by default, so two nodes grant 120. |
| SSF streams and their queued SETs | In memory, per node, when the transmitter's `dataStoreId` and `jdbcUrl` are blank (`SsfSupport`, `InMemorySsfStore`) | A stream created through one node does not exist at the other: management and poll requests that reach it answer 404 `not_found`, and an event raised on one node is queued only for that node's streams. |
| The SSF push loop | One per node, started when PingFederate boots, with no lease (`PushDeliveryService`) | With a shared data store both loops can read the same due SET before either records an attempt on it - `SsfStore.dueForPush` is a plain `SELECT` with no row lock - and both post it, so a receiver can get a SET once per node. Each node's failed attempt is counted towards `pushRetryMaxAttempts` (5 by default), so a stream whose receiver is down can dead-letter after fewer rounds than on one node. |
| The SSF receiver's `jti` dedupe and its poll acknowledgements | Always per node, whatever the stores: `SsfReceiverService` keeps the `jti`s it has seen in an in-memory set, and `PollReceiverClient` holds the acknowledgements it has yet to send in memory, one poll loop per node with no lease ([F-0043](../findings/F-0043.yaml)) | A SET can be acted on once per node: a transmitter's retried push that reaches the other node, or the same SET handed to both nodes' poll loops before either acknowledges it, passes the other node's dedupe. An acknowledgement a node holds for its next poll is lost with that node, so the transmitter delivers the SET again. `SsfReceiverService`'s own comment counts on the action being idempotent; that the installed handlers are has not been checked. |
| The federation authority's hosted entities, Trust Marks and key history | In memory, per node, unless `OIDF_AUTHORITY_JDBC_URL` or `OIDF_AUTHORITY_DATA_STORE_ID` names a database (`AuthoritySupport`, `TrustMarkSupport`, `KeyHistorySupport`) | An entity enrolled, or a Trust Mark issued, at one node is unknown at the other. |
| Clients that automatic or explicit registration creates | PingFederate's client store, written through `MgmtFactory` | Whether another engine node sees the client, and how soon, is unverified ([U-0027](../findings/U-0027.yaml)). |
| The RAR models document | Read once per PingFederate process (`OIDF_RAR_MODELS_FILE` or `OIDF_RAR_MODELS`) | Nodes given different documents answer the same request differently. Give every node the same one, or none. |

## The device path, until 0.9.0

services/device-enrolment is not production-usable until Phase 6: a device enrols `UNKNOWN`, re-minting needs
`COMPLIANT`, and nothing in this repository can make it so. Its README says why
([services/device-enrolment](../../services/device-enrolment/README.md#not-production-usable-until-phase-6)).
