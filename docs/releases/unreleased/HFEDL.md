# Federation correctness and load: racing operator changes, authority_hints, the validator's cache, the resolve endpoint

## Changelog

- A hosted entity's suspension, reactivation or revocation, a Trust Mark grant, revocation or reinstatement, and a
  historical key's revocation now apply only to the state they read: of two operators changing one of them at once,
  the second to commit is answered 409 `stale_update` at the federation admin API and writes nothing, its audit line
  and event included (plan item H-FED-3, F-0019).
- `/federation/entity?sub=<this entity>` now serves this entity's Entity Configuration, the same statement as
  `/.well-known/openid-federation`, so both carry `authority_hints` by one rule: none for a Trust Anchor, its configured
  superiors otherwise, never `[]` (H-FED-8).
- The trust chain validator caches only the statements of the route it validated, under keys that treat
  `https://a.example/` and `https://a.example` as one entity, and parses a statement's `metadata_policy` only once the
  route's signatures have verified: a policy that does not parse now fails the chain after the signature check, never
  before it (H-FED-8).
- `TrustMarkIssuer.marked` reads a type's standing grants in one query; a hosted entity's signed Entity Configuration is
  kept for the first quarter of its hour - or of the time until the first Trust Mark it carries expires, if that is
  sooner - and dropped when the entity or its Trust Marks change; the resolve endpoint
  answers each caller address about a capped number of distinct subjects a minute and keeps its responses for up to
  60 s; AuthZEN discovery is read again every ten minutes (H-FED-9, F-0051). Two settings join the
  `federation-resolution` catalogue: `OIDF_FEDERATION_RESOLUTION_RESOLVE_SUBJECTS_PER_MINUTE` (30) and
  `OIDF_FEDERATION_RESOLUTION_RESOLVE_CACHE_SECONDS` (60).

## Before you deploy

1. **Concurrent operator changes to one hosted entity or Trust Mark now conflict.** From 0.6.0, when two operators
   change the same hosted entity (`/federation/admin/entities/suspend`, `reactivate`, `revoke`), the same Trust Mark
   grant (`/federation/admin/trust-marks`, `/trust-marks/revoke`) or the same retired key (`/keys/revoke`) at once, each
   deciding on what it read, the change that reaches the store second is answered `409` with
   `{"error": "stale_update"}` and changes nothing - no new status, no audit line, no `federation.*` event. Why: before 0.6.0 each change read the current state and then wrote its own
   unconditionally, so a revocation could race a reactivation and both be recorded, the later one silently undoing the
   earlier, or two revocations each record a reason. How to tell: an operator tool or script that calls the admin API
   concurrently, or retries on a timeout, will now see 409 where it saw 200; the audit trail
   (`/federation/admin/entities/audit`, `/trust-marks/audit`) shows only the change that applied. What to change: on
   409, read the entity, grant or key again (`GET /federation/admin/entities?entity_id=`, `/trust-marks?sub=`, `/keys`)
   and decide whether the change is still wanted before sending it again. A Trust Mark grant reads the grant itself
   when it runs, so it conflicts only with a change committed while it runs: a grant that arrives after another
   operator's revocation has committed reinstates the mark, as before. Repeating a change that has already applied
   - revoking a revoked entity, grant or key - is still answered 200 and changes nothing, as before. There is no
   development-profile escape: the conditional write is how the store settles a race, whatever the profile.

2. **`/federation/resolve` is rate-limited per caller.** From 0.6.0 the resolve endpoint answers one caller address
   about at most `OIDF_FEDERATION_RESOLUTION_RESOLVE_SUBJECTS_PER_MINUTE` distinct subjects in any minute (30 by
   default, 1 to 10000). A request about one more subject is answered `503` with `{"error": "temporarily_unavailable"}`
   and a `Retry-After` header giving the seconds until the caller's oldest subject leaves the minute; asking again about
   a subject already counted is not counted again, even with other trust anchors or entity types (F-0383). It also keeps each resolve response for
   `OIDF_FEDERATION_RESOLUTION_RESOLVE_CACHE_SECONDS` (60 by default, 0 to 60, 0 keeping none) or until the response's
   own `exp`, whichever is sooner, and answers the same request - subject, trust anchors, entity types and the client
   it is addressed to - from it. Why: OpenID Federation 1.0 §18.1 names the resolve endpoint first among the interfaces
   that "could be used for Denial-of-Service attacks", and before 0.6.0 every request started a trust chain resolution
   of its own, bounded only by each resolution's budget. How to tell: count the distinct `sub` values your busiest
   resolve client asks about in a minute - a relying party resolving the entities it meets, or a monitoring job
   sweeping many subjects - from PingFederate's request log or the "Resolved ... to trust anchor" lines in server.log.
   The caller is the connection's address, so every client behind one reverse proxy or NAT shares one minute. What to
   change: raise `OIDF_FEDERATION_RESOLUTION_RESOLVE_SUBJECTS_PER_MINUTE` on every node to above what one address
   legitimately needs, and have clients honour `Retry-After`. A revocation that must stop a subject resolving at once
   is seen by the resolve endpoint up to the cache time later; set `OIDF_FEDERATION_RESOLUTION_RESOLVE_CACHE_SECONDS=0`
   where that matters more than the load. There is no development-profile escape: the cap is a setting, the same in
   every profile, and a rig or test that needs more raises it.

3. **A Trust Mark revoked on another node stays in this node's hosted configurations for up to 15 minutes.** From 0.6.0
   the Entity Configuration a node signs for an authority-signed hosted entity is kept in that node's memory for the
   first quarter of its hour (or of the time until the first Trust Mark it carries expires, if sooner). A change to the
   entity itself is seen by every node at once, and the node that grants or revokes a Trust Mark drops its copy at once;
   another node keeps serving the configuration it signed, with the revoked mark in `trust_marks`, until its copy is
   due for renewal - fifteen minutes at most. Why: signing on every request cost a signature each time, and a
   round trip to OpenBao for an OpenBao-held key (plan item H-FED-9). How to tell: you run more than one node behind
   one address and rely on a Trust Mark revocation removing the mark from `/federation/entity?sub=<hosted entity>` at
   once; the mark's own `/federation/trust_mark_status` answer is not cached and reflects the revocation at once. What
   to change: nothing, if a relying party that must honour a revocation at once checks the mark's status; otherwise
   send the revocation to every node, or accept the lag. The resolve endpoint's own cache (see
   **`/federation/resolve` is rate-limited per caller**) adds up to its cache time on top. There is no
   development-profile escape: the cache is the same in every profile, and has no setting.

## Notes

- **The `authority_hints` rule.** OpenID Federation 1.0 §3.1.2 (Final, 17 February 2026, fetched 2026-09-30): "This
  Claim is REQUIRED in Entity Configurations of the Entities that have at least one Superior above them, such as Leaf
  and Intermediate Entities. Its value MUST contain the Entity Identifiers of its Immediate Superiors and MUST NOT be the
  empty array []. This Claim MUST NOT be present in Entity Configurations of Trust Anchors with no Superiors." This
  entity's superiors are its configured trust anchors (`OIDF_FEDERATION_TRUST_ANCHORS`). When it names itself among
  them (compared with `EntityId.same`, so a trailing slash does not matter) it is a Trust Anchor and its configuration
  names no superior of it, so it publishes no `authority_hints`; otherwise it publishes each configured anchor once;
  with none configured, none - never `[]`. The Entity Configuration always followed this rule, except that it compared
  itself with the anchors exactly; the non-standard `/federation/entity?sub=<this entity>` did not, and published the
  whole configured list, this entity itself and `[]` included. It now serves the Entity Configuration itself.
- **Policy after the signature.** §3.2 lets the validation steps run "in a different order, provided that the result -
  accepting or rejecting the Entity Statement - is the same", and §10.2 says "After the preceding validation, metadata
  MUST be resolved to the subject of the Trust Chain, as described in Section 6.1.4". The shape of `metadata_policy`
  (a JSON object of JSON objects) is still checked with the other claims; its operators are parsed only when the chain's
  policy is resolved, after every signature on the route has verified. A chain whose statement fails its signature is
  now refused for the signature (`invalid_trust_chain`) where one whose policy would not parse was refused for the
  policy (`invalid_metadata`) before any key was tried.
- **The configuration cache.** A hosted entity's signed Entity Configuration (lifetime one hour) is served from memory
  while more than three quarters of its lifetime remains, for the exact registry record it was built from. This node's
  changes to the entity, and its Trust Mark grants and revocations to it, drop it at once; another node's changes to
  the entity are seen at once (the record read differs), and its Trust Mark changes within 15 minutes. The lifetime
  counted ends at the earlier of the configuration's `exp` and that of the first Trust Mark it carries to expire, so a
  configuration carrying a five-minute mark is renewed after 75 seconds and never serves a mark past its `exp`.
- **Listing a hosted-only Trust Mark type.** `marked` reads the grants in one query; for a type issued to hosted entities
  only, each subject returned is still checked against the hosted-entity registry one at a time, because the check is
  wired as a per-entity predicate where the federation servlet starts (F-0381).
- **AuthZEN discovery.** The decision point fetched the PDP's `/.well-known/authzen-configuration` once and kept its
  `access_evaluation_endpoint` for the life of the process; it now reads it again once ten minutes have passed, and a
  read that fails is no decision, retried on the next request. A PDP configured by URL
  (`OIDF_FEDERATION_POLICY_PDP_URL` without discovery) fetches nothing and is unchanged.
- **Verified.** `openid-federation` (663 tests) and `pf-integration` (896) on JDK 17, 20 and 21.0.12 with Postgres 16,
  coverage gates met. The conditional updates were exercised by two threads whose updates were held until both had
  read; with the hosted-entity update made unconditional again, all four hosted-entity races failed. The
  abandoned-route test fails when the validator commits every staged statement, as it did before.
- **On the rig, 2026-09-30.** Slot 3 (`pfai-p3-hfedl`, PingFederate 13.1.3, `PF_PROFILE=federation-op`, so
  `OIDF_FEDERATION_ENABLED=true`, modules built from 65235d83 with the change committed as e0e81ca9), against this
  repo's own suite (release-v5.3.1): `openid-federation-deployed-entity-test-plan`, plan `gbHA7qdHXshoT`, 5 of 5
  WARNING, 0 FAILED; `openid-federation-entity-joined-to-test-federation-op-test-plan`, plan `FwQV9d5MFfYQH`, 20 of 20
  WARNING, 0 FAILED - the same results as 0.5.0's, every warning the known
  `CheckForUnexpectedParametersInServerMetadata` on PingFederate's vendor metadata. `/.well-known/openid-federation`
  and `/federation/entity?sub=<PF>` both carried no `authority_hints` (PF names itself among its anchors). Thirty
  resolve requests about thirty subjects, each with a different `X-Forwarded-For`, were followed by a 503 with
  `Retry-After: 60`, so the caller is the connection's address (U-0390); a repeated resolve three seconds later came
  back identical, `iat` included.
