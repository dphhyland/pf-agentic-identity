# SSF streams take the optional members, a verify limit and a cap per receiver; SCIM reads, filters, replaces and re-enables

## Changelog

- SSF streams carry SSF 1.0 §8.1.1's optional members (plan item H-SSF-3, finding F-0055, closed): `description`
  (the receiver's, cut at 1,024 characters), and `min_verification_interval` and `inactivity_timeout`, which the
  transmitter gives each new stream from the new `OIDF_SSF_MIN_VERIFICATION_INTERVAL_SECONDS` (30, 0-86400) and
  `OIDF_SSF_INACTIVITY_TIMEOUT_SECONDS` (0 = none, 0-31536000). All three are stored by the JDBC and in-memory stores and
  returned; a receiver echoing a Transmitter-Supplied member on PATCH or PUT must send the stream's value. The `ldm`
  store keeps none of them until the Identity Object Model declares them: there a stream reports the two settings and
  a `description` is refused with a 400.
- A verification request sooner than the stream's `min_verification_interval` after its last is answered 429 with
  `Retry-After`, and nothing is signed.
- `OIDF_SSF_MAX_STREAMS_PER_CLIENT` (10, 1-1000) caps the streams one receiver client may have; one more create is 409.
- A stream create with no `delivery` is a poll stream (SSF 1.0 §8.1.1.1), where it was a 400.
- An `OIDF_SSF_ISSUER` that is not https is `FAILED_CONFIG` in production (a WARN in development); one with a query, a
  fragment or no host is `FAILED_CONFIG` in any profile.
- `OIDF_SSF_BASE_PATH` is removed: every URL the transmitter advertises is the issuer and the path its servlet is
  mapped to.
- SCIM (plan item H-SSF-4, finding F-0056, closed): `GET /ssf/scim/v2/Users/{id}`, and `GET /ssf/scim/v2/Users` with a
  `filter` (a subset of RFC 7644 §3.4.2.2, 400 `invalidFilter` for the rest), `startIndex` and `count`; every error in
  the RFC 7644 §3.12 schema as `application/scim+json`; `PUT` replaces, and is 404 for an unknown id; `POST` of a user
  already recorded is 409 `uniqueness`; `active` false to true puts the subject back on its streams and emits RISC
  `account-enabled`. The endpoint keeps a record per user (the JDBC store's new `ssf_scim_users` table; the `ldm`
  store keeps none until the model has a class for it). A PATCH, PUT or DELETE that deactivates a user the endpoint
  has no record of still emits `account-disabled`, as every deprovision did before.

## Before you deploy

1. **SSF streams are capped per client.** What to do: count the streams each receiver client holds - on the JDBC
   store, `SELECT owner_client_id, count(*) FROM ssf_streams GROUP BY owner_client_id` - and if any client needs more
   than 10, set `OIDF_SSF_MAX_STREAMS_PER_CLIENT` (1-1000) to what it needs. Why: without a cap one receiver could make
   the transmitter hold, sign for and deliver to as many streams as it cared to create (plan item H-SSF-3). What now
   happens: a create that would take a client past the cap is answered 409 Conflict, `{"error":"conflict"}`, the
   status SSF 1.0 §8.1.1.1 gives a transmitter that allows a receiver no more streams ("If the Transmitter does not
   allow multiple streams with the same Receiver, it MUST respond with HTTP status code "409 Conflict""); streams
   already over the cap keep working, and the client creates no more until it deletes some. How to tell: a
   receiver's create fails with 409 and a message naming the cap. Development-profile escape: none needed; the
   setting is the escape, in any profile.
2. **The SSF transmitter's issuer must be https in production.** What to do: set `OIDF_SSF_ISSUER` to the https
   origin receivers reach this PingFederate at, with no query or fragment. Why: SSF 1.0 §7.1 defines the issuer as a
   "URL using the https scheme with no query or fragment component", and every endpoint the metadata advertises is
   the issuer and a path, each of which "MUST use HTTP over TLS" - over http a receiver's bearer token and its stream's
   configuration cross the network in clear. What now happens: under the production profile an http issuer leaves SSF
   `FAILED_CONFIG` - its endpoints answer 503 and server.log has an ERROR "SSF transmitter NOT started:
   OIDF_SSF_ISSUER is http" - and an issuer with a query, a fragment or no host does so in any profile. How to tell:
   that ERROR line, and SSF `FAILED_CONFIG` in the health detail. Development-profile escape: with
   `OIDF_DEPLOYMENT_PROFILE=development` an http issuer starts, with a WARN naming it.
3. **The ldm SSF store needs the new IOM attributes for the optional stream members.** What to do: with
   `OIDF_SSF_STORE_DIALECT=ldm`, have the Identity Object Model's owner (idp-scim-service) declare `description`,
   `minVerificationInterval`, `inactivityTimeout` and `ownerClientId` as MAY attributes of `ssfStream`, and a class
   for the SCIM endpoint's user records; until then, have receivers create streams without a `description`. Why: this
   repo does not change the shared model (the programme plan's Cross-repo rule), and the model declares none of them,
   so the ldm store keeps none of them. What now happens: on the ldm store a stream reports this transmitter's
   `OIDF_SSF_MIN_VERIFICATION_INTERVAL_SECONDS` and `OIDF_SSF_INACTIVITY_TIMEOUT_SECONDS` as its
   `min_verification_interval` and `inactivity_timeout` - both "Transmitter-Supplied, OPTIONAL" in SSF 1.0 §8.1.1, so
   a changed setting changes what every stream reports - and a create, PATCH or PUT carrying a `description` is 400
   "description is not supported by this transmitter's stream store (ldm)", since SSF lets a transmitter truncate a
   description ("The transmitter MAY truncate the string beyond an allowed max length") and not drop it. The SCIM
   endpoint keeps no user records there: a user is the subject the streams hold, `userName` and `externalId` are not
   kept, a deactivated user is forgotten (GET 404), a second POST adds to its streams rather than answering 409, and
   reactivating a forgotten user is a POST, which emits no `account-enabled`. How to tell: a receiver's create with a
   `description` fails 400 with that message. Development-profile escape: none needed; the JDBC and in-memory stores
   keep everything, in either profile (finding F-0387).
4. **SCIM PUT now replaces.** What to do: a provisioner that sent `PUT /ssf/scim/v2/Users/{id}` with part of a user -
   only the SSF extension, say - must send the whole resource, or use PATCH; and one that relied on PUT or PATCH to create a
   user this endpoint had never seen, or on a second POST of the same user, must create with POST and then update. Why:
   RFC 7644 §3.5.1: "HTTP PUT is used to replace a resource's attributes", and "HTTP PUT MUST NOT be used to create
   new resources"; §3.3 has a duplicate create answered "409 (Conflict) with a "scimType" error code of
   "uniqueness"". What now happens: an attribute a PUT leaves out is removed - no `userName` clears it, and no SSF
   extension takes the subject off every stream it was on; a GET, or a PUT or PATCH that leaves `active` true, of an id
   the endpoint has no record of and no stream holds is 404; a second POST of a recorded user is 409; every error body is the SCIM error schema, not `{"error": ...}`. Also, `active` false to true
   now emits RISC `account-enabled` and puts the subject back on the streams it was taken off, and an `active:false`
   for a user already inactive emits nothing again. A deactivation is never lost for want of a record: a PATCH or PUT
   setting `active` false, or a DELETE, for a user with no record on no stream - one provisioned before 0.6.0, heard
   about through `OIDF_SSF_DEFAULT_SUBJECTS=ALL` - emits `account-disabled` as it did before, and the PATCH or PUT
   leaves an inactive record. How to tell: the provisioner's log shows 404 or 409 from
   `/ssf/scim/v2/Users`, or a user's streams empty after a PUT. Development-profile escape: none; these are the
   protocol's rules, the same in every profile.
5. **`OIDF_SSF_BASE_PATH` is removed.** What to do: unset `OIDF_SSF_BASE_PATH`, the system property
   `oidf.ssf.basePath` and the init-param `basePath` wherever they are set. Why: the setting changed the URLs the
   transmitter advertised and not the paths its servlets answer - their `@WebServlet` paths are fixed when the module
   is built - so any value but `/ssf` sent receivers to endpoints nothing served (plan item H-SSF-3). What now
   happens: set by any of its names, to any value, `/ssf` included, SSF is `FAILED_CONFIG` with "OIDF_SSF_BASE_PATH was
   removed in 0.6.0 and nothing replaces it; unset it". How to tell: that ERROR in server.log at start-up, and SSF
   `FAILED_CONFIG` in the health detail. Development-profile escape: none; a removed name is refused in every profile,
   and unsetting it changes nothing a receiver sees.
6. **A verification request within the stream's interval is refused.** What to do: check how often your receivers
   call `/ssf/verify` on one stream; if more often than every 30 seconds, space them out or set
   `OIDF_SSF_MIN_VERIFICATION_INTERVAL_SECONDS` (0 turns the limit off for new streams). Why: each request has the
   transmitter sign a SET, so an unlimited verify endpoint is a signing oracle a receiver can run as fast as it likes;
   SSF 1.0 §8.1.1 allows the 429: "If an Event Receiver submits verification requests more frequently than this, the
   Event Transmitter MAY respond with a 429 status code." What now happens: a request sooner than the stream's
   `min_verification_interval` after the last accepted one is answered 429 with `Retry-After` in seconds; streams
   created before 0.6.0 are held to the current setting. How to tell: 429 from `/ssf/verify`; the stream's
   `min_verification_interval` is in its configuration. Development-profile escape: none needed; the setting applies
   in any profile.

## Notes

- Verified 2026-09-30 on the rig (slot 5, `pfai-p3-hssf2`, PingFederate 13.1.3 on Java 21.0.12.1, development
  profile, the modules built from the branch at `5eb1d5de`, only documentation uncommitted): `openid-ssf-transmitter-test-plan` plan `OPPPf9qYr0V85` 19 of 19 PASSED, and
  `openid-ssf-transmitter-caep-test-plan` plan `d1AS8YI8fOnmo` 13 of 13 PASSED, against the suite release-v5.3.1 of
  `suite/suite-compose.yml`, with the default cap (10) and interval (30 s) in force. The metadata served there carried
  every SSF 1.0 §7.1 member but `critical_subject_members`, endpoints at `https://host.docker.internal:35031/ssf/...`.
- The SCIM endpoint on the same rig, with the rig's provisioner client (`conformance-ssf-emitter`): POST 201 with
  `Location`; a second POST 409 `uniqueness`; `filter=userName eq "HSSF2.ALICE"` one result; `userName gt "a"` 400
  `invalidFilter`; PATCH `active` false then true, each logged ("account-disabled raised", "account-enabled raised");
  PUT without `userName` answered without it; PUT of an unknown id 404; DELETE 204 and then GET 404; no token 401 with
  `WWW-Authenticate: Bearer` - every error body in the RFC 7644 §3.12 schema as `application/scim+json`.
- After the review (2026-10-01): deactivating a user with no record by PATCH, PUT or DELETE emits
  `account-disabled` again (a regression the review found under `OIDF_SSF_DEFAULT_SUBJECTS=ALL`); the ldm store no
  longer writes attributes or parent-less entries the model does not declare; an over-long `userName`, `externalId`
  or id and an argument refused below the service are 400 `invalidValue`, not 500; `active` reads the same in POST,
  PUT and PATCH. `mvn verify` of servlets/ssf on JDK 17 then passed with 557 tests, none skipped, the Postgres store
  contracts on Postgres 16 and the coverage gate met.
- `mvn verify` of servlets/ssf (547 tests, the Postgres store contracts on a local Postgres 16 through
  `OIDF_TEST_JDBC_URL`, the 100% METHOD gate with the new methods added) passed on JDK 20, and with libs/conformance
  (549 tests, none skipped) on JDK 17 and on JDK 21.0.12 (`maven:3-eclipse-temurin-21`, the Postgres suites against
  the same database).
- Normative text was read on 2026-09-30 from the published documents: SSF 1.0 final (29 August 2025) §7.1, §7.2.3,
  §8.1.1, §8.1.1.1, §8.1.1.3, §8.1.1.4 and Table 10; RFC 7644 §3.3, §3.4.2, §3.4.2.2, §3.4.2.4, §3.5.1 and §3.12;
  RFC 7643 §3.1, §4.1.1 and §8.7.1; RISC 1.0 final §2.3 and §2.4.
- The JDBC store adds `description`, `min_verification_interval` and `inactivity_timeout` to `ssf_streams` with
  `ALTER TABLE ... ADD COLUMN IF NOT EXISTS` at start-up, and creates `ssf_scim_users`, as `ensureSchema` already
  creates its tables. DB-2 (Phase 4) removes DDL at runtime: its V300 baseline must be `JdbcSsfStore.DDL_STREAMS` and
  `DDL_SCIM_USERS` as written here, the new columns included.
- The metadata was checked member by member against SSF 1.0 §7.1: none was missing before this change;
  `critical_subject_members` is left out because this transmitter names none and §7.2.3 says "Claims with zero
  elements MUST be omitted from the response".
- `basePath` was removed rather than honoured: the servlets' `@WebServlet` paths are compile-time constants, and
  `SsfRoutes` and the SSF surface matrix are built on them. A test holds every path the transmitter advertises
  (`SsfPaths`) to a mapped pattern.
- `inactivity_timeout` is recorded and reported only; pausing an inactive stream, with the stream-updated event SSF
  requires, is S10c's (Phase 4; finding F-0389).
- The verification interval is counted per node, in memory (the Phase 3 plan's decision 9 allows a rate limit
  there; finding F-0385). The cap is counted before the insert, so racing creates can leave a receiver one over
  (F-0386). The SCIM list reads every stream's subjects on each request, and `userName` is not held unique (F-0388).
  The SCIM endpoint has not been driven by a real SCIM client (U-0395).
- The component gate's own 503 and 404 on `/ssf/scim/v2/Users` are left as every SSF surface answers them, not
  rewritten in the SCIM error schema.
- Owner actions: the IOM change in idp-scim-service under **The ldm SSF store needs the new IOM attributes for the
  optional stream members**; and David has not confirmed the Phase 3 plan's decisions 1-20, which this package builds
  on as the plan recommends (decision 9, a rate limit in memory; decision 11, strict settings; decision 16, the
  package split).
