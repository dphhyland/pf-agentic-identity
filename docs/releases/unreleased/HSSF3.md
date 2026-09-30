# SSF's events and audit source, a logout signal that cannot be replayed, push headers encrypted at rest, and Kafka over TLS

## Changelog

- Every SET the SSF transmitter mints carries a `txn`, the same on every SET one PingFederate event raises: the audit
  record's or the logout request's PingFederate `transactionid`, or a value minted for that event (plan item H-SSF-5,
  F-0057; SSF 1.0 §4.1.9).
- The audit source's default vocabulary is every PingFederate 13.1.3 audit event that maps to one CAEP or RISC event
  without ambiguity: `SLO`, `SRI_REVOKED` and `AUTHN_SESSIONS_DELETED` to session-revoked, `AUTHN_SESSION_CREATED` to
  session-established, `PWD_CHANGE` to credential-change (`password`, `update`) and `ACCOUNT_DELETE` to RISC
  account-purged. `SESSION_REVOKED`, `SESSION_DELETED` and `AUTHN_SESSION_DELETED`, which no PingFederate 13.1.3 class
  writes, are gone. `OIDF_SSF_AUDIT_EVENT_MAP` takes `session-established`, `account-purged` and
  `credential-change:<credential_type>[:<change_type>]`.
- credential-change carries only a CAEP 1.0 registered `credential_type`; the audit source no longer sends
  `"credential"`, and an unnamed credential is dropped and counted, not guessed. An audit-raised account-disabled
  carries no `reason` (RISC's are `hijacking` and `bulk-account`).
- `SsfEventBridge.onAssuranceLevelChange` raises a CAEP 1.0 §3.4 assurance-level-change with its required `namespace`
  and `current_level`; PingFederate's audit records carry no assurance level, so the audit source never raises one.
- The audit source re-attaches when log4j replaces its configuration (PingFederate's `log4j2.xml` has
  `monitorInterval="30"`) and detaches when the webapp shuts down.
- The logout signal (`LogoutEventFilter`) is raised only for an `id_token_hint` that is an ID token signed and issued
  by this PingFederate, issued within `OIDF_SSF_LOGOUT_HINT_MAX_AGE_SECONDS` (new, default 86400), when PingFederate's
  handling did not fail, and at most once per session and `iat` (plan item H-SSF-6, F-0022). A `logout_token`
  parameter is no longer read. The issuer comes from `PfInternals.issuer` (F-0215).
- A push stream's `authorization_header` is encrypted at rest with AES-256-GCM under the new `OIDF_SSF_SECRET_KEY`
  (and `OIDF_SSF_SECRET_KEY_PREVIOUS` during a rotation); a clear value is sealed on its stream's next write (plan item
  H-SSF-7, F-0058).
- Kafka: `OIDF_SSF_KAFKA_SECURITY_PROTOCOL` defaults to `SSL` and is a choice; `PLAINTEXT` and `SASL_PLAINTEXT` are
  forbidden in production (plan item PR-2). New settings pass the `ssl.*` truststore, keystore and host-name settings
  through (`OIDF_SSF_KAFKA_SSL_TRUSTSTORE_LOCATION`, `_PASSWORD`, `_TYPE`, `OIDF_SSF_KAFKA_SSL_KEYSTORE_LOCATION`,
  `_PASSWORD`, `_TYPE`, `OIDF_SSF_KAFKA_SSL_KEY_PASSWORD`, `OIDF_SSF_KAFKA_SSL_HOSTNAME_VERIFICATION`) and bound the
  producer's timeouts (`OIDF_SSF_KAFKA_REQUEST_TIMEOUT_MS` 10000, `OIDF_SSF_KAFKA_DELIVERY_TIMEOUT_MS` 30000,
  `OIDF_SSF_KAFKA_MAX_BLOCK_MS` 2000; `linger.ms` 0). The JAAS line escapes every value.
- A new event catalogue, `ssf`: `ssf.set.emitted`, `ssf.set.dropped`, `ssf.logout.signal.refused`,
  `ssf.audit.source.attached` and `ssf.audit.source.detached`, each counted in `oidf_events_total` (plan item O-2).

## Before you deploy

1. **Set `OIDF_SSF_SECRET_KEY` before streams with push headers are written.** What to do: generate a key
   (`openssl rand -base64 32`) and set `OIDF_SSF_SECRET_KEY` (or `OIDF_SSF_SECRET_KEY_FILE`) on every node that runs
   the SSF transmitter with a JDBC or `ldm` store. Why: a push stream's `authorization_header` is the credential the
   transmitter presents at the receiver's endpoint, and until 0.6.0 the store kept it in clear. How to tell: under the
   production profile, a stream create or update that carries an `authorization_header` without the key answers 500
   with an ERROR naming `OIDF_SSF_SECRET_KEY`, and SSF is `FAILED_CONFIG` naming it (its endpoints 503) when the store
   already holds a push stream with a header; a key that is not 32 bytes of base64 is `FAILED_CONFIG` too. What to
   change: set the key and restart. Existing headers are read as they are and encrypted on each stream's next write -
   to encrypt them all at once, have each receiver post its current status to `/ssf/status`, or pause and re-enable
   each stream. To rotate later, move the old key to `OIDF_SSF_SECRET_KEY_PREVIOUS` and set a new one. Keep the key:
   a header sealed under a key you no longer hold stays sealed, and its receiver refuses the pushes. Development-profile
   escape: with `OIDF_DEPLOYMENT_PROFILE=development`, headers are stored in clear without the key, with a WARN.
2. **Kafka must use TLS in production.** What to do: if `OIDF_SSF_KAFKA_ENABLED=true`, run the brokers' listener with
   TLS and set `OIDF_SSF_KAFKA_SECURITY_PROTOCOL` to `SSL` (the new default) or `SASL_SSL`, with
   `OIDF_SSF_KAFKA_SSL_TRUSTSTORE_LOCATION` (and its password and type) when the brokers' CA is not in the JVM's, and
   the keystore settings when they require mutual TLS. Why: `PLAINTEXT` sends every SET, and `SASL_PLAINTEXT` the SASL
   password too, across the network in clear, and the default was `PLAINTEXT`. How to tell: under the production
   profile, `PLAINTEXT` or `SASL_PLAINTEXT` set anywhere refuses SSF (`REFUSED`, its endpoints 503, the start-up audit
   and an ERROR naming `OIDF_SSF_KAFKA_SECURITY_PROTOCOL`), and so does `OIDF_SSF_KAFKA_SSL_HOSTNAME_VERIFICATION=false`;
   a deployment that set no protocol now connects with TLS, so against a plaintext listener each publish fails and is
   logged (the streams still get their SETs; not run against a broker here, U-0410). A send now blocks the thread that raised the event for at most
   `OIDF_SSF_KAFKA_MAX_BLOCK_MS` (2 s) rather than Kafka's minute. What to change: the protocol and the `ssl.*`
   settings; a SASL user name or password with quotes, backslashes or semicolons in it now works as written.
   Development-profile escape: `PLAINTEXT`, `SASL_PLAINTEXT` and host-name verification off are used with a WARN.
3. **Logout signals are raised only for a successful logout with a recent ID token hint.** What to do: check that
   your relying parties send `id_token_hint` at `/idp/init_logout.openid` (OpenID Connect RP-Initiated Logout 1.0 marks
   it RECOMMENDED), with an ID token PingFederate issued within `OIDF_SSF_LOGOUT_HINT_MAX_AGE_SECONDS` (default 86400,
   60 to 2592000); raise the bound if your users stay signed in longer and you want their logout signalled. Why: a
   captured hint could raise a session-revoked again and again, of any age, and an access token or a logout token
   signed by PingFederate's keys was taken as a hint (F-0022). How to tell: each logout that raises nothing logs an
   `ssf.logout.signal.refused` event with its reason (`hint_invalid`, `hint_not_id_token`, `hint_too_old`,
   `logout_failed` or `replayed`); a logout that sent only a `logout_token` now raises nothing. What to change: send an
   ID token as the hint, or raise the bound. Development-profile escape: none for the hint rules; the development-only
   `OIDF_SSF_LOGOUT_ALLOW_SUB_PARAM` is unchanged.
4. **The SSF audit vocabulary is wider.** What to do: check what your receivers subscribe to. A receiver whose stream
   delivers session-established, credential-change or account-purged now gets them when PingFederate audits a new
   authentication session (`AUTHN_SESSION_CREATED`), a local identity's password change (`PWD_CHANGE`) or its deletion
   (`ACCOUNT_DELETE`), and session-revoked for `AUTHN_SESSIONS_DELETED`; every SET now carries `txn`. Why: plan item
   H-SSF-5 asks for every PingFederate audit event that maps to a CAEP or RISC event without ambiguity. How to tell:
   `ssf.set.emitted` counts them by event type. What to change: to keep an event out, remove its mapping
   (`OIDF_SSF_AUDIT_EVENT_MAP=AUTHN_SESSION_CREATED=`) or leave it out of the stream's `events_requested`; a mapping to
   `credential-change` now names its CAEP credential type (`PWD_SET=credential-change:password:update`), and one that names
   none sends nothing. Development-profile escape: none; this is not a profile rule.

## Notes

- Verified 2026-10-01: `mvn verify` of servlets/ssf on JDK 20 and 17 and its tests on JDK 21 (the image's), with
  PostgreSQL 16 for both stores (the `ldm` store on the model repo's own migrations); EventsCataloguedTest and
  InternalsBoundaryTest; the settings scan, the configuration reference, the findings register and the showcase links.
- The rig (slot 2, `pfai-p3-hssf3`, PingFederate 13.1.3, development profile), 2026-10-01: the CAEP Interop plan
  `openid-ssf-transmitter-caep-test-plan` `Rx8fy4v52mDwr` passed 13 of 13 and the SSF plan
  `openid-ssf-transmitter-test-plan` `7VvB7uhXQFfNs` 19 of 19, the suite's CAEP SETs carrying `txn` (its
  verification SETs do not: F-0403). A logout with a fresh hint signalled and the same hint again was refused
  (`replayed`); the login's access token as the hint was refused (`hint_not_id_token`), where 0.5.0 signalled for it;
  a touch of `log4j2.xml` re-attached the audit source four seconds later; a login's audit record reached the bridge.
- What the logout filter cannot see: on 13.1.3 `/idp/init_logout.openid` answers 200 in every case and PingFederate
  signs the user off after a confirmation on a later request, so "the logout succeeded" is held to what the response
  shows (F-0401). The replay memory is per node until C-1 (F-0402). A sealed push header over about 3000 characters
  does not fit the tables store's column (F-0404). shared-signals' own assurance-level-change builder is not
  CAEP-shaped and is not used (F-0400). Kafka was not run against a broker (U-0410); the audit records' subjects for
  the new mappings were read from PingFederate's classes, not seen on the rig (U-0411).
- Closes F-0022, F-0057, F-0058 and F-0215. F-0201 (Kafka's producer thread) stays with S-10.
