# Federation reads each setting through one catalogue entry, strictly

## Changelog

- Every federation reader is on `platform.settings` (plan item ST-5): `FederationRuntimeConfig` through the
  `federation-runtime` catalogue, the federation servlet's `FederationConfiguration` and `AttestationMetadataConfig`
  through `federation-entity`, the hosted-entity store and servlet through `hosted-entities`, the hosted entities'
  vault through `hosted-entity-signing`, the registration servlet's and filters' init-params through `registration`,
  `Fapi2ProfileFilter` through `fapi2-profile`, the attestation filter's two global settings through
  `attestation-token-endpoint`, and `OutboundUrlPolicy` through `outbound-fetch`. Each setting is read from its
  entry's sources in its entry's order, its superseded names come from the catalogue (not written out by hand), and
  every value is parsed strictly, a number within the entry's range.
- One setting per variable, whichever class reads it (finding F-0197, closed). `OIDF_FEDERATION_IGNORE_SSL_ERRORS` is
  one entry, in openid-federation's `federation-entity` catalogue: the federation servlet's init-param `ignoreSslErrors`,
  then the system property `oidf.federation.ignore.ssl.errors`, then the environment variable, then the superseded
  `OIDF_TRUST_CONTROLLER_IGNORE_SSL` with a warning. Until 0.6.0 the servlet read the init-param and then the
  environment variable only, and `FederationRuntimeConfig` the system property, the environment variable and the
  superseded name. `HostedEntityServlet` reads its init-params `openBaoUrl` and `openBaoToken`, and without the pair
  leaves OpenBao to `RegistryHostedEntitySigner`, which reads `OIDF_OPENBAO_URL` and `OIDF_OPENBAO_TOKEN` through
  their `hosted-entity-signing` entries. Until 0.6.0 the servlet read each as init-param, then system property
  (`oidf.openbao.url`, `oidf.openbao.token`), then environment variable, and only when the pair was incomplete fell
  back to the signer's reading, which took the superseded `OPENBAO_*`, `BAO_*` and `VAULT_*` names. What is new: the
  superseded names are checked against the new ones even when the new ones are set, and a disagreement is refused.
- `FederationRuntimeConfig` logs its banner the first time it is read: each federation setting that is set and where
  its value came from, such as `OIDF_FEDERATION_IGNORE_SSL_ERRORS from system-property oidf.federation.ignore.ssl.errors`
  - the source and the name, never the value.
- The two automatic-registration limits, `OIDF_AUTO_REGISTRATION_MAX_REQUEST_OBJECT_BYTES` and
  `OIDF_AUTO_REGISTRATION_MAX_CONCURRENT_RESOLUTIONS`, are read as ints from 1 to 2147483647: `4294967297` was read as
  `1` and accepted, and is now refused. The per-client extended property `trust_chain_request_max_age` defaults to 60
  seconds for every reader: the OGNL chain criterion's default, now the attestation criterion's and the token-endpoint
  filter's for an attester's chain too, which used no limit (finding F-0198, closed). The validator drops a presented
  statement older than that and fetches it again, so a stale attester chain costs a fetch per statement, and one whose
  statements cannot be fetched - the host is unreachable, or `OutboundUrlPolicy` refuses it as private (only the trust
  controller is exempt) - now fails where the presented copy passed before. A client whose extended property
  `trust_chain_request_max_age` is `-1` keeps the old behaviour.
- Secrets can be read from a file: `OIDF_PDP_AUTH_TOKEN_FILE`, `OIDF_BRIDGE_VAULT_TOKEN_FILE`,
  `OIDF_AUTHORITY_JDBC_PASSWORD_FILE` and `OIDF_OPENBAO_TOKEN_FILE` (or the system property with `.file`) name a file
  whose content, one trailing newline trimmed, is the value; a name and its file variant set together are refused.
- The federation servlet validates each trust anchor as an Entity Identifier - an https URL with a host and no query,
  fragment or user info - and refuses one that is not, naming it; an issuer is recognised as an anchor with or without
  a trailing slash and whatever the case of its scheme and host (RFC 3986 §6.2.2.1: "the scheme and host are
  case-insensitive"). That is H-FED-8's anchor item; finding F-0050 closes when HFEDL, which has the other three items,
  has merged too.
- `FederationConfiguration` loses its dead methods (H-FED-10's part for this class; finding F-0052 stays open for the
  rest): `trustControllerHost()`, `trustAnchorIssuers()`, `defaultTrustAnchorIssuer()`, `findTrustAnchor(String)`, the
  constructors of 4, 9 and 10 arguments, and the `trustControllerHost` field - the init-param was read and nothing used
  it, and it is now a removed name.
- `OIDF_BRIDGE_PRIVATE_JWK` and `OIDF_BRIDGE_PREVIOUS_PUBLIC_JWK`, removed in 0.1.2, are refused by the catalogue's
  removed-name rule on every federation setting read, where `BridgeSigners` refused them itself.
- `OIDF_FEDERATION_CLIENT_REGISTRATION_TYPES=none` advertises neither registration type, which a list of nothing
  (`" , "`) did before.
- PR-2 for the federation stores (Phase 3 plan, decisions 9, 10 and 15): in production the hosted-entity registry
  kept in memory refuses `HOSTING`, and the Trust Mark registry or the key history kept in memory refuses `FEDERATION`
  when it issues Trust Marks or keeps a key history, unless the `in-memory-state` risk is accepted; a store that is
  not PostgreSQL refuses the same component. Each goes through `ProfileRefusals`, so the start-up audit lists it.
  Under development each is a WARN and the store is used.
- `HOSTING` asks a PingFederate data store what its database is, on one connection, when it starts: a database that
  cannot be reached then is `FAILED_DEPENDENCY`, retried by the supervisor, where until 0.6.0 hosting started and its
  first request failed.

## Before you deploy

1. **Federation settings are parsed strictly.** What to do: check every federation variable, system property and
   init-param you set. The switches that took anything but `true` as `false` now take `true` or `false` only (in any
   case): `OIDF_FEDERATION_IGNORE_SSL_ERRORS` and its superseded `OIDF_TRUST_CONTROLLER_IGNORE_SSL`, the federation
   servlet's init-params `ignoreSslErrors`, `corsEnabled` and `attestationChallengeEndpointEnabled`,
   `OIDF_ATTESTATION_REQUIRE_HOSTED_AGENT` (and `oidf.attestation.require_hosted_agent`), `OIDF_FETCH_ALLOW_HTTP` and
   `OIDF_FETCH_ALLOW_PRIVATE_NETWORKS`. `OIDF_FETCH_MAX_BODY_BYTES` takes a whole number of at least 1, where a value
   that did not parse was read as the default. The two automatic-registration limits take an int, 1 to 2147483647. A
   list of nothing (a comma alone) is refused where it was read as none or as the default:
   `OIDF_FEDERATION_SUBORDINATES`, the six attestation metadata init-params (`tokenEndpointAuthMethodsSupported` and
   the rest), `acceptedSigningAlgorithms`, `OIDF_FETCH_HOST_ALLOWLIST`, `OIDF_FAPI2_CLIENTS` and
   `oidf.attestation.required.claims` / `OIDF_ATTESTATION_REQUIRED_CLAIMS`; set `OIDF_FEDERATION_CLIENT_REGISTRATION_TYPES=none`
   to advertise neither type. Each `OIDF_FEDERATION_TRUST_ANCHORS` entry must be an Entity Identifier. A JSON setting
   set to the literal `null` is refused where it read as unset. Lists are space- or comma-separated, and the
   `signingAlgorithm` choices are read in any case. Why: a typo in a security switch quietly meant `false`, and a
   bound past an int wrapped round to one the check accepted (F-0198). What now happens: the components that read the
   setting are `FAILED_CONFIG` - `FEDERATION` for the federation servlet's settings, `FEDERATION`, `AUTO_REGISTRATION`
   and `ATTESTATION_AUTH` for the runtime's, `FAPI`, `HOSTING`, the fetch settings' readers - their endpoints answer
   503, readiness is 503, and server.log has an ERROR naming the setting, such as "OIDF_FETCH_ALLOW_HTTP must be true or
   false, not yes". How to tell: the start-up audit's components list shows the component `FAILED_CONFIG` with that
   reason. What to change: the value, to the strict spelling. Development-profile escape: with
   `OIDF_DEPLOYMENT_PROFILE=development` a switch's legacy spelling (`yes`, `no`, `1`, `0`, `on`, `off`) is still read,
   as `false` - what the reader before 0.6.0 made of it - with a WARN naming the strict spelling, and the start-up audit
   lists it under "legacy values"; production refuses it. A number, a list or an identifier has no escape: none of them
   was ever meant to be read the way it was.
2. **The federation servlet and the token endpoint now read the same federation variables the same way.** What to do:
   set `OIDF_FEDERATION_IGNORE_SSL_ERRORS` once, as an environment variable, and remove the federation servlet's
   init-params `ignoreSslErrors` and `trustControllerHost` if a web.xml of yours sets them. Why: until 0.6.0 the federation
   servlet read the switch from its init-param and then the environment variable only, and everything else - registration,
   the OGNL criteria, attestation - from the system property, the environment variable and the superseded name, so
   `-Doidf.federation.ignore.ssl.errors=true`, or only `OIDF_TRUST_CONTROLLER_IGNORE_SSL`, turned certificate checks off
   for registration but left them on for the servlet's own fetches (resolve, Trust Mark status), and the init-param did
   the reverse (F-0197). What now happens: both read one entry in one order - the servlet's init-param, the system
   property, the environment variable, the superseded name - so a deployment that set the switch by system property or
   by the superseded name now skips the federation servlet's certificate checks as well (in development; production
   refuses the switch however it is set), and one that set only the init-param skips them in the servlet alone, as
   before. The init-param `trustControllerHost` was never used and is now a removed name: set, the federation servlet
   does not start. OpenBao's address and token are now checked against their superseded names even when
   `OIDF_OPENBAO_URL` and `OIDF_OPENBAO_TOKEN` are set, so a `VAULT_ADDR` that disagrees with `OIDF_OPENBAO_URL` stops
   hosting starting. How to tell: the banner
   `FederationRuntimeConfig` logs names the source of each federation setting that is set ("Federation settings
   (federation-runtime, federation-entity): OIDF_FEDERATION_IGNORE_SSL_ERRORS from system-property
   oidf.federation.ignore.ssl.errors"), and a superseded name in use logs a WARN naming its replacement. What to change:
   one name, in the environment. Development-profile escape: none is needed - nothing is refused that was accepted,
   apart from the removed init-param, which did nothing.
3. **In-memory federation stores need the `in-memory-state` risk in production.** What to do: give the authority a
   store - `OIDF_AUTHORITY_DATA_STORE_ID`, a PingFederate JDBC data store on PostgreSQL with the authority's migrations
   applied - wherever hosting runs (`OIDF_AUTHORITY_ENTITY_ID` set), or the federation servlet issues Trust Marks
   (`OIDF_FEDERATION_TRUST_MARK_TYPES`) or keeps a key history (`OIDF_FEDERATION_HISTORICAL_KEYS=true`); or, on a
   standalone node that can lose them at a restart, add `in-memory-state` to `OIDF_ACCEPTED_RISKS`. Why: in memory the
   hosted entities, the Trust Mark grants and the key history are lost at every restart and invisible to any other node
   (Phase 3 plan, decision 9). What now happens: under production without the risk, `HOSTING` (the registry) or
   `FEDERATION` (Trust Marks, key history) is `REFUSED`, its endpoints answer 503 and readiness is 503. How to tell: the
   start-up audit's "code refusals" line names the store and the risk. What to change: the store, or the accepted risk.
   Development-profile escape: under development the store is kept in memory with a WARN, as before.
4. **Federation stores must be PostgreSQL in production.** What to do: point `OIDF_AUTHORITY_DATA_STORE_ID` at a data
   store on PostgreSQL. Why: the authority's tables and queries are written and tested for PostgreSQL only (Phase 3
   plan, decision 10), and H2 and HSQLDB were dropped in 0.5.0. What now happens: under production a direct
   `OIDF_AUTHORITY_JDBC_URL` that is not `jdbc:postgresql:` (forbidden in production in any case), or a data store whose
   database reports another product name, refuses `HOSTING` or `FEDERATION`, naming the product or only the URL's
   scheme. Hosting now opens one connection to the data store when it starts, to ask; a database that is down then is
   `FAILED_DEPENDENCY` and the supervisor starts hosting again when it answers. How to tell: the start-up audit's "code
   refusals" line, or a `FAILED_DEPENDENCY` reason naming `OIDF_AUTHORITY_DATA_STORE_ID`. What to change: the data
   store. Development-profile escape: under development another database is a WARN and is used.

## Notes

- The rig, 2026-09-30, slot 1 (`PF_RIG_NAME=pfai-p3-st5f`, PingFederate 13.1.3.0 on java 21.0.12.1, the branch's
  modules staged for the conformance profile), against this repository's own suite at release-v5.3.1: the conformance
  profile booted with `conformance/vars.env` unchanged, every component in the state 0.5.0's rig left it (FAPI and SSF
  READY, federation, automatic registration and attestation DISABLED by their switches), and `Fapi2ProfileFilter`
  read `OIDF_FAPI2_CLIENTS` through its catalogue entry. `fapi2-security-profile-final-test-plan` (`private_key_jwt`,
  DPoP, `plain_fapi`, OpenID Connect), plan `gakYJxmDDMtpD`: 56 modules, 50 PASSED, 3 REVIEW, 2 WARNING, 1 SKIPPED, 0
  FAILED - 0.5.0's result (plan `FTWRpvoSNQpNQ`). With `PF_PROFILE=federation` the same image booted with `FEDERATION`
  and `AUTO_REGISTRATION` READY and the banner listing `OIDF_FEDERATION_TRUST_CONTROLLER_HOST`,
  `OIDF_ATTESTATION_AUTH_ENABLED` and `OIDF_FEDERATION_SELF_ANCHOR` from the environment;
  `openid-federation-deployed-entity-test-plan`, plan `hLyVBFxwjeahz`: 5 modules, 5 WARNING, 0 FAILED - 0.5.0's result
  (plan `ZM7mLEPCPKzIN`).
- The production refusals of the federation stores are tested in unit tests only (U-0380): the rig cannot boot in
  production with a plaintext archive, and configures no authority store.
- The admin API can still grant Trust Marks into an in-memory registry while the federation servlet is refused for it
  (F-0370, low): those marks are never issued while `FEDERATION` is refused.
- `RegistrationExpirySweeper`'s two reads are the JVM-wide ownership latch `oidf.registration.sweeper.owner`, which the
  settings scan lists as not a setting; they stay as they are.
- F-0025, the ST-5 umbrella, is left to the release package.
