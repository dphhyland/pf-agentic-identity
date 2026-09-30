# Attestation settings: strict readers, in-memory state refused in production, and the challenge events

## Changelog

- client-attestation's two challenge endpoints, attestation-issuer's issuance, CAS metadata and attester-configuration
  servlets, `EvidencePolicy`, `AttesterSigningKey` and rar-model's `RarModels.fromEnvironment` read every setting through
  their settings catalogues - `attestation-challenge`, `attestation-issuer`, `evidence-policy`, openid-federation's
  `hosted-entity-signing` and `rar-models` - strictly (plan item ST-5). A value an entry refuses is the servlet's part
  `FAILED_CONFIG` at deploy, naming the setting, and its path answers 503; before 0.6.0 most of them were ignored with
  a warning, or read leniently, or failed at a first request.
- A client's `attestation_*` extended properties are parsed as the `issuance-client-properties` catalogue says: a value
  an entry refuses is that client's `invalid_client`, naming the property and never its value.
  `attestation_bundle_url` must be an http or https URL, `attestation_spiffe_bundle` a JSON object, and
  `attestation_evidence` is taken in any case.
- Under the production profile the attester's and the authorization server's in-memory stores - the challenges, the
  spent proof `jti`s and, at the attester, the evidence bindings, each namespace its own - need the `in-memory-state`
  accepted risk when `OIDF_REDIS_URL` is unset; without it `ProfileRefusals.refuse` refuses `ATTESTATION_AUTH` (the
  `oidf:as:*` stores) or `ATTESTATION_ISSUER` (the `oidf:cas:*` stores) at deploy, with a reason naming the risk and
  `OIDF_REDIS_URL` (plan item PR-2, Phase 3 plan decisions 9 and 15). `AttestationSupport.requireSharedState` is the
  rule; `AgentRegistrySupport.configureInMemoryRegistry` follows it too. The challenge rate limit's counters need no
  risk.
- rar-model's common-fields fallback reads `OIDF_DEPLOYMENT_PROFILE` as every other module does: `development`,
  trimmed, in any case (finding F-0160, and F-0107 with it).
- The two challenge endpoints emit `attestation.challenge.issued` and `attestation.challenge.refused` (`rate_limited`,
  `store_unavailable`, `method_not_allowed`), with the surface (`AS` or `CAS`) and never the challenge, from
  client-attestation's new `challenge` event catalogue; both are counted in `oidf_events_total` (plan item O-2).
- The challenge endpoints, the CAS metadata servlet and the attester-configuration servlet are parts of their
  component (plan item S-9), registered at deploy: the authorization server's challenge endpoint of `ATTESTATION_AUTH`,
  the rest of `ATTESTATION_ISSUER`. client-attestation depends on platform-pf for the part, the gate and the init-params.

## Before you deploy

1. **Attestation settings are parsed strictly.** From 0.6.0 each setting below is read by its catalogue entry, and a
   value the entry refuses leaves the servlet that reads it `FAILED_CONFIG` at deploy - the log and the health detail
   name the setting - and its path answers 503 `temporarily_unavailable`. Why: a wrong value used to be ignored, read
   as `false`, or found at the first request, so a typo quietly turned a check off or broke issuance later. The
   readers that were lenient: the switches `challengeRequired` (issuance, CAS metadata and attester-configuration
   servlets; anything but `true` was `false`) and `challengeEndpointEnabled` (CAS metadata; anything but `true` was
   `false`), now `true` or `false` in any case; the numbers `challengeCacheMaxEntries`, `challengeTtlSeconds`,
   `challengeRateLimitPerWindow`, `challengeRateLimitWindowSeconds`, `challengeRateLimitMaxCallers` (both challenge
   endpoints) and `replayCacheMaxEntries` (the authorization server's), which were ignored with a warning when they
   were not whole numbers; the lists `customClaimsRequired`, `customClaimsSupported` and
   `attestationSigningAlgValuesSupported` (and their `OIDF_ATTESTATION_CUSTOM_CLAIMS_*` sources), now split at spaces
   as well as commas, with a list of nothing (`, ,`) refused where it used to mean nothing or the default;
   `OIDF_WALLET_PROVIDER_JWKS` and `OIDF_ENTRA_AGENT_DIRECTORY`, which were ignored without a word when they were not
   JSON objects; `OIDF_ATTESTER_SPIRE_ENTRIES_URL`, which must be an http or https URL; and OpenBao's address and
   token, whose superseded names (`OPENBAO_ADDR`, `BAO_ADDR`, `VAULT_ADDR`, `OPENBAO_TOKEN`, `BAO_TOKEN`,
   `VAULT_TOKEN`) are refused when they hold another value than `OIDF_OPENBAO_URL` or `OIDF_OPENBAO_TOKEN`. The
   evidence policy's two variables, `OIDF_ATTESTER_MAX_EVIDENCE_LIFETIME_SECONDS` and
   `OIDF_ATTESTER_REQUIRE_SINGLE_AUDIENCE_EVIDENCE`, were strict already; a wrong one is now refused at deploy
   instead of by every issuance's 500. A client's `attestation_bundle_url` that is not an http or https URL, or an
   `attestation_spiffe_bundle` that is not a JSON object, is that client's `invalid_client`. How to tell: server.log
   and the health detail (`/agentic-identity/health`) name the setting, and `/agentic-identity/health/ready` answers
   503; `docs/configuration/attestation-challenge.md`,
   `attestation-issuer.md`, `evidence-policy.md`, `issuance-client-properties.md` and `rar-models.md` give each
   entry's rule. What to change: write each switch as `true` or `false`, each number as a whole number, and remove a
   list of nothing. Development-profile escape: under `OIDF_DEPLOYMENT_PROFILE=development` a switch spelt `yes`,
   `no`, `1`, `0`, `on` or `off` is read as `false`, as the reader before 0.6.0 read it, with a warning naming the
   strict spelling; production refuses it. A number has no legacy spelling (a padded number is trimmed in both).
2. **Attestation without Redis needs the `in-memory-state` risk in production.** From 0.6.0, under the production
   profile with `OIDF_REDIS_URL` unset, the authorization server's attestation state (`oidf:as:*`) and the attester's
   (`oidf:cas:*`) would be kept in each node's memory, and the component that uses it is refused at deploy unless
   `OIDF_ACCEPTED_RISKS` names `in-memory-state`: `ATTESTATION_AUTH` - the token-endpoint check, whose challenge
   endpoint now starts at deploy - and `ATTESTATION_ISSUER`, the attester. Why: every node keeps its own replay cache,
   challenges and evidence bindings, lost on restart and invisible to the other nodes, so a replayed proof or a
   challenge redeemed twice passes on a second node, and a restart forgets every spent `jti`. How to tell: the start-up
   audit lists the refusal ("... would be kept in this node's memory, because OIDF_REDIS_URL is unset"), the
   component is `REFUSED` in the health detail (`/agentic-identity/health`), `/agentic-identity/health/ready` answers 503,
   and its paths answer 503. What to change: set
   `OIDF_REDIS_URL` to a `rediss://` URL; or, on a standalone node, add `in-memory-state` to `OIDF_ACCEPTED_RISKS`; or,
   where the component is not used, switch it off (`OIDF_ATTESTATION_ISSUER_ENABLED=false`,
   `OIDF_ATTESTATION_AUTH_ENABLED=false`) - an attester left unswitched in production is inferred and so is refused
   too. A clustered deployment must use Redis: the risk does not make in-memory state shared. Development-profile
   escape: in development the stores stay in memory with a warning.
3. **The agent registry needs a data store or the risk in production.** From 0.6.0
   `AgentRegistrySupport.configureInMemoryRegistry()` under the production profile without the `in-memory-state` risk
   refuses `ATTESTATION_ISSUER` and throws, so the part that called it is `REFUSED`. Why: the in-memory registry
   forgets every `agent_id` on restart and re-mints them, so an agent's identity changes under the relying parties
   that recorded it. How to tell: the start-up audit names the refusal. What to change: nothing for the war this
   repository ships, which configures no agent registry; a host that configures one calls
   `configureJdbcRegistry(DataSource)` in production, or accepts `in-memory-state` on a standalone node.
   Development-profile escape: in development the in-memory registry is allowed with a warning.
4. **The attestation challenge and discovery endpoints follow their component's switch.** From 0.6.0
   `POST /federation/attestation-challenge` is a part of `ATTESTATION_AUTH`, and `GET /federation/attestation/challenge`,
   `/.well-known/client-attestation-service` and `/.well-known/client-attester` (with `/federation/attester-configuration`)
   are parts of `ATTESTATION_ISSUER`, each registered at deploy. Why: each reads settings that must fail at deploy, and
   a component switched off or refused should not keep serving half of itself. How to tell: with the component
   switched off (`OIDF_ATTESTATION_AUTH_ENABLED=false` or `OIDF_ATTESTATION_ISSUER_ENABLED=false`) those paths answer
   404 `not_found`, as a war without them would; with it refused or failed, 503 `temporarily_unavailable`. What to
   change: a client that fetches a challenge or reads the attester's discovery documents from a server with the
   component switched off must stop doing so. There is no development-profile escape: the switches mean the same in
   both profiles.

## Notes

Package ST5A of Phase 3 (plan items ST-5 for the attestation side, PR-2's in-memory stores, O-2's challenge events).
Built on origin/main 6606b141 (2026-09-30).

The in-memory rule is one method, `AttestationSupport.requireSharedState(namespace)`, called from the start function
of a part that will use a namespace's stores; each namespace's component is `AttestationSupport.componentOf`. The
authorization server's challenge endpoint calls it for `oidf:as:*` and so refuses `ATTESTATION_AUTH`, whose
token-endpoint filter shares those stores; the attester's issuance servlet and challenge endpoint call it for
`oidf:cas:*`. A refusal in code refuses every part of the component (`ComponentGate` answers 503 on each once one part
is `REFUSED`). Two other users of the attestation stores are not wired here, because their classes are other packages':
the federation endpoints' spent assertion `jti`s (`oidf:fed:endpoint:*`, `OpenIdFederationServlet`) and automatic
registration's use of the authorization server's replay cache (`FrontChannelAutoRegistrationFilter`); finding F-0335
records them.

F-0160: rar-model now reads the profile through `DeploymentProfile.of(env).isDevelopment()`. A deployment set to
`OIDF_DEPLOYMENT_PROFILE=Development` (capital D) - development everywhere else since PR1 - now has the common-fields
fallback on in rar-model too, so its models fingerprint (`RarModels.SEMANTICS` is unchanged; the fallback flag is part
of the canonical JSON) differs from the one 0.5.0 logged. That is harmless: it is a development deployment, and every
loader - the token-endpoint filter, the attester, the OGNL criterion and the RAR plugin - reads the same variable
through the same code, so they change together and still agree with each other (the plugin refuses a request only when
its fingerprint differs from the filter's). `DeploymentProfile.isExactlyDevelopment` in libs/platform has no caller in
main code now; platform's owner can delete it. F-0107 closes with F-0160: the plugin's reading
(`GovernanceEngineConfig.profileOf`, `DeploymentProfile.parse`) and rar-model's now meet.

Per-client properties: a value the catalogue refuses is the client's `invalid_client` with a message that names the
property and what it must be, never the value, as S4CP's TTL cap does. The attester has no event for a client whose
configuration is refused; F-0336 records it for the package that owns the issuance request path.

Verified locally on 2026-09-30 on JDK 17 (the four modules' `mvn install` with their coverage gates, the settings scan,
the configuration reference's `--check`, pf-integration's `EventsCataloguedTest`); the PR records the JDK 21 run and
CI. The rig was not booted for this package: U-0345 records what a production-profile PingFederate without Redis should
show at deploy.

Umbrella: F-0025 (ST-5's strict readers).
