# Settings catalogues for the attestation side, the RAR models and the plugins

## Changelog

- Plan item ST-3 (part 2 of 3): eight more settings catalogues, one per component, under
  `src/main/resources/META-INF/oidf-settings/`: `attestation-challenge` (client-attestation's two challenge
  endpoints), `rar-models` (rar-model's `OIDF_RAR_MODELS_FILE` and `OIDF_RAR_MODELS`), `attestation-issuer`,
  `evidence-policy` and `issuance-client-properties` (attestation-issuer, the last its eleven per-client
  `attestation_*` extended properties and `attestation_asserted_context_resolver`), `rar-pdp-processor` (the RAR
  plugin's fifteen configuration fields and `OIDF_RAR_EXTRA_TYPES`), `instance-registry` (the data source's two
  fields and its filter field) and `ciba-simulator` (`OIDF_CIBA_SIM_ENABLED` and `OIDF_CIBA_SIM_DIR`) - 58
  settings with their sources, defaults, types, profile classes and whether they bear on security. A plugin field
  is catalogued under the name PingFederate shows for it, and its entry names the plugin's descriptor id. The
  settings scan no longer exempts these six modules. The jars carry the catalogues; nothing reads them at run
  time yet. New in the register: F-0230, F-0231.

## Before you deploy

None.

## Notes

Nothing a deployment sets changes: no reader was touched, and the catalogues describe what the code reads today,
lenient readers included (ST-5 makes them strict in Phase 3). Where a module's README and the code disagreed, the
catalogue follows the code and the README row was corrected: attestation-issuer's rows for the OpenBao
init-params (used only when both are set), `OIDF_ATTESTER_SIGNING_JWK` (the attester's signing key, not a client
source), the wallet-provider trust names (the current `OIDF_FEDERATION_*` names, the old ones still read with a
warning), the metadata servlet's init-params (their defaults, and `customClaimsSupported`'s property and
environment fallbacks) and the challenge rate limits (0 or less is the default).

The RAR models' two settings carry the rule plan decision 2 set: one document, from the environment, read by every
classloader - the token-endpoint filter, the attester, the issuance criterion and the RAR plugin - and never a
plugin field; each logs the set's SHA-256 fingerprint, and the plugin refuses a request whose attestation context
carries another. The per-client `attestation_*` names are catalogued as extended properties, so the
`docs/extended-properties.json` that ST-4 generates will list them and a consumer's Terraform will be asked to
declare them (F-0041, which ST-4 closes).

What the cataloguing found, recorded as findings: `attestation_asserted_context_resolver` is read from a client's
properties but is not among the names the attester reads off a PingFederate client, so there it has no effect and
a request's asserted context is ignored (F-0230); and the catalogue format records a removed name only for an
environment variable, a system property or an init-param, so the RAR plugin's "Deny unless PERMIT" field,
removed in 0.4.0 and ignored when an old configuration still holds it, is not in its catalogue (F-0231).
