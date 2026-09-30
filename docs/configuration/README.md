# Configuration reference

Every setting each component reads - its type, default, range, what it does, what happens when it is wrong,
and how it stands with the deployment profile - one page per component, generated from the component's settings
catalogue by `tools/config-reference.py` (plan item ST-4). The catalogue is the only place a row is written:
[docs/development/settings-catalogue.md](../development/settings-catalogue.md) is its format, and
`tools/settings-scan.py` holds it to the code both ways - every setting the code reads is catalogued, and every
catalogued setting is read. The Build workflow's lint job runs `tools/config-reference.py --check`, which fails
when a page here, the list below or [docs/extended-properties.json](../extended-properties.json) is not what the
catalogues generate.

To change a row, change the catalogue in the module that reads the setting, then run
`python3 tools/config-reference.py` and commit what it writes. A page here is never edited by hand; the only text
written by hand is this page, outside its generated list.

## The components

<!-- GENERATED: the components, by tools/config-reference.py -->

| Component | Module | Package | Settings |
|---|---|---|---|
| [components](components.md) | `libs/platform` | `com.pingidentity.ps.oidf.platform.component` | 9 |
| [deployment-profile](deployment-profile.md) | `libs/platform` | `com.pingidentity.ps.oidf.platform.profile` | 3 |
| [platform-redis](platform-redis.md) | `libs/platform` | `com.pingidentity.ps.oidf.platform.redis` | 9 |
| [rar-models](rar-models.md) | `libs/rar-model` | `com.pingidentity.ps.oidf.rar.model` | 2 |
| [outbound-fetch](outbound-fetch.md) | `libs/oidf-jose` | `com.pingidentity.ps.oidf.jose` | 4 |
| [attestation-challenge](attestation-challenge.md) | `libs/client-attestation` | `com.pingidentity.ps.oidf.clientattestation.servlet` | 6 |
| [federation-entity](federation-entity.md) | `libs/openid-federation` | `com.pingidentity.ps.oidf.federation` | 21 |
| [federation-resolution](federation-resolution.md) | `libs/openid-federation` | `com.pingidentity.ps.oidf.federation` | 5 |
| [hosted-entity-signing](hosted-entity-signing.md) | `libs/openid-federation` | `com.pingidentity.ps.oidf.authority` | 2 |
| [operator-auth](operator-auth.md) | `libs/platform-pf` | `com.pingidentity.ps.oidf.platform.pf.auth` | 11 |
| [pf-audit](pf-audit.md) | `libs/platform-pf` | `com.pingidentity.ps.oidf.platform.pf.audit` | 2 |
| [attestation-token-endpoint](attestation-token-endpoint.md) | `servlets/pf-integration` | `com.pingidentity.ps.oidf.servlet.clientregistration` | 4 |
| [client-properties](client-properties.md) | `servlets/pf-integration` | `com.pingidentity.ps.oidf.servlet.clientregistration` | 22 |
| [fapi2-profile](fapi2-profile.md) | `servlets/pf-integration` | `com.pingidentity.ps.oidf.servlet.fapi2` | 1 |
| [federation-runtime](federation-runtime.md) | `servlets/pf-integration` | `com.pingidentity.ps.oidf.pf` | 54 |
| [hosted-entities](hosted-entities.md) | `servlets/pf-integration` | `com.pingidentity.ps.oidf.servlet.trustanchor` | 8 |
| [registration](registration.md) | `servlets/pf-integration` | `com.pingidentity.ps.oidf.servlet.clientregistration` | 9 |
| [attestation-issuer](attestation-issuer.md) | `servlets/attestation-issuer` | `com.pingidentity.ps.oidf.servlet.attestation` | 16 |
| [evidence-policy](evidence-policy.md) | `servlets/attestation-issuer` | `com.pingidentity.ps.oidf.issuer` | 13 |
| [issuance-client-properties](issuance-client-properties.md) | `servlets/attestation-issuer` | `com.pingidentity.ps.oidf.servlet.attestation` | 12 |
| [ssf-logout-signal](ssf-logout-signal.md) | `servlets/ssf` | `com.pingidentity.ps.oidf.servlet.ssf` | 1 |
| [ssf-transmitter](ssf-transmitter.md) | `servlets/ssf` | `com.pingidentity.ps.oidf.ssf` | 54 |
| [rar-pdp-processor](rar-pdp-processor.md) | `plugins/rar-paz-plugin` | `com.pingidentity.ps.oidf.rar` | 24 |
| [instance-registry](instance-registry.md) | `plugins/instance-registry-datasource` | `com.pingidentity.ps.oidf.registry` | 4 |
| [ciba-simulator](ciba-simulator.md) | `plugins/ciba-sim` | `com.pingidentity.ps.oidf.cibasim` | 2 |
| [device-enrolment](device-enrolment.md) | `services/device-enrolment` | `com.pingidentity.ps.oidf.enrolment` | 35 |
| [gm-api](gm-api.md) | `services/gm-api/servlet` | `au.com.idpartners.gm.servlet` | 6 |

<!-- END GENERATED -->

## Reading a row

The columns are the style guide's four ([style-guide.md](../development/style-guide.md#settings)), with two more.

- **Setting** - the name the operator sets. An environment variable stands alone; any other kind says what it
  is: an init-param (an `<init-param>` of the servlet or filter in the `web.xml` that deploys it), a system
  property, a plugin
  field (a field of the plugin's screen in PingFederate's admin console) or an extended property (a property of
  an OAuth client in PingFederate, which PingFederate must be told about first - below). When a setting is read
  from more than one place, they follow in the order they are tried: the first one set wins. A superseded name is
  still read when the new one is unset. The `OIDF_TRUST_*` names, and any read through `platform.settings`, log a
  warning when used and are refused when set to a different value from the new one; `OPENBAO_ADDR`, `BAO_ADDR`,
  `VAULT_ADDR` and the matching `*_TOKEN` names are plain fallbacks, tried in turn with no warning (checked
  2026-09-29 in `RegistryHostedEntitySigner`). "Or from the file ... names" is a secret that may be read from a
  file instead.
- **Default** - what applies when nothing sets it, or Unset, and then what a value must be: a whole number in its
  range, seconds, one of a list of choices, an https URL, a JSON object, a list. How a list is separated is in its
  description, because readers differ: most split on commas only, and a list written with spaces is then one
  item (`OIDF_FAPI2_CLIENTS=a b` holds no client to FAPI 2.0). A
  switch is `true` or `false`, in any case, and anything else is refused unless its row says otherwise. A secret
  is never shown in a message, a log line or a `toString`.
- **What it does** - one line.
- **When it's wrong** - when a wrong value shows, then what it does:
  - **Doesn't start** - the component that reads it fails at deploy and the log names the setting. For a module
    running in PingFederate, the component takes `pf-runtime.war` with it, so PingFederate's runtime endpoints do
    not start.
  - **First request** - a servlet that starts lazily fails on its first request, and only its paths fail.
  - **Per request** - nothing at start-up; the requests that need it fail.
  - **Not checked** - nothing checks the value; the sentence says what a wrong one does instead.
- **Profile** - how the setting stands with the deployment profile (`OIDF_DEPLOYMENT_PROFILE`): Any; Not in
  production; Required in production; or In production only as an accepted risk, whose id names it - followed, for
  the two that act on values, by the values they act on (`true`, `log` or `disable`, a `redis://` URL, any value),
  and by the components the setting refuses when they are not its page's. From 0.6.0 production enforces it: a
  violation refuses the components named at the top of the page
  ([deployment-profile.md](../operator/deployment-profile.md)).
- **Security** - Yes when a wrong value weakens a security property: what is trusted, checked, refused or kept
  secret.

## How a setting is read

Most settings are environment variables, and most can also be a Java system property, which wins; a row names
every place a setting is read, so the row is the answer, not the rule of thumb.
[docs/federation/configuration.md](../federation/configuration.md#how-a-setting-is-read) says how the federation
modules read theirs and when a setting is read, and
[settings-catalogue.md](../development/settings-catalogue.md#how-a-setting-is-resolved) says how `platform.settings`
resolves one.

**Extended properties.** PingFederate drops an extended property it has not been told about - silently - so a
per-client setting written onto a client that PingFederate does not declare is never applied.
[docs/extended-properties.json](../extended-properties.json), generated from every extended-property row here, is
the list a deployment declares, typically as a `pingfederate_extended_properties` resource in its own Terraform
([conformance/terraform/extended-properties.tf](../../conformance/terraform/extended-properties.tf) reads it).

## Every name, A to Z

`python3 tools/config-reference.py --index settings-index.md` writes an index of every name a component reads -
entry names, the other names they are read under, superseded names - with the component that reads it. It is
generated when someone wants it and never committed: it moves with every catalogue, and a committed copy would be
a conflict in every pull request that adds a setting (programme plan, decision 18).

## What is not here

- Settings of the modules that never reach a deployment: `libs/testkit` and `services/harness`, listed with the
  reason in `tools/settings-scan-exemptions.txt`. CONTRIBUTING.md and the harness's README describe theirs.
- Anything read outside Java - the image entrypoint's shell variables, the conformance rig's - which the scan does
  not see.
- The modules' own README tables, written by hand before this reference existed; plan item D-8 replaces them with
  links here.
