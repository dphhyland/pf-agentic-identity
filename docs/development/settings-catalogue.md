# Settings catalogues

Every setting a module reads is described once, in a catalogue: one JSON document per component, at
`src/main/resources/META-INF/oidf-settings/<component>.json` in the module that reads the settings (plan items
ST-2 and ST-3). `platform.settings` loads and checks it ([libs/platform](../../libs/platform/README.md#settings)),
the configuration reference is generated from it (ST-4), and readers resolve their settings through it (ST-5).

The catalogue is data rather than Java for two reasons. The plugins shade and relocate platform, so a Java type
describing a setting would be a different class in every plugin and invisible to anything reading across the
reactor. And one file per component keeps packages that catalogue different components, at the same time, in
different files.

This page is the format. The worked example is a test catalogue,
[example.json](../../libs/platform/src/test/resources/META-INF/oidf-settings/example.json) in platform's test
resources; the production catalogues arrive with ST3A (platform, platform-pf, oidf-jose, openid-federation,
pf-integration), ST3B and ST3C (the rest), and with the Phase 2 packages that add settings of their own.

## Where a catalogue lives, and who owns it

- **One file per component.** A component is what an operator configures as one thing: the federation entity,
  automatic registration, the policy decision point, the SSF transmitter. The file is named for it:
  lower-case words joined by hyphens, and the `component` member says the same name.
- **In the module that reads the settings**, under `src/main/resources/META-INF/oidf-settings/`, so the file
  ships in that module's jar. `Catalogue.load` reads it from the caller's classloader: a servlet's jar in the
  webapp, the engine's copy on the engine's loader, a plugin's own jar in the plugin's loader. The webapp's
  loader also sees the engine's copy: PingFederate stages each jar in `pf-runtime.war`'s `WEB-INF/lib` and in
  `server/default/deploy`, which is on the webapp loader's parent, and Jetty's webapp loader returns both. So
  copies of one file with identical bytes are accepted as one module's file, and copies that differ are
  refused, naming two that differ: two modules cannot ship one component.
- **Exactly one owning package.** The `package` member names the one Java package whose code resolves these
  settings. A module with several components has one file per component, each naming its own package; when two
  packages of one module read settings, they are two components, or one package resolves the settings and hands
  the values to the other (as `FederationRuntimeConfig` does for the whole of pf-integration today).
  `tools/settings-scan.py` checks the package against the code: it, or a package under it, reads at least one
  of the file's settings.
- **Families.** `families` lists the `OIDF_*` prefixes the component owns, such as `OIDF_PDP_`. They are what
  `UnknownKeys.find` looks under for a set name no catalogue declares. A family may be shared by two components;
  a name is known when any loaded catalogue declares it.

## The document

Every member is required but `components`, and a member not listed here is refused.

| Member | What it holds |
|---|---|
| `format` | `1` |
| `component` | the component's name, the same as the file's |
| `module` | the module's path from the repository root: `servlets/pf-integration` |
| `package` | the one Java package that owns the file |
| `families` | the `OIDF_*` prefixes it owns, each ending in `_` (may be empty) |
| `components` | optional (0.6.0): the S-9 components its settings belong to, such as `["SSF", "SSF_RECEIVER"]`; without it, its line in the [components table](#components) |
| `settings` | its entries, below, in the order a reference prints them |
| `removed` | the names it no longer reads, below (may be empty) |

## An entry

Every member is required but `governed` and `components`, `min` and `max` for a ranged type and `choices` for a
`choice` as well, and nothing else.

| Member | What it holds |
|---|---|
| `name` | the name the operator sets, and every message gives: `OIDF_PDP_MODE`, `signingAlgorithm` |
| `kind` | `env`, `system-property`, `init-param`, `plugin-field` or `extended-property` |
| `type` | `bool`, `int`, `long`, `seconds`, `millis`, `string`, `choice`, `https-url`, `url`, `json-object`, `words`, `path` or `secret` |
| `default` | the default as text, a number, `true` or `false`, or `null` for none; it must parse as the type |
| `min`, `max` | the range, inclusive, for `int`, `long`, `seconds` and `millis` |
| `choices` | for `choice`: the values allowed, read in any case, returned as spelt here |
| `description` | what it does, one line: the reference's "What it does" |
| `when_wrong` | `{"effect": ..., "detail": ...}`: when a wrong value shows, and the sentence the reference prints |
| `profile` | `any`, `forbidden-in-production`, `accepted-risk:<id>` or `required-in-production` |
| `security` | whether it bears on security; the reference marks it |
| `sources` | where it is read, in precedence order: `[{"from": "system-property", "name": "oidf.pdp.mode"}, {"from": "env", "name": "OIDF_PDP_MODE"}]` |
| `aliases` | superseded names still read: `[{"name": ..., "sources": [...]}]` |
| `file` | whether a secret may be read from the file its `_FILE` variant names |
| `governed` | optional (0.6.0): the values its profile class acts on - see [Governed values](#governed-values) |
| `components` | optional (0.6.0): the components this entry refuses, when they are not the catalogue's |

**Kinds.** `env`, `system-property` and `init-param` are resolved from their sources, and one of the sources
is of the kind's own source with the entry's name: an `env` entry named `OIDF_PDP_MODE` is read from the
environment as `OIDF_PDP_MODE`, whatever else it is read from and in whatever order. `plugin-field` (a field of
a plugin's configuration screen) and `extended-property` (an OAuth client's extended property) are supplied by
PingFederate: they have no sources, aliases or file, and a reader parses the value it is given
(`Settings.parse`).

**Types.** `bool` is `true` or `false` in any case and always has a default. The ranged types are whole numbers
within `min` and `max` (an `int`'s range fits an `int`); `seconds` and `millis` are read as a `Duration`. A
`choice` has at least one choice, none repeated in any case. `https-url` is an absolute https URL with a host,
`url` http or https. A system property's name may carry upper-case letters (0.6.0), as the JDK's
`jdk.internal.httpclient.disableHostnameVerification` and SSF's `oidf.ssf.<camelCase>` properties do. `json-object` is one JSON object read by `platform.json`: duplicate member names, content
after it, nesting past 32 and number literals past 128 characters are refused. `words` are space- or
comma-separated, and a list of nothing is refused. A `secret` is text that no message, log line or `toString`
shows; it bears on security, has no default, and is the only type that may set `file`.

**When it's wrong.** `effect` is one of the style guide's four
([style-guide.md](style-guide.md#settings)): `doesnt-start` (the component fails at deploy and the log names
the setting), `first-request`, `per-request`, or `not-checked`, whose `detail` says what a wrong value does
instead. `detail` is the sentence the reference prints: "Anything but true or false".

**Profile.** How the setting stands with the deployment profile (PR-1, PR-2): allowed in `any` profile,
`forbidden-in-production`, allowed in production only under `accepted-risk:<id>` (lower-case words joined by
hyphens), or `required-in-production`, where unset or blank is the violation. From 0.6.0 the production profile acts
on it: see [Enforcement](#enforcement).

## How a setting is resolved

`Settings` first refuses any of the catalogue's removed names that is set in its own source, whichever
setting is being read, naming the replacement (or saying nothing replaces it) and the release it went in; see
removed names below. It then resolves the entry in this order, and returns the value with its provenance -
which source and which name supplied it, or `default`:

1. The first of `sources` set to something not blank supplies the value, trimmed.
3. For a `secret` with `file`, each source has a `_FILE` variant: `OIDF_X_FILE` for an environment variable,
   `oidf.x.file` for a system property, `xFile` for an init-param. The first one set names a file whose content,
   with one trailing newline trimmed, is the value. The name and its `_FILE` variant both set is refused, naming
   both. A file that cannot be read, is empty, or holds more than 64 KiB is refused, naming the file and never
   its content; so is a value that is not a path.
3. Each alias, read from its own sources in their order: used when nothing above supplied a value, with a
   warning logged once; the same value under both names warns that the old one is redundant; different values
   are refused, naming both names and neither value.
4. Otherwise the default, which may be none.

The value is then parsed as the type, by the strict parsers `FederationRuntimeConfig` used, with their
messages: the setting's name and the value refused, never a secret's value.

A removed name is `{"name": ..., "from": "env", "replacement": "OIDF_NEW" or null, "release": "0.4.0"}`, where
`from` is `env`, `system-property`, `init-param` or (from 0.6.0) `plugin-field`: a plugin's saved configuration keeps a
field its descriptor no longer declares (F-0231), and the plugin refuses one still set with
`Catalogue.refuseRemovedFields`. Its
name, like every source name, alias name and `_FILE` variant, is declared once in a catalogue. A replacement
is a setting of the same catalogue, or null; a replacement the catalogue does not have is refused, so a typo
there cannot quietly name nothing. Set in the source it was read from, a removed name is refused on the
component's first read (`Catalogue.refuseRemoved`, which `Settings` calls before every value). It counts as
declared for `UnknownKeys.find`, which leaves it to that refusal and its better message.

## An example

Two entries from the worked example, a switch with a superseded name and a secret that may come from a file:

```json
{
  "format": 1,
  "component": "example",
  "module": "libs/platform",
  "package": "com.pingidentity.ps.oidf.platform.settings",
  "families": ["OIDF_EXAMPLE_"],
  "settings": [
    {
      "name": "OIDF_EXAMPLE_FAIL_CLOSED",
      "kind": "env",
      "type": "bool",
      "default": true,
      "description": "Whether a request whose check fails is refused, rather than passed on",
      "when_wrong": {"effect": "doesnt-start", "detail": "Anything but true or false"},
      "profile": "accepted-risk:example-fail-open",
      "security": true,
      "sources": [
        {"from": "system-property", "name": "oidf.example.fail.closed"},
        {"from": "env", "name": "OIDF_EXAMPLE_FAIL_CLOSED"}
      ],
      "aliases": [
        {"name": "OIDF_EXAMPLE_REFUSE_ON_FAILURE", "sources": [
          {"from": "system-property", "name": "oidf.example.refuse.on.failure"},
          {"from": "env", "name": "OIDF_EXAMPLE_REFUSE_ON_FAILURE"}
        ]}
      ],
      "file": false
    },
    {
      "name": "OIDF_EXAMPLE_TOKEN",
      "kind": "env",
      "type": "secret",
      "default": null,
      "description": "The bearer token sent to the remote service",
      "when_wrong": {"effect": "per-request", "detail": "The remote service refuses every call"},
      "profile": "required-in-production",
      "security": true,
      "sources": [{"from": "env", "name": "OIDF_EXAMPLE_TOKEN"}],
      "aliases": [],
      "file": true
    }
  ],
  "removed": [
    {"name": "OIDF_EXAMPLE_STRICT", "from": "env", "replacement": "OIDF_EXAMPLE_FAIL_CLOSED", "release": "0.4.0"}
  ]
}
```

Read through it:

```java
Settings example = Settings.of("example");                    // this class's loader, this process's sources
boolean failClosed = example.bool("OIDF_EXAMPLE_FAIL_CLOSED"); // true unless set; the old name still read
Secret token = example.secret("OIDF_EXAMPLE_TOKEN");          // or from OIDF_EXAMPLE_TOKEN_FILE
Resolved r = example.resolve("OIDF_EXAMPLE_FAIL_CLOSED");      // r.provenance(): "env OIDF_EXAMPLE_REFUSE_ON_FAILURE"
```

A servlet adds its init-params with `Settings.of("...").with(InitParams.sources(config))`
([libs/platform-pf](../../libs/platform-pf/README.md#settings)).


## Governed values

An entry classed `forbidden-in-production` or `accepted-risk:<id>` acts on some of its values, not all: a switch that
is `false` by default is forbidden when it is `true`, not when it is `false`. `governed` says which, in one of two
forms, or leaves it to the default rule (`platform.settings.Governed`):

- `"governed": ["log", "disable"]` - these values, for a `bool` or a `choice` only. Each must be a value of the type,
  none twice, and the default may not be one: unset would then be the case the profile governs, and nothing could see
  it.
- `"governed": {"schemes": ["redis"]}` - a URL whose scheme, the text before `://` in any case, is one of these; for a
  `string`, `secret`, `url` or `https-url` only. `OIDF_REDIS_URL` uses it for `redis://`. It may add
  `"unless_set": ["OIDF_REDIS_URL"]`: other entries of the same catalogue that the reader takes first. While any of
  them is set (or set to something its resolver refuses, where the reader stops too), this entry is not read, so the
  start-up sweep does not judge it. `REDIS_URL` uses it: `RedisConfig.url()` reads it only when `OIDF_REDIS_URL` and
  `oidf.redis.url` are unset, so a managed Redis's `redis://` `REDIS_URL` beside a `rediss://` `OIDF_REDIS_URL` refuses
  nothing. The loader and the scan refuse a name that is not an entry of the catalogue, the entry's own, or one twice.
- Absent - the default rule: a `bool` governs every value but its default; a `choice` of exactly two with a default
  governs the other one; a type with no default governs any value set. Any other classed entry - a `choice` of more
  than two, a number or text with a default - must say, and the loader refuses it until it does.

An entry classed `any` or `required-in-production` has no `governed`. The configuration reference prints the governed
values in the Profile column.

## Components

A violation refuses components, by S-9's names: the entry's `components`, else its catalogue's, else the catalogue's
line in this table. The table is what the catalogues of 0.6.0 would carry: `DefaultComponents` holds the same lines,
`DefaultComponentsTest` holds it to this table, and `tools/settings-scan.py` checks that every catalogue is in the
table or names its own components, and that the table names only catalogues. An owner who narrows a catalogue's
components writes them into the catalogue, per catalogue or per entry, and deletes its line here.

The nine S-9 components are `FEDERATION`, `AUTO_REGISTRATION`, `ATTESTATION_AUTH`, `ATTESTATION_ISSUER`, `HOSTING`,
`SSF`, `SSF_RECEIVER`, `OPERATOR_API` and `FAPI` ([components.md](../operator/components.md)); `GM_API` is gm-api's
own. A plugin or a service that registers no component is named by its catalogue (`CIBA_SIMULATOR`,
`RAR_PDP_PROCESSOR`, `INSTANCE_REGISTRY`, `DEVICE_ENROLMENT`), so a violation always names what it refuses, and the
package that converts that reader asks `ProfileRefusals` under that name.

<!-- components table: tools/settings-scan.py and DefaultComponentsTest read it -->
| Catalogue | Components |
|---|---|
| `attestation-challenge` | `ATTESTATION_AUTH`, `ATTESTATION_ISSUER` |
| `attestation-issuer` | `ATTESTATION_ISSUER` |
| `attestation-token-endpoint` | `ATTESTATION_AUTH` |
| `ciba-simulator` | `CIBA_SIMULATOR` |
| `client-properties` | `FEDERATION`, `AUTO_REGISTRATION`, `ATTESTATION_AUTH` |
| `components` | none |
| `deployment-profile` | `FEDERATION`, `AUTO_REGISTRATION`, `ATTESTATION_AUTH`, `ATTESTATION_ISSUER`, `HOSTING`, `SSF`, `SSF_RECEIVER`, `OPERATOR_API`, `FAPI` |
| `device-enrolment` | `DEVICE_ENROLMENT` |
| `evidence-policy` | `ATTESTATION_ISSUER` |
| `fapi2-profile` | `FAPI` |
| `federation-entity` | `FEDERATION`, `HOSTING` |
| `federation-resolution` | `FEDERATION`, `AUTO_REGISTRATION` |
| `federation-runtime` | `FEDERATION`, `AUTO_REGISTRATION`, `ATTESTATION_AUTH` |
| `gm-api` | `GM_API` |
| `hosted-entities` | `HOSTING`, `OPERATOR_API` |
| `hosted-entity-signing` | `HOSTING`, `ATTESTATION_ISSUER` |
| `instance-registry` | `INSTANCE_REGISTRY` |
| `issuance-client-properties` | `ATTESTATION_ISSUER` |
| `operator-auth` | `OPERATOR_API` |
| `outbound-fetch` | `FEDERATION`, `AUTO_REGISTRATION`, `ATTESTATION_AUTH`, `ATTESTATION_ISSUER`, `HOSTING` |
| `pf-audit` | `FEDERATION`, `AUTO_REGISTRATION`, `ATTESTATION_AUTH`, `ATTESTATION_ISSUER`, `HOSTING`, `SSF`, `SSF_RECEIVER`, `OPERATOR_API`, `FAPI` |
| `platform-redis` | `ATTESTATION_AUTH`, `ATTESTATION_ISSUER`, `OPERATOR_API` |
| `rar-models` | `ATTESTATION_AUTH` |
| `rar-pdp-processor` | `RAR_PDP_PROCESSOR` |
| `registration` | `FEDERATION`, `AUTO_REGISTRATION` |
| `ssf-logout-signal` | `SSF` |
| `ssf-transmitter` | `SSF`, `SSF_RECEIVER` |
<!-- end components table -->
The table is coarse on purpose where one catalogue serves several components: a switch in `federation-runtime`
refuses `FEDERATION`, `AUTO_REGISTRATION` and `ATTESTATION_AUTH` together; its entries carry no per-entry
`components` in 0.6.0 ([F-0297](../findings/F-0297.yaml), open for 0.7.0), where `ssf-transmitter`'s do. `deployment-profile` and `pf-audit` refuse every component: the profile and the audit switch
govern the whole process.

## Enforcement

From 0.6.0 (plan item PR-5) the production profile is enforced from the catalogues:

- **At start-up.** platform-pf's lifecycle listener evaluates every `env` and `system-property` entry whose class is
  not `any` (`ProfileAudit.evaluate`) before any filter's or servlet's `init`, and publishes the result in
  `ProfileRefusals`. A governed value set without its risk accepted, a required value unset, a governed value that
  does not parse, an `OIDF_*` name under a family no catalogue declares (`UnknownKeys`), and a catalogue that cannot
  be loaded are each a violation naming the setting, the reason, the fix and the components. Under production,
  `Startup.begin` makes every part of a refused component `REFUSED` before its start runs, so its gate answers 503;
  under development nothing is refused and the list is a warning. A required setting refuses only a component
  switched on.
- **At read.** What the sweep cannot see - a value from an init-param, a plugin field, an extended property - is
  refused when `Settings` reads it: `ProfileRefused`, a `SettingRefused` that a part's `init` records as `REFUSED`.
- **In code.** A condition that is not a setting, such as a store in memory, is refused with
  `ProfileRefusals.refuse` or `ProfileRefusals.requireRisk` by the package that owns it.
- **Before a deployment.** `Preflight` runs the same sweep on an env file.

What an operator sees is in [docs/operator/deployment-profile.md](../operator/deployment-profile.md).

**The ratchet.** From 0.6.0 (plan item ST-6) a setting is read only through `platform.settings`, and CI holds that:
`tools/direct-read-scan.py` fails on `System.getenv`, `System.getProperty`, `getInitParameter` and their kin -
called, statically imported, or handed on as a method reference such as `System::getenv` - in main code outside
`libs/platform` and platform-pf's `settings` package, unless `tools/direct-read-allow.txt` admits it by file and line
pattern with a finding or a reason. The settings scan checks that each name read is catalogued; this one checks that
it is read through the catalogue. A servlet reads its init-params with `InitParams.sources(config)`, and a class
that needs a seam for its tests takes a `Sources` or the `Function<String, String>` platform's own API takes, and
says so in the allow-list.

## Legacy spellings

The readers ST-5 converts parsed leniently, and strict parsing would refuse values a deployment has set for years.
The development profile keeps an escape until 1.0 (Phase 3 plan, decision 11), when it goes with the deprecated
aliases: a value only the old reader took resolves to what that reader made of it, with one WARN per setting naming
the strict spelling, and `Resolved.legacySpelling()` records it for the start-up banner. The production profile
refuses it as it refuses any value that does not parse.

For a switch the legacy spellings are `yes`, `no`, `1`, `0`, `on` and `off`, in any case, trimmed
(`Parsers.LEGACY_BOOLEAN`), and every one reads as **`false`**: no reader before 0.6.0 took `yes`, `1` or `on` as
true, so reading them as true in development would silently turn on what had been off. `true` and `false` in any case
with blanks around them were strict already. A number has no legacy spelling: blanks around it were always trimmed,
and `Long.parseLong` takes a leading `+` (its javadoc, JDK 17 and 21: "the first character may be an ASCII minus sign
'-' ... to indicate a negative value or an ASCII plus sign '+' ... to indicate a positive value").

The old rules, reader by reader, from a search on 2026-09-30 for `Boolean.parseBoolean`, `equalsIgnoreCase("true")`
and `trim()` in main code outside platform:

| Reader | Old rule for a switch | Old rule for a number |
|---|---|---|
| oidf-jose `OutboundUrlPolicy` (`OIDF_FETCH_ALLOW_HTTP`, `OIDF_FETCH_ALLOW_PRIVATE_NETWORKS`, `OIDF_FETCH_MAX_BODY_BYTES`) | `Boolean.parseBoolean`, untrimmed: `true` in any case, anything else false | trimmed; not a number, zero or negative is the default |
| openid-federation `FederationConfiguration`, `AttestationMetadataConfig` | blank is the default; else `Boolean.parseBoolean`, trimmed | `Integer.parseInt`, trimmed; anything else refused |
| pf-integration `FederationRuntimeConfig` | `OIDF_FEDERATION_IGNORE_SSL_ERRORS`: `Boolean.parseBoolean`; `OIDF_FETCH_ALLOW_HTTP`: `"true".equalsIgnoreCase`, trimmed; the rest strict, through `platform.settings.Parsers` | strict |
| pf-integration `ClientAttestationAuthFilter` (`OIDF_ATTESTATION_REQUIRE_HOSTED_AGENT`) | `Boolean.parseBoolean`, untrimmed | - |
| pf-integration `ClientAttestationUtils` (a client's extended properties) | `Boolean.parseBoolean`, untrimmed | `Long.parseLong`, untrimmed; anything else ignored with a WARN |
| pf-integration `RegisteredClientsServlet` (`OIDF_REGISTERED_CLIENTS_ENABLED`) | `Boolean.parseBoolean` | - |
| pf-integration `RegistrationConfiguration` | - | `Integer.parseInt` or `Long.parseLong`, trimmed; anything else refused |
| pf-integration `OpenIdFederationServlet` | `true` or `false`, any case, trimmed; anything else refused | - |
| ssf `SsfConfiguration` | blank is the default; else `Boolean.parseBoolean`, trimmed | `Integer.parseInt` or `Long.parseLong`, trimmed; anything else refused |
| ssf `LogoutEventFilter` (`OIDF_SSF_LOGOUT_ALLOW_SUB_PARAM`) | `Boolean.parseBoolean`, untrimmed | - |
| attestation-issuer `AttesterConfigurationServlet`, `AttestationIssuanceServlet` (`challengeRequired`) | `Boolean.parseBoolean`, untrimmed | - |
| attestation-issuer `ClientAttestationServiceMetadataServlet` | blank is the default; else `Boolean.parseBoolean`, trimmed | - |
| attestation-issuer `EvidencePolicy` | `true` or `false`, any case; anything else refused | `Long.parseLong`, untrimmed |
| client-attestation `ChallengeEndpointServlet` | - | `Integer.valueOf` or `Long.valueOf`, trimmed; anything else ignored with a WARN |
| client-attestation `ClientAttestationChallengeServlet` | - | `Integer.parseInt`, trimmed; anything else refused |
| device-enrolment `Main` | blank is the default; else `Boolean.parseBoolean`, trimmed | - |
| ciba-sim `SimulatorGate` (`OIDF_CIBA_SIM_ENABLED`) | `"true".equalsIgnoreCase`, trimmed | - |
| platform-pf `PfAuditSink` (`OIDF_EVENTS_AUDIT`) | blank or `true` is true, `false` is false, anything else true with a WARN | - |

Two old behaviours the escape does not keep: a `true` with blanks around it, which an untrimmed reader read as false,
is true in both profiles; and a number that is not one, which `OutboundUrlPolicy` and `ChallengeEndpointServlet`
replaced with the default, is refused in both. `OIDF_EVENTS_AUDIT`'s own rule - anything but `false` keeps auditing -
is safer than the escape's, so its reader keeps it when it is converted.
