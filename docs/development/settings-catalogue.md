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
  the values to the other (as `FederationRuntimeConfig` does for the whole of pf-integration today). Nothing
  checks the package against the code in Phase 2; the scan (ST3A) does.
- **Families.** `families` lists the `OIDF_*` prefixes the component owns, such as `OIDF_PDP_`. They are what
  `UnknownKeys.find` looks under for a set name no catalogue declares. A family may be shared by two components;
  a name is known when any loaded catalogue declares it.

## The document

Every member is required, and a member not listed here is refused.

| Member | What it holds |
|---|---|
| `format` | `1` |
| `component` | the component's name, the same as the file's |
| `module` | the module's path from the repository root: `servlets/pf-integration` |
| `package` | the one Java package that owns the file |
| `families` | the `OIDF_*` prefixes it owns, each ending in `_` (may be empty) |
| `settings` | its entries, below, in the order a reference prints them |
| `removed` | the names it no longer reads, below (may be empty) |

## An entry

Every member is required, `min` and `max` for a ranged type and `choices` for a `choice` as well, and nothing else.

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

**Kinds.** `env`, `system-property` and `init-param` are resolved from their sources, and one of the sources
is of the kind's own source with the entry's name: an `env` entry named `OIDF_PDP_MODE` is read from the
environment as `OIDF_PDP_MODE`, whatever else it is read from and in whatever order. `plugin-field` (a field of
a plugin's configuration screen) and `extended-property` (an OAuth client's extended property) are supplied by
PingFederate: they have no sources, aliases or file, and a reader parses the value it is given
(`Settings.parse`).

**Types.** `bool` is `true` or `false` in any case and always has a default. The ranged types are whole numbers
within `min` and `max` (an `int`'s range fits an `int`); `seconds` and `millis` are read as a `Duration`. A
`choice` has at least one choice, none repeated in any case. `https-url` is an absolute https URL with a host,
`url` http or https. `json-object` is one JSON object read by `platform.json`: duplicate member names, content
after it, nesting past 32 and number literals past 128 characters are refused. `words` are space- or
comma-separated, and a list of nothing is refused. A `secret` is text that no message, log line or `toString`
shows; it bears on security, has no default, and is the only type that may set `file`.

**When it's wrong.** `effect` is one of the style guide's four
([style-guide.md](style-guide.md#settings)): `doesnt-start` (the component fails at deploy and the log names
the setting), `first-request`, `per-request`, or `not-checked`, whose `detail` says what a wrong value does
instead. `detail` is the sentence the reference prints: "Anything but true or false".

**Profile.** How the setting stands with the deployment profile (PR-1, PR-2): allowed in `any` profile,
`forbidden-in-production`, allowed in production only under `accepted-risk:<id>` (lower-case words joined by
hyphens), or `required-in-production`. The catalogue records it; the profile package and the start-up audit
(PR-5, Phase 3) act on it.

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

A removed name is `{"name": ..., "from": "env", "replacement": "OIDF_NEW" or null, "release": "0.4.0"}`. Its
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

## What is not enforced yet

In Phase 2 the catalogue is a format, a loader and a resolver. Nothing refuses a deployment for it: no reader
has been converted to `Settings` (ST-5, Phase 3), and `UnknownKeys.find` - the `OIDF_*` names under a family
that no catalogue declares - is called by nothing at run time, because refusing an unknown key before every
module is catalogued would stop working deployments. The start-up audit (PR-5) and ST-5 wire both in.
