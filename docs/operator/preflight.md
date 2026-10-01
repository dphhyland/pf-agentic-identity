# Preflight: check an environment before you upgrade

`oidf-preflight.jar` reads the environment a deployment will start with and says what the production profile would
refuse, before the upgrade rather than in server.log after it. From 0.6.0 an unset `OIDF_DEPLOYMENT_PROFILE` is
production, and production refuses components ([deployment-profile.md](deployment-profile.md)): run this first,
against every environment, on the release you are moving to.

It is the start-up sweep PingFederate runs (plan item PR-5's `Preflight`) packed with platform's classes and every
module's settings catalogue, so it judges a file's governed values, required settings, unknown names and component
switches as that release's sweep would, and it needs nothing but Java 17 or later. It does not make the refusals a
server makes only when a component reads a setting - a removed name, a value that does not parse, a name set beside
its `_FILE` variant ("What it cannot check" below). `java -jar oidf-preflight.jar --list` prints the catalogues it holds.

## Get it

Each release from 0.6.0 carries `oidf-preflight.jar` among its assets, listed in `SHA256SUMS` beside the module jars:

```
gh release download v0.6.0 --repo ID-Partners/pf-agentic-identity --pattern oidf-preflight.jar --pattern SHA256SUMS
grep ' oidf-preflight.jar$' SHA256SUMS | sha256sum -c -
```

Releases are published at `ID-Partners/pf-agentic-identity`; releases up to 0.6.0 are mirrored there with their
original assets, so their `SHA256SUMS` is unchanged.

Use the jar of the release you are upgrading to: its catalogues are that release's rules. Its manifest names the
version and the commit (`unzip -p oidf-preflight.jar META-INF/MANIFEST.MF`), and so does the first line of `--list`.
It runs on the JDK that builds this repository (17), on 21, and on the java in PingFederate's image (21.0.12.1 in
13.1.3; checked in CI on every build).

## Run it

```
java -jar oidf-preflight.jar --env-file FILE [--profile production|development] [--accepted-risks IDS]
java -jar oidf-preflight.jar --list
```

- `--env-file FILE` - the environment, as `NAME=value` lines: blank lines and `#` comments are skipped, `export `
  before a name is allowed, one pair of matching quotes around a value is removed, and a name set twice keeps its last
  value. A `JAVA_OPTS` line's `-Dname=value` words are read as the JVM's system properties.
- `--profile` - judge under this profile instead of the file's `OIDF_DEPLOYMENT_PROFILE`. Leave it out to judge as
  the server will; `--profile production` shows what production would make of a development file.
- `--accepted-risks IDS` - judge with `IDS` (the comma-separated form `OIDF_ACCEPTED_RISKS` takes) in place of the
  file's `OIDF_ACCEPTED_RISKS`, to see what accepting a risk changes before you edit the file. An empty value accepts
  nothing.
- `--list` - every catalogue in the jar, its module, and how many settings and removed names it declares.

It judges each violation as the server does, from the `OIDF_<COMPONENT>_ENABLED` switches in the file: a component
switched off is never refused, and a required setting left unset refuses only a component switched on
([components.md](components.md) says how an unset switch is inferred).

### A Docker env file

```
sed -E "s/^([A-Za-z_][A-Za-z0-9_]*)=(.*)$/\1='\2'/" prod.env > prod.preflight.env
java -jar oidf-preflight.jar --env-file prod.preflight.env
```

`docker run --env-file` passes a value exactly as written, quotes and all: with Docker 29.4.1 (checked 2026-10-01) the
line `A="quoted"` reaches the container as `"quoted"`, and `C=plain # note` as `plain # note`. The preflight
removes one pair of quotes, so a file with `OIDF_FETCH_ALLOW_HTTP="false"` would pass it and then be refused by the
server, which cannot read `"false"` as a boolean ([F-0426](../findings/F-0426.yaml)). The `sed` above wraps every value
in single quotes, which the preflight removes, so it sees what Docker passes. A line that is a bare `NAME`, which
Docker fills from the calling shell, is not `NAME=value` and stops the preflight with exit 2: write its value in.

To check a container that is already running, with the image's own `ENV` lines included:

```
docker inspect --format '{{range .Config.Env}}{{println .}}{{end}}' pf \
  | sed -E "s/^([A-Za-z_][A-Za-z0-9_]*)=(.*)$/\1='\2'/" > running.env
```

### A Kubernetes ConfigMap

```
kubectl get configmap pf-env -o go-template="{{range \$k, \$v := .data}}{{\$k}}='{{\$v}}'{{\"\\n\"}}{{end}}" > pf-env.env
java -jar oidf-preflight.jar --env-file pf-env.env
```

Each key becomes one `NAME='value'` line (checked with kubectl 1.31.3, 2026-10-01). A pod usually takes more than one
source: add the lines of every other ConfigMap in its `envFrom`, and each `env` entry of the container. For a Secret,
do not write its values to disk: list its keys with a stand-in value (`{{$k}}=set`), and keep the scheme of a URL the
profile judges - `OIDF_REDIS_URL='rediss://stand-in'`, not `set` - since `redis://` is refused and `rediss://` is not.
A value that spans lines cannot be one `NAME=value` line: leave it out, or write a one-line stand-in.

### PingFederate's run.properties and JAVA_OPTS

PingFederate puts every line of `run.properties` into the JVM's system properties at start (13.1.3's
`org.pingidentity.RunPF.main` loads the file named by `-Drun.properties`, substituting `${VAR}` from the environment,
and calls `System.getProperties().putAll` with it: `javap -c` of `bin/pf-startup.jar` in the 13.1.3 image, read
2026-10-01). So a system property the catalogues govern - `oidf.mock.attesters`,
`jdk.internal.httpclient.disableHostnameVerification` - counts from `run.properties` as it does from `JAVA_OPTS`. Give
the preflight both as one `JAVA_OPTS` line, with the JVM options your deployment passes in `$JAVA_OPTS`:

```
{
  cat prod.env
  printf 'JAVA_OPTS="%s %s"\n' "$JAVA_OPTS" \
    "$(grep -E '^[[:space:]]*(oidf|jdk)\.' run.properties \
       | sed -E 's/^[[:space:]]*([^=:[:space:]]+)[[:space:]]*[=:]?[[:space:]]*/-D\1=/' | tr '\n' ' ')"
} > prod.preflight.env
```

The `sed` takes the three separators `java.util.Properties` reads - `key=value`, `key: value` and `key value` - and
writes each as `-Dkey=value`. It does not follow a line that ends in `\` onto the next, or undo a `\` escape: join and
unescape those lines first. The words are split at whitespace, so a property whose value holds a space is read only up
to it; and a `${VAR}` in `run.properties` is read as written, so resolve it first. A second `JAVA_OPTS` line replaces
the first, so leave any in `prod.env` out. (Checked 2026-10-01 on a sample `run.properties` with macOS's `sed`: an
`oidf.mock.attesters: a,b` line and an empty `jdk.internal.httpclient.disableHostnameVerification=` line each
refused.)

## Exit status

| Status | Meaning |
|---|---|
| `0` | Nothing the start-up sweep judges would be refused. A setting refused only when it is read is not judged: a removed name, a value that does not parse where the profile governs nothing, a name set beside its `_FILE` variant or a superseded name ("What it cannot check"). The output may still list violations that refuse nothing here (a component switched off, a required setting for a component not switched on, anything under development) and warnings. With `--list`, every catalogue loaded. |
| `1` | At least one component would be refused: each `REFUSED:` line names one. Fix each, accept its risk, or switch its component off. With `--list`, a catalogue in the jar could not be loaded, which means the jar is damaged: download it again. |
| `2` | The arguments or the file could not be read: the usage line, or `Preflight: FILE cannot be read (...)`, or `Preflight: FILE: line N is not NAME=value`, on standard error. Nothing was judged. |

A deployment pipeline can stop on anything but 0.

## What it prints

One line per switch that does not parse, then one per violation, labelled as server.log labels it, then one per
warning, then the verdict. Each violation line is the reason, the fix, and the components it refuses in brackets. From
this repository's `tools/preflight/src/test/resources/fixtures/violations.env` (one line of each kind) on JDK 17.0.11,
2026-10-01, the catalogue descriptions cut to `(...)`:

```
REFUSED: OIDF_SSF_ENABLED must be one of true, false, not maybe [SSF]
not refused (switched off): OIDF_ATTESTER_CIMD_URL is set, which the production profile forbids (...). Unset OIDF_ATTESTER_CIMD_URL (a rig or a demo sets OIDF_DEPLOYMENT_PROFILE=development instead) [ATTESTATION_ISSUER]
REFUSED: jdk.internal.httpclient.disableHostnameVerification is set, which the production profile forbids (...). Remove -Djdk.internal.httpclient.disableHostnameVerification from the JVM's options (JAVA_OPTS) (a rig or a demo sets OIDF_DEPLOYMENT_PROFILE=development instead) [FEDERATION, AUTO_REGISTRATION, ATTESTATION_AUTH, ATTESTATION_ISSUER, HOSTING, SSF, SSF_RECEIVER, OPERATOR_API, FAPI]
REFUSED: OIDF_FEDERATION_RESOLVE_DISCOVERY=any, which the production profile allows only with the risk 'resolve-any' accepted (the federation resolve endpoint resolves any entity for anyone, not only this entity's own). Accept the risk by adding resolve-any to OIDF_ACCEPTED_RISKS, or set OIDF_FEDERATION_RESOLVE_DISCOVERY to known, or unset it [FEDERATION, HOSTING]
REFUSED: OIDF_FEDERATION_IGNORE_SSL_ERRORS cannot be read (OIDF_FEDERATION_IGNORE_SSL_ERRORS must be true or false, not yes), so the production profile cannot tell whether it asks for true, which it governs. Write OIDF_FEDERATION_IGNORE_SSL_ERRORS as its type reads it: true or false (a rig or a demo sets OIDF_DEPLOYMENT_PROFILE=development instead) [FEDERATION, AUTO_REGISTRATION, ATTESTATION_AUTH, ATTESTATION_ISSUER, HOSTING]
REFUSED: OIDF_OPERATOR_AUDIENCE is unset, and the production profile requires it (...). Set OIDF_OPERATOR_AUDIENCE (a rig or a demo sets OIDF_DEPLOYMENT_PROFILE=development instead) [OPERATOR_API]
REFUSED: OIDF_OPERATOR_BASE_URL is unset, and the production profile requires it (...). Set OIDF_OPERATOR_BASE_URL (a rig or a demo sets OIDF_DEPLOYMENT_PROFILE=development instead) [OPERATOR_API]
REFUSED: OIDF_FETCH_ALLOW_HTTP=true, which the production profile forbids (...). Set OIDF_FETCH_ALLOW_HTTP to false, or unset it (a rig or a demo sets OIDF_DEPLOYMENT_PROFILE=development instead) [FEDERATION, AUTO_REGISTRATION, ATTESTATION_AUTH, ATTESTATION_ISSUER, HOSTING]
REFUSED: OIDF_FEDERATION_TRUST_ANCHOR is set, under the OIDF_FEDERATION_ family, and no settings catalogue declares it. Correct the name - a misspelling is the usual cause - or unset it; the configuration reference (docs/configuration) lists every name (a rig or a demo sets OIDF_DEPLOYMENT_PROFILE=development instead) [FEDERATION, HOSTING, AUTO_REGISTRATION, ATTESTATION_AUTH]
warning: OIDF_NOT_A_FAMILY is set and no settings catalogue declares it; it is under no catalogue's family, so nothing refuses it - check the spelling
warning: OIDF_ACCEPTED_RISKS names 'no-such-risk', which is not a risk this release knows; the ids are no-metadata-policy, attester-binding-off, registration-fail-open, expiry-log-mode, pdp-fail-open, pkce-off, resolve-any, audit-off, in-memory-state - that risk is not accepted
8 line(s) under the production profile refuse the components named; each answers 503 until it is fixed
```

Line by line, one of each kind:

| Line | Kind | What to do |
|---|---|---|
| `OIDF_SSF_ENABLED must be one of true, false` | A component switch that does not parse. It refuses its component under either profile | Write `true` or `false` |
| `not refused (switched off): OIDF_ATTESTER_CIMD_URL` | A violation whose only component is switched off: it refuses nothing, and would if the component were switched on | Nothing now; unset it before you switch the component on |
| `jdk.internal.httpclient.disableHostnameVerification is set` | The JVM-wide hostname flag, from `JAVA_OPTS`: it refuses every component | Remove it from the JVM's options and `run.properties` |
| `OIDF_FEDERATION_RESOLVE_DISCOVERY=any ... risk 'resolve-any'` | A risky switch whose risk is not accepted | Accept the risk in `OIDF_ACCEPTED_RISKS`, or change the value |
| `OIDF_FEDERATION_IGNORE_SSL_ERRORS cannot be read` | A governed value that does not parse: production reads it as the value it governs | Write it as its type reads it |
| `OIDF_OPERATOR_AUDIENCE is unset, and the production profile requires it` | A required setting, its component switched on | Set it, or switch the component off |
| `OIDF_FETCH_ALLOW_HTTP=true ... forbids` | A forbidden switch | Unset it, or set its default |
| `OIDF_FEDERATION_TRUST_ANCHOR is set, under the OIDF_FEDERATION_ family` | An unknown name under a catalogue's family: it refuses that family's components | Correct the spelling (here `OIDF_FEDERATION_TRUST_ANCHORS`) |
| `warning: OIDF_NOT_A_FAMILY` | An `OIDF_*` name under no family | Check the spelling; nothing is refused |
| `warning: OIDF_ACCEPTED_RISKS names 'no-such-risk'` | An accepted-risks entry that is not accepted (unknown, expired, undated where a date is needed, repeated) | Correct the entry; the risk it meant is not accepted until then |

Three other labels appear: `not refused (not switched on):` for a required setting left unset whose component is not
switched on (the clean fixture prints two, `OIDF_OPERATOR_AUDIENCE` and `OIDF_OPERATOR_BASE_URL`),
`not refused (development):` for every violation when the profile is development, where only a switch that does not
parse refuses its component, and `not refused (names no component):` for a violation of a setting that belongs to no
component. The last line is either the count of refusing lines (exit 1) or
`clean under the ... profile: nothing would be refused`, with the number of violations listed that refuse nothing
there (exit 0).

## What it cannot check

It checks settings: names and values in the file against the catalogues. It cannot check what only a running node
knows, and a clean result says nothing about these:

- **Anything not in the file.** An image's own `ENV` lines, a server profile's files, a Kubernetes Secret or
  ConfigMap you did not export, the `-D` options `run.sh` adds itself. What the file leaves out is judged unset.
- **Whether a service answers.** A database named by a JDBC URL (reachable, the schema migrated, the user's
  rights), Redis (reachable, its password, its certificate), a PingAuthorize decision point, OpenBao or another key
  store, a federation trust anchor or a subordinate, PingOne or any other token endpoint.
- **PingFederate's own configuration.** Its data stores (the JDBC data store the registry and SSF stores use), OAuth
  clients and their extended properties, access token managers and mappings, the plugin instances' fields, and the
  licence. A servlet's `init-param`, a plugin's field and a client's extended property are refused when their reader
  reads them ([deployment-profile.md](deployment-profile.md), "At read"), not by the start-up sweep or by this.
- **Certificates and keys.** Expiry, the trust chain, whether a signing key the settings name exists.
- **Refusals made when a setting is read.** A server refuses these on a component's first read of its settings
  (`Settings.resolve`), not in the start-up sweep, so the jar does not see them ([F-0427](../findings/F-0427.yaml)):
  - a removed name still set, under either profile: `OIDF_BRIDGE_PRIVATE_JWK`, removed in 0.1.2 for
    `OIDF_BRIDGE_SIGNING_KEYS`;
  - a value that does not parse as its setting's type where the profile governs nothing:
    `OIDF_AUTO_REGISTRATION_FRONT_CHANNEL=yes`, `OIDF_REGISTRATION_MAX_TTL_SECONDS=abc`. This is the strict parsing
    0.6.0 brings in; development softens it only for a boolean spelled `yes`, `no`, `1`, `0`, `on` or `off`, read as
    false as the reader before 0.6.0 read it;
  - a secret set both directly and by its `_FILE` variant (`OIDF_REDIS_SENTINEL_PASSWORD` beside
    `OIDF_REDIS_SENTINEL_PASSWORD_FILE`), or a setting and its superseded name set to different values.

  A production file with `OIDF_AUTO_REGISTRATION_ENABLED=true` and the first three examples exits 0 here (checked
  2026-10-01). Check such names and values by hand against the configuration reference
  ([docs/configuration](../configuration/README.md)) and the release's "Before you deploy" items.
- **Refusals made in code.** A store that keeps its state in memory needs the `in-memory-state` risk in production;
  which store a process builds is decided when it starts, and the start-up audit lists those refusals under
  `code refusals`.
- **Which process the file is for.** The jar holds every catalogue of the release, so it knows names that one process
  does not load: a device-enrolment setting such as `OIDF_AGENT_CLIENT_ID` in PingFederate's file draws no warning
  here, where PingFederate's sweep would warn, and `OIDF_CIBA_SIM_ENABLED=true` is refused here though a production
  image stages no simulator and PingFederate only warns about it ([F-0425](../findings/F-0425.yaml)).

The server's start-up sweep and audit ([startup-audit.md](startup-audit.md)) remain the record of what a node
actually refused; the preflight is how to see it before the node starts.

## The same check from the release's jars

Before this jar, the check ran from the release's jars on a class path, which still works:

```
java -cp '<the release's jars>/*' com.pingidentity.ps.oidf.platform.settings.Preflight --env-file prod.env [--profile production]
```

It sees only the catalogues of the jars on that class path, so a module left out has its rules left out without a
word: with platform's jar alone, `OIDF_FETCH_ALLOW_HTTP=true` is only a warning ("under no catalogue's family"). The
jar holds every catalogue by construction, and the build fails when a module's catalogue is not in it.
