# The production profile

From 0.6.0 the production profile is enforced (plan item PR-5). A switch that production forbids, a risky switch
whose risk the deployment has not accepted, an `OIDF_*` name no settings catalogue declares, and the JVM-wide
hostname flag each refuse the components they belong to: those components answer 503 on their own surfaces and
readiness is 503, while PingFederate's own SSO and OAuth endpoints keep serving - with one exception for FAPI's own
clients, below. Nothing is refused under the development profile: the same list is logged as a warning.

`OIDF_DEPLOYMENT_PROFILE` chooses the profile. `development` - trimmed, in any case - is development; unset, blank,
`production` and any other value are production, so a typo lands on the safe side. A rig or a demo sets
`development`; nothing else should.

## What production refuses

Every rule below comes from a settings catalogue: each setting's profile class and the values it governs are in its
page under [docs/configuration](../configuration/README.md) (the Profile column), and the components a violation
refuses are named at the top of the page.

**Forbidden switches.** Set to the value shown, each refuses the components after it.

| Setting | Refused when | Refuses |
|---|---|---|
| `OIDF_FETCH_ALLOW_HTTP`, `OIDF_FETCH_ALLOW_PRIVATE_NETWORKS` | `true` | `FEDERATION`, `AUTO_REGISTRATION`, `ATTESTATION_AUTH`, `ATTESTATION_ISSUER`, `HOSTING` |
| `OIDF_FEDERATION_IGNORE_SSL_ERRORS` | `true` | `FEDERATION`, `AUTO_REGISTRATION`, `ATTESTATION_AUTH` |
| `OIDF_SSF_INTROSPECTION_INSECURE_TLS`, `OIDF_SSF_RECEIVER_INSECURE_TLS` | `true` | `SSF`, `SSF_RECEIVER` |
| `OIDF_SSF_JDBC_URL` | set | `SSF`, `SSF_RECEIVER` |
| `OIDF_SSF_LOGOUT_ALLOW_SUB_PARAM` | `true` | `SSF` |
| `OIDF_SSF_RECEIVER_POLL_TOKEN` (the static development token; production uses the receiver's client, `OIDF_SSF_RECEIVER_TOKEN_ENDPOINT`) | set | `SSF_RECEIVER` |
| `OIDF_SSF_RECEIVER_TOKEN_ENDPOINT`, `OIDF_SSF_RECEIVER_TRANSMITTER_CONFIGURATION_URL`, `OIDF_SSF_RECEIVER_PUSH_ENDPOINT_URL` | an `http://` URL (the receiver's tokens would cross the network in clear) | `SSF_RECEIVER` |
| `OIDF_AUTHORITY_JDBC_URL` | set | `HOSTING`, `OPERATOR_API` |
| `OIDF_OPERATOR_INSECURE_TLS` | `true` | `OPERATOR_API` |
| `OIDF_ATTESTER_CIMD_URL` | set | `ATTESTATION_ISSUER` |
| `oidf.mock.attesters` (system property) | set | `ATTESTATION_AUTH` |
| `OIDF_REDIS_URL`, `REDIS_URL` | a `redis://` URL (plaintext; `rediss://` is allowed); `REDIS_URL` only while `OIDF_REDIS_URL` and `oidf.redis.url` are unset, since the client reads it only then | `ATTESTATION_AUTH`, `ATTESTATION_ISSUER`, `OPERATOR_API` |
| `jdk.internal.httpclient.disableHostnameVerification` (system property) | set, with any value | every component |
| `OIDF_CIBA_SIM_ENABLED` | `true` | `CIBA_SIMULATOR` (the simulator already refuses to run outside development) |

**Risks a deployment may accept.** Each switch below is allowed in production only when `OIDF_ACCEPTED_RISKS` names
its risk, as a comma-separated list of ids, each alone or with the last day it holds (`id@YYYY-MM-DD`, UTC).

| Setting | Needs the risk when | Risk id | Refuses without it |
|---|---|---|---|
| `OIDF_REQUIRE_METADATA_POLICY` | `false` | `no-metadata-policy` | `FEDERATION`, `AUTO_REGISTRATION`, `ATTESTATION_AUTH` |
| `OIDF_ATTESTATION_REQUIRE_ATTESTER_BINDING` | `false` | `attester-binding-off` | the same |
| `OIDF_AUTO_REGISTRATION_FAIL_CLOSED` | `false` | `registration-fail-open` | the same |
| `OIDF_REGISTRATION_EXPIRY_ENFORCEMENT` | `disable` or `log` | `expiry-log-mode`, dated only: `expiry-log-mode@2026-12-31` | the same |
| `OIDF_PDP_FAIL_OPEN` | `true` | `pdp-fail-open` | the same |
| `OIDF_AUTO_REGISTRATION_REQUIRE_PKCE` | `false` | `pkce-off` | the same |
| `OIDF_FEDERATION_RESOLVE_DISCOVERY` | `any` | `resolve-any` | `FEDERATION`, `HOSTING` |
| `OIDF_EVENTS_AUDIT` | `false` | `audit-off` | every component |

An entry that is empty, unknown, expired, repeated, or undated where a date is needed is not accepted; the start-up
audit lists it, and the switch that needed it refuses its components.

**Required settings.** `OIDF_OPERATOR_AUDIENCE` and `OIDF_OPERATOR_BASE_URL` are required for the operator API. Left
unset they refuse `OPERATOR_API` only when `OIDF_OPERATOR_API_ENABLED=true`: a component not switched on is, in
production, one none of whose settings is set, and it disables itself.

**Unknown names.** An `OIDF_*` environment variable under a catalogue's family (`OIDF_FEDERATION_`, `OIDF_SSF_`,
`OIDF_REDIS_` and the rest, listed on each configuration page) that no catalogue declares refuses that family's
components: `OIDF_FEDERATION_TRUST_ANCHOR` for `OIDF_FEDERATION_TRUST_ANCHORS` takes federation down, not SSF. A
misspelling is the usual cause. An `OIDF_*` name under no family is only a warning.

**A governed value that cannot be read**, such as `OIDF_FETCH_ALLOW_HTTP=yes`, is refused as if it asked for the
governed value: production cannot tell what it meant.

**Refusals in code.** Some conditions are not settings: a store that keeps its state in memory needs the
`in-memory-state` risk in production. The packages that own those stores add them from 0.6.0 on; each is listed in
the start-up audit under `code refusals`.

**At read.** An init-param, a plugin's field and a client's extended property are not in the environment, so the
start-up sweep cannot see them. Each is refused when its reader reads it through the settings catalogue - in 0.6.0
the federation servlet's init-params (ST5F), the RAR plugin's fields (PLG) and the instance registry's JDBC URL field
(ST5S) - and its component is then `REFUSED` in the same way.

## What a refusal looks like

Before any filter or servlet starts, server.log has one entry listing every violation, at ERROR when something is
refused. From the conformance rig in production profile with `OIDF_FEDERATION_RESOLVE_DISCOVERY=any` and no accepted
risk (PingFederate 13.1.3.0 on java 21.0.12.1, this change, 2026-09-30; long lines cut):

```
ERROR [com.pingidentity.ps.oidf.platform.pf.lifecycle.LifecycleListener] Deployment profile production for / (ROOT) - 1 violation(s) refuse the components they name, which answer 503; PingFederate's own endpoints keep serving:
  REFUSED: OIDF_FEDERATION_RESOLVE_DISCOVERY=any, which the production profile allows only with the risk 'resolve-any' accepted (the federation resolve endpoint resolves any entity for anyone, not only this entity's own). Accept the risk by adding resolve-any to OIDF_ACCEPTED_RISKS, or set OIDF_FEDERATION_RESOLVE_DISCOVERY to known, or unset it [FEDERATION, HOSTING]
  not refused (not switched on): OIDF_OPERATOR_AUDIENCE is unset, and the production profile requires it (...) [OPERATOR_API]
  not refused (not switched on): OIDF_OPERATOR_BASE_URL is unset, and the production profile requires it (...) [OPERATOR_API]
```

The start-up audit ([startup-audit.md](startup-audit.md)) lists the same violations and names the component
`FEDERATION REFUSED: OpenIdRegistrationServlet: refused by the production profile: ...`; PingFederate's audit log has
one `platform.profile.refused` event per violation that refuses something. On that boot the Entity Configuration and
`/federation/resolve` answered 503 `{"error":"temporarily_unavailable","error_description":"FEDERATION is not
available"}`, ready answered 503, and live, `/pf/heartbeat.ping`, `/.well-known/openid-configuration` and a
`client_credentials` request at `/as/token.oauth2` answered 200. With `OIDF_ACCEPTED_RISKS=resolve-any` the next
boot logged the risk as accepted, refused nothing, and the Entity Configuration answered 200.

**The exception: FAPI.** A `FAPI` component that is not serving answers 503 at the endpoints its filter covers to the
clients `OIDF_FAPI2_CLIENTS` names (to every client when it is `*`), and passes every other client's request to
PingFederate: package S9B has the filter read its client list apart from the rest of its start
([F-0270](../findings/F-0270.yaml), closed). A violation that refuses every component - the JVM-wide hostname flag,
`OIDF_EVENTS_AUDIT=false` without `audit-off` - therefore closes PingFederate's token endpoint to those clients. Before
S9B it closed it to every client: on the rig with `-Djdk.internal.httpclient.disableHostnameVerification=false`
in `JAVA_OPTS` (2026-09-30), `ATTESTATION_ISSUER`, `AUTO_REGISTRATION`, `FAPI` and `FEDERATION` were `REFUSED`, the
three components switched off stayed `DISABLED`, and the same `client_credentials` request answered 503 `FAPI is not
available`. (`SSF` showed `READY` on that boot; see below.) A deployment that does not use FAPI sets `OIDF_FAPI_ENABLED=false`: a
component switched off is never refused.

**Switch off what you do not run.** A violation refuses the components it names that are switched on or inferred;
one switched off with `OIDF_<COMPONENT>_ENABLED=false` stays disabled and never counts against readiness.

**The SSF servlets** start as `SSF`'s part since package ST5C, with a gate on every endpoint: a refused `SSF` or
`SSF_RECEIVER` no longer configures the transmitter, and its endpoints answer 503 ([F-0295](../findings/F-0295.yaml),
closed). The boot above was made before that change and showed `SSF READY`. On the v0.6.0 release's rig (2026-10-01, the code at
`600fa6b5`, production, the flag in `JAVA_OPTS`), `SSF` and `SSF_RECEIVER` were `REFUSED` with every other component
switched on or inferred, `ATTESTATION_AUTH`, switched off, stayed `DISABLED`, and the token endpoint answered 200 to a
client `OIDF_FAPI2_CLIENTS` does not name and 503 `FAPI is not available` to one it names.

## Before you deploy: Preflight

The same sweep runs on an env file before it reaches a server. Use `oidf-preflight.jar`, a release asset with every
catalogue of the release in it (package ST7; [preflight.md](preflight.md) says how to run it on a Docker env file, a
Kubernetes ConfigMap and `run.properties`):

```
java -jar oidf-preflight.jar --env-file prod.env [--profile production]
```

The class the jar runs can also be run from the release's jars on a class path:

```
java -cp '<the release's jars>/*' com.pingidentity.ps.oidf.platform.settings.Preflight --env-file prod.env [--profile production]
```

It reads `NAME=value` lines (blank lines and `#` comments skipped, `export ` allowed, one pair of quotes around a
value removed) and the `-D` words of a `JAVA_OPTS` line, judges them against every catalogue on the class path -
point `-cp` at the jars of the release you are about to deploy - and prints what the server would log, each line
labelled as server.log labels it. It judges each violation as the server does, from the `OIDF_<COMPONENT>_ENABLED`
switches in the file: a component switched off is never refused, and a required setting left unset refuses only a
component switched on. A switch that does not parse is listed too, since it refuses its component in either
profile. It exits 0 when nothing would be refused, 1 when a component would be, and 2 when it cannot read its
arguments or the file. The
profile is the file's `OIDF_DEPLOYMENT_PROFILE` unless `--profile` names one. On a class path it judges only by the
catalogues of the jars it is given, and a module left out has its rules left out without a word, which is why the
jar is the one to run.

## The development profile

Under `OIDF_DEPLOYMENT_PROFILE=development` nothing is refused. The sweep's list is logged once at WARN, each line
`not refused (development):`, and the start-up audit shows it. A value only the reader before 0.6.0 took - for a
switch `yes`, `no`, `1`, `0`, `on` or `off` - is read as `false`, which is what most of those readers made of it,
with a WARN naming the strict spelling; production refuses it. `OIDF_EVENTS_AUDIT` is the exception: its reader takes
anything but `false` as true, so auditing stays on, and it keeps that rule. That escape goes at 1.0
([settings-catalogue.md](../development/settings-catalogue.md#legacy-spellings)).
