# The production profile is enforced

## Changelog

- The production profile is enforced from the settings catalogues (plan items PR-5 and PR-2's mechanism). Before
  any filter or servlet starts, the lifecycle listener checks every classed environment variable and system
  property: a forbidden switch set, a risky switch whose risk `OIDF_ACCEPTED_RISKS` does not accept, a required
  setting left unset, a governed value that does not parse, an `OIDF_*` name under a catalogue's family that no
  catalogue declares, and a catalogue that cannot be loaded are each a violation. Under production each refuses the
  components it names: their parts are `REFUSED` before their start runs, their surfaces answer 503, readiness
  answers 503, and PingFederate's own endpoints keep serving (the FAPI exception is under "Before you deploy").
  Server.log lists every violation once, the start-up banner lists them, and PingFederate's audit log gets one
  `platform.profile.refused` event per refusal. Under development nothing is refused and the list is a warning.
- `jdk.internal.httpclient.disableHostnameVerification` is catalogued (F-0195) and forbidden in production with any
  value, refusing every component (F-0035). `OIDF_REDIS_URL` and `REDIS_URL` are refused at start-up when they are
  `redis://` URLs; `REDIS_URL` only when it is the one read, with `OIDF_REDIS_URL` and `oidf.redis.url` unset. The
  catalogue format's `governed` schemes form gains `unless_set` to say so.
- A value read from an init-param, a plugin's field or a client's extended property is refused when its reader reads
  it through the catalogue, once the 0.6.0 package that converts that reader lands.
- `ProfileRefusals.refuse` and `requireRisk` let a package refuse a component for a condition that is not a setting,
  such as a store in memory without the `in-memory-state` risk.
- `Preflight` runs the same check on an env file before a deployment:
  `java -cp '<jars>/*' com.pingidentity.ps.oidf.platform.settings.Preflight --env-file FILE [--profile production]`,
  exiting 1 when something would be refused.
- The catalogue format (still `format: 1`, every addition optional) gains `governed` - the values a class acts on,
  as a list or as URL schemes - and `components`, per catalogue and per entry; system-property names may carry
  upper-case letters, and a removed name may be a plugin field. The configuration reference shows the governed
  values in the Profile column and names the components each page's violations refuse.
- The development profile reads the legacy spellings of a switch (`yes`, `no`, `1`, `0`, `on`, `off`) as `false`,
  as most readers before 0.6.0 did, with a warning, until 1.0; production refuses them. `OIDF_EVENTS_AUDIT`'s reader
  keeps its own rule: anything but `false` keeps auditing on.
- New events: `platform.profile.refused` (audited) and `platform.component.changed` (counted), in platform's new
  `platform` event catalogue.

## Before you deploy

1. **Run the preflight against your environment before you upgrade.** From 0.6.0 an unset `OIDF_DEPLOYMENT_PROFILE`
   is production, and production refuses components for what this release checks. Run
   `java -cp '<the 0.6.0 jars>/*' com.pingidentity.ps.oidf.platform.settings.Preflight --env-file <your env file>`
   (put the JVM's `-D` options in a `JAVA_OPTS` line) until a later 0.6.0 package ships it as `oidf-preflight.jar`.
   Exit 1 means a component would be refused: each line marked `REFUSED:` names the violation, its fix and the
   components it refuses; fix each, or accept its risk. It judges as the server does, from the component switches
   in the file: a component switched off is never refused, and a required setting left unset refuses only a
   component switched on (those lines say `not refused`). A running
   PingFederate shows the same list at the top of server.log and in the start-up audit. Development: under
   `OIDF_DEPLOYMENT_PROFILE=development` nothing is refused; the list is a warning.

2. **A forbidden switch now refuses its component in production.** Each of these, set to the value shown, refuses
   the components named in [docs/operator/deployment-profile.md](../../operator/deployment-profile.md):
   `OIDF_FETCH_ALLOW_HTTP=true`, `OIDF_FETCH_ALLOW_PRIVATE_NETWORKS=true`, `OIDF_FEDERATION_IGNORE_SSL_ERRORS=true`,
   `OIDF_SSF_INTROSPECTION_INSECURE_TLS=true`, `OIDF_SSF_RECEIVER_INSECURE_TLS=true`, `OIDF_SSF_JDBC_URL` (any value),
   `OIDF_SSF_LOGOUT_ALLOW_SUB_PARAM=true`, `OIDF_AUTHORITY_JDBC_URL` (any value), `OIDF_OPERATOR_INSECURE_TLS=true`,
   `OIDF_ATTESTER_CIMD_URL` (any value; before 0.6.0 the attester only left that source out), `oidf.mock.attesters`
   (any value), `OIDF_REDIS_URL` or `REDIS_URL` as a `redis://` URL (use `rediss://`; `REDIS_URL` counts only while
   `OIDF_REDIS_URL` is unset), `OIDF_CIBA_SIM_ENABLED=true`,
   and the JVM flag (see "Remove `jdk.internal.httpclient.disableHostnameVerification` from the JVM"). Why: each turns off a check production depends on. How to tell: the component is
   `REFUSED` in `/agentic-identity/health` and the start-up audit, and server.log names the switch. What to change:
   unset the switch, or set it to its default. Development: a rig sets `OIDF_DEPLOYMENT_PROFILE=development`.

3. **Accept the risks you run with.** A risky switch is allowed in production only when `OIDF_ACCEPTED_RISKS` names
   its risk: `OIDF_REQUIRE_METADATA_POLICY=false` needs `no-metadata-policy`,
   `OIDF_ATTESTATION_REQUIRE_ATTESTER_BINDING=false` needs `attester-binding-off`,
   `OIDF_AUTO_REGISTRATION_FAIL_CLOSED=false` needs `registration-fail-open`, `OIDF_PDP_FAIL_OPEN=true` needs
   `pdp-fail-open`, `OIDF_AUTO_REGISTRATION_REQUIRE_PKCE=false` needs `pkce-off`,
   `OIDF_FEDERATION_RESOLVE_DISCOVERY=any` needs `resolve-any`, `OIDF_EVENTS_AUDIT=false` needs `audit-off`, and
   `OIDF_REGISTRATION_EXPIRY_ENFORCEMENT=disable` or `log` needs `expiry-log-mode` with a date, as
   `expiry-log-mode@2026-12-31` (UTC; it lapses after that day). Why: each is legitimate but weakens a check, and
   production wants that said. How to tell: the violation names the risk id. What to change: add the id to
   `OIDF_ACCEPTED_RISKS` (comma-separated), or change the switch back. Development: nothing needs accepting.

4. **Unknown `OIDF_` names now refuse their component.** An environment variable under a catalogue's family
   (`OIDF_FEDERATION_`, `OIDF_SSF_`, `OIDF_REDIS_`, `OIDF_ACCEPTED_` and the others on each page of
   docs/configuration) that no catalogue declares refuses that family's components; a typo is the usual cause, and
   `OIDF_ACCEPTED_RISK` for `OIDF_ACCEPTED_RISKS` refuses every component. Why: a misspelt setting was silently
   ignored before. How to tell: the preflight or server.log names it as "no settings catalogue declares it". What to
   change: correct the name, or unset it. An `OIDF_*` name under no family is only a warning. Development: a
   warning.

5. **Remove `jdk.internal.httpclient.disableHostnameVerification` from the JVM.** With any value, even `false`, it
   refuses every component in production: it turns off the host name check of every Java HTTP client in the JVM,
   PingFederate's included (the JDK reads it once, in `jdk.internal.net.http.common.Utils`: empty or `true` turns the
   check off). idp-agentic-demo's image sets it (F-0035); remove it from `JAVA_OPTS` before running 0.6.0 in
   production. Until a later 0.6.0 package narrows it, a refused `FAPI` answers 503 to every token request
   ([F-0270](../../findings/F-0270.yaml)), so this flag, or `OIDF_EVENTS_AUDIT=false` without `audit-off`, closes
   PingFederate's token endpoint too, unless `OIDF_FAPI_ENABLED=false`. How to tell: every component is `REFUSED`
   and server.log names the flag. Development: nothing is refused, and the banner still says host names are not
   checked.

6. **Strict parsing arrives with the ST-5 packages.** As each later 0.6.0 package moves its readers onto the
   catalogue, a value only the old reader took is refused in production; development still reads the legacy
   spellings of a switch (`yes`, `no`, `1`, `0`, `on`, `off`, each as `false`; `OIDF_EVENTS_AUDIT` keeps its own
   rule, anything but `false` is true) with a warning, until 1.0.

## Notes

**Choices this package made (the plan's decisions are David's to confirm).** A `required-in-production` setting left
unset refuses its component only when the component's switch is `true`: unswitched, a component is inferred in
production only while none of its settings is set, and its start disables it. A component switched off with
`OIDF_<COMPONENT>_ENABLED=false` is never refused. A refused part stays `REFUSED` whatever its `init` reports next,
until it registers again. The legacy spellings of a switch read as `false`, not their plain meaning, because most
readers before 0.6.0 (`Boolean.parseBoolean`, `"true".equalsIgnoreCase`) read them so (`OIDF_EVENTS_AUDIT`'s reader,
which reads anything but `false` as true, keeps its rule); reading `yes` as true in
development would silently turn on what had been off. The components each catalogue refuses come from a table in
docs/development/settings-catalogue.md until each catalogue's owner writes its own: `federation-runtime` refuses
`FEDERATION`, `AUTO_REGISTRATION` and `ATTESTATION_AUTH` together until ST5F narrows it (F-0297).

**The rig, 2026-09-30** (slot 1, `pfai-p3-pr5`, PingFederate 13.1.3.0 on java 21.0.12.1, this branch, the image
booting an age-encrypted archive so that production would start): in development the sweep logged four violations as
"not refused (development)" and refused nothing. In production with `OIDF_FEDERATION_RESOLVE_DISCOVERY=any`, the
sweep logged at ERROR before the first component registered; `FEDERATION` was `REFUSED`; the Entity Configuration
and `/federation/resolve` answered 503; ready answered 503; live, heartbeat, OpenID discovery and a
`client_credentials` token request answered 200; audit.log had the `platform.profile.refused` event. With
`OIDF_ACCEPTED_RISKS=resolve-any` the Entity Configuration answered 200. With the JVM flag in `JAVA_OPTS`, every
component not switched off was `REFUSED` but `SSF` (which reports outside the component start: F-0295), and the
token request answered 503 from the FAPI floor. The rig was taken down.
