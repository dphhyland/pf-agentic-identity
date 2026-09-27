# The deployment profile, accepted risks and one trust-all

## Changelog

- `libs/platform` gains `platform.profile` and `platform.tls` (plan item PR-1). `DeploymentProfile` is the one
  reading of `OIDF_DEPLOYMENT_PROFILE` - `development`, trimmed, in any case, and production for everything else,
  unset included - and every module reads it there: client-attestation, attestation-issuer, rar-model, the RAR
  plugin and ciba-sim. `AcceptedRisks` reads the new `OIDF_ACCEPTED_RISKS`, and `ProfileGuard` asks whether a
  switch is forbidden, required or an accepted risk under the production profile. Nothing asks it yet: PR-2 and
  PR-5 (Phase 3) wire the switches and refuse components.
- `InsecureTls` is now the only place a trust-all TLS context is built. The federation fetches
  (`OIDF_FEDERATION_IGNORE_SSL_ERRORS`), the RAR plugin's "Skip TLS verification (dev only)", the SSF
  receiver's and introspection's insecure-TLS switches, device-enrolment's `PF_AUTHORITY_INSECURE_TLS` and the
  harness ask it; each use logs one WARN naming its setting. What each switch trusts is unchanged: any
  certificate chain, and the certificate must still name the host dialled - except in the harness, which turns
  the JDK's host-name check off for every run ([F-0162](../../findings/F-0162.yaml)).
- `tools/trust-scan.py`, a new step in the lint job, fails on a trust-all trust manager, an always-true
  hostname verifier, a null endpoint identification algorithm or the JDK's hostname flag anywhere else in main
  code (F-0042, CodeQL alerts 4 to 9).
- The RAR plugin and ciba-sim shade and relocate platform, as the RAR plugin already does Jackson and rar-model;
  ciba-sim's jar is now a shaded jar under the same name. rar-model depends on platform.

## Before you deploy

1. **`OIDF_ACCEPTED_RISKS` is new, and its format is checked.** It lists the risks a production deployment
   accepts, as ids from a fixed registry (`no-metadata-policy`, `attester-binding-off`, `registration-fail-open`,
   `expiry-log-mode`, `pdp-fail-open`, `pkce-off`, `resolve-any`, `audit-off`, `in-memory-state`), each alone or
   as `id@YYYY-MM-DD`, the last day it holds; `expiry-log-mode` must carry a date. An unknown id, a date that is
   not one, an expired date and an id named twice are refused, each with a message naming the entry. In this
   release nothing reads the list to refuse anything: PR-2 and PR-5 (0.6.0) make the production profile refuse a
   risky switch whose risk is not accepted. Leave it unset for now, or write it in the checked format; the
   start-up audit (F-2) will report every refused entry.
2. **Deploy `platform` beside every module, as 0.5.0's platform item says: from this package it is called.**
   oidf-jose, client-attestation, attestation-issuer, ssf, rar-model, device-enrolment and the harness now load
   platform classes (`DeploymentProfile`, `InsecureTls`) - the profile on the first request that asks it,
   `InsecureTls` whenever an HTTP client is built. A PingFederate or a service without
   `platform-<version>.jar` beside those jars fails with `NoClassDefFoundError:
   com/pingidentity/ps/oidf/platform/...` there. A consumer that builds from this repository's Dockerfile and
   `stage-modules.sh` has it already; one that copies jars itself (pf-oidf-modules, idp-agentic-demo) must add
   it, and rar-model now needs it too. The two plugins carry their own relocated copy and need nothing.

## Notes

What changed. Every reader of `OIDF_DEPLOYMENT_PROFILE` in Java asks `DeploymentProfile`, with its behaviour and
its tests unchanged; the class names that held the old reads (`DeploymentProfile` in client-attestation,
`EvidencePolicy.isProduction`, `SimulatorGate.isProduction`, `GovernanceEngineConfig.profileOf`) now delegate.
Two readings still differ from the rule and are pinned by tests: rar-model's fallback takes exactly
`development`, lower case ([F-0160](../../findings/F-0160.yaml)), and the image's entrypoint does not trim, so
a padded value is production there ([F-0161](../../findings/F-0161.yaml)); `DeploymentProfileShellTest` runs one
table through the Java rule and the entrypoint's `is_development`. The seven trust-all implementations in main
code (the six CodeQL reported and the harness's) are gone; the gm-api example keeps its `--insecure`, exempt
from the scan by name ([F-0163](../../findings/F-0163.yaml)). device-enrolment's own warning line for
`PF_AUTHORITY_INSECURE_TLS` is replaced by `InsecureTls`'s WARN, which names the variable. The harness still
turns the JDK's hostname check off for every run, now through `InsecureTls` ([F-0162](../../findings/F-0162.yaml)).

How it was verified (2026-09-28). The reactor on JDK 20 and JDK 17 with a Postgres server, green, with the
coverage gates on the new decision methods. Each trust-all site against a self-signed certificate made for the
run: accepted for `localhost` with the switch on, refused for `wrong.example` with the switch on (the host name
is still checked), refused on the chain with the switch off. The same cases in the pinned PingFederate image's
JDK (OpenJDK 21.0.12.1): refused for the wrong name without `jdk.internal.httpclient.disableHostnameVerification`,
accepted with it. `tools/trust-scan.py` over main's copies of the sites before this change reported ten hits in
seven files, and over this tree none. `tools/pf-linkcheck.py` against PingFederate 13.1.3 resolved every
reference in both plugin jars; each plugin's `ShadedJarCheck` finds platform only under its relocated package,
and the RAR plugin still shades rar-model. CodeQL 2.27.1 on the pull request's merge commit ran `java/insecure-trustmanager`
and reported nothing, `InsecureTls` included, so no alert needs dismissing; alerts 4 to 9 have no instance there
and close on main's first analysis after the merge.

Residual risk. Nothing refuses a forbidden switch or an unaccepted risk yet (PLAN.md decision 7). A trust-all
switch still trusts any chain until PR-2 forbids it in production; the alternative, a trusted CA file in place of
every ignore-TLS switch, would remove trust-all altogether and is breaking, so it is PR-2's to decide. A plugin's
use of `InsecureTls` is recorded in its own relocated copy, which the start-up audit does not load
([F-0164](../../findings/F-0164.yaml)).
