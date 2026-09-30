# The CIBA simulator

An authentication device with no device. PingFederate implements CIBA itself - the backchannel endpoint,
poll and ping, signed requests, the hint rules - but the only out-of-band authenticator it ships wants a
PingOne tenant and a phone. This plugin is the stand-in the conformance rig uses for the OpenID Foundation
suite's FAPI-CIBA plan: an `OOBAuthPlugin` that answers `IN_PROGRESS` until an operator has recorded
`allow` or `deny` for the request, then `SUCCESS` or `FAILURE`, which PingFederate turns into a token or
`access_denied`. Nothing is approved by default, and nothing is approved by time.

It is one jar, `pf.plugins.ciba-sim.jar`, with two halves that PingFederate loads in two classloaders:

- `SimOobAuthenticator`, the plugin, found by `PF-INF/oob-auth-plugins` when the jar sits loose in
  `server/default/deploy/`;
- `CibaSimDecisionServlet` at `POST /ciba-sim/decision?auth_req_id=...&action=allow|deny` - the shape the
  suite's `automated_ciba_approval_url` takes - found by annotation when the same jar is merged into
  `pf-runtime.war`.

The two share nothing in memory, so the handoff is a directory: one file per transaction, named by the
SHA-256 of the `auth_req_id` (which is also the plugin's transaction id, and keeps the `auth_req_id` - a
bearer credential at the token endpoint - out of directory listings), holding the decision and when it was
recorded. A decision older than fifteen minutes reads as absent.

## Where it runs, and where it never does

The endpoint is an approval oracle keyed by nothing but an `auth_req_id`: on a server where it is on, anyone
who learns one can approve that request, and anyone who can write to the directory can do the same without
the endpoint. So it is **conformance-only**, twice over:

- **It is not in a production image.** `build/pingfederate/stage-modules.sh` stages this jar only under
  `--profile conformance`; the default, `production`, leaves it out, and the assembler refuses a stage whose
  profile is not the one the image is built for ([the image build](../../build/pingfederate/README.md)).
- **Both halves ask `SimulatorGate` before every request**, and refuse unless all three settings below hold.
  The servlet answers `404 {"error":"not_found"}` - what the same URL answers on an image without the jar;
  not a 503, because nothing about a refusal changes with time. The plugin throws
  `OOBAuthGeneralException` from `initiate`, `check` and `finished` alike, which fails the backchannel
  request: a recorded `allow` is never read, and never forgotten either.

Every refusal is logged at WARN with its reason, in the form the table's last column quotes.

## Settings

| Setting | Default | What it does | When it's wrong |
|---|---|---|---|
| `OIDF_CIBA_SIM_ENABLED` | unset (off) | `true`, in any case, switches the simulator on. Nothing else does: not `yes`, not `1` | Unset or anything but `true`: `OIDF_CIBA_SIM_ENABLED is not true`. The endpoint is 404 and every backchannel request through this authenticator fails |
| `OIDF_DEPLOYMENT_PROFILE` | unset, which is `production` | `development` says this PingFederate is a rig or a demo, and is the only value the simulator runs under. Read through libs/platform's `DeploymentProfile` (plan item PR-1), shaded into this jar under `com.pingidentity.ps.oidf.cibasim.shaded.platform`; the image's entrypoint applies the same rule in shell | Unset: `OIDF_DEPLOYMENT_PROFILE is unset, which is production`. `production`, or any other value - a typo lands on the safe side: `... counts as production`. Either way `the simulator never runs there`, whatever `OIDF_CIBA_SIM_ENABLED` says |
| `OIDF_CIBA_SIM_DIR` | unset | The decision directory. Required once enabled: an absolute path to a directory that exists, is not a symbolic link, is owned by the user PingFederate runs as, has mode `0700` (`rwx------`, nothing for group or other) and is on a POSIX filesystem. Never created by the plugin - a store that made its own directory would pass these checks without anyone having decided to. The conformance image makes `/opt/ciba-sim` to this shape, and the rig's `vars.env` names it | Unset or blank: `OIDF_CIBA_SIM_DIR is not set`. Relative: `is not an absolute path`. Missing: `does not exist`. A file: `is not a directory`. A link: `is a symbolic link`. Another user's: `is owned by <user>, not by <user>, the user this process runs as`. Wider than `0700`, or narrower: `has mode <mode>; it must be rwx------ (0700)`. A filesystem with no owner or mode to check: `is not on a POSIX filesystem`. Unreadable: `cannot be read: <error>`. If the JVM cannot find out who it runs as (it looks at the owner of a file it creates in `java.io.tmpdir`): `the user this process runs as could not be determined` |

The checks run on every request, from both classloaders, so a directory that is loosened while PingFederate
runs is refused from that request on; the log line says which check failed.

## What the rig does

`conformance/vars.env` sets all three: `OIDF_DEPLOYMENT_PROFILE=development`, `OIDF_CIBA_SIM_ENABLED=true`
and `OIDF_CIBA_SIM_DIR=/opt/ciba-sim`. `conformance/author.sh` stages the jar into the authoring
PingFederate so `terraform/ciba.tf` can create an instance of the authenticator, `up.sh` stages the module
set with `--profile conformance`, and `docker-compose.yml` builds the image with
`STAGING_PROFILE=conformance`. The FAPI-CIBA plan's results are in [conformance/README.md](../../conformance/README.md).

## Tests

`mvn -o -B verify` in this module runs the four test classes and a jacoco gate that holds every decision
method at 100% line and branch coverage: `SimulatorGate.refusal`, `enabled`, `isProduction` and
`directoryRefusal` - each refusal in the table has a test - together with `DecisionStore.record`, `lookup`
and `txIdFor`, `SimOobAuthenticator.initiate`, `check` and `finished`, and `CibaSimDecisionServlet.handle`.
The non-POSIX branch is exercised through a zip filesystem opened without POSIX attributes; the ownership
branch through a principal that is not the one the tests run as.
