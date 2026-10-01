# The image and the conformance rig can be built from a release

## Changelog

- `build/pingfederate/stage-from-release.sh` stages `modules/` and `assembler/` from a published release's assets
  instead of from the reactor: no Maven and no git, every file checked against the release's `SHA256SUMS` before
  anything is staged, and a fetch that sends no credentials. Build's image job proves its stage equals
  `stage-modules.sh`'s for both profiles, jar for jar. `stage-lib.sh` holds the `MANIFEST` writer both scripts use.
- The conformance rig has a release mode: `PF_RELEASE=<version|dir> conformance/up.sh` stages from a release
  instead of building, and needs no JDK or Maven. `conformance/layout.sh` finds the image build and the
  PingFederate version in this repository and in the public tree.
- Two new release assets: `war-assembler-<version>.jar`, the war assembler the image build runs, and
  `demo-only-ciba-sim.jar`, the rig's CIBA simulator. `tools/ci/assemble-dist.sh` makes the release's `dist/`.
- `ciba-sim` is no longer deployed to GitHub Packages (F-0120).

## Before you deploy

1. **Never put `demo-only-ciba-sim.jar` in a production deploy directory.** It is the conformance rig's CIBA
   simulator, an approval oracle keyed by nothing but an `auth_req_id`, shipped so a rig can be built from a
   release. Outside `OIDF_DEPLOYMENT_PROFILE=development` it refuses every request. Its name does not keep it out
   of PingFederate: on 13.1.3 a jar named `demo-only-ciba-sim.jar` in `server/default/deploy` is loaded like any
   other, and its authenticator type is offered for new CIBA instances (U-0460). To tell whether a deployment has
   it, look for `demo-only-ciba-sim.jar` or `pf.plugins.ciba-sim.jar` in `server/default/deploy`, or for
   `com.pingidentity.ps.oidf.cibasim.SimOobAuthenticator` among the admin API's out-of-band authenticator plugin
   descriptors. Copy the release's assets by name, not by a `*.jar` glob.
2. **`ciba-sim` is no longer published to GitHub Packages.** Nothing in this repository or the rig resolves it from a
   repository. A consumer that resolved `com.pingidentity.ps.oidf:ciba-sim` from GitHub Packages takes the release
   asset `demo-only-ciba-sim.jar` instead; versions already published stay where they are.
3. **`war-assembler-<version>.jar` is a build tool.** It runs inside the image build, which `stage-from-release.sh`
   stages it for, and is never deployed: do not put it in `server/default/deploy` or a war.

## Notes

`stage-from-release.sh` refuses a release before 0.7.0, the first release with a war assembler among its assets,
and says so. The production profile stages exactly the jars the release's `MANIFEST` names; the conformance
profile adds the simulator under `pf.plugins.ciba-sim.jar`.

Verified on 2026-10-01:

- `stage-modules.sh`, sourcing `stage-lib.sh`, staged both profiles byte for byte as before, apart from the
  `MANIFEST`'s `built=` time.
- Two `mvn -DskipTests install` runs of 0.7.0-SNAPSHOT made byte-identical `war-assembler-0.7.0-SNAPSHOT.jar` and
  `pf.plugins.ciba-sim.jar`, so release.yml's rebuild comparison can hold both new assets to it.
- GitHub serves a release asset to an anonymous `curl -fL` (`.../releases/download/v0.5.0/MANIFEST` answered 200).
- On the conformance rig (slot 1, `pfai-split-b`, PingFederate 13.1.3), `conformance/up.sh` in reactor mode booted
  and the FAPI 2.0 Security Profile plan (private_key_jwt, DPoP, plain FAPI, OpenID Connect) passed, plan
  `wBHUoVhm4H6Ou`: 50 passed, 3 review, 2 warning, 1 skipped of 56. Then `PF_RELEASE=<dir> conformance/up.sh`, with
  a `dist/` from `tools/ci/assemble-dist.sh`, booted with every module jar in `server/default/deploy` byte for byte
  the reactor rig's and the staged `MANIFEST` equal but for its header, and the same plan passed with the same
  results, plan `0LwxnoGVIgvFn`. The two images' `pf-runtime.war` differ, because the war assembler dates each
  staged jar's entry with its file time (F-0450).
- `test-stage-from-release.sh` passed every case locally against that `dist/`.
