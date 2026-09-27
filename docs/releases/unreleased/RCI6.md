# The image, built, tested and scanned in CI

## Changelog

- `build/pingfederate/Dockerfile` has three targets: `builder` assembles `pf-runtime.war`, `capability` is the
  image with no configuration archive, and `deployment` adds the archive and `overlay/` to it. `deployment` is the
  last stage, so `docker build` with no `--target` builds the image it built before (plan item R-CI6, taking
  plan item R-I3's targets ahead of Phase 3). The bake-ins R-I3 removes - the EULA, DEBUG logging, the 9080
  listener, `ForceUnsupportedImport`, the required claims and the mock attesters - are unchanged.
- Build has an `image` job, and `.github/required-checks.txt` names it, so a release needs it green. It builds
  `capability` for both staging profiles, runs `test-entrypoint.sh --image` in each, runs the war assembler against
  PingFederate's own `pf-runtime.war` (`StockWarGoldenTest`), builds the default target from a placeholder
  archive and without one, publishes a syft SBOM of each image (SPDX JSON, the `image-sbom` artefact), and scans
  each with grype, failing on a HIGH or CRITICAL finding in the layers this repository adds and reporting the
  base image's own without failing.
- `tools/ci/install-lint-tools.sh` installs grype 0.119.0 and syft 1.52.0 by checksum; `.github/grype.yaml` names
  the accepted findings with their reasons; `tools/ci/image-scan-gate.py` decides what is ours.
- `tools/pf-version-check.py` and `tools/pf-version-sync.py` read a `FROM` that names its stage, and treat a
  `FROM` naming an earlier stage as a stage rather than an image.

## Before you deploy

None.

## Notes

A consumer building with no `--target` gets today's image. Checked 2026-09-28 on 13.1.3, for both profiles, from
one context with a placeholder archive, before and after the change: every file has the same path, type, mode,
owner, size and sha256 - the assembled war included - and the labels, environment, user and entrypoint are the
same. The differences are what the build stamps: `/etc/shadow`'s last-changed day for `klogd`, three fontconfig
caches and `/var/log/apk.log`, all written by apk on each build, and `/tmp/hsperfdata_root`, which the JVM left
when the assembler ran in the image and now leaves in the `builder` stage.

What CI now checks on every pull request (build/pingfederate/README.md, "Scanning the image"):

- the war assembler against 13.1.3's stock war, which closes the gap U-0185 records;
- the entrypoint's 42 cases inside both images;
- that `deployment` is still the default target and still refuses a context with no archive;
- a HIGH or CRITICAL vulnerability in this repository's jars, the assembled war or the Alpine packages the
  Dockerfile installs fails the build. PingFederate's own findings are listed in the job summary and never fail
  it: a PingFederate version bump fixes them.

Found on the way, recorded, not fixed here: the base image ships without apk's installed database, so the
Dockerfile's `apk add` reinstalls all 57 base packages at the day's Alpine versions (F-0220, for R-I3); and
Alpine's `age` is built with a `golang.org/x/crypto` whose SSH code carries twelve HIGH and CRITICAL advisories
that decrypting a file does not reach, accepted in `.github/grype.yaml` until Alpine rebuilds it (F-0221).

The service images plan item R-CI6 names - device-enrolment, the adapter, the SPIRE reader - do not exist until
R-I8 (Phases 5 and 6). Booting the image under a licence is R-CI7 (Phase 4). F-0006 stays open until then and
until R-CI10.
