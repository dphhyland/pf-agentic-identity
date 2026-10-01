# pf-agentic-identity

Agentic and workload identity for PingFederate: OpenID Federation 1.0, OAuth 2.0 Attestation-Based Client
Authentication, Rich Authorization Requests with an external policy decision point, Shared Signals (SSF, CAEP
and RISC), a device enrolment service and the Grant Management API, delivered as PingFederate modules, a war
and plugin jars. This repository carries the released artefacts, the documentation an operator needs to
configure, deploy and upgrade them, and the specifications they implement.

Generated from a private source repository at each release; raise issues here, pull requests are not accepted.
The source code is not published here.

## Download and verify a release

Each release's assets are on its release page: the module jars, `oidf.war`, `gm-api.war`, the plugin jars,
`MANIFEST`, `SHA256SUMS` and `PROVENANCE.txt`. With the GitHub CLI:

```sh
gh release download v{{VERSION}} -R ID-Partners/pf-agentic-identity -D vendor/
```

or anonymously, one asset at a time:

```sh
curl -fsSLO https://github.com/ID-Partners/pf-agentic-identity/releases/download/v{{VERSION}}/SHA256SUMS
curl -fsSLO https://github.com/ID-Partners/pf-agentic-identity/releases/download/v{{VERSION}}/<asset>
```

Then check every file against `SHA256SUMS` before you use it, and record what you took:

```sh
( cd vendor && sha256sum -c SHA256SUMS )          # Linux
( cd vendor && shasum -a 256 -c SHA256SUMS )      # macOS
grep -E '^(commit|tag):' vendor/PROVENANCE.txt >> VENDORED.txt
```

`PROVENANCE.txt` names the source commit and the tag the release was built from. Releases from v0.3.0 to v0.6.0
were mirrored here from the source repository with their original assets, so their checksums are unchanged.

This release runs on PingFederate {{PF_VERSION}}. Every release here is a `jakarta.servlet` build for
PingFederate 13.1.x; the v0.1.x releases, built for 13.0.x, are not published here.

<!-- if:demo -->
## The image and the demo

<!-- if:staging -->
`image/` builds a PingFederate image with this release's modules merged into PingFederate's own war. Stage the
release's assets into it, verified against `SHA256SUMS`, then build:

```sh
image/stage-from-release.sh {{VERSION}}
docker build --target capability image/
```

[image/README.md](image/README.md) describes the targets, the build arguments and the runtime environment.

`demo/` is a conformance rig: `demo/up.sh` stages the same release, boots a configured PingFederate in Docker and
prints where it answers. It needs Docker and Terraform, and your own Ping DevOps credentials: the image bakes no
licence, and PingFederate fetches an evaluation licence with them at boot.
[demo/README.md](demo/README.md) says where they go and what the rig configures.
<!-- end:staging -->
<!-- unless:staging -->
`image/` (the PingFederate image build) and `demo/` (a conformance rig, `demo/up.sh`) are this release's files
as they were tagged. They build from the private source repository, not from the release assets, so they do
not run from this repository alone; v0.7.0 is the first release whose image and demo do.
<!-- end:staging -->
<!-- end:demo -->
## Documentation

- [docs/operator/](docs/operator/README.md) - deploying, health, preflight and upgrading.
- [docs/configuration/](docs/configuration/README.md) - every setting, by component.
- [docs/federation/](docs/federation/README.md) - OpenID Federation: how it works, configuration, limits.
- [docs/releases/](docs/releases/README.md) - each release's notes, and [CHANGELOG.md](CHANGELOG.md).

Report a vulnerability as [SECURITY.md](SECURITY.md) says, never in an issue.

## Licence

Apache License 2.0: [LICENSE](LICENSE) and [NOTICE](NOTICE). PingFederate and the Ping Identity images are
Ping Identity's, under their own licence.
