# Security policy

This repository builds the servlets, plugins and libraries that give PingFederate agentic and workload
identity: OpenID Federation, Client Attestation, Rich Authorization Requests, Shared Signals, the device
enrolment service and the Grant Management API. They run inside an authorisation server, so a defect in them
is a defect in someone's token endpoint. Please report one privately.

## Supported versions

| Version | Supported |
|---|---|
| The latest 0.x release (0.3.0 at the time of writing, on PingFederate 13.1.3) | Yes - fixes land in the next release |
| Earlier 0.x releases on the 13.1 line (0.2.0 was never tagged) | No - move to the latest release |
| 1.x, once 1.0.0 is released | Yes - the latest 1.x release; the 0.x line then gets nothing |
| 0.1.x and the frozen `pf-13.0` branch (v0.1.5, PingFederate 13.0.x) | No - frozen on 2026-09-26, no backports |

A release is a `v*` tag of this repository, built and published by `.github/workflows/release.yml` from the
commit it verified. Consumers pin a release by tag and checksum (`SHA256SUMS`, `PROVENANCE.txt` in the release
assets); a copy of the jars taken from a working tree is not a version anyone can support.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting for this repository: the "Report a vulnerability" button on the
repository's Advisories page (under Security), which opens a draft advisory only the maintainer can see.

As of 2026-09-27 the feature is not yet enabled (the API answers `enabled: false`), and there is no other
private channel: the maintainer's GitHub profile carries no contact address. Only the repository's owner can
turn it on - GitHub's docs, read 2026-09-27: "Owners and administrators of public repositories can allow
security researchers to report vulnerabilities securely in the repository by enabling private vulnerability
reporting" (Settings, then Advanced Security under "Security and quality", then Enable beside "Private
vulnerability reporting") - and the gap is [F-0068](docs/findings/F-0068.yaml) in the findings register,
targeted at 0.6.0. Until the button is there, keep the details out of public view: no issue, pull request or
discussion that names the module, the endpoint or the trigger, and no proof of concept. If you cannot wait,
open an issue that says only that you have a security report and need a private channel, and the maintainer
will answer with one. This paragraph goes when the feature is on.

Say what you found, where (module, class, endpoint), how to reproduce it against the rig
(`conformance/up.sh` boots a configured PingFederate 13.1.3 from a clone), and what you think it lets an
attacker do. A proof of concept is welcome; a working exploit against someone else's deployment is not.

What happens next: the report is acknowledged, the defect is confirmed on the rig, a fix is made and released
as the next release with a note in `docs/releases/<version>.md` under "Before you deploy" if a consumer has to
act, and the finding is recorded in the [findings register](docs/findings/README.md) once the fix is public -
never before. Credit is given in the release notes unless you would rather not be named.

## What is in scope

- Every module in this repository's reactor: `libs/`, `servlets/`, `plugins/`, `services/`, the BOM, and the
  image build under `build/pingfederate/`.
- The PingFederate configuration the conformance rig authors (`conformance/terraform`), where it would carry
  into a deployment.
- The GitHub Actions workflows and the tools under `tools/`, where a defect would let untrusted input into a
  build or a release.

Out of scope, with where to go instead:

- PingFederate itself, PingAuthorize, PingOne and the Ping DevOps images: Ping Identity's own disclosure
  process.
- The demo and deployment repositories that consume this one (idp-agentic-demo, pf-oidf-modules,
  pf-agentic-identity-domain-authority): report to them, unless the defect is in an artefact they took from
  here.
- The showcase page under `showcase/`: static HTML with no server side.
- Findings that need the PingFederate administrator's credentials or the master key to exploit: an
  administrator is trusted by design.

Design limits that are documented rather than defects: the [federation limits](docs/federation/limits.md),
the deliberate divergences in the [claim dictionary](docs/claim-dictionary.md), and the open findings in
the register, which say what is known to be missing and which release closes it.

## Config archives and key material

A PingFederate configuration archive is a plain zip that contains `pf.jwk` - the master key that decrypts
every secret in it - beside the system keys, both keystores, the admin password hash and the master-key-
reversible client secrets. So no archive and no key material may ever be tracked in this repository, in any
directory, under any name: the root `.gitignore` ignores `data*.zip`, `*.jwk`, `*.jks`, `*.p12`, `*.pfx` and
`*.lic` anywhere in the tree, and `build.yml`'s `secrets-guard` job fails the build if one is tracked anyway,
or if an age identity or a private key appears in any file's content. An encrypted archive (`data.zip.age`,
encrypted to a public recipient) is the only form that may be committed or baked into an image; the identity
that decrypts it belongs in a password manager and a sealed runtime variable.

If you find an archive, a `pf.jwk`, a private key or an age identity in this repository's history, that is a
vulnerability: report it as above, and say which commit. The fix is rotation, not deletion - a key that was
public once stays public.
