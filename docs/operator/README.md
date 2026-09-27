# Operator documentation

What someone who runs a PingFederate built from this repository needs: how to move between releases, and,
from Phase 7 of the production programme, installation, the reference stacks, the deployment profile,
clustering, the database and Redis, observability, a hardening checklist and the runbooks (plan items D-5 and
D-7).

What is here now:

- [deployment-limits.md](deployment-limits.md) - what a release does not support yet, and what goes wrong if
  you deploy it that way: from 0.4.0, one PingFederate node only until 0.7.0, and the device path until 0.9.0.
- [health.md](health.md) - the health endpoints, `/agentic-identity/health/{live,ready}`, the detail and
  `/agentic-identity/info`: what ready means and who may read the detail.
- [startup-audit.md](startup-audit.md) - the banner each war logs as it starts: version, profile, accepted risks,
  insecure TLS and each component's state, line by line, and what its listener does at shutdown.
- [upgrading/](upgrading/) - one guide per move between releases. [0.1.5-to-0.3.0.md](upgrading/0.1.5-to-0.3.0.md)
  is the move from the last PingFederate 13.0 release to the first 13.1.3 one.

The release notes themselves live in [docs/releases](../releases/README.md); each release's "Before you deploy"
list is the short form of its upgrade guide. Until the operator set exists, the module READMEs and
[docs/federation/operations.md](../federation/operations.md) are where the operational detail is.
