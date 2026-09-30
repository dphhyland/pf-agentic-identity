# A production container restarts

## Changelog

- `pf-entrypoint.sh` keeps the age-encrypted archive and decrypts it on every start of the container, restarts
  included. Until now the first start removed a ciphertext baked into the image's drop-in directory (one mounted
  through `PF_ARCHIVE_FILE` was always kept), and the next start of the same container - `docker restart`, a
  restart policy, a node reboot - found only the plaintext it had written, which production refuses:
  the container stopped with `FATAL: a plaintext archive (...) is refused when OIDF_DEPLOYMENT_PROFILE is
  production` (F-0313).
- `test-entrypoint.sh` starts a case twice on the same filesystem, in both profiles.

## Before you deploy

1. **Keep the age identity available at every start.** The entrypoint now decrypts the archive on each start of
   the container, not only the first, so `PF_ARCHIVE_AGE_KEY_FILE`'s file (or `PF_ARCHIVE_AGE_KEY`) must be there
   whenever the container starts, restarts included. In production nothing changes in practice: before this
   release a restart failed when the ciphertext was baked into the image's drop-in directory, and an archive
   mounted through `PF_ARCHIVE_FILE` was always kept, so that container already decrypted it again and needed
   the identity at every start. A development container booted from a ciphertext baked into the image used to
   restart from the plaintext its first start had left, without the identity and with the plaintext warning;
   it now needs the identity as the first start did. To tell, a start without it stops with `FATAL: ... is
   age-encrypted but neither PF_ARCHIVE_AGE_KEY_FILE nor PF_ARCHIVE_AGE_KEY is set`. Mount the identity as a secret
   for the container's life (a Kubernetes Secret volume, a Docker or Compose secret) rather than for its first
   start only. There is no development escape, because the identity is what makes the archive readable at all;
   a rig that wants no identity boots from a plaintext `data.zip` under `OIDF_DEPLOYMENT_PROFILE=development`.

## Notes

The fix keeps the ciphertext and decrypts it again on every start. The plaintext a start wrote is then never what
a later start boots from: while the ciphertext is there it is chosen and the plaintext overwritten, and a plaintext
archive is chosen only when there is no ciphertext, which production refuses whoever wrote it. The finding named
two other designs. Removing the decrypted archive once the base image's bootstrap had copied it was rejected. The
entrypoint execs the bootstrap, but the image could still do it: the base image's `run_hook` runs a `<hook>.pre` and
`<hook>.post` script around each hook, so a `07-apply-server-profile.sh.post` could remove the plaintext after the
copy. It is rejected all the same because a restart with `/opt/out` on a tmpfs, which the image README recommends,
is a first start to the bootstrap and must import the archive again, so the ciphertext has to survive the first
start whichever way the plaintext is removed. Marking the file the
script wrote was rejected because anyone who can put a `data.zip` in the drop-in directory can put the marker
beside it. The age identity handling, `umask 077`, the integrity check and the removal of both identity variables
are unchanged.

What the base image does with the archive, read from the 13.1.3 image's hooks and seen on the rig on 2026-10-01:
every start copies `/opt/in` to `/opt/staging`; only a first start (no `/opt/out/instance/bin/run.sh`) or
`SERVER_PROFILE_UPDATE=true` copies that into `/opt/out`, where the drop-in deployer imports `data.zip` and renames
it `data.zip.<date>`. It deploys `data.zip` only, so the `data.zip.age` now copied beside it is ignored. The
plaintext copies outlive the start that needed them, as they did before; the image README's "Where the plaintext
lives" says why that adds nothing a reader of the writable layer lacks.

Verified 2026-10-01 on the conformance rig (slot 4, PingFederate 13.1.3), with the rig's image rebuilt from an
encrypted archive and `OIDF_DEPLOYMENT_PROFILE=production`: with the entrypoint as main had it at e377dbae,
`docker restart` stopped with the FATAL above; with this one the restart answered 200 on `/pf/heartbeat.ping` and
`/agentic-identity/health/live` and was healthy by the image's healthcheck, and so did a restart with `/opt/out` on
a tmpfs, which imported the archive again. `test-entrypoint.sh --image` passes 87 checks in that image; ten of them
fail against the old entrypoint. No conformance plan was re-run: the change is to the boot shim alone.
