# The image stops configuring your deployment

## Changelog

- The PingFederate image no longer bakes in configuration: it does not accept Ping Identity's licence agreement,
  open the plain HTTP listener on 9080, log this repository's packages at DEBUG, set `ForceUnsupportedImport`,
  require the `workload` attestation claim or trust mock attesters from the build context. Each is set at run time
  by the deployment (plan item R-I3; [build/pingfederate/README.md](../../../build/pingfederate/README.md#what-the-image-leaves-to-you)).
- `pf-entrypoint.sh` refuses to start without `PING_IDENTITY_ACCEPT_EULA=YES`, and refuses a plain HTTP listener
  (`PF_RUN_PF_HTTP_PORT`) unless `OIDF_DEPLOYMENT_PROFILE=development`. It trims the profile as the Java modules do
  (F-0161).
- The image has OCI labels (`org.opencontainers.image.*`, with the version, commit and build time), `EXPOSE 9031
  9999` and a `HEALTHCHECK` on PingFederate's heartbeat and `/agentic-identity/health/live` - live, not ready.
- The build records its commit in platform-pf's manifest (`-Doidf.build.commit`), so `/agentic-identity/info` and
  the start-up banner report it rather than null (F-0190).
- `oidf.attestation.required.claims` can come from the environment as `OIDF_ATTESTATION_REQUIRED_CLAIMS`.
- age is installed from its checksum-pinned 1.3.2 release binary instead of apk, which reinstalled the base image's
  whole Alpine userland, and the image has no bash (F-0220).

## Before you deploy

1. **Accept the EULA at run time.** The image set `PING_IDENTITY_ACCEPT_EULA=YES` for everyone who ran it; it
   leaves the base image's `NO` now, because accepting Ping Identity's licence agreement is the operator's act.
   Set `PING_IDENTITY_ACCEPT_EULA=YES` in the deployment's environment. Without it the container exits at once
   with `pf-entrypoint: FATAL: PING_IDENTITY_ACCEPT_EULA is '': set PING_IDENTITY_ACCEPT_EULA=YES at run time`,
   before PingFederate starts, whatever the profile: there is no development escape, and the rig in
   `conformance/` sets it in `vars.env`.
2. **Turn the plain HTTP listener on yourself if you need it.** Every image opened PingFederate's plain HTTP
   runtime listener on 9080, which serves tokens and codes in the clear. It is off now (`PF_RUN_PF_HTTP_PORT=-1`,
   PingFederate's own off) and 9080 is not in `EXPOSE`. To tell whether you use it, look for anything that
   reaches the container on 9080 - a load balancer's backend, a health probe, a compose `ports:` line. If you do,
   move it to 9031 (HTTPS) and terminate TLS in front of that. On a rig, set `PF_RUN_PF_HTTP_PORT=9080` with
   `OIDF_DEPLOYMENT_PROFILE=development`; in production the entrypoint refuses any port with
   `FATAL: PF_RUN_PF_HTTP_PORT=9080 opens PingFederate's plain HTTP listener, which is refused when
   OIDF_DEPLOYMENT_PROFILE is production`.
3. **Set `OIDF_ATTESTATION_REQUIRED_CLAIMS=workload` to keep what the image required.** The image wrote
   `oidf.attestation.required.claims=workload` into `run.properties`, so every client whose
   `attestation_required_claims` named nothing had to present a `workload` claim. The code's default has always
   been none, and the image no longer sets it: such clients are now admitted without one. If you relied on that,
   set `OIDF_ATTESTATION_REQUIRED_CLAIMS=workload` (or the system property, which wins) in every environment,
   development included. To tell, a client attestation without `workload` was refused at the token endpoint
   before and is accepted after.
4. **Supply mock attesters yourself, in development only.** A build context holding `oidf-mock-attesters.json`
   got it copied into the image and `oidf.mock.attesters` pointed at it. The Dockerfile ignores the file now.
   A development deployment that trusts attesters directly mounts the file and sets the system property
   `oidf.mock.attesters` to its path itself, through `JAVA_OPTS` or a server profile's `run.properties`. The
   settings catalogue classes the property forbidden in production; there is no production equivalent, because
   attester trust in production comes from the federation. To tell, server.log warned, when the resolver was first
   used, that it trusted mock attesters; after the upgrade it does not, and an attestation signed only by such an
   attester is refused.
5. **`ForceUnsupportedImport` is no longer set.** The overlay set it `true`; it is `false` now, PingFederate's own
   default. With it `false`, an archive whose version PingFederate's import check refuses is not imported: the
   drop-in deployer logs the reason as an error and the import fails, where before it logged a warning and
   imported anyway. Export the archive from the PingFederate version the image runs
   (13.1.3), and after the upgrade look for "Config archive import completed successfully" in `server.log`. There
   is no development escape in the image; a rig that needs it can put its own
   `org.sourceid.saml20.domain.mgmt.impl.DataDeployer.xml` in the build context's `overlay/config-store/`.
6. **Expect INFO, not DEBUG.** The image set `com.pingidentity.ps.oidf` to DEBUG in `log4j2.xml`; it now
   inherits PingFederate's root logger, INFO. Log lines this repository writes at DEBUG - the federation's trust
   chain validation, its subordinate statement cache and trust controller calls, among others - are gone from
   `server.log`. A dashboard or alert that
   matched them needs INFO lines instead, or a `log4j2.xml` of your own, from a server profile or a mount, that
   sets the logger to DEBUG, for as long as you need it.
7. **The image has a HEALTHCHECK.** It is healthy when PingFederate's own liveness check passes and
   `/pf/heartbeat.ping` and `/agentic-identity/health/live` both answer 200 on the runtime port; it does not
   check ready, because some not-ready states are not ones a restart fixes (F-0192), and orchestrators restart an
   unhealthy container. A `docker ps` now shows `(healthy)` or `(unhealthy)`. If your orchestrator acts on
   Docker health, check that 241 seconds' start period and seven failed checks 31 seconds apart suit you; route
   traffic on `/agentic-identity/health/ready` with your own readiness probe. A compose file's own `healthcheck:`
   still replaces the image's.
8. **Copy `pf-healthcheck.sh` into a build context you compose yourself.** The Dockerfile copies it beside
   `pf-entrypoint.sh`, so a context composed outside this repository without it fails to build at that `COPY`.
   `conformance/compose-context.sh` copies it; a consumer's own script (pf-oidf-modules'
   `deploy/pingfederate/compose-context.sh`, for one) must add `build/pingfederate/pf-healthcheck.sh` to what it
   copies. The build's error names the missing file; there is no escape, development or otherwise.

## Notes

Plan item R-I3, decisions 3 (Phase 2) and 19 and 12 (Phase 3). The Dockerfile's `capability` and `deployment`
targets both lost the bake-ins; `capability` gained the labels, `EXPOSE` and `HEALTHCHECK`, which `deployment`
inherits.

Verify first, 2026-09-29, in the pinned 13.1.3 image: its `run.properties.subst.default` has `pf.http.port=-1`
written out, where its neighbours read variables (`pf.https.port=${PF_ENGINE_PORT}`), and no hook script names
`pf.http.port`, so no variable of the base image's own reaches the listener. The Dockerfile has the template read
`${PF_RUN_PF_HTTP_PORT}`, which the base image's `05-expand-templates.sh` substitutes at boot. The image has
`curl` (`/usr/bin/curl`), which its own `liveness.sh` uses. What `/pf/heartbeat.ping` answers on an engine node
while it syncs from the admin node was not seen: this repository has no clustered rig (U-0295).

The healthcheck departs from the plan, which asked for heartbeat and ready (Phase 3 decision 19);
[build/pingfederate/README.md](../../../build/pingfederate/README.md#the-healthcheck) says why and how to route on
ready.

age 1.3.2's release binaries are built with golang.org/x/crypto v0.55.0, which has two HIGH advisories in its SSH
connection code, fixed in v0.56.0; the image scan accepts them with their reasons (F-0285). The advisories that
Alpine's age 1.3.1-r6 carried, and zlib's CVE-2026-85091, no longer match anything in the image and their entries
are gone from `.github/grype.yaml`. F-0221, which accepted Alpine's age, is superseded by F-0285 and was not this
package's to close.

Verified 2026-09-29: the reactor's tests on JDK 17; `test-entrypoint.sh --image` (68 checks) inside the rig's image;
the conformance rig on slot 4 (`PF_RIG_NAME=pfai-p3-ri3`) built from this branch with `vars.env` accepting the
agreement and turning the listener on - the archive imported with `ForceUnsupportedImport` false, discovery and the
heartbeat answered on 9031 and the heartbeat on the plain listener, the banner printed the commit, and the
container was healthy by the image's healthcheck while `/agentic-identity/health/ready` answered 503. No
conformance plan was re-run.

pf-oidf-modules composes its context from `build/pingfederate` and gets every item above on its next rebuild; its
`oidf-mock-attesters.json` is no longer read. idp-agentic-demo's image builds from the stock 13.0.3 image with its
own mock-attester COPY, not from this Dockerfile, so nothing here reaches it until it moves (read 2026-09-30).

F-0026, the umbrella for the image's production posture, stays open.
