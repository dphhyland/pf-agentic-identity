# The capability's PingFederate image: stock PingFederate 13.1.3 (jakarta.servlet) + this repo's module set,
# merged into pf-runtime.war, and nothing else. No RAR->PingAuthorize plugin, no consent page, no agentic
# clients: those belong to a consumer's own image, built FROM the same base with its own archive.
#
# Three targets (plan item R-CI6, taking R-I3's build targets ahead of Phase 3):
#   builder      assembles pf-runtime.war from the stock war, modules/ and filters.xml; nothing else
#   capability   the image with no configuration archive: what Build's image job builds, tests and scans
#   deployment   capability plus the configuration archive and overlay/ - the last stage, so a
#                `docker build` with no --target builds it, as it did before the targets existed
#
# Build-context artifacts required here (see README.md in this directory):
#   data.zip.age (preferred) or data.zip  <- the config archive (produced by terraform/ export); deployment only
#   overlay/config-store/org.sourceid.saml20.domain.mgmt.impl.DataDeployer.xml   deployment only
#   overlay/pf.jwk, overlay/pingfederate-system-keys.xml   only under the plaintext scheme (SECRET, git-ignored)
#   modules/                         <- stage-modules.sh output of this repo's reactor, staged for the
#                                       profile this image is built for (merged into pf-runtime.war AND
#                                       copied to server/default/deploy; see below)
#   assembler/war-assembler.jar      <- stage-modules.sh output too; with assemble-pf-runtime-war.sh and filters.xml
#
# Build arg STAGING_PROFILE selects what the image is: production (the default; the jars modules/MANIFEST names) or
# conformance (those and the CIBA simulator, an approval oracle for the suite's FAPI-CIBA plan that
# has no business in a production image, plus the directory it keeps its decisions in). The profile is
# recorded as a label, and the assembler refuses a modules/ that was staged for the other one.
#   (no jose4j: the assemble call passes "-" and relies on PF's own copy in server/default/lib)
#
# The image carries no configuration of its own (plan item R-I3): no EULA acceptance, no DEBUG logging, no plain
# HTTP listener, no ForceUnsupportedImport, no required claims and no mock attesters. Each is the deployment's to
# set at run time - README.md, "What the image leaves to you".
#
# The module is MERGED INTO pf-runtime.war (not deployed as a loose oidf.war + jar). This puts its
# @WebServlet servlets in the ROOT context — so `/.well-known/ssf-configuration`, `/ssf/*`, the challenge endpoints
# at `/federation/attestation-challenge` and `/federation/attestation/challenge`, etc. serve at root (no `/oidf` prefix) — gives a single
# classloader (one AttestationSupport singleton; no OGNL-hook caching split), and lets the SSF logout filter
# run over PF's own `/idp/init_logout.openid`. Repoint any `/oidf/*` consumers (e.g. the demo UI PF_BASE) to root.
#
# Licensing is DevOps-fetched — NO pingfederate.lic is baked. The base image's boot hook
# 17-check-license.sh pulls a fresh evaluation license when these RUNTIME env vars are set (as the
# deployment's secrets - see vars.<env>.env):
#   PING_IDENTITY_ACCEPT_EULA=YES            (the deployment's to set; pf-entrypoint.sh refuses to start without it)
#   PING_IDENTITY_DEVOPS_USER=<devops email> (SECRET — never in git)
#   PING_IDENTITY_DEVOPS_KEY=<devops key>    (SECRET — never in git)
# Trade-off: DevOps eval licenses are short-lived (~7 days) and re-fetched only at container start.

ARG STAGING_PROFILE=production
# What the OCI labels say (org.opencontainers.image.*): the release version, the commit and the build time. CI
# passes all three; a local build says unknown, unknown and nothing.
ARG OCI_VERSION=unknown
ARG OCI_REVISION=unknown
ARG OCI_CREATED=

# The tag and digest are the ones build/pf-version.env records (PF_IMAGE, PF_IMAGE_DIGEST), written out as a
# literal so Dependabot can bump them here; tools/pf-version-check.py fails when the two disagree, and
# tools/pf-version-sync.py rewrites the env file from this line after a bump. It is the one FROM that names an
# image: every later stage starts from this one or from another stage.
FROM pingidentity/pingfederate:13.1.3-alpine_3.24.1-al21-latest@sha256:0d559261d658222179b07de8b2c84a8aea3cb30c7be107970686f58ea9dd3a4a AS pingfederate
ARG STAGING_PROFILE
# Refuse a third value here, at the top, rather than let a typo build a production image by default.
RUN case "$STAGING_PROFILE" in production|conformance) ;; *) \
      echo "ERROR: STAGING_PROFILE must be production or conformance, not '$STAGING_PROFILE'" >&2; exit 1 ;; esac

# --- builder: pf-runtime.war, assembled ---
# Merge the OIDF attestation/federation/SSF modules into pf-runtime.war (root context, the webapp
# classloader — the same jars are ALSO copied to server/default/deploy below, so the engine classloader
# gets its own copy: two classloaders, deliberately, and without Redis the filter and the OGNL criterion
# therefore keep separate in-memory challenge/replay stores), and register the filters filters.xml declares
# (SsfLogoutSignal, Fapi2Profile, FapiResourceServer, OAuthErrorDescription, OidfFrontChannelAutoRegistration,
# OidfAutoRegistration, ClientAttestationAuth) in its web.xml - via the same assemble script a consumer's CI
# would use, a wrapper round the war assembler (build/war-assembler) that stage-modules.sh stages into
# assembler/, run here on the base image's own Java 21 (JAVA_HOME=/opt/java). modules/ holds the reactor's jars
# (modules/MANIFEST names every one; under the conformance profile the CIBA simulator too), staged for one
# profile, and the assembler checks them against the MANIFEST - digests, and the profile against
# STAGING_PROFILE. bash is for the wrapper, in this stage only: the image the capability stage makes has no bash.
# The base image has unzip itself. (No pf-rar-paz-plugin - agentic.)
FROM pingfederate AS builder
USER root
ARG STAGING_PROFILE
COPY assemble-pf-runtime-war.sh filters.xml assembler/war-assembler.jar /tmp/assembler/
COPY modules/ /tmp/modules/
RUN apk add --no-cache bash \
 && mkdir -p /build \
 && STOCK="$(find /opt -name pf-runtime.war 2>/dev/null | grep -v '/opt/in/' | head -1)" \
 && { [ -n "$STOCK" ] || { echo 'stock pf-runtime.war not found in base image'; exit 1; }; } \
 && WAR_ASSEMBLER_JAR=/tmp/assembler/war-assembler.jar bash /tmp/assembler/assemble-pf-runtime-war.sh "$STOCK" \
      /tmp/modules - /build/pf-runtime.war "$STAGING_PROFILE"

# --- age: the release binary, checked, in a stage of its own ---
# age decrypts the configuration archive at boot (pf-entrypoint.sh). It comes from age's own GitHub release,
# checked against the sha256 recorded here before it is unpacked, and not from apk: the base image has no apk
# database (/lib/apk/db holds no installed file), so `apk add` believed nothing was installed and reinstalled the
# whole of PingFederate's Alpine userland at the day's versions (F-0220). This way the image's system files are
# the base image's, byte for byte, apart from the two binaries and the licence copied below - Build's image job
# checks exactly that. The sums are of the archives as downloaded on 2026-09-29 (age publishes sigsum proofs, not
# a checksums file); the binaries are Go, statically linked, built with golang.org/x/crypto v0.55.0. To move
# age: change the version and both sums, and build both architectures.
FROM pingfederate AS age
USER root
ARG TARGETARCH
ARG AGE_VERSION=1.3.2
RUN case "$TARGETARCH" in \
      amd64) sum=cbe24006683f8eb669266162894b9a522a1af52f2665fbc63a4bb032ed26ac10 ;; \
      arm64) sum=6b8dc4333c53a5a57c9e5834e3a48f92605d7154014cd07269ff3327db5d37f4 ;; \
      *) echo "ERROR: no age checksum recorded for '$TARGETARCH'" >&2; exit 1 ;; \
    esac \
 && curl -fsSL --retry 3 -o /tmp/age.tar.gz \
      "https://github.com/FiloSottile/age/releases/download/v${AGE_VERSION}/age-v${AGE_VERSION}-linux-${TARGETARCH}.tar.gz" \
 && echo "$sum  /tmp/age.tar.gz" | sha256sum -c - \
 && mkdir /age && tar -xzf /tmp/age.tar.gz -C /age --strip-components=1 age/age age/age-keygen age/LICENSE \
 && /age/age --version

# --- capability: the image with no configuration archive ---
FROM pingfederate AS capability
USER root
ARG STAGING_PROFILE
ARG OCI_VERSION
ARG OCI_REVISION
ARG OCI_CREATED
LABEL io.github.dphhyland.pf-agentic-identity.staging-profile=$STAGING_PROFILE \
      org.opencontainers.image.title="pf-agentic-identity PingFederate" \
      org.opencontainers.image.description="PingFederate 13.1.3 with pf-agentic-identity's modules merged into pf-runtime.war" \
      org.opencontainers.image.source="https://github.com/ID-Partners/pf-agentic-identity" \
      org.opencontainers.image.version=$OCI_VERSION \
      org.opencontainers.image.revision=$OCI_REVISION \
      org.opencontainers.image.created=$OCI_CREATED \
      org.opencontainers.image.licenses="Apache-2.0 AND BSD-3-Clause AND LicenseRef-PingIdentity-Proprietary"

# age and age-keygen (the entrypoint needs age; test-entrypoint.sh --image makes its fixtures with age-keygen),
# and age's licence, which its BSD-3-Clause terms ask a binary distribution to carry.
COPY --from=age --chown=0:0 /age/age /age/age-keygen /usr/local/bin/
COPY --from=age --chown=0:0 /age/LICENSE /usr/local/share/licenses/age/LICENSE

# The assembled war from the builder. The directories above deploy/ are PingFederate's user's, as the archive's
# COPY used to leave them when it came first.
COPY modules/ /tmp/modules/
RUN mkdir -p /opt/in/instance/server/default/deploy \
 && chown 9031:0 /opt/in/instance /opt/in/instance/server /opt/in/instance/server/default
COPY --from=builder --chown=9031:0 /build/pf-runtime.war /opt/in/instance/server/default/deploy/pf-runtime.war

# ALSO place the module jars on the ENGINE classpath (server/default/deploy): the token-endpoint OGNL
# issuance criteria evaluate on the engine classloader, which does NOT search pf-runtime.war's
# WEB-INF/lib — without this, @ClientAttestationUtils@validateClientAttestation fails as an opaque
# OGNL "Method failed" (ClassNotFoundException). The webapp and engine copies communicate only via
# request attributes with string keys, so the dual-classloader split is by design. jose4j is already
# in server/default/lib.
RUN cp /tmp/modules/*.jar /opt/in/instance/server/default/deploy/ \
 && chown 9031:0 /opt/in/instance/server/default/deploy/*.jar \
 && rm -rf /tmp/modules

# The CIBA simulator's decision directory, conformance profile only. plugins/ciba-sim refuses every
# request unless OIDF_CIBA_SIM_DIR names a directory that exists, is not a symlink, is owned by the user
# PingFederate runs as and is 0700: it is the handoff between the plugin's two classloaders, and anyone
# else who could write to it could approve a request. Made here so the rig's vars.env can simply name
# it; outside /opt/out, which the base image's bootstrap populates by copying without preserving modes.
# A production image has neither the jar nor the directory.
RUN if [ "$STAGING_PROFILE" = conformance ]; then \
      mkdir -m 0700 /opt/ciba-sim && chown 9031:0 /opt/ciba-sim && echo 'ciba-sim: /opt/ciba-sim made for the simulator (conformance profile)'; \
    else echo 'ciba-sim: not in this image (production profile)'; fi

# PingFederate's plain HTTP runtime listener, off as PingFederate ships it and switchable at run time. The base
# image's run.properties template has pf.http.port=-1 written out, where its neighbours read variables
# (pf.https.port=${PF_ENGINE_PORT}); this has it read PF_RUN_PF_HTTP_PORT - the base image's PF_RUN_PF_* naming -
# which the base image's 05-expand-templates.sh substitutes at boot as it does the others. -1 is off, and the
# entrypoint refuses any port outside the development profile. (Checked 2026-09-29 in the 13.1.3 image: no
# variable of the base image's own reaches pf.http.port.) The template's lines end CRLF, and the sed keeps the CR.
ENV PF_RUN_PF_HTTP_PORT=-1
RUN F=/opt/staging/instance/bin/run.properties.subst.default \
 && sed -i 's/^pf\.http\.port=-1\([[:space:]]*\)$/pf.http.port=${PF_RUN_PF_HTTP_PORT}\1/' "$F" \
 && [ "$(grep -c '^pf\.http\.port=' "$F")" = 1 ] \
 && grep -q '^pf\.http\.port=\${PF_RUN_PF_HTTP_PORT}[[:space:]]*$' "$F"

# Check and decrypt the archive at boot, with the identity gone from the environment before PingFederate
# starts, then hand over to the base image's own bootstrap. build/pingfederate/test-entrypoint.sh --image
# exercises its decisions in the built image, and the healthcheck's.
COPY --chown=9031:0 pf-entrypoint.sh pf-healthcheck.sh /opt/
RUN chmod 755 /opt/pf-entrypoint.sh /opt/pf-healthcheck.sh

# The runtime (HTTPS) and admin ports, as the base image declares them; the plain HTTP listener is off unless
# the deployment turns it on, so it is not declared. The healthcheck is live, not ready: see pf-healthcheck.sh
# and README.md, "The healthcheck". It replaces the base image's (liveness.sh alone), which it runs first; the
# timings are the base image's.
EXPOSE 9031 9999
HEALTHCHECK --interval=31s --timeout=29s --start-period=241s --retries=7 CMD ["/opt/pf-healthcheck.sh"]

USER 9031:0
ENTRYPOINT ["/opt/pf-entrypoint.sh"]

# --- deployment: capability plus the configuration (the default target) ---
FROM capability AS deployment
USER root

# Config restore via PF's native drop-in-deployer: the DataDeployer timer imports data.zip on boot
# (no admin API, no license-acceptance gate). The overlay's DataDeployer settings are PingFederate's own
# defaults (README.md, "The drop-in deployer's settings"); the master-key overlay lets the archive's encrypted
# secrets decrypt natively (running master key == archive key).
# data.zip.age (encrypted, preferred) or data.zip (plaintext, transitional); the glob takes whichever
# is staged. It does NOT enforce that one is: a COPY glob matching nothing succeeds silently under
# BuildKit, which would produce an image that boots with no configuration and looks like it worked.
# Hence the assertion below - verified to fail when neither file is present.
COPY --chown=9031:0 data.zip* /opt/in/instance/server/default/data/drop-in-deployer/
RUN D=/opt/in/instance/server/default/data/drop-in-deployer; \
    if [ ! -f "$D/data.zip" ] && [ ! -f "$D/data.zip.age" ]; then \
      echo "ERROR: no config archive staged. Put data.zip.age (preferred) or data.zip in the build" >&2; \
      echo "       context. An image with neither imports nothing and starts an empty PF." >&2; \
      exit 1; \
    fi

# overlay/ as a directory, because under the encrypted scheme pf.jwk and the system keys are NOT staged
# at all - pf-entrypoint.sh extracts them from inside the archive at boot, so the running key is by
# construction the one the archive was encrypted under. config-store/ is plain config and always present.
COPY --chown=9031:0 overlay/ /opt/in/overlay-staged/
RUN D=/opt/in/instance/server/default/data; mkdir -p "$D/config-store"; \
    cp /opt/in/overlay-staged/config-store/*.xml "$D/config-store/"; \
    for f in pf.jwk pingfederate-system-keys.xml; do \
      if [ -f "/opt/in/overlay-staged/$f" ]; then \
        echo "WARNING: staging plaintext $f into an image layer - ship data.zip.age instead"; \
        cp "/opt/in/overlay-staged/$f" "$D/$f"; \
      fi; \
    done; \
    rm -rf /opt/in/overlay-staged; chown -R 9031:0 "$D"
# NB: no pingfederate.lic COPY — the boot hook fetches the license from the DevOps env vars above.

USER 9031:0
# The capability stage's entrypoint and healthcheck: pf-entrypoint.sh places the archive, and the drop-in
# deployer imports data.zip during boot.
