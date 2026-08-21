# OIDF demo AS — stock PingFederate 13.0.3 + the pf-oidf-modules attestation/federation module ONLY.
#
# This is the ISOLATED deploy context for pingfederate-runtime (Railway project e02a8e2f). It is the
# minus-RAR variant of idp-paz-authzen-adapter/demo/pingfederate/Dockerfile: it drops the agentic
# RFC 9396 RAR->PingAuthorize plugin, the RAR consent page, and the PingAuthorize-TLS workaround, and
# it bakes THIS repo's own OIDF-only data.zip (produced by terraform/ Phase 2) — so no agentic
# urn:agent:* clients or token-exchange plane ride along.
#
# Build-context artifacts required here before `railway up` (see terraform/README.md Step 6):
#   data.zip                         <- terraform Phase-2 export (OIDF-only configArchive)
#   overlay/pf.jwk                   <- prod master key           (SECRET, git-ignored)
#   overlay/pingfederate-system-keys.xml                          (SECRET, git-ignored)
#   overlay/config-store/org.sourceid.saml20.domain.mgmt.impl.DataDeployer.xml
#   pf-oidf-modules.jar              <- `mvn -q package` output of this repo (merged into pf-runtime.war)
#   jose4j-0.9.6.jar                 <- runtime dep of the module (merged into pf-runtime.war)
#   oidf-mock-attesters.json         <- DEV attester trust (issuer -> public JWK)
#
# The module is MERGED INTO pf-runtime.war (not deployed as a loose oidf.war + jar). This puts its
# @WebServlet servlets in the ROOT context — so `/.well-known/ssf-configuration`, `/ssf/*`, the challenge
# endpoint at `/federation/attestation-challenge`, etc. serve at root (no `/oidf` prefix) — gives a single
# classloader (one AttestationSupport singleton; no OGNL-hook caching split), and lets the SSF logout filter
# run over PF's own `/idp/init_logout.openid`. Repoint any `/oidf/*` consumers (e.g. the demo UI PF_BASE) to root.
#
# Licensing is DevOps-fetched — NO pingfederate.lic is baked. The base image's boot hook
# 17-check-license.sh pulls a fresh evaluation license when these RUNTIME env vars are set (as Railway
# service vars / GitHub Actions secrets — see vars.<env>.env + the deploy workflow):
#   PING_IDENTITY_ACCEPT_EULA=YES            (baked below; non-secret)
#   PING_IDENTITY_DEVOPS_USER=<devops email> (SECRET — never in git)
#   PING_IDENTITY_DEVOPS_KEY=<devops key>    (SECRET — never in git)
# Trade-off: DevOps eval licenses are short-lived (~7 days) and re-fetched only at container start.

FROM pingidentity/pingfederate:13.0.3-alpine_3.23.4-al21-latest
USER root

# Accept the Ping EULA so the DevOps license hook runs unattended (non-secret; the DEVOPS_USER/KEY that
# actually authenticate the fetch are supplied as runtime secrets, never baked).
ENV PING_IDENTITY_ACCEPT_EULA=YES

# age, for the encrypted config archive (see pf-entrypoint.sh). Verified available from the community
# repo this base image already enables: alpine 3.23.4, age 1.2.1. No static-binary fallback needed.
RUN apk add --no-cache age

# Config restore via PF's native drop-in-deployer: the DataDeployer timer imports data.zip on boot
# (no admin API, no license-acceptance gate). ForceImport is set in the overlay below; the master-key
# overlay lets the archive's encrypted secrets decrypt natively (running master key == archive key).
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

# Merge the OIDF attestation/federation/SSF modules into pf-runtime.war (root context, single classloader),
# and register the SSF logout filter in its web.xml — via the same assemble script the build-in-CI path uses.
# modules/ holds the monorepo reactor's modular jars (oidf.jar + attestation-issuer/ssf +
# oidf-jose/client-attestation/openid-federation) — staged by stage-modules.sh.
# (No pf-rar-paz-plugin — that's agentic.)
COPY assemble-pf-runtime-war.sh /tmp/assemble-pf-runtime-war.sh
COPY modules/ /tmp/modules/
RUN mkdir -p /opt/in/instance/server/default/deploy \
 && apk add --no-cache bash zip unzip \
 && STOCK="$(find /opt -name pf-runtime.war 2>/dev/null | grep -v '/opt/in/' | head -1)" \
 && { [ -n "$STOCK" ] || { echo 'stock pf-runtime.war not found in base image'; exit 1; }; } \
 && bash /tmp/assemble-pf-runtime-war.sh "$STOCK" /tmp/modules - \
      /opt/in/instance/server/default/deploy/pf-runtime.war \
 && chown 9031:0 /opt/in/instance/server/default/deploy/pf-runtime.war \
 && rm -f /tmp/assemble-pf-runtime-war.sh
COPY --chown=9031:0 oidf-mock-attesters.json /opt/in/instance/server/default/conf/oidf-mock-attesters.json

# ALSO place the module jars on the ENGINE classpath (server/default/deploy): the token-endpoint OGNL
# issuance criteria evaluate on the engine classloader, which does NOT search pf-runtime.war's
# WEB-INF/lib — without this, @ClientAttestationUtils@validateClientAttestation fails as an opaque
# OGNL "Method failed" (ClassNotFoundException). The webapp and engine copies communicate only via
# request attributes with string keys, so the dual-classloader split is by design. jose4j is already
# in server/default/lib.
RUN cp /tmp/modules/*.jar /opt/in/instance/server/default/deploy/ \
 && chown 9031:0 /opt/in/instance/server/default/deploy/*.jar \
 && rm -rf /tmp/modules

# Railway terminates TLS at its edge and forwards plain HTTP to the target port; PF's 9031 is HTTPS-only,
# so expose an HTTP runtime listener on 9080 for the service's HTTP domain.
RUN sed -i 's/^pf.http.port=-1/pf.http.port=9080/' /opt/staging/instance/bin/run.properties.subst.default
# Activate the static mock-attester resolver (DEV) — PF loads run.properties entries as sys props.
RUN printf '\noidf.mock.attesters=/opt/out/instance/server/default/conf/oidf-mock-attesters.json\n' >> /opt/staging/instance/bin/run.properties.subst.default
# Federation-gated disclosure (AS side): this AS REQUIRES the workload attributes disclosed, so a
# presentation that withholds them (external / unknown profile) is rejected (insufficient_disclosure).
RUN printf '\noidf.attestation.required.claims=workload\n' >> /opt/staging/instance/bin/run.properties.subst.default

# Surface the federation plugin's DEBUG resolve/fetch lines (fetchEntityStatement /
# fetchSubordinateStatement / chain walk in HttpTrustControllerGateway + TrustChainValidator) so the demo's
# activity panel shows the AS resolving the entity statement + walking the chain — not just the final
# "Automatically registered" line. Scoped to the module's package; the rest of PF stays at INFO.
RUN CONF="$(find /opt -path '*server/default/conf/log4j2.xml' 2>/dev/null | head -1)"; echo "log4j2 = $CONF"; \
    sed -i 's#</Loggers>#    <Logger name="com.pingidentity.ps.oidf" level="DEBUG" />\n    </Loggers>#' "$CONF" \
    && grep -c 'com.pingidentity.ps.oidf' "$CONF"

# Decrypt the archive at boot, then hand over to the base image's own bootstrap.
COPY --chown=9031:0 pf-entrypoint.sh /opt/pf-entrypoint.sh
RUN chmod 755 /opt/pf-entrypoint.sh

USER 9031:0
ENTRYPOINT ["/opt/pf-entrypoint.sh"]
# Stock entrypoint: the drop-in-deployer imports data.zip during boot.
