# The capability's PingFederate image: stock PingFederate 13.1.3 (jakarta.servlet) + this repo's module set,
# merged into pf-runtime.war, and nothing else. No RAR->PingAuthorize plugin, no consent page, no agentic
# clients: those belong to a consumer's own image, built FROM the same base with its own archive.
#
# Build-context artifacts required here (see README.md in this directory):
#   data.zip.age (preferred) or data.zip  <- the config archive (produced by terraform/ export)
#   overlay/config-store/org.sourceid.saml20.domain.mgmt.impl.DataDeployer.xml
#   overlay/pf.jwk, overlay/pingfederate-system-keys.xml   only under the plaintext scheme (SECRET, git-ignored)
#   modules/                         <- stage-modules.sh output of this repo's reactor (merged into
#                                       pf-runtime.war AND copied to server/default/deploy; see below)
#   (no jose4j: the assemble call passes "-" and relies on PF's own copy in server/default/lib)
#   oidf-mock-attesters.json         <- OPTIONAL, consumer-supplied: DEV attester trust
#                                       (issuer -> public JWK), bypassing federation trust chains
#
# The module is MERGED INTO pf-runtime.war (not deployed as a loose oidf.war + jar). This puts its
# @WebServlet servlets in the ROOT context — so `/.well-known/ssf-configuration`, `/ssf/*`, the challenge
# endpoint at `/federation/attestation-challenge`, etc. serve at root (no `/oidf` prefix) — gives a single
# classloader (one AttestationSupport singleton; no OGNL-hook caching split), and lets the SSF logout filter
# run over PF's own `/idp/init_logout.openid`. Repoint any `/oidf/*` consumers (e.g. the demo UI PF_BASE) to root.
#
# Licensing is DevOps-fetched — NO pingfederate.lic is baked. The base image's boot hook
# 17-check-license.sh pulls a fresh evaluation license when these RUNTIME env vars are set (as the
# deployment's secrets - see vars.<env>.env):
#   PING_IDENTITY_ACCEPT_EULA=YES            (baked below; non-secret)
#   PING_IDENTITY_DEVOPS_USER=<devops email> (SECRET — never in git)
#   PING_IDENTITY_DEVOPS_KEY=<devops key>    (SECRET — never in git)
# Trade-off: DevOps eval licenses are short-lived (~7 days) and re-fetched only at container start.

# The tag and digest are the ones build/pf-version.env records (PF_IMAGE, PF_IMAGE_DIGEST), written out as a
# literal so Dependabot can bump them here; tools/pf-version-check.py fails when the two disagree, and
# tools/pf-version-sync.py rewrites the env file from this line after a bump.
FROM pingidentity/pingfederate:13.1.3-alpine_3.24.1-al21-latest@sha256:0d559261d658222179b07de8b2c84a8aea3cb30c7be107970686f58ea9dd3a4a
USER root

# Accept the Ping EULA so the DevOps license hook runs unattended (non-secret; the DEVOPS_USER/KEY that
# actually authenticate the fetch are supplied as runtime secrets, never baked).
ENV PING_IDENTITY_ACCEPT_EULA=YES

# age, for the encrypted config archive (see pf-entrypoint.sh). Available from the community repo this
# base image already enables: alpine 3.24.1, age 1.3.1 (verified 2026-09-26 on the 13.1.3 image). No
# static-binary fallback needed.
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

# Merge the OIDF attestation/federation/SSF modules into pf-runtime.war (root context, the webapp
# classloader — the same jars are ALSO copied to server/default/deploy below, so the engine classloader
# gets its own copy: two classloaders, deliberately, and without Redis the filter and the OGNL criterion
# therefore keep separate in-memory challenge/replay stores), and register the seven filters the
# assemble script names (SsfLogoutSignal, Fapi2Profile, FapiResourceServer, OAuthErrorDescription,
# OidfFrontChannelAutoRegistration, OidfAutoRegistration, ClientAttestationAuth) in its web.xml - via the
# same assemble script a consumer's CI would use. modules/ holds the reactor's modular jars (oidf.jar +
# attestation-issuer/ssf + oidf-jose/client-attestation/openid-federation/agent-registry/device-instance +
# the CIBA simulator), staged by stage-modules.sh, which writes the MANIFEST the assemble script checks.
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
# DEV attester trust, OPTIONAL — supplied by the consumer, never baked here. This file is a static
# issuer -> public JWK map that BYPASSES OpenID Federation trust-chain resolution, so whoever ships it
# decides which attesters this AS believes. That is a demo's decision about its own trust, not a
# capability this image should carry: baking one in would hand every consumer another consumer's
# attesters and silently pre-trust a key they never chose. The bracket glob makes it a no-op when the
# build context does not supply the file.
COPY --chown=9031:0 oidf-mock-attesters.jso[n] /opt/in/instance/server/default/conf/

# ALSO place the module jars on the ENGINE classpath (server/default/deploy): the token-endpoint OGNL
# issuance criteria evaluate on the engine classloader, which does NOT search pf-runtime.war's
# WEB-INF/lib — without this, @ClientAttestationUtils@validateClientAttestation fails as an opaque
# OGNL "Method failed" (ClassNotFoundException). The webapp and engine copies communicate only via
# request attributes with string keys, so the dual-classloader split is by design. jose4j is already
# in server/default/lib.
RUN cp /tmp/modules/*.jar /opt/in/instance/server/default/deploy/ \
 && chown 9031:0 /opt/in/instance/server/default/deploy/*.jar \
 && rm -rf /tmp/modules

# A platform that terminates TLS at its edge forwards plain HTTP to the target port; PF's 9031 is
# HTTPS-only, so expose an HTTP runtime listener on 9080 for that path.
RUN sed -i 's/^pf.http.port=-1/pf.http.port=9080/' /opt/staging/instance/bin/run.properties.subst.default
# Activate the static mock-attester resolver ONLY if the consumer supplied one — PF loads
# run.properties entries as sys props. Unconditional activation would mean the image always resolves
# attester trust from a file it chose; absent the file, attester trust resolves the real way, through
# federation trust chains. Both branches announce themselves: which resolver is live decides what this
# AS will believe about who vouched for a client, and that should never be a silent build detail.
RUN if [ -f /opt/in/instance/server/default/conf/oidf-mock-attesters.json ]; then \
      printf '\noidf.mock.attesters=/opt/out/instance/server/default/conf/oidf-mock-attesters.json\n' \
        >> /opt/staging/instance/bin/run.properties.subst.default; \
      echo 'oidf.mock.attesters: ACTIVE - static attester trust supplied by the build context (DEV/DEMO)'; \
    else \
      echo 'oidf.mock.attesters: not supplied - attester trust resolves via OpenID Federation trust chains'; \
    fi
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
