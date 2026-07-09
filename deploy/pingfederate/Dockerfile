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
#   pingfederate.lic                 <- PF eval license           (SECRET, git-ignored)
#   oidf.war, pf-oidf-modules.jar    <- `mvn -q package` outputs of this repo
#   jose4j-0.9.6.jar                 <- runtime dep of the module
#   oidf-mock-attesters.json         <- DEV attester trust (issuer -> public JWK)

FROM pingidentity/pingfederate:13.0.3-alpine_3.23.4-al21-latest
USER root

# Config restore via PF's native drop-in-deployer: the DataDeployer timer imports data.zip on boot
# (no admin API, no license-acceptance gate). ForceImport is set in the overlay below; the master-key
# overlay lets the archive's encrypted secrets decrypt natively (running master key == archive key).
COPY --chown=9031:0 data.zip /opt/in/instance/server/default/data/drop-in-deployer/data.zip
COPY --chown=9031:0 overlay/pf.jwk /opt/in/instance/server/default/data/pf.jwk
COPY --chown=9031:0 overlay/pingfederate-system-keys.xml /opt/in/instance/server/default/data/pingfederate-system-keys.xml
COPY --chown=9031:0 overlay/config-store/org.sourceid.saml20.domain.mgmt.impl.DataDeployer.xml /opt/in/instance/server/default/data/config-store/org.sourceid.saml20.domain.mgmt.impl.DataDeployer.xml
COPY --chown=9031:0 pingfederate.lic /opt/in/instance/server/default/conf/pingfederate.lic

# The OIDF attestation/federation module + its runtime dep. (No pf-rar-paz-plugin — that's agentic.)
COPY --chown=9031:0 oidf.war /opt/in/instance/server/default/deploy/oidf.war
COPY --chown=9031:0 pf-oidf-modules.jar /opt/in/instance/server/default/deploy/pf-oidf-modules.jar
COPY --chown=9031:0 jose4j-0.9.6.jar /opt/in/instance/server/default/deploy/jose4j-0.9.6.jar
COPY --chown=9031:0 oidf-mock-attesters.json /opt/in/instance/server/default/conf/oidf-mock-attesters.json

# Railway terminates TLS at its edge and forwards plain HTTP to the target port; PF's 9031 is HTTPS-only,
# so expose an HTTP runtime listener on 9080 for the service's HTTP domain.
RUN sed -i 's/^pf.http.port=-1/pf.http.port=9080/' /opt/staging/instance/bin/run.properties.subst.default
# Activate the static mock-attester resolver (DEV) — PF loads run.properties entries as sys props.
RUN printf '\noidf.mock.attesters=/opt/out/instance/server/default/conf/oidf-mock-attesters.json\n' >> /opt/staging/instance/bin/run.properties.subst.default
# Federation-gated disclosure (AS side): this AS REQUIRES the workload attributes disclosed, so a
# presentation that withholds them (external / unknown profile) is rejected (insufficient_disclosure).
RUN printf '\noidf.attestation.required.claims=workload\n' >> /opt/staging/instance/bin/run.properties.subst.default

USER 9031:0
# Stock entrypoint: the drop-in-deployer imports data.zip during boot.
