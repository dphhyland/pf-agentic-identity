/*
 * Chooses the attester's client resolver from the environment: a CIMD document, or the PF client store.
 */
package com.pingidentity.ps.oidf.servlet.attestation;

import com.pingidentity.ps.oidf.issuer.ChainClientResolver;
import com.pingidentity.ps.oidf.issuer.CimdClientResolver;
import com.pingidentity.ps.oidf.issuer.IssuanceClientResolver;
import com.pingidentity.ps.oidf.issuer.OpenIdFederationClientResolver;
import com.pingidentity.ps.oidf.pf.PfMgmtClientStore;
import java.util.ArrayList;
import java.util.List;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * Selects where the attester reads its SPIFFE-ID → client mapping. If the system property
 * {@code oidf.attester.cimd.url} (or env {@code OIDF_ATTESTER_CIMD_URL}) is set, the mapping comes from
 * that hosted Client ID Metadata Document; otherwise it comes from PingFederate's own client store.
 * Mirrors the {@code oidf.mock.attesters} switch used on the verification side.
 */
final class AttesterResolvers {
    private static final Log LOGGER = LogFactory.getLog(AttesterResolvers.class);

    static final String CIMD_URL_PROPERTY = "oidf.attester.cimd.url";
    static final String CIMD_URL_ENV = "OIDF_ATTESTER_CIMD_URL";
    static final String FEDERATION_ENTITY_PROPERTY = "oidf.attester.federation.entity";
    static final String FEDERATION_ENTITY_ENV = "OIDF_ATTESTER_FEDERATION_ENTITY";
    static final String SIGNING_JWK_PROPERTY = "oidf.attester.signing.jwk";
    static final String SIGNING_JWK_ENV = "OIDF_ATTESTER_SIGNING_JWK";

    private AttesterResolvers() {
    }

    /**
     * Builds the active resolver chain from configuration. The PingFederate client store is always a
     * plugin; a CIMD document and/or an OpenID Federation entity are added when configured. With none of
     * the external sources set, this is just the PF store (backwards compatible).
     */
    static IssuanceClientResolver fromEnvironment() {
        String signingJwk = firstSet(System.getProperty(SIGNING_JWK_PROPERTY), System.getenv(SIGNING_JWK_ENV));
        List<IssuanceClientResolver> plugins = new ArrayList<>();

        String cimdUrl = firstSet(System.getProperty(CIMD_URL_PROPERTY), System.getenv(CIMD_URL_ENV));
        if (cimdUrl != null) {
            LOGGER.info((Object) ("Attester resolver plugin: cimd -> " + cimdUrl));
            plugins.add(new CimdClientResolver(cimdUrl, signingJwk));
        }
        String fedEntity = firstSet(System.getProperty(FEDERATION_ENTITY_PROPERTY), System.getenv(FEDERATION_ENTITY_ENV));
        if (fedEntity != null) {
            LOGGER.info((Object) ("Attester resolver plugin: openid-federation -> " + fedEntity));
            plugins.add(new OpenIdFederationClientResolver(fedEntity, signingJwk));
        }
        // The PF client store is always available as a plugin (registered client metadata).
        plugins.add(new PfIssuanceClientResolver(new PfMgmtClientStore()));

        return plugins.size() == 1 ? plugins.get(0) : new ChainClientResolver(plugins);
    }

    /** The distinct plugin ids in an active resolver (for the discovery document). */
    static List<String> activePluginIds(IssuanceClientResolver resolver) {
        if (resolver instanceof ChainClientResolver) {
            return ((ChainClientResolver) resolver).activePluginIds();
        }
        return List.of(resolver.pluginId());
    }

    private static String firstSet(String a, String b) {
        if (a != null && !a.isBlank()) {
            return a.trim();
        }
        if (b != null && !b.isBlank()) {
            return b.trim();
        }
        return null;
    }
}
