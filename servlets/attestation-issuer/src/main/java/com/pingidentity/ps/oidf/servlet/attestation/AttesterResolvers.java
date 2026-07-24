/*
 * Chooses the attester's client resolver from the environment: a CIMD document, or the PF client store.
 */
package com.pingidentity.ps.oidf.servlet.attestation;

import com.pingidentity.ps.oidf.common.CimdClientResolver;
import com.pingidentity.ps.oidf.common.IssuanceClientResolver;
import com.pingidentity.ps.oidf.common.PfMgmtClientStore;
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
    static final String SIGNING_JWK_PROPERTY = "oidf.attester.signing.jwk";
    static final String SIGNING_JWK_ENV = "OIDF_ATTESTER_SIGNING_JWK";

    private AttesterResolvers() {
    }

    static IssuanceClientResolver fromEnvironment() {
        String cimdUrl = firstSet(System.getProperty(CIMD_URL_PROPERTY), System.getenv(CIMD_URL_ENV));
        if (cimdUrl != null) {
            // The attester's signing key is a deployment secret, applied to CIMD entries — never in the
            // public document. Sourced from config here.
            String signingJwk = firstSet(System.getProperty(SIGNING_JWK_PROPERTY), System.getenv(SIGNING_JWK_ENV));
            LOGGER.info((Object) ("Attester client mapping from CIMD document: " + cimdUrl));
            return new CimdClientResolver(cimdUrl, signingJwk);
        }
        return new PfIssuanceClientResolver(new PfMgmtClientStore());
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
