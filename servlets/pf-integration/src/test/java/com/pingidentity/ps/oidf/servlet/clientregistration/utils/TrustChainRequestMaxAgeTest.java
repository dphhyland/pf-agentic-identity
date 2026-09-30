/*
 * One default for the per-client trust_chain_request_max_age, whichever reader asks (F-0198).
 */
package com.pingidentity.ps.oidf.servlet.clientregistration.utils;

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.pingidentity.ps.oidf.platform.settings.Catalogue;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * The OGNL chain criterion, the attestation criterion's attester chain and the token-endpoint filter's attester chain hold
 * a presented chain to one default, the catalogue's: until 0.6.0 the two attester paths used -1, no limit (F-0198).
 */
class TrustChainRequestMaxAgeTest {

    @Test
    void theDefaultIsTheCataloguesAndEveryReaderUsesIt() {
        Catalogue properties = Catalogue.load(OIDFederationUtils.class.getClassLoader(), "client-properties");
        assertEquals(String.valueOf(OIDFederationUtils.TRUST_CHAIN_REQUEST_MAX_AGE_DEFAULT),
                properties.setting("trust_chain_request_max_age").defaultValue());

        Map<String, Object> none = new HashMap<>();
        assertEquals(60L, OIDFederationUtils.trustChainRequestMaxAge(none));
        none.put("extproperties.trust_chain_request_max_age", "not a number");
        assertEquals(60L, OIDFederationUtils.trustChainRequestMaxAge(none), "a per-request property: the default, with a warning");
        Map<String, Object> set = Map.of("extproperties.trust_chain_request_max_age", "-1");
        assertEquals(-1L, OIDFederationUtils.trustChainRequestMaxAge(set), "the client's own value, -1 for no limit");
    }
}
