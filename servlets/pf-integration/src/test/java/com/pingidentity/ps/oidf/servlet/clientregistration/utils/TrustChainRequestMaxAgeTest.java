/*
 * One default for the per-client trust_chain_request_max_age, whichever reader asks (F-0198).
 */
package com.pingidentity.ps.oidf.servlet.clientregistration.utils;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.pingidentity.ps.oidf.federation.TrustChainValidator;
import com.pingidentity.ps.oidf.pf.FederationAttesterKeyResolver;
import com.pingidentity.ps.oidf.pf.FederationRuntimeConfig;
import com.pingidentity.ps.oidf.platform.settings.Catalogue;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * The OGNL chain criterion, the attestation criterion's attester chain and the token-endpoint filter's attester chain hold
 * a presented chain to one default, the catalogue's: until 0.6.0 the two attester paths used -1, no limit (F-0198).
 */
class TrustChainRequestMaxAgeTest {

    private static final String[] VALIDATOR_STATE = {"validator", "gateway", "configuredIgnoreSslErrors",
        "configuredTrustControllerHost", "configuredTrustControllerBaseUrl"};

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

    /** The attestation criterion's attester chain: the client's property, else the same default. */
    @Test
    void theAttestationCriterionHoldsAnAttesterChainToTheSameDefault() {
        assertEquals(60L, ClientAttestationUtils.trustChainEntryMaxAge(new HashMap<>()));
        assertEquals(-1L, ClientAttestationUtils.trustChainEntryMaxAge(Map.of("extproperties.trust_chain_request_max_age", "-1")));
        assertEquals(300L, ClientAttestationUtils.trustChainEntryMaxAge(Map.of("extproperties.trust_chain_request_max_age", "300")));
    }

    /**
     * The token-endpoint filter's attester chain, which has no client's properties: the resolver it is given asks the
     * validator for the default, seen on the call the resolver makes.
     */
    @Test
    void theTokenEndpointFilterHoldsAnAttesterChainToTheSameDefault() throws Exception {
        FederationRuntimeConfig runtime = FederationRuntimeConfig.get();
        TrustChainValidator validator = mock(TrustChainValidator.class);
        IllegalStateException stop = new IllegalStateException("stop after the call");
        when(validator.validate(any(), anyString(), anyString(), anyLong(), anyLong(), anyLong())).thenThrow(stop);
        Map<String, Object> saved = swapValidatorState(Map.of("validator", validator,
                "configuredIgnoreSslErrors", runtime.ignoreSslErrors(),
                "configuredTrustControllerHost", nullable(runtime.trustControllerHost()),
                "configuredTrustControllerBaseUrl", nullable(effectiveBaseUrl(runtime))));
        String mockAttesters = System.clearProperty("oidf.mock.attesters");
        resetMockAttesters();
        try {
            var resolver = ClientAttestationUtils.attesterResolver("https://op.example");

            assertInstanceOf(FederationAttesterKeyResolver.class, resolver);
            IllegalStateException thrown = assertThrows(IllegalStateException.class,
                    () -> resolver.resolve("https://attester.example", List.of()));
            assertSame(stop, thrown);
            verify(validator).validate(eq(List.of()), eq("https://attester.example"), eq("https://op.example"), eq(-1L), eq(-1L),
                    eq(OIDFederationUtils.TRUST_CHAIN_REQUEST_MAX_AGE_DEFAULT));
        } finally {
            swapValidatorState(saved);
            if (mockAttesters != null) {
                System.setProperty("oidf.mock.attesters", mockAttesters);
            }
            resetMockAttesters();
        }
    }

    private static final Object NULL = new Object();

    private static Object nullable(Object value) {
        return value == null ? NULL : value;
    }

    private static String effectiveBaseUrl(FederationRuntimeConfig runtime) {
        String base = runtime.trustControllerBaseUrl();
        return base == null || base.isBlank() ? runtime.trustControllerHost() : base;
    }

    /** Sets the named statics (NULL for null, the rest to null) and returns what they held, to restore. */
    private static Map<String, Object> swapValidatorState(Map<String, Object> values) throws Exception {
        Map<String, Object> previous = new LinkedHashMap<>();
        for (String name : VALIDATOR_STATE) {
            Field field = ClientAttestationUtils.class.getDeclaredField(name);
            field.setAccessible(true);
            previous.put(name, nullable(field.get(null)));
            Object value = values.get(name);
            field.set(null, value == null || value == NULL ? null : value);
        }
        return previous;
    }

    private static void resetMockAttesters() throws Exception {
        Method reset = ClientAttestationUtils.class.getDeclaredMethod("resetMockAttesterResolverForTest");
        reset.setAccessible(true);
        reset.invoke(null);
    }
}
