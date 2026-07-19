/*
 * Configuration parsing: defaults, overrides, and validation.
 */
package com.pingidentity.ps.oidf.ssf;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.HashMap;
import java.util.Map;
import javax.servlet.ServletConfig;
import org.junit.jupiter.api.Test;

class SsfConfigurationTest {

    private static ServletConfig servletConfig(Map<String, String> params) {
        ServletConfig cfg = mock(ServletConfig.class);
        lenient().when(cfg.getInitParameter(org.mockito.ArgumentMatchers.anyString()))
                .thenAnswer(inv -> params.get(inv.getArgument(0)));
        return cfg;
    }

    @Test
    void minimalConfigAppliesDocumentedDefaults() {
        Map<String, String> p = new HashMap<>();
        p.put("issuer", "https://op.example.com/");
        SsfConfiguration cfg = SsfConfiguration.fromServletConfig(servletConfig(p));

        assertEquals("https://op.example.com", cfg.issuer(), "trailing slash trimmed");
        assertEquals("RS256", cfg.signingAlgorithm());
        assertTrue(cfg.usesInMemoryStore());
        assertFalse(cfg.kafkaEnabled());
        assertEquals("sse-events", cfg.kafkaTopic());
        assertEquals("ssf.manage", cfg.receiverScope());
        assertEquals(5, cfg.pushRetryMaxAttempts());
        assertEquals(100, cfg.pollMaxEvents());
        assertTrue(cfg.verificationEventEnabled());
        assertEquals("https://op.example.com/pf/JWKS", cfg.jwksUri());
        assertEquals("https://op.example.com/ssf/streams", cfg.configurationEndpoint());
    }

    @Test
    void overridesAreParsed() {
        Map<String, String> p = new HashMap<>();
        p.put("issuer", "https://op.example.com");
        p.put("signingAlgorithm", "PS256");
        p.put("dataStoreId", "ds-123");
        p.put("kafkaEnabled", "true");
        p.put("kafkaBootstrapServers", "broker:9092");
        p.put("kafkaTopic", "custom-topic");
        p.put("pushRetryMaxAttempts", "9");
        p.put("pollMaxEvents", "10");
        p.put("setTtlSeconds", "60");
        p.put("receiverScope", "ssf.admin");
        p.put("defaultEventTypes", SsfEventTypes.CAEP_SESSION_REVOKED + " , " + SsfEventTypes.RISC_ACCOUNT_DISABLED);
        p.put("verificationEventEnabled", "false");

        SsfConfiguration cfg = SsfConfiguration.fromServletConfig(servletConfig(p));
        assertEquals("PS256", cfg.signingAlgorithm());
        assertEquals("ds-123", cfg.dataStoreId());
        assertFalse(cfg.usesInMemoryStore());
        assertTrue(cfg.kafkaEnabled());
        assertEquals("broker:9092", cfg.kafkaBootstrapServers());
        assertEquals("custom-topic", cfg.kafkaTopic());
        assertEquals(9, cfg.pushRetryMaxAttempts());
        assertEquals(10, cfg.pollMaxEvents());
        assertEquals(60L, cfg.setTtlSeconds());
        assertEquals("ssf.admin", cfg.receiverScope());
        assertEquals(2, cfg.defaultEventTypes().size());
        assertFalse(cfg.verificationEventEnabled());
    }

    @Test
    void rejectsMissingIssuer() {
        assertThrows(IllegalArgumentException.class,
                () -> SsfConfiguration.fromServletConfig(servletConfig(new HashMap<>())));
    }

    @Test
    void rejectsBadSigningAlgorithm() {
        Map<String, String> p = new HashMap<>();
        p.put("issuer", "https://op.example.com");
        p.put("signingAlgorithm", "HS256");
        assertThrows(IllegalArgumentException.class,
                () -> SsfConfiguration.fromServletConfig(servletConfig(p)));
    }

    @Test
    void rejectsKafkaEnabledWithoutBootstrap() {
        Map<String, String> p = new HashMap<>();
        p.put("issuer", "https://op.example.com");
        p.put("kafkaEnabled", "true");
        assertThrows(IllegalArgumentException.class,
                () -> SsfConfiguration.fromServletConfig(servletConfig(p)));
    }
}
