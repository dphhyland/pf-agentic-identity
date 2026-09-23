/*
 * Configuration parsing: defaults, overrides, and validation.
 */
package com.pingidentity.ps.oidf.ssf;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;
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
    void defaultSubjectsIsNoneUnlessSetToAllAndNothingElseIsAccepted() {
        Map<String, String> p = new HashMap<>();
        p.put("issuer", "https://op.example.com");
        assertEquals("NONE", SsfConfiguration.fromServletConfig(servletConfig(p)).defaultSubjects());
        assertFalse(SsfConfiguration.fromServletConfig(servletConfig(p)).defaultSubjectsAll());

        p.put("defaultSubjects", " ALL ");
        assertTrue(SsfConfiguration.fromServletConfig(servletConfig(p)).defaultSubjectsAll());
        p.put("defaultSubjects", "NONE");
        assertEquals("NONE", SsfConfiguration.fromServletConfig(servletConfig(p)).defaultSubjects());

        for (String bad : new String[] {"all", "Everyone", "true"}) {
            p.put("defaultSubjects", bad);
            assertThrows(IllegalArgumentException.class, () -> SsfConfiguration.fromServletConfig(servletConfig(p)), bad);
        }
        assertEquals("NONE", SsfConfiguration.parseDefaultSubjects(null));
        assertEquals("NONE", SsfConfiguration.parseDefaultSubjects("  "));
    }

    @Test
    void theDefaultEventTypesNameTheThreeInteropEvents() {
        Map<String, String> p = new HashMap<>();
        p.put("issuer", "https://op.example.com");
        assertTrue(SsfConfiguration.fromServletConfig(servletConfig(p)).defaultEventTypes()
                .containsAll(SsfEventTypes.CAEP_INTEROP));
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
    void resolvesFromSystemPropertyWhenInitParamAbsent() {
        System.setProperty("oidf.ssf.issuer", "https://sysprop.example.com");
        System.setProperty("oidf.ssf.receiverScope", "ssf.custom");
        try {
            SsfConfiguration cfg = SsfConfiguration.fromServletConfig(servletConfig(new HashMap<>()));
            assertEquals("https://sysprop.example.com", cfg.issuer());
            assertEquals("ssf.custom", cfg.receiverScope());
        } finally {
            System.clearProperty("oidf.ssf.issuer");
            System.clearProperty("oidf.ssf.receiverScope");
        }
    }

    @Test
    void initParamTakesPrecedenceOverSystemProperty() {
        Map<String, String> p = new HashMap<>();
        p.put("issuer", "https://initparam.example.com");
        System.setProperty("oidf.ssf.issuer", "https://sysprop.example.com");
        try {
            assertEquals("https://initparam.example.com",
                    SsfConfiguration.fromServletConfig(servletConfig(p)).issuer());
        } finally {
            System.clearProperty("oidf.ssf.issuer");
        }
    }

    @Test
    void storeDialectDefaultsToTablesAndAcceptsLdm() {
        Map<String, String> p = new HashMap<>();
        p.put("issuer", "https://op.example.com");
        assertEquals("tables", SsfConfiguration.fromServletConfig(servletConfig(p)).storeDialect());
        p.put("storeDialect", "ldm");
        assertEquals("ldm", SsfConfiguration.fromServletConfig(servletConfig(p)).storeDialect());
        p.put("storeDialect", "bogus");
        assertThrows(IllegalArgumentException.class, () -> SsfConfiguration.fromServletConfig(servletConfig(p)));
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

    /** Unset is the safe value, so it has to be what an operator who has never heard of the setting gets. */
    @Test
    void nobodyIsAdmittedToUnownedStreamsUnlessAClientIsNamed() {
        Map<String, String> p = new HashMap<>();
        p.put("issuer", "https://op.example.com");
        assertNull(SsfConfiguration.fromServletConfig(servletConfig(p)).unownedStreamOwner());

        p.put("unownedStreamOwner", "   "); // set, but to nothing: still nobody, not a client named ""
        assertNull(SsfConfiguration.fromServletConfig(servletConfig(p)).unownedStreamOwner());
        assertNull(new SsfConfiguration.Builder().issuer("https://op.example.com").unownedStreamOwner(" ").build()
                .unownedStreamOwner());

        p.put("unownedStreamOwner", " legacy-receiver "); // control
        assertEquals("legacy-receiver", SsfConfiguration.fromServletConfig(servletConfig(p)).unownedStreamOwner());
    }

    /** The name an operator actually types. OIDF_SSF_UNOWNED_STREAM_OWNER is derived from this one the same way. */
    @Test
    void theUnownedStreamOwnerResolvesFromItsSystemProperty() {
        System.setProperty("oidf.ssf.issuer", "https://sysprop.example.com");
        System.setProperty("oidf.ssf.unownedStreamOwner", "legacy-receiver");
        try {
            assertEquals("legacy-receiver",
                    SsfConfiguration.fromServletConfig(servletConfig(new HashMap<>())).unownedStreamOwner());
        } finally {
            System.clearProperty("oidf.ssf.issuer");
            System.clearProperty("oidf.ssf.unownedStreamOwner");
        }
    }

    /** Unset is the closed value: nobody provisions until an operator names a scope for it. */
    @Test
    void thereIsNoProvisionerScopeUnlessOneIsNamed() {
        Map<String, String> p = new HashMap<>();
        p.put("issuer", "https://op.example.com");
        assertNull(SsfConfiguration.fromServletConfig(servletConfig(p)).provisionerScope());

        p.put("provisionerScope", "  ");
        assertNull(SsfConfiguration.fromServletConfig(servletConfig(p)).provisionerScope());

        p.put("provisionerScope", " ssf.provision "); // control
        assertEquals("ssf.provision", SsfConfiguration.fromServletConfig(servletConfig(p)).provisionerScope());
    }

    /** Naming the receiver scope would make every receiver a provisioner, which is the hole the scope closes. */
    @Test
    void theProvisionerScopeMayNotBeTheReceiverScope() {
        assertThrows(IllegalArgumentException.class, () -> new SsfConfiguration.Builder().issuer("https://op.example.com")
                .provisionerScope("ssf.manage").build());
        assertThrows(IllegalArgumentException.class, () -> new SsfConfiguration.Builder().issuer("https://op.example.com")
                .receiverScope("custom").provisionerScope(" custom ").build());
        // control: the default receiver scope's name is free once the receiver scope is something else
        assertEquals("ssf.manage", new SsfConfiguration.Builder().issuer("https://op.example.com")
                .receiverScope("custom").provisionerScope("ssf.manage").build().provisionerScope());
    }

    @Test
    void allowedAudiencesAreReadPerClient() {
        Map<String, String> p = new HashMap<>();
        p.put("issuer", "https://op.example.com");
        assertEquals(Set.of(), SsfConfiguration.fromServletConfig(servletConfig(p)).allowedAudiences("receiver-a"));

        p.put("allowedAudiences", " receiver-a = https://a.example.com , https://a2.example.com ;; receiver-b=https://b.example.com?x=1; receiver-a=https://a3.example.com ");
        SsfConfiguration cfg = SsfConfiguration.fromServletConfig(servletConfig(p));
        assertEquals(Set.of("https://a.example.com", "https://a2.example.com", "https://a3.example.com"), cfg.allowedAudiences("receiver-a"));
        assertEquals(Set.of("https://b.example.com?x=1"), cfg.allowedAudiences("receiver-b"));
        assertEquals(Set.of(), cfg.allowedAudiences("receiver-c"));
        assertEquals(Set.of(), cfg.allowedAudiences(null));
        assertEquals(Set.of(), new SsfConfiguration.Builder().issuer("https://op.example.com").allowedAudiences("  ").build()
                .allowedAudiences("receiver-a"));

        // an entry that names no client is a mistake to be told about, not an audience open to all
        for (String bad : new String[] {"https://a.example.com", "=https://a.example.com", " =https://a.example.com"}) {
            p.put("allowedAudiences", bad);
            assertThrows(IllegalArgumentException.class, () -> SsfConfiguration.fromServletConfig(servletConfig(p)));
        }
    }
}
