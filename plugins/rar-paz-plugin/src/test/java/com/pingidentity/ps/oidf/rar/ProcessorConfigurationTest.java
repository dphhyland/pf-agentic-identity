package com.pingidentity.ps.oidf.rar;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.stream.Collectors.toSet;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.sdk.authorizationdetails.AuthorizationDetail;
import com.pingidentity.sdk.authorizationdetails.AuthorizationDetailContext;
import com.pingidentity.sdk.authorizationdetails.AuthorizationDetailProcessingException;
import com.sun.net.httpserver.HttpServer;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Predicate;
import org.junit.jupiter.api.Test;
import org.sourceid.saml20.adapter.conf.Configuration;
import org.sourceid.saml20.adapter.conf.Field;
import org.sourceid.saml20.adapter.gui.CheckBoxFieldDescriptor;
import org.sourceid.saml20.adapter.gui.FieldDescriptor;

/**
 * What an instance's stored configuration turns into, and the version PingFederate shows for the plugin.
 *
 * <p>A field can be missing from a stored configuration: the instance was saved before the field existed, or
 * the admin API or an archive left it out. PingFederate 13.1.3 hands an instance with no parent its stored
 * configuration as it is, and fills a child instance's gaps from the descriptor's defaults. The switches used
 * to be read with the one-argument {@code getBooleanFieldValue}, which reads a missing field as false. A missing
 * "Deny unless PERMIT" therefore turned the check off, and a PDP's DENY was granted.
 */
class ProcessorConfigurationTest {

    private static final String PDP_URL = "https://pdp.example/governance-engine";

    /**
     * Every checkbox, by the name PingFederate stores it under, with what it turns into. The names are pinned
     * on purpose: renaming a field orphans the value every existing instance has stored under the old name.
     */
    private static final Map<String, Predicate<GovernanceEngineConfig>> SWITCHES = Map.of(
            "Prefix Attributes with Type", GovernanceEngineConfig::isPrefixAttributesWithType,
            "Deny unless PERMIT", GovernanceEngineConfig::isDenyOnNonPermit,
            "Fail open on engine error", GovernanceEngineConfig::isFailOpenOnError,
            "Trust a client-asserted principal", GovernanceEngineConfig::isAllowClientAssertedPrincipal,
            "Trust the PAR-carried agent marker", GovernanceEngineConfig::isTrustAgentMarker,
            "Skip TLS verification (dev only)", GovernanceEngineConfig::isInsecureTls);

    /** A stored configuration holding exactly these fields, as name, value pairs. */
    private static Configuration stored(String... namesAndValues) {
        Configuration configuration = new Configuration();
        for (int i = 0; i + 1 < namesAndValues.length; i += 2) {
            configuration.addField(new Field(namesAndValues[i], namesAndValues[i + 1]));
        }
        return configuration;
    }

    @Test
    void aConfigurationWithoutTheSwitchesReadsAsTheSecureDefaults() {
        GovernanceEngineConfig settings = AttestationAwareRarProcessor.settings(stored("PDP URL", PDP_URL));

        assertTrue(settings.isDenyOnNonPermit(), "a missing field must not turn deny-unless-PERMIT off");
        assertFalse(settings.isFailOpenOnError(), "nor turn fail-open on");
        assertFalse(settings.isAllowClientAssertedPrincipal(), "nor let the caller name the principal");
        assertFalse(settings.isTrustAgentMarker(), "nor trust the PAR-carried agent marker");
        assertFalse(settings.isInsecureTls(), "nor skip TLS verification");
        assertTrue(settings.isPrefixAttributesWithType(), "and the PDP attributes keep their usual names");
    }

    /** The defaults fill a gap; they never override what an operator stored. Every switch here is stored flipped. */
    @Test
    void whatIsStoredIsWhatIsRead() {
        GovernanceEngineConfig defaults = AttestationAwareRarProcessor.settings(stored("PDP URL", PDP_URL));
        Configuration configuration = stored("PDP URL", PDP_URL, "PDP Domain Prefix", "bank.rar", "PDP Service", "Payments",
                "PDP Action", "decide", "Attribute Prefix", "x", "Shared Secret Header", "X-PDP-KEY", "Shared Secret", "s3cret",
                "Request timeout (ms)", "2500");
        SWITCHES.forEach((name, read) -> configuration.addField(new Field(name, Boolean.toString(!read.test(defaults)))));

        GovernanceEngineConfig settings = AttestationAwareRarProcessor.settings(configuration);

        SWITCHES.forEach((name, read) -> assertEquals(!read.test(defaults), read.test(settings), name));
        assertEquals(PDP_URL, settings.getPdpUrl());
        assertEquals("bank.rar", settings.getDomainPrefix());
        assertEquals("Payments", settings.getService());
        assertEquals("decide", settings.getAction());
        assertEquals("x", settings.getAttributePrefix());
        assertEquals("X-PDP-KEY", settings.getSecretHeader());
        assertEquals("s3cret", settings.getSecret());
        assertEquals(2500, settings.getTimeoutMillis());
    }

    /**
     * What a missing field reads as is what the admin console offers, for every checkbox - so an instance
     * that never stored a switch behaves as one created with the defaults on screen, and a child instance,
     * whose gaps PingFederate fills from those same defaults, reads the same.
     */
    @Test
    void everyCheckboxDefaultsToWhatAMissingFieldReadsAs() {
        GovernanceEngineConfig missing = AttestationAwareRarProcessor.settings(stored("PDP URL", PDP_URL));
        List<FieldDescriptor> checkboxes = new AttestationAwareRarProcessor().getPluginDescriptor()
                .getGuiConfigDescriptor().getFields().stream().filter(CheckBoxFieldDescriptor.class::isInstance).toList();

        assertEquals(SWITCHES.keySet(), checkboxes.stream().map(FieldDescriptor::getName).collect(toSet()),
                "a checkbox this test does not know would have no default checked");
        for (FieldDescriptor checkbox : checkboxes) {
            assertEquals(Boolean.parseBoolean(checkbox.getDefaultValue()), SWITCHES.get(checkbox.getName()).test(missing),
                    checkbox.getName());
        }
    }

    /** Through configure and enrich, as PingFederate calls them: a PDP's DENY is refused with the field missing. */
    @Test
    void aProcessorConfiguredWithoutTheSwitchStillRefusesADeny() throws Exception {
        HttpServer pdp = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        pdp.createContext("/decide", exchange -> {
            byte[] body = "{\"decision\":\"DENY\",\"authorised\":false}".getBytes(UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, body.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(body);
            }
        });
        pdp.start();
        try {
            String url = "http://127.0.0.1:" + pdp.getAddress().getPort() + "/decide";
            AttestationAwareRarProcessor unset = new AttestationAwareRarProcessor();
            unset.configure(stored("PDP URL", url));
            AuthorizationDetailProcessingException denied = assertThrows(AuthorizationDetailProcessingException.class,
                    () -> unset.enrich(payment(), context(), Map.of()));
            assertTrue(denied.getMessage().contains("DENY"), denied.getMessage());

            AttestationAwareRarProcessor switchedOff = new AttestationAwareRarProcessor();
            switchedOff.configure(stored("PDP URL", url, "Deny unless PERMIT", "false"));
            assertEquals("42.00", switchedOff.enrich(payment(), context(), Map.of()).getDetail().get("amount"),
                    "an operator who stored the switch off still gets what they stored");
        } finally {
            pdp.stop(0);
        }
    }

    @Test
    void theVersionIsTheJarsOrPlainlyADevelopmentBuild() {
        assertEquals("0.3.0", AttestationAwareRarProcessor.versionOf("0.3.0"));
        assertEquals("0.3.0", AttestationAwareRarProcessor.versionOf(" 0.3.0 "));
        assertEquals("development", AttestationAwareRarProcessor.versionOf(null));
        assertEquals("development", AttestationAwareRarProcessor.versionOf("  "));
        // Loaded from target/classes, as here, there is no manifest to read: the descriptor says so rather than
        // carrying a number nobody built.
        assertEquals(AttestationAwareRarProcessor.DEVELOPMENT_VERSION,
                new AttestationAwareRarProcessor().getPluginDescriptor().getVersion());
    }

    private static AuthorizationDetail payment() {
        Map<String, Object> detail = new HashMap<>();
        detail.put("type", "payment_initiation");
        detail.put("amount", "42.00");
        detail.put("currency", "AUD");
        return new AuthorizationDetail(detail);
    }

    private static AuthorizationDetailContext context() {
        return new AuthorizationDetailContext.Builder().withClientId("agent-client").build();
    }
}
