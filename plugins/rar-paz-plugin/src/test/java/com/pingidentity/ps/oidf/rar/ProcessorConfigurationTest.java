package com.pingidentity.ps.oidf.rar;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.stream.Collectors.toSet;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
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
import java.util.Set;
import java.util.function.Predicate;
import org.junit.jupiter.api.Test;
import org.sourceid.saml20.adapter.conf.Configuration;
import org.sourceid.saml20.adapter.conf.Field;
import org.sourceid.saml20.adapter.gui.CheckBoxFieldDescriptor;
import org.sourceid.saml20.adapter.gui.FieldDescriptor;
import org.sourceid.saml20.adapter.gui.TextFieldDescriptor;
import org.sourceid.saml20.adapter.gui.validation.ValidationException;

/**
 * What an instance's stored configuration turns into, the descriptor PingFederate shows, and the version.
 *
 * <p>A field can be missing from a stored configuration: the instance was saved before the field existed, or
 * the admin API or an archive left it out. PingFederate 13.1.3 hands an instance with no parent its stored
 * configuration as it is, and fills a child instance's gaps from the descriptor's defaults. The switches used
 * to be read with the one-argument {@code getBooleanFieldValue}, which reads a missing field as false. A missing
 * "Deny unless PERMIT" therefore turned the check off, and a PDP's DENY was granted; from 0.4.0 that switch is
 * gone and a stored value under its name is never read.
 */
class ProcessorConfigurationTest {

    private static final String PDP_URL = "https://pdp.example/governance-engine";

    /**
     * Every checkbox, by the name PingFederate stores it under, with what it turns into. The names are pinned
     * on purpose: renaming a field orphans the value every existing instance has stored under the old name.
     */
    private static final Map<String, Predicate<GovernanceEngineConfig>> SWITCHES = Map.of(
            "Prefix Attributes with Type", GovernanceEngineConfig::isPrefixAttributesWithType,
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

    private static GovernanceEngineConfig production(Configuration configuration) {
        return AttestationAwareRarProcessor.settings(configuration, GovernanceEngineConfig.PROFILE_PRODUCTION);
    }

    @Test
    void aConfigurationWithoutTheSwitchesReadsAsTheSecureDefaults() {
        GovernanceEngineConfig settings = production(stored("PDP URL", PDP_URL));

        assertFalse(settings.isFailOpenOnError(), "a missing field must not turn fail-open on");
        assertFalse(settings.isAllowClientAssertedPrincipal(), "nor let the caller name the principal");
        assertFalse(settings.isTrustAgentMarker(), "nor trust the PAR-carried agent marker");
        assertFalse(settings.isInsecureTls(), "nor skip TLS verification");
        assertTrue(settings.isPrefixAttributesWithType(), "and the PDP attributes keep their usual names");
        assertEquals(GovernanceEngineConfig.DEFAULT_AUTHENTICATED_PRINCIPAL_TYPES, settings.getAuthenticatedPrincipalTypes(),
                "and payments and account queries need a person");
        assertEquals("production", settings.getDeploymentProfile());
    }

    /** The defaults fill a gap; they never override what an operator stored. Every switch here is stored flipped. */
    @Test
    void whatIsStoredIsWhatIsRead() {
        GovernanceEngineConfig defaults = production(stored("PDP URL", PDP_URL));
        Configuration configuration = stored("PDP URL", PDP_URL, "PDP Domain Prefix", "bank.rar", "PDP Service", "Payments",
                "PDP Action", "decide", "Attribute Prefix", "x", "Shared Secret Header", "X-PDP-KEY", "Shared Secret", "s3cret",
                "Request timeout (ms)", "2500", "Types requiring an authenticated principal", "payment_initiation, transfer");
        SWITCHES.forEach((name, read) -> configuration.addField(new Field(name, Boolean.toString(!read.test(defaults)))));

        GovernanceEngineConfig settings = production(configuration);

        SWITCHES.forEach((name, read) -> assertEquals(!read.test(defaults), read.test(settings), name));
        assertEquals(PDP_URL, settings.getPdpUrl());
        assertEquals("bank.rar", settings.getDomainPrefix());
        assertEquals("Payments", settings.getService());
        assertEquals("decide", settings.getAction());
        assertEquals("x", settings.getAttributePrefix());
        assertEquals("X-PDP-KEY", settings.getSecretHeader());
        assertEquals("s3cret", settings.getSecret());
        assertEquals(2500, settings.getTimeoutMillis());
        assertEquals(Set.of("payment_initiation", "transfer"), settings.getAuthenticatedPrincipalTypes());
    }

    /**
     * What a missing field reads as is what the admin console offers, for every checkbox - so an instance
     * that never stored a switch behaves as one created with the defaults on screen, and a child instance,
     * whose gaps PingFederate fills from those same defaults, reads the same.
     */
    @Test
    void everyCheckboxDefaultsToWhatAMissingFieldReadsAs() {
        GovernanceEngineConfig missing = production(stored("PDP URL", PDP_URL));
        List<FieldDescriptor> checkboxes = new AttestationAwareRarProcessor().getPluginDescriptor()
                .getGuiConfigDescriptor().getFields().stream().filter(CheckBoxFieldDescriptor.class::isInstance).toList();

        assertEquals(SWITCHES.keySet(), checkboxes.stream().map(FieldDescriptor::getName).collect(toSet()),
                "a checkbox this test does not know would have no default checked");
        for (FieldDescriptor checkbox : checkboxes) {
            assertEquals(Boolean.parseBoolean(checkbox.getDefaultValue()), SWITCHES.get(checkbox.getName()).test(missing),
                    checkbox.getName());
        }
    }

    /** The switch that turned deny-unless-PERMIT off is gone from the descriptor, and a stored value under its name is not read. */
    @Test
    void theDenySwitchIsGoneAndAStoredValueIsIgnored() throws Exception {
        List<FieldDescriptor> fields = new AttestationAwareRarProcessor().getPluginDescriptor().getGuiConfigDescriptor().getFields();
        assertTrue(fields.stream().noneMatch(f -> f.getName().equals(AttestationAwareRarProcessor.DENY_ON_NON_PERMIT_REMOVED)));

        HttpServer pdp = denyingPdp();
        try {
            AttestationAwareRarProcessor switchedOff = new AttestationAwareRarProcessor();
            switchedOff.configure(stored("PDP URL", url(pdp), "Shared Secret", "s",
                    AttestationAwareRarProcessor.DENY_ON_NON_PERMIT_REMOVED, "false"), "development");
            AuthorizationDetailProcessingException denied = assertThrows(AuthorizationDetailProcessingException.class,
                    () -> switchedOff.enrich(payment(), context(), Map.of()));
            assertTrue(denied.getMessage().contains("DENY"), denied.getMessage());
        } finally {
            pdp.stop(0);
        }
    }

    /** Through configure and enrich, as PingFederate calls them: a PDP's DENY is refused with every switch missing. */
    @Test
    void aProcessorConfiguredWithoutTheSwitchesStillRefusesADeny() throws Exception {
        HttpServer pdp = denyingPdp();
        try {
            AttestationAwareRarProcessor unset = new AttestationAwareRarProcessor();
            unset.configure(stored("PDP URL", url(pdp)), "development");
            AuthorizationDetailProcessingException denied = assertThrows(AuthorizationDetailProcessingException.class,
                    () -> unset.enrich(payment(), context(), Map.of()));
            assertTrue(denied.getMessage().contains("DENY"), denied.getMessage());
        } finally {
            pdp.stop(0);
        }
    }

    /** The AuthZEN dialect through configure as well, with the client-asserted switch on outside development (a warning, no effect). */
    @Test
    void theAuthZenDialectIsChosenByTheField() throws Exception {
        HttpServer pdp = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        pdp.createContext("/access/v1/evaluation", exchange -> {
            byte[] body = "{\"decision\":true}".getBytes(UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, body.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(body);
            }
        });
        pdp.start();
        try {
            AttestationAwareRarProcessor authzen = new AttestationAwareRarProcessor();
            // http, so development; the client-asserted switch is exercised through the warning branch below.
            authzen.configure(stored("PDP URL", "http://127.0.0.1:" + pdp.getAddress().getPort() + "/access/v1/evaluation",
                    "PDP Dialect", " AuthZEN ", "Trust a client-asserted principal", "true"), "development");
            assertEquals("42.00", authzen.enrich(payment(), context(), Map.of()).getDetail().get("amount"));
        } finally {
            pdp.stop(0);
        }
        AttestationAwareRarProcessor warned = new AttestationAwareRarProcessor();
        warned.configure(stored("PDP URL", PDP_URL, "Trust a client-asserted principal", "true"), "production");
    }

    // ---- the PDP URL: https, or development ------------------------------------------------------------

    @Test
    void aPlaintextPdpUrlIsRefusedOutsideDevelopment() {
        IllegalStateException e = assertThrows(IllegalStateException.class,
                () -> production(stored("PDP URL", "http://pdp.internal/decide")));
        assertTrue(e.getMessage().contains("OIDF_DEPLOYMENT_PROFILE=development"), e.getMessage());
        assertEquals("http://pdp.internal/decide", AttestationAwareRarProcessor.settings(
                stored("PDP URL", " http://pdp.internal/decide "), "development").getPdpUrl());
    }

    /**
     * An archive import runs no field validator, so a plaintext URL outside development stops configure; the
     * instance left behind refuses every request as a processing failure rather than throwing a NullPointerException.
     */
    @Test
    void anInstanceThatDidNotConfigureRefusesEveryRequest() {
        AttestationAwareRarProcessor unconfigured = new AttestationAwareRarProcessor();
        assertThrows(IllegalStateException.class,
                () -> unconfigured.configure(stored("PDP URL", "http://pdp.internal/decide"), "production"));
        AuthorizationDetailProcessingException e = assertThrows(AuthorizationDetailProcessingException.class,
                () -> unconfigured.enrich(payment(), context(), Map.of()));
        assertTrue(e.getMessage().contains("not configured"), e.getMessage());
        // Settings read but no PDP client built: the same refusal.
        AttestationAwareRarProcessor noClient = new AttestationAwareRarProcessor(null, production(stored("PDP URL", PDP_URL)));
        assertThrows(AuthorizationDetailProcessingException.class, () -> noClient.enrich(payment(), context(), Map.of()));
    }

    /** The same rule sits on the field, so the admin console and the admin API say so before anything is stored. */
    @Test
    void thePdpUrlFieldCarriesTheHttpsValidator() {
        FieldDescriptor url = field("PDP URL");
        boolean refused = false;
        for (FieldDescriptor.FieldValidationWrapper v : url.getValidationChain()) {
            try {
                v.getValidator().validate(new Field("PDP URL", "http://pdp.internal/decide"));
            } catch (ValidationException e) {
                refused |= e.getMessage().contains("https");
            }
        }
        // Under a development profile the validator would pass; the test JVM is production (the variable is unset).
        assertEquals(!GovernanceEngineConfig.PROFILE_DEVELOPMENT.equals(AttestationAwareRarProcessor.deploymentProfile()), refused);
    }

    // ---- the secret ------------------------------------------------------------------------------------

    /** Same field name as every stored instance uses, now declared encrypted: the archive holds it obfuscated. */
    @Test
    void theSharedSecretIsAnEncryptedFieldUnderTheSameName() {
        FieldDescriptor secret = field(AttestationAwareRarProcessor.PDP_SECRET);
        assertInstanceOf(TextFieldDescriptor.class, secret);
        assertTrue(((TextFieldDescriptor) secret).isEncrypted());
        assertEquals("Shared Secret", secret.getName());
        assertFalse(((TextFieldDescriptor) field("PDP URL")).isEncrypted(), "and nothing else is");
    }

    @Test
    void theTypeListFieldDefaultsToPaymentsAndAccounts() {
        assertEquals("payment_initiation,account_information", field(AttestationAwareRarProcessor.AUTHENTICATED_PRINCIPAL_TYPES).getDefaultValue());
        assertNotNull(field("Fail open on engine error"));
        assertNull(fieldOrNull("Deny unless PERMIT"));
    }

    // ---- the config's own parsing ----------------------------------------------------------------------

    @Test
    void theProfileIsDevelopmentOrProduction() {
        assertEquals("development", GovernanceEngineConfig.profileOf("development"));
        assertEquals("development", GovernanceEngineConfig.profileOf(" DEVELOPMENT "));
        assertEquals("production", GovernanceEngineConfig.profileOf("production"));
        assertEquals("production", GovernanceEngineConfig.profileOf("staging"));
        assertEquals("production", GovernanceEngineConfig.profileOf(null));
        assertEquals("production", GovernanceEngineConfig.profileOf(""));
    }

    @Test
    void theTypeListIsParsedAndADashMeansNone() {
        assertEquals(GovernanceEngineConfig.DEFAULT_AUTHENTICATED_PRINCIPAL_TYPES, GovernanceEngineConfig.authenticatedPrincipalTypesOf(null));
        assertEquals(GovernanceEngineConfig.DEFAULT_AUTHENTICATED_PRINCIPAL_TYPES, GovernanceEngineConfig.authenticatedPrincipalTypesOf("  "));
        assertEquals(Set.of("a", "b", "c"), GovernanceEngineConfig.authenticatedPrincipalTypesOf("a, b\n c,"));
        assertEquals(Set.of(), GovernanceEngineConfig.authenticatedPrincipalTypesOf("-"));
        assertEquals(Set.of("a"), GovernanceEngineConfig.authenticatedPrincipalTypesOf("-, a"));
        assertEquals(Set.of("a"), GovernanceEngineConfig.authenticatedPrincipalTypesOf(",a"));
    }

    @Test
    void theClientAssertedSwitchNeedsTheProfile() {
        assertTrue(GovernanceEngineConfig.builder().pdpUrl(PDP_URL).allowClientAssertedPrincipal(true)
                .deploymentProfile("development").build().isClientAssertedPrincipalHonoured());
        assertFalse(GovernanceEngineConfig.builder().pdpUrl(PDP_URL).allowClientAssertedPrincipal(true)
                .deploymentProfile("production").build().isClientAssertedPrincipalHonoured());
        assertFalse(GovernanceEngineConfig.builder().pdpUrl(PDP_URL).allowClientAssertedPrincipal(false)
                .deploymentProfile("development").build().isClientAssertedPrincipalHonoured());
        assertThrows(IllegalStateException.class, () -> GovernanceEngineConfig.builder().build());
    }

    /** https to a PDP whose certificate nobody checks is https in name only, so the switch needs the profile too. */
    @Test
    void theInsecureTlsSwitchNeedsTheProfile() {
        assertTrue(GovernanceEngineConfig.builder().pdpUrl(PDP_URL).insecureTls(true)
                .deploymentProfile("development").build().isInsecureTlsHonoured());
        assertFalse(GovernanceEngineConfig.builder().pdpUrl(PDP_URL).insecureTls(true)
                .deploymentProfile("production").build().isInsecureTlsHonoured());
        assertFalse(GovernanceEngineConfig.builder().pdpUrl(PDP_URL).insecureTls(false)
                .deploymentProfile("development").build().isInsecureTlsHonoured());
        assertTrue(production(stored("PDP URL", PDP_URL, "Skip TLS verification (dev only)", "true")).isInsecureTls(),
                "the stored value is still read; it is what it may do that the profile decides");
    }

    /** What configure builds, not only what the settings say: the trust-all context exists only in development. */
    @Test
    void configureTrustsAnyCertificateOnlyInDevelopment() {
        AttestationAwareRarProcessor production = new AttestationAwareRarProcessor();
        production.configure(stored("PDP URL", PDP_URL, "Skip TLS verification (dev only)", "true"), "production");
        assertEquals(PdpTls.JVM_DEFAULT, production.pdpTransport().tls().mode(), "production checks the certificate");

        AttestationAwareRarProcessor development = new AttestationAwareRarProcessor();
        development.configure(stored("PDP URL", PDP_URL, "Skip TLS verification (dev only)", "true"), "development");
        assertEquals("insecure", development.pdpTransport().tls().mode(), "development may skip it");

        AttestationAwareRarProcessor off = new AttestationAwareRarProcessor();
        off.configure(stored("PDP URL", PDP_URL), "development");
        assertEquals(PdpTls.JVM_DEFAULT, off.pdpTransport().tls().mode(), "the switch is off unless set");
        assertNull(new AttestationAwareRarProcessor().transport(), "nothing is built before configure");
        assertNull(new AttestationAwareRarProcessor().pdpTransport(), "nothing is built before configure");
    }

    /**
     * Through configure, enrich and the real transport, with fail-open on: a PDP whose DENY carries a header named
     * "connection reset", and one whose status line names it, answered - neither is granted (F-0093).
     */
    @Test
    void failOpenDoesNotGrantAMalformedAnswerThatNamesAReset() throws Exception {
        String deny = "{\"decision\": false}";
        try (RawHttpServer pdp = new RawHttpServer("HTTP/1.1 200 OK\r\nconnection reset: x\r\n"
                + "Content-Type: application/json\r\nContent-Length: " + deny.length() + "\r\n\r\n" + deny)) {
            AttestationAwareRarProcessor authzen = new AttestationAwareRarProcessor();
            authzen.configure(stored("PDP URL", pdp.url("/access/v1/evaluation"), "PDP Dialect", "AuthZEN",
                    "Fail open on engine error", "true"), "development");
            assertThrows(AuthorizationDetailProcessingException.class, () -> authzen.enrich(payment(), context(), Map.of()));
        }
        try (RawHttpServer pdp = new RawHttpServer("HTTP/1.1 2x0 connection reset\r\n"
                + "Content-Type: application/json\r\nContent-Length: 2\r\n\r\n{}")) {
            AttestationAwareRarProcessor governance = new AttestationAwareRarProcessor();
            governance.configure(stored("PDP URL", pdp.url("/decide"), "Fail open on engine error", "true"), "development");
            assertThrows(AuthorizationDetailProcessingException.class, () -> governance.enrich(payment(), context(), Map.of()));
        }
    }

    /** Each development-only switch left on in production is named at configure, once, at WARNING. */
    @Test
    void configureSaysWhichSwitchesItIgnores() {
        java.util.List<java.util.logging.LogRecord> records = new java.util.ArrayList<>();
        java.util.logging.Handler capture = new java.util.logging.Handler() {
            @Override public void publish(java.util.logging.LogRecord record) { records.add(record); }
            @Override public void flush() { }
            @Override public void close() { }
        };
        java.util.logging.Logger log = java.util.logging.Logger.getLogger(AttestationAwareRarProcessor.class.getName());
        log.addHandler(capture);
        try {
            new AttestationAwareRarProcessor().configure(stored("PDP URL", PDP_URL,
                    "Trust a client-asserted principal", "true", "Skip TLS verification (dev only)", "true"), "production");
            new AttestationAwareRarProcessor().configure(stored("PDP URL", PDP_URL,
                    "Trust a client-asserted principal", "true", "Skip TLS verification (dev only)", "true"), "development");
        } finally {
            log.removeHandler(capture);
        }
        List<String> warnings = records.stream().filter(r -> r.getLevel() == java.util.logging.Level.WARNING)
                .map(java.util.logging.LogRecord::getMessage).toList();
        assertEquals(2, warnings.size(), warnings.toString());
        assertTrue(warnings.get(0).contains("Trust a client-asserted principal"), warnings.get(0));
        assertTrue(warnings.get(1).contains("Skip TLS verification") && warnings.get(1).contains("certificate is checked"),
                warnings.get(1));
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

    private static FieldDescriptor field(String name) {
        FieldDescriptor field = fieldOrNull(name);
        assertNotNull(field, name);
        return field;
    }

    private static FieldDescriptor fieldOrNull(String name) {
        return new AttestationAwareRarProcessor().getPluginDescriptor().getGuiConfigDescriptor().getFields().stream()
                .filter(f -> f.getName().equals(name)).findFirst().orElse(null);
    }

    private static HttpServer denyingPdp() throws Exception {
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
        return pdp;
    }

    private static String url(HttpServer pdp) {
        return "http://127.0.0.1:" + pdp.getAddress().getPort() + "/decide";
    }

    private static AuthorizationDetail payment() {
        Map<String, Object> detail = new HashMap<>();
        detail.put("type", "payment_initiation");
        detail.put("amount", "42.00");
        detail.put("currency", "AUD");
        return new AuthorizationDetail(detail);
    }

    private static AuthorizationDetailContext context() {
        return new AuthorizationDetailContext.Builder().withClientId("agent-client").withUserKey("alice").build();
    }
}
