package com.pingidentity.ps.oidf.rar;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.pingidentity.sdk.authorizationdetails.AuthorizationDetail;
import com.pingidentity.sdk.authorizationdetails.AuthorizationDetailContext;
import com.pingidentity.sdk.authorizationdetails.AuthorizationDetailProcessingException;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.Test;
import org.sourceid.saml20.adapter.conf.Configuration;
import org.sourceid.saml20.adapter.conf.Field;
import org.sourceid.saml20.adapter.gui.FieldDescriptor;
import org.sourceid.saml20.adapter.gui.SelectFieldDescriptor;
import org.sourceid.saml20.adapter.gui.TextAreaFieldDescriptor;
import org.sourceid.saml20.adapter.gui.validation.ConfigurationValidator;
import org.sourceid.saml20.adapter.gui.validation.ValidationException;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

/**
 * The 0.6.0 fields through the processor: configure builds what they say and refuses what they may not say, and
 * {@code enrich} asks the PDP once per distinct question in a request - one Access Evaluations call for all of a
 * request's details when a batch URL is set.
 */
class ProcessorResilienceTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private static Configuration stored(String... namesAndValues) {
        Configuration configuration = new Configuration();
        for (int i = 0; i + 1 < namesAndValues.length; i += 2) {
            configuration.addField(new Field(namesAndValues[i], namesAndValues[i + 1]));
        }
        return configuration;
    }

    private static AuthorizationDetail sales(String region) {
        Map<String, Object> detail = new HashMap<>();
        detail.put("type", "sales_agent");
        detail.put("sales_regions", List.of(region));
        return new AuthorizationDetail(detail);
    }

    private static AuthorizationDetailContext context(HttpServletRequest request) {
        return new AuthorizationDetailContext.Builder().withRequest(request).withClientId("agent-client")
                .withUserKey("alice").build();
    }

    private static String sent(String... regions) {
        StringBuilder json = new StringBuilder("[");
        for (int i = 0; i < regions.length; i++) {
            json.append(i == 0 ? "" : ",").append("{\"type\":\"sales_agent\",\"sales_regions\":[\"").append(regions[i]).append("\"]}");
        }
        return json.append("]").toString();
    }

    @Test
    void configureBuildsTheTransportTheFieldsDescribe() throws Exception {
        StubPdp.Ca ca = StubPdp.Ca.get();
        AttestationAwareRarProcessor pinned = new AttestationAwareRarProcessor();
        pinned.configure(stored("PDP URL", "https://pdp.example/access/v1/evaluation", "PDP Dialect", "authzen",
                "PDP TLS trust", "pinned-ca", "PDP CA certificates (PEM)", ca.caPem,
                "AuthZEN batch URL", "https://pdp.example/access/v1/evaluations", "Decision cache types", "sales_agent",
                "Decision cache TTL (s)", "45", "Circuit breaker failures", "3", "Circuit breaker open (s)", "12",
                "Request timeout (ms)", "4000"), "production");
        assertEquals(PdpTls.PINNED_CA, pinned.pdpTransport().tls().mode());
        assertEquals(4_000, pinned.pdpTransport().total().toMillis());
        assertEquals(3, pinned.breaker().threshold());
        assertEquals(java.util.concurrent.TimeUnit.SECONDS.toNanos(12), pinned.breaker().openNanos());
        assertTrue(((AuthZenPdpClient) pinned.decisions().client()).batches());
        assertEquals(Set.of("sales_agent"), pinned.decisions().cache().types());
        assertEquals(java.util.concurrent.TimeUnit.SECONDS.toNanos(45), pinned.decisions().cache().ttlNanos());

        AttestationAwareRarProcessor pingFederate = new AttestationAwareRarProcessor();
        pingFederate.configure(stored("PDP URL", "https://pdp.example/decide", "PDP TLS trust", "pingfederate-trusted-cas",
                "Request timeout (ms)", "60000"), "production");
        assertEquals(PdpTls.PINGFEDERATE_TRUSTED_CAS, pingFederate.pdpTransport().tls().mode(),
                "PingFederate's CAs are not read at configure, so no PingFederate service is needed here");
        assertEquals(10_000, pingFederate.pdpTransport().total().toMillis(), "held to ten seconds");
        assertNull(pingFederate.decisions().cache(), "no cache types, no cache");
        assertInstanceOf(GovernanceEngineClient.class, pingFederate.decisions().client());
        assertEquals(CircuitBreaker.DEFAULT_THRESHOLD, pingFederate.breaker().threshold());

        AttestationAwareRarProcessor defaults = new AttestationAwareRarProcessor();
        defaults.configure(stored("PDP URL", "https://pdp.example/decide"), "production");
        assertEquals(PdpTls.JVM_DEFAULT, defaults.pdpTransport().tls().mode());
        assertEquals(2_500, defaults.pdpTransport().total().toMillis(), "a stored configuration without the field is 2.5 s");
    }

    @Test
    void configureRefusesWhatTheFieldsMayNotSay() {
        String url = "https://pdp.example/access/v1/evaluation";
        for (String[] bad : List.of(
                new String[] {"PDP TLS trust", "trust-everything"},
                new String[] {"PDP TLS trust", "pinned-ca"},
                new String[] {"PDP TLS trust", "pinned-ca", "PDP CA certificates (PEM)", "not a certificate"},
                new String[] {"Decision cache types", "payment_initiation"},
                new String[] {"Decision cache types", "sales_agent, account_information"},
                new String[] {"Decision cache types", "transfer", "Types requiring an authenticated principal", "transfer"},
                new String[] {"Decision cache TTL (s)", "61"},
                new String[] {"Decision cache TTL (s)", "soon"},
                new String[] {"Circuit breaker failures", "0"},
                new String[] {"Circuit breaker open (s)", "3601"},
                new String[] {"AuthZEN batch URL", "http://pdp.example/access/v1/evaluations"},
                new String[] {"PDP Dialect", "governance-engine", "AuthZEN batch URL", "https://pdp.example/access/v1/evaluations"})) {
            String[] fields = new String[bad.length + 4];
            fields[0] = "PDP URL";
            fields[1] = url;
            fields[2] = "PDP Dialect";
            fields[3] = "authzen";
            System.arraycopy(bad, 0, fields, 4, bad.length);
            AttestationAwareRarProcessor processor = new AttestationAwareRarProcessor();
            IllegalStateException e = assertThrows(IllegalStateException.class,
                    () -> processor.configure(stored(fields), "production"), String.join(" ", bad));
            assertNotNull(e.getMessage());
            assertThrows(AuthorizationDetailProcessingException.class,
                    () -> processor.enrich(sales("EMEA"), context(null), Map.of()),
                    "an instance configure refused refuses every request: " + String.join(" ", bad));
        }
        // Development may send the batch over http, as it may the PDP URL.
        assertDoesNotThrow(() -> new AttestationAwareRarProcessor().configure(stored("PDP URL", "http://pdp:1080/access/v1/evaluation",
                "PDP Dialect", "authzen", "AuthZEN batch URL", "http://pdp:1080/access/v1/evaluations"), "development"));
        // A principal-types field of '-' frees account_information for the cache; payment_initiation never.
        assertDoesNotThrow(() -> new AttestationAwareRarProcessor().configure(stored("PDP URL", url,
                "Types requiring an authenticated principal", "-", "Decision cache types", "account_information"), "production"));
    }

    @Test
    void theAdminConsoleRefusesTheSameOnSave() throws Exception {
        AttestationAwareRarProcessor processor = new AttestationAwareRarProcessor();
        List<ConfigurationValidator> validators = processor.getPluginDescriptor().getGuiConfigDescriptor().getValidationChain();
        ConfigurationValidator validator = validators.stream().filter(v -> v instanceof PdpResilience.Validator).findFirst().orElseThrow();
        ValidationException payment = assertThrows(ValidationException.class, () -> validator.validate(stored(
                "PDP URL", "https://pdp.example/x", "Decision cache types", "payment_initiation")));
        assertTrue(payment.getMessage().contains("payment_initiation"), payment.getMessage());
        assertThrows(ValidationException.class, () -> validator.validate(stored("PDP URL", "https://pdp.example/x",
                "AuthZEN batch URL", "https://pdp.example/access/v1/evaluations")), "a batch URL needs the authzen dialect");
        validator.validate(stored("PDP URL", "https://pdp.example/x", "PDP Dialect", " AuthZEN ",
                "AuthZEN batch URL", "https://pdp.example/access/v1/evaluations", "Decision cache types", "sales_agent",
                "Decision cache TTL (s)", "60", "Circuit breaker failures", "1", "Circuit breaker open (s)", "1"));
        validator.validate(stored("PDP URL", "https://pdp.example/x"));

        Map<String, FieldDescriptor> fields = new HashMap<>();
        processor.getPluginDescriptor().getGuiConfigDescriptor().getFields().forEach(f -> fields.put(f.getName(), f));
        assertInstanceOf(SelectFieldDescriptor.class, fields.get("PDP TLS trust"));
        assertEquals("jvm-default", fields.get("PDP TLS trust").getDefaultValue());
        assertInstanceOf(TextAreaFieldDescriptor.class, fields.get("PDP CA certificates (PEM)"));
        assertEquals("2500", fields.get("Request timeout (ms)").getDefaultValue());
        assertEquals("", fields.get("Decision cache types").getDefaultValue());
        assertEquals("30", fields.get("Decision cache TTL (s)").getDefaultValue());
        assertEquals("5", fields.get("Circuit breaker failures").getDefaultValue());
        assertEquals("30", fields.get("Circuit breaker open (s)").getDefaultValue());
        assertEquals("", fields.get("AuthZEN batch URL").getDefaultValue());
    }

    /** PingFederate calls enrich once per detail; the same detail twice in a request is one PDP question. */
    @Test
    void repeatedEnrichOfOneRequestAsksThePdpOncePerDistinctDetail() throws Exception {
        try (StubPdp pdp = StubPdp.plain(StubPdp.json(200, "{\"decision\":true}"))) {
            AttestationAwareRarProcessor processor = new AttestationAwareRarProcessor();
            processor.configure(stored("PDP URL", pdp.url("/access/v1/evaluation"), "PDP Dialect", "authzen",
                    "Types requiring an authenticated principal", "-"), "development");
            HttpServletRequest request = PdpDecisionsTest.request(null);
            processor.enrich(sales("EMEA"), context(request), Map.of());
            processor.enrich(sales("EMEA"), context(request), Map.of());
            processor.enrich(sales("APAC"), context(request), Map.of());
            assertEquals(2, pdp.accepted.get(), "EMEA once, APAC once");
            assertInstanceOf(DecisionMemo.class, request.getAttribute(processor.memoAttribute()));
            processor.enrich(sales("EMEA"), context(PdpDecisionsTest.request(null)), Map.of());
            assertEquals(3, pdp.accepted.get(), "a new request asks again");
        }
    }

    /** The rig check in miniature: a token request carrying three details makes one Access Evaluations call. */
    @Test
    void aRequestWithThreeDetailsMakesOneBatchCall() throws Exception {
        try (StubPdp pdp = StubPdp.plain(StubPdp.json(200, "{\"evaluations\":[{\"decision\":true},{\"decision\":false},"
                + "{\"decision\":true}]}"))) {
            AttestationAwareRarProcessor processor = new AttestationAwareRarProcessor();
            processor.configure(stored("PDP URL", pdp.url("/access/v1/evaluation"), "PDP Dialect", "authzen",
                    "AuthZEN batch URL", pdp.url("/access/v1/evaluations"),
                    "Types requiring an authenticated principal", "-"), "development");
            HttpServletRequest request = PdpDecisionsTest.request(sent("EMEA", "AMER", "APAC")
                    .replace("]}]", "]}, {\"type\":\"other_processors_type\"}, 7, {\"type\":\"\"}, {\"no\":\"type\"}]"));
            when(request.getParameter("grant_type")).thenReturn("client_credentials");
            AuthorizationDetail emea = processor.enrich(sales("EMEA"), context(request), Map.of());
            assertEquals(List.of("EMEA"), emea.getDetail().get("sales_regions"));
            assertThrows(AuthorizationDetailProcessingException.class, () -> processor.enrich(sales("AMER"), context(request), Map.of()),
                    "the second evaluation's false denies the second detail");
            AuthorizationDetail apac = processor.enrich(sales("APAC"), context(request), Map.of());
            assertEquals(List.of("APAC"), apac.getDetail().get("sales_regions"));
            assertEquals(1, pdp.accepted.get(), "one call for three details");
            StubPdp.Recorded call = pdp.take();
            assertEquals("/access/v1/evaluations", call.path());
            JsonNode evaluations = MAPPER.readTree(call.body()).get("evaluations");
            assertEquals(3, evaluations.size(), "another processor's type and the malformed entries are not sent");
            assertEquals("AMER", evaluations.get(1).path("resource").path("properties").path("sales_regions").get(0).asText());
        }
    }

    @Test
    void theBatchCandidatesAreOnlyWhatEnrichWouldAsk() throws Exception {
        AttestationAwareRarProcessor processor = new AttestationAwareRarProcessor(
                (type, detail, subject, owner, client, source) -> new DecisionResponse("PERMIT", true, List.of(), "{}"),
                GovernanceEngineConfig.builder().pdpUrl("https://pdp").build());
        for (String param : new String[] {null, " ", "{not json", "{\"type\":\"sales_agent\"}"}) {
            assertEquals(List.of(), processor.batchCandidates(null, PdpDecisionsTest.request(param),
                    AttestationSubject.empty(), Map.of()), String.valueOf(param));
        }
        assertEquals(List.of(), processor.batchCandidates(null, null, AttestationSubject.empty(), Map.of()));
        HttpServletRequest broken = org.mockito.Mockito.mock(HttpServletRequest.class);
        when(broken.getParameter("authorization_details")).thenThrow(new IllegalStateException("recycled"));
        assertEquals(List.of(), processor.batchCandidates(null, broken, AttestationSubject.empty(), Map.of()));
        // A payment with no authenticated principal would be refused by enrich, so it is not a candidate either.
        List<PdpDecisions.Ask> asks = processor.batchCandidates(context(null), PdpDecisionsTest.request(
                "[{\"type\":\"payment_initiation\",\"amount\":\"1.00\",\"currency\":\"AUD\"},"
                        + "{\"type\":\"sales_agent\",\"sales_regions\":[\"EMEA\"],\"unknown\":1},"
                        + "{\"type\":\"sales_agent\",\"sales_regions\":[\"EMEA\"]}]"), AttestationSubject.empty(), Map.of());
        assertEquals(2, asks.size(), "the payment has an authenticated principal here; the undeclared field is refused");
        assertEquals("payment_initiation", asks.get(0).type());
        assertEquals("alice", asks.get(0).owner());
        List<PdpDecisions.Ask> noPerson = processor.batchCandidates(
                new AuthorizationDetailContext.Builder().withClientId("agent-client").withUserKey("agent-client").build(),
                PdpDecisionsTest.request("[{\"type\":\"payment_initiation\",\"amount\":\"1.00\",\"currency\":\"AUD\"}]"),
                AttestationSubject.empty(), Map.of());
        assertEquals(List.of(), noPerson);
    }

    @Test
    void aPinnedFieldThatCannotBeBuiltStopsConfigure() {
        GovernanceEngineConfig settings = GovernanceEngineConfig.builder().pdpUrl("https://pdp").build();
        IllegalStateException e = assertThrows(IllegalStateException.class, () -> AttestationAwareRarProcessor.tlsOf(settings,
                new PdpResilience(PdpTls.PINNED_CA, "junk", null, Set.of(), 30, 5, 30)));
        assertTrue(e.getMessage().contains("PDP CA certificates (PEM)"), e.getMessage());
    }

    @Test
    void theTestSeamTakesAPdpStepOfItsOwn() {
        PdpDecisions decisions = new PdpDecisions((t, d, s, o, c, p) -> null, null, null, "m");
        AttestationAwareRarProcessor processor = new AttestationAwareRarProcessor(decisions,
                GovernanceEngineConfig.builder().pdpUrl("https://pdp").build(), ModelGate.of(
                        com.pingidentity.ps.oidf.rar.model.RarModels.builtIn()));
        assertSame(decisions, processor.decisions());
        assertNull(processor.breaker());
        assertFalse(processor.memoAttribute().isEmpty());
    }
}
