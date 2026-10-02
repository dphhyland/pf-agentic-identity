package com.pingidentity.ps.oidf.rar;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.pingidentity.ps.oidf.conformance.Requirement;
import com.pingidentity.ps.oidf.rar.model.RarModels;
import com.pingidentity.sdk.authorizationdetails.AuthorizationDetail;
import com.pingidentity.sdk.authorizationdetails.AuthorizationDetailContext;
import com.pingidentity.sdk.authorizationdetails.AuthorizationDetailValidationResult;
import jakarta.servlet.http.HttpServletRequest;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.logging.Handler;
import java.util.logging.LogRecord;
import java.util.logging.Logger;
import org.junit.jupiter.api.Test;
import org.sourceid.saml20.adapter.conf.Configuration;
import org.sourceid.saml20.adapter.conf.Field;
import org.sourceid.saml20.adapter.gui.FieldDescriptor;
import org.sourceid.saml20.adapter.gui.validation.ConfigurationValidator;
import org.sourceid.saml20.adapter.gui.validation.ValidationException;

/**
 * {@link AttestationAwareRarProcessor#validate}: the shape check PingFederate asks where a detail arrives (PAR, the
 * authorization endpoint, CIBA, device, token exchange, the token endpoint), and the JWT-bearer rule (F-0108). No PDP
 * is ever asked here: every processor in this class has a client that must not be touched.
 */
class ValidateTest {

    private static final String JWT_BEARER = "urn:ietf:params:oauth:grant-type:jwt-bearer";
    /** A value no refusal may repeat. */
    private static final String SECRET = "value-4711-never-logged";

    private final PdpClient client = mock(PdpClient.class);

    private AttestationAwareRarProcessor processor(ModelGate gate) {
        return new AttestationAwareRarProcessor(client,
                GovernanceEngineConfig.builder().pdpUrl("https://pdp.example/x").build(), gate);
    }

    private AttestationAwareRarProcessor production() {
        return processor(ModelGate.of(RarModels.builtIn()));
    }

    @SafeVarargs
    private static AuthorizationDetail detail(String type, Map.Entry<String, Object>... fields) {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("type", type);
        for (Map.Entry<String, Object> field : fields) {
            map.put(field.getKey(), field.getValue());
        }
        return new AuthorizationDetail(map);
    }

    /** A context whose request says which endpoint and which grant, as PingFederate's does. */
    private static AuthorizationDetailContext at(String path, String grantType) {
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getRequestURI()).thenReturn(path);
        when(request.getParameter("grant_type")).thenReturn(grantType);
        return new AuthorizationDetailContext.Builder().withRequest(request).withClientId("agent-client").build();
    }

    private static AuthorizationDetailContext par() {
        return at("/as/par.oauth2", null);
    }

    private static AuthorizationDetailContext jwtBearer() {
        return at("/as/token.oauth2", JWT_BEARER);
    }

    private static String refusal(AuthorizationDetailValidationResult result) {
        assertFalse(result.isValid(), "should have been refused");
        assertNotNull(result.getReason());
        assertFalse(result.getReason().contains(SECRET), "a refusal never repeats a value: " + result.getReason());
        return result.getReason();
    }

    private static void valid(AuthorizationDetailValidationResult result) {
        assertTrue(result.isValid(), () -> "should have passed: " + result.getReason());
    }

    // ---- the model, where the detail arrives -----------------------------------------------------------

    @Test
    @Requirement("RFC9396 §5")
    void aConformingDetailOfEachBuiltInTypePasses() {
        AttestationAwareRarProcessor processor = production();
        valid(processor.validate(detail("payment_initiation", Map.entry("amount", "42.00"), Map.entry("currency", "AUD"),
                Map.entry("creditorName", "Acme")), par(), Map.of()));
        valid(processor.validate(detail("payment_initiation", Map.entry("instructedAmount",
                Map.of("amount", "42.00", "currency", "AUD"))), par(), Map.of()));
        valid(processor.validate(detail("account_information", Map.entry("accounts", List.of("acc-1")),
                Map.entry("validUntil", "2026-12-31T00:00:00Z")), par(), Map.of()));
        valid(processor.validate(detail("sales_agent", Map.entry("sales_regions", List.of("EMEA")),
                Map.entry("max_txn_eur", 500)), par(), Map.of()));
        verifyNoInteractions(client);
    }

    @Test
    @Requirement("RFC9396 §5")
    void anUndeclaredFieldIsRefusedForEachBuiltInType() {
        AttestationAwareRarProcessor processor = production();
        for (String type : List.of("payment_initiation", "account_information", "sales_agent")) {
            String reason = refusal(processor.validate(detail(type, Map.entry("colour", SECRET)), par(), Map.of()));
            assertTrue(reason.contains("UNDECLARED_FIELD") && reason.contains("'colour'") && reason.contains(type), reason);
        }
        verifyNoInteractions(client);
    }

    @Test
    @Requirement("RFC9396 §5")
    void aValueOfTheWrongJsonTypeIsRefusedForEachBuiltInType() {
        AttestationAwareRarProcessor processor = production();
        String payment = refusal(processor.validate(detail("payment_initiation", Map.entry("amount", true),
                Map.entry("currency", SECRET)), par(), Map.of()));
        assertTrue(payment.contains("MALFORMED") && payment.contains("amount"), payment);
        String accounts = refusal(processor.validate(detail("account_information", Map.entry("accounts", SECRET)),
                par(), Map.of()));
        assertTrue(accounts.contains("MALFORMED") && accounts.contains("accounts"), accounts);
        String sales = refusal(processor.validate(detail("sales_agent", Map.entry("sales_regions", SECRET)), par(), Map.of()));
        assertTrue(sales.contains("MALFORMED") && sales.contains("sales_regions"), sales);
        // A flat amount without its currency is a shape the model refuses too.
        String flat = refusal(processor.validate(detail("payment_initiation", Map.entry("amount", "42.00")), par(), Map.of()));
        assertTrue(flat.contains("currency"), flat);
    }

    @Test
    @Requirement("RFC9396 §5")
    void aDetailOverTheSizeLimitsIsRefusedForEachBuiltInType() {
        AttestationAwareRarProcessor processor = production();
        String longValue = SECRET + "x".repeat(10_000);
        for (Map.Entry<String, Map.Entry<String, Object>> c : List.of(
                Map.entry("payment_initiation", Map.<String, Object>entry("creditorName", longValue)),
                Map.entry("account_information", Map.<String, Object>entry("accounts", List.of(longValue))),
                Map.entry("sales_agent", Map.<String, Object>entry("sales_regions", List.of(longValue))))) {
            String reason = refusal(processor.validate(detail(c.getKey(), c.getValue()), par(), Map.of()));
            assertTrue(reason.contains("TOO_LARGE"), reason);
        }
    }

    @Test
    void theMarkersAreStrippedBeforeTheModelIsAsked() {
        AttestationAwareRarProcessor processor = production();
        valid(processor.validate(detail("sales_agent", Map.entry("sales_regions", List.of("EMEA")),
                Map.entry(ModelGate.PRINCIPAL_MARKER, "alice"), Map.entry(ModelGate.AGENT_MARKER, "agent-1")), par(), Map.of()));
    }

    @Test
    @Requirement("RFC9396 §5")
    void anUnmodelledTypeIsRefusedInProductionAndHeldToTheCommonFieldsInDevelopment() {
        String reason = refusal(production().validate(detail("https://extra.example/type", Map.entry("purpose", "x")),
                par(), Map.of()));
        assertTrue(reason.contains("UNMODELLED_TYPE"), reason);

        AttestationAwareRarProcessor development = processor(ModelGate.fromEnvironment(
                Map.of(RarModels.ENV_PROFILE, RarModels.DEVELOPMENT_PROFILE)));
        valid(development.validate(detail("https://extra.example/type", Map.entry("purpose", "x"),
                Map.entry("actions", List.of("read"))), par(), Map.of()));
        String undeclared = refusal(development.validate(detail("https://extra.example/type", Map.entry("amount", SECRET)),
                par(), Map.of()));
        assertTrue(undeclared.contains("UNDECLARED_FIELD"), undeclared);
    }

    @Test
    void aModelsDocumentThatDidNotLoadRefusesEveryDetailWithoutSayingWhy() {
        ModelGate none = ModelGate.fromEnvironment(Map.of(RarModels.ENV_MODELS, "{\"types\": \"" + SECRET + "\"}"));
        assertFalse(none.loaded());
        AttestationAwareRarProcessor processor = processor(none);
        for (String type : List.of("payment_initiation", "account_information", "sales_agent")) {
            String reason = refusal(processor.validate(detail(type), par(), Map.of()));
            assertTrue(reason.contains("RAR model did not load"), reason);
            assertFalse(reason.contains(none.loadFailure()), "the load failure is the operator's, in the SEVERE line");
        }
    }

    @Test
    void anUnconfiguredInstanceRefusesEveryDetail() {
        AttestationAwareRarProcessor unconfigured = new AttestationAwareRarProcessor();
        String reason = refusal(unconfigured.validate(detail("sales_agent", Map.entry("sales_regions", List.of("EMEA"))),
                par(), Map.of()));
        assertTrue(reason.contains("not configured"), reason);
    }

    @Test
    void aMissingTypeIsRefusedFirst() {
        String reason = refusal(production().validate(new AuthorizationDetail(new HashMap<>(Map.of("amount", SECRET))),
                par(), Map.of()));
        assertEquals("authorization_details entry is missing 'type'", reason);
    }

    @Test
    void validateNeverThrowsAndRefusesWhatItCannotCheck() {
        // The SDK's AuthorizationDetail turns a map it cannot read into no detail, which the model refuses as missing.
        Map<String, Object> broken = new HashMap<>(Map.of("type", "sales_agent")) {
            @Override
            public Set<Map.Entry<String, Object>> entrySet() {
                throw new IllegalStateException(SECRET);
            }
        };
        String missing = refusal(production().validate(new AuthorizationDetail(broken), par(), Map.of()));
        assertTrue(missing.contains("MALFORMED"), missing);
        // Anything that throws on the way is a refusal, never an exception PingFederate would answer with a 500.
        AuthorizationDetail unreadable = mock(AuthorizationDetail.class);
        when(unreadable.getType()).thenReturn("sales_agent");
        when(unreadable.getDetail()).thenThrow(new IllegalStateException(SECRET));
        String reason = refusal(production().validate(unreadable, par(), Map.of()));
        assertTrue(reason.contains("could not be checked"), reason);
    }

    @Test
    void aRefusalIsLoggedWithTheTypeFlowAndReasonAndNoValue() {
        Logger log = Logger.getLogger(AttestationAwareRarProcessor.class.getName());
        List<LogRecord> records = new ArrayList<>();
        Handler handler = new Handler() {
            @Override public void publish(LogRecord record) { records.add(record); }
            @Override public void flush() { }
            @Override public void close() { }
        };
        log.addHandler(handler);
        try {
            production().validate(detail("payment_initiation", Map.entry("colour", SECRET)), par(), Map.of());
        } finally {
            log.removeHandler(handler);
        }
        assertEquals(1, records.size());
        String line = records.get(0).getMessage();
        assertTrue(line.contains("type=payment_initiation") && line.contains("path=/as/par.oauth2")
                && line.contains("UNDECLARED_FIELD"), line);
        assertFalse(line.contains(SECRET), line);
    }

    // ---- the JWT-bearer grant (F-0108) -----------------------------------------------------------------

    @Test
    void onTheJwtBearerGrantATypeTheFieldDoesNotListIsRefused() {
        AttestationAwareRarProcessor processor = production();
        for (String type : List.of("payment_initiation", "account_information", "sales_agent")) {
            assertEquals(JwtBearerTypes.REFUSAL, refusal(processor.validate(detail(type), jwtBearer(), Map.of())));
        }
        assertEquals("authorization_details of this type are not accepted on the JWT-bearer grant", JwtBearerTypes.REFUSAL);
        // Every other grant is held to the model alone.
        valid(processor.validate(detail("sales_agent", Map.entry("sales_regions", List.of("EMEA"))),
                at("/as/token.oauth2", "client_credentials"), Map.of()));
        valid(processor.validate(detail("sales_agent", Map.entry("sales_regions", List.of("EMEA"))),
                new AuthorizationDetailContext.Builder().build(), Map.of()));
        verifyNoInteractions(client);
    }

    @Test
    @Requirement("RFC9396 §5")
    void aListedTypePassesTheModelCheckOnTheJwtBearerGrantAndNothingElseDoes() {
        AttestationAwareRarProcessor processor = production();
        processor.jwtBearerTypes(Set.of("sales_agent"));
        valid(processor.validate(detail("sales_agent", Map.entry("sales_regions", List.of("EMEA"))), jwtBearer(), Map.of()));
        String undeclared = refusal(processor.validate(detail("sales_agent", Map.entry("colour", SECRET)), jwtBearer(), Map.of()));
        assertTrue(undeclared.contains("UNDECLARED_FIELD"), undeclared);
        assertEquals(JwtBearerTypes.REFUSAL, refusal(processor.validate(detail("payment_initiation",
                Map.entry("amount", "1.00"), Map.entry("currency", "AUD")), jwtBearer(), Map.of())));
        verifyNoInteractions(client);
    }

    @Test
    void theFieldIsEmptyByDefaultAndConfigureReadsIt() {
        AttestationAwareRarProcessor processor = new AttestationAwareRarProcessor();
        processor.configure(stored("PDP URL", "https://pdp.example/x"), "production");
        assertEquals(Set.of(), processor.jwtBearerTypes());
        assertEquals(JwtBearerTypes.REFUSAL, refusal(processor.validate(detail("sales_agent",
                Map.entry("sales_regions", List.of("EMEA"))), jwtBearer(), Map.of())));

        processor.configure(stored("PDP URL", "https://pdp.example/x", JwtBearerTypes.FIELD, " sales_agent, - "), "production");
        assertEquals(Set.of("sales_agent"), processor.jwtBearerTypes());
        valid(processor.validate(detail("sales_agent", Map.entry("sales_regions", List.of("EMEA"))), jwtBearer(), Map.of()));

        Map<String, FieldDescriptor> fields = new HashMap<>();
        processor.getPluginDescriptor().getGuiConfigDescriptor().getFields().forEach(f -> fields.put(f.getName(), f));
        FieldDescriptor field = fields.get(JwtBearerTypes.FIELD);
        assertNotNull(field);
        assertEquals("", field.getDefaultValue());
        assertTrue(field.getDescription().contains("issued without a PDP decision"), field.getDescription());
    }

    @Test
    void aTypeRequiringAnAuthenticatedPrincipalIsRefusedAtConfigure() {
        AttestationAwareRarProcessor processor = new AttestationAwareRarProcessor();
        IllegalStateException e = assertThrows(IllegalStateException.class, () -> processor.configure(stored(
                "PDP URL", "https://pdp.example/x", JwtBearerTypes.FIELD, "sales_agent,payment_initiation"), "production"));
        assertTrue(e.getMessage().contains("payment_initiation") && !e.getMessage().contains("sales_agent,"), e.getMessage());
        // Configure refused, so the instance refuses every detail where it arrives.
        assertTrue(refusal(processor.validate(detail("sales_agent", Map.entry("sales_regions", List.of("EMEA"))),
                par(), Map.of())).contains("not configured"));

        // The principal types are the deployment's to name: with none, payment_initiation may be listed.
        processor.configure(stored("PDP URL", "https://pdp.example/x", "Types requiring an authenticated principal", "-",
                JwtBearerTypes.FIELD, "payment_initiation"), "production");
        assertEquals(Set.of("payment_initiation"), processor.jwtBearerTypes());
    }

    @Test
    void theAdminConsoleRefusesTheSameOnSave() throws Exception {
        List<ConfigurationValidator> chain = new AttestationAwareRarProcessor().getPluginDescriptor()
                .getGuiConfigDescriptor().getValidationChain();
        ConfigurationValidator validator = chain.stream().filter(v -> v instanceof JwtBearerTypes.Validator)
                .findFirst().orElseThrow();
        ValidationException both = assertThrows(ValidationException.class, () -> validator.validate(stored(
                JwtBearerTypes.FIELD, "account_information payment_initiation")));
        assertTrue(both.getMessage().contains("account_information, payment_initiation") && both.getMessage().contains("them"),
                both.getMessage());
        ValidationException named = assertThrows(ValidationException.class, () -> validator.validate(stored(
                "Types requiring an authenticated principal", "sales_agent", JwtBearerTypes.FIELD, "sales_agent")));
        assertTrue(named.getMessage().contains(" it,"), named.getMessage());
        validator.validate(stored(JwtBearerTypes.FIELD, "sales_agent"));
        validator.validate(stored());
        validator.validate(stored("Types requiring an authenticated principal", "-", JwtBearerTypes.FIELD, "payment_initiation"));
    }

    @Test
    void theRuleIsItsOwnAndReadsOnlyTheGrantType() {
        assertTrue(JwtBearerTypes.isJwtBearer(JWT_BEARER));
        assertFalse(JwtBearerTypes.isJwtBearer("urn:ietf:params:oauth:grant-type:saml2-bearer"));
        assertFalse(JwtBearerTypes.isJwtBearer(null));
        assertNull(JwtBearerTypes.refusal(Set.of("sales_agent"), Set.of("payment_initiation")));
        assertEquals(Set.of(), JwtBearerTypes.of(stored(), Set.of()));
    }

    private static Configuration stored(String... namesAndValues) {
        Configuration configuration = new Configuration();
        for (int i = 0; i + 1 < namesAndValues.length; i += 2) {
            configuration.addField(new Field(namesAndValues[i], namesAndValues[i + 1]));
        }
        return configuration;
    }
}
