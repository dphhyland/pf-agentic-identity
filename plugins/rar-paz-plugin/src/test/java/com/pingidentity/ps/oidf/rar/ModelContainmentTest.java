package com.pingidentity.ps.oidf.rar;

import com.pingidentity.ps.oidf.conformance.Requirement;
import com.pingidentity.ps.oidf.rar.model.RarModelException;
import com.pingidentity.ps.oidf.rar.model.RarModels;
import com.pingidentity.sdk.authorizationdetails.AuthorizationDetail;
import com.pingidentity.sdk.authorizationdetails.AuthorizationDetailContext;
import com.pingidentity.sdk.authorizationdetails.AuthorizationDetailProcessingException;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Handler;
import java.util.logging.LogRecord;
import java.util.logging.Logger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * The containment model in the processor (plan S-1, package S1c): a requested detail is held to its type's model
 * before any PDP call, the PDP may narrow what was requested and never widen it, a refresh stays within what was
 * granted by the model's strict {@code contains}, and a request whose attestation context names another model set
 * is refused.
 */
class ModelContainmentTest {

    private static final String BUILT_IN = RarModels.builtIn().fingerprint();

    private final PdpClient pdp = mock(PdpClient.class);

    private static GovernanceEngineConfig config(boolean failOpen) {
        return GovernanceEngineConfig.builder().pdpUrl("https://pdp/decide").failOpenOnError(failOpen).build();
    }

    private AttestationAwareRarProcessor processor() {
        return new AttestationAwareRarProcessor(pdp, config(false));
    }

    private void answers(DecisionResponse.Statement... statements) throws Exception {
        when(pdp.decide(anyString(), any(), any(), any(), any(), any()))
                .thenReturn(new DecisionResponse("PERMIT", true, List.of(statements), "{}"));
    }

    private static AuthorizationDetail detail(Object... pairs) {
        Map<String, Object> map = new LinkedHashMap<>();
        for (int i = 0; i < pairs.length; i += 2) {
            map.put((String) pairs[i], pairs[i + 1]);
        }
        return new AuthorizationDetail(map);
    }

    private static AuthorizationDetail payment(String amount) {
        return detail("type", "payment_initiation", "amount", amount, "currency", "AUD");
    }

    private static AuthorizationDetail sales(String... regions) {
        return detail("type", "sales_agent", "sales_regions", new ArrayList<>(List.of(regions)));
    }

    /** A person the authorization endpoint authenticated, and no attestation context: the code flow's resume. */
    private static AuthorizationDetailContext person() {
        return new AuthorizationDetailContext.Builder().withClientId("agent-client").withUserKey("alice").build();
    }

    /** The token endpoint with the attestation context the filter would publish, carrying this fingerprint. */
    private static AuthorizationDetailContext attested(Object fingerprint, String userKey) {
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getRequestURI()).thenReturn("/as/token.oauth2");
        when(request.getParameter("grant_type")).thenReturn("refresh_token");
        Map<String, Object> attr = new HashMap<>();
        attr.put("sub", "agent-client");
        attr.put("client_id", "agent-client");
        if (fingerprint != null) {
            attr.put(AttestationSubject.RAR_MODELS_FINGERPRINT_KEY, fingerprint);
        }
        when(request.getAttribute(AttestationSubject.REQUEST_ATTRIBUTE)).thenReturn(attr);
        return new AuthorizationDetailContext.Builder().withRequest(request).withClientId("agent-client").withUserKey(userKey).build();
    }

    private static List<LogRecord> captured(ThrowingRunnable action) throws Exception {
        Logger log = Logger.getLogger(AttestationAwareRarProcessor.class.getName());
        List<LogRecord> records = new ArrayList<>();
        Handler capture = new Handler() {
            @Override public void publish(LogRecord record) { records.add(record); }
            @Override public void flush() { }
            @Override public void close() { }
        };
        log.addHandler(capture);
        try {
            action.run();
        } finally {
            log.removeHandler(capture);
        }
        return records;
    }

    private interface ThrowingRunnable {
        void run() throws Exception;
    }

    // ---- before the PDP: a detail the model cannot compare is refused -----------------------------------------

    /**
     * RFC 9396 section 5: "The AS MUST refuse to process any unknown authorization details type or authorization
     * details not conforming to the respective type definition." PingFederate answers the processor's refusal
     * with {@code invalid_authorization_details}, and the PDP is never asked about a detail the model cannot read.
     */
    @Test
    @Requirement("RFC9396 §5")
    void aDetailTheModelCannotCompareIsRefusedBeforeThePdp() throws Exception {
        answers();
        for (AuthorizationDetail refused : List.of(
                detail("type", "sales_agent", "sales_regions", List.of("EMEA"), "tier", "gold"),
                detail("type", "https://unknown.example/type", "actions", List.of("read")),
                detail("type", "payment_initiation", "amount", "42.00"),
                detail("type", "sales_agent", "max_txn_eur", -1))) {
            AuthorizationDetailProcessingException e = assertThrows(AuthorizationDetailProcessingException.class,
                    () -> processor().enrich(refused, person(), Map.of()));
            assertTrue(e.getMessage().contains("is not one this processor's RAR model accepts"), e.getMessage());
            assertTrue(e.getMessage().endsWith("refused before any PDP call"), e.getMessage());
        }
        verify(pdp, never()).decide(anyString(), any(), any(), any(), any(), any());
    }

    /** Failing open grants only what the model has checked: a detail it cannot read never reaches that path. */
    @Test
    void failingOpenNeverGrantsADetailTheModelRefused() throws Exception {
        when(pdp.decide(anyString(), any(), any(), any(), any(), any())).thenThrow(new PdpUnavailableException("connection refused"));
        AttestationAwareRarProcessor failOpen = new AttestationAwareRarProcessor(pdp, config(true));

        assertEquals("42.00", failOpen.enrich(payment("42.00"), person(), Map.of()).getDetail().get("amount"));
        assertThrows(AuthorizationDetailProcessingException.class,
                () -> failOpen.enrich(detail("type", "payment_initiation", "amount", "42.00", "currency", "AUD", "tier", "gold"),
                        person(), Map.of()));
    }

    /**
     * The markers are stripped before the model is asked and after their values are read: {@code _principal_sub}
     * still names the principal in development with the switch on, {@code _agent_id} still names the agent when
     * the marker is trusted, and neither reaches the model (which would refuse the detail as malformed), the
     * PDP or the grant.
     */
    @Test
    void theMarkersAreReadThenStrippedBeforeTheModelIsAsked() throws Exception {
        answers();
        GovernanceEngineConfig development = GovernanceEngineConfig.builder().pdpUrl("http://pdp/decide")
                .allowClientAssertedPrincipal(true).trustAgentMarker(true).deploymentProfile("development").build();
        AuthorizationDetail marked = detail("type", "payment_initiation", "amount", "42.00", "currency", "AUD",
                ModelGate.PRINCIPAL_MARKER, "bob", ModelGate.AGENT_MARKER, "agent-7");
        AuthorizationDetailContext nobody = new AuthorizationDetailContext.Builder().withClientId("agent-client").build();

        AuthorizationDetail granted = new AttestationAwareRarProcessor(pdp, development).enrich(marked, nobody, Map.of());

        @SuppressWarnings("unchecked")
        ArgumentCaptor<Map<String, Object>> sent = ArgumentCaptor.forClass(Map.class);
        ArgumentCaptor<AttestationSubject> subject = ArgumentCaptor.forClass(AttestationSubject.class);
        ArgumentCaptor<String> owner = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> source = ArgumentCaptor.forClass(String.class);
        verify(pdp).decide(anyString(), sent.capture(), subject.capture(), owner.capture(), any(), source.capture());
        assertEquals(List.of("bob", PrincipalResolver.CLIENT_ASSERTED), List.of(owner.getValue(), source.getValue()));
        assertEquals("agent-7", subject.getValue().getAgentId());
        for (Map<String, Object> seen : List.of(sent.getValue(), granted.getDetail())) {
            assertFalse(seen.containsKey(ModelGate.PRINCIPAL_MARKER), seen.toString());
            assertFalse(seen.containsKey(ModelGate.AGENT_MARKER), seen.toString());
        }
    }

    // ---- after the PDP: narrow, never widen -----------------------------------------------------------------

    /**
     * PROFILE section 7 item 2: a deployment "SHOULD enforce that any authorization_details granted downstream is
     * a subset of the attested entitlement". The token endpoint holds the request to the attested ceiling; the
     * policy engine comes after it, so the plugin holds the engine's answer to the request - a lower amount, a
     * region fewer, a limit the request left open - and what is granted stays within what the ceiling allowed.
     * RFC 9396 section 7.1 allows the answer to differ: "In addition to the user authorizing less than what the
     * client requested, there are some use cases where the AS enriches the data in an authorization details
     * object. Whether enrichment is allowed and specifics of how it works are necessarily part of the definition
     * of the respective authorization details type." The type's model is that definition here.
     */
    @Test
    @Requirement({"PROFILE §7(2)", "RFC9396 §7.1", "CAS §7(1)"})
    void thePdpMayNarrowTheRequest() throws Exception {
        answers(new DecisionResponse.Statement("amount", "40.00"));
        assertEquals("40.00", processor().enrich(payment("42.00"), person(), Map.of()).getDetail().get("amount"));

        PdpClient regions = mock(PdpClient.class);
        when(regions.decide(anyString(), any(), any(), any(), any(), any())).thenReturn(new DecisionResponse("PERMIT", true,
                List.of(new DecisionResponse.Statement("sales_regions", "[\"EMEA\"]"),
                        new DecisionResponse.Statement("max_txn_eur", 100)), "{}"));
        Map<String, Object> granted = new AttestationAwareRarProcessor(regions, config(false))
                .enrich(sales("EMEA", "APAC"), person(), Map.of()).getDetail();
        assertEquals(List.of("EMEA"), granted.get("sales_regions"));
        assertEquals(100, granted.get("max_txn_eur"), "a limit the request left open is the PDP's to set");
    }

    /**
     * The same rule, the other way: whatever the PDP permits, a grant wider than the request is refused - a larger
     * amount, another currency, or another type altogether (which the model cannot even compare with the request,
     * since the payment's fields are not the other type's).
     */
    @Test
    @Requirement({"PROFILE §7(2)", "CAS §7(1)"})
    void thePdpMayNotWidenTheRequest() throws Exception {
        Map<DecisionResponse.Statement, String> widening = new LinkedHashMap<>();
        widening.put(new DecisionResponse.Statement("amount", "4200.00"), "it is not within the request");
        widening.put(new DecisionResponse.Statement("currency", "USD"), "it is not within the request");
        widening.put(new DecisionResponse.Statement("type", "sales_agent"), "the model cannot compare it with the request (UNDECLARED_FIELD)");
        for (Map.Entry<DecisionResponse.Statement, String> c : widening.entrySet()) {
            PdpClient widens = mock(PdpClient.class);
            when(widens.decide(anyString(), any(), any(), any(), any(), any()))
                    .thenReturn(new DecisionResponse("PERMIT", true, List.of(c.getKey()), "{}"));
            AuthorizationDetailProcessingException e = assertThrows(AuthorizationDetailProcessingException.class,
                    () -> new AttestationAwareRarProcessor(widens, config(false)).enrich(payment("42.00"), person(), Map.of()));
            assertTrue(e.getMessage().contains("a PDP may narrow a request and never widen it: " + c.getValue()), e.getMessage());
            if (!"type".equals(c.getKey().getName())) {   // a type is named by the model's message; a value never is
                assertFalse(e.getMessage().contains(String.valueOf(c.getKey().getPayload())), "no PDP payload: " + e.getMessage());
            }
        }
        PdpClient regions = mock(PdpClient.class);
        when(regions.decide(anyString(), any(), any(), any(), any(), any())).thenReturn(new DecisionResponse("PERMIT", true,
                List.of(new DecisionResponse.Statement("sales_regions", "[\"EMEA\",\"APAC\"]")), "{}"));
        assertThrows(AuthorizationDetailProcessingException.class,
                () -> new AttestationAwareRarProcessor(regions, config(false)).enrich(sales("EMEA"), person(), Map.of()));
    }

    /**
     * {@code StatementApplier} writes into nested maps in place. Were the grant built on a shallow copy of the
     * request, a statement naming a nested member would rewrite the request as well, and the grant would be
     * compared with itself: a 5000.00 payment approved against a 42.00 request.
     */
    @Test
    void aNestedStatementCannotRewriteTheRequestItIsComparedWith() throws Exception {
        answers(new DecisionResponse.Statement("instructedAmount.amount", "5000.00"));
        Map<String, Object> amount = new HashMap<>(Map.of("amount", "42.00", "currency", "EUR"));
        AuthorizationDetail request = detail("type", "payment_initiation", "instructedAmount", amount);

        AuthorizationDetailProcessingException e = assertThrows(AuthorizationDetailProcessingException.class,
                () -> processor().enrich(request, person(), Map.of()));
        assertTrue(e.getMessage().contains("it is not within the request"), e.getMessage());

        answers(new DecisionResponse.Statement("instructedAmount.amount", "40.00"));
        Map<String, Object> narrowed = processor().enrich(detail("type", "payment_initiation",
                "instructedAmount", new HashMap<>(Map.of("amount", "42.00", "currency", "EUR"))), person(), Map.of()).getDetail();
        assertEquals("40.00", ((Map<?, ?>) narrowed.get("instructedAmount")).get("amount"));
    }

    /** A statement that writes a field the type does not declare - the old {@code access.limit} - is refused. */
    @Test
    void aStatementTheModelCannotCompareIsRefusedAndNamedWithoutItsValue() throws Exception {
        answers(new DecisionResponse.Statement("access.limit", "100.00"));
        AuthorizationDetailProcessingException e = assertThrows(AuthorizationDetailProcessingException.class,
                () -> processor().enrich(payment("42.00"), person(), Map.of()));
        assertTrue(e.getMessage().contains("the model cannot compare it with the request (UNDECLARED_FIELD)"), e.getMessage());
        assertTrue(e.getMessage().contains("'access'"), e.getMessage());
        assertFalse(e.getMessage().contains("100.00"), e.getMessage());
    }

    @Test
    void theRefusalIsLoggedWithThePrincipalHashedAndNoPayload() throws Exception {
        answers(new DecisionResponse.Statement("amount", "999.00"));
        List<LogRecord> lines = captured(() -> assertThrows(AuthorizationDetailProcessingException.class,
                () -> processor().enrich(payment("42.00"), person(), Map.of())));
        LogRecord refusal = lines.stream().filter(r -> r.getMessage().contains("refusing the PDP's answer")).findFirst().orElseThrow();
        assertTrue(refusal.getMessage().contains("principal=" + PrincipalResolver.hashForLog("alice")), refusal.getMessage());
        for (LogRecord line : lines) {
            assertFalse(line.getMessage().contains("999.00"), line.getMessage());
            assertFalse(line.getMessage().contains("alice"), line.getMessage());
        }
    }

    // ---- the fingerprint --------------------------------------------------------------------------------------

    @Test
    void aContextFromAFilterWithTheSameModelsIsDecided() throws Exception {
        answers();
        assertEquals("42.00", processor().enrich(payment("42.00"), attested(BUILT_IN, "alice"), Map.of()).getDetail().get("amount"));
    }

    @Test
    void aContextWithoutTheFingerprintOrWithAnotherIsRefusedBeforeThePdp() throws Exception {
        answers();
        String other = RarModels.load("{\"types\":{\"https://x.example\":{\"fields\":{\"a\":\"set\"}}}}").fingerprint();
        for (Object fingerprint : new Object[] {null, other, "  "}) {
            AuthorizationDetailProcessingException e = assertThrows(AuthorizationDetailProcessingException.class,
                    () -> processor().enrich(payment("42.00"), attested(fingerprint, "alice"), Map.of()));
            assertTrue(e.getMessage().contains("refused before any PDP call: the attestation context"), e.getMessage());
        }
        verify(pdp, never()).decide(anyString(), any(), any(), any(), any(), any());
    }

    /** No context at all is a request the filter did not verify: decided as PR #29 left it, with no ceiling sent. */
    @Test
    void withoutAContextTheDecisionIsTheOneBeforeTheModel() throws Exception {
        answers();
        processor().enrich(payment("42.00"), person(), Map.of());
        ArgumentCaptor<AttestationSubject> subject = ArgumentCaptor.forClass(AttestationSubject.class);
        verify(pdp).decide(anyString(), any(), subject.capture(), any(), any(), any());
        assertFalse(subject.getValue().isContextPresent());
        assertTrue(subject.getValue().getEntitlement().isEmpty());
    }

    @Test
    void aProcessorWithNoModelRefusesEverything() throws Exception {
        answers();
        ModelGate none = ModelGate.fromEnvironment(Map.of(RarModels.ENV_MODELS, "{"));
        AttestationAwareRarProcessor broken = new AttestationAwareRarProcessor(pdp, config(true), none);
        AuthorizationDetailProcessingException e = assertThrows(AuthorizationDetailProcessingException.class,
                () -> broken.enrich(payment("42.00"), person(), Map.of()));
        assertTrue(e.getMessage().contains("has no RAR model to hold it to"), e.getMessage());
        assertFalse(broken.isEqualOrSubset(payment("42.00"), payment("42.00"), null, Map.of()));
        assertEquals(RarModelException.Reason.MODEL_INVALID, broken.refreshVerdict(payment("1.00"), payment("2.00"), null).reason());
        verify(pdp, never()).decide(anyString(), any(), any(), any(), any(), any());
    }

    // ---- refresh: the model's strict contains ---------------------------------------------------------------

    /**
     * RFC 9396 section 6.1: "For example, upon refreshing a token, the client can ask for a new access token with
     * "fewer permissions" than had been previously authorized by the resource owner." and "An AS should not rely
     * on simple object comparison in most cases". CAS section 7 rule 1 gives the comparison: "for a candidate to
     * be within the ceiling there must be a ceiling object of the same type whose constraints it does not exceed
     * (arrays: subset; numeric limits: ≤; absent ceiling field: unconstrained)." The grant is the ceiling.
     */
    @Test
    @Requirement({"RFC9396 §6.1", "CAS §7(1)"})
    void aRefreshMayAskForLessAndNeverForMore() {
        AttestationAwareRarProcessor processor = processor();
        assertTrue(processor.isEqualOrSubset(payment("42.00"), payment("42.00"), null, Map.of()), "the same grant again");
        assertTrue(processor.isEqualOrSubset(payment("10.00"), payment("42.00"), null, Map.of()), "fewer permissions");
        assertTrue(processor.isEqualOrSubset(sales("EMEA"), sales("EMEA", "APAC"), null, Map.of()));
        assertFalse(processor.isEqualOrSubset(payment("42.01"), payment("42.00"), null, Map.of()),
                "an amount above the grant: RarContainment never compared it (F-0031)");
        assertFalse(processor.isEqualOrSubset(detail("type", "payment_initiation", "amount", "42.00", "currency", "USD"),
                payment("42.00"), null, Map.of()), "another currency");
        assertFalse(processor.isEqualOrSubset(sales("EMEA", "APAC"), sales("EMEA"), null, Map.of()));
        assertFalse(processor.isEqualOrSubset(detail("type", "sales_agent"), sales("EMEA"), null, Map.of()),
                "silence about a constrained field is not a narrower request");
        assertFalse(processor.isEqualOrSubset(detail("type", "payment_initiation", "creditorName", "Mallory"),
                detail("type", "payment_initiation", "creditorName", "Acme"), null, Map.of()), "a different payee");
    }

    @Test
    void aRefreshTheModelCannotCompareIsNotContainedAndSaysWhy() throws Exception {
        AttestationAwareRarProcessor processor = processor();
        ModelGate.Verdict undeclared = processor.refreshVerdict(
                detail("type", "sales_agent", "sales_regions", List.of("EMEA"), "tier", "gold"), sales("EMEA"), null);
        assertEquals(RarModelException.Reason.UNDECLARED_FIELD, undeclared.reason());
        assertEquals(RarModelException.Reason.MALFORMED, processor.refreshVerdict(null, sales("EMEA"), null).reason());
        assertEquals(RarModelException.Reason.MALFORMED, processor.refreshVerdict(sales("EMEA"), null, null).reason());

        List<LogRecord> lines = captured(() -> assertFalse(processor.isEqualOrSubset(
                detail("type", "sales_agent", "sales_regions", List.of("EMEA"), "tier", "platinum"), sales("EMEA"), null, Map.of())));
        assertEquals(1, lines.size());
        assertTrue(lines.get(0).getMessage().contains("is not within the grant it was compared with; refused:"), lines.get(0).getMessage());
        assertFalse(lines.get(0).getMessage().contains("platinum"), lines.get(0).getMessage());
        List<LogRecord> plain = captured(() -> assertFalse(processor.isEqualOrSubset(sales("APAC"), sales("EMEA"), null, Map.of())));
        assertTrue(plain.get(0).getMessage().endsWith("is not within the grant it was compared with"), plain.get(0).getMessage());
        assertTrue(captured(() -> assertTrue(processor.isEqualOrSubset(sales("EMEA"), sales("EMEA"), null, Map.of()))).isEmpty());
    }

    /** Both sides are compared without their markers, as PingFederate may hand them over. */
    @Test
    void aRefreshIsComparedWithoutTheMarkers() {
        AuthorizationDetail asked = detail("type", "sales_agent", "sales_regions", List.of("EMEA"), ModelGate.AGENT_MARKER, "agent-7");
        AuthorizationDetail granted = detail("type", "sales_agent", "sales_regions", List.of("EMEA", "APAC"),
                ModelGate.PRINCIPAL_MARKER, "alice");
        assertTrue(processor().isEqualOrSubset(asked, granted, null, Map.of()));
    }

    @Test
    void aRefreshWithAnAttestationContextMustNameThisPluginsModels() throws Exception {
        AttestationAwareRarProcessor processor = processor();
        assertTrue(processor.isEqualOrSubset(sales("EMEA"), sales("EMEA"), attested(BUILT_IN, null), Map.of()));
        ModelGate.Verdict mismatch = processor.refreshVerdict(sales("EMEA"), sales("EMEA"), attested(null, null));
        assertFalse(mismatch.contained());
        assertNull(mismatch.reason(), "not the model's refusal: the plugin's");
        assertTrue(mismatch.refusal().contains("carries no " + ModelGate.FINGERPRINT_MEMBER), mismatch.refusal());
        assertFalse(processor.isEqualOrSubset(sales("EMEA"), sales("EMEA"), attested("0".repeat(64), null), Map.of()));
    }
}
