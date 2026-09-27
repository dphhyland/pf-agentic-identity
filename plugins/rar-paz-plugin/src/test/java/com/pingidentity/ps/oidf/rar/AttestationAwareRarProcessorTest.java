package com.pingidentity.ps.oidf.rar;

import com.pingidentity.sdk.authorizationdetails.AuthorizationDetail;
import com.pingidentity.sdk.authorizationdetails.AuthorizationDetailContext;
import com.pingidentity.sdk.authorizationdetails.AuthorizationDetailProcessingException;
import com.pingidentity.ps.oidf.conformance.Requirement;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;

import javax.net.ssl.SSLHandshakeException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Covers {@link AttestationAwareRarProcessor#enrich}: the internal markers must never survive into the
 * granted detail - on the PERMIT path or on the fail-open path - the decision is deny-unless-PERMIT with no
 * switch to say otherwise, and fail-open grants through exactly one failure class, the PDP being unreachable.
 */
class AttestationAwareRarProcessorTest {

    private static final String PRINCIPAL_KEY = "_principal_sub";
    private static final Logger LOG = Logger.getLogger(AttestationAwareRarProcessor.class.getName());

    private final PdpClient client = mock(PdpClient.class);

    @AfterEach
    void restoreLogging() {
        LOG.setLevel(null);
    }

    private static GovernanceEngineConfig config(boolean failOpen) {
        return GovernanceEngineConfig.builder()
                .pdpUrl("https://pdp/governance-engine")
                .failOpenOnError(failOpen)
                .build();
    }

    private static AuthorizationDetail paymentDetail() {
        Map<String, Object> detail = new HashMap<>();
        detail.put("type", "payment_initiation");
        detail.put("amount", "42.00");
        detail.put("currency", "AUD");
        detail.put(PRINCIPAL_KEY, "user-123");
        return new AuthorizationDetail(detail);
    }

    private static AuthorizationDetail salesDetail() {
        Map<String, Object> detail = new HashMap<>();
        detail.put("type", "sales_agent");
        detail.put("sales_regions", List.of("EMEA"));
        return new AuthorizationDetail(detail);
    }

    /** A context with an authenticated user key, as the authorization endpoint passes one (13.1: the Builder is the way in). */
    private static AuthorizationDetailContext context() {
        return new AuthorizationDetailContext.Builder().withClientId("agent-client").withUserKey("alice").build();
    }

    private void permit() throws Exception {
        when(client.decide(anyString(), any(), any(), any(), any(), any()))
                .thenReturn(new DecisionResponse("PERMIT", true, List.of(), "{}"));
    }

    // ---- fail-open: one failure class, and only when asked ------------------------------------------

    @Test
    void failOpenGrantsTheCleanedDetailWhenThePdpIsUnreachable() throws Exception {
        when(client.decide(anyString(), any(), any(), any(), any(), any()))
                .thenThrow(new PdpUnavailableException("connection refused"));
        AttestationAwareRarProcessor processor = new AttestationAwareRarProcessor(client, config(true));

        AuthorizationDetail result = processor.enrich(paymentDetail(), context(), Map.of());

        assertFalse(result.getDetail().containsKey(PRINCIPAL_KEY),
                "fail-open must not leak the internal principal marker into the issued token");
        assertEquals("42.00", result.getDetail().get("amount"));
    }

    @Test
    void anUnreachablePdpDeniesWhenFailOpenIsOff() throws Exception {
        PdpUnavailableException down = new PdpUnavailableException("connection refused");
        when(client.decide(anyString(), any(), any(), any(), any(), any())).thenThrow(down);
        AttestationAwareRarProcessor processor = new AttestationAwareRarProcessor(client, config(false));

        AuthorizationDetailProcessingException e = assertThrows(AuthorizationDetailProcessingException.class,
                () -> processor.enrich(paymentDetail(), context(), Map.of()));
        assertSame(down, e.getCause());
    }

    /** The high from the review: fail-open used to catch everything. A PDP that answered badly is not "unreachable". */
    @Test
    void failOpenDoesNotCoverAPdpThatAnsweredBadly() throws Exception {
        for (Exception refused : List.of(
                new IOException("AuthZEN PDP returned HTTP 401"),
                new IOException("response is not JSON"),
                new SSLHandshakeException("PKIX path building failed"),
                new IllegalArgumentException("field collides with a server attribute"))) {
            PdpClient failing = mock(PdpClient.class);
            when(failing.decide(anyString(), any(), any(), any(), any(), any())).thenThrow(refused);
            AttestationAwareRarProcessor processor = new AttestationAwareRarProcessor(failing, config(true));

            AuthorizationDetailProcessingException e = assertThrows(AuthorizationDetailProcessingException.class,
                    () -> processor.enrich(paymentDetail(), context(), Map.of()), refused.toString());
            assertTrue(e.getMessage().contains(refused.getMessage()), e.getMessage());
            assertNull(e.getCause(), "carried as text, so PingFederate's log of it holds nothing unredacted");
        }
    }

    /**
     * A PDP's error body can name the principal it was asked about. The refusal's WARNING line quotes the
     * failure with the principal hashed and carries no exception (the stack goes to FINE), and no line at INFO
     * or above names the user key.
     */
    @Test
    void theRefusalLineCarriesThePrincipalHashed() throws Exception {
        IOException cause = new IOException("{\"error\":\"no such subject alice\"}");
        when(client.decide(anyString(), any(), any(), any(), any(), any()))
                .thenThrow(new IOException("AuthZEN PDP returned HTTP 400", cause));
        List<LogRecord> records = new ArrayList<>();
        Handler capture = new Handler() {
            @Override public void publish(LogRecord record) { records.add(record); }
            @Override public void flush() { }
            @Override public void close() { }
        };
        LOG.addHandler(capture);
        AuthorizationDetailProcessingException thrown;
        try {
            thrown = assertThrows(AuthorizationDetailProcessingException.class,
                    () -> new AttestationAwareRarProcessor(client, config(false)).enrich(paymentDetail(), context(), Map.of()));
        } finally {
            LOG.removeHandler(capture);
        }
        String hashed = "no such subject " + PrincipalResolver.hashForLog("alice");
        LogRecord warning = records.stream().filter(r -> r.getLevel() == Level.WARNING).findFirst().orElseThrow();
        assertTrue(warning.getMessage().contains("HTTP 400 <- java.io.IOException: {\"error\":\"" + hashed), warning.getMessage());
        assertNull(warning.getThrown());
        assertTrue(thrown.getMessage().contains(hashed), thrown.getMessage());
        assertFalse(thrown.getMessage().contains("alice"), thrown.getMessage());
        assertNull(thrown.getCause());
        for (LogRecord record : records) {
            assertFalse(record.getMessage().contains("alice"), record.getMessage());
        }
    }


    /** Causes are followed three deep, which also ends a cycle of causes. */
    @Test
    void aFailureIsDescribedWithItsFirstCauses() {
        Exception deep = new Exception("a", new Exception("b", new Exception("c", new Exception("d", new Exception("e")))));
        assertEquals("java.lang.Exception: a <- java.lang.Exception: b <- java.lang.Exception: c <- java.lang.Exception: d",
                AttestationAwareRarProcessor.describe(deep));
        assertEquals("java.io.IOException: alone", AttestationAwareRarProcessor.describe(new IOException("alone")));
    }

    // ---- the decision ---------------------------------------------------------------------------------

    @Test
    @Requirement({"RFC9396 §7.1", "PF-SDK §AuthorizationDetailProcessor.enrich"})
    void permitMergesStatementsAndStripsThePrincipalMarker() throws Exception {
        when(client.decide(anyString(), any(), any(), any(), any(), any())).thenReturn(new DecisionResponse(
                "PERMIT", true,
                List.of(new DecisionResponse.Statement("access.limit", "100.00")),
                "{}"));
        AttestationAwareRarProcessor processor = new AttestationAwareRarProcessor(client, config(false));

        AuthorizationDetail result = processor.enrich(paymentDetail(), context(), Map.of());

        assertFalse(result.getDetail().containsKey(PRINCIPAL_KEY));
        Object access = result.getDetail().get("access");
        assertInstanceOf(Map.class, access);
        assertEquals("100.00", ((Map<?, ?>) access).get("limit"));

        // The marker is consumed, not forwarded to the PDP as a payload field.
        @SuppressWarnings("unchecked")
        ArgumentCaptor<Map<String, Object>> sent = ArgumentCaptor.forClass(Map.class);
        verify(client).decide(anyString(), sent.capture(), any(), any(), any(), any());
        assertFalse(sent.getValue().containsKey(PRINCIPAL_KEY));
    }

    /** There is no switch: a non-PERMIT is refused, whatever the configuration says. */
    @Test
    @Requirement("PF-SDK §AuthorizationDetailProcessor.enrich")
    void aDenyIsAlwaysRefused() throws Exception {
        when(client.decide(anyString(), any(), any(), any(), any(), any()))
                .thenReturn(new DecisionResponse("DENY", false, List.of(), "{}"));
        AttestationAwareRarProcessor processor = new AttestationAwareRarProcessor(client, config(true));

        AuthorizationDetailProcessingException e = assertThrows(AuthorizationDetailProcessingException.class,
                () -> processor.enrich(paymentDetail(), context(), Map.of()));
        assertTrue(e.getMessage().contains("payment_initiation"), e.getMessage());
        assertNull(e.getCause());
    }

    // ---- the types that need a person -----------------------------------------------------------------

    @Test
    void aPaymentIsRefusedBeforeThePdpWhenThePrincipalIsTheClient() throws Exception {
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getParameter("grant_type")).thenReturn("client_credentials");
        when(request.getRequestURI()).thenReturn("/as/token.oauth2");
        AuthorizationDetailContext cc = new AuthorizationDetailContext.Builder()
                .withRequest(request).withClientId("agent-client").withUserKey("agent-client").build();

        AuthorizationDetailProcessingException e = assertThrows(AuthorizationDetailProcessingException.class,
                () -> new AttestationAwareRarProcessor(client, config(false)).enrich(paymentDetail(), cc, Map.of()));
        assertTrue(e.getMessage().contains("client"), e.getMessage());
        verify(client, never()).decide(anyString(), any(), any(), any(), any(), any());
    }

    @Test
    void aPaymentIsRefusedBeforeThePdpWhenThereIsNoPrincipal() throws Exception {
        AuthorizationDetailContext nobody = new AuthorizationDetailContext.Builder().withClientId("agent-client").build();

        assertThrows(AuthorizationDetailProcessingException.class,
                () -> new AttestationAwareRarProcessor(client, config(false)).enrich(paymentDetail(), nobody, Map.of()));
        verify(client, never()).decide(anyString(), any(), any(), any(), any(), any());
    }

    @Test
    void aTypeOffTheListReachesThePdpAsTheClient() throws Exception {
        permit();
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getParameter("grant_type")).thenReturn("client_credentials");
        AuthorizationDetailContext cc = new AuthorizationDetailContext.Builder()
                .withRequest(request).withClientId("agent-client").withUserKey("agent-client").build();

        new AttestationAwareRarProcessor(client, config(false)).enrich(salesDetail(), cc, Map.of());

        ArgumentCaptor<String> owner = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> source = ArgumentCaptor.forClass(String.class);
        verify(client).decide(anyString(), any(), any(), owner.capture(), any(), source.capture());
        assertEquals("agent-client", owner.getValue());
        assertEquals("client", source.getValue());
    }

    @Test
    void anOperatorCanEmptyTheList() throws Exception {
        permit();
        GovernanceEngineConfig none = GovernanceEngineConfig.builder().pdpUrl("https://pdp")
                .authenticatedPrincipalTypes(Set.of()).build();
        AuthorizationDetailContext nobody = new AuthorizationDetailContext.Builder().withClientId("agent-client").build();

        assertEquals("42.00", new AttestationAwareRarProcessor(client, none).enrich(paymentDetail(), nobody, Map.of())
                .getDetail().get("amount"));
    }

    // ---- what reaches the PDP about the principal -----------------------------------------------------

    @Test
    void theAuthenticatedUserKeyIsThePrincipal() throws Exception {
        permit();
        new AttestationAwareRarProcessor(client, config(false)).enrich(paymentDetail(), context(), Map.of());

        ArgumentCaptor<String> owner = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> source = ArgumentCaptor.forClass(String.class);
        verify(client).decide(anyString(), any(), any(), owner.capture(), any(), source.capture());
        assertEquals("alice", owner.getValue());
        assertEquals("authenticated", source.getValue());
    }

    /** A null context is not something PingFederate passes; the code tolerates it rather than NPE into a server_error. */
    @Test
    void aNullContextIsNobody() throws Exception {
        permit();
        LOG.setLevel(Level.WARNING);   // the INFO summary line is skipped on this path
        new AttestationAwareRarProcessor(client, config(false)).enrich(salesDetail(), null, null);

        ArgumentCaptor<String> source = ArgumentCaptor.forClass(String.class);
        verify(client).decide(anyString(), any(), any(), any(), any(), source.capture());
        assertEquals("none", source.getValue());
    }

    @Test
    void aCallerAssertedNameThatWasNotUsedIsNotedAtFine() throws Exception {
        permit();
        LOG.setLevel(Level.FINE);
        // A null parameter map, as the token-endpoint callers pass none, is logged as "-" rather than thrown at.
        AuthorizationDetail result = new AttestationAwareRarProcessor(client, config(false)).enrich(paymentDetail(), context(), null);

        ArgumentCaptor<String> owner = ArgumentCaptor.forClass(String.class);
        verify(client).decide(anyString(), any(), any(), owner.capture(), any(), any());
        assertEquals("alice", owner.getValue(), "the authenticated key wins; the marker is merely noted");
        assertFalse(result.getDetail().containsKey(PRINCIPAL_KEY));
    }

    // ---- the flow, from the request -------------------------------------------------------------------

    @Test
    void theFlowIsReadFromTheRequestAndUnknownWithoutOne() {
        assertSame(PrincipalResolver.Flow.UNKNOWN, AttestationAwareRarProcessor.flowOf(null));

        HttpServletRequest token = mock(HttpServletRequest.class);
        when(token.getParameter("grant_type")).thenReturn(" refresh_token ");
        when(token.getRequestURI()).thenReturn("/as/token.oauth2");
        assertEquals(new PrincipalResolver.Flow("refresh_token", "/as/token.oauth2"), AttestationAwareRarProcessor.flowOf(token));

        HttpServletRequest blank = mock(HttpServletRequest.class);
        when(blank.getParameter("grant_type")).thenReturn(" ");
        when(blank.getRequestURI()).thenReturn("/as/bc-auth.ciba");
        assertEquals(new PrincipalResolver.Flow(null, "/as/bc-auth.ciba"), AttestationAwareRarProcessor.flowOf(blank));

        HttpServletRequest broken = mock(HttpServletRequest.class);
        when(broken.getParameter("grant_type")).thenThrow(new IllegalStateException("recycled"));
        assertSame(PrincipalResolver.Flow.UNKNOWN, AttestationAwareRarProcessor.flowOf(broken));
    }

    @Test
    void aRequestThatCannotBeReadStillGetsADecision() throws Exception {
        permit();
        HttpServletRequest broken = mock(HttpServletRequest.class);
        when(broken.getAttribute(anyString())).thenThrow(new IllegalStateException("recycled"));
        when(broken.getParameter(anyString())).thenThrow(new IllegalStateException("recycled"));
        AuthorizationDetailContext ctx = new AuthorizationDetailContext.Builder()
                .withRequest(broken).withClientId("agent-client").withUserKey("alice").build();

        assertEquals("EMEA", ((List<?>) new AttestationAwareRarProcessor(client, config(false))
                .enrich(salesDetail(), ctx, Map.of()).getDetail().get("sales_regions")).get(0));
    }

    // ---- the descriptor and the id --------------------------------------------------------------------

    @Test
    void aDeploymentAddsItsOwnTypesToTheBuiltInOnes() {
        java.util.Set<String> types = AttestationAwareRarProcessor.supportedTypes(
                "https://schemas.example/v1/retrieve_customer_offer, https://schemas.example/v1/retrieve_customer_position__balance", null);
        assertTrue(types.containsAll(List.of("sales_agent", "payment_initiation", "account_information",
                "https://schemas.example/v1/retrieve_customer_offer", "https://schemas.example/v1/retrieve_customer_position__balance")));
        assertEquals(5, types.size());
        assertTrue(AttestationAwareRarProcessor.supportedTypes(" ", "a b\nc").containsAll(List.of("a", "b", "c")));
        assertEquals(3, AttestationAwareRarProcessor.supportedTypes(null, null).size());
    }

    @Test
    void theShortNamedProcessorFitsPingFederatesPluginIdLimit() {
        assertTrue(au.idp.rar.FedRar.class.getName().length() <= 32, au.idp.rar.FedRar.class.getName());
        assertInstanceOf(AttestationAwareRarProcessor.class, new au.idp.rar.FedRar());
    }

    // ---- the PAR-carried agent marker -----------------------------------------------------------------

    private static AuthorizationDetail markedDetail(Object marker) {
        Map<String, Object> detail = new HashMap<>();
        detail.put("type", "https://schemas.example/v1/retrieve_customer_offer");
        detail.put("purpose", "https://w3id.org/dpv#PersonalisedBenefits");
        detail.put(AttestationAwareRarProcessor.AGENT_DETAIL_KEY, marker);
        return new AuthorizationDetail(detail);
    }

    @Test
    @SuppressWarnings({"unchecked", "rawtypes"})
    void thePARCarriedMarkerNamesTheAgentWhereTheAttestationIsNotInTheRequest() throws Exception {
        permit();
        GovernanceEngineConfig trusting = GovernanceEngineConfig.builder().pdpUrl("https://pdp").trustAgentMarker(true).build();
        AuthorizationDetail result = new AttestationAwareRarProcessor(client, trusting).enrich(markedDetail("agent-7"), context(), Map.of());

        ArgumentCaptor<Map> sent = ArgumentCaptor.forClass(Map.class);
        ArgumentCaptor<AttestationSubject> subject = ArgumentCaptor.forClass(AttestationSubject.class);
        verify(client).decide(anyString(), sent.capture(), subject.capture(), any(), any(), any());
        assertEquals("agent-7", subject.getValue().getAgentId());
        assertFalse(sent.getValue().containsKey(AttestationAwareRarProcessor.AGENT_DETAIL_KEY), "the marker is not a detail the PDP decides on");
        assertFalse(result.getDetail().containsKey(AttestationAwareRarProcessor.AGENT_DETAIL_KEY), "nor one the customer or the token ever sees");
        assertEquals("https://w3id.org/dpv#PersonalisedBenefits", result.getDetail().get("purpose"));
    }

    @Test
    void theMarkerIsIgnoredUnlessConfiguredOrBlankOrNotAStringButAlwaysStripped() throws Exception {
        permit();
        GovernanceEngineConfig trusting = GovernanceEngineConfig.builder().pdpUrl("https://pdp").trustAgentMarker(true).build();
        for (Object[] c : new Object[][] {
                {config(false), "agent-7"}, {trusting, " "}, {trusting, 42}}) {
            PdpClient pdp = mock(PdpClient.class);
            when(pdp.decide(anyString(), any(), any(), any(), any(), any())).thenReturn(new DecisionResponse("PERMIT", true, List.of(), "{}"));
            AuthorizationDetail result = new AttestationAwareRarProcessor(pdp, (GovernanceEngineConfig) c[0])
                    .enrich(markedDetail(c[1]), context(), Map.of());

            ArgumentCaptor<AttestationSubject> subject = ArgumentCaptor.forClass(AttestationSubject.class);
            verify(pdp).decide(anyString(), any(), subject.capture(), any(), any(), any());
            assertNull(subject.getValue().getAgentId(), String.valueOf(c[1]));
            assertFalse(result.getDetail().containsKey(AttestationAwareRarProcessor.AGENT_DETAIL_KEY));
        }
    }

    /** The filter's verified context names the agent; the marker is then not consulted. */
    @Test
    void aVerifiedAgentIdWinsOverTheMarker() throws Exception {
        permit();
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getAttribute(AttestationSubject.REQUEST_ATTRIBUTE)).thenReturn(Map.of(
                "sub", "agent-client", "client_id", "agent-client", "agent_id", "agent-verified", "iss", "https://attester"));
        AuthorizationDetailContext ctx = new AuthorizationDetailContext.Builder()
                .withRequest(request).withClientId("agent-client").withUserKey("alice").build();
        GovernanceEngineConfig trusting = GovernanceEngineConfig.builder().pdpUrl("https://pdp").trustAgentMarker(true).build();

        new AttestationAwareRarProcessor(client, trusting).enrich(markedDetail("agent-7"), ctx, Map.of());

        ArgumentCaptor<AttestationSubject> subject = ArgumentCaptor.forClass(AttestationSubject.class);
        verify(client).decide(anyString(), any(), subject.capture(), any(), any(), any());
        assertEquals("agent-verified", subject.getValue().getAgentId());
        assertEquals("https://attester", subject.getValue().getAttesterIssuer());
    }

}
