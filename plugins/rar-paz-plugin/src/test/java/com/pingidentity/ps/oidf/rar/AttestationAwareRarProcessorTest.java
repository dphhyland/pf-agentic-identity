package com.pingidentity.ps.oidf.rar;

import com.pingidentity.sdk.authorizationdetails.AuthorizationDetail;
import com.pingidentity.sdk.authorizationdetails.AuthorizationDetailContext;
import com.pingidentity.sdk.authorizationdetails.AuthorizationDetailProcessingException;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Covers {@link AttestationAwareRarProcessor#enrich}: the internal {@code _principal_sub} marker must
 * never survive into the granted detail — on the PERMIT path or on the fail-open path — and the
 * enforcement knobs (deny-unless-PERMIT, fail-open) must behave as configured.
 */
class AttestationAwareRarProcessorTest {

    private static final String PRINCIPAL_KEY = "_principal_sub";

    private final PdpClient client = mock(PdpClient.class);

    private static GovernanceEngineConfig config(boolean denyOnNonPermit, boolean failOpen) {
        return GovernanceEngineConfig.builder()
                .pdpUrl("https://pdp/governance-engine")
                .denyOnNonPermit(denyOnNonPermit)
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

    private static AuthorizationDetailContext context() {
        return new AuthorizationDetailContext(null, "agent-client", null);
    }

    @Test
    void failOpenStripsThePrincipalMarker() throws Exception {
        when(client.decide(anyString(), any(), any(), any(), any(), any())).thenThrow(new IOException("pdp unreachable"));
        AttestationAwareRarProcessor processor =
                new AttestationAwareRarProcessor(client, config(true, true));

        AuthorizationDetail result = processor.enrich(paymentDetail(), context(), Map.of());

        assertFalse(result.getDetail().containsKey(PRINCIPAL_KEY),
                "fail-open must not leak the internal principal marker into the issued token");
        assertEquals("42.00", result.getDetail().get("amount"));
    }

    @Test
    void permitMergesStatementsAndStripsThePrincipalMarker() throws Exception {
        when(client.decide(anyString(), any(), any(), any(), any(), any())).thenReturn(new DecisionResponse(
                "PERMIT", true,
                List.of(new DecisionResponse.Statement("access.limit", "100.00")),
                "{}"));
        AttestationAwareRarProcessor processor =
                new AttestationAwareRarProcessor(client, config(true, false));

        AuthorizationDetail result = processor.enrich(paymentDetail(), context(), Map.of());

        assertFalse(result.getDetail().containsKey(PRINCIPAL_KEY));
        Object access = result.getDetail().get("access");
        assertInstanceOf(Map.class, access);
        assertEquals("100.00", ((Map<?, ?>) access).get("limit"));

        // The marker is consumed as the principal, not forwarded to the PDP as a payload field.
        @SuppressWarnings("unchecked")
        ArgumentCaptor<Map<String, Object>> sent = ArgumentCaptor.forClass(Map.class);
        verify(client).decide(anyString(), sent.capture(), any(), any(), any(), any());
        assertFalse(sent.getValue().containsKey(PRINCIPAL_KEY));
    }

    @Test
    void denyThrowsWhenConfiguredToDenyOnNonPermit() throws Exception {
        when(client.decide(anyString(), any(), any(), any(), any(), any()))
                .thenReturn(new DecisionResponse("DENY", false, List.of(), "{}"));
        AttestationAwareRarProcessor processor =
                new AttestationAwareRarProcessor(client, config(true, false));

        AuthorizationDetailProcessingException e = assertThrows(AuthorizationDetailProcessingException.class,
                () -> processor.enrich(paymentDetail(), context(), Map.of()));
        assertTrue(e.getMessage().contains("payment_initiation"), e.getMessage());
    }

    @Test
    void engineErrorThrowsWithTheCauseWhenNotFailingOpen() throws Exception {
        IOException boom = new IOException("pdp unreachable");
        when(client.decide(anyString(), any(), any(), any(), any(), any())).thenThrow(boom);
        AttestationAwareRarProcessor processor =
                new AttestationAwareRarProcessor(client, config(true, false));

        AuthorizationDetailProcessingException e = assertThrows(AuthorizationDetailProcessingException.class,
                () -> processor.enrich(paymentDetail(), context(), Map.of()));
        assertSame(boom, e.getCause());
    }
}
