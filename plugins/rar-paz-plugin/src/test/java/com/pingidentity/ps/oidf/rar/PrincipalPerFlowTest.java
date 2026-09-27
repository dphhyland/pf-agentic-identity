package com.pingidentity.ps.oidf.rar;

import com.pingidentity.sdk.authorizationdetails.AuthorizationDetail;
import com.pingidentity.sdk.authorizationdetails.AuthorizationDetailContext;
import com.pingidentity.sdk.authorizationdetails.AuthorizationDetailProcessingException;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
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
 * Each OAuth flow through {@link AttestationAwareRarProcessor#enrich}, as PingFederate 13.1.3 calls it: the
 * context built with {@code AuthorizationDetailContext.Builder} the way {@code AuthorizationDetailsUtil.enrich}
 * builds it (request, client id, scope, user key), carrying the user key each caller passes, and the servlet
 * request each caller is serving.
 *
 * <p>What each caller passes, read with javap from {@code pf-protocolengine-13.1.3.0.jar} on 2026-09-27 (the
 * seven classes that call {@code AuthorizationDetailsUtil.enrich}): {@code ClientCredentialsGrantProcessor}
 * the client id; {@code RefreshTokenGrantProcessor} the grant's {@code getUniqueUserIdentifer()};
 * {@code TokenExchangeRequest} {@code null}; {@code CibaAuthenticationRequestHandler} the identity hint's
 * subject; {@code OAuthResumableRequestHandlerBase} (the resume after authentication) and
 * {@code UserAuthorizationRequestHandler} (the device flow's approval) the authenticated subject;
 * {@code JwtGrantProcessor} never calls it. Client credentials, CIBA, refresh, token exchange and the code
 * flow were then driven on the rig by {@code conformance/verify-rar-principal.sh}; the device flow was not.
 */
class PrincipalPerFlowTest {

    private static final String CLIENT = "agent-client";
    private static final String TOKEN_PATH = "/as/token.oauth2";

    private final PdpClient pdp = mock(PdpClient.class);

    private AttestationAwareRarProcessor processor() throws Exception {
        when(pdp.decide(anyString(), any(), any(), any(), any(), any()))
                .thenReturn(new DecisionResponse("PERMIT", true, List.of(), "{}"));
        return new AttestationAwareRarProcessor(pdp, GovernanceEngineConfig.builder().pdpUrl("https://pdp/decide").build());
    }

    private static HttpServletRequest request(String path, String grantType) {
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getRequestURI()).thenReturn(path);
        when(request.getParameter("grant_type")).thenReturn(grantType);
        return request;
    }

    private static AuthorizationDetailContext context(HttpServletRequest request, String userKey) {
        return new AuthorizationDetailContext.Builder().withRequest(request).withClientId(CLIENT).withUserKey(userKey).build();
    }

    private static AuthorizationDetail detail(String type) {
        Map<String, Object> detail = new HashMap<>();
        detail.put("type", type);
        detail.put("amount", "42.00");
        return new AuthorizationDetail(detail);
    }

    /** The principal and its source, as the PDP was asked. */
    private String[] asked() throws Exception {
        ArgumentCaptor<String> owner = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> source = ArgumentCaptor.forClass(String.class);
        verify(pdp).decide(anyString(), any(), any(), owner.capture(), any(), source.capture());
        return new String[] {owner.getValue(), source.getValue()};
    }

    private void refusedBeforeThePdp(AuthorizationDetailContext context) throws Exception {
        AttestationAwareRarProcessor processor = processor();
        AuthorizationDetailProcessingException e = assertThrows(AuthorizationDetailProcessingException.class,
                () -> processor.enrich(detail("payment_initiation"), context, Map.of()));
        assertTrue(e.getMessage().contains("refused before any PDP call"), e.getMessage());
        verify(pdp, never()).decide(anyString(), any(), any(), any(), any(), any());
    }

    @Test
    void clientCredentialsIsTheClientAndAPaymentNeverReachesThePdp() throws Exception {
        AuthorizationDetailContext cc = context(request(TOKEN_PATH, "client_credentials"), CLIENT);
        processor().enrich(detail("sales_agent"), cc, Map.of());
        assertEquals(List.of(CLIENT, "client"), List.of(asked()));

        PdpClient fresh = mock(PdpClient.class);
        AuthorizationDetailProcessingException e = assertThrows(AuthorizationDetailProcessingException.class,
                () -> new AttestationAwareRarProcessor(fresh, GovernanceEngineConfig.builder().pdpUrl("https://pdp").build())
                        .enrich(detail("payment_initiation"), cc, Map.of()));
        assertTrue(e.getMessage().contains("has client"), e.getMessage());
        verify(fresh, never()).decide(anyString(), any(), any(), any(), any(), any());
    }

    @Test
    void refreshIsTheGrantsAuthenticatedUser() throws Exception {
        processor().enrich(detail("payment_initiation"),
                context(request(TOKEN_PATH, "refresh_token"), "alice"), Map.of());
        assertEquals(List.of("alice", "authenticated"), List.of(asked()));
    }

    @Test
    void cibaIsTheIdentityHintAndMayAskAboutAPayment() throws Exception {
        processor().enrich(detail("payment_initiation"),
                context(request("/as/bc-auth.ciba", null), "alice"), Map.of());
        assertEquals(List.of("alice", "identity_hint"), List.of(asked()));
    }

    /** PingFederate passes no user key for token exchange; the plugin decides about nobody unless the filter verified a subject. */
    @Test
    void tokenExchangeWithoutAVerifiedSubjectIsNobody() throws Exception {
        HttpServletRequest exchange = request(TOKEN_PATH, PrincipalResolver.GRANT_TOKEN_EXCHANGE);
        refusedBeforeThePdp(context(exchange, null));

        processor().enrich(detail("sales_agent"), context(exchange, null), Map.of());
        String[] asked = asked();
        assertNull(asked[0], "no principal: the builders fall back to the client for the subject");
        assertEquals("none", asked[1]);
    }

    @Test
    void tokenExchangeIsTheSubjectTheFilterVerifiedAndNothingTheCallerSent() throws Exception {
        HttpServletRequest exchange = request(TOKEN_PATH, PrincipalResolver.GRANT_TOKEN_EXCHANGE);
        when(exchange.getAttribute(AttestationSubject.REQUEST_ATTRIBUTE)).thenReturn(
                Map.of("client_id", CLIENT, AttestationSubject.VERIFIED_SUBJECT_TOKEN_KEY, "bob"));
        when(exchange.getParameter("login_hint")).thenReturn("mallory");
        processor().enrich(detail("payment_initiation"), context(exchange, null), Map.of());
        assertEquals(List.of("bob", "subject_token"), List.of(asked()));

        // A subject token's subject the caller puts in the request, rather than one the filter published, is not read.
        HttpServletRequest claimed = request(TOKEN_PATH, PrincipalResolver.GRANT_TOKEN_EXCHANGE);
        when(claimed.getParameter(AttestationSubject.VERIFIED_SUBJECT_TOKEN_KEY)).thenReturn("bob");
        when(claimed.getParameter("login_hint")).thenReturn("mallory");
        PdpClient fresh = mock(PdpClient.class);
        GovernanceEngineConfig switchedOnInProduction = GovernanceEngineConfig.builder().pdpUrl("https://pdp")
                .allowClientAssertedPrincipal(true).deploymentProfile(GovernanceEngineConfig.PROFILE_PRODUCTION).build();
        assertThrows(AuthorizationDetailProcessingException.class,
                () -> new AttestationAwareRarProcessor(fresh, switchedOnInProduction)
                        .enrich(detail("payment_initiation"), context(claimed, null), Map.of()));
        verify(fresh, never()).decide(anyString(), any(), any(), any(), any(), any());
    }

    /** The code flow asks once, at the resume after authentication, with the authentication result's subject. */
    @Test
    void theResumeAfterAuthenticationIsTheAuthenticatedSubject() throws Exception {
        processor().enrich(detail("payment_initiation"),
                context(request("/as/kx5Qa/resume/as/authorization.ping", null), "alice"), Map.of());
        assertEquals(List.of("alice", "authenticated"), List.of(asked()));
    }

    /** An authentication contract without a subject attribute: the user has signed in, and the plugin still knows nobody. */
    @Test
    void theResumeWithoutASubjectAttributeIsNobody() throws Exception {
        refusedBeforeThePdp(context(request("/as/kx5Qa/resume/as/authorization.ping", null), null));
    }

    /** The device flow's approval (javap only; not driven on the rig): the approving user, as authenticated. */
    @Test
    void theDeviceApprovalIsTheAuthenticatedUser() throws Exception {
        processor().enrich(detail("payment_initiation"),
                context(request("/as/user_authz.oauth2", null), "alice"), Map.of());
        assertEquals(List.of("alice", "authenticated"), List.of(asked()));
    }
}
