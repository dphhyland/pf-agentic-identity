package com.pingidentity.ps.oidf.rar;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.pingidentity.sdk.authorizationdetails.AuthorizationDetail;
import com.pingidentity.sdk.authorizationdetails.AuthorizationDetailContext;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

/**
 * Who the PDP decides <em>about</em> when PingFederate knows nobody.
 *
 * <p>Two names are the caller's own: the {@code login_hint} request parameter and the {@code _principal_sub}
 * marker a BFF folds into {@code authorization_details}. Treating either as the principal lets a client name
 * whoever it likes and have the PDP decide about that person - nothing looks broken, the attestation verifies,
 * the decision is sound, and it is about the wrong human. From 0.4.0 they are honoured only when the operator
 * switched it on AND {@code OIDF_DEPLOYMENT_PROFILE=development} (plan decision 9); at 1.0 they go. These
 * tests pin the default (refuse), the two halves of the escape hatch, and the {@code principal_source} that
 * lets policy tell the sources apart when it is open.
 */
class ClientAssertedPrincipalTest {

    private final PdpClient client = mock(PdpClient.class);

    private static GovernanceEngineConfig config(boolean allowClientAsserted, String profile) {
        return GovernanceEngineConfig.builder()
                .pdpUrl("https://pdp/governance-engine")
                .allowClientAssertedPrincipal(allowClientAsserted)
                .deploymentProfile(profile)
                .authenticatedPrincipalTypes(Set.of())    // isolate the principal question from the type rule
                .build();
    }

    private static AuthorizationDetail detailWithPrincipalMarker(String principal) {
        Map<String, Object> detail = new HashMap<>();
        detail.put("type", "payment_initiation");
        detail.put("amount", "42.00");
        if (principal != null) {
            detail.put("_principal_sub", principal);
        }
        return new AuthorizationDetail(detail);
    }

    /** A context whose request carries the given login_hint, with the user key PingFederate passed (or none). */
    private static AuthorizationDetailContext contextWith(String loginHint, String userKey) {
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getParameter("login_hint")).thenReturn(loginHint);
        when(request.getRequestURI()).thenReturn("/as/authorization.oauth2");
        // The way PingFederate 13.1 builds it: a jakarta request, which the plugin reads with getJakartaRequest().
        return new AuthorizationDetailContext.Builder().withRequest(request).withClientId("agent-client").withUserKey(userKey).build();
    }

    private void permit() throws Exception {
        when(client.decide(anyString(), any(), any(), any(), any(), any()))
                .thenReturn(new DecisionResponse("PERMIT", true, List.of(), "{}"));
    }

    /** Runs enrich and returns the (resourceOwner, principalSource) the PDP was actually asked about. */
    private String[] askedAbout(GovernanceEngineConfig cfg, AuthorizationDetail detail,
                                AuthorizationDetailContext ctx) throws Exception {
        permit();
        new AttestationAwareRarProcessor(client, cfg).enrich(detail, ctx, Map.of());
        ArgumentCaptor<String> owner = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> source = ArgumentCaptor.forClass(String.class);
        verify(client).decide(anyString(), any(), any(), owner.capture(), any(), source.capture());
        return new String[] { owner.getValue(), source.getValue() };
    }

    // ---- the default: a caller does not get to choose who the decision is about --------------------

    @Test
    void aLoginHintIsNotThePrincipalByDefault() throws Exception {
        String[] asked = askedAbout(config(false, "development"), detailWithPrincipalMarker(null),
                contextWith("alice", null));

        assertNull(asked[0], "login_hint is a query parameter, not an authenticated identity");
        assertEquals("none", asked[1]);
    }

    @Test
    void aPrincipalMarkerInTheDetailIsNotThePrincipalByDefault() throws Exception {
        String[] asked = askedAbout(config(false, "development"), detailWithPrincipalMarker("alice"),
                contextWith(null, null));

        assertNull(asked[0], "_principal_sub is caller-supplied like any other authorization_details field");
        assertEquals("none", asked[1]);
    }

    // ---- the switch alone is not enough: production ignores it ---------------------------------------

    @Test
    void theSwitchIsInertOutsideDevelopment() throws Exception {
        String[] asked = askedAbout(config(true, "production"), detailWithPrincipalMarker("alice"),
                contextWith("alice", null));

        assertNull(asked[0], "a production deployment never takes the caller's word for the principal");
        assertEquals("none", asked[1]);
    }

    @Test
    void anUnsetProfileIsProduction() throws Exception {
        String[] asked = askedAbout(config(true, null), detailWithPrincipalMarker("alice"), contextWith(null, null));

        assertEquals("none", asked[1]);
    }

    // ---- what PingFederate authenticated is trusted, and labelled as such -----------------------------

    @Test
    void anAuthenticatedUserKeyIsUsedAndLabelled() throws Exception {
        String[] asked = askedAbout(config(false, "production"), detailWithPrincipalMarker(null),
                contextWith(null, "alice"));

        assertEquals("alice", asked[0]);
        assertEquals("authenticated", asked[1]);
    }

    /**
     * The one that would let the fix be bypassed: a request that carries both. PingFederate's key must win,
     * and a caller must not be able to override it by also sending a hint - even in development with the
     * switch on.
     */
    @Test
    void anAuthenticatedPrincipalWinsOverAClientAssertedOne() throws Exception {
        String[] asked = askedAbout(config(true, "development"), detailWithPrincipalMarker("mallory"),
                contextWith("mallory", "alice"));

        assertEquals("alice", asked[0], "the user key PingFederate passed is the only trustworthy source");
        assertEquals("authenticated", asked[1]);
    }

    // ---- the escape hatch: the switch on, in development ---------------------------------------------

    @Test
    void aLoginHintIsUsedInDevelopmentWhenTheOperatorEnabledIt() throws Exception {
        String[] asked = askedAbout(config(true, "development"), detailWithPrincipalMarker(null),
                contextWith("alice", null));

        assertEquals("alice", asked[0]);
        assertEquals("client_asserted", asked[1],
                "policy must be able to see that this principal was the caller's word");
    }

    @Test
    void aPrincipalMarkerIsUsedInDevelopmentWhenTheOperatorEnabledIt() throws Exception {
        String[] asked = askedAbout(config(true, " Development "), detailWithPrincipalMarker("alice"),
                contextWith(null, null));

        assertEquals("alice", asked[0]);
        assertEquals("client_asserted", asked[1]);
    }

    // ---- and the marker still never survives into what is granted ----------------------------------

    @Test
    void theMarkerIsStrippedRegardlessOfWhetherItWasTrusted() throws Exception {
        permit();
        AuthorizationDetail detail = detailWithPrincipalMarker("alice");
        new AttestationAwareRarProcessor(client, config(true, "development")).enrich(detail, contextWith(null, null), Map.of());

        assertNull(detail.getDetail().get("_principal_sub"),
                "consumed as the principal, but it must never reach the consent page or the token");
    }
}
