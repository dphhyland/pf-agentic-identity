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
import javax.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

/**
 * Who the PDP decides <em>about</em>.
 *
 * <p>PingFederate's {@code AuthorizationDetailContext} exposes no authenticated resource owner, so the
 * processor reads the principal out-of-band. One source is trustworthy — a request attribute an authn
 * hook set server-side. Two are not: the {@code login_hint} request parameter and the
 * {@code _principal_sub} marker a BFF folds into {@code authorization_details}. Both are simply what
 * the caller sent, and the resolution treated all three alike.
 *
 * <p>That is a subtle failure, because nothing looks broken: the attestation verifies, the chain
 * validates, the PDP returns a sound decision. It is just a decision about the wrong human — a client
 * asserting {@code login_hint=alice} got Alice's entitlements evaluated. These tests pin the default
 * (refuse), the escape hatch (a deliberate operator choice), and the {@code principal_source} that lets
 * policy tell the two apart when the hatch is open.
 */
class ClientAssertedPrincipalTest {

    private final PdpClient client = mock(PdpClient.class);

    private static GovernanceEngineConfig config(boolean allowClientAsserted) {
        return GovernanceEngineConfig.builder()
                .pdpUrl("https://pdp/governance-engine")
                .denyOnNonPermit(false)                       // isolate the principal question
                .allowClientAssertedPrincipal(allowClientAsserted)
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

    /** A context whose request carries the given login_hint and/or authn-hook attribute. */
    private static AuthorizationDetailContext contextWith(String loginHint, String authenticatedAttribute) {
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getParameter("login_hint")).thenReturn(loginHint);
        when(request.getAttribute("com.pingidentity.ps.oidf.rar.resource_owner_sub"))
                .thenReturn(authenticatedAttribute);
        return new AuthorizationDetailContext(request, "agent-client", null);
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
        String[] asked = askedAbout(config(false), detailWithPrincipalMarker(null),
                contextWith("alice", null));

        assertNull(asked[0], "login_hint is a query parameter, not an authenticated identity");
        assertEquals("none", asked[1]);
    }

    @Test
    void aPrincipalMarkerInTheDetailIsNotThePrincipalByDefault() throws Exception {
        String[] asked = askedAbout(config(false), detailWithPrincipalMarker("alice"),
                contextWith(null, null));

        assertNull(asked[0], "_principal_sub is caller-supplied like any other authorization_details field");
        assertEquals("none", asked[1]);
    }

    // ---- an authn hook's attribute is trusted, and labelled as such --------------------------------

    @Test
    void anAuthenticatedPrincipalIsUsedAndLabelled() throws Exception {
        String[] asked = askedAbout(config(false), detailWithPrincipalMarker(null),
                contextWith(null, "alice"));

        assertEquals("alice", asked[0]);
        assertEquals("authenticated", asked[1]);
    }

    /**
     * The one that would let the fix be bypassed: a request that carries both. The server-side attribute
     * must win, and a caller must not be able to override it by also sending a hint.
     */
    @Test
    void anAuthenticatedPrincipalWinsOverAClientAssertedOne() throws Exception {
        String[] asked = askedAbout(config(true), detailWithPrincipalMarker("mallory"),
                contextWith("mallory", "alice"));

        assertEquals("alice", asked[0], "the authn hook's attribute is the only trustworthy source");
        assertEquals("authenticated", asked[1]);
    }

    // ---- the escape hatch, for a deployment whose only caller is a trusted BFF ---------------------

    @Test
    void aLoginHintIsUsedWhenTheOperatorEnabledIt() throws Exception {
        String[] asked = askedAbout(config(true), detailWithPrincipalMarker(null),
                contextWith("alice", null));

        assertEquals("alice", asked[0]);
        assertEquals("client_asserted", asked[1],
                "policy must be able to see that this principal was the caller's word");
    }

    @Test
    void aPrincipalMarkerIsUsedWhenTheOperatorEnabledIt() throws Exception {
        String[] asked = askedAbout(config(true), detailWithPrincipalMarker("alice"),
                contextWith(null, null));

        assertEquals("alice", asked[0]);
        assertEquals("client_asserted", asked[1]);
    }

    // ---- and the marker still never survives into what is granted ----------------------------------

    @Test
    void theMarkerIsStrippedRegardlessOfWhetherItWasTrusted() throws Exception {
        permit();
        AuthorizationDetail detail = detailWithPrincipalMarker("alice");
        new AttestationAwareRarProcessor(client, config(true)).enrich(detail, contextWith(null, null), Map.of());

        assertNull(detail.getDetail().get("_principal_sub"),
                "consumed as the principal, but it must never reach the consent page or the token");
    }
}
