package com.pingidentity.ps.oidf.servlet.clientregistration.utils;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.pingidentity.ps.oidf.conformance.Requirement;
import com.pingidentity.ps.oidf.federation.TrustChainValidationException;
import com.pingidentity.ps.oidf.federation.event.FederationEvent;
import com.pingidentity.ps.oidf.federation.event.FederationEvents;
import com.pingidentity.ps.oidf.federation.testkit.EventCapture;
import com.pingidentity.ps.oidf.federation.testkit.Federation;
import com.pingidentity.ps.oidf.federation.testkit.Statements;
import com.pingidentity.ps.oidf.jose.JwtVerificationException;
import com.pingidentity.ps.oidf.pf.FederationRuntimeConfig;
import jakarta.servlet.http.HttpServletRequest;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.jose4j.json.JsonUtil;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.sourceid.saml20.adapter.attribute.AttributeValue;

/**
 * The OGNL issuance criterion {@code OIDFederationUtils.validateTrustChain(#this)}, driven end to end over a
 * whole federation: the chain in the client assertion's {@code trust_chain} header either validates to the
 * pinned anchor or the criterion answers false - and either way one event records it.
 */
class OIDFederationUtilsTest {
    private static final String TA = "https://ta.example.com";
    private static final String INT = "https://int.example.com";
    private static final String RP = "https://rp.example.com";
    private static final String OP = "https://op.example.com";

    private EventCapture events;

    @BeforeEach
    void setUp() {
        OIDFederationUtils.resetForTests();
        this.events = EventCapture.install();
    }

    @AfterEach
    void tearDown() {
        OIDFederationUtils.resetForTests();
        FederationRuntimeConfig.resetForTests();
        this.events.close();
    }

    private Federation federation() {
        Federation f = Federation.builder()
                .anchor(TA)
                .intermediate(INT, TA)
                .leaf(RP, INT)
                .metadata(RP, "oauth_client", Map.of("client_name", "agent"))
                .build();
        FederationRuntimeConfig.install(FederationRuntimeConfig.from(Map.of(
                FederationRuntimeConfig.HOST_ENV, TA,
                FederationRuntimeConfig.TRUST_ANCHOR_JWKS_ENV, JsonUtil.toJson(f.publicJwks(TA)))::get, name -> null));
        OIDFederationUtils.useHttpClient(f.http());
        OIDFederationUtils.useIssuerResolver(req -> OP);
        return f;
    }

    private static Map<String, Object> criteria(String clientId, String clientAssertion, Map<String, Object> extra) {
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getParameter("client_assertion")).thenReturn(clientAssertion);
        AttributeValue requestValue = mock(AttributeValue.class);
        when(requestValue.getObjectValue()).thenReturn(request);
        AttributeValue clientValue = mock(AttributeValue.class);
        when(clientValue.getValue()).thenReturn(clientId);
        Map<String, Object> in = new HashMap<>(extra);
        in.put("context.ClientId", clientValue);
        in.put("context.HttpRequest", requestValue);
        return in;
    }

    private static String assertionCarrying(Federation f, List<String> chain) {
        return Statements.spec("JWT").header("trust_chain", chain)
                .claim("iss", RP).claim("sub", RP).claim("aud", OP).sign(f.key(RP), f.clock());
    }

    @Test
    @Requirement("OIDFED §4")
    void aChainThatReachesThePinnedAnchorPassesAndIsRecorded() {
        Federation f = federation();

        boolean ok = OIDFederationUtils.validateTrustChain(criteria(RP, assertionCarrying(f, f.chain(RP, TA)), Map.of()));

        assertTrue(ok);
        FederationEvent validated = this.events.only(FederationEvents.CHAIN_VALIDATED);
        assertEquals(RP, validated.subject());
        assertEquals(TA, validated.partner());
        assertEquals("3", validated.fields().get("presented"));
    }

    @Test
    void aForgedStatementFailsTheCriterionAndLeavesAnAuditEventWithoutTheToken() {
        Federation f = Federation.builder().anchor(TA).intermediate(INT, TA).leaf(RP, INT)
                .subordinate(INT, RP, s -> s.signWith(com.pingidentity.ps.oidf.federation.testkit.Keys.ec("int-example-com-1")))
                .build();
        FederationRuntimeConfig.install(FederationRuntimeConfig.from(Map.of(
                FederationRuntimeConfig.HOST_ENV, TA,
                FederationRuntimeConfig.TRUST_ANCHOR_JWKS_ENV, JsonUtil.toJson(f.publicJwks(TA)))::get, name -> null));
        OIDFederationUtils.useHttpClient(f.http());
        OIDFederationUtils.useIssuerResolver(req -> OP);

        boolean ok = OIDFederationUtils.validateTrustChain(criteria(RP, assertionCarrying(f, f.chain(RP, TA)), Map.of()));

        assertFalse(ok);
        FederationEvent refused = this.events.only(FederationEvents.CHAIN_REFUSED);
        assertTrue(refused.isFailure());
        assertTrue(refused.audit());
        assertEquals(RP, refused.subject());
        this.events.assertNoJwtIn();
    }

    @Test
    void aBlankOrNonNumericPerClientSettingFallsBackInsteadOfFailing() {
        Federation f = federation();
        Map<String, Object> extra = new HashMap<>();
        extra.put("extproperties.trust_chain_leaf_max_time", "");
        extra.put("extproperties.trust_chain_trustanchor_max_time", "null");
        extra.put("extproperties.trust_chain_request_max_age", "soon");

        assertTrue(OIDFederationUtils.validateTrustChain(criteria(RP, assertionCarrying(f, f.chain(RP, TA)), extra)));
    }

    @Test
    void longSettingReadsEveryShape() {
        AttributeValue v = mock(AttributeValue.class);
        when(v.getValue()).thenReturn("120");
        Map<String, Object> in = new HashMap<>();
        in.put("a", v);
        in.put("b", 30);
        in.put("c", null);
        assertEquals(120L, OIDFederationUtils.longSetting(in, "a", -1L));
        assertEquals(30L, OIDFederationUtils.longSetting(in, "b", -1L));
        assertEquals(-1L, OIDFederationUtils.longSetting(in, "c", -1L));
        assertEquals(7L, OIDFederationUtils.longSetting(in, "absent", 7L));
    }

    @Test
    void aRefusalIsNamedByWhatRefusedIt() {
        assertEquals("signature", OIDFederationUtils.refusalReason(new TrustChainValidationException(
                TrustChainValidationException.Kind.SIGNATURE, null, null, "x")));
        assertEquals("expired", OIDFederationUtils.refusalReason(
                new JwtVerificationException(JwtVerificationException.Reason.EXPIRED)));
        assertEquals("invalid", OIDFederationUtils.refusalReason(new IllegalArgumentException("x")));
    }
}
