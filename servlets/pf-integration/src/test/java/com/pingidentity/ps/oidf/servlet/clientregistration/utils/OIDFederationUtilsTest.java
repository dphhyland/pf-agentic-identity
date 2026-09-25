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
import com.pingidentity.ps.oidf.federation.policy.DecisionPoint;
import com.pingidentity.ps.oidf.jose.HttpPostClient;
import com.pingidentity.ps.oidf.pf.FederationPolicySupport;
import com.pingidentity.ps.oidf.pf.FederationRuntimeConfig;
import com.pingidentity.ps.oidf.pf.FederationRuntimeConfig.PdpAuth;
import com.pingidentity.ps.oidf.pf.FederationRuntimeConfig.PdpMode;
import com.pingidentity.ps.oidf.pf.FederationRuntimeConfig.PdpSettings;
import jakarta.servlet.http.HttpServletRequest;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
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
        FederationPolicySupport.resetForTests();
        this.events.close();
    }

    /** An AuthZEN PDP asked about tokens, answering {@code decision} to every question. */
    private static void pdpAnswering(boolean decision) {
        PdpSettings d = PdpSettings.DEFAULTS;
        FederationPolicySupport.configure(new PdpSettings(PdpMode.AUTHZEN, "https://pdp.example.com", null, false, PdpAuth.NONE, null,
                d.authHeader(), false, false, 0L, d.connectTimeoutMs(), d.requestTimeoutMs(), false, null, Set.of(DecisionPoint.TOKEN_ISSUANCE)),
                (url, contentType, body, headers, accept) -> new HttpPostClient.Response(200, "{\"decision\": " + decision + "}", Map.of()),
                null, java.time.Clock.systemUTC());
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

    // ---- §12.3: the recorded registration expiry, checked with no network ------------------------------------

    private static Map<String, Object> expiringAt(long epochSeconds) {
        return Map.of(OIDFederationUtils.EXPIRES_AT_PROPERTY, Long.toString(epochSeconds));
    }

    @Test
    @Requirement("OIDFED §12.3(1)")
    void aClientPastItsRegistrationsExpiryIsRefusedAtIssuanceWhateverItsChainSays() {
        Federation f = federation();
        long past = java.time.Instant.now().getEpochSecond() - 1;

        boolean ok = OIDFederationUtils.validateTrustChain(criteria(RP, assertionCarrying(f, f.chain(RP, TA)), expiringAt(past)));

        assertFalse(ok);
        FederationEvent expired = this.events.only(FederationEvents.REGISTRATION_EXPIRED_AT_ISSUANCE);
        assertTrue(expired.audit());
        assertEquals(RP, expired.subject());
        assertEquals(Long.toString(past), expired.fields().get("expires_at"));
        assertEquals("refuse", expired.fields().get("enforcement"));
        assertEquals(List.of(), this.events.withCode(FederationEvents.CHAIN_VALIDATED), "refused before any chain is looked at");
    }

    @Test
    void aClientInsideItsRegistrationIsCheckedOnItsChain() {
        Federation f = federation();

        assertTrue(OIDFederationUtils.validateTrustChain(criteria(RP, assertionCarrying(f, f.chain(RP, TA)),
                expiringAt(java.time.Instant.now().getEpochSecond() + 600))));
        assertEquals(List.of(), this.events.withCode(FederationEvents.REGISTRATION_EXPIRED_AT_ISSUANCE));
    }

    @Test
    void aClientWithNoRecordedExpiryIsLeftToTheChainCheck() {
        assertFalse(OIDFederationUtils.registrationExpired(Map.of(), RP));
        assertFalse(OIDFederationUtils.registrationExpired(Map.of(OIDFederationUtils.EXPIRES_AT_PROPERTY, "soon"), RP));
        assertEquals(List.of(), this.events.events());
    }

    @Test
    void underLogAnExpiredRegistrationIsOnlyRecorded() {
        FederationRuntimeConfig.install(FederationRuntimeConfig.from(
                Map.of(FederationRuntimeConfig.REGISTRATION_EXPIRY_ENFORCEMENT_ENV, "log")::get, name -> null));

        assertFalse(OIDFederationUtils.registrationExpired(expiringAt(1L), RP));
        assertEquals("log", this.events.only(FederationEvents.REGISTRATION_EXPIRED_AT_ISSUANCE).fields().get("enforcement"));
    }

    // ---- the token-issuance decision point ----------------------------------------------------------

    @Test
    void aChainThatStandsStillNeedsThePolicyDecisionWhenTokensAreAskedAbout() {
        Federation f = federation();
        Map<String, Object> criteria = criteria(RP, assertionCarrying(f, f.chain(RP, TA)), Map.of());

        pdpAnswering(false);
        assertFalse(OIDFederationUtils.validateTrustChain(criteria));
        assertEquals("policy_denied", this.events.only(FederationEvents.TOKEN_REFUSED).reason());

        pdpAnswering(true);
        assertTrue(OIDFederationUtils.validateTrustChain(criteria));
    }

    @Test
    void theDecisionPointOnItsOwnSaysYesUnlessSomebodyDecidesAndRefuses() {
        Map<String, Object> criteria = criteria(RP, null, Map.of());
        OIDFederationUtils.useIssuerResolver(req -> OP);

        assertTrue(OIDFederationUtils.federationPolicy(criteria), "nobody decides tokens by default");
        pdpAnswering(false);
        assertFalse(OIDFederationUtils.federationPolicy(criteria));
        pdpAnswering(true);
        assertTrue(OIDFederationUtils.federationPolicy(criteria));
        assertFalse(OIDFederationUtils.federationPolicy("not a criteria map"), "anything unexpected fails closed");
    }
}
