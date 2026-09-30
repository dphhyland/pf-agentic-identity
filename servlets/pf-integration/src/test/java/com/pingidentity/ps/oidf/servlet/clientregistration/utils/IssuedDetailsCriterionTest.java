/*
 * The issued-details criterion: what an access-token mapping is about to issue, held to the attestation's ceiling, and
 * the bare refresh of a listed type sent back to be decided again.
 */
package com.pingidentity.ps.oidf.servlet.clientregistration.utils;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.pingidentity.ps.oidf.clientattestation.AttestationRarModels;
import com.pingidentity.ps.oidf.conformance.Requirement;
import com.pingidentity.ps.oidf.platform.component.ComponentSwitches;
import com.pingidentity.ps.oidf.platform.events.Event;
import com.pingidentity.ps.oidf.platform.events.Events;
import com.pingidentity.ps.oidf.rar.model.RarModelException;
import com.pingidentity.ps.oidf.rar.model.RarModels;
import jakarta.servlet.http.HttpServletRequest;
import java.io.File;
import java.math.BigDecimal;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.jose4j.json.JsonUtil;
import org.jose4j.jwk.EcJwkGenerator;
import org.jose4j.jwk.EllipticCurveJsonWebKey;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.NumericDate;
import org.jose4j.keys.EllipticCurves;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.sourceid.saml20.adapter.attribute.AttributeValue;

class IssuedDetailsCriterionTest {
    private static final String CLIENT = "client-1";
    private static final String TOKEN_PATH = "/as/token.oauth2";
    private static final String CEILING = "[{\"type\":\"sales_agent\",\"sales_regions\":[\"EMEA\",\"AMER\"],\"max_txn_eur\":500},"
            + "{\"type\":\"payment_initiation\",\"instructedAmount\":{\"currency\":\"EUR\",\"amount\":\"100.00\"}}]";
    private static final Set<String> LISTED = Set.of("payment_initiation", "account_information");

    private final List<Event> events = new ArrayList<>();

    @BeforeEach
    void capture() {
        Events.reset();
        Events.configure(e -> {
            if (IssuedDetailsCriterion.ISSUED_REFUSED.equals(e.code())) {
                this.events.add(e);
            }
        });
    }

    @AfterEach
    void release() throws Exception {
        Events.reset();
        IssuedDetailsCriterion.resetForTest();
        System.clearProperty("oidf.mock.attesters");
        invoke(ClientAttestationUtils.class, "resetMockAttesterResolverForTest");
        java.lang.reflect.Method reset = AttestationRarModels.class.getDeclaredMethod("resetForTest", Map.class);
        reset.setAccessible(true);
        reset.invoke(null, (Object) null);
    }

    private static void invoke(Class<?> owner, String name) throws Exception {
        java.lang.reflect.Method m = owner.getDeclaredMethod(name);
        m.setAccessible(true);
        m.invoke(null);
    }

    static String attestation(String details) {
        Base64.Encoder b64 = Base64.getUrlEncoder().withoutPadding();
        String claims = "{\"sub\":\"" + CLIENT + "\"" + (details == null ? "" : ",\"authorization_details\":" + details) + "}";
        return b64.encodeToString("{\"alg\":\"ES256\"}".getBytes(StandardCharsets.UTF_8)) + "."
                + b64.encodeToString(claims.getBytes(StandardCharsets.UTF_8)) + ".sig";
    }

    /** A token request as the criterion sees it. */
    static final class Req {
        final Map<String, String[]> params = new HashMap<>();
        final Map<String, List<String>> headers = new HashMap<>();
        final Map<String, Object> attributes = new HashMap<>();
        String path = TOKEN_PATH;

        Req grant(String grantType) {
            this.params.put("grant_type", new String[]{grantType});
            return this;
        }

        Req param(String name, String value) {
            this.params.put(name, new String[]{value});
            return this;
        }

        Req header(String name, String... values) {
            this.headers.put(name, List.of(values));
            return this;
        }

        /** The attestation header, and the filter's published verification for {@code client}. */
        Req verified(String ceiling, String client) {
            this.header("OAuth-Client-Attestation", attestation(ceiling));
            this.attributes.put(ClientAttestationUtils.VERIFIED_ATTESTATION_ATTRIBUTE, Map.of("client_id", client));
            return this;
        }

        HttpServletRequest build() {
            HttpServletRequest request = mock(HttpServletRequest.class);
            when(request.getParameter(anyString())).thenAnswer(i -> {
                String[] v = this.params.get((String) i.getArgument(0));
                return v == null ? null : v[0];
            });
            when(request.getParameterValues(anyString())).thenAnswer(i -> this.params.get((String) i.getArgument(0)));
            when(request.getHeaders(anyString())).thenAnswer(i -> Collections.enumeration(
                    this.headers.getOrDefault((String) i.getArgument(0), List.of())));
            when(request.getHeader(anyString())).thenAnswer(i -> {
                List<String> v = this.headers.get((String) i.getArgument(0));
                return v == null || v.isEmpty() ? null : v.get(0);
            });
            when(request.getAttribute(anyString())).thenAnswer(i -> this.attributes.get((String) i.getArgument(0)));
            doAnswer(i -> this.attributes.put(i.getArgument(0), i.getArgument(1))).when(request).setAttribute(anyString(), any());
            when(request.getServletPath()).thenAnswer(i -> this.path);
            when(request.getMethod()).thenReturn("POST");
            return request;
        }
    }

    /** The criteria context: the request, the client PingFederate authenticated, and the details about to be issued. */
    static Map<String, Object> context(HttpServletRequest request, String client, List<?> issued) {
        Map<String, Object> in = new HashMap<>();
        AttributeValue requestValue = mock(AttributeValue.class);
        when(requestValue.getObjectValue()).thenReturn(request);
        in.put("context.HttpRequest", requestValue);
        if (client != null) {
            in.put("context.ClientId", new AttributeValue(client));
        }
        if (issued != null) {
            List<String> texts = new ArrayList<>();
            for (Object o : issued) {
                texts.add(String.valueOf(o));
            }
            in.put("context.OAuthAuthorizationDetails", new AttributeValue(texts, issued));
        }
        return in;
    }

    /** A detail as PingFederate 13.1.3 hands it over: a LinkedHashMap, numbers as its JSON reader made them. */
    static Map<String, Object> detail(Object... pairs) {
        Map<String, Object> d = new LinkedHashMap<>();
        for (int i = 0; i < pairs.length; i += 2) {
            d.put((String) pairs[i], pairs[i + 1]);
        }
        return d;
    }

    static final Map<String, Object> EMEA_100 = detail("type", "sales_agent", "sales_regions", List.of("EMEA"), "max_txn_eur", 100);
    static final Map<String, Object> APAC_100 = detail("type", "sales_agent", "sales_regions", List.of("APAC"), "max_txn_eur", 100);
    static final Map<String, Object> EMEA_NO_LIMIT = detail("type", "sales_agent", "sales_regions", List.of("EMEA"));
    static final Map<String, Object> PAY_42 = detail("type", "payment_initiation", "instructedAmount",
            detail("currency", "EUR", "amount", "42.00"));
    static final Map<String, Object> ACCOUNTS = detail("type", "account_information", "accounts", List.of("acc-1"));

    private static IssuedDetailsCriterion.Collaborators with(AttestationPolicyResolver resolver, Set<String> redecide) {
        return new IssuedDetailsCriterion.Collaborators(r -> "https://as.example", () -> null, resolver,
                CriterionTesting.NO_SUBJECT_TOKENS, RarModels::builtIn, () -> redecide);
    }

    private static IssuedDetailsCriterion.Collaborators with() {
        return with(CriterionTesting.NO_CLIENTS, LISTED);
    }

    private static boolean decide(Req req, List<?> issued) {
        return IssuedDetailsCriterion.decide(context(req.build(), CLIENT, issued), IssuedDetailsCriterion.Engine.SERVING, with());
    }

    /**
     * U-0018 on the rig: each grant hands the criterion the details it is about to issue. Whatever the grant, a verified
     * attestation's ceiling holds them - CAS §7.1: "any authority granted in issued tokens is a subset of the
     * attestation's authorization_details".
     */
    @Test
    @Requirement({"CAS §7.1", "RFC9396 §7"})
    void everyGrantsIssuedDetailsAreHeldToTheCeiling() {
        String[][] grants = {{"client_credentials", null}, {"authorization_code", null},
                {"urn:openid:params:grant-type:ciba", null}, {"urn:ietf:params:oauth:grant-type:device_code", null},
                {"refresh_token", "[{\"type\":\"sales_agent\"}]"}, {"urn:ietf:params:oauth:grant-type:token-exchange", null}};
        for (String[] grant : grants) {
            for (Object[] row : new Object[][]{{List.of(EMEA_100), true}, {List.of(EMEA_100, PAY_42), true}, {List.of(), true},
                    {List.of(APAC_100), false}, {List.of(EMEA_NO_LIMIT), false}, {List.of(EMEA_100, APAC_100), false},
                    {List.of(detail("type", "sales_agent", "sales_regions", List.of("EMEA"), "max_txn_eur", 500.25)), false},
                    {List.of(detail("type", "sales_agent", "sales_regions", List.of("EMEA"), "max_txn_eur", 499.99)), true}}) {
                Req req = new Req().grant(grant[0]).verified(CEILING, CLIENT);
                if (grant[1] != null) {
                    req.param("authorization_details", grant[1]);
                }
                assertEquals(row[1], decide(req, (List<?>) row[0]), grant[0] + " " + row[0]);
            }
        }
        Event refused = this.events.get(0);
        assertEquals("exceeds_ceiling", refused.reason());
        assertEquals(Map.of("enforcer", "issuance_criterion", "detail_types", "sales_agent"), refused.fields());
        assertEquals(CLIENT, refused.subject());
    }

    /** No details issued: nothing to hold, and the refresh rule has nothing to send back. */
    @Test
    void nothingIssuedIsWithinAnything() {
        assertTrue(IssuedDetailsCriterion.decide(context(new Req().grant("refresh_token").verified(CEILING, CLIENT).build(), CLIENT, null),
                IssuedDetailsCriterion.Engine.SERVING, with()));
    }

    @Test
    void theMarkersAreNotAuthority() {
        Map<String, Object> marked = new LinkedHashMap<>(EMEA_100);
        marked.put("_agent_id", "agent-7");
        marked.put("_principal_sub", "alice");
        assertTrue(decide(new Req().grant("client_credentials").verified(CEILING, CLIENT), List.of(marked)));
    }

    @Test
    void aVerificationForAnotherClientHoldsNothingAndRefuses() {
        assertFalse(decide(new Req().grant("client_credentials").verified(CEILING, "someone-else"), List.of(EMEA_100)));
        assertFalse(IssuedDetailsCriterion.decide(context(new Req().grant("client_credentials").verified(CEILING, CLIENT).build(), null,
                List.of(EMEA_100)), IssuedDetailsCriterion.Engine.SERVING, with()));
        assertEquals("uncheckable", this.events.get(0).reason());
    }

    /** An attestation without authorization_details is an empty ceiling, as at the token gate. */
    @Test
    @Requirement("CAS §7.1")
    void anAttestationWithoutDetailsHoldsEveryDetailOut() {
        assertFalse(decide(new Req().grant("client_credentials").verified(null, CLIENT), List.of(EMEA_100)));
        assertTrue(decide(new Req().grant("client_credentials").verified(null, CLIENT), List.of()));
    }

    /** A request with no attestation: the criterion invents no ceiling, unless the client authenticates only with one. */
    @Test
    void withoutAnAttestationOnlyAnAttestationRequiredClientIsRefused() {
        assertTrue(decide(new Req().grant("client_credentials"), List.of(APAC_100)));
        AttestationPolicyResolver required = AttestationPolicyResolver.over(
                id -> Map.of(ClientAttestationPolicy.REQUIRED, List.of("true")), Clock.systemUTC(), () -> false);
        assertFalse(IssuedDetailsCriterion.decide(context(new Req().grant("client_credentials").build(), CLIENT, List.of()),
                IssuedDetailsCriterion.Engine.SERVING, with(required, LISTED)));
        assertEquals("attestation_required", this.events.get(0).reason());
        AttestationPolicyResolver unreadable = AttestationPolicyResolver.over(
                id -> Map.of(ClientAttestationPolicy.REQUIRED, List.of("maybe")), Clock.systemUTC(), () -> false);
        assertFalse(IssuedDetailsCriterion.decide(context(new Req().grant("client_credentials").build(), CLIENT, List.of()),
                IssuedDetailsCriterion.Engine.SERVING, with(unreadable, LISTED)));
        AttestationPolicyResolver down = AttestationPolicyResolver.over(id -> {
            throw new IllegalStateException("client manager down");
        }, Clock.systemUTC(), () -> false);
        assertFalse(IssuedDetailsCriterion.decide(context(new Req().grant("client_credentials").build(), CLIENT, List.of()),
                IssuedDetailsCriterion.Engine.SERVING, with(down, LISTED)));
        AttestationPolicyResolver otherBad = AttestationPolicyResolver.over(
                id -> Map.of(ClientAttestationPolicy.POP_MAX_AGE, List.of("soon")), Clock.systemUTC(), () -> false);
        assertTrue(IssuedDetailsCriterion.decide(context(new Req().grant("client_credentials").build(), CLIENT, List.of()),
                IssuedDetailsCriterion.Engine.SERVING, with(otherBad, LISTED)), "only attestation_required decides here");
    }

    /**
     * PingFederate asks the mapping's criteria where the authorization endpoint resumes too (the rig, 2026-09-30), where
     * no attestation is ever sent: an attestation-required client is decided at the token endpoint instead.
     */
    @Test
    void offTheTokenEndpointAnAttestationRequiredClientIsNotRefused() {
        AttestationPolicyResolver required = AttestationPolicyResolver.over(
                id -> Map.of(ClientAttestationPolicy.REQUIRED, List.of("true")), Clock.systemUTC(), () -> false);
        Req req = new Req();
        req.path = "/as/AbCd/resume/as/authorization.ping";
        assertTrue(IssuedDetailsCriterion.decide(context(req.build(), CLIENT, List.of(EMEA_100)), IssuedDetailsCriterion.Engine.SERVING,
                with(required, LISTED)));
    }

    /**
     * F-0105, the PLAN's decision 14: a refresh that sends no authorization_details, of a grant holding a listed type, is
     * refused, so the client repeats its details and PingFederate calls enrich (and the PDP) again. RFC 9396 §7: "If the
     * client does not specify the authorization_details token request parameters, the AS determines the resulting
     * authorization_details at its discretion."
     */
    @Test
    @Requirement({"RFC9396 §7", "RFC9396 §6"})
    void aBareRefreshOfAListedTypeIsSentBackToBeDecidedAgain() {
        for (Map<String, Object> listed : List.of(PAY_42, ACCOUNTS)) {
            Req bare = new Req().grant("refresh_token").verified(CEILING + "", CLIENT);
            assertFalse(decide(bare, List.of(listed)), listed.get("type") + " bare");
            Req bareUnattested = new Req().grant("refresh_token");
            assertFalse(decide(bareUnattested, List.of(listed)), listed.get("type") + " bare, no attestation");
        }
        assertEquals("redecide_on_refresh", this.events.get(0).reason());
        assertEquals("payment_initiation", this.events.get(0).fields().get("detail_types"));
        // Repeating the details is decided again, and held to the ceiling like any other.
        assertTrue(decide(new Req().grant("refresh_token").param("authorization_details", "[{\"type\":\"payment_initiation\"}]")
                .verified(CEILING, CLIENT), List.of(PAY_42)));
        // A type not listed, or an empty list, sends nothing back.
        assertTrue(decide(new Req().grant("refresh_token").verified(CEILING, CLIENT), List.of(EMEA_100)));
        assertTrue(IssuedDetailsCriterion.decide(context(new Req().grant("refresh_token").build(), CLIENT, List.of(PAY_42)),
                IssuedDetailsCriterion.Engine.SERVING, with(CriterionTesting.NO_CLIENTS, Set.of())));
        // Another grant with no parameter is not a refresh.
        assertTrue(decide(new Req().grant("authorization_code"), List.of(PAY_42)));
        // A blank parameter is no parameter.
        assertFalse(decide(new Req().grant("refresh_token").param("authorization_details", " "), List.of(PAY_42)));
    }

    @Test
    void theRedecideSettingDefaultsToPaymentAndAccountTypes() {
        IssuedDetailsCriterion.resetForTest();
        Set<String> read = IssuedDetailsCriterion.configuredRedecideTypes();
        assertEquals(Set.of("payment_initiation", "account_information"), read);
        assertSame(read, IssuedDetailsCriterion.configuredRedecideTypes(), "read once");
    }

    /** S9B's rule for criteria: a component that is not serving answers false, and nothing throws. */
    @Test
    void aFailedComponentRefusesEveryTokenAndADisabledOneOnlyAttestationTraffic() {
        HttpServletRequest plain = new Req().grant("client_credentials").build();
        assertFalse(IssuedDetailsCriterion.decide(context(plain, CLIENT, List.of()), IssuedDetailsCriterion.Engine.FAILED, with()));
        assertTrue(IssuedDetailsCriterion.decide(context(plain, CLIENT, List.of(APAC_100)), IssuedDetailsCriterion.Engine.DISABLED, with()));
        for (String header : List.of("OAuth-Client-Attestation", "OAuth-Client-Attestation-PoP")) {
            HttpServletRequest attested = new Req().grant("client_credentials").header(header, "x").build();
            assertFalse(IssuedDetailsCriterion.decide(context(attested, CLIENT, List.of()), IssuedDetailsCriterion.Engine.DISABLED, with()));
        }
        HttpServletRequest blank = new Req().grant("client_credentials").header("OAuth-Client-Attestation", " ").build();
        assertTrue(IssuedDetailsCriterion.decide(context(blank, CLIENT, List.of()), IssuedDetailsCriterion.Engine.DISABLED, with()));
    }

    @Test
    void theEngineCopysStateComesFromTheSwitchAndTheProfile() {
        for (Object[] row : new Object[][]{{ComponentSwitches.Kind.ENABLED, false, IssuedDetailsCriterion.Engine.SERVING},
                {ComponentSwitches.Kind.INFERRED, false, IssuedDetailsCriterion.Engine.SERVING},
                {ComponentSwitches.Kind.ENABLED, true, IssuedDetailsCriterion.Engine.FAILED},
                {ComponentSwitches.Kind.FAILED_CONFIG, false, IssuedDetailsCriterion.Engine.FAILED},
                {ComponentSwitches.Kind.DISABLED, true, IssuedDetailsCriterion.Engine.DISABLED}}) {
            ComponentSwitches.Verdict verdict = new ComponentSwitches.Verdict("ATTESTATION_AUTH", "OIDF_ATTESTATION_AUTH_ENABLED",
                    (ComponentSwitches.Kind) row[0], "");
            assertEquals(row[2], IssuedDetailsCriterion.Engine.of(verdict, (Boolean) row[1]), String.valueOf(row[0]));
        }
        IssuedDetailsCriterion.resetForTest();
        IssuedDetailsCriterion.Engine state = IssuedDetailsCriterion.engine();
        assertSame(state, IssuedDetailsCriterion.engine(), "read once");
    }

    /** The OGNL entry point never throws: whatever it is handed, a refusal is false. */
    @Test
    void theEntryPointAnswersFalseAndNeverThrows() {
        assertFalse(IssuedDetailsCriterion.withinCeiling(null));
        assertFalse(IssuedDetailsCriterion.withinCeiling("not a map"));
        assertFalse(IssuedDetailsCriterion.withinCeiling(new HashMap<>()), "no request: a NullPointerException, caught");
        assertFalse(IssuedDetailsCriterion.decide("not a map", IssuedDetailsCriterion.Engine.SERVING, with()));
    }

    /** Through the entry point itself, with this process's switches: a verified request within its ceiling passes. */
    @Test
    void theEntryPointDecidesAVerifiedRequest() {
        IssuedDetailsCriterion.resetForTest();
        Map<String, Object> in = context(new Req().grant("client_credentials").verified(CEILING, CLIENT).build(), CLIENT, List.of(EMEA_100));
        assertEquals(IssuedDetailsCriterion.engine() != IssuedDetailsCriterion.Engine.FAILED, IssuedDetailsCriterion.withinCeiling(in));
    }

    @Test
    void detailsThatCannotBeReadAreRefused() {
        assertFalse(decide(new Req().grant("client_credentials").verified(CEILING, CLIENT), List.of("{not json")));
        assertFalse(decide(new Req().grant("client_credentials").verified(CEILING, CLIENT), List.of(7)));
        assertEquals("uncheckable", this.events.get(0).reason());
        // JSON text of a detail is read as the detail.
        assertTrue(decide(new Req().grant("client_credentials").verified(CEILING, CLIENT),
                List.of("{\"type\":\"sales_agent\",\"sales_regions\":[\"EMEA\"],\"max_txn_eur\":100}")));
    }

    @Test
    void theIssuedDetailsAreTheAttributesObjectValues() throws Exception {
        assertEquals(List.of(), IssuedDetailsCriterion.issued(null));
        assertEquals(List.of(), IssuedDetailsCriterion.issued("not an attribute"));
        AttributeValue none = mock(AttributeValue.class);
        assertEquals(List.of(), IssuedDetailsCriterion.issued(none));
        AttributeValue nothing = mock(AttributeValue.class);
        when(nothing.getAllObjectValues()).thenReturn(null);
        assertEquals(List.of(), IssuedDetailsCriterion.issued(nothing));
        List<Object> withNull = new ArrayList<>();
        withNull.add(null);
        withNull.add(EMEA_100);
        assertEquals(List.of(EMEA_100), IssuedDetailsCriterion.issued(new AttributeValue(List.of("a", "b"), withNull)));
        assertNotSame(EMEA_100, IssuedDetailsCriterion.issued(new AttributeValue(List.of("a"), List.of(EMEA_100))).get(0));
    }

    @Test
    void theModelsNotLoadingRefuses() {
        IssuedDetailsCriterion.Collaborators broken = new IssuedDetailsCriterion.Collaborators(r -> "https://as.example", () -> null,
                CriterionTesting.NO_CLIENTS, CriterionTesting.NO_SUBJECT_TOKENS, () -> {
                    throw new IllegalStateException("the RAR containment models could not be loaded: bad document");
                }, () -> LISTED);
        assertFalse(IssuedDetailsCriterion.decide(context(new Req().grant("client_credentials").verified(CEILING, CLIENT).build(), CLIENT,
                List.of(EMEA_100)), IssuedDetailsCriterion.Engine.SERVING, broken));
    }

    @Test
    void theCheckItselfIsStrictAndNeverThrows() throws Exception {
        RarModels models = RarModels.builtIn();
        String jwt = attestation(CEILING);
        assertEquals(IssuedDetailsCriterion.Outcome.WITHIN, IssuedDetailsCriterion.held(models, jwt, List.of()));
        assertEquals(IssuedDetailsCriterion.Outcome.WITHIN, IssuedDetailsCriterion.held(models, jwt, List.of(EMEA_100)));
        assertEquals(IssuedDetailsCriterion.Outcome.EXCEEDS, IssuedDetailsCriterion.held(models, jwt, List.of(APAC_100)));
        assertEquals(IssuedDetailsCriterion.Outcome.WITHIN, IssuedDetailsCriterion.held(models, jwt,
                List.of(detail("type", "sales_agent", "sales_regions", List.of("EMEA"), "max_txn_eur", new BigDecimal("500.00")))));
        for (String bad : new String[]{null, " ", "a.b", "a." + Base64.getUrlEncoder().encodeToString("[1]".getBytes()) + ".c",
                "a.%%%.c", "a." + Base64.getUrlEncoder().encodeToString("{\"authorization_details\":{}}".getBytes()) + ".c"}) {
            assertEquals(IssuedDetailsCriterion.Outcome.UNCHECKABLE, IssuedDetailsCriterion.held(models, bad, List.of(EMEA_100)), bad);
        }
        assertEquals(IssuedDetailsCriterion.Outcome.UNCHECKABLE, IssuedDetailsCriterion.held(null, jwt, List.of(EMEA_100)));
        assertEquals(IssuedDetailsCriterion.Outcome.UNCHECKABLE, IssuedDetailsCriterion.held(models, jwt,
                List.of(detail("type", "no_such_type_in_production", "x", 1))), "an unmodelled type or field cannot be answered");
        assertEquals("exceeds_ceiling", IssuedDetailsCriterion.Outcome.EXCEEDS.reason());
        assertEquals(null, IssuedDetailsCriterion.Outcome.WITHIN.reason());
        assertThrows(RarModelException.class, () -> IssuedDetailsCriterion.ceilingOf("x"));
    }

    @Test
    void aRepeatedAttestationHeaderIsAttestedButCannotBeRead() {
        Req req = new Req().grant("client_credentials").header("OAuth-Client-Attestation", attestation(CEILING), attestation(CEILING));
        req.attributes.put(ClientAttestationUtils.VERIFIED_ATTESTATION_ATTRIBUTE, Map.of("client_id", CLIENT));
        assertFalse(decide(req, List.of(EMEA_100)));
        assertEquals(null, IssuedDetailsCriterion.singleHeader(new Req().build(), "X"));
    }

    /** A container that will not enumerate a header's values (getHeaders is null) has no value for it. */
    @Test
    void aHeaderTheContainerWillNotEnumerateIsAbsent() {
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getHeaders(anyString())).thenReturn(null);
        assertEquals(null, IssuedDetailsCriterion.singleHeader(request, "X"));
        assertFalse(IssuedDetailsCriterion.hasHeader(request, "X"));
    }

    @Test
    void aBareRefreshLooksPastADetailWithNoType() {
        assertEquals("payment_initiation", IssuedDetailsCriterion.bareRefreshOf(new Req().grant("refresh_token").build(),
                List.of(Map.of("x", 1), PAY_42), Set.of("payment_initiation")));
    }

    // --- The criterion's own route: no filter verified the request, so the criterion verifies it. ---

    private Req attested(Path dir, String ceiling, boolean popFromTheInstance) throws Exception {
        EllipticCurveJsonWebKey attester = EcJwkGenerator.generateJwk(EllipticCurves.P256);
        EllipticCurveJsonWebKey instance = EcJwkGenerator.generateJwk(EllipticCurves.P256);
        EllipticCurveJsonWebKey stranger = EcJwkGenerator.generateJwk(EllipticCurves.P256);
        Path trust = dir.resolve("mock-attesters.json");
        Files.writeString(trust, "{\"https://attester.example\":{\"keys\":[" + attester.toJson(JsonWebKey.OutputControlLevel.PUBLIC_ONLY) + "]}}");
        System.setProperty("oidf.mock.attesters", trust.toString());
        invoke(ClientAttestationUtils.class, "resetMockAttesterResolverForTest");
        JwtClaims a = new JwtClaims();
        a.setIssuer("https://attester.example");
        a.setSubject(CLIENT);
        a.setIssuedAtToNow();
        a.setExpirationTime(NumericDate.fromSeconds(NumericDate.now().getValue() + 600L));
        a.setClaim("cnf", Map.of("jwk", instance.toParams(JsonWebKey.OutputControlLevel.PUBLIC_ONLY)));
        a.setClaim("authorization_details", JsonUtil.parseJson("{\"d\":" + ceiling + "}").get("d"));
        JwtClaims p = new JwtClaims();
        p.setIssuer(CLIENT);
        p.setAudience("https://as.example");
        p.setJwtId(UUID.randomUUID().toString());
        p.setIssuedAtToNow();
        return new Req().grant("client_credentials")
                .header("OAuth-Client-Attestation", sign(attester, "oauth-client-attestation+jwt", a))
                .header("OAuth-Client-Attestation-PoP", sign(popFromTheInstance ? instance : stranger, "oauth-client-attestation-pop+jwt", p));
    }

    private static String sign(EllipticCurveJsonWebKey key, String typ, JwtClaims claims) throws Exception {
        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(claims.toJson());
        jws.setKey(key.getPrivateKey());
        jws.setAlgorithmHeaderValue("ES256");
        jws.setHeader("typ", typ);
        return jws.getCompactSerialization();
    }

    @Test
    @Requirement("CAS §7.1")
    void withNoFilterTheCriterionVerifiesTheAttestationItselfAndHoldsToIt(@TempDir Path dir) throws Exception {
        Req within = this.attested(dir, CEILING, true);
        HttpServletRequest request = within.build();
        assertTrue(IssuedDetailsCriterion.decide(context(request, CLIENT, List.of(EMEA_100)), IssuedDetailsCriterion.Engine.SERVING, with()));
        assertTrue(within.attributes.get(ClientAttestationUtils.VERIFIED_ATTESTATION_ATTRIBUTE) instanceof Map,
                "published, so validateClientAttestation reuses it rather than verifying twice");

        assertFalse(IssuedDetailsCriterion.decide(context(this.attested(dir, CEILING, true).build(), CLIENT, List.of(APAC_100)),
                IssuedDetailsCriterion.Engine.SERVING, with()));
        assertFalse(IssuedDetailsCriterion.decide(context(this.attested(dir, CEILING, false).build(), CLIENT, List.of(EMEA_100)),
                IssuedDetailsCriterion.Engine.SERVING, with()), "a proof from another key does not verify");
    }

    @Test
    void aCriterionRouteWhoseModelsCannotLoadRefuses(@TempDir Path dir) throws Exception {
        java.lang.reflect.Method reset = AttestationRarModels.class.getDeclaredMethod("resetForTest", Map.class);
        reset.setAccessible(true);
        reset.invoke(null, Map.of(RarModels.ENV_MODELS, "{not a models document"));
        assertFalse(IssuedDetailsCriterion.decide(context(this.attested(dir, CEILING, true).build(), CLIENT, List.of(EMEA_100)),
                IssuedDetailsCriterion.Engine.SERVING, with()));
    }

    /**
     * The engine's classloader has its own statics (docs/development/classloaders.md): a copy loaded apart from this
     * one loads its own models and answers from them (U-0110's result for the models), and its entry point still never
     * throws.
     */
    @Test
    void aCopyOnAnotherClassloaderChecksWithItsOwnModels() throws Exception {
        List<URL> urls = new ArrayList<>();
        for (String entry : System.getProperty("java.class.path").split(File.pathSeparator)) {
            urls.add(new File(entry).toURI().toURL());
        }
        try (URLClassLoader engine = new URLClassLoader(urls.toArray(new URL[0]), ClassLoader.getPlatformClassLoader())) {
            Class<?> criterion = engine.loadClass(IssuedDetailsCriterion.class.getName());
            assertNotSame(IssuedDetailsCriterion.class, criterion);
            Object models = engine.loadClass(RarModels.class.getName()).getMethod("builtIn").invoke(null);
            Object within = criterion.getMethod("held", engine.loadClass(RarModels.class.getName()), String.class, List.class)
                    .invoke(null, models, attestation(CEILING), List.of(EMEA_100));
            assertEquals("WITHIN", ((Enum<?>) within).name());
            Object exceeds = criterion.getMethod("held", engine.loadClass(RarModels.class.getName()), String.class, List.class)
                    .invoke(null, models, attestation(CEILING), List.of(APAC_100));
            assertEquals("EXCEEDS", ((Enum<?>) exceeds).name());
            assertEquals(Boolean.FALSE, criterion.getMethod("withinCeiling", Object.class).invoke(null, new HashMap<>()));
        }
    }
}
