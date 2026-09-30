package com.pingidentity.ps.oidf.servlet.clientregistration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.pingidentity.ps.oidf.conformance.Requirement;
import com.pingidentity.ps.oidf.pf.BridgeSigners;
import com.pingidentity.ps.oidf.pf.ClientStore;
import com.pingidentity.ps.oidf.pf.FederationRuntimeConfig;
import com.pingidentity.ps.oidf.platform.events.Event;
import com.pingidentity.ps.oidf.platform.events.Events;
import com.pingidentity.ps.oidf.servlet.clientregistration.utils.AttestationEvents;
import com.pingidentity.ps.oidf.servlet.clientregistration.utils.AttestationPolicyResolver;
import com.pingidentity.ps.oidf.servlet.clientregistration.utils.ClientAttestationPolicy;
import com.pingidentity.ps.oidf.servlet.clientregistration.utils.ClientAttestationUtils;
import com.pingidentity.ps.oidf.servlet.clientregistration.utils.SubjectTokenVerifier;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.function.Function;
import java.util.function.Supplier;
import org.jose4j.jwk.EcJwkGenerator;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.JsonWebKeySet;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.NumericDate;
import org.jose4j.keys.EllipticCurves;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.sourceid.oauth20.domain.Client;
import org.sourceid.oauth20.domain.ParamValues;
import org.sourceid.saml20.adapter.attribute.AttributeValue;

/**
 * One client attestation policy on both routes (plan item S4c, F-0009): {@link ClientAttestationAuthFilter} and the
 * OGNL criterion ({@code ClientAttestationUtils.validateClientAttestation}, idp-agentic-demo's only gate) are driven
 * over one table of client properties with real attestations and proofs, and must agree on every row. Then what only
 * the filter does: the client resolved from the unverified {@code sub}, {@code attestation_required}, the 503, and the
 * verified subject token (F-0074).
 */
class AttestationPolicyRoutesTest {
    private static final String ATTESTER = "https://attester.example.com";
    private static final String CLIENT = "https://rp.example.com/agent-1";
    private static final String ISSUER = "https://as.example.com";
    private static final String TOKEN_PATH = "/as/token.oauth2";
    private static final String TOKEN_ENDPOINT = ISSUER + TOKEN_PATH;
    private static final Function<HttpServletRequest, String> CONFIGURED_ISSUER = r -> ISSUER;
    private static final String TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange";

    private PublicJsonWebKey attesterKey;
    private PublicJsonWebKey instanceKey;
    private PublicJsonWebKey pingFederateKey;
    private final List<Event> events = new ArrayList<>();

    @BeforeEach
    void configure(@TempDir Path dir) throws Exception {
        attesterKey = ecKey("attester-1");
        instanceKey = ecKey("instance-1");
        pingFederateKey = ecKey("pf-1");
        Path keys = dir.resolve("bridge-keys.json");
        Files.writeString(keys, "{\"" + CLIENT + "\":{\"jwk\":"
                + ecKey("bridge-1").toJson(JsonWebKey.OutputControlLevel.INCLUDE_PRIVATE)
                + ",\"attesters\":[\"" + ATTESTER + "\"]}}");
        System.setProperty("oidf.bridge.signer.backing", "config");
        System.setProperty("oidf.bridge.signing.keys", keys.toString());
        Path attesters = dir.resolve("mock-attesters.json");
        Files.writeString(attesters, "{\"" + ATTESTER + "\":{\"keys\":["
                + attesterKey.toJson(JsonWebKey.OutputControlLevel.PUBLIC_ONLY) + "]}}");
        System.setProperty("oidf.mock.attesters", attesters.toString());
        System.setProperty("oidf.federation.trust.controller.host", "https://trust-controller.example.com");
        resetSingletons();
        Events.reset();
        Events.configure(this.events::add);
    }

    @AfterEach
    void clear() throws Exception {
        System.clearProperty("oidf.bridge.signer.backing");
        System.clearProperty("oidf.bridge.signing.keys");
        System.clearProperty("oidf.mock.attesters");
        System.clearProperty("oidf.federation.trust.controller.host");
        resetSingletons();
        Events.reset();
    }

    private static void resetSingletons() throws Exception {
        FederationRuntimeConfig.resetForTests();
        Method bridge = BridgeSigners.class.getDeclaredMethod("resetForTest");
        bridge.setAccessible(true);
        bridge.invoke(null);
        Method mock = ClientAttestationUtils.class.getDeclaredMethod("resetMockAttesterResolverForTest");
        mock.setAccessible(true);
        mock.invoke(null);
    }

    private static PublicJsonWebKey ecKey(String kid) throws Exception {
        PublicJsonWebKey key = EcJwkGenerator.generateJwk(EllipticCurves.P256);
        key.setKeyId(kid);
        return key;
    }

    private static String sign(PublicJsonWebKey key, String typ, JwtClaims claims, boolean jwkHeader) throws Exception {
        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(claims.toJson());
        jws.setKey(key.getPrivateKey());
        jws.setAlgorithmHeaderValue("ES256");
        if (typ != null) {
            jws.setHeader("typ", typ);
        }
        if (key.getKeyId() != null) {
            jws.setKeyIdHeaderValue(key.getKeyId());
        }
        if (jwkHeader) {
            jws.setJwkHeader((PublicJsonWebKey) JsonWebKey.Factory.newJwk(key.toParams(JsonWebKey.OutputControlLevel.PUBLIC_ONLY)));
        }
        return jws.getCompactSerialization();
    }

    private String attestation(String subject) throws Exception {
        JwtClaims c = new JwtClaims();
        c.setIssuer(ATTESTER);
        c.setSubject(subject);
        c.setIssuedAtToNow();
        c.setExpirationTime(NumericDate.fromSeconds(NumericDate.now().getValue() + 600L));
        c.setClaim("cnf", Map.of("jwk", instanceKey.toParams(JsonWebKey.OutputControlLevel.PUBLIC_ONLY)));
        return sign(attesterKey, "oauth-client-attestation+jwt", c, false);
    }

    private String pop(long age) throws Exception {
        JwtClaims c = new JwtClaims();
        c.setIssuer(CLIENT);
        c.setClaim("aud", ISSUER);
        c.setJwtId(UUID.randomUUID().toString());
        c.setIssuedAt(NumericDate.fromSeconds(NumericDate.now().getValue() - age));
        return sign(instanceKey, "oauth-client-attestation-pop+jwt", c, false);
    }

    private String dpop(String htu, long age) throws Exception {
        JwtClaims c = new JwtClaims();
        c.setClaim("htm", "POST");
        c.setClaim("htu", htu);
        c.setJwtId(UUID.randomUUID().toString());
        c.setIssuedAt(NumericDate.fromSeconds(NumericDate.now().getValue() - age));
        return sign(instanceKey, "dpop+jwt", c, true);
    }

    /** A POST to the token endpoint with these headers (null: absent) and parameters, keeping its attributes. */
    private static HttpServletRequest request(Map<String, String> headers, Map<String, String[]> parameters) {
        HttpServletRequest req = mock(HttpServletRequest.class);
        for (String name : List.of("OAuth-Client-Attestation", "OAuth-Client-Attestation-PoP", "DPoP")) {
            String value = headers.get(name);
            when(req.getHeaders(name)).thenAnswer(i -> Collections.enumeration(value == null ? List.of() : List.of(value)));
            when(req.getHeader(name)).thenReturn(value);
        }
        when(req.getHeader("Authorization")).thenReturn(headers.get("Authorization"));
        when(req.getRequestURI()).thenReturn(TOKEN_PATH);
        when(req.getContextPath()).thenReturn("");
        when(req.getServletPath()).thenReturn(TOKEN_PATH);
        when(req.getMethod()).thenReturn("POST");
        Map<String, String[]> params = new LinkedHashMap<>(parameters);
        params.putIfAbsent("grant_type", new String[]{"client_credentials"});
        when(req.getParameterMap()).thenReturn(params);
        when(req.getParameter(anyString())).thenAnswer(i -> {
            String[] v = params.get((String) i.getArgument(0));
            return v == null ? null : v[0];
        });
        when(req.getParameterValues(anyString())).thenAnswer(i -> params.get((String) i.getArgument(0)));
        Map<String, Object> attributes = new HashMap<>();
        when(req.getAttribute(anyString())).thenAnswer(i -> attributes.get(i.getArgument(0)));
        org.mockito.Mockito.doAnswer(i -> attributes.put(i.getArgument(0), i.getArgument(1))).when(req).setAttribute(anyString(), any());
        return req;
    }

    private static Map<String, String> headers(String attestation, String pop, String dpop) {
        Map<String, String> h = new HashMap<>();
        h.put("OAuth-Client-Attestation", attestation);
        h.put("OAuth-Client-Attestation-PoP", pop);
        h.put("DPoP", dpop);
        return h;
    }

    // ---- the client's properties --------------------------------------------------------------------------------

    private static Client client(String id, Map<String, String> properties) {
        Client client = new Client();
        client.setClientId(id);
        Map<String, ParamValues> params = new HashMap<>();
        properties.forEach((k, v) -> {
            ParamValues values = new ParamValues();
            values.setElements(List.of(v));
            params.put(k, values);
        });
        client.setExtendedParams(params);
        return client;
    }

    private static ClientStore store(Client... clients) {
        return new ClientStore() {
            @Override
            public void add(Client client) {
            }

            @Override
            public void update(Client client) {
            }

            @Override
            public Client get(String clientId) {
                for (Client c : clients) {
                    if (c.getClientId().equals(clientId)) {
                        return c;
                    }
                }
                return null;
            }

            @Override
            public Collection<Client> getAll() {
                return List.of(clients);
            }

            @Override
            public void disable(Client client) {
            }
        };
    }

    private static AttestationPolicyResolver resolver(ClientStore store) {
        return AttestationPolicyResolver.over(AttestationPolicyResolver.from(store), Clock.systemUTC(), () -> false);
    }

    private SubjectTokenVerifier pingFederateKeys() {
        return new SubjectTokenVerifier(() -> new JsonWebKeySet(this.pingFederateKey));
    }

    private ClientAttestationAuthFilter filter(ClientStore store) throws Exception {
        ClientAttestationAuthFilter filter = new ClientAttestationAuthFilter(CONFIGURED_ISSUER, () -> null, store, resolver(store),
                pingFederateKeys());
        filter.init(null);
        return filter;
    }

    /** What the filter answered, or "" when it forwarded the request. */
    private static String run(ClientAttestationAuthFilter filter, HttpServletRequest req, FilterChain chain, int[] status) throws Exception {
        StringWriter body = new StringWriter();
        HttpServletResponse resp = mock(HttpServletResponse.class);
        when(resp.getWriter()).thenReturn(new PrintWriter(body));
        org.mockito.Mockito.doAnswer(i -> status[0] = i.getArgument(0)).when(resp).setStatus(org.mockito.ArgumentMatchers.anyInt());
        filter.doFilter(req, resp, chain);
        return body.toString();
    }

    private static boolean criterion(HttpServletRequest request, AttestationPolicyResolver resolver, SubjectTokenVerifier tokens)
            throws Exception {
        Map<String, Object> in = new HashMap<>();
        AttributeValue requestValue = mock(AttributeValue.class);
        when(requestValue.getObjectValue()).thenReturn(request);
        in.put("context.HttpRequest", requestValue);
        AttributeValue clientValue = mock(AttributeValue.class);
        when(clientValue.getValue()).thenReturn(CLIENT);
        in.put("context.ClientId", clientValue);
        Method m = ClientAttestationUtils.class.getDeclaredMethod("validateClientAttestationInner", Object.class, Boolean.class,
                String.class, String.class, Function.class, Supplier.class, AttestationPolicyResolver.class, SubjectTokenVerifier.class);
        m.setAccessible(true);
        Supplier<String> noBase = () -> null;
        return (Boolean) m.invoke(null, in, false, "https://trust-controller.example.com", "https://trust-controller.example.com",
                CONFIGURED_ISSUER, noBase, resolver, tokens);
    }

    // ---- F-0009: one table, both routes ------------------------------------------------------------------------

    /** A row: the client's properties, the proof it sends, and whether it is accepted. */
    private record Row(String name, Map<String, String> properties, boolean dpopMode, long proofAge, String htu, boolean accepted) {
    }

    private static final List<Row> TABLE = List.of(
            new Row("no properties, a fresh DPoP proof", Map.of(), true, 0, TOKEN_ENDPOINT, true),
            new Row("no properties, a fresh PoP", Map.of(), false, 0, null, true),
            new Row("a tighter DPoP age, a fresh proof", Map.of("attestation_dpop_max_age", "30"), true, 0, TOKEN_ENDPOINT, true),
            new Row("a tighter DPoP age, a proof older than it", Map.of("attestation_dpop_max_age", "30"), true, 120, TOKEN_ENDPOINT, false),
            new Row("a tighter PoP age, a proof older than it", Map.of("attestation_pop_max_age", "30"), false, 120, null, false),
            new Row("a DPoP age that loosens", Map.of("attestation_dpop_max_age", "600"), true, 0, TOKEN_ENDPOINT, false),
            new Row("a DPoP age that does not parse", Map.of("attestation_dpop_max_age", "soon"), true, 0, TOKEN_ENDPOINT, false),
            new Row("a skew that loosens", Map.of("attestation_clock_skew", "61"), true, 0, TOKEN_ENDPOINT, false),
            new Row("a tighter skew", Map.of("attestation_clock_skew", "5"), true, 0, TOKEN_ENDPOINT, true),
            new Row("DPoP algorithms narrowed to the proof's", Map.of("attestation_dpop_algs", "ES256,PS256"), true, 0, TOKEN_ENDPOINT, true),
            new Row("DPoP algorithms narrowed away from the proof's", Map.of("attestation_dpop_algs", "PS256"), true, 0, TOKEN_ENDPOINT, false),
            new Row("DPoP algorithms with nothing in common", Map.of("attestation_dpop_algs", "HS256"), true, 0, TOKEN_ENDPOINT, false),
            new Row("attestation algorithms narrowed away", Map.of("attestation_accepted_algs", "RS256"), true, 0, TOKEN_ENDPOINT, false),
            new Row("PoP algorithms narrowed to the proof's", Map.of("attestation_pop_algs", "ES256"), false, 0, null, true),
            new Row("an htu pin naming the token endpoint", Map.of("attestation_expected_htu", TOKEN_ENDPOINT), true, 0, TOKEN_ENDPOINT, true),
            new Row("an htu pin naming another server", Map.of("attestation_expected_htu", "https://other.example/as/token.oauth2"),
                    true, 0, "https://other.example/as/token.oauth2", false),
            new Row("a challenge required and none sent", Map.of("attestation_challenge_required", "true"), false, 0, null, false),
            new Row("a challenge flag that does not parse", Map.of("attestation_challenge_required", "yes"), false, 0, null, false),
            new Row("a required claim the attestation lacks", Map.of("attestation_required_claims", "workload"), true, 0, TOKEN_ENDPOINT, false));

    @Test
    @Requirement({"RFC9449 §4.3(9)", "ABCA-10 §4"})
    void theFilterAndTheCriterionApplyAClientsPropertiesAlike() throws Exception {
        List<String> disagreements = new ArrayList<>();
        for (Row row : TABLE) {
            ClientStore store = store(client(CLIENT, row.properties()));
            String proof = row.dpopMode() ? dpop(row.htu(), row.proofAge()) : pop(row.proofAge());
            HttpServletRequest atFilter = request(row.dpopMode() ? headers(attestation(CLIENT), null, proof)
                    : headers(attestation(CLIENT), proof, null), Map.of());
            FilterChain chain = mock(FilterChain.class);
            boolean filtered = run(filter(store), atFilter, chain, new int[1]).isEmpty();

            String proof2 = row.dpopMode() ? dpop(row.htu(), row.proofAge()) : pop(row.proofAge());
            HttpServletRequest atCriterion = request(row.dpopMode() ? headers(attestation(CLIENT), null, proof2)
                    : headers(attestation(CLIENT), proof2, null), Map.of());
            boolean criterion = criterion(atCriterion, resolver(store), pingFederateKeys());

            if (filtered != row.accepted() || criterion != row.accepted()) {
                disagreements.add(row.name() + ": expected " + row.accepted() + ", filter " + filtered + ", criterion " + criterion);
            }
        }
        assertEquals(List.of(), disagreements);
    }

    /** The rig check, unit-sized: a client with a DPoP age tighter than the server's is refused on the filter path. */
    @Test
    void aProofOlderThanTheClientsLimitIsRefusedAtTheFilterWith401AndAnEvent() throws Exception {
        ClientStore store = store(client(CLIENT, Map.of(ClientAttestationPolicy.DPOP_MAX_AGE, "30")));
        FilterChain chain = mock(FilterChain.class);
        int[] status = new int[1];
        String body = run(filter(store), request(headers(attestation(CLIENT), null, dpop(TOKEN_ENDPOINT, 120)), Map.of()), chain, status);
        assertEquals(401, status[0]);
        assertTrue(body.contains("invalid_client"), body);
        verify(chain, never()).doFilter(any(), any());
        Event refused = this.events.stream().filter(e -> e.code().equals(AttestationEvents.REFUSED)).findFirst().orElseThrow();
        assertEquals(CLIENT, refused.subject());
        assertEquals(AttestationEvents.FILTER, refused.fields().get("endpoint"));
    }

    @Test
    void aLooseningPropertyIsAGeneric401AndNamesThePropertyInTheEventOnly() throws Exception {
        ClientStore store = store(client(CLIENT, Map.of(ClientAttestationPolicy.DPOP_MAX_AGE, "3600")));
        int[] status = new int[1];
        String body = run(filter(store), request(headers(attestation(CLIENT), null, dpop(TOKEN_ENDPOINT, 0)), Map.of()),
                mock(FilterChain.class), status);
        assertEquals(401, status[0]);
        assertTrue(body.contains("\"error\":\"invalid_client\"") && body.contains("the client's attestation policy is not valid"), body);
        assertFalse(body.contains("3600") || body.contains("attestation_dpop_max_age"), body);
        Event invalid = this.events.stream().filter(e -> e.code().equals(AttestationEvents.POLICY_INVALID)).findFirst().orElseThrow();
        assertEquals(ClientAttestationPolicy.DPOP_MAX_AGE, invalid.fields().get("property"));
        assertEquals("loosens", invalid.reason());
        assertFalse(invalid.toString().contains("3600"), invalid.toString());
    }

    @Test
    void aVerifiedRequestIsAVerifiedEventAndCarriesThePolicyFingerprintTheCriterionAccepts() throws Exception {
        ClientStore store = store(client(CLIENT, Map.of(ClientAttestationPolicy.DPOP_MAX_AGE, "30")));
        HttpServletRequest req = request(headers(attestation(CLIENT), null, dpop(TOKEN_ENDPOINT, 0)), Map.of());
        FilterChain chain = mock(FilterChain.class);
        assertEquals("", run(filter(store), req, chain, new int[1]));
        @SuppressWarnings("unchecked")
        Map<String, Object> context = (Map<String, Object>) req.getAttribute(ClientAttestationUtils.VERIFIED_ATTESTATION_ATTRIBUTE);
        assertEquals(64, ((String) context.get(ClientAttestationUtils.POLICY_FINGERPRINT_KEY)).length());
        Event verified = this.events.stream().filter(e -> e.code().equals(AttestationEvents.VERIFIED)).findFirst().orElseThrow();
        assertEquals(ATTESTER, verified.partner());

        // The criterion on the same request reuses the verification under the same policy...
        assertTrue(criterion(req, resolver(store), pingFederateKeys()));
        // ...and refuses it when the client's properties say something else.
        assertFalse(criterion(req, resolver(store(client(CLIENT, Map.of(ClientAttestationPolicy.DPOP_MAX_AGE, "20")))),
                pingFederateKeys()));
    }

    // ---- the client, from the unverified sub ---------------------------------------------------------------------

    /**
     * draft-ietf-oauth-attestation-based-client-auth-10 §4: "sub: REQUIRED.  The sub (subject) claim MUST specify
     * client_id value of the OAuth Client." The policy is the one of the client the attestation names, read before it
     * is verified; the verified sub must be that client.
     */
    @Test
    @Requirement("ABCA-10 §4")
    void theClientIsResolvedFromTheAttestationsSubBeforeItIsVerified() throws Exception {
        Client tight = client(CLIENT, Map.of(ClientAttestationPolicy.DPOP_MAX_AGE, "30"));
        Client loose = client("https://rp.example.com/other", Map.of());
        int[] status = new int[1];
        // A client_id parameter naming another client does not choose the policy: the attestation's sub does.
        String body = run(filter(store(tight, loose)), request(headers(attestation(CLIENT), null, dpop(TOKEN_ENDPOINT, 120)),
                Map.of("client_id", new String[]{"https://rp.example.com/other"})), mock(FilterChain.class), status);
        assertEquals(401, status[0]);
        assertTrue(body.contains("invalid_client"), body);

        assertNull(ClientAttestationAuthFilter.subjectChanged(CLIENT, CLIENT));
        assertTrue(ClientAttestationAuthFilter.subjectChanged(null, CLIENT).contains("not the client"));
        assertTrue(ClientAttestationAuthFilter.subjectChanged(CLIENT, "https://rp.example.com/other").contains("not the client"));
        assertTrue(ClientAttestationAuthFilter.subjectChanged(CLIENT, null).contains("not the client"));
        assertNull(ClientAttestationAuthFilter.unverifiedSubject("not a jwt"));
        assertNull(ClientAttestationAuthFilter.unverifiedSubject(null));
        assertNull(ClientAttestationAuthFilter.unverifiedSubject(" "));
        assertEquals(CLIENT, ClientAttestationAuthFilter.unverifiedSubject(attestation(CLIENT)));
        JwtClaims numeric = new JwtClaims();
        numeric.setClaim("sub", 7);
        assertNull(ClientAttestationAuthFilter.unverifiedSubject(sign(attesterKey, "JWT", numeric, false)));
    }

    @Test
    void aClientManagerThatCannotAnswerIs503NeverNoPolicy() throws Exception {
        ClientStore broken = new ClientStore() {
            @Override
            public void add(Client client) {
            }

            @Override
            public void update(Client client) {
            }

            @Override
            public Client get(String clientId) {
                throw new IllegalStateException("database down");
            }

            @Override
            public Collection<Client> getAll() {
                return List.of();
            }

            @Override
            public void disable(Client client) {
            }
        };
        int[] status = new int[1];
        String body = run(filter(broken), request(headers(attestation(CLIENT), null, dpop(TOKEN_ENDPOINT, 0)), Map.of()),
                mock(FilterChain.class), status);
        assertEquals(503, status[0]);
        assertTrue(body.contains("temporarily_unavailable"), body);
        status[0] = 0;
        body = run(filter(broken), request(Map.of(), Map.of("client_id", new String[]{CLIENT})), mock(FilterChain.class), status);
        assertEquals(503, status[0], "without an attestation too: whether the client requires one is unknown");
        assertFalse(criterion(request(headers(attestation(CLIENT), null, dpop(TOKEN_ENDPOINT, 0)), Map.of()), resolver(broken),
                pingFederateKeys()));
        assertTrue(this.events.stream().anyMatch(e -> e.code().equals(AttestationEvents.REFUSED)
                && "temporarily_unavailable".equals(e.reason()) && AttestationEvents.CRITERION.equals(e.fields().get("endpoint"))));
    }

    // ---- attestation_required ------------------------------------------------------------------------------------

    @Test
    void aClientThatRequiresAnAttestationIsRefusedWithoutOne() throws Exception {
        ClientStore store = store(client(CLIENT, Map.of(ClientAttestationPolicy.REQUIRED, "true")),
                client("ordinary", Map.of(ClientAttestationPolicy.DPOP_MAX_AGE, "not a number")));
        ClientAttestationAuthFilter filter = filter(store);
        String basic = "Basic " + Base64.getEncoder().encodeToString(
                (java.net.URLEncoder.encode(CLIENT, StandardCharsets.UTF_8) + ":secret").getBytes(StandardCharsets.UTF_8));
        JwtClaims assertion = new JwtClaims();
        assertion.setSubject(CLIENT);
        for (HttpServletRequest named : List.of(
                request(Map.of(), Map.of("client_id", new String[]{CLIENT})),
                request(Map.of("Authorization", basic), Map.of()),
                request(Map.of(), Map.of("client_assertion", new String[]{sign(instanceKey, "JWT", assertion, false)})))) {
            FilterChain chain = mock(FilterChain.class);
            int[] status = new int[1];
            String body = run(filter, named, chain, status);
            assertEquals(401, status[0]);
            assertTrue(body.contains("invalid_client") && body.contains("authenticates with a client attestation"), body);
            verify(chain, never()).doFilter(any(), any());
        }
        assertTrue(this.events.stream().filter(e -> e.code().equals(AttestationEvents.REFUSED)).count() >= 3);

        // A client that does not require one goes on to PingFederate, even with another property refused: that one is
        // refused when it sends an attestation.
        for (HttpServletRequest other : List.of(request(Map.of(), Map.of("client_id", new String[]{"ordinary"})),
                request(Map.of(), Map.of("client_id", new String[]{"unknown"})),
                request(Map.of("Authorization", "Basic !!!"), Map.of()),
                request(Map.of("Authorization", "Bearer x"), Map.of()),
                request(Map.of("Authorization", "Basic " + Base64.getEncoder().encodeToString("no-colon".getBytes(StandardCharsets.UTF_8))), Map.of()),
                request(Map.of(), Map.of()))) {
            FilterChain chain = mock(FilterChain.class);
            assertEquals("", run(filter, other, chain, new int[1]));
            verify(chain).doFilter(org.mockito.ArgumentMatchers.eq(other), any());
        }
    }

    /** The filter's own part of ATTESTATION_AUTH, as its init registered it. */
    private static com.pingidentity.ps.oidf.platform.health.ComponentParts.Part part(ClientAttestationAuthFilter filter) throws Exception {
        java.lang.reflect.Field field = ClientAttestationAuthFilter.class.getDeclaredField("part");
        field.setAccessible(true);
        return (com.pingidentity.ps.oidf.platform.health.ComponentParts.Part) field.get(filter);
    }

    @Test
    void aClientThatRequiresAnAttestationIsRefusedWhileAttestationIsDisabledOrFailed() throws Exception {
        // S9b: switched off or failed, the filter passes ordinary traffic on, but a client that authenticates only with an
        // attestation must not authenticate with its other credential instead.
        ClientStore store = store(client(CLIENT, Map.of(ClientAttestationPolicy.REQUIRED, "true")),
                client("ordinary", Map.of()));
        for (boolean disabled : new boolean[]{true, false}) {
            ClientAttestationAuthFilter filter = filter(store);
            if (disabled) {
                part(filter).disabled();
            } else {
                part(filter).failedConfig("injected by the test");
            }
            FilterChain chain = mock(FilterChain.class);
            int[] status = new int[1];
            String body = run(filter, request(Map.of(), Map.of("client_id", new String[]{CLIENT})), chain, status);
            assertEquals(401, status[0], disabled ? "disabled" : "failed");
            assertTrue(body.contains("invalid_client") && body.contains("authenticates with a client attestation"), body);
            verify(chain, never()).doFilter(any(), any());

            HttpServletRequest ordinary = request(Map.of(), Map.of("client_id", new String[]{"ordinary"}));
            FilterChain passes = mock(FilterChain.class);
            assertEquals("", run(filter, ordinary, passes, new int[1]));
            verify(passes).doFilter(org.mockito.ArgumentMatchers.eq(ordinary), any());
        }

        // A client store that cannot answer is 503 on the disabled path too: whether the client requires one is unknown.
        ClientStore broken = new ClientStore() {
            @Override
            public void add(Client client) {
            }

            @Override
            public void update(Client client) {
            }

            @Override
            public Client get(String clientId) {
                throw new IllegalStateException("database down");
            }

            @Override
            public Collection<Client> getAll() {
                return List.of();
            }

            @Override
            public void disable(Client client) {
            }
        };
        ClientAttestationAuthFilter filter = filter(broken);
        part(filter).disabled();
        FilterChain chain = mock(FilterChain.class);
        int[] status = new int[1];
        String body = run(filter, request(Map.of(), Map.of("client_id", new String[]{CLIENT})), chain, status);
        assertEquals(503, status[0]);
        assertTrue(body.contains("temporarily_unavailable"), body);
        verify(chain, never()).doFilter(any(), any());
    }

    @Test
    void anAttestationRequiredThatDoesNotParseIsRefused() throws Exception {
        ClientStore store = store(client(CLIENT, Map.of(ClientAttestationPolicy.REQUIRED, "sometimes")));
        int[] status = new int[1];
        String body = run(filter(store), request(Map.of(), Map.of("client_id", new String[]{CLIENT})), mock(FilterChain.class), status);
        assertEquals(401, status[0]);
        assertTrue(body.contains("the client's attestation policy is not valid"), body);
        assertTrue(this.events.stream().anyMatch(e -> e.code().equals(AttestationEvents.POLICY_INVALID)
                && ClientAttestationPolicy.REQUIRED.equals(e.fields().get("property"))));
    }

    @Test
    void theClientsARequestNamesAreReadInOrderWithoutRepeats() throws Exception {
        String basic = "Basic " + Base64.getEncoder().encodeToString("a%3Ab:pw".getBytes(StandardCharsets.UTF_8));
        assertEquals(List.of("x", "a%3Ab", "a:b"), new ArrayList<>(ClientAttestationAuthFilter.namedClients(
                request(Map.of("Authorization", basic), Map.of("client_id", new String[]{"x"})))));
        assertEquals(List.of("x"), new ArrayList<>(ClientAttestationAuthFilter.namedClients(
                request(Map.of("Authorization", "basic " + Base64.getEncoder().encodeToString("x:".getBytes(StandardCharsets.UTF_8))),
                        Map.of("client_id", new String[]{"x"}, "client_assertion", new String[]{"garbage"})))));
        assertEquals(List.of(), new ArrayList<>(ClientAttestationAuthFilter.namedClients(
                request(Map.of("Authorization", "Basic " + Base64.getEncoder().encodeToString(":pw".getBytes(StandardCharsets.UTF_8))),
                        Map.of("client_id", new String[]{" "})))));
        // A user that does not form-decode is still named as sent.
        String undecodable = "Basic " + Base64.getEncoder().encodeToString("bad%zz:pw".getBytes(StandardCharsets.UTF_8));
        assertEquals(List.of("bad%zz"), new ArrayList<>(ClientAttestationAuthFilter.namedClients(
                request(Map.of("Authorization", undecodable), Map.of()))));
        // A client_assertion names its sub and its iss.
        JwtClaims assertion = new JwtClaims();
        assertion.setIssuer("assertion-iss");
        assertion.setSubject("assertion-sub");
        assertEquals(List.of("assertion-sub", "assertion-iss"), new ArrayList<>(ClientAttestationAuthFilter.namedClients(
                request(Map.of(), Map.of("client_assertion", new String[]{sign(attesterKey, "JWT", assertion, false)})))));
    }

    // ---- F-0074: the subject token ---------------------------------------------------------------------------------

    private String subjectToken(PublicJsonWebKey key, String issuer, long expiresIn, String typ, Object act) throws Exception {
        JwtClaims c = new JwtClaims();
        c.setIssuer(issuer);
        c.setSubject("alice");
        c.setExpirationTime(NumericDate.fromSeconds(NumericDate.now().getValue() + expiresIn));
        if (act != null) {
            c.setClaim("act", act);
        }
        return sign(key, typ, c, false);
    }

    private Map<String, Object> publishedFor(String subjectToken, String... more) throws Exception {
        Map<String, String[]> params = new HashMap<>();
        params.put("grant_type", new String[]{TOKEN_EXCHANGE});
        String[] tokens = new String[1 + more.length];
        tokens[0] = subjectToken;
        System.arraycopy(more, 0, tokens, 1, more.length);
        params.put("subject_token", tokens);
        HttpServletRequest req = request(headers(attestation(CLIENT), null, dpop(TOKEN_ENDPOINT, 0)), params);
        assertEquals("", run(filter(store()), req, mock(FilterChain.class), new int[1]));
        @SuppressWarnings("unchecked")
        Map<String, Object> context = (Map<String, Object>) req.getAttribute(ClientAttestationUtils.RAR_ATTESTATION_CONTEXT_ATTRIBUTE);
        return context;
    }

    @Test
    void aSubjectTokenPingFederateSignedIsPublishedAsTheVerifiedSubject() throws Exception {
        Map<String, Object> context = publishedFor(subjectToken(pingFederateKey, ISSUER, 300, "at+jwt", null));
        assertEquals("alice", context.get(ClientAttestationUtils.VERIFIED_SUBJECT_TOKEN_KEY));
        assertEquals("alice", publishedFor(subjectToken(pingFederateKey, ISSUER, 300, null, null))
                .get(ClientAttestationUtils.VERIFIED_SUBJECT_TOKEN_KEY));
    }

    @Test
    void aForgedExpiredForeignOrRepeatedSubjectTokenPublishesNoSubject() throws Exception {
        String key = ClientAttestationUtils.VERIFIED_SUBJECT_TOKEN_KEY;
        assertFalse(publishedFor(subjectToken(ecKey("pf-1"), ISSUER, 300, "JWT", null)).containsKey(key), "another key, same kid");
        assertFalse(publishedFor(subjectToken(pingFederateKey, "https://other.example", 300, "JWT", null)).containsKey(key), "another issuer");
        assertFalse(publishedFor(subjectToken(pingFederateKey, ISSUER, -120, "JWT", null)).containsKey(key), "expired");
        assertFalse(publishedFor(subjectToken(pingFederateKey, ISSUER, 300, "entity-statement+jwt", null)).containsKey(key),
                "a federation statement PingFederate's keys signed");
        String good = subjectToken(pingFederateKey, ISSUER, 300, "JWT", null);
        assertFalse(publishedFor(good, good).containsKey(key), "sent twice");
        assertFalse(publishedFor("not.a.token").containsKey(key));
        // Not a token exchange: nothing is looked at.
        HttpServletRequest req = request(headers(attestation(CLIENT), null, dpop(TOKEN_ENDPOINT, 0)),
                Map.of("subject_token", new String[]{good}));
        run(filter(store()), req, mock(FilterChain.class), new int[1]);
        assertFalse(((Map<?, ?>) req.getAttribute(ClientAttestationUtils.RAR_ATTESTATION_CONTEXT_ATTRIBUTE)).containsKey(key));
    }

    @Test
    void theSubjectTokenVerifierFailsClosed() throws Exception {
        String good = subjectToken(pingFederateKey, ISSUER, 300, "JWT", null);
        assertNull(new SubjectTokenVerifier(() -> null).verify(good, ISSUER));
        assertNull(new SubjectTokenVerifier(JsonWebKeySet::new).verify(good, ISSUER));
        assertNull(new SubjectTokenVerifier(() -> {
            throw new IllegalStateException("no PingFederate");
        }).verify(good, ISSUER));
        assertNull(pingFederateKeys().verify(good, null));
        assertNull(pingFederateKeys().verify(good, " "));
        assertNull(pingFederateKeys().verify(null, ISSUER));
        assertNull(pingFederateKeys().verify(" ", ISSUER));
        assertNull(SubjectTokenVerifier.pingFederate().verify(good, ISSUER), "outside PingFederate the SDK cannot answer");
    }

    // ---- delegationActChain ----------------------------------------------------------------------------------------

    private static String actChain(HttpServletRequest request, SubjectTokenVerifier tokens) throws Exception {
        Map<String, Object> in = new HashMap<>();
        AttributeValue requestValue = mock(AttributeValue.class);
        when(requestValue.getObjectValue()).thenReturn(request);
        in.put("context.HttpRequest", requestValue);
        AttributeValue clientValue = mock(AttributeValue.class);
        when(clientValue.getValue()).thenReturn(CLIENT);
        in.put("context.ClientId", clientValue);
        Method m = ClientAttestationUtils.class.getDeclaredMethod("delegationActChain", Object.class, Function.class, SubjectTokenVerifier.class);
        m.setAccessible(true);
        return (String) m.invoke(null, in, CONFIGURED_ISSUER, tokens);
    }

    @Test
    void theActChainNestsOnlyAVerifiedSubjectTokensAct() throws Exception {
        Map<String, Object> prior = Map.of("sub", "https://agent.example/first");
        String verified = subjectToken(pingFederateKey, ISSUER, 300, "JWT", prior);
        String chain = actChain(request(Map.of(), Map.of("subject_token", new String[]{verified})), pingFederateKeys());
        assertTrue(chain.contains("\"act\":{\"sub\":\"https://agent.example/first\"}"), chain);

        String asString = subjectToken(pingFederateKey, ISSUER, 300, "JWT", org.jose4j.json.JsonUtil.toJson(prior));
        assertTrue(actChain(request(Map.of(), Map.of("subject_token", new String[]{asString})), pingFederateKeys())
                .contains("\"act\":{\"sub\":\"https://agent.example/first\"}"));

        String forged = subjectToken(ecKey("pf-1"), ISSUER, 300, "JWT", prior);
        String unverified = actChain(request(Map.of(), Map.of("subject_token", new String[]{forged})), pingFederateKeys());
        assertEquals("{\"sub\":\"" + CLIENT + "\"}", unverified, "only the acting party: " + unverified);
        assertFalse(actChain(request(Map.of(), Map.of("subject_token", new String[]{verified, verified})), pingFederateKeys()).contains("act"));
        assertFalse(actChain(request(Map.of(), Map.of()), pingFederateKeys()).contains("act"));
        String noAct = subjectToken(pingFederateKey, ISSUER, 300, "JWT", "not json {");
        assertFalse(actChain(request(Map.of(), Map.of("subject_token", new String[]{noAct})), pingFederateKeys()).contains("act"));
        String listAct = subjectToken(pingFederateKey, ISSUER, 300, "JWT", List.of("x"));
        assertFalse(actChain(request(Map.of(), Map.of("subject_token", new String[]{listAct})), pingFederateKeys()).contains("act"));
    }
}
