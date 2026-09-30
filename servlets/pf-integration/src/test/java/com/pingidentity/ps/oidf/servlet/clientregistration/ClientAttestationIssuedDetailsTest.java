package com.pingidentity.ps.oidf.servlet.clientregistration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.pingidentity.ps.oidf.clientattestation.ClientAttestationException;
import com.pingidentity.ps.oidf.conformance.Requirement;
import com.pingidentity.ps.oidf.pf.BridgeSigners;
import com.pingidentity.ps.oidf.pf.FederationRuntimeConfig;
import com.pingidentity.ps.oidf.rar.model.Json;
import com.pingidentity.ps.oidf.rar.model.RarModels;
import com.pingidentity.ps.oidf.servlet.clientregistration.utils.AttestationPolicyResolver;
import com.pingidentity.ps.oidf.servlet.clientregistration.utils.ClientAttestationUtils;
import com.pingidentity.ps.oidf.servlet.clientregistration.utils.SubjectTokenVerifier;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;
import org.jose4j.jwk.EcJwkGenerator;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.NumericDate;
import org.jose4j.keys.EllipticCurves;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.ArgumentCaptor;

/**
 * Plan item S4d (F-0032): what the filter forwards to PingFederate at each endpoint it is mapped over.
 *
 * <p>PingFederate issues the details stored at PAR, CIBA and the device authorization endpoint whatever the token
 * request says (U-0019, seen on the rig on 2026-09-30), so the filter holds a request's {@code authorization_details}
 * to the attestation's where they arrive: it grants {@code authorize(requested, ceiling, INHERIT)} and forwards the
 * granted details, never the request's. Requests that ask for none forward none. A signed request object, which cannot
 * be rewritten, is held to the ceiling as it stands. Introspection and revocation authenticate and bridge only. At the
 * authorization endpoint, an attestation-required client's details that did not come through PAR are refused with a
 * page.
 */
class ClientAttestationIssuedDetailsTest {
    private static final String ATTESTER = "https://attester.example.com";
    private static final String CLIENT = "https://rp.example.com/agent-1";
    private static final String OTHER_CLIENT = "https://rp.example.com/plain";
    private static final String ISSUER = "https://as.example.com";
    private static final String AGENT = "agent-7";
    private static final String CEILING = "[{\"type\":\"sales_agent\",\"sales_regions\":[\"EMEA\",\"AMER\"],\"max_txn_eur\":500},"
            + "{\"type\":\"payment_initiation\",\"amount\":\"100.00\",\"currency\":\"EUR\",\"creditorName\":\"Merchant A\"}]";

    private PublicJsonWebKey attesterKey;
    private PublicJsonWebKey instanceKey;
    private PublicJsonWebKey clientKey;
    /** The clients whose attestation_required is true, for the policy resolver. */
    private final List<String> required = new ArrayList<>();
    private final AtomicInteger lookups = new AtomicInteger();
    private boolean managerDown;

    @BeforeEach
    void configure(@TempDir Path dir) throws Exception {
        attesterKey = ecKey("attester-1");
        instanceKey = ecKey("instance-1");
        clientKey = ecKey("client-1");
        Path keys = dir.resolve("bridge-keys.json");
        Files.writeString(keys, "{\"" + CLIENT + "\":{\"jwk\":" + ecKey("bridge-1").toJson(JsonWebKey.OutputControlLevel.INCLUDE_PRIVATE)
                + ",\"attesters\":[\"" + ATTESTER + "\"]}}");
        System.setProperty("oidf.bridge.signer.backing", "config");
        System.setProperty("oidf.bridge.signing.keys", keys.toString());
        Path attesters = dir.resolve("mock-attesters.json");
        Files.writeString(attesters, "{\"" + ATTESTER + "\":{\"keys\":[" + attesterKey.toJson(JsonWebKey.OutputControlLevel.PUBLIC_ONLY)
                + "]}}");
        System.setProperty("oidf.mock.attesters", attesters.toString());
        System.setProperty("oidf.federation.trust.controller.host", "https://trust-controller.example.com");
        resetSingletons();
    }

    @AfterEach
    void clear() throws Exception {
        System.clearProperty("oidf.bridge.signer.backing");
        System.clearProperty("oidf.bridge.signing.keys");
        System.clearProperty("oidf.mock.attesters");
        System.clearProperty("oidf.federation.trust.controller.host");
        resetSingletons();
    }

    private static void resetSingletons() throws Exception {
        FederationRuntimeConfig.resetForTests();
        java.lang.reflect.Method bridge = BridgeSigners.class.getDeclaredMethod("resetForTest");
        bridge.setAccessible(true);
        bridge.invoke(null);
        java.lang.reflect.Method mock = ClientAttestationUtils.class.getDeclaredMethod("resetMockAttesterResolverForTest");
        mock.setAccessible(true);
        mock.invoke(null);
    }

    private static PublicJsonWebKey ecKey(String kid) throws Exception {
        PublicJsonWebKey key = EcJwkGenerator.generateJwk(EllipticCurves.P256);
        key.setKeyId(kid);
        return key;
    }

    private static String sign(PublicJsonWebKey key, String typ, String payload) throws Exception {
        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(payload);
        jws.setKey(key.getPrivateKey());
        jws.setAlgorithmHeaderValue("ES256");
        jws.setHeader("typ", typ);
        return jws.getCompactSerialization();
    }

    /** A Client Attestation for {@link #CLIENT} whose authorization_details is {@code ceiling} as written (null: none). */
    private String attestation(String ceiling) throws Exception {
        long now = NumericDate.now().getValue();
        return sign(attesterKey, "oauth-client-attestation+jwt", "{\"iss\":\"" + ATTESTER + "\",\"sub\":\"" + CLIENT + "\",\"iat\":" + now
                + ",\"exp\":" + (now + 600) + ",\"agent_id\":\"" + AGENT + "\",\"cnf\":{\"jwk\":"
                + instanceKey.toJson(JsonWebKey.OutputControlLevel.PUBLIC_ONLY) + "}"
                + (ceiling == null ? "" : ",\"authorization_details\":" + ceiling) + "}");
    }

    private String pop() throws Exception {
        JwtClaims c = new JwtClaims();
        c.setIssuer(CLIENT);
        c.setAudience(ISSUER);
        c.setJwtId(UUID.randomUUID().toString());
        c.setIssuedAtToNow();
        return sign(instanceKey, "oauth-client-attestation-pop+jwt", c.toJson());
    }

    /** A request object signed by the client (never verified by the filter), with {@code details} as its claim. */
    private String requestObject(String details) throws Exception {
        return sign(clientKey, "oauth-authz-req+jwt", "{\"iss\":\"" + CLIENT + "\",\"aud\":\"" + ISSUER + "\",\"client_id\":\"" + CLIENT
                + "\",\"response_type\":\"code\"" + (details == null ? "" : ",\"authorization_details\":" + details) + "}");
    }

    /** A POST to {@code path}, with the attestation headers when {@code attestation} is not null. */
    private static HttpServletRequest request(String path, String attestation, String pop, Map<String, String[]> params) {
        HttpServletRequest req = mock(HttpServletRequest.class);
        when(req.getHeaders("OAuth-Client-Attestation"))
                .thenReturn(Collections.enumeration(attestation == null ? List.of() : List.of(attestation)));
        when(req.getHeaders("OAuth-Client-Attestation-PoP")).thenReturn(Collections.enumeration(pop == null ? List.of() : List.of(pop)));
        when(req.getHeaders("DPoP")).thenReturn(Collections.emptyEnumeration());
        when(req.getRequestURI()).thenReturn(path);
        when(req.getContextPath()).thenReturn("");
        when(req.getServletPath()).thenReturn(path);
        when(req.getMethod()).thenReturn("POST");
        when(req.getParameterMap()).thenReturn(params);
        when(req.getParameter(org.mockito.ArgumentMatchers.anyString())).thenAnswer(inv -> {
            String[] v = params.get((String) inv.getArgument(0));
            return v == null ? null : v[0];
        });
        when(req.getParameterValues(org.mockito.ArgumentMatchers.anyString())).thenAnswer(inv -> params.get((String) inv.getArgument(0)));
        return req;
    }

    private static Map<String, String[]> params(String... nameValues) {
        Map<String, String[]> params = new LinkedHashMap<>();
        for (int i = 0; i < nameValues.length; i += 2) {
            params.put(nameValues[i], new String[]{nameValues[i + 1]});
        }
        return params;
    }

    /** What the filter did with one request: the body it wrote, the status, and the request it forwarded if any. */
    private record Outcome(String body, Integer status, HttpServletRequest forwarded, HttpServletRequest original) {
        Map<?, ?> error() {
            return (Map<?, ?>) Json.parse(this.body);
        }
    }

    private ClientAttestationAuthFilter filter() throws Exception {
        AttestationPolicyResolver policies = AttestationPolicyResolver.over(clientId -> {
            this.lookups.incrementAndGet();
            if (this.managerDown) {
                throw new IllegalStateException("the client manager is down");
            }
            return this.required.contains(clientId) ? Map.of("attestation_required", List.of("true")) : Map.of();
        }, Clock.systemUTC(), () -> false);
        ClientAttestationAuthFilter filter = new ClientAttestationAuthFilter(r -> ISSUER, () -> null, ClientAttestationAuthFilter.NO_CLIENTS,
                policies, new SubjectTokenVerifier(() -> null));
        filter.init(null);
        return filter;
    }

    private Outcome run(ClientAttestationAuthFilter filter, HttpServletRequest req) throws Exception {
        StringWriter body = new StringWriter();
        HttpServletResponse resp = mock(HttpServletResponse.class);
        when(resp.getWriter()).thenReturn(new PrintWriter(body));
        FilterChain chain = mock(FilterChain.class);
        filter.doFilter(req, resp, chain);
        ArgumentCaptor<Integer> status = ArgumentCaptor.forClass(Integer.class);
        verify(resp, org.mockito.Mockito.atMost(1)).setStatus(status.capture());
        ArgumentCaptor<ServletRequest> forwarded = ArgumentCaptor.forClass(ServletRequest.class);
        verify(chain, org.mockito.Mockito.atMost(1)).doFilter(forwarded.capture(), any());
        return new Outcome(body.toString(), status.getAllValues().isEmpty() ? null : status.getValue(),
                forwarded.getAllValues().isEmpty() ? null : (HttpServletRequest) forwarded.getValue(), req);
    }

    private Outcome attested(String path, String ceiling, Map<String, String[]> params) throws Exception {
        return run(filter(), request(path, attestation(ceiling), pop(), params));
    }

    private static List<Map<String, Object>> details(String text) throws Exception {
        return RarModels.parseDetails(text);
    }

    // ---- INHERIT and the rewrite, at every endpoint that takes details --------------------------------------

    /** One row of the table: what the client asked for and what the filter forwards, against {@link #CEILING}. */
    private record Row(String requested, String granted) {
    }

    private static final List<Row> TABLE = List.of(
            // A constrained field left out takes the ceiling's value.
            new Row("[{\"type\":\"sales_agent\",\"sales_regions\":[\"EMEA\"]}]",
                    "[{\"type\":\"sales_agent\",\"sales_regions\":[\"EMEA\"],\"max_txn_eur\":500}]"),
            // Silence on every field is the whole of the ceiling's first entry of the type.
            new Row("[{\"type\":\"sales_agent\"}]", "[{\"type\":\"sales_agent\",\"sales_regions\":[\"EMEA\",\"AMER\"],\"max_txn_eur\":500}]"),
            // What the request names is kept, narrower than the ceiling.
            new Row("[{\"type\":\"sales_agent\",\"sales_regions\":[\"AMER\"],\"max_txn_eur\":20}]",
                    "[{\"type\":\"sales_agent\",\"sales_regions\":[\"AMER\"],\"max_txn_eur\":20}]"),
            // A limit sent without its unit gets the ceiling's, and the omitted string its value.
            new Row("[{\"type\":\"payment_initiation\",\"amount\":\"42.00\"}]",
                    "[{\"type\":\"payment_initiation\",\"amount\":\"42.00\",\"currency\":\"EUR\",\"creditorName\":\"Merchant A\"}]"),
            // Two details, each fitted and kept in order.
            new Row("[{\"type\":\"payment_initiation\"},{\"type\":\"sales_agent\",\"max_txn_eur\":1}]",
                    "[{\"type\":\"payment_initiation\",\"amount\":\"100.00\",\"currency\":\"EUR\",\"creditorName\":\"Merchant A\"},"
                            + "{\"type\":\"sales_agent\",\"sales_regions\":[\"EMEA\",\"AMER\"],\"max_txn_eur\":1}]"));

    @Test
    @Requirement({"ABCA-10 §7.6", "RFC9126 §2.1", "RFC9396 §6", "CAS §7.1"})
    void everyEndpointThatTakesDetailsForwardsTheGrantedDetailsInPlaceOfTheRequests() throws Exception {
        RarModels models = RarModels.builtIn();
        for (AttestedEndpoint endpoint : List.of(AttestedEndpoint.TOKEN, AttestedEndpoint.PAR, AttestedEndpoint.CIBA, AttestedEndpoint.DEVICE)) {
            for (Row row : TABLE) {
                Outcome o = attested(endpoint.path(), CEILING, params("authorization_details", row.requested(), "scope", "openid"));
                String where = endpoint + " " + row.requested();
                assertNotNull(o.forwarded(), where + ": " + o.body());
                String forwarded = o.forwarded().getParameter("authorization_details");
                assertNotEquals(row.requested(), forwarded, where + ": never the client's own text");
                List<Map<String, Object>> sent = details(forwarded);
                List<Map<String, Object>> expected = details(row.granted());
                for (Map<String, Object> detail : sent) {
                    assertEquals(AGENT, detail.remove(ClientAttestationAuthFilter.AGENT_MARKER), where + ": the verified agent rides in each");
                }
                assertEquals(Json.write(expected), Json.write(sent), where);
                assertTrue(models.contains(details(CEILING), sent), where + ": contains(ceiling, granted)");
                assertEquals(forwarded, o.forwarded().getParameterValues("authorization_details")[0]);
                assertEquals(1, o.forwarded().getParameterValues("authorization_details").length);
                assertEquals(forwarded, o.forwarded().getParameterMap().get("authorization_details")[0], where + ": the map agrees");
                assertEquals("openid", o.forwarded().getParameter("scope"), where + ": the rest is forwarded as sent");
                assertNotNull(o.forwarded().getParameter("client_assertion"), where + ": bridged");
            }
        }
    }

    @Test
    @Requirement({"RFC9396 §5", "RFC9396 §6", "CAS §7.1"})
    void aRequestOverTheCeilingIsRefusedAtEveryEndpointThatTakesDetails() throws Exception {
        for (AttestedEndpoint endpoint : List.of(AttestedEndpoint.TOKEN, AttestedEndpoint.PAR, AttestedEndpoint.CIBA, AttestedEndpoint.DEVICE)) {
            Outcome over = attested(endpoint.path(), CEILING, params("authorization_details", "[{\"type\":\"sales_agent\",\"max_txn_eur\":900}]"));
            assertNull(over.forwarded(), endpoint.toString());
            assertEquals(400, over.status());
            assertEquals("invalid_authorization_details", over.error().get("error"));
            assertEquals("authorization_details exceeds what the client attestation allows", over.error().get("error_description"));
            Outcome undeclared = attested(endpoint.path(), CEILING, params("authorization_details", "[{\"type\":\"sales_agent\",\"discount\":5}]"));
            assertEquals(400, undeclared.status(), endpoint + ": RFC 9396 §5, a field its type does not define");
            Outcome noCeiling = attested(endpoint.path(), null, params("authorization_details", "[{\"type\":\"sales_agent\"}]"));
            assertEquals(400, noCeiling.status(), endpoint + ": nothing is within an attestation with no details");
        }
    }

    /** F-0032: a request that asks for nothing at PAR or CIBA forwards nothing, so PingFederate stores nothing. */
    @Test
    @Requirement({"CAS §7.1", "RFC9126 §2.1"})
    void aCeilingedClientThatOmitsTheParameterAtParOrCibaForwardsNone() throws Exception {
        for (AttestedEndpoint endpoint : List.of(AttestedEndpoint.PAR, AttestedEndpoint.CIBA, AttestedEndpoint.DEVICE, AttestedEndpoint.TOKEN)) {
            for (Map<String, String[]> params : List.of(params("scope", "openid"), params("scope", "openid", "authorization_details", " "),
                    params("scope", "openid", "authorization_details", "[]"))) {
                Outcome o = attested(endpoint.path(), CEILING, params);
                assertNotNull(o.forwarded(), endpoint + ": " + o.body());
                assertNull(o.forwarded().getParameter("authorization_details"), endpoint + ": absent stays absent");
                assertFalse(o.forwarded().getParameterMap().containsKey("authorization_details"), endpoint.toString());
                assertNull(o.forwarded().getParameterValues("authorization_details"), endpoint.toString());
            }
        }
    }

    /** The older parameter is checked as it stands and forwarded as sent: it is never rewritten, so omission is not inherited. */
    @Test
    @Requirement("CAS §7.1")
    void theHarnessParameterIsHeldStrictlyAndForwardedAsSent() throws Exception {
        String within = "[{\"type\":\"sales_agent\",\"sales_regions\":[\"EMEA\"],\"max_txn_eur\":5}]";
        Outcome ok = attested(AttestedEndpoint.TOKEN.path(), CEILING, params(ClientAttestationAuthFilter.REQUESTED_ACCESS, within));
        assertEquals(within, ok.forwarded().getParameter(ClientAttestationAuthFilter.REQUESTED_ACCESS));
        assertNull(ok.forwarded().getParameter("authorization_details"));
        Outcome omitted = attested(AttestedEndpoint.TOKEN.path(), CEILING,
                params(ClientAttestationAuthFilter.REQUESTED_ACCESS, "[{\"type\":\"sales_agent\",\"sales_regions\":[\"EMEA\"]}]"));
        assertEquals(400, omitted.status(), "an omitted constrained field is not within, strictly");
    }

    /** RFC 6749 §3.2: "Request and response parameters MUST NOT be included more than once." */
    @Test
    @Requirement("RFC6749 §3.2")
    void aRepeatedDetailsParameterIsRefusedBeforeAnythingIsVerified() throws Exception {
        for (String name : List.of("authorization_details", ClientAttestationAuthFilter.REQUESTED_ACCESS, "request", "request_uri")) {
            Map<String, String[]> params = new LinkedHashMap<>();
            params.put(name, new String[]{"[{\"type\":\"sales_agent\"}]", "[{\"type\":\"sales_agent\"}]"});
            Outcome o = attested(AttestedEndpoint.PAR.path(), CEILING, params);
            assertEquals(400, o.status(), name);
            assertEquals("invalid_request", o.error().get("error"));
            assertEquals(name + " must not be sent more than once", o.error().get("error_description"));
            assertNull(o.forwarded());
        }
    }

    /** The context the RAR plugin reads is published wherever the plugin can be asked with the request in hand. */
    @Test
    @Requirement("CAS §7.1")
    void theAttestationContextIsPublishedAtParCibaAndTheDeviceEndpointAsAtTheTokenEndpoint() throws Exception {
        for (AttestedEndpoint endpoint : List.of(AttestedEndpoint.TOKEN, AttestedEndpoint.PAR, AttestedEndpoint.CIBA, AttestedEndpoint.DEVICE)) {
            Outcome o = attested(endpoint.path(), CEILING, params("authorization_details", "[{\"type\":\"sales_agent\"}]"));
            ArgumentCaptor<Object> context = ArgumentCaptor.forClass(Object.class);
            verify(o.original()).setAttribute(org.mockito.ArgumentMatchers.eq(ClientAttestationUtils.RAR_ATTESTATION_CONTEXT_ATTRIBUTE),
                    context.capture());
            assertEquals(AGENT, ((Map<?, ?>) context.getValue()).get("agent_id"), endpoint.toString());
        }
    }

    // ---- introspection and revocation: authentication only -------------------------------------------------------

    @Test
    @Requirement({"ABCA-10 §7.6", "ABCA-10 §7.5"})
    void introspectionAndRevocationAuthenticateAndBridgeAndCarryNoDetails() throws Exception {
        for (AttestedEndpoint endpoint : List.of(AttestedEndpoint.INTROSPECTION, AttestedEndpoint.REVOCATION)) {
            // Details there mean nothing: never checked (so not refused however wide) and never forwarded.
            Outcome o = attested(endpoint.path(), CEILING, params("token", "t-1", "authorization_details", "[{\"type\":\"sales_agent\",\"max_txn_eur\":9999}]"));
            assertNotNull(o.forwarded(), endpoint + ": " + o.body());
            assertEquals("t-1", o.forwarded().getParameter("token"));
            assertEquals(CLIENT, o.forwarded().getParameter("client_id"));
            assertEquals("urn:ietf:params:oauth:client-assertion-type:jwt-bearer", o.forwarded().getParameter("client_assertion_type"));
            assertNotNull(o.forwarded().getParameter("client_assertion"));
            assertNull(o.forwarded().getParameter("authorization_details"), endpoint.toString());
        }
    }

    /** attestation_required holds wherever a client authenticates, not only at the token endpoint. */
    @Test
    void anAttestationRequiredClientWithoutAnAttestationIsRefusedAtEveryEndpointThatAuthenticates() throws Exception {
        required.add(CLIENT);
        for (AttestedEndpoint endpoint : List.of(AttestedEndpoint.TOKEN, AttestedEndpoint.PAR, AttestedEndpoint.CIBA, AttestedEndpoint.DEVICE,
                AttestedEndpoint.INTROSPECTION, AttestedEndpoint.REVOCATION)) {
            Outcome o = run(filter(), request(endpoint.path(), null, null, params("client_id", CLIENT, "token", "t")));
            assertEquals(401, o.status(), endpoint.toString());
            assertEquals("invalid_client", o.error().get("error"));
            Outcome other = run(filter(), request(endpoint.path(), null, null, params("client_id", OTHER_CLIENT, "token", "t")));
            assertSame(other.original(), other.forwarded(), endpoint + ": a client with no attestation and no requirement is untouched");
        }
    }

    // ---- a signed request object: held to the ceiling as it stands -----------------------------------------------

    @Test
    @Requirement({"RFC9126 §2.1", "RFC9396 §5", "CAS §7.1"})
    void aRequestObjectWithinTheCeilingIsForwardedAsSigned() throws Exception {
        for (AttestedEndpoint endpoint : List.of(AttestedEndpoint.PAR, AttestedEndpoint.CIBA)) {
            String object = requestObject("[{\"type\":\"sales_agent\",\"sales_regions\":[\"EMEA\"],\"max_txn_eur\":100}]");
            Outcome o = attested(endpoint.path(), CEILING, params("request", object));
            assertNotNull(o.forwarded(), endpoint + ": " + o.body());
            assertEquals(object, o.forwarded().getParameter("request"), "not rewritten: its signature would break");
            Outcome none = attested(endpoint.path(), CEILING, params("request", requestObject(null)));
            assertNotNull(none.forwarded(), "a request object that asks for nothing passes");
            Outcome asString = attested(endpoint.path(), CEILING,
                    params("request", requestObject("\"[{\\\"type\\\":\\\"sales_agent\\\",\\\"sales_regions\\\":[\\\"AMER\\\"],\\\"max_txn_eur\\\":1}]\"")));
            assertNotNull(asString.forwarded(), "the claim as a string holding the array: " + asString.body());
        }
    }

    @Test
    @Requirement({"RFC9396 §5", "CAS §7.1"})
    void aRequestObjectOutsideTheCeilingOrOmittingAConstrainedFieldIsRefused() throws Exception {
        for (AttestedEndpoint endpoint : List.of(AttestedEndpoint.PAR, AttestedEndpoint.CIBA)) {
            for (String details : List.of("[{\"type\":\"sales_agent\",\"sales_regions\":[\"APAC\"],\"max_txn_eur\":1}]",
                    "[{\"type\":\"sales_agent\",\"sales_regions\":[\"EMEA\"]}]")) {
                Outcome o = attested(endpoint.path(), CEILING, params("request", requestObject(details)));
                assertNull(o.forwarded(), endpoint + " " + details);
                assertEquals(400, o.status());
                assertEquals("invalid_authorization_details", o.error().get("error"));
                assertEquals(GrantedDetails.EXCEEDS, o.error().get("error_description"));
            }
            // A marker it cannot overwrite is refused, not trusted.
            Outcome marked = attested(endpoint.path(), CEILING,
                    params("request", requestObject("[{\"type\":\"sales_agent\",\"sales_regions\":[\"EMEA\"],\"max_txn_eur\":1,\"_agent_id\":\"forged\"}]")));
            assertEquals(400, marked.status());
            assertEquals(GrantedDetails.MALFORMED, marked.error().get("error_description"));
            Outcome notDetails = attested(endpoint.path(), CEILING, params("request", requestObject("{\"type\":\"sales_agent\"}")));
            assertEquals(GrantedDetails.MALFORMED, notDetails.error().get("error_description"));
        }
    }

    @Test
    @Requirement("RFC9396 §5")
    void aRequestObjectTheFilterCannotReadIsRefused() throws Exception {
        String jwe = "eyJhbGciOiJSU0EtT0FFUCJ9.a.b.c.d";
        for (String object : List.of(jwe, "not-a-jwt", "e30.bm90LWpzb24.c2ln")) {
            Outcome o = attested(AttestedEndpoint.PAR.path(), CEILING, params("request", object));
            assertEquals(400, o.status(), object);
            assertEquals(GrantedDetails.INVALID_REQUEST_OBJECT, o.error().get("error"));
            assertEquals(GrantedDetails.UNREADABLE, o.error().get("error_description"));
        }
    }

    /** RFC 9126 §2.1: "The \"request_uri\" authorization request parameter is one exception, and it MUST NOT be provided." */
    @Test
    @Requirement("RFC9126 §2.1")
    void aRequestUriAtParIsRefused() throws Exception {
        Outcome o = attested(AttestedEndpoint.PAR.path(), CEILING, params("request_uri", "https://rp.example.com/ro"));
        assertEquals(400, o.status());
        assertEquals("invalid_request", o.error().get("error"));
        assertNull(o.forwarded());
    }

    @Test
    void theAttestationsOwnDetailsTheModelRefusesAreTheCredentialsFaultForARequestObject() {
        ClientAttestationException e = assertThrows(ClientAttestationException.class, () -> GrantedDetails.requestObjectWithin(
                RarModels.builtIn(), requestObject("[{\"type\":\"sales_agent\"}]"), attestation("[{\"type\":\"no-such-type\"}]")));
        assertEquals(ClientAttestationException.INVALID_CLIENT, e.error());
        assertThrows(com.pingidentity.ps.oidf.rar.model.RarModelException.class, () -> GrantedDetails.ceilingOf("a.b"));
        assertEquals(List.of(), GrantedDetails.requested("not json"));
        assertNull(GrantedDetails.payload(null));
    }

    // ---- the authorization endpoint: details an attestation-required client did not push ----------------------------

    private Outcome authorize(Map<String, String[]> params) throws Exception {
        return run(filter(), request(AttestedEndpoint.AUTHORIZATION.path(), null, null, params));
    }

    @Test
    @Requirement({"RFC9126 §2.1", "RFC9396 §5"})
    void anAttestationRequiredClientsDetailsWithoutParAreRefusedWithAPageNeverARedirect() throws Exception {
        required.add(CLIENT);
        List<Map<String, String[]>> refused = List.of(
                params("client_id", CLIENT, "response_type", "code", "redirect_uri", "https://rp.example.com/cb",
                        "authorization_details", "[{\"type\":\"sales_agent\"}]"),
                params("client_id", CLIENT, "request", requestObject("[{\"type\":\"sales_agent\"}]")),
                params("request", requestObject("[{\"type\":\"sales_agent\"}]")),
                params("client_id", CLIENT, "request", "eyJhbGciOiJSU0EtT0FFUCJ9.a.b.c.d"),
                params("client_id", CLIENT, "request_uri", "https://rp.example.com/request-object"));
        for (Map<String, String[]> params : refused) {
            Outcome o = authorize(params);
            assertNull(o.forwarded(), params.keySet().toString());
            assertEquals(400, o.status());
            assertTrue(o.body().contains(PushedDetailsRule.ERROR) && o.body().contains("pushed authorization request (PAR)"), o.body());
            assertTrue(o.body().contains("<html") || o.body().contains("<!DOCTYPE") || o.body().contains("<!doctype"), "a page: " + o.body());
        }
    }

    @Test
    void theAuthorizationEndpointPassesEverythingElse() throws Exception {
        required.add(CLIENT);
        String par = PushedDetailsRule.PAR_REFERENCE_PREFIX + "abc";
        for (Map<String, String[]> params : List.of(
                params("client_id", CLIENT, "request_uri", par),
                params("client_id", CLIENT, "response_type", "code", "scope", "openid"),
                params("client_id", CLIENT, "request", requestObject(null), "authorization_details", " "),
                params("client_id", OTHER_CLIENT, "authorization_details", "[{\"type\":\"sales_agent\"}]"))) {
            Outcome o = authorize(params);
            assertSame(o.original(), o.forwarded(), params.keySet() + ": " + o.body());
        }
        int before = lookups.get();
        authorize(params("client_id", CLIENT, "response_type", "code"));
        assertEquals(before, lookups.get(), "a request that asks for no details is never looked up");
    }

    @Test
    void aClientManagerThatCannotAnswerIs503AndABadPropertyIsRefused() throws Exception {
        managerDown = true;
        Outcome down = authorize(params("client_id", CLIENT, "authorization_details", "[{\"type\":\"sales_agent\"}]"));
        assertEquals(503, down.status());
        assertNull(down.forwarded());
        managerDown = false;
        AttestationPolicyResolver bad = AttestationPolicyResolver.over(id -> Map.of("attestation_required", List.of("maybe")),
                Clock.systemUTC(), () -> false);
        ClientAttestationAuthFilter filter = new ClientAttestationAuthFilter(r -> ISSUER, () -> null, ClientAttestationAuthFilter.NO_CLIENTS,
                bad, new SubjectTokenVerifier(() -> null));
        filter.init(null);
        Outcome o = run(filter, request(AttestedEndpoint.AUTHORIZATION.path(), null, null,
                params("client_id", CLIENT, "authorization_details", "[{\"type\":\"sales_agent\"}]")));
        assertEquals(400, o.status());
        assertNull(o.forwarded());
    }

    @Test
    void theErrorPageIsReadOnceAndFallsBackToTheBuiltInOne(@TempDir Path dir) throws Exception {
        ClientAttestationAuthFilter filter = filter();
        assertSame(filter.errorPage(), filter.errorPage(), "read once");
        System.setProperty("oidf.federation.error.page", dir.resolve("missing.html").toString());
        try {
            FederationRuntimeConfig.resetForTests();
            assertNotNull(filter().errorPage(), "an unreadable page is the built-in one");
        } finally {
            System.clearProperty("oidf.federation.error.page");
            FederationRuntimeConfig.resetForTests();
        }
    }

    // ---- which endpoint a path is ------------------------------------------------------------------------------

    @Test
    void eachMappedPathIsItsEndpointAndAnyOtherIsTheStrictest() {
        assertEquals(AttestedEndpoint.TOKEN, AttestedEndpoint.of("/as/token.oauth2"));
        assertEquals(AttestedEndpoint.PAR, AttestedEndpoint.of("/as/par.oauth2"));
        assertEquals(AttestedEndpoint.CIBA, AttestedEndpoint.of("/as/bc-auth.ciba"));
        assertEquals(AttestedEndpoint.DEVICE, AttestedEndpoint.of("/as/device_authz.oauth2"));
        assertEquals(AttestedEndpoint.INTROSPECTION, AttestedEndpoint.of("/as/introspect.oauth2"));
        assertEquals(AttestedEndpoint.REVOCATION, AttestedEndpoint.of("/as/revoke_token.oauth2"));
        assertEquals(AttestedEndpoint.AUTHORIZATION, AttestedEndpoint.of("/as/authorization.oauth2"));
        for (String other : java.util.Arrays.asList(null, "", "/as/other.oauth2", "/as/token.oauth2/")) {
            AttestedEndpoint e = AttestedEndpoint.of(other);
            assertEquals(AttestedEndpoint.OTHER, e);
            assertTrue(e.authenticates() && e.carriesDetails() && e.takesRequestObjects(), "never one that skips a check");
            assertNull(e.path());
        }
        assertFalse(AttestedEndpoint.INTROSPECTION.carriesDetails());
        assertFalse(AttestedEndpoint.AUTHORIZATION.authenticates());
        assertFalse(AttestedEndpoint.TOKEN.takesRequestObjects());
    }

    @Test
    void aPayloadIsReadOnlyFromACompactJwsWithAJsonObject() {
        Base64.Encoder b64 = Base64.getUrlEncoder().withoutPadding();
        String array = b64.encodeToString("{}".getBytes(StandardCharsets.UTF_8)) + "." + b64.encodeToString("[1]".getBytes(StandardCharsets.UTF_8)) + ".s";
        assertNull(GrantedDetails.payload(array));
        assertNull(GrantedDetails.payload("a.!!.c"));
        assertEquals(Map.of(), GrantedDetails.payload("e30.e30.c"));
    }
}
