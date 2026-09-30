package com.pingidentity.ps.oidf.servlet.trustanchor;

import com.pingidentity.ps.oidf.pf.testkit.OperatorRequests;
import com.pingidentity.ps.oidf.servlet.oauth.PublicErrorsAssert;
import com.pingidentity.ps.oidf.platform.pf.auth.OperatorTestKit;
import com.pingidentity.ps.oidf.platform.profile.DeploymentProfile;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.pingidentity.ps.oidf.authority.AuthoritySupport;
import com.pingidentity.ps.oidf.authority.EntityStatus;
import com.pingidentity.ps.oidf.authority.HostedEntity;
import com.pingidentity.ps.oidf.authority.HostingMode;
import com.pingidentity.ps.oidf.federation.testkit.EventCapture;
import com.pingidentity.ps.oidf.trustmark.TrustMarkSupport;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.PrintWriter;
import java.io.StringReader;
import java.io.StringWriter;
import java.time.Instant;
import java.util.List;
import java.util.Map;
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

/**
 * A SELF_SIGNED agent through the servlet: enrolled with its own public keys, publishing the Entity
 * Configuration it signed, served verbatim, and revoked. The authority holds no key for such an agent and
 * never signs for it.
 */
class HostedEntityServletSelfSignedTest {
    private static final String TOKEN = "admin-token";
    private static final String AUTHORITY = "https://pf.example";
    private static final String AGENT = AUTHORITY + "/federation/agents/a1";

    private EventCapture events;
    private EllipticCurveJsonWebKey agentKey;

    @BeforeEach
    void reset() throws Exception {
        this.events = EventCapture.install();
        AuthoritySupport.resetForTests();
        TrustMarkSupport.resetForTests();
        // As the authority servlet does at start-up; a self-signed agent must never reach this signer.
        AuthoritySupport.configureSigning(entity -> {
            throw new AssertionError("the authority never signs for a self-signed agent");
        }, AUTHORITY);
        this.agentKey = EcJwkGenerator.generateJwk(EllipticCurves.P256);
        this.agentKey.setKeyId(this.agentKey.calculateBase64urlEncodedThumbprint("SHA-256"));
    }

    @AfterEach
    void release() {
        this.events.close();
        AuthoritySupport.resetForTests();
        TrustMarkSupport.resetForTests();
    }

    private static final class Exchange {
        final HttpServletResponse response = mock(HttpServletResponse.class);
        final StringWriter body = new StringWriter();

        Exchange(String method, String pathInfo, String requestBody, boolean withToken) throws Exception {
            HttpServletRequest request = mock(HttpServletRequest.class);
            when(request.getMethod()).thenReturn(method);
            when(request.getRemoteAddr()).thenReturn("192.0.2.62");
            when(request.getServletPath()).thenReturn("/federation/agents");
            when(request.getPathInfo()).thenReturn(pathInfo);
            OperatorRequests.stub(request, "/federation/agents" + (pathInfo == null ? "" : pathInfo),
                    withToken ? "Bearer " + TOKEN : null, null);
            when(request.getReader()).thenReturn(new BufferedReader(new StringReader(requestBody == null ? "" : requestBody)));
            when(this.response.getWriter()).thenReturn(new PrintWriter(this.body));
            new HostedEntityServlet(OperatorTestKit.unconfigured(DeploymentProfile.DEVELOPMENT).withStaticBearer(TOKEN))
                    .service(request, this.response);
        }

        Exchange(String method, String pathInfo, String requestBody) throws Exception {
            this(method, pathInfo, requestBody, true);
        }

        Map<String, Object> json(int status) throws Exception {
            verify(this.response).setStatus(status);
            return JsonUtil.parseJson(this.body.toString());
        }

        String error(int status) throws Exception {
            verify(this.response).setStatus(status);
            return String.valueOf(JsonUtil.parseJson(this.body.toString()).get("error"));
        }
    }

    private String publicJwks() {
        Map<String, Object> jwk = new java.util.LinkedHashMap<>(this.agentKey.toParams(JsonWebKey.OutputControlLevel.PUBLIC_ONLY));
        jwk.remove("kid"); // the authority names it, by its RFC 7638 thumbprint
        return JsonUtil.toJson(Map.of("keys", List.of(jwk)));
    }

    private Map<String, Object> enrolSelfSigned() throws Exception {
        return new Exchange("POST", null, "{\"id\": \"a1\", \"hostingMode\": \"SELF_SIGNED\", \"federationJwks\": " + this.publicJwks() + "}")
                .json(201);
    }

    private String configuration(long exp, List<String> authorityHints) throws Exception {
        JwtClaims claims = new JwtClaims();
        claims.setIssuer(AGENT);
        claims.setSubject(AGENT);
        claims.setIssuedAt(NumericDate.fromSeconds(exp - 3600));
        claims.setExpirationTime(NumericDate.fromSeconds(exp));
        claims.setClaim("jwks", Map.of("keys", List.of(this.agentKey.toParams(JsonWebKey.OutputControlLevel.PUBLIC_ONLY))));
        claims.setClaim("authority_hints", authorityHints);
        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(claims.toJson());
        jws.setAlgorithmHeaderValue("ES256");
        jws.setHeader("typ", "entity-statement+jwt");
        jws.setKeyIdHeaderValue(this.agentKey.getKeyId());
        jws.setKey(this.agentKey.getPrivateKey());
        return jws.getCompactSerialization();
    }

    @Test
    void aSelfSignedAgentIsEnrolledWithItsOwnKeysAndToldWhereToPublish() throws Exception {
        Map<String, Object> created = this.enrolSelfSigned();

        assertEquals(AGENT, created.get("entityId"));
        assertEquals(AGENT + "/entity-configuration", created.get("publishUrl"));
        HostedEntity stored = AuthoritySupport.registry().find(AGENT).orElseThrow();
        assertEquals(HostingMode.SELF_SIGNED, stored.hostingMode());
        assertNull(stored.hostingKeyRef());
        assertEquals(Map.of(), stored.metadata(), "its own configuration carries its metadata");
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> keys = (List<Map<String, Object>>) stored.federationJwks().get("keys");
        assertEquals(this.agentKey.getKeyId(), keys.get(0).get("kid"));
    }

    @Test
    void theBankVouchesForASelfSignedAgentInItsOwnWords() throws Exception {
        // What device-enrolment sends: the agent's keys, and what the bank says about every such agent.
        Map<String, Object> vouched = Map.of("oauth_client", Map.of("description", "Reads balances. It cannot move money."));
        new Exchange("POST", null, "{\"id\": \"a1\", \"hostingMode\": \"SELF_SIGNED\", \"federationJwks\": " + this.publicJwks()
                + ", \"metadata\": " + JsonUtil.toJson(vouched) + "}").json(201);
        assertEquals(vouched, AuthoritySupport.registry().find(AGENT).orElseThrow().metadata());
    }

    @Test
    void anAuthoritySignedEnrolmentMaySayWhatItIs() throws Exception {
        Map<String, Object> created = new Exchange("POST", null,
                "{\"id\": \"a2\", \"hostingMode\": \"AUTHORITY_SIGNED\", \"hostingKeyRef\": \"k1\", \"metadata\": {\"oauth_client\": {}}}").json(201);
        assertEquals(null, created.get("publishUrl"), "the authority signs its configuration; there is nothing to publish");
        assertEquals(HostingMode.AUTHORITY_SIGNED, AuthoritySupport.registry().find(AUTHORITY + "/federation/agents/a2").orElseThrow().hostingMode());
    }

    @Test
    void anEnrolmentThatIsNotOneOfTheTwoHostingModesIsRefused() throws Exception {
        assertEquals("invalid_request", new Exchange("POST", null,
                "{\"id\": \"a1\", \"hostingMode\": \"SOMEONE_ELSE\", \"hostingKeyRef\": \"k1\", \"metadata\": {}}").error(400));
    }

    @Test
    void aSelfSignedAgentMayNotNameAKeyTheAuthorityHolds() throws Exception {
        assertEquals("invalid_request", new Exchange("POST", null, "{\"id\": \"a1\", \"hostingMode\": \"SELF_SIGNED\", \"hostingKeyRef\": \"k1\", "
                + "\"federationJwks\": " + this.publicJwks() + "}").error(400));
    }

    @Test
    void aSelfSignedAgentMustBringUsablePublicKeys() throws Exception {
        String privateKey = JsonUtil.toJson(Map.of("keys", List.of(this.agentKey.toParams(JsonWebKey.OutputControlLevel.INCLUDE_PRIVATE))));
        for (String jwks : List.of("\"not a key set\"", "{\"keys\": []}", "{\"keys\": [\"a string\"]}", privateKey, "{\"keys\": [{\"kty\": \"EC\"}]}")) {
            Exchange refused = new Exchange("POST", null, "{\"id\": \"a1\", \"hostingMode\": \"SELF_SIGNED\", \"federationJwks\": " + jwks + "}");
            assertEquals("invalid_request", refused.error(400), jwks);
        }
        assertTrue(AuthoritySupport.registry().find(AGENT).isEmpty(), "nothing was enrolled");
    }

    @Test
    void anAgentPublishesTheConfigurationItSignedAndIsServedExactlyThat() throws Exception {
        this.enrolSelfSigned();
        assertEquals("not_found", new Exchange("GET", "/a1/.well-known/openid-federation", null).error(404), "nothing published yet");

        String published = this.configuration(Instant.now().getEpochSecond() + 3600, List.of(AUTHORITY));
        verify(new Exchange("PUT", "/a1/entity-configuration", published, false).response).setStatus(204);
        Exchange served = new Exchange("GET", "/a1/.well-known/openid-federation", null);
        verify(served.response).setStatus(200);
        assertEquals(published, served.body.toString());
    }

    @Test
    void aPublicationThatDoesNotCheckOutIsRefused() throws Exception {
        this.enrolSelfSigned();
        long exp = Instant.now().getEpochSecond() + 3600;
        assertEquals("not_found", new Exchange("PUT", "/a1/something-else", "x", false).error(404));
        assertEquals("not_found", new Exchange("PUT", "/nobody/entity-configuration", this.configuration(exp, List.of(AUTHORITY)), false).error(404));
        assertEquals("invalid_entity_configuration",
                new Exchange("PUT", "/a1/entity-configuration", this.configuration(exp, List.of("https://elsewhere.example")), false).error(400));
    }

    /**
     * H-FED-4 (F-0046): a publication is refused before its signer is known, so whatever it carries - a JWS header's
     * {@code alg} or {@code kid}, a body no parser accepts, an entity id in the path - is the caller's own text, and
     * the answer is the code's fixed description and a reference, never that text. A store that cannot be read is a
     * server error that names nothing of the store.
     */
    @Test
    void aHostileMarkerNeverReachesAPublicationsRefusal() throws Exception {
        this.enrolSelfSigned();
        String marker = "hfede-marker-" + java.util.UUID.randomUUID();
        java.util.Base64.Encoder b64 = java.util.Base64.getUrlEncoder().withoutPadding();
        String header = b64.encodeToString(JsonUtil.toJson(Map.of("alg", marker, "kid", marker, "typ", "entity-statement+jwt"))
                .getBytes(java.nio.charset.StandardCharsets.UTF_8));
        String payload = b64.encodeToString(("{\"iss\":\"" + marker + "\"}").getBytes(java.nio.charset.StandardCharsets.UTF_8));
        long exp = Instant.now().getEpochSecond() + 3600;
        List<Map.Entry<String, Exchange>> refusals = new java.util.ArrayList<>();
        refusals.add(Map.entry("invalid_entity_configuration", new Exchange("PUT", "/a1/entity-configuration", header + "." + payload + ".c2ln", false)));
        refusals.add(Map.entry("invalid_entity_configuration", new Exchange("PUT", "/a1/entity-configuration", "not a JWS " + marker, false)));
        refusals.add(Map.entry("invalid_entity_configuration",
                new Exchange("PUT", "/a1/entity-configuration", this.configuration(exp, List.of("https://" + marker + ".example")), false)));
        refusals.add(Map.entry("not_found", new Exchange("PUT", "/" + marker + "/entity-configuration", this.configuration(exp, List.of(AUTHORITY)), false)));
        refusals.add(Map.entry("not_found", new Exchange("PUT", "/a1/" + marker, "x", false)));

        AuthoritySupport.resetForTests();
        javax.sql.DataSource unreachable = mock(javax.sql.DataSource.class);
        when(unreachable.getConnection()).thenThrow(new java.sql.SQLException("the database is down " + marker));
        AuthoritySupport.configureJdbcRegistry(unreachable);
        AuthoritySupport.configureSigning(entity -> {
            throw new AssertionError("nothing is signed on a publication");
        }, AUTHORITY);
        refusals.add(Map.entry("server_error", new Exchange("PUT", "/a1/entity-configuration", this.configuration(exp, List.of(AUTHORITY)), false)));

        for (Map.Entry<String, Exchange> refusal : refusals) {
            String body = refusal.getValue().body.toString();
            assertTrue(!body.contains(marker), body);
            PublicErrorsAssert.assertGeneric(refusal.getKey(), body);
        }
    }

    @Test
    void anAgentIsRevokedByTheAuthorityAlone() throws Exception {
        this.enrolSelfSigned();
        verify(new Exchange("DELETE", "/a1", null, false).response).setStatus(401);
        assertEquals("not_found", new Exchange("DELETE", "/Not A Slug", null).error(404));
        assertEquals("not_found", new Exchange("DELETE", "/nobody", null).error(404));

        verify(new Exchange("DELETE", "/a1", null).response).setStatus(204);
        assertEquals(EntityStatus.REVOKED, AuthoritySupport.registry().find(AGENT).orElseThrow().status());
        String actor = AuthoritySupport.registry().auditTrail(AGENT).get(AuthoritySupport.registry().auditTrail(AGENT).size() - 1).actor();
        assertTrue(actor.matches("admin:[0-9a-f]{8}"), "the revocation names its operator: " + actor);
        assertEquals("not_found", new Exchange("GET", "/a1/.well-known/openid-federation", null).error(404), "a revoked agent is not served");
    }

    @Test
    void aRevocationWithNoEntityIs404AndOneTheStoreCannotRecordIs500() throws Exception {
        assertEquals("not_found", new Exchange("DELETE", null, null).error(404), "the collection itself is not revocable");

        AuthoritySupport.resetForTests();
        javax.sql.DataSource unreachable = mock(javax.sql.DataSource.class);
        when(unreachable.getConnection()).thenThrow(new java.sql.SQLException("the database is down"));
        AuthoritySupport.configureJdbcRegistry(unreachable);
        AuthoritySupport.configureSigning(entity -> {
            throw new AssertionError("nothing is signed on a revocation");
        }, AUTHORITY);
        assertEquals("storage_failure", new Exchange("DELETE", "/a1", null).error(500));
        assertTrue(this.events.withCode("federation.hosted_entity.revoked").isEmpty(),
                "a revocation the store did not record is not announced");
    }
}
