package com.pingidentity.ps.oidf.servlet.trustanchor;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.pingidentity.ps.oidf.authority.AuthoritySupport;
import com.pingidentity.ps.oidf.authority.HostedEntity;
import com.pingidentity.ps.oidf.authority.JdbcHostedEntityRegistry;
import com.pingidentity.ps.oidf.federation.event.FederationEvents;
import com.pingidentity.ps.oidf.federation.testkit.EventCapture;
import com.pingidentity.ps.oidf.jose.JwsSigner;
import com.pingidentity.ps.oidf.federation.policy.DecisionPoint;
import com.pingidentity.ps.oidf.jose.HttpPostClient;
import com.pingidentity.ps.oidf.pf.FederationPolicySupport;
import com.pingidentity.ps.oidf.pf.FederationRuntimeConfig;
import com.pingidentity.ps.oidf.pf.FederationRuntimeConfig.PdpAuth;
import com.pingidentity.ps.oidf.pf.FederationRuntimeConfig.PdpMode;
import com.pingidentity.ps.oidf.pf.FederationRuntimeConfig.PdpSettings;
import com.pingidentity.ps.oidf.trustmark.TrustMarkSupport;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.PrintWriter;
import java.io.StringReader;
import java.io.StringWriter;
import java.util.Map;
import org.jose4j.json.JsonUtil;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/** Enrolling a hosted entity, and configuring this deployment as the authority that hosts it. */
class HostedEntityServletEnrolTest {
    private static final String TOKEN = "admin-token";
    private static final String AUTHORITY = "https://pf.example";

    private EventCapture events;

    @BeforeEach
    void reset() {
        this.events = EventCapture.install();
        AuthoritySupport.resetForTests();
        TrustMarkSupport.resetForTests();
    }

    @AfterEach
    void release() {
        this.events.close();
        AuthoritySupport.resetForTests();
        TrustMarkSupport.resetForTests();
        FederationRuntimeConfig.resetForTests();
        FederationPolicySupport.resetForTests();
    }

    private static void host(JwsSigner signer) {
        AuthoritySupport.configureSigning(entity -> {
            if (signer == null) {
                throw new IllegalStateException("vault down at https://bao.internal:8200");
            }
            return signer;
        }, AUTHORITY);
    }

    private static final JwsSigner SIGNER = new JwsSigner() {
        @Override
        public String algorithm() {
            return "ES256";
        }

        @Override
        public String keyId() {
            return "k1";
        }

        @Override
        public Map<String, Object> publicJwk() {
            return Map.of("kty", "EC", "crv", "P-256", "x", "abc", "y", "def", "kid", "k1");
        }

        @Override
        public byte[] sign(byte[] signingInput) {
            return new byte[64];
        }
    };

    private static final class Exchange {
        final HttpServletResponse response = mock(HttpServletResponse.class);
        final StringWriter body = new StringWriter();

        Exchange(String method, String pathInfo, String json) throws Exception {
            this(TOKEN, method, pathInfo, json);
        }

        Exchange(String servletToken, String method, String pathInfo, String json) throws Exception {
            HttpServletRequest request = mock(HttpServletRequest.class);
            when(request.getServletPath()).thenReturn("/federation/agents");
            when(request.getPathInfo()).thenReturn(pathInfo);
            when(request.getHeader("Authorization")).thenReturn("Bearer " + TOKEN);
            when(request.getHeader("X-Federation-Actor")).thenReturn("dave");
            when(request.getReader()).thenReturn(new BufferedReader(new StringReader(json == null ? "" : json)));
            when(this.response.getWriter()).thenReturn(new PrintWriter(this.body));
            HostedEntityServlet servlet = new HostedEntityServlet(servletToken);
            if ("POST".equals(method)) {
                servlet.doPost(request, this.response);
            } else {
                servlet.doGet(request, this.response);
            }
        }

        Map<String, Object> json(int status) throws Exception {
            verify(this.response).setStatus(status);
            return JsonUtil.parseJson(this.body.toString());
        }
    }

    private static String enrolment(String extra) {
        return "{\"id\": \"a1\", \"hostingKeyRef\": \"k1\", \"metadata\": {\"oauth_client\": {\"client_name\": \"Agent\"}}" + extra + "}";
    }

    @Test
    void anEntityIsEnrolledWithItsOwnPolicyAndWhoEnrolledIt() throws Exception {
        host(SIGNER);

        Map<String, Object> created = new Exchange("POST", null, enrolment(", \"metadataPolicy\": {\"oauth_client\": {\"scope\": {\"subset_of\": [\"read\"]}}}"))
                .json(201);

        String id = AUTHORITY + "/federation/agents/a1";
        assertEquals(id, created.get("entityId"));
        HostedEntity stored = AuthoritySupport.registry().find(id).orElseThrow();
        assertEquals(Map.of("oauth_client", Map.of("scope", Map.of("subset_of", java.util.List.of("read")))), stored.metadataPolicy());
        assertTrue(AuthoritySupport.registry().auditTrail(id).get(0).actor().endsWith("(dave)"));
        assertEquals(id, this.events.only(FederationEvents.HOSTED_ENTITY_ENROLLED).subject());
        assertEquals("duplicate", new Exchange("POST", "/", enrolment("")).json(409).get("error"));
    }

    @Test
    void aPolicyThatWouldNotComposeWithTheDomainDefaultIsRefusedAtEnrolment() throws Exception {
        host(SIGNER);
        AuthoritySupport.configureDomainDefaultMetadataPolicy(Map.of("oauth_client", Map.of("token_endpoint_auth_method",
                Map.of("value", "private_key_jwt"))));

        assertEquals("invalid_request", new Exchange("POST", null, enrolment(
                ", \"metadataPolicy\": {\"oauth_client\": {\"token_endpoint_auth_method\": {\"value\": \"none\"}}}")).json(400).get("error"));
        assertEquals("invalid_request", new Exchange("POST", null, enrolment(", \"metadataPolicy\": [1]")).json(400).get("error"));
        assertTrue(AuthoritySupport.registry().all().isEmpty());
    }

    @Test
    void aPolicyDecisionPointCanRefuseAnEnrolment() throws Exception {
        host(SIGNER);
        java.util.List<String> answers = new java.util.ArrayList<>(java.util.List.of(
                "{\"decision\": false, \"context\": {\"reason_admin\": \"no new agents this week\"}}", "{\"decision\": true}"));
        HttpPostClient pdp = (url, contentType, body, headers, accept) -> new HttpPostClient.Response(200, answers.remove(0), Map.of());
        PdpSettings d = PdpSettings.DEFAULTS;
        FederationPolicySupport.configure(new PdpSettings(PdpMode.AUTHZEN, "https://pdp.example.com", null, false, PdpAuth.NONE, null,
                d.authHeader(), false, false, 0L, d.connectTimeoutMs(), d.requestTimeoutMs(), false, null,
                java.util.Set.of(DecisionPoint.HOSTED_ENTITY_ENROL)), pdp, null, java.time.Clock.systemUTC());

        Map<String, Object> refused = new Exchange("POST", null, enrolment("")).json(403);

        assertEquals("access_denied", refused.get("error"));
        assertFalse(refused.toString().contains("this week"), "the administrator's reason stays in the logs");
        assertTrue(AuthoritySupport.registry().all().isEmpty());
        assertEquals("policy_denied", this.events.only(FederationEvents.HOSTED_ENTITY_REFUSED).reason());
        assertEquals(AUTHORITY + "/federation/agents/a1", new Exchange("POST", null, enrolment("")).json(201).get("entityId"));
    }

    /** A fault of the authority's shows nothing of itself - not the vault's address, not the database's. */
    @Test
    void aFaultIsAServerErrorThatShowsNothingOfTheFault() throws Exception {
        host(null);
        AuthoritySupport.registry().register(HostedEntity.hosted(AUTHORITY + "/federation/agents/a1", "k1", Map.of("oauth_client", Map.of()), null));

        Exchange resolving = new Exchange("GET", "/a1/.well-known/openid-federation", null);

        assertEquals("server_error", resolving.json(500).get("error"));
        assertFalse(resolving.body.toString().contains("bao.internal"), resolving.body.toString());
    }

    @Test
    void aStoreThatFailsAtEnrolmentShowsNothingOfTheFault() throws Exception {
        AuthoritySupport.configureJdbcRegistry((javax.sql.DataSource) java.lang.reflect.Proxy.newProxyInstance(
                javax.sql.DataSource.class.getClassLoader(), new Class<?>[]{javax.sql.DataSource.class}, (proxy, method, args) -> {
                    throw new java.sql.SQLException("connection refused to jdbc:postgresql://secret-host/idm");
                }));
        host(SIGNER);

        Exchange enrol = new Exchange("POST", null, enrolment(""));

        assertEquals("server_error", enrol.json(500).get("error"));
        assertFalse(enrol.body.toString().contains("secret-host"), enrol.body.toString());
    }

    // ---- configuring the authority ------------------------------------------------------------------

    @Test
    void withoutAnAuthorityEntityIdNothingIsHosted() {
        assertFalse(HostedEntityServlet.configureAuthority(name -> null));
        assertFalse(AuthoritySupport.isHostingConfigured());
    }

    /** The stores are configured before signing, or the first hosted lookup would fall back to memory for good. */
    @Test
    void theStoresComeFirstThenThePolicyThenSigning() {
        FederationRuntimeConfig.install(FederationRuntimeConfig.from(Map.of(FederationRuntimeConfig.AUTHORITY_METADATA_POLICY_ENV,
                "{\"oauth_client\": {\"token_endpoint_auth_method\": {\"value\": \"private_key_jwt\"}}}")::get, name -> null));
        Map<String, String> params = Map.of("authorityEntityId", AUTHORITY, "jdbcUrl", "jdbc:nowhere:authority");

        assertTrue(HostedEntityServlet.configureAuthority(params::get));

        assertTrue(AuthoritySupport.isHostingConfigured());
        assertTrue(AuthoritySupport.registry() instanceof JdbcHostedEntityRegistry);
        assertTrue(TrustMarkSupport.isConfigured(), "Trust Mark grants live in the same store");
        assertEquals(AUTHORITY, AuthoritySupport.authorityEntityId());
        assertThrows(IllegalArgumentException.class, () -> AuthoritySupport.requireComposable(new HostedEntity(AUTHORITY + "/federation/agents/a9",
                com.pingidentity.ps.oidf.authority.HostingMode.AUTHORITY_SIGNED, "k1", Map.of("oauth_client", Map.of()),
                Map.of("oauth_client", Map.of("token_endpoint_auth_method", Map.of("value", "none"))),
                com.pingidentity.ps.oidf.authority.EntityStatus.ACTIVE, false, null, java.time.Instant.now(), null)), "the domain default is in force");
    }

    @Test
    void aPingFederateDataStoreIsUsedWhenThereIsNoJdbcUrl() {
        Map<String, String> params = Map.of("authorityEntityId", AUTHORITY, "dataStoreId", "pf-store", "openBaoUrl", "https://bao.example",
                "openBaoToken", "token");

        assertTrue(HostedEntityServlet.configureAuthority(params::get));

        assertTrue(AuthoritySupport.registry() instanceof JdbcHostedEntityRegistry);
    }

    @Test
    void enrolmentNeedsTheAdminTokenAndTheCollectionRoot() throws Exception {
        host(SIGNER);

        Exchange refused = new Exchange("another-token", "POST", null, enrolment(""));
        assertEquals("unauthorized", refused.json(401).get("error"));
        verify(refused.response).setHeader("WWW-Authenticate", "Bearer");
        assertEquals("unauthorized", new Exchange(null, "POST", null, enrolment("")).json(401).get("error"), "no token configured opens nothing");
        assertEquals("not_found", new Exchange("POST", "/a1", enrolment("")).json(404).get("error"));
    }

    @Test
    void anEnrolmentCarriesAnIdAKeyAndMetadata() throws Exception {
        host(SIGNER);

        assertEquals("invalid_request", new Exchange("POST", null, "not json").json(400).get("error"));
        assertEquals("invalid_request", new Exchange("POST", null, "{\"id\": \"Not A Slug\", \"hostingKeyRef\": \"k1\", \"metadata\": {}}")
                .json(400).get("error"));
        assertEquals("invalid_request", new Exchange("POST", null, "{\"hostingKeyRef\": \"k1\", \"metadata\": {}}").json(400).get("error"));
        assertEquals("invalid_request", new Exchange("POST", null, "{\"id\": \"a1\", \"metadata\": {}}").json(400).get("error"));
        assertEquals("invalid_request", new Exchange("POST", null, "{\"id\": \"a1\", \"hostingKeyRef\": \"k1\", \"metadata\": [1]}")
                .json(400).get("error"));
        assertTrue(AuthoritySupport.registry().all().isEmpty());
    }

    @Test
    void listabilityOwnershipAndAnEndAreRecorded() throws Exception {
        host(SIGNER);

        new Exchange("POST", "/", enrolment(", \"listable\": true, \"ownerRef\": \"team-payments\", \"notAfterSeconds\": 3600")).json(201);

        HostedEntity stored = AuthoritySupport.registry().find(AUTHORITY + "/federation/agents/a1").orElseThrow();
        assertTrue(stored.listable());
        assertEquals("team-payments", stored.ownerRef());
        assertTrue(stored.notAfter().isAfter(java.time.Instant.now().plusSeconds(3500)));
    }

    @Test
    void aHostedEntityResolvesToItsSignedConfigurationAndNothingElseDoes() throws Exception {
        host(SIGNER);
        new Exchange("POST", null, enrolment("")).json(201);

        Exchange resolved = new Exchange("GET", "/a1/.well-known/openid-federation", null);
        verify(resolved.response).setStatus(200);
        verify(resolved.response).setContentType("application/entity-statement+jwt");
        assertEquals(AUTHORITY + "/federation/agents/a1", com.pingidentity.ps.oidf.jose.JwtCodec.parseUnverifiedClaims(resolved.body.toString()).getSubject());

        assertEquals("not_found", new Exchange("GET", "/a1", null).json(404).get("error"));
        assertEquals("not_found", new Exchange("GET", "/a2/.well-known/openid-federation", null).json(404).get("error"));
        AuthoritySupport.registry().setStatus(AUTHORITY + "/federation/agents/a1", com.pingidentity.ps.oidf.authority.EntityStatus.SUSPENDED, "review");
        assertEquals("not_found", new Exchange("GET", "/a1/.well-known/openid-federation", null).json(404).get("error"),
                "a suspended entity is refused as one never hosted");
    }

    @Test
    void aRegistryThatFailsWhileResolvingShowsNothingOfTheFault() throws Exception {
        AuthoritySupport.configureJdbcRegistry((javax.sql.DataSource) java.lang.reflect.Proxy.newProxyInstance(
                javax.sql.DataSource.class.getClassLoader(), new Class<?>[]{javax.sql.DataSource.class}, (proxy, method, args) -> {
                    throw new java.sql.SQLException("connection refused to jdbc:postgresql://secret-host/idm");
                }));
        host(SIGNER);

        Exchange resolving = new Exchange("GET", "/a1/.well-known/openid-federation", null);

        assertEquals("server_error", resolving.json(500).get("error"));
        assertFalse(resolving.body.toString().contains("secret-host"));
    }

    @Test
    void anAuthorityWithoutAStoreFallsBackToMemoryWhenFirstUsed() {
        assertTrue(HostedEntityServlet.configureAuthority(Map.of("authorityEntityId", " " + AUTHORITY + " ")::get));

        assertEquals(AUTHORITY, AuthoritySupport.authorityEntityId(), "trimmed");
        assertTrue(AuthoritySupport.registry() instanceof com.pingidentity.ps.oidf.authority.InMemoryHostedEntityRegistry);
        assertFalse(TrustMarkSupport.isConfigured());
    }

    /** Blank is unset at every level: an init-param, then a system property, then the environment. */
    @Test
    void aSettingComesFromTheFirstLevelThatHasOne() {
        System.setProperty("oidf.authority.entity_id", " ");
        try {
            assertFalse(HostedEntityServlet.configureAuthority(null), "a blank system property is no authority");
            System.setProperty("oidf.authority.entity_id", AUTHORITY);
            assertTrue(HostedEntityServlet.configureAuthority(Map.of("authorityEntityId", " ")::get), "a blank init-param defers to the property");
            assertEquals(AUTHORITY, AuthoritySupport.authorityEntityId());
        } finally {
            System.clearProperty("oidf.authority.entity_id");
        }
    }

    @Test
    void aTrustMarkStoreAlreadyChosenIsKeptAndAHalfConfiguredVaultIsTheEnvironments() {
        com.pingidentity.ps.oidf.trustmark.TrustMarkRegistry chosen = TrustMarkSupport.registry();

        assertTrue(HostedEntityServlet.configureAuthority(Map.of("authorityEntityId", AUTHORITY, "jdbcUrl", "jdbc:nowhere:authority",
                "openBaoUrl", "https://bao.example")::get));

        assertTrue(chosen == TrustMarkSupport.registry(), "the grants stay where they were first kept");
        assertTrue(AuthoritySupport.isHostingConfigured(), "a vault URL without its token leaves the signer to the environment");
    }
}
