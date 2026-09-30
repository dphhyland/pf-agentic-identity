package com.pingidentity.ps.oidf.servlet.trustanchor;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.pingidentity.ps.oidf.authority.AuthorityRegistryException;
import com.pingidentity.ps.oidf.federation.event.FederationEvents;
import com.pingidentity.ps.oidf.federation.testkit.EventCapture;
import com.pingidentity.ps.oidf.federation.testkit.Keys;
import com.pingidentity.ps.oidf.keyhistory.InMemoryKeyHistoryStore;
import com.pingidentity.ps.oidf.keyhistory.KeyHistory;
import com.pingidentity.ps.oidf.federation.testkit.MutableClock;
import com.pingidentity.ps.oidf.pf.PfRequestScope;
import com.pingidentity.ps.oidf.pf.testkit.AuditCapture;
import com.pingidentity.ps.oidf.pf.testkit.OperatorRequests;
import com.pingidentity.ps.oidf.platform.pf.auth.OperatorAuthenticator;
import com.pingidentity.ps.oidf.platform.pf.auth.OperatorScopes;
import com.pingidentity.ps.oidf.platform.pf.auth.OperatorTestKit;
import com.pingidentity.ps.oidf.platform.profile.DeploymentProfile;
import com.pingidentity.ps.oidf.trustmark.InMemoryTrustMarkRegistry;
import com.pingidentity.ps.oidf.trustmark.TrustMarkAuditEntry;
import com.pingidentity.ps.oidf.trustmark.TrustMarkGrant;
import com.pingidentity.ps.oidf.trustmark.TrustMarkRegistry;
import com.pingidentity.ps.oidf.trustmark.TrustMarkType;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.PrintWriter;
import java.io.StringReader;
import java.io.StringWriter;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.jose4j.json.JsonUtil;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * The operator's API for Trust Mark grants: only for an operator the authenticator lets through with the route's scope,
 * only for a type this entity issues, only to an entity that may hold it - and every change audited with the token's
 * subject as who made it. Most tests use the development static bearer; the OAuth tests a production DPoP token.
 */
class FederationAdminServletTest {
    private static final String TOKEN = "admin-token";
    private static final String OPEN = "https://pf.example/marks/open";
    private static final String HOSTED_ONLY = "https://pf.example/marks/hosted";
    private static final String RP = "https://rp.example";
    private static final String AGENT = "https://pf.example/federation/agents/a1";
    private static final String CALLER = "192.0.2.77";

    private final MutableClock clock = new MutableClock(Instant.ofEpochSecond(1_800_000_000L));
    private final InMemoryTrustMarkRegistry registry = new InMemoryTrustMarkRegistry(this.clock);
    private KeyHistory keyHistory = new KeyHistory(new InMemoryKeyHistoryStore(), this.clock, Duration.ofDays(1));
    private OperatorAuthenticator authenticator = OperatorTestKit.unconfigured(DeploymentProfile.DEVELOPMENT).withStaticBearer(TOKEN);
    /** When set, a request carries a production DPoP token from this kit with {@link #scopes} instead of the static bearer. */
    private OperatorTestKit kit;
    private String[] scopes;
    private EventCapture events;

    @BeforeEach
    void capture() {
        this.events = EventCapture.install();
    }

    @AfterEach
    void release() {
        this.events.close();
    }

    private FederationAdminServlet servlet(TrustMarkRegistry registry) {
        return new FederationAdminServlet(this.authenticator, Map.of(OPEN, new TrustMarkType(OPEN, 3600, TrustMarkType.Subjects.ANY, null, null, null),
                HOSTED_ONLY, new TrustMarkType(HOSTED_ONLY, 3600, TrustMarkType.Subjects.HOSTED, null, null, null)), registry, AGENT::equals, this.clock,
                this.keyHistory);
    }

    /** One request, answered. */
    private final class Exchange {
        final HttpServletResponse response = mock(HttpServletResponse.class);
        final StringWriter body = new StringWriter();

        Exchange(TrustMarkRegistry registry, String method, String path, String token, String json, Map<String, String> params,
                 String actor) throws Exception {
            HttpServletRequest request = mock(HttpServletRequest.class);
            when(request.getMethod()).thenReturn(method);
            when(request.getRemoteAddr()).thenReturn(CALLER);
            when(request.getPathInfo()).thenReturn(path);
            String uri = "/federation/admin" + (path == null ? "" : path);
            if (FederationAdminServletTest.this.kit != null) {
                OperatorRequests.dpop(request, FederationAdminServletTest.this.kit, method, uri, FederationAdminServletTest.this.scopes);
            } else {
                OperatorRequests.stub(request, uri, token == null ? null : "Bearer " + token, null);
            }
            when(request.getHeader("X-Federation-Actor")).thenReturn(actor);
            when(request.getReader()).thenReturn(new BufferedReader(new StringReader(json == null ? "" : json)));
            params.forEach((name, value) -> when(request.getParameter(name)).thenReturn(value));
            when(this.response.getWriter()).thenReturn(new PrintWriter(this.body));
            FederationAdminServletTest.this.servlet(registry).service(request, this.response);
        }

        Map<String, Object> json(int status) throws Exception {
            verify(this.response).setStatus(status);
            return JsonUtil.parseJson(this.body.toString());
        }

        List<?> array() throws Exception {
            verify(this.response).setStatus(200);
            return (List<?>) JsonUtil.parseJson("{\"array\": " + this.body + "}").get("array");
        }
    }

    private Exchange post(String path, String json) throws Exception {
        return new Exchange(this.registry, "POST", path, TOKEN, json, Map.of(), null);
    }

    private Exchange get(String path, Map<String, String> params) throws Exception {
        return new Exchange(this.registry, "GET", path, TOKEN, null, params, null);
    }

    @Test
    void aGrantsAuditRecordCarriesTheOperatorsAddressAndTheScopeEndsWithTheRequest() throws Exception {
        try (AuditCapture audit = AuditCapture.install()) {
            this.post("/trust-marks", "{\"trust_mark_type\": \"" + OPEN + "\", \"sub\": \"" + RP + "\"}").json(201);

            assertEquals(CALLER, audit.only(FederationEvents.TRUST_MARK_GRANTED).remoteAddress());
            assertNull(PfRequestScope.current());
        }
    }

    @Test
    void aGrantIsMadeRecordedAndAudited() throws Exception {
        Exchange exchange = new Exchange(this.registry, "POST", "/trust-marks", TOKEN,
                "{\"trust_mark_type\": \"" + OPEN + "\", \"sub\": \"" + RP + "\", \"not_after_seconds\": 3600}", Map.of(), "dave");

        Map<String, Object> grant = exchange.json(201);
        assertEquals(OPEN, grant.get("trust_mark_type"));
        assertEquals(RP, grant.get("sub"));
        assertEquals("active", grant.get("status"));
        assertEquals(this.clock.epochSecond(), ((Number) grant.get("granted_at")).longValue());
        assertEquals(this.clock.epochSecond() + 3600, ((Number) grant.get("not_after")).longValue());
        String actor = (String) grant.get("actor");
        assertTrue(actor.matches("admin:[0-9a-f]{8}"), "the static bearer's digest, never the token: " + actor);
        assertEquals(actor, this.events.only(FederationEvents.TRUST_MARK_GRANTED).fields().get("actor"));
        assertTrue(!this.events.only(FederationEvents.TRUST_MARK_GRANTED).fields().toString().contains("dave"),
                "X-Federation-Actor names nobody in the grant (F-0165)");
        assertTrue(this.events.only(FederationEvents.TRUST_MARK_GRANTED).audit());
        verify(exchange.response).setHeader("Cache-Control", "no-store");
    }

    @Test
    void aGrantMustBeOfATypeThisEntityIssuesToAnEntityThatMayHoldIt() throws Exception {
        assertEquals("invalid_request", this.post("/trust-marks", "{\"trust_mark_type\": \"https://pf.example/marks/other\", \"sub\": \"" + RP + "\"}")
                .json(400).get("error"));
        assertEquals("invalid_request", this.post("/trust-marks", "{\"sub\": \"" + RP + "\"}").json(400).get("error"));
        assertEquals("invalid_request", this.post("/trust-marks", "{\"trust_mark_type\": \"" + OPEN + "\", \"sub\": \"http://rp.example\"}").json(400).get("error"));
        assertEquals("invalid_request", this.post("/trust-marks", "{\"trust_mark_type\": \"" + OPEN + "\"}").json(400).get("error"));
        assertEquals("invalid_request", this.post("/trust-marks", "{\"trust_mark_type\": \"" + HOSTED_ONLY + "\", \"sub\": \"" + RP + "\"}").json(400).get("error"),
                "a hosted-only type to an entity not hosted here");
        assertEquals("invalid_request", this.post("/trust-marks", "{\"trust_mark_type\": \"" + OPEN + "\", \"sub\": \"" + RP + "\", \"not_after_seconds\": 0}")
                .json(400).get("error"));
        assertEquals("invalid_request", this.post("/trust-marks", "{\"trust_mark_type\": \"" + OPEN + "\", \"sub\": \"" + RP + "\", \"not_after_seconds\": \"soon\"}")
                .json(400).get("error"));
        assertEquals("invalid_request", this.post("/trust-marks", "not json").json(400).get("error"));
        this.post("/trust-marks", "{\"trust_mark_type\": \"" + HOSTED_ONLY + "\", \"sub\": \"" + AGENT + "\"}").json(201);
        assertTrue(this.registry.find(OPEN, RP).isEmpty());
    }

    @Test
    void aRevocationIsRecordedOnceAndAudited() throws Exception {
        this.registry.grant(OPEN, RP, null, "admin:setup");

        Map<String, Object> revoked = this.post("/trust-marks/revoke", "{\"trust_mark_type\": \"" + OPEN + "\", \"sub\": \"" + RP + "\", \"reason\": \"audit failed\"}")
                .json(200);
        Map<String, Object> again = this.post("/trust-marks/revoke", "{\"trust_mark_type\": \"" + OPEN + "\", \"sub\": \"" + RP + "\"}").json(200);

        assertEquals("revoked", revoked.get("status"));
        assertEquals("audit failed", revoked.get("reason"));
        assertEquals(this.clock.epochSecond(), ((Number) revoked.get("revoked_at")).longValue());
        assertEquals(revoked, again, "revoking a revoked grant changes nothing");
        assertEquals(1, this.events.withCode(FederationEvents.TRUST_MARK_REVOKED).size());
        assertEquals("audit failed", this.events.only(FederationEvents.TRUST_MARK_REVOKED).description());
    }

    @Test
    void aRevocationNeedsAGrantToRevoke() throws Exception {
        assertEquals("not_found", this.post("/trust-marks/revoke", "{\"trust_mark_type\": \"" + OPEN + "\", \"sub\": \"" + RP + "\"}").json(404).get("error"));
        assertEquals("invalid_request", this.post("/trust-marks/revoke", "{\"sub\": \"" + RP + "\"}").json(400).get("error"));
        assertEquals("invalid_request", this.post("/trust-marks/revoke", "{\"trust_mark_type\": \"" + OPEN + "\"}").json(400).get("error"));
        this.registry.grant(OPEN, RP, null, null);
        assertEquals("revoked by the operator", this.post("/trust-marks/revoke", "{\"trust_mark_type\": \"" + OPEN + "\", \"sub\": \"" + RP + "\"}")
                .json(200).get("reason"));
    }

    @Test
    void grantsAreListedBySubjectOrByTypeAndEachHasItsHistory() throws Exception {
        this.registry.grant(OPEN, RP, null, "admin:1");
        this.registry.grant(HOSTED_ONLY, AGENT, null, "admin:1");
        this.registry.grant(OPEN, AGENT, null, "admin:1");
        this.registry.revoke(OPEN, RP, "lapsed", "admin:2");

        assertEquals(2, this.get("/trust-marks/", Map.of("sub", AGENT)).array().size());
        assertEquals(1, this.get("/trust-marks", Map.of("sub", AGENT, "trust_mark_type", OPEN)).array().size());
        assertEquals(2, this.get("/trust-marks/", Map.of("trust_mark_type", OPEN)).array().size(), "the revoked grant included");
        assertEquals("invalid_request", this.get("/trust-marks/", Map.of()).json(400).get("error"));

        List<?> history = this.get("/trust-marks/audit", Map.of("sub", RP, "trust_mark_type", OPEN)).array();
        assertEquals(List.of(TrustMarkAuditEntry.GRANTED, TrustMarkAuditEntry.REVOKED), history.stream().map(e -> ((Map<?, ?>) e).get("event")).toList());
        assertEquals("lapsed", ((Map<?, ?>) history.get(1)).get("detail"));
        assertEquals("invalid_request", this.get("/trust-marks/audit", Map.of("sub", RP)).json(400).get("error"));
        assertEquals("invalid_request", this.get("/trust-marks/audit", Map.of("trust_mark_type", OPEN)).json(400).get("error"));
    }

    @Test
    void withoutACredentialNothingIsAnsweredAndTheRefusalCarriesTheChallenge() throws Exception {
        for (String token : new String[]{null, "wrong"}) {
            Exchange get = new Exchange(this.registry, "GET", "/trust-marks", token, null, Map.of("sub", RP), null);
            verify(get.response).setStatus(401);
            verify(get.response).addHeader(org.mockito.ArgumentMatchers.eq("WWW-Authenticate"),
                    org.mockito.ArgumentMatchers.startsWith("DPoP algs="));
            assertEquals("", get.body.toString());
            verify(new Exchange(this.registry, "POST", "/trust-marks", token, "{}", Map.of(), null).response).setStatus(401);
        }
        assertTrue(this.registry.find(OPEN, RP).isEmpty());
    }

    @Test
    void aProductionTokenIsLetThroughForItsScopeAndItsSubjectIsTheActor() throws Exception {
        this.kit = new OperatorTestKit();
        this.authenticator = this.kit.authenticator(DeploymentProfile.PRODUCTION);
        this.scopes = new String[] {OperatorScopes.ADMIN_TRUST_MARKS};
        Map<String, Object> grant = new Exchange(this.registry, "POST", "/trust-marks", null,
                "{\"trust_mark_type\": \"" + OPEN + "\", \"sub\": \"" + RP + "\"}", Map.of(), "Dave <dave@example.com>").json(201);
        assertEquals(OperatorTestKit.CLIENT, grant.get("actor"));
        assertEquals(OperatorTestKit.CLIENT, this.events.only(FederationEvents.TRUST_MARK_GRANTED).fields().get("actor"));
        assertEquals(OperatorTestKit.CLIENT, this.registry.auditTrail(OPEN, RP).get(0).actor());
    }

    @Test
    void eachRouteNeedsItsOwnScope() throws Exception {
        this.kit = new OperatorTestKit();
        this.authenticator = this.kit.authenticator(DeploymentProfile.PRODUCTION);
        this.scopes = new String[] {OperatorScopes.ADMIN_READ};
        verify(this.get("/trust-marks", Map.of("sub", RP)).response).setStatus(200);
        for (String path : List.of("/trust-marks", "/trust-marks/revoke", "/keys/revoke", "/entities/suspend", "/entities/rotate-key")) {
            Exchange post = this.post(path, "{}");
            verify(post.response).setStatus(403);
            assertEquals("", post.body.toString(), path);
        }
        this.scopes = new String[] {OperatorScopes.ADMIN_TRUST_MARKS};
        verify(this.get("/keys", Map.of()).response).setStatus(403);
        verify(this.post("/keys/revoke", "{}").response).setStatus(403);
        this.scopes = new String[] {OperatorScopes.ADMIN_KEYS};
        verify(this.post("/keys/revoke", "{}").response).setStatus(400);
        verify(this.post("/trust-marks", "{}").response).setStatus(403);
        assertTrue(this.registry.find(OPEN, RP).isEmpty());
    }

    @Test
    void productionRefusesTheStaticBearer() throws Exception {
        this.authenticator = new OperatorTestKit().authenticator(DeploymentProfile.PRODUCTION).withStaticBearer(TOKEN);
        verify(this.get("/trust-marks", Map.of("sub", RP)).response).setStatus(503);
        this.authenticator = new OperatorTestKit().authenticator(DeploymentProfile.PRODUCTION);
        verify(this.get("/trust-marks", Map.of("sub", RP)).response).setStatus(401);
    }

    @Test
    void aHandlerAskedForARouteItDoesNotServeAnswers404() throws Exception {
        HttpServletResponse response = mock(HttpServletResponse.class);
        when(response.getWriter()).thenReturn(new PrintWriter(new StringWriter()));
        this.servlet(this.registry).read("/grants", mock(HttpServletRequest.class), response);
        this.servlet(this.registry).change("/grant", Map.of(), "operator", response);
        verify(response, org.mockito.Mockito.times(2)).setStatus(404);
    }

    @Test
    void unknownPathsAreNotFound() throws Exception {
        assertEquals("not_found", this.get("/grants", Map.of()).json(404).get("error"));
        assertEquals("not_found", this.get(null, Map.of()).json(404).get("error"), "the admin root itself answers nothing");
        assertEquals("not_found", this.post("/grant", "{}").json(404).get("error"));
    }

    @Test
    void aStoreThatFailsIsAServerErrorThatShowsNothingOfTheFault() throws Exception {
        TrustMarkRegistry failing = new TrustMarkRegistry() {
            private AuthorityRegistryException down() {
                return new AuthorityRegistryException(AuthorityRegistryException.STORAGE_FAILURE, "jdbc:postgresql://secret-host/idm refused");
            }

            @Override
            public TrustMarkGrant grant(String type, String subject, Instant notAfter, String actor) throws AuthorityRegistryException {
                throw this.down();
            }

            @Override
            public Optional<TrustMarkGrant> find(String type, String subject) throws AuthorityRegistryException {
                throw this.down();
            }

            @Override
            public List<TrustMarkGrant> grantsTo(String subject) throws AuthorityRegistryException {
                throw this.down();
            }

            @Override
            public List<TrustMarkGrant> grantsOf(String type) throws AuthorityRegistryException {
                throw this.down();
            }

            @Override
            public TrustMarkGrant revoke(String type, String subject, String reason, String actor) throws AuthorityRegistryException {
                throw this.down();
            }

            @Override
            public List<TrustMarkAuditEntry> auditTrail(String type, String subject) throws AuthorityRegistryException {
                throw this.down();
            }
        };

        Exchange get = new Exchange(failing, "GET", "/trust-marks", TOKEN, null, Map.of("sub", RP), null);
        Exchange post = new Exchange(failing, "POST", "/trust-marks", TOKEN, "{\"trust_mark_type\": \"" + OPEN + "\", \"sub\": \"" + RP + "\"}", Map.of(), null);

        assertEquals("server_error", get.json(500).get("error"));
        assertEquals("server_error", post.json(500).get("error"));
        assertTrue(!get.body.toString().contains("secret-host") && !post.body.toString().contains("secret-host"), "nothing of the fault is shown");
    }

    // ---- the key history (§8.7) -----------------------------------------------------------------------

    @Test
    void theRetiredKeysAreListedAndOneCanBeRevokedWithAReason() throws Exception {
        this.keyHistory.observe(Keys.publicJwk(Keys.rsa("pf-1")));
        this.keyHistory.observe(Keys.publicJwk(Keys.rsa("pf-2")));

        List<?> keys = this.get("/keys", Map.of()).array();
        assertEquals("pf-1", ((Map<?, ?>) keys.get(0)).get("kid"));

        Map<String, Object> revoked = new Exchange(this.registry, "POST", "/keys/revoke", TOKEN, "{\"kid\": \"pf-1\", \"reason\": \"compromised\"}",
                Map.of(), "dave").json(200);
        assertEquals("compromised", ((Map<?, ?>) revoked.get("revoked")).get("reason"));
        assertTrue(((String) this.events.only(FederationEvents.KEY_REVOKED).fields().get("actor")).matches("admin:[0-9a-f]{8}"));
    }

    @Test
    void onlyARetiredKeyCanBeRevokedAndOnlyForAReasonSection8Point7Point3Defines() throws Exception {
        this.keyHistory.observe(Keys.publicJwk(Keys.rsa("pf-1")));

        assertEquals("not_found", this.post("/keys/revoke", "{\"kid\": \"pf-1\"}").json(404).get("error"), "the key in use is not history");
        assertEquals("invalid_request", this.post("/keys/revoke", "{\"kid\": \"pf-1\", \"reason\": \"lost\"}").json(400).get("error"));
        assertEquals("invalid_request", this.post("/keys/revoke", "{}").json(400).get("error"));
    }

    @Test
    void withoutAKeyHistoryTheKeyRoutesAreNotFound() throws Exception {
        this.keyHistory = null;

        assertEquals("not_found", this.get("/keys", Map.of()).json(404).get("error"));
        assertEquals("not_found", this.post("/keys/revoke", "{\"kid\": \"pf-1\"}").json(404).get("error"));
    }

    @Test
    void aKeyStoreThatFailsIsAServerError() throws Exception {
        this.keyHistory = new KeyHistory(new com.pingidentity.ps.oidf.keyhistory.KeyHistoryStore() {
            @Override
            public Optional<com.pingidentity.ps.oidf.keyhistory.HistoricalKey> rotateTo(Map<String, Object> publicJwk, Instant now, Instant until) {
                return Optional.empty();
            }

            @Override
            public com.pingidentity.ps.oidf.keyhistory.HistoricalKey revoke(String kid, Instant revokedAt, String reason) throws AuthorityRegistryException {
                throw new AuthorityRegistryException(AuthorityRegistryException.STORAGE_FAILURE, "down");
            }

            @Override
            public List<com.pingidentity.ps.oidf.keyhistory.HistoricalKey> retired() throws AuthorityRegistryException {
                throw new AuthorityRegistryException(AuthorityRegistryException.STORAGE_FAILURE, "down");
            }
        }, this.clock, Duration.ZERO);

        assertEquals("server_error", this.get("/keys", Map.of()).json(500).get("error"));
        assertEquals("server_error", this.post("/keys/revoke", "{\"kid\": \"pf-1\"}").json(500).get("error"));
    }
}
