package com.pingidentity.ps.oidf.servlet.trustanchor;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.pingidentity.ps.oidf.authority.AuthorityRegistryException;
import com.pingidentity.ps.oidf.federation.event.FederationEvents;
import com.pingidentity.ps.oidf.federation.testkit.EventCapture;
import com.pingidentity.ps.oidf.federation.testkit.MutableClock;
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
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.jose4j.json.JsonUtil;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * The operator's API for Trust Mark grants: only with the admin token, only for a type this entity issues, only to an
 * entity that may hold it - and every change audited with who made it.
 */
class FederationAdminServletTest {
    private static final String TOKEN = "admin-token";
    private static final String OPEN = "https://pf.example/marks/open";
    private static final String HOSTED_ONLY = "https://pf.example/marks/hosted";
    private static final String RP = "https://rp.example";
    private static final String AGENT = "https://pf.example/federation/agents/a1";

    private final MutableClock clock = new MutableClock(Instant.ofEpochSecond(1_800_000_000L));
    private final InMemoryTrustMarkRegistry registry = new InMemoryTrustMarkRegistry(this.clock);
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
        return new FederationAdminServlet(TOKEN, Map.of(OPEN, new TrustMarkType(OPEN, 3600, TrustMarkType.Subjects.ANY, null, null, null),
                HOSTED_ONLY, new TrustMarkType(HOSTED_ONLY, 3600, TrustMarkType.Subjects.HOSTED, null, null, null)), registry, AGENT::equals, this.clock);
    }

    /** One request, answered. */
    private final class Exchange {
        final HttpServletResponse response = mock(HttpServletResponse.class);
        final StringWriter body = new StringWriter();

        Exchange(TrustMarkRegistry registry, String method, String path, String token, String json, Map<String, String> params,
                 String actor) throws Exception {
            HttpServletRequest request = mock(HttpServletRequest.class);
            when(request.getPathInfo()).thenReturn(path);
            when(request.getHeader("Authorization")).thenReturn(token == null ? null : "Bearer " + token);
            when(request.getHeader("X-Federation-Actor")).thenReturn(actor);
            when(request.getReader()).thenReturn(new BufferedReader(new StringReader(json == null ? "" : json)));
            params.forEach((name, value) -> when(request.getParameter(name)).thenReturn(value));
            when(this.response.getWriter()).thenReturn(new PrintWriter(this.body));
            FederationAdminServlet servlet = FederationAdminServletTest.this.servlet(registry);
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
    void aGrantIsMadeRecordedAndAudited() throws Exception {
        Exchange exchange = new Exchange(this.registry, "POST", null, TOKEN,
                "{\"trust_mark_type\": \"" + OPEN + "\", \"sub\": \"" + RP + "\", \"not_after_seconds\": 3600}", Map.of(), "dave");

        Map<String, Object> grant = exchange.json(201);
        assertEquals(OPEN, grant.get("trust_mark_type"));
        assertEquals(RP, grant.get("sub"));
        assertEquals("active", grant.get("status"));
        assertEquals(this.clock.epochSecond(), ((Number) grant.get("granted_at")).longValue());
        assertEquals(this.clock.epochSecond() + 3600, ((Number) grant.get("not_after")).longValue());
        String actor = (String) grant.get("actor");
        assertTrue(actor.matches("admin:[0-9a-f]{8} \\(dave\\)"), actor);
        assertEquals(actor, FederationAdminServlet.actor(TOKEN, "dave"), "the token is never recorded, only a digest of it");
        assertEquals(actor, this.events.only(FederationEvents.TRUST_MARK_GRANTED).fields().get("actor"));
        assertTrue(this.events.only(FederationEvents.TRUST_MARK_GRANTED).audit());
        verify(exchange.response).setHeader("Cache-Control", "no-store");
    }

    @Test
    void aGrantMustBeOfATypeThisEntityIssuesToAnEntityThatMayHoldIt() throws Exception {
        assertEquals("invalid_request", this.post("/", "{\"trust_mark_type\": \"https://pf.example/marks/other\", \"sub\": \"" + RP + "\"}")
                .json(400).get("error"));
        assertEquals("invalid_request", this.post("/", "{\"sub\": \"" + RP + "\"}").json(400).get("error"));
        assertEquals("invalid_request", this.post("/", "{\"trust_mark_type\": \"" + OPEN + "\", \"sub\": \"http://rp.example\"}").json(400).get("error"));
        assertEquals("invalid_request", this.post("/", "{\"trust_mark_type\": \"" + OPEN + "\"}").json(400).get("error"));
        assertEquals("invalid_request", this.post("/", "{\"trust_mark_type\": \"" + HOSTED_ONLY + "\", \"sub\": \"" + RP + "\"}").json(400).get("error"),
                "a hosted-only type to an entity not hosted here");
        assertEquals("invalid_request", this.post("/", "{\"trust_mark_type\": \"" + OPEN + "\", \"sub\": \"" + RP + "\", \"not_after_seconds\": 0}")
                .json(400).get("error"));
        assertEquals("invalid_request", this.post("/", "{\"trust_mark_type\": \"" + OPEN + "\", \"sub\": \"" + RP + "\", \"not_after_seconds\": \"soon\"}")
                .json(400).get("error"));
        assertEquals("invalid_request", this.post("/", "not json").json(400).get("error"));
        this.post("/", "{\"trust_mark_type\": \"" + HOSTED_ONLY + "\", \"sub\": \"" + AGENT + "\"}").json(201);
        assertTrue(this.registry.find(OPEN, RP).isEmpty());
    }

    @Test
    void aRevocationIsRecordedOnceAndAudited() throws Exception {
        this.registry.grant(OPEN, RP, null, "admin:setup");

        Map<String, Object> revoked = this.post("/revoke", "{\"trust_mark_type\": \"" + OPEN + "\", \"sub\": \"" + RP + "\", \"reason\": \"audit failed\"}")
                .json(200);
        Map<String, Object> again = this.post("/revoke", "{\"trust_mark_type\": \"" + OPEN + "\", \"sub\": \"" + RP + "\"}").json(200);

        assertEquals("revoked", revoked.get("status"));
        assertEquals("audit failed", revoked.get("reason"));
        assertEquals(this.clock.epochSecond(), ((Number) revoked.get("revoked_at")).longValue());
        assertEquals(revoked, again, "revoking a revoked grant changes nothing");
        assertEquals(1, this.events.withCode(FederationEvents.TRUST_MARK_REVOKED).size());
        assertEquals("audit failed", this.events.only(FederationEvents.TRUST_MARK_REVOKED).description());
    }

    @Test
    void aRevocationNeedsAGrantToRevoke() throws Exception {
        assertEquals("not_found", this.post("/revoke", "{\"trust_mark_type\": \"" + OPEN + "\", \"sub\": \"" + RP + "\"}").json(404).get("error"));
        assertEquals("invalid_request", this.post("/revoke", "{\"sub\": \"" + RP + "\"}").json(400).get("error"));
        assertEquals("invalid_request", this.post("/revoke", "{\"trust_mark_type\": \"" + OPEN + "\"}").json(400).get("error"));
        this.registry.grant(OPEN, RP, null, null);
        assertEquals("revoked by the operator", this.post("/revoke", "{\"trust_mark_type\": \"" + OPEN + "\", \"sub\": \"" + RP + "\"}")
                .json(200).get("reason"));
    }

    @Test
    void grantsAreListedBySubjectOrByTypeAndEachHasItsHistory() throws Exception {
        this.registry.grant(OPEN, RP, null, "admin:1");
        this.registry.grant(HOSTED_ONLY, AGENT, null, "admin:1");
        this.registry.grant(OPEN, AGENT, null, "admin:1");
        this.registry.revoke(OPEN, RP, "lapsed", "admin:2");

        assertEquals(2, this.get("/", Map.of("sub", AGENT)).array().size());
        assertEquals(1, this.get(null, Map.of("sub", AGENT, "trust_mark_type", OPEN)).array().size());
        assertEquals(2, this.get("/", Map.of("trust_mark_type", OPEN)).array().size(), "the revoked grant included");
        assertEquals("invalid_request", this.get("/", Map.of()).json(400).get("error"));

        List<?> history = this.get("/audit", Map.of("sub", RP, "trust_mark_type", OPEN)).array();
        assertEquals(List.of(TrustMarkAuditEntry.GRANTED, TrustMarkAuditEntry.REVOKED), history.stream().map(e -> ((Map<?, ?>) e).get("event")).toList());
        assertEquals("lapsed", ((Map<?, ?>) history.get(1)).get("detail"));
        assertEquals("invalid_request", this.get("/audit", Map.of("sub", RP)).json(400).get("error"));
        assertEquals("invalid_request", this.get("/audit", Map.of("trust_mark_type", OPEN)).json(400).get("error"));
    }

    @Test
    void withoutTheAdminTokenNothingIsAnswered() throws Exception {
        for (String token : new String[]{null, "wrong"}) {
            Exchange get = new Exchange(this.registry, "GET", "/", token, null, Map.of("sub", RP), null);
            assertEquals("unauthorized", get.json(401).get("error"));
            verify(get.response).setHeader("WWW-Authenticate", "Bearer");
            assertEquals("unauthorized", new Exchange(this.registry, "POST", "/", token, "{}", Map.of(), null).json(401).get("error"));
        }
        FederationAdminServlet unconfigured = new FederationAdminServlet(null, Map.of(), this.registry, id -> true, this.clock);
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getHeader("Authorization")).thenReturn("Bearer ");
        HttpServletResponse response = mock(HttpServletResponse.class);
        when(response.getWriter()).thenReturn(new PrintWriter(new StringWriter()));
        unconfigured.doGet(request, response);
        verify(response).setStatus(401);
    }

    @Test
    void unknownPathsAreNotFound() throws Exception {
        assertEquals("not_found", this.get("/grants", Map.of()).json(404).get("error"));
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

        Exchange get = new Exchange(failing, "GET", "/", TOKEN, null, Map.of("sub", RP), null);
        Exchange post = new Exchange(failing, "POST", "/", TOKEN, "{\"trust_mark_type\": \"" + OPEN + "\", \"sub\": \"" + RP + "\"}", Map.of(), null);

        assertEquals("server_error", get.json(500).get("error"));
        assertEquals("server_error", post.json(500).get("error"));
        assertTrue(!get.body.toString().contains("secret-host") && !post.body.toString().contains("secret-host"), "nothing of the fault is shown");
    }

    @Test
    void anActorCanNameItselfButNotForgeALine() {
        assertTrue(FederationAdminServlet.actor(TOKEN, null).matches("admin:[0-9a-f]{8}"));
        assertEquals(FederationAdminServlet.actor(TOKEN, null), FederationAdminServlet.actor(TOKEN, " "));
        String forged = FederationAdminServlet.actor(TOKEN, "dave\nevent=federation.trust_mark.granted");
        assertTrue(!forged.contains("\n"), forged);
        assertTrue(FederationAdminServlet.actor(TOKEN, "x".repeat(500)).length() < 160, "the name is capped");
    }
}
