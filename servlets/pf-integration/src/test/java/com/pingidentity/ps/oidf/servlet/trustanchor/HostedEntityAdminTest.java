package com.pingidentity.ps.oidf.servlet.trustanchor;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.pingidentity.ps.oidf.authority.AuthoritySupport;
import com.pingidentity.ps.oidf.authority.HostedEntity;
import com.pingidentity.ps.oidf.federation.event.FederationEvents;
import com.pingidentity.ps.oidf.federation.testkit.EventCapture;
import com.pingidentity.ps.oidf.federation.testkit.MutableClock;
import com.pingidentity.ps.oidf.jose.JwsSigner;
import com.pingidentity.ps.oidf.trustmark.InMemoryTrustMarkRegistry;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.PrintWriter;
import java.io.StringReader;
import java.io.StringWriter;
import java.util.List;
import java.util.Map;
import org.jose4j.json.JsonUtil;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * The operator's routes for hosted entities: every entity whatever its status, the lifecycle, and the checks that keep a
 * change from breaking what the authority publishes - a policy that would not compose, a key that cannot sign.
 */
class HostedEntityAdminTest {
    private static final String TOKEN = "admin-token";
    private static final String AUTHORITY = "https://pf.example";
    private static final String AGENT = "https://pf.example/federation/agents/a1";

    private final MutableClock clock = MutableClock.startingNow();
    private EventCapture events;

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

    @BeforeEach
    void host() throws Exception {
        this.events = EventCapture.install();
        AuthoritySupport.resetForTests();
        AuthoritySupport.configureSigning(entity -> {
            if (entity.hostingKeyRef().startsWith("good")) {
                return SIGNER;
            }
            throw new IllegalStateException("no such transit key: " + entity.hostingKeyRef());
        }, AUTHORITY);
        AuthoritySupport.registry().register(HostedEntity.hosted(AGENT, "good-1", Map.of("oauth_client", Map.of("client_name", "Agent")), "ops"));
    }

    @AfterEach
    void release() {
        this.events.close();
        AuthoritySupport.resetForTests();
    }

    private final class Exchange {
        final HttpServletResponse response = mock(HttpServletResponse.class);
        final StringWriter body = new StringWriter();

        Exchange(String method, String path, String json, Map<String, String> params) throws Exception {
            HttpServletRequest request = mock(HttpServletRequest.class);
            when(request.getPathInfo()).thenReturn(path);
            when(request.getHeader("Authorization")).thenReturn("Bearer " + TOKEN);
            when(request.getHeader("X-Federation-Actor")).thenReturn("dave");
            when(request.getReader()).thenReturn(new BufferedReader(new StringReader(json == null ? "" : json)));
            params.forEach((name, value) -> when(request.getParameter(name)).thenReturn(value));
            when(this.response.getWriter()).thenReturn(new PrintWriter(this.body));
            FederationAdminServlet servlet = new FederationAdminServlet(TOKEN, Map.of(), new InMemoryTrustMarkRegistry(HostedEntityAdminTest.this.clock),
                    id -> true, HostedEntityAdminTest.this.clock, null);
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

    private Exchange post(String action, String json) throws Exception {
        return new Exchange("POST", "/entities/" + action, json, Map.of());
    }

    private Exchange get(String path, Map<String, String> params) throws Exception {
        return new Exchange("GET", path, null, params);
    }

    private static String body(String... pairs) {
        StringBuilder json = new StringBuilder("{\"entity_id\": \"" + AGENT + "\"");
        for (int i = 0; i + 1 < pairs.length; i += 2) {
            json.append(", \"").append(pairs[i]).append("\": ").append(pairs[i + 1]);
        }
        return json.append('}').toString();
    }

    @Test
    void theOperatorSeesEveryEntityAndOneInFull() throws Exception {
        AuthoritySupport.registry().register(HostedEntity.hosted(AUTHORITY + "/federation/agents/a0", "good-1", Map.of("oauth_client", Map.of()), null));
        this.post("suspend", body()).json(200);

        List<?> all = this.get("/entities", Map.of()).array();
        Map<String, Object> one = this.get("/entities/", Map.of("entity_id", AGENT)).json(200);

        assertEquals(2, all.size(), "suspended and unlisted entities included");
        assertEquals("suspended", one.get("status"));
        assertEquals(Map.of("oauth_client", Map.of("client_name", "Agent")), one.get("metadata"));
        assertEquals(Map.of(), one.get("metadata_policy"));
        assertEquals("ops", one.get("owner_ref"));
        assertEquals("not_found", this.get("/entities", Map.of("entity_id", AUTHORITY + "/federation/agents/nobody")).json(404).get("error"));
    }

    @Test
    void anEntityIsSuspendedReactivatedAndRevokedForGood() throws Exception {
        assertEquals("suspended", this.post("suspend", body("reason", "\"review\"")).json(200).get("status"));
        assertEquals("active", this.post("reactivate", body()).json(200).get("status"));
        assertEquals("revoked", this.post("revoke", body("reason", "\"key lost\"")).json(200).get("status"));
        assertEquals("invalid_request", this.post("reactivate", body()).json(409).get("error"), "revocation is permanent");
        assertEquals("revoked", this.post("revoke", body()).json(200).get("status"), "revoking again changes nothing");

        List<?> history = this.get("/entities/audit", Map.of("entity_id", AGENT)).array();
        assertEquals(4, history.size(), "the second revocation wrote nothing");
        assertTrue(((String) ((Map<?, ?>) history.get(1)).get("actor")).endsWith("(dave)"));
        assertEquals("key lost", this.events.only(FederationEvents.HOSTED_ENTITY_REVOKED).description());
        assertEquals(1, this.events.withCode(FederationEvents.HOSTED_ENTITY_SUSPENDED).size());
        assertEquals(1, this.events.withCode(FederationEvents.HOSTED_ENTITY_REACTIVATED).size());
    }

    @Test
    void metadataIsReplacedWholeAndMustBeOneBlockPerType() throws Exception {
        Map<String, Object> changed = this.post("metadata", body("metadata", "{\"oauth_client\": {\"client_name\": \"Renamed\"}}")).json(200);

        assertEquals(List.of("oauth_client"), changed.get("entity_types"));
        assertEquals("Renamed", ((Map<?, ?>) AuthoritySupport.registry().find(AGENT).orElseThrow().metadata().get("oauth_client")).get("client_name"));
        assertEquals("invalid_request", this.post("metadata", body("metadata", "{\"oauth_client\": \"x\"}")).json(400).get("error"));
        assertEquals("invalid_request", this.post("metadata", body()).json(400).get("error"));
        assertEquals("metadata", this.events.only(FederationEvents.HOSTED_ENTITY_UPDATED).fields().get("changed"));
    }

    @Test
    void anEntitysPolicyMayOnlyNarrowTheDomainDefault() throws Exception {
        AuthoritySupport.configureDomainDefaultMetadataPolicy(Map.of("oauth_client", Map.of("token_endpoint_auth_method",
                Map.of("value", "private_key_jwt"))));

        assertEquals("invalid_metadata", this.post("metadata-policy", body("metadata_policy",
                "{\"oauth_client\": {\"token_endpoint_auth_method\": {\"value\": \"none\"}}}")).json(400).get("error"));
        this.post("metadata-policy", body("metadata_policy", "{\"oauth_client\": {\"scope\": {\"subset_of\": [\"read\"]}}}")).json(200);

        assertEquals(Map.of("oauth_client", Map.of("scope", Map.of("subset_of", List.of("read")))),
                AuthoritySupport.registry().find(AGENT).orElseThrow().metadataPolicy());
        assertEquals("invalid_request", this.post("metadata-policy", body("metadata_policy", "[]")).json(400).get("error"));
    }

    @Test
    void aNewHostingKeyMustSignBeforeTheEntityMovesToIt() throws Exception {
        Exchange refused = this.post("rotate-key", body("hosting_key_ref", "\"missing-9\""));
        assertEquals("invalid_request", refused.json(400).get("error"));
        assertTrue(!refused.body.toString().contains("transit"), "nothing of the vault's answer is shown");
        assertEquals("invalid_request", this.post("rotate-key", body()).json(400).get("error"));

        assertEquals("good-2", this.post("rotate-key", body("hosting_key_ref", "\"good-2\"")).json(200).get("hosting_key_ref"));
        assertEquals(1, this.events.withCode(FederationEvents.HOSTED_ENTITY_ROTATED).size());
    }

    @Test
    void requestsNamingNothingOrNobodyAreRefused() throws Exception {
        assertEquals("invalid_request", this.post("suspend", "{}").json(400).get("error"));
        assertEquals("not_found", this.post("suspend", "{\"entity_id\": \"" + AUTHORITY + "/federation/agents/nobody\"}").json(404).get("error"));
        assertEquals("not_found", this.post("frobnicate", body()).json(404).get("error"));
        assertEquals("invalid_request", this.get("/entities/audit", Map.of()).json(400).get("error"));
    }

    @Test
    void withoutHostingThereIsNothingToAdminister() throws Exception {
        AuthoritySupport.resetForTests();

        assertEquals("not_found", this.get("/entities", Map.of()).json(404).get("error"));
        assertEquals("not_found", this.get("/entities/audit", Map.of("entity_id", AGENT)).json(404).get("error"));
        assertEquals("not_found", this.post("suspend", body()).json(404).get("error"));
    }

    @Test
    void aStoreThatFailsIsAServerError() throws Exception {
        AuthoritySupport.resetForTests();
        AuthoritySupport.configureJdbcRegistry((javax.sql.DataSource) java.lang.reflect.Proxy.newProxyInstance(
                javax.sql.DataSource.class.getClassLoader(), new Class<?>[]{javax.sql.DataSource.class}, (proxy, method, args) -> {
                    throw new java.sql.SQLException("connection refused");
                }));
        AuthoritySupport.configureSigning(entity -> SIGNER, AUTHORITY);

        assertEquals("server_error", this.get("/entities", Map.of()).json(500).get("error"));
        assertEquals("server_error", this.post("suspend", body()).json(500).get("error"));
    }
}
