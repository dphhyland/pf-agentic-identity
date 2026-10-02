package com.pingidentity.ps.oidf.rar;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.pingidentity.ps.oidf.conformance.Requirement;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AuthZenPdpClientTest {

    private final ObjectMapper mapper = new ObjectMapper();
    private final GovernanceEngineConfig config = GovernanceEngineConfig.builder()
            .pdpUrl("https://pdp/access/v1/evaluation")
            .secretHeader("Authorization")
            .secret("Bearer s3cret")
            .build();

    /** Captures the outbound request and returns a canned response. */
    private static final class StubTransport implements HttpTransport {
        String url;
        String body;
        Map<String, String> headers;
        final Response response;

        StubTransport(Response response) {
            this.response = response;
        }

        @Override
        public Response post(String url, String body, Map<String, String> headers) {
            this.url = url;
            this.body = body;
            this.headers = headers;
            return response;
        }
    }

    private AuthZenPdpClient client(StubTransport t) {
        return new AuthZenPdpClient(config, t, new AuthZenRequestBuilder(config), mapper);
    }

    private DecisionResponse decide(StubTransport t) throws IOException {
        return client(t).decide("sales_agent", Map.of("type", "sales_agent"),
                AttestationSubject.empty(), "alice", "client-1", "authenticated");
    }

    @Test
    @Requirement({"AUTHZEN-1.0 §5.5", "AUTHZEN-1.0 §6.1"})
    void trueDecisionIsPermitAndSendsAuthZenShape() throws Exception {
        StubTransport t = new StubTransport(new HttpTransport.Response(200, "{\"decision\":true}"));
        DecisionResponse r = decide(t);

        assertTrue(r.isPermit());
        assertEquals("PERMIT", r.getDecision());
        assertEquals("Bearer s3cret", t.headers.get("Authorization"));
        assertEquals("https://pdp/access/v1/evaluation", t.url);
        // wire body is the AuthZEN evaluation shape, not the governance-engine one
        assertTrue(t.body.contains("\"subject\""));
        assertTrue(t.body.contains("\"resource\""));
        assertFalse(t.body.contains("\"domain\""));
    }

    @Test
    @Requirement("AUTHZEN-1.0 §5.5")
    void falseDecisionIsDeny() throws Exception {
        StubTransport t = new StubTransport(new HttpTransport.Response(200, "{\"decision\":false}"));
        assertFalse(decide(t).isPermit());
        assertEquals("DENY", decide(new StubTransport(new HttpTransport.Response(200, "{\"decision\":false}"))).getDecision());
    }

    @Test
    void contextStatementsMapIntoTheStatementPipelineWhenTheAllowListNamesThem() throws Exception {
        String body = "{\"decision\":true,\"context\":{\"statements\":["
                + "{\"name\":\"access.limits\",\"payload\":{\"max_amount\":100}},"
                + "{\"name\":\"sales_regions\",\"payload\":[\"EMEA\"]}]}}";
        DecisionResponse r = decide(new StubTransport(new HttpTransport.Response(200, body)));

        assertEquals(1, r.getStatements().size(), "access is not a member sales_agent's model declares, so it is dropped");
        assertEquals("sales_regions", r.getStatements().get(0).getName());

        AuthZenPdpClient listed = new AuthZenPdpClient(config, new StubTransport(new HttpTransport.Response(200, body)),
                new AuthZenRequestBuilder(config), mapper, null, ContextAllowList.of("sales_agent: access", type -> Set.of()));
        DecisionResponse allowed = listed.decide("sales_agent", Map.of("type", "sales_agent"), AttestationSubject.empty(),
                "alice", "client-1", "authenticated");
        assertEquals(1, allowed.getStatements().size());
        assertEquals("access.limits", allowed.getStatements().get(0).getName());
        Map<String, Object> detail = new HashMap<>();
        StatementApplier.apply(allowed.getStatements(), detail, mapper);
        assertEquals(Map.of("limits", Map.of("max_amount", 100)), detail.get("access"));
    }

    @Test
    void bareContextMembersBecomeEnrichmentButReasonsDoNot() throws Exception {
        String body = "{\"decision\":true,\"context\":{"
                + "\"id\":\"eval-1\",\"reason_admin\":{\"en\":\"policy X\"},\"reason_user\":{\"en\":\"ok\"},"
                + "\"sales_regions\":[\"EMEA\"],\"downscoped_regions\":[\"EMEA\"]}}";
        DecisionResponse r = decide(new StubTransport(new HttpTransport.Response(200, body)));

        assertEquals(1, r.getStatements().size(), "downscoped_regions is on no list, so it is dropped");
        assertEquals("sales_regions", r.getStatements().get(0).getName());
        assertEquals(List.of("EMEA"), r.getStatements().get(0).getPayload());
    }

    /** A PDP that answered with anything but a JSON 2xx is refused, and only "not serving" reads as unreachable. */
    @Test
    @Requirement("AUTHZEN-1.0 §10.1")
    void nonSuccessStatusThrowsAndOnlyUnavailableStatusesFailOpen() {
        for (int status : new int[] {400, 401, 403, 404, 500, 302}) {
            IOException e = assertThrows(IOException.class, () -> decide(new StubTransport(new HttpTransport.Response(status, "boom"))));
            assertFalse(e instanceof PdpUnavailableException, "HTTP " + status + " is a refusal, not an outage");
        }
        for (int status : new int[] {429, 502, 503, 504}) {
            assertThrows(PdpUnavailableException.class, () -> decide(new StubTransport(new HttpTransport.Response(status, "later"))));
        }
    }

    @Test
    void aNonJsonAnswerAndAMalformedOneAreRefused() {
        IOException html = assertThrows(IOException.class,
                () -> decide(new StubTransport(new HttpTransport.Response(200, "<html>login</html>", "text/html"))));
        assertFalse(html instanceof PdpUnavailableException);
        assertTrue(html.getMessage().contains("text/html"), html.getMessage());
        IOException malformed = assertThrows(IOException.class,
                () -> decide(new StubTransport(new HttpTransport.Response(200, "{\"decision\": tru"))));
        assertFalse(malformed instanceof PdpUnavailableException);
        assertThrows(IOException.class, () -> decide(new StubTransport(new HttpTransport.Response(200, "", "application/json"))));
        assertThrows(IOException.class, () -> decide(new StubTransport(new HttpTransport.Response(200, null, "application/json"))));
    }

    @Test
    @Requirement("AUTHZEN-1.0 §5.5")
    void missingBooleanDecisionThrows() {
        StubTransport t = new StubTransport(new HttpTransport.Response(200, "{\"decision\":\"PERMIT\"}"));
        assertThrows(IOException.class, () -> decide(t));
    }

    /**
     * AuthZEN Authorization API 1.0 (Final, 11 January 2026) §5.5: "Decision is an object that contains a
     * REQUIRED decision key with a boolean value, and an OPTIONAL context key with an object value." Only a
     * JSON boolean is a decision; a string, a number, null or no member is refused, never read as either.
     */
    @Test
    @Requirement("AUTHZEN-1.0 §5.5")
    void theDecisionIsABooleanOrTheAnswerIsRefused() throws Exception {
        assertTrue(AuthZenPdpClient.decisionOf(mapper.readTree("{\"decision\":true}"), "{}"));
        assertFalse(AuthZenPdpClient.decisionOf(mapper.readTree("{\"decision\":false,\"context\":{}}"), "{}"));
        for (String body : new String[] {"{}", "{\"decision\":\"true\"}", "{\"decision\":1}", "{\"decision\":null}",
                "{\"allow\":true}"}) {
            IOException e = assertThrows(IOException.class, () -> AuthZenPdpClient.decisionOf(mapper.readTree(body), body), body);
            assertTrue(e.getMessage().contains("no boolean 'decision'"), e.getMessage());
        }
    }

    @Test
    void theAttesterIssuerRidesWithTheActor() throws Exception {
        StubTransport t = new StubTransport(new HttpTransport.Response(200, "{\"decision\":true}"));
        AttestationSubject subject = new AttestationSubject("c", "c", List.of(), Map.of(), null, "agent-1", "https://attester", null);
        client(t).decide("sales_agent", Map.of("type", "sales_agent"), subject, "alice", "c", "authenticated");
        assertTrue(t.body.contains("\"actor\":{\"type\":\"agent\",\"id\":\"agent-1\",\"iss\":\"https://attester\"}"), t.body);
        assertTrue(t.body.contains("\"attestation\":{\"iss\":\"https://attester\"}"), t.body);
    }

    @Test
    void noSecretHeaderIsSentWithoutASecret() throws Exception {
        GovernanceEngineConfig bare = GovernanceEngineConfig.builder().pdpUrl("https://pdp/access/v1/evaluation").secret("").build();
        StubTransport t = new StubTransport(new HttpTransport.Response(200, "{\"decision\":true}"));
        new AuthZenPdpClient(bare, t, new AuthZenRequestBuilder(bare), mapper)
                .decide("sales_agent", Map.of("type", "sales_agent"), AttestationSubject.empty(), null, "c", "none");
        assertFalse(t.headers.containsKey("CLIENT-TOKEN"));
    }
}
