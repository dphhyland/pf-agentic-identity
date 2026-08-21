package com.pingidentity.ps.oidf.rar;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

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
    void falseDecisionIsDeny() throws Exception {
        StubTransport t = new StubTransport(new HttpTransport.Response(200, "{\"decision\":false}"));
        assertFalse(decide(t).isPermit());
        assertEquals("DENY", decide(new StubTransport(new HttpTransport.Response(200, "{\"decision\":false}"))).getDecision());
    }

    @Test
    void contextStatementsMapVerbatimIntoTheStatementPipeline() throws Exception {
        String body = "{\"decision\":true,\"context\":{\"statements\":["
                + "{\"name\":\"access.limits\",\"payload\":{\"max_amount\":100}}]}}";
        DecisionResponse r = decide(new StubTransport(new HttpTransport.Response(200, body)));

        assertEquals(1, r.getStatements().size());
        assertEquals("access.limits", r.getStatements().get(0).getName());
        Map<String, Object> detail = new HashMap<>();
        StatementApplier.apply(r.getStatements(), detail, mapper);
        assertEquals(Map.of("limits", Map.of("max_amount", 100)), detail.get("access"));
    }

    @Test
    void bareContextMembersBecomeEnrichmentButReasonsDoNot() throws Exception {
        String body = "{\"decision\":true,\"context\":{"
                + "\"id\":\"eval-1\",\"reason_admin\":{\"en\":\"policy X\"},\"reason_user\":{\"en\":\"ok\"},"
                + "\"downscoped_regions\":[\"EMEA\"]}}";
        DecisionResponse r = decide(new StubTransport(new HttpTransport.Response(200, body)));

        assertEquals(1, r.getStatements().size());
        assertEquals("downscoped_regions", r.getStatements().get(0).getName());
        assertEquals(List.of("EMEA"), r.getStatements().get(0).getPayload());
    }

    @Test
    void nonSuccessStatusThrows() {
        StubTransport t = new StubTransport(new HttpTransport.Response(500, "boom"));
        assertThrows(IOException.class, () -> decide(t));
    }

    @Test
    void missingBooleanDecisionThrows() {
        StubTransport t = new StubTransport(new HttpTransport.Response(200, "{\"decision\":\"PERMIT\"}"));
        assertThrows(IOException.class, () -> decide(t));
    }
}
