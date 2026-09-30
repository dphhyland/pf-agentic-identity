package com.pingidentity.ps.oidf.rar;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class GovernanceEngineClientTest {

    private final ObjectMapper mapper = new ObjectMapper();
    private final GovernanceEngineConfig config = GovernanceEngineConfig.builder()
            .pdpUrl("https://pdp/governance-engine")
            .secretHeader("CLIENT-TOKEN")
            .secret("s3cret")
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

    private GovernanceEngineClient client(StubTransport t) {
        return new GovernanceEngineClient(config, t, new GovernanceEngineRequestBuilder(config, mapper), mapper);
    }

    @Test
    void sendsSecretHeaderAndParsesPermit() throws Exception {
        StubTransport t = new StubTransport(new HttpTransport.Response(200, "{\"decision\":\"PERMIT\",\"authorised\":true}"));
        DecisionResponse r = client(t).decide("sales_agent", Map.of("type", "sales_agent"), AttestationSubject.empty(), null, "client-1", "none");

        assertTrue(r.isPermit());
        assertEquals("s3cret", t.headers.get("CLIENT-TOKEN"));
        assertEquals("https://pdp/governance-engine", t.url);
        assertTrue(t.body.contains("\"domain\":\"sales_agent\""), t.body);
        assertTrue(t.body.contains("\"action\":\"authorize\""), t.body);
    }

    @Test
    void nonPermitIsParsedAsDeny() throws Exception {
        StubTransport t = new StubTransport(new HttpTransport.Response(200, "{\"decision\":\"DENY\",\"authorised\":false}"));
        assertFalse(client(t).decide("sales_agent", Map.of("type", "sales_agent"), AttestationSubject.empty(), null, "client-1", "none").isPermit());
    }

    private DecisionResponse decide(StubTransport t) throws IOException {
        return client(t).decide("sales_agent", Map.of("type", "sales_agent"), AttestationSubject.empty(), null, "client-1", "none");
    }

    /** A 401 from a wrong secret is the case that used to fail open; it, and every other refusal, fail closed. */
    @Test
    void nonSuccessStatusThrowsAndOnlyUnavailableStatusesFailOpen() {
        for (int status : new int[] {400, 401, 403, 404, 500}) {
            IOException e = assertThrows(IOException.class, () -> decide(new StubTransport(new HttpTransport.Response(status, "boom"))));
            assertFalse(e instanceof PdpUnavailableException, "HTTP " + status);
        }
        for (int status : new int[] {429, 502, 503, 504}) {
            assertThrows(PdpUnavailableException.class, () -> decide(new StubTransport(new HttpTransport.Response(status, "later"))));
        }
    }

    @Test
    void aNonJsonOrMalformedAnswerIsRefused() {
        assertFalse(assertThrows(IOException.class, () -> decide(new StubTransport(
                new HttpTransport.Response(200, "<html/>", "text/html; charset=utf-8")))) instanceof PdpUnavailableException);
        assertThrows(IOException.class, () -> decide(new StubTransport(new HttpTransport.Response(200, "{\"decision\":"))));
        assertThrows(IOException.class, () -> decide(new StubTransport(new HttpTransport.Response(200, "[1,2]"))));
        assertThrows(IOException.class, () -> decide(new StubTransport(new HttpTransport.Response(200, "\"PERMIT\""))));
    }

    @Test
    void anEmptyBodyIsNoDecision() throws Exception {
        assertFalse(decide(new StubTransport(new HttpTransport.Response(200, ""))).isPermit());
        assertFalse(decide(new StubTransport(new HttpTransport.Response(200, null))).isPermit());
    }
}
