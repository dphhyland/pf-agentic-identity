/*
 * Stream-registration client: request shapes for create/add-subject/verify.
 */
package com.pingidentity.ps.oidf.ssf;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

class ReceiverStreamClientTest {

    private static final class Call {
        final String method;
        final String url;
        final String body;

        Call(String method, String url, String body) {
            this.method = method;
            this.url = url;
            this.body = body;
        }
    }

    @Test
    void createPushStreamPostsDeliveryAndReturnsId() throws Exception {
        List<Call> calls = new ArrayList<>();
        ReceiverStreamClient c = new ReceiverStreamClient("https://tx.example.com/", (m, u, b) -> {
            calls.add(new Call(m, u, b));
            return "{\"stream_id\":\"s-1\"}";
        });
        String id = c.createPushStream("https://me.example.com",
                List.of(SsfEventTypes.CAEP_SESSION_REVOKED), "https://me.example.com/ssf/receiver/events", "tok");
        assertEquals("s-1", id);
        assertEquals("POST", calls.get(0).method);
        assertEquals("https://tx.example.com/ssf/streams", calls.get(0).url, "trailing slash trimmed");
        assertTrue(calls.get(0).body.contains("urn:ietf:rfc:8935"));
        assertTrue(calls.get(0).body.contains("\"authorization_header\":\"Bearer tok\""));
    }

    @Test
    void missingStreamIdThrows() {
        ReceiverStreamClient c = new ReceiverStreamClient("https://tx.example.com", (m, u, b) -> "{}");
        assertThrows(IllegalStateException.class,
                () -> c.createPollStream("https://me.example.com", List.of()));
    }

    @Test
    void addSubjectAndVerifyHitTheRightEndpoints() throws Exception {
        List<Call> calls = new ArrayList<>();
        ReceiverStreamClient c = new ReceiverStreamClient("https://tx.example.com", (m, u, b) -> {
            calls.add(new Call(m, u, b));
            return "{}";
        });
        c.addSubject("s-1", SubjectId.email("bob@example.com"));
        c.requestVerification("s-1", "st");
        assertEquals("https://tx.example.com/ssf/subjects:add", calls.get(0).url);
        assertTrue(calls.get(0).body.contains("bob@example.com"));
        assertEquals("https://tx.example.com/ssf/verify", calls.get(1).url);
        assertTrue(calls.get(1).body.contains("\"state\":\"st\""));
    }
}
