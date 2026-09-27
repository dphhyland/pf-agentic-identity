package com.pingidentity.ps.oidf.clientattestation.servlet;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.PrintWriter;
import java.io.StringWriter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

/**
 * A challenge the store could not record must not be handed out: it could never be consumed, and the client
 * would fetch another to meet the same store. The endpoint answers 503 {@code temporarily_unavailable} instead.
 * The store is a TLS Redis on a port nothing listens on, which the production profile accepts as a URL and
 * which fails at the first command.
 *
 * <p>No {@code @Requirement}: RFC 6749 defines {@code temporarily_unavailable} in §4.1.2.1, for the authorization
 * endpoint's redirect, and this endpoint is ABCA's challenge endpoint. The 503 and the code are this project's
 * decision (plan item S3a).
 */
class ChallengeEndpointStoreOutageTest {
    private static final String REDIS_URL_PROPERTY = "oidf.redis.url";

    @BeforeEach
    void pointTheStoreAtNothing() {
        System.setProperty(REDIS_URL_PROPERTY, "rediss://127.0.0.1:1");
    }

    @AfterEach
    void restoreInMemoryStores() {
        System.clearProperty(REDIS_URL_PROPERTY);
    }

    @Test
    void anUnavailableStoreAnswers503WithTemporarilyUnavailableAndNoChallenge() throws Exception {
        ClientAttestationChallengeServlet servlet = new ClientAttestationChallengeServlet();
        HttpServletRequest req = mock(HttpServletRequest.class);
        when(req.getRemoteAddr()).thenReturn("10.0.0.9");
        HttpServletResponse resp = mock(HttpServletResponse.class);
        StringWriter body = new StringWriter();
        when(resp.getWriter()).thenReturn(new PrintWriter(body));

        servlet.doPost(req, resp);

        ArgumentCaptor<Integer> status = ArgumentCaptor.forClass(Integer.class);
        org.mockito.Mockito.verify(resp).setStatus(status.capture());
        assertEquals(503, status.getValue());
        assertTrue(body.toString().contains("\"temporarily_unavailable\""), body.toString());
        assertTrue(!body.toString().contains("attestation_challenge"), body.toString());
    }
}
