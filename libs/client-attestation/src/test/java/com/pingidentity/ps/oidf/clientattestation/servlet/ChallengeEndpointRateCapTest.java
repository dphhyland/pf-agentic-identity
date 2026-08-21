package com.pingidentity.ps.oidf.clientattestation.servlet;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.pingidentity.ps.oidf.clientattestation.ChallengeRateLimiter;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.Test;

/**
 * The cap firing through {@code doPost}, not merely existing in the limiter it delegates to — a
 * correct limiter that nothing calls is the shape this kind of fix usually fails in.
 */
class ChallengeEndpointRateCapTest {

    private static final class Resp {
        final HttpServletResponse mock = mock(HttpServletResponse.class);
        final StringWriter body = new StringWriter();

        Resp() throws IOException {
            when(mock.getWriter()).thenReturn(new PrintWriter(body));
        }
    }

    private static HttpServletRequest from(String address) {
        HttpServletRequest req = mock(HttpServletRequest.class);
        when(req.getRemoteAddr()).thenReturn(address);
        return req;
    }

    @Test
    void aCallerOverTheCapGets429WithRetryAfterAndNoChallenge() throws Exception {
        ClientAttestationChallengeServlet servlet = new ClientAttestationChallengeServlet();
        servlet.setRateLimiterForTest(new ChallengeRateLimiter(1, 60L, 16));

        Resp first = new Resp();
        servlet.doPost(from("10.0.0.1"), first.mock);
        verify(first.mock).setStatus(200);
        assertTrue(first.body.toString().contains("attestation_challenge"), first.body.toString());

        Resp second = new Resp();
        servlet.doPost(from("10.0.0.1"), second.mock);

        verify(second.mock).setStatus(429);
        verify(second.mock).setHeader("Retry-After", "60");
        assertTrue(second.body.toString().contains("slow_down"), second.body.toString());
        assertTrue(!second.body.toString().contains("attestation_challenge"),
                "a throttled request must not consume a challenge cache entry - the eviction it causes "
                        + "is the whole reason for the cap");
    }

    @Test
    void aDifferentCallerIsUnaffected() throws Exception {
        ClientAttestationChallengeServlet servlet = new ClientAttestationChallengeServlet();
        servlet.setRateLimiterForTest(new ChallengeRateLimiter(1, 60L, 16));

        servlet.doPost(from("10.0.0.1"), new Resp().mock);

        Resp other = new Resp();
        servlet.doPost(from("10.0.0.2"), other.mock);

        verify(other.mock).setStatus(200);
        verify(other.mock, never()).setStatus(429);
    }

    @Test
    void anOrdinaryRequestStillGetsAChallenge() throws Exception {
        ClientAttestationChallengeServlet servlet = new ClientAttestationChallengeServlet();
        Resp resp = new Resp();

        servlet.doPost(from("10.0.0.9"), resp.mock);

        verify(resp.mock).setStatus(200);
        verify(resp.mock).setHeader("Cache-Control", "no-store");
        assertTrue(resp.body.toString().contains("expires_in"), resp.body.toString());
    }
}
