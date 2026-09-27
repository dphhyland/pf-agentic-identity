package com.pingidentity.ps.oidf.clientattestation.servlet;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.pingidentity.ps.oidf.clientattestation.AttestationChallengeService.Consumption;
import com.pingidentity.ps.oidf.clientattestation.AttestationSupport;
import com.pingidentity.ps.oidf.clientattestation.ChallengeRateLimiter;
import com.pingidentity.ps.oidf.clientattestation.StoreNamespace;
import com.pingidentity.ps.oidf.conformance.Requirement;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.Map;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.jose4j.json.JsonUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * The authorization server's challenge endpoint takes POST and nothing else, and its challenges live in the
 * authorization server's namespace only.
 *
 * <p>ABCA-10 §6.1 (draft-ietf-oauth-attestation-based-client-auth-10, read 2026-09-27 at ietf.org; -11 reads the
 * same): the request is an HTTP POST to the {@code challenge_endpoint} URL, the 200 response carries
 * {@code attestation_challenge} in an {@code application/json} body, and the response is made uncacheable with
 * {@code Cache-Control: no-store}. What the endpoint does with any other method is this repository's decision
 * (plan item S4b), so those tests carry no {@code @Requirement}.
 */
class ChallengeEndpointMethodTest {

    private static final class Resp {
        final HttpServletResponse mock = mock(HttpServletResponse.class);
        final StringWriter body = new StringWriter();

        Resp() throws IOException {
            when(mock.getWriter()).thenReturn(new PrintWriter(body));
        }

        Map<String, Object> json() throws Exception {
            return JsonUtil.parseJson(body.toString());
        }
    }

    private static HttpServletRequest request(String method, String address) {
        HttpServletRequest req = mock(HttpServletRequest.class);
        when(req.getMethod()).thenReturn(method);
        when(req.getRemoteAddr()).thenReturn(address);
        return req;
    }

    @BeforeEach
    void inMemoryStores() {
        assumeTrue(System.getProperty("oidf.redis.url") == null && System.getenv("OIDF_REDIS_URL") == null
                && System.getenv("REDIS_URL") == null, "the environment configures a Redis URL, which these tests would not control");
    }

    @Test
    @Requirement("ABCA-10 §6.1")
    void aPostGetsAnUncacheableJsonChallenge() throws Exception {
        Resp resp = new Resp();
        new ClientAttestationChallengeServlet().service(request("POST", "10.0.1.1"), resp.mock);

        verify(resp.mock).setStatus(200);
        verify(resp.mock).setContentType("application/json");
        verify(resp.mock).setHeader("Cache-Control", "no-store");
        Map<String, Object> body = resp.json();
        assertTrue(body.get("attestation_challenge") instanceof String challenge && !challenge.isBlank(), body.toString());
        assertEquals(300L, ((Number) body.get("expires_in")).longValue());
    }

    @Test
    void theChallengeIsTheAuthorizationServersAndUnknownToTheAttester() throws Exception {
        Resp resp = new Resp();
        new ClientAttestationChallengeServlet().service(request("POST", "10.0.1.2"), resp.mock);
        String challenge = (String) resp.json().get("attestation_challenge");

        assertEquals(Consumption.UNKNOWN, AttestationSupport.challengeService(StoreNamespace.CAS).consumeChallenge(challenge),
                "the attester's store has never seen it");
        assertEquals(Consumption.CONSUMED, AttestationSupport.challengeService(StoreNamespace.AS).consumeChallenge(challenge),
                "the authorization server's store has it, and the attester's lookup did not spend it");
        assertEquals(Consumption.UNKNOWN, AttestationSupport.challengeService(StoreNamespace.AS).consumeChallenge(challenge));
    }

    @Test
    void aGetIsRefusedWith405NamingPostAndIssuesNothing() throws Exception {
        Resp resp = new Resp();
        new ClientAttestationChallengeServlet().service(request("GET", "10.0.1.3"), resp.mock);

        verify(resp.mock).setStatus(405);
        verify(resp.mock).setHeader("Allow", "POST");
        verify(resp.mock).setHeader("Cache-Control", "no-store");
        Map<String, Object> body = resp.json();
        assertEquals("invalid_request", body.get("error"));
        assertTrue(((String) body.get("error_description")).contains("POST"), body.toString());
        assertFalse(body.containsKey("attestation_challenge"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"HEAD", "PUT", "DELETE", "PATCH", "OPTIONS", "TRACE"})
    void everyOtherMethodIsRefusedTheSameWay(String method) throws Exception {
        Resp resp = new Resp();
        new ClientAttestationChallengeServlet().service(request(method, "10.0.1.4"), resp.mock);

        verify(resp.mock).setStatus(405);
        verify(resp.mock).setHeader("Allow", "POST");
        verify(resp.mock, never()).setStatus(200);
        assertFalse(resp.body.toString().contains("attestation_challenge"), resp.body.toString());
    }

    @Test
    void aRefusedMethodDoesNotSpendTheCallersAllowance() throws Exception {
        ClientAttestationChallengeServlet servlet = new ClientAttestationChallengeServlet();
        servlet.setRateLimiterForTest(new ChallengeRateLimiter(1, 60L, 16));

        servlet.service(request("GET", "10.0.1.5"), new Resp().mock);
        Resp post = new Resp();
        servlet.service(request("POST", "10.0.1.5"), post.mock);

        verify(post.mock).setStatus(200);
        assertNotNull(post.json().get("attestation_challenge"));
    }

    @Test
    void theEndpointIsTheAuthorizationServersPostAtItsMappedPath() {
        ClientAttestationChallengeServlet servlet = new ClientAttestationChallengeServlet();
        assertEquals(StoreNamespace.AS, servlet.namespace());
        assertEquals("POST", servlet.method());
        assertArrayEquals(new String[] {"/federation/attestation-challenge"},
                ClientAttestationChallengeServlet.class.getAnnotation(WebServlet.class).urlPatterns());
        assertEquals(ClientAttestationChallengeServlet.PATH,
                ClientAttestationChallengeServlet.class.getAnnotation(WebServlet.class).urlPatterns()[0]);
    }

    @Test
    void anEndpointNeedsANamespaceAndAMethod() {
        assertThrows(NullPointerException.class, () -> new ChallengeEndpointServlet(null, "GET") { });
        assertThrows(NullPointerException.class, () -> new ChallengeEndpointServlet(StoreNamespace.CAS, null) { });
    }
}
