package com.pingidentity.ps.oidf.servlet.attestation;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.pingidentity.ps.oidf.clientattestation.AttestationChallengeService.Consumption;
import com.pingidentity.ps.oidf.clientattestation.AttestationSupport;
import com.pingidentity.ps.oidf.clientattestation.InMemoryAttestationChallengeService;
import com.pingidentity.ps.oidf.clientattestation.StoreNamespace;
import com.pingidentity.ps.oidf.clientattestation.servlet.ClientAttestationChallengeServlet;
import com.pingidentity.ps.oidf.conformance.Requirement;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.Map;
import jakarta.servlet.ServletConfig;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.jose4j.json.JsonUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * The client attestation service's challenge endpoint: {@code GET /federation/attestation/challenge}, issuing into
 * {@code oidf:cas:challenge:*} and nowhere else.
 *
 * <p>CAS §4 (docs/openid-client-attestation-service-1_0.md): "Responses containing attestations or challenges MUST
 * include {@code Cache-Control: no-store}." CAS §4.1: the request is {@code GET /attestation-challenge}, the response
 * {@code { "attestation_challenge": "...", "expires_in": 120 }}, and "a challenge issued by one party MUST NOT be
 * accepted by the other". The path is this deployment's, discovered from {@code challenge_endpoint} (CAS §5.1).
 * Refusing every other method with 405 is this repository's decision (plan item S4b), and carries no tag.
 */
@org.junit.jupiter.api.extension.ExtendWith(InMemoryStateAccepted.class)
class AttestationIssuanceChallengeServletTest {

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

    /** The container's entry point: the HTTP overload is protected, in client-attestation's package. */
    private static Resp call(AttestationIssuanceChallengeServlet servlet, String method, String address) throws Exception {
        Resp resp = new Resp();
        servlet.service((ServletRequest) request(method, address), (ServletResponse) resp.mock);
        return resp;
    }

    @BeforeEach
    void inMemoryStores() {
        assumeTrue(System.getProperty("oidf.redis.url") == null && System.getenv("OIDF_REDIS_URL") == null
                && System.getenv("REDIS_URL") == null, "the environment configures a Redis URL, which these tests would not control");
    }

    @Test
    @Requirement({"CAS §4", "CAS §4.1"})
    void aGetGetsAnUncacheableChallengeWithItsLifetime() throws Exception {
        Resp resp = call(new AttestationIssuanceChallengeServlet(), "GET", "10.0.3.1");

        verify(resp.mock).setStatus(200);
        verify(resp.mock).setContentType("application/json");
        verify(resp.mock).setHeader("Cache-Control", "no-store");
        Map<String, Object> body = resp.json();
        assertTrue(body.get("attestation_challenge") instanceof String challenge && !challenge.isBlank(), body.toString());
        assertEquals(300L, ((Number) body.get("expires_in")).longValue(), "the default lifetime, as before the split");
    }

    @Test
    @Requirement("CAS §4.1")
    void itsChallengeIsTheAttestersAndUnknownToTheAuthorizationServer() throws Exception {
        String challenge = (String) call(new AttestationIssuanceChallengeServlet(), "GET", "10.0.3.2").json().get("attestation_challenge");

        assertEquals(Consumption.UNKNOWN, AttestationSupport.challengeService(StoreNamespace.AS).consumeChallenge(challenge),
                "the token endpoint's store has never seen it");
        assertEquals(Consumption.CONSUMED, AttestationSupport.challengeService(StoreNamespace.CAS).consumeChallenge(challenge),
                "the attester's store has it, unspent by the other's lookup");
    }

    @Test
    void aPostIsRefusedWith405NamingGetAndIssuesNothing() throws Exception {
        Resp resp = call(new AttestationIssuanceChallengeServlet(), "POST", "10.0.3.3");

        verify(resp.mock).setStatus(405);
        verify(resp.mock).setHeader("Allow", "GET");
        Map<String, Object> body = resp.json();
        assertEquals("invalid_request", body.get("error"));
        assertTrue(((String) body.get("error_description")).contains("GET"), body.toString());
        assertFalse(body.containsKey("attestation_challenge"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"HEAD", "PUT", "DELETE", "OPTIONS"})
    void everyOtherMethodIsRefusedAndWritesNoChallenge(String method) throws Exception {
        InMemoryAttestationChallengeService store =
                (InMemoryAttestationChallengeService) AttestationSupport.challengeService(StoreNamespace.CAS);
        int before = store.size();

        Resp resp = call(new AttestationIssuanceChallengeServlet(), method, "10.0.3.4");

        verify(resp.mock).setStatus(405);
        verify(resp.mock).setHeader("Allow", "GET");
        verify(resp.mock, never()).setStatus(200);
        assertEquals(before, store.size(), "a HEAD would write a challenge its response cannot carry");
    }

    @Test
    void itsOwnCapAppliesToItsOwnCallers() throws Exception {
        AttestationIssuanceChallengeServlet servlet = new AttestationIssuanceChallengeServlet();
        ServletConfig config = mock(ServletConfig.class);
        when(config.getInitParameter("challengeRateLimitPerWindow")).thenReturn("1");
        servlet.init(config);

        verify(call(servlet, "GET", "10.0.3.5").mock).setStatus(200);
        Resp second = call(servlet, "GET", "10.0.3.5");
        verify(second.mock).setStatus(429);
        assertEquals("slow_down", second.json().get("error"));

        Resp atTheAuthorizationServer = new Resp();
        new ClientAttestationChallengeServlet().service((ServletRequest) request("POST", "10.0.3.5"),
                (ServletResponse) atTheAuthorizationServer.mock);
        verify(atTheAuthorizationServer.mock).setStatus(200);
    }

    /**
     * CAS §4.6: {@code temporarily_unavailable} (503) when "the store that tracks challenges, proof {@code jti}s or
     * bindings does not answer". A challenge the store could not record is not handed out. The store is a TLS Redis
     * on a port nothing listens on, which the production profile accepts as a URL and which fails at the first
     * command.
     */
    @Test
    @Requirement("CAS §4.6")
    void aStoreThatCannotRecordTheChallengeAnswers503AndHandsNothingOut() throws Exception {
        System.setProperty("oidf.redis.url", "rediss://127.0.0.1:1");
        try {
            Resp resp = call(new AttestationIssuanceChallengeServlet(), "GET", "10.0.3.6");

            verify(resp.mock).setStatus(503);
            assertEquals("temporarily_unavailable", resp.json().get("error"));
            assertFalse(resp.body.toString().contains("attestation_challenge"), resp.body.toString());
        } finally {
            System.clearProperty("oidf.redis.url");
        }
    }

    @Test
    void itIsTheAttestersGetAtItsMappedPath() {
        AttestationIssuanceChallengeServlet servlet = new AttestationIssuanceChallengeServlet();
        assertEquals(StoreNamespace.CAS, servlet.namespace());
        assertEquals("GET", servlet.method());
        assertArrayEquals(new String[] {"/federation/attestation/challenge"},
                AttestationIssuanceChallengeServlet.class.getAnnotation(WebServlet.class).urlPatterns());
    }
}
