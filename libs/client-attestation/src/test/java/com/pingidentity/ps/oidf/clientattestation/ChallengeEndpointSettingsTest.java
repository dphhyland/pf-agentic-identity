package com.pingidentity.ps.oidf.clientattestation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assumptions.assumeTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.pingidentity.ps.oidf.clientattestation.servlet.ChallengeEndpointServlet;
import com.pingidentity.ps.oidf.clientattestation.servlet.ClientAttestationChallengeServlet;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.Map;
import jakarta.servlet.ServletConfig;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Each challenge endpoint's init-params reach its own namespace and no other: the authorization server's endpoint
 * sizes {@code oidf:as:challenge:*}, the attester's {@code oidf:cas:challenge:*}. Before plan item S4b there was one
 * endpoint and one store, so its settings were everybody's. Here rather than beside the servlets because
 * {@link AttestationSupport#reset()} is package-private, and these tests change process-wide state.
 */
class ChallengeEndpointSettingsTest {

    @BeforeEach
    void inMemoryStores() {
        assumeTrue(System.getenv("OIDF_REDIS_URL") == null && System.getenv("REDIS_URL") == null,
                "the environment configures a Redis URL, which these tests would not control");
        System.clearProperty("oidf.redis.url");
        AttestationSupport.reset();
    }

    @AfterEach
    void forget() {
        AttestationSupport.reset();
    }

    private static ServletConfig config(Map<String, String> params) {
        ServletConfig config = mock(ServletConfig.class);
        params.forEach((name, value) -> when(config.getInitParameter(name)).thenReturn(value));
        return config;
    }

    /** An endpoint over the attester's namespace, as attestation-issuer's is; this module cannot see that class. */
    private static ChallengeEndpointServlet attesterEndpoint() {
        return new ChallengeEndpointServlet(StoreNamespace.CAS, "GET") {
            private static final long serialVersionUID = 1L;
        };
    }

    private static int status(ChallengeEndpointServlet servlet, String method, String address) throws Exception {
        HttpServletRequest req = mock(HttpServletRequest.class);
        when(req.getMethod()).thenReturn(method);
        when(req.getRemoteAddr()).thenReturn(address);
        HttpServletResponse resp = mock(HttpServletResponse.class);
        when(resp.getWriter()).thenReturn(new PrintWriter(new StringWriter()));
        // The public entry point, as the container calls it: the HTTP overload is protected, in another package.
        servlet.service((jakarta.servlet.ServletRequest) req, (jakarta.servlet.ServletResponse) resp);
        org.mockito.ArgumentCaptor<Integer> status = org.mockito.ArgumentCaptor.forClass(Integer.class);
        verify(resp).setStatus(status.capture());
        return status.getValue();
    }

    @Test
    void theAuthorizationServersTtlStaysWithItsOwnChallenges() throws Exception {
        new ClientAttestationChallengeServlet().init(config(Map.of("challengeTtlSeconds", "90")));

        assertEquals(90L, AttestationSupport.challengeService(StoreNamespace.AS).ttlSeconds());
        assertEquals(AttestationChallengeService.DEFAULT_TTL_SECONDS, AttestationSupport.challengeService(StoreNamespace.CAS).ttlSeconds(),
                "the attester's challenges keep the default, whichever endpoint starts first");
    }

    @Test
    void theAttestersSizeAndTtlStayWithItsOwnChallenges() throws Exception {
        AttestationChallengeService before = AttestationSupport.challengeService(StoreNamespace.AS);
        attesterEndpoint().init(config(Map.of("challengeCacheMaxEntries", "2", "challengeTtlSeconds", " ")));

        AttestationChallengeService cas = AttestationSupport.challengeService(StoreNamespace.CAS);
        assertEquals(AttestationChallengeService.DEFAULT_TTL_SECONDS, cas.ttlSeconds(), "a size with a blank TTL keeps the default TTL");
        String first = cas.issue();
        cas.issue();
        cas.issue();
        assertEquals(AttestationChallengeService.Consumption.UNKNOWN, cas.consumeChallenge(first), "a bound of two evicted the first");
        assertSame(before, AttestationSupport.challengeService(StoreNamespace.AS), "the authorization server's store is untouched");
    }

    @Test
    void noChallengeSettingLeavesTheStoreAlone() throws Exception {
        AttestationChallengeService before = AttestationSupport.challengeService(StoreNamespace.CAS);
        attesterEndpoint().init(config(Map.of()));
        assertSame(before, AttestationSupport.challengeService(StoreNamespace.CAS));
    }

    @Test
    void aValueThatIsNotAnIntegerIsIgnoredAndTheDefaultUsed() throws Exception {
        attesterEndpoint().init(config(Map.of("challengeTtlSeconds", "soon", "challengeCacheMaxEntries", " ",
                "challengeRateLimitPerWindow", "many")));
        assertEquals(AttestationChallengeService.DEFAULT_TTL_SECONDS, AttestationSupport.challengeService(StoreNamespace.CAS).ttlSeconds());
    }

    @Test
    void aTtlTheStoreRefusesFailsTheEndpointAndKeepsTheStoreItHad() throws Exception {
        AttestationChallengeService before = AttestationSupport.challengeService(StoreNamespace.CAS);
        ChallengeEndpointServlet endpoint = attesterEndpoint();
        assertThrows(IllegalArgumentException.class, () -> endpoint.init(config(Map.of("challengeTtlSeconds", "0"))));
        assertSame(before, AttestationSupport.challengeService(StoreNamespace.CAS));
        assertEquals(AttestationChallengeService.DEFAULT_TTL_SECONDS, AttestationSupport.challengeService(StoreNamespace.CAS).ttlSeconds());
    }

    @Test
    void eachRateSettingAloneTakesEffectWithTheOthersDefaulted() throws Exception {
        ChallengeEndpointServlet perWindow = attesterEndpoint();
        perWindow.init(config(Map.of("challengeRateLimitPerWindow", "1")));
        assertEquals(200, status(perWindow, "GET", "10.0.2.1"));
        assertEquals(429, status(perWindow, "GET", "10.0.2.1"));

        ChallengeEndpointServlet window = attesterEndpoint();
        window.init(config(Map.of("challengeRateLimitWindowSeconds", "1")));
        assertEquals(200, status(window, "GET", "10.0.2.2"));

        ChallengeEndpointServlet callers = attesterEndpoint();
        callers.init(config(Map.of("challengeRateLimitMaxCallers", "1")));
        assertEquals(200, status(callers, "GET", "10.0.2.3"));
        assertEquals(200, status(callers, "GET", "10.0.2.4"));
    }

    @Test
    void theAuthorizationServersEndpointStillSizesItsReplayCache() throws Exception {
        AttestationReplayCache before = AttestationSupport.replayCache(StoreNamespace.AS);
        new ClientAttestationChallengeServlet().init(config(Map.of("replayCacheMaxEntries", "16")));
        assertNotSame(before, AttestationSupport.replayCache(StoreNamespace.AS));

        AttestationReplayCache sized = AttestationSupport.replayCache(StoreNamespace.AS);
        new ClientAttestationChallengeServlet().init(config(Map.of("replayCacheMaxEntries", "sixteen")));
        new ClientAttestationChallengeServlet().init(config(Map.of("replayCacheMaxEntries", " ")));
        assertSame(sized, AttestationSupport.replayCache(StoreNamespace.AS), "a value that is not an integer is ignored");
    }
}
