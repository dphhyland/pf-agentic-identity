package com.pingidentity.ps.oidf.clientattestation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.pingidentity.ps.oidf.clientattestation.servlet.ChallengeEndpointServlet;
import com.pingidentity.ps.oidf.clientattestation.servlet.ClientAttestationChallengeServlet;
import com.pingidentity.ps.oidf.platform.component.ComponentState;
import com.pingidentity.ps.oidf.platform.events.Events;
import com.pingidentity.ps.oidf.platform.health.PartStatus;
import com.pingidentity.ps.oidf.platform.health.Startup;
import com.pingidentity.ps.oidf.platform.profile.AcceptedRisks;
import com.pingidentity.ps.oidf.platform.profile.ProfileRefusals;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.time.LocalDate;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import jakarta.servlet.ServletConfig;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Both challenge endpoints count callers by the client address platform's TrustedProxies gives (plan item H-ATT-3,
 * F-0116): behind a proxy {@code OIDF_TRUSTED_PROXIES} lists, each client has its own allowance; from a sender it does
 * not list, a forwarding header changes nothing; and a list that cannot be read leaves the endpoint FAILED_CONFIG.
 * Here rather than beside the servlets because {@link AttestationSupport#reset()} is package-private.
 */
class ChallengeEndpointTrustedProxyTest {

    private static final AcceptedRisks IN_MEMORY = AcceptedRisks.parse("in-memory-state", LocalDate.of(2026, 9, 30));
    private static final String PROXY = "10.20.0.5";

    @BeforeEach
    void inMemoryStores() {
        assumeTrue(System.getenv("OIDF_REDIS_URL") == null && System.getenv("REDIS_URL") == null,
                "the environment configures a Redis URL, which these tests would not control");
        System.clearProperty("oidf.redis.url");
        AttestationSupport.reset();
        ProfileRefusals.resetForTests();
        AttestationSupport.acceptedRisksForTests(IN_MEMORY);
        Events.reset();
    }

    @AfterEach
    void forget() {
        System.clearProperty("oidf.trusted.proxies");
        AttestationSupport.reset();
        ProfileRefusals.resetForTests();
        Events.reset();
    }

    private static ServletConfig config(Map<String, String> params) {
        ServletConfig config = mock(ServletConfig.class);
        params.forEach((name, value) -> when(config.getInitParameter(name)).thenReturn(value));
        return config;
    }

    private static ChallengeEndpointServlet attesterEndpoint() {
        return new ChallengeEndpointServlet(StoreNamespace.CAS, "GET") {
            private static final long serialVersionUID = 1L;
        };
    }

    private static PartStatus part(String name) {
        return Startup.parts().parts().stream().filter(p -> p.part().equals(name)).findFirst().orElseThrow();
    }

    /** What {@code endpoint} answers {@code method} from {@code sender}, forwarded for {@code client} when not null. */
    private static int status(ChallengeEndpointServlet endpoint, String method, String sender, String client) throws Exception {
        HttpServletRequest req = mock(HttpServletRequest.class);
        when(req.getMethod()).thenReturn(method);
        when(req.getRemoteAddr()).thenReturn(sender);
        if (client != null) {
            when(req.getHeaders("X-Forwarded-For")).thenAnswer(i -> Collections.enumeration(List.of(client)));
        }
        HttpServletResponse resp = mock(HttpServletResponse.class);
        when(resp.getWriter()).thenReturn(new PrintWriter(new StringWriter()));
        when(resp.getOutputStream()).thenReturn(new jakarta.servlet.ServletOutputStream() {
            @Override
            public void write(int b) {
            }

            @Override
            public boolean isReady() {
                return true;
            }

            @Override
            public void setWriteListener(jakarta.servlet.WriteListener listener) {
            }
        });
        int[] status = {0};
        org.mockito.Mockito.doAnswer(i -> status[0] = i.getArgument(0)).when(resp).setStatus(org.mockito.ArgumentMatchers.anyInt());
        endpoint.service((jakarta.servlet.ServletRequest) req, (jakarta.servlet.ServletResponse) resp);
        return status[0];
    }

    private static void eachClientHasItsOwnAllowance(ChallengeEndpointServlet endpoint, String method) throws Exception {
        assertEquals(200, status(endpoint, method, PROXY, "192.0.2.1"));
        assertEquals(429, status(endpoint, method, PROXY, "192.0.2.1"), "the second call from one client is over the cap");
        assertEquals(200, status(endpoint, method, PROXY, "192.0.2.2"), "another client behind the same proxy is not");
        // A client that forges a chain is counted by the hop our proxy appended.
        assertEquals(429, status(endpoint, method, PROXY, "198.51.100.9, 192.0.2.1"));
    }

    @Test
    void theAttestersEndpointCountsEachClientBehindATrustedProxy() throws Exception {
        System.setProperty("oidf.trusted.proxies", "10.20.0.0/16");
        ChallengeEndpointServlet endpoint = attesterEndpoint();
        endpoint.init(config(Map.of("challengeRateLimitPerWindow", "1")));
        eachClientHasItsOwnAllowance(endpoint, "GET");
    }

    @Test
    void theAuthorizationServersEndpointCountsEachClientBehindATrustedProxy() throws Exception {
        System.setProperty("oidf.trusted.proxies", "10.20.0.0/16");
        ClientAttestationChallengeServlet endpoint = new ClientAttestationChallengeServlet();
        endpoint.init(config(Map.of("challengeRateLimitPerWindow", "1")));
        eachClientHasItsOwnAllowance(endpoint, "POST");
    }

    @Test
    void withNoTrustedProxyEveryCallerBehindTheProxySharesItsAllowance() throws Exception {
        ChallengeEndpointServlet endpoint = attesterEndpoint();
        endpoint.init(config(Map.of("challengeRateLimitPerWindow", "1")));
        assertEquals(200, status(endpoint, "GET", PROXY, "192.0.2.1"));
        assertEquals(429, status(endpoint, "GET", PROXY, "192.0.2.2"), "the header is not believed from an unlisted sender");
    }

    @Test
    void aListThatCannotBeReadFailsTheEndpointNamingTheSetting() throws Exception {
        System.setProperty("oidf.trusted.proxies", "10.20.0.0/16 the-load-balancer");
        ChallengeEndpointServlet endpoint = attesterEndpoint();
        endpoint.init(config(Map.of()));
        PartStatus part = part("ChallengeEndpointServlet");
        assertEquals(ComponentState.FAILED_CONFIG, part.state());
        assertTrue(part.reason().contains("OIDF_TRUSTED_PROXIES"), part.reason());
        assertEquals(503, status(endpoint, "GET", PROXY, null));
    }
}
