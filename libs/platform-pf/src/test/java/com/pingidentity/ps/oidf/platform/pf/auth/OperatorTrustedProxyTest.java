package com.pingidentity.ps.oidf.platform.pf.auth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.mockito.Mockito.when;

import jakarta.servlet.http.HttpServletRequest;
import java.util.Collections;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/**
 * The failed-authentication limit counts the client address platform's TrustedProxies gives (plan item H-ATT-3,
 * F-0275): behind a proxy {@code OIDF_TRUSTED_PROXIES} lists, each client behind it has its own counter; with the list
 * unset, a forwarding header is never believed and every caller behind the proxy shares its counter.
 */
class OperatorTrustedProxyTest {

    private final OperatorFixture f;

    OperatorTrustedProxyTest() throws Exception {
        this.f = new OperatorFixture();
    }

    @AfterEach
    void close() {
        System.clearProperty("oidf.trusted.proxies");
        this.f.close();
    }

    /** {@code r} as the proxy at the fixture's address forwards it for {@code client}. */
    private static HttpServletRequest via(OperatorFixture.Request r, String client) {
        HttpServletRequest mock = r.mock();
        when(mock.getHeaders("X-Forwarded-For")).thenAnswer(i -> Collections.enumeration(List.of(client)));
        return mock;
    }

    private void failTenTimes(OperatorAuthenticator a, String client) {
        for (int i = 0; i < 10; i++) {
            assertEquals(401, assertInstanceOf(OperatorAuthenticator.Refused.class,
                    a.authenticate(via(OperatorFixture.bearer("not-a-token"), client), OperatorFixture.READ)).status());
        }
    }

    @Test
    void behindATrustedProxyEachClientHasItsOwnCounter() throws Exception {
        System.setProperty("oidf.trusted.proxies", OperatorFixture.ADDRESS);
        OperatorAuthenticator a = this.f.jwt();
        this.failTenTimes(a, "192.0.2.1");
        assertEquals(429, assertInstanceOf(OperatorAuthenticator.Refused.class, a.authenticate(
                via(this.f.dpop(this.f.token("oidf.admin.read"), "GET"), "192.0.2.1"), OperatorFixture.READ)).status());
        assertInstanceOf(OperatorAuthenticator.Authorised.class, a.authenticate(
                via(this.f.dpop(this.f.token("oidf.admin.read"), "GET"), "192.0.2.2"), OperatorFixture.READ));
        assertEquals("192.0.2.1", this.f.events.stream().filter(e -> "429".equals(e.fields().get("status")))
                .findFirst().orElseThrow().fields().get("client_address"));
    }

    @Test
    void withNoTrustedProxyTheForwardingHeaderIsNotBelieved() throws Exception {
        OperatorAuthenticator a = this.f.jwt();
        this.failTenTimes(a, "192.0.2.1");
        assertEquals(429, assertInstanceOf(OperatorAuthenticator.Refused.class, a.authenticate(
                via(this.f.dpop(this.f.token("oidf.admin.read"), "GET"), "192.0.2.2"), OperatorFixture.READ)).status());
    }
}
