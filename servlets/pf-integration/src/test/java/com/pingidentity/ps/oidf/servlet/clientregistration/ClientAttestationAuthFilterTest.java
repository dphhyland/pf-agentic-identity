package com.pingidentity.ps.oidf.servlet.clientregistration;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.pingidentity.ps.oidf.pf.FederationRuntimeConfig;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.jose4j.jwk.EcJwkGenerator;
import org.jose4j.jwk.EllipticCurveJsonWebKey;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.keys.EllipticCurves;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

/**
 * The token-endpoint filter that turns a verified Client Attestation into the credential PF
 * understands. Its fail-closed behaviour used to be asserted in a javadoc comment and nowhere else.
 *
 * <p>The load-bearing case is the LAST one: with no bridge key the filter used to pass every request
 * through, and clients registered for attestation authentication were registered as public - so the
 * composition authenticated nobody. It must now refuse to start instead.
 */
class ClientAttestationAuthFilterTest {

    private static final String BRIDGE_KEY_PROP = "oidf.bridge.private.jwk";
    private static final String REQUIRE_PROP = "oidf.attestation.require.bridge.key";

    @AfterEach
    void clearProps() throws Exception {
        System.clearProperty(BRIDGE_KEY_PROP);
        System.clearProperty(REQUIRE_PROP);
        resetSingletons();
    }

    /** Both holders memoise; a test that changes the environment has to clear them. */
    private static void resetSingletons() throws Exception {
        java.lang.reflect.Field instance = FederationRuntimeConfig.class.getDeclaredField("instance");
        instance.setAccessible(true);
        instance.set(null, null);
        java.lang.reflect.Method reset = Class.forName("com.pingidentity.ps.oidf.pf.BridgeKey")
                .getDeclaredMethod("resetForTest");
        reset.setAccessible(true);
        reset.invoke(null);
    }

    private static String privateJwk() throws Exception {
        EllipticCurveJsonWebKey key = EcJwkGenerator.generateJwk(EllipticCurves.P256);
        key.setKeyId("bridge-test");
        return key.toJson(JsonWebKey.OutputControlLevel.INCLUDE_PRIVATE);
    }

    private static HttpServletRequest requestWithoutAttestation() {
        HttpServletRequest req = mock(HttpServletRequest.class);
        when(req.getHeader(any())).thenReturn(null);
        return req;
    }

    @Test
    void refusesToStartWhenTheBridgeKeyIsMissingAndRequired() throws Exception {
        resetSingletons();

        ServletException e = assertThrows(ServletException.class,
                () -> new ClientAttestationAuthFilter().init(null));

        assertTrue(e.getMessage().contains(FederationRuntimeConfig.BRIDGE_KEY_ENV), e.getMessage());
        assertTrue(e.getMessage().contains(FederationRuntimeConfig.REQUIRE_BRIDGE_KEY_ENV),
                "the failure must name the opt-out, or an operator cannot act on it: " + e.getMessage());
    }

    @Test
    void refusesToStartWhenTheBridgeKeyIsMalformed() throws Exception {
        System.setProperty(BRIDGE_KEY_PROP, "{\"kty\":\"EC\",\"crv\":\"nonsense\"}");
        resetSingletons();

        assertThrows(ServletException.class, () -> new ClientAttestationAuthFilter().init(null),
                "a malformed key must fail loudly, not degrade to pass-through");
    }

    @Test
    void startsWithoutABridgeKeyOnlyWhenExplicitlyOptedOut() throws Exception {
        System.setProperty(REQUIRE_PROP, "false");
        resetSingletons();

        assertDoesNotThrow(() -> new ClientAttestationAuthFilter().init(null));
    }

    @Test
    void startsWhenAValidBridgeKeyIsConfigured() throws Exception {
        System.setProperty(BRIDGE_KEY_PROP, privateJwk());
        resetSingletons();

        assertDoesNotThrow(() -> new ClientAttestationAuthFilter().init(null));
    }

    @Test
    void aRequestWithNoAttestationHeaderIsForwardedUntouched() throws Exception {
        System.setProperty(BRIDGE_KEY_PROP, privateJwk());
        resetSingletons();
        ClientAttestationAuthFilter filter = new ClientAttestationAuthFilter();
        filter.init(null);
        HttpServletRequest req = requestWithoutAttestation();
        HttpServletResponse resp = mock(HttpServletResponse.class);
        FilterChain chain = mock(FilterChain.class);

        filter.doFilter(req, resp, chain);

        ArgumentCaptor<ServletRequest> forwarded = ArgumentCaptor.forClass(ServletRequest.class);
        verify(chain).doFilter(forwarded.capture(), any());
        assertSame(req, forwarded.getValue(),
                "with no attestation the request must pass through unwrapped - the filter only ever "
                        + "translates a verified attestation, it never adds a credential of its own");
        verify(resp, never()).setStatus(any(Integer.class));
    }

    @Test
    void bothAttestationHeadersAreRequiredTogether() throws Exception {
        System.setProperty(BRIDGE_KEY_PROP, privateJwk());
        resetSingletons();
        ClientAttestationAuthFilter filter = new ClientAttestationAuthFilter();
        filter.init(null);
        HttpServletRequest req = mock(HttpServletRequest.class);
        when(req.getHeader("OAuth-Client-Attestation")).thenReturn("a.b.c");
        when(req.getHeaders("OAuth-Client-Attestation"))
                .thenReturn(java.util.Collections.enumeration(java.util.List.of("a.b.c", "d.e.f")));
        HttpServletResponse resp = mock(HttpServletResponse.class);
        java.io.StringWriter body = new java.io.StringWriter();
        when(resp.getWriter()).thenReturn(new java.io.PrintWriter(body));
        FilterChain chain = mock(FilterChain.class);

        filter.doFilter(req, resp, chain);

        verify(resp).setStatus(400);
        verify(chain, never()).doFilter(any(), any());
        assertNotNull(body.toString());
    }
}
