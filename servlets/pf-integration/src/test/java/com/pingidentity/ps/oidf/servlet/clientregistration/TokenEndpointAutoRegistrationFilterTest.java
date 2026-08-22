package com.pingidentity.ps.oidf.servlet.clientregistration;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import java.util.List;
import java.util.function.Function;
import javax.servlet.FilterChain;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import org.jose4j.jwk.EcJwkGenerator;
import org.jose4j.jwk.EllipticCurveJsonWebKey;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.keys.EllipticCurves;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for the transparent token-endpoint auto-registration filter (OpenID Federation §12.1).
 *
 * <p>Ported from pf-oidf-modules (2026-08-15) when that repo was reduced to the demo.
 */
class TokenEndpointAutoRegistrationFilterTest {

    private static final String CLIENT_ID = "https://rp.example.com/e/agent-42";
    private static final String OP_ISSUER = "https://as.example.com";
    private static final List<String> TRUST_CHAIN = List.of("leafJwt", "anchorJwt");
    private static final Function<HttpServletRequest, String> FIXED_ISSUER = req -> OP_ISSUER;

    /** A client_assertion JWT carrying the Trust Chain in its {@code trust_chain} header and sub=client_id. */
    private static String clientAssertion(List<String> trustChain, String sub) throws Exception {
        EllipticCurveJsonWebKey key = EcJwkGenerator.generateJwk(EllipticCurves.P256);
        JwtClaims claims = new JwtClaims();
        claims.setSubject(sub);
        claims.setIssuer(sub);
        claims.setAudience(OP_ISSUER);
        claims.setGeneratedJwtId();
        claims.setIssuedAtToNow();
        claims.setExpirationTimeMinutesInTheFuture(5.0f);
        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(claims.toJson());
        jws.setKey(key.getPrivateKey());
        jws.setAlgorithmHeaderValue("ES256");
        jws.setHeader("trust_chain", trustChain);
        return jws.getCompactSerialization();
    }

    @Test
    void autoRegistersTheClientThenProceeds() throws Exception {
        RegistrationService service = mock(RegistrationService.class);
        TokenEndpointAutoRegistrationFilter filter = new TokenEndpointAutoRegistrationFilter(service, FIXED_ISSUER);
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getParameter("client_assertion")).thenReturn(clientAssertion(TRUST_CHAIN, CLIENT_ID));
        FilterChain chain = mock(FilterChain.class);
        ServletResponse response = mock(ServletResponse.class);

        filter.doFilter(request, response, chain);

        verify(service).automaticRegister(eq(TRUST_CHAIN), eq(CLIENT_ID), eq(OP_ISSUER));
        verify(chain).doFilter(request, response);
    }

    @Test
    void proceedsEvenWhenRegistrationThrows() throws Exception {
        RegistrationService service = mock(RegistrationService.class);
        doThrow(new IllegalStateException("untrusted")).when(service).automaticRegister(anyList(), anyString(), anyString());
        TokenEndpointAutoRegistrationFilter filter = new TokenEndpointAutoRegistrationFilter(service, FIXED_ISSUER);
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getParameter("client_assertion")).thenReturn(clientAssertion(TRUST_CHAIN, CLIENT_ID));
        FilterChain chain = mock(FilterChain.class);
        ServletResponse response = mock(ServletResponse.class);

        filter.doFilter(request, response, chain);

        verify(chain).doFilter(request, response);
    }

    @Test
    void proceedsUntouchedWhenNoClientAssertion() throws Exception {
        RegistrationService service = mock(RegistrationService.class);
        TokenEndpointAutoRegistrationFilter filter = new TokenEndpointAutoRegistrationFilter(service, FIXED_ISSUER);
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getParameter("client_assertion")).thenReturn(null);
        FilterChain chain = mock(FilterChain.class);
        ServletResponse response = mock(ServletResponse.class);

        filter.doFilter(request, response, chain);

        verify(chain).doFilter(request, response);
        verifyNoInteractions(service);
    }

    /**
     * A {@code client_assertion} with no {@code trust_chain} header is an ordinary
     * {@code private_key_jwt} assertion from an already-registered client, not a §12.1 candidate. This
     * must not attempt registration - a client with no chain to validate has nothing this filter can
     * provision.
     */
    @Test
    void proceedsUntouchedWhenClientAssertionCarriesNoTrustChain() throws Exception {
        RegistrationService service = mock(RegistrationService.class);
        TokenEndpointAutoRegistrationFilter filter = new TokenEndpointAutoRegistrationFilter(service, FIXED_ISSUER);
        HttpServletRequest request = mock(HttpServletRequest.class);
        // clientAssertion(...) with an empty list omits the trust_chain header entirely (see
        // extractTrustChain: only a non-empty List survives to become a candidate).
        when(request.getParameter("client_assertion")).thenReturn(clientAssertion(List.of(), CLIENT_ID));
        FilterChain chain = mock(FilterChain.class);
        ServletResponse response = mock(ServletResponse.class);

        filter.doFilter(request, response, chain);

        verify(chain).doFilter(request, response);
        verifyNoInteractions(service);
    }

    /**
     * A trust_chain header with no parseable subject (a malformed or empty-sub assertion) must not reach
     * the registration service with a blank/null client id - {@code automaticRegister} requires a
     * non-null clientId and this is the guard that keeps a bad assertion from ever calling it.
     */
    @Test
    void proceedsUntouchedWhenTheAssertionHasNoSubject() throws Exception {
        RegistrationService service = mock(RegistrationService.class);
        TokenEndpointAutoRegistrationFilter filter = new TokenEndpointAutoRegistrationFilter(service, FIXED_ISSUER);
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getParameter("client_assertion")).thenReturn(clientAssertion(TRUST_CHAIN, ""));
        FilterChain chain = mock(FilterChain.class);
        ServletResponse response = mock(ServletResponse.class);

        filter.doFilter(request, response, chain);

        verify(chain).doFilter(request, response);
        verifyNoInteractions(service);
    }
}
