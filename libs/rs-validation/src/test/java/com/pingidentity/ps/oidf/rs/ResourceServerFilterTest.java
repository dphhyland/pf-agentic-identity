package com.pingidentity.ps.oidf.rs;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.pingidentity.ps.oidf.conformance.Requirement;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/** The filter's answers: the status, the WWW-Authenticate challenges, DPoP-Nonce, and what reaches the chain. */
class ResourceServerFilterTest {
    private Fixture f;
    private DelegatedTokenValidator validator;
    private FilterChain chain;
    private Map<String, List<String>> sent;
    private int[] status;

    @BeforeEach
    void setUp() throws Exception {
        this.f = new Fixture();
        this.validator = this.f.builder(new InMemoryReplayStore()).build();
        this.chain = mock(FilterChain.class);
    }

    private HttpServletRequest request(List<String> authorization, List<String> dpop, String query) {
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getHeaders("Authorization")).thenReturn(Collections.enumeration(authorization));
        when(request.getHeaders("DPoP")).thenReturn(Collections.enumeration(dpop));
        when(request.getMethod()).thenReturn("GET");
        when(request.getRequestURI()).thenReturn("/orders");
        when(request.getQueryString()).thenReturn(query);
        return request;
    }

    private HttpServletResponse response() {
        this.sent = new HashMap<>();
        this.status = new int[] {0};
        HttpServletResponse response = mock(HttpServletResponse.class);
        org.mockito.Mockito.doAnswer(i -> {
            this.sent.put(i.getArgument(0), new ArrayList<>(List.of((String) i.getArgument(1))));
            return null;
        }).when(response).setHeader(any(), any());
        org.mockito.Mockito.doAnswer(i -> {
            this.sent.computeIfAbsent(i.getArgument(0), k -> new ArrayList<>()).add(i.getArgument(1));
            return null;
        }).when(response).addHeader(any(), any());
        org.mockito.Mockito.doAnswer(i -> {
            this.status[0] = i.getArgument(0);
            return null;
        }).when(response).setStatus(org.mockito.ArgumentMatchers.anyInt());
        return response;
    }

    private HttpServletResponse run(ResourceServerFilter filter, HttpServletRequest request) throws Exception {
        HttpServletResponse response = this.response();
        filter.doFilter(request, response, this.chain);
        return response;
    }

    private ResourceServerFilter filter(DelegatedTokenValidator v) {
        return new ResourceServerFilter(v, Fixture.BASE);
    }

    @Test
    void aValidRequestReachesTheChainWithItsResult() throws Exception {
        String token = this.f.token();
        HttpServletRequest request = this.request(List.of("DPoP " + token), List.of(this.f.proof(token)), "page=2");
        HttpServletResponse response = this.run(this.filter(this.validator), request);
        verify(this.chain).doFilter(request, response);
        verify(request).setAttribute(eq(ResourceServerFilter.RESULT_ATTRIBUTE), any(DelegatedTokenValidator.Result.class));
        assertTrue(this.sent.isEmpty());
    }

    /**
     * RFC 6750 §3.1: "If the request lacks any authentication information (e.g., the client was unaware that
     * authentication is necessary or attempted using an unsupported authentication method), the resource server
     * SHOULD NOT include an error code or other error information." RFC 9449 §7.1: "An algs parameter SHOULD be
     * included to signal to the client the JWS algorithms that are acceptable for the DPoP proof JWT."
     */
    @Test
    @Requirement({"RFC6750 §3.1", "RFC9449 §7.1"})
    void noCredentialsIsAChallengeWithoutAnError() throws Exception {
        this.run(this.filter(this.validator), this.request(List.of(), List.of(), null));
        assertEquals(401, this.status[0]);
        assertEquals(List.of("DPoP algs=\"ES256 PS256 RS256\""), this.sent.get("WWW-Authenticate"));
        verify(this.chain, never()).doFilter(any(), any());

        this.run(this.filter(this.validator), this.request(List.of("Basic dXNlcjpwYXNz"), List.of(), null));
        assertEquals(List.of("DPoP algs=\"ES256 PS256 RS256\""), this.sent.get("WWW-Authenticate"));
    }

    /**
     * RFC 9449 §7.1: "An error parameter ([RFC6750], Section 3) SHOULD be included to indicate the reason why the
     * request was declined, if the request included an access token but failed authentication." RFC 6750 §3.1:
     * invalid_token - "The resource SHOULD respond with the HTTP 401 (Unauthorized) status code."
     */
    @Test
    @Requirement({"RFC9449 §7.1", "RFC6750 §3.1"})
    void aRefusedTokenCarriesTheErrorInTheDpopChallenge() throws Exception {
        String token = this.f.token();
        String proof = Fixture.proof(new Fixture().clientKey, token, "GET", Fixture.URL, c -> { });
        this.run(this.filter(this.validator), this.request(List.of("dpop  " + token), List.of(proof), null));
        assertEquals(401, this.status[0]);
        String challenge = this.sent.get("WWW-Authenticate").get(0);
        assertTrue(challenge.startsWith("DPoP algs=\"ES256 PS256 RS256\", error=\"invalid_token\", error_description=\""),
                challenge);
        assertEquals(List.of("no-store"), this.sent.get("Cache-Control"));
    }

    /**
     * RFC 9449 §7.1: "Additionally, invalid_dpop_proof is used to indicate that the DPoP proof itself was deemed
     * invalid based on the criteria of Section 4.3." The request URI the proof must name is the configured base URL
     * and the path, so a proof made for the Host header's server is refused.
     */
    @Test
    @Requirement({"RFC9449 §7.1", "RFC9449 §4.3"})
    void aProofForAnotherOriginIsInvalidDpopProof() throws Exception {
        String token = this.f.token();
        String proof = this.f.proof(token, "GET", "https://attacker.example.com/orders", c -> { });
        this.run(this.filter(this.validator), this.request(List.of("DPoP " + token), List.of(proof), null));
        assertTrue(this.sent.get("WWW-Authenticate").get(0).contains("error=\"invalid_dpop_proof\""));
    }

    /**
     * RFC 6750 §3.1, invalid_request: "The request is missing a required parameter, includes an unsupported parameter
     * or parameter value, repeats the same parameter, uses more than one method for including an access token, or is
     * otherwise malformed. The resource server SHOULD respond with the HTTP 400 (Bad Request) status code."
     */
    @Test
    @Requirement("RFC6750 §3.1")
    void anAmbiguousOrMalformedRequestIsA400() throws Exception {
        DelegatedTokenValidator both = this.f.builder(new InMemoryReplayStore()).mtls(true).build();
        this.run(this.filter(both), this.request(List.of("Bearer abc", "DPoP abc"), List.of(), null));
        assertEquals(400, this.status[0]);
        List<String> challenges = this.sent.get("WWW-Authenticate");
        assertEquals(2, challenges.size());
        assertTrue(challenges.get(0).startsWith("DPoP algs=") && challenges.get(0).contains("error=\"invalid_request\""));
        assertTrue(challenges.get(1).startsWith("Bearer realm=\"https://rs.example.com\", error=\"invalid_request\""));

        this.run(this.filter(this.validator), this.request(List.of("DPoP abc"), List.of(), "x=1&access_token=abc"));
        assertEquals(400, this.status[0]);
        this.run(this.filter(this.validator), this.request(List.of("DPoP a b"), List.of(), null));
        assertEquals(400, this.status[0]);
        this.run(this.filter(this.validator), this.request(List.of("DPoP"), List.of(), null));
        assertEquals(400, this.status[0]);
    }

    /**
     * RFC 9449 §7.2: "If the mechanism used to attempt authentication could be established unambiguously, then the
     * corresponding challenge SHOULD be used to deliver error information".
     */
    @Test
    @Requirement("RFC9449 §7.2")
    void withBothSchemesTheErrorGoesInTheChallengeOfTheSchemeUsed() throws Exception {
        DelegatedTokenValidator both = this.f.builder(new InMemoryReplayStore()).mtls(true).build();
        String token = this.f.token();
        this.run(this.filter(both), this.request(List.of("Bearer " + token), List.of(), null));
        List<String> bearerUsed = this.sent.get("WWW-Authenticate");
        assertEquals("DPoP algs=\"ES256 PS256 RS256\"", bearerUsed.get(0));
        assertTrue(bearerUsed.get(1).startsWith("Bearer realm=\"https://rs.example.com\", error=\"invalid_token\""));

        this.run(this.filter(both), this.request(List.of("DPoP " + token), List.of(), null));
        List<String> dpopUsed = this.sent.get("WWW-Authenticate");
        assertTrue(dpopUsed.get(0).contains("error=\"invalid_token\""));
        assertEquals("Bearer realm=\"https://rs.example.com\"", dpopUsed.get(1));

        this.run(this.filter(both), this.request(List.of(), List.of(), null));
        assertEquals(List.of("DPoP algs=\"ES256 PS256 RS256\"", "Bearer realm=\"https://rs.example.com\""),
                this.sent.get("WWW-Authenticate"));
    }

    /**
     * RFC 9449 §9: "Resource servers use an HTTP 401 (Unauthorized) error code with an accompanying WWW-Authenticate:
     * DPoP value and DPoP-Nonce value to accomplish this." §8.2: "Responses that include the DPoP-Nonce HTTP header
     * should be uncacheable".
     */
    @Test
    @Requirement({"RFC9449 §9", "RFC9449 §8.2"})
    void useDpopNonceSendsTheNonceAndAPassingRequestOnAnOldOneGetsTheNext() throws Exception {
        Instant start = Instant.parse("2026-09-28T00:00:05Z");
        DpopRefusalTest.MutableClock clock = new DpopRefusalTest.MutableClock(start);
        DelegatedTokenValidator v = this.f.builder(new InMemoryReplayStore())
                .nonces(new DpopNonces(new byte[32], Duration.ofMinutes(1), clock)).build();
        String token = this.f.token();
        this.run(this.filter(v), this.request(List.of("DPoP " + token), List.of(this.f.proof(token)), null));
        assertEquals(401, this.status[0]);
        assertTrue(this.sent.get("WWW-Authenticate").get(0).contains("error=\"use_dpop_nonce\""));
        String nonce = this.sent.get("DPoP-Nonce").get(0);
        assertEquals(List.of("no-store"), this.sent.get("Cache-Control"));

        clock.now = start.plusSeconds(60);
        String proof = this.f.proof(token, "GET", Fixture.URL, c -> c.setClaim("nonce", nonce));
        HttpServletRequest request = this.request(List.of("DPoP " + token), List.of(proof), null);
        this.run(this.filter(v), request);
        verify(this.chain).doFilter(eq(request), any());
        assertEquals(List.of(v.currentNonce().orElseThrow()), this.sent.get("DPoP-Nonce"));
        assertEquals(List.of("no-store"), this.sent.get("Cache-Control"));
    }

    /** An mTLS-bound token under Bearer: the certificate comes from the container's attribute. */
    @Test
    void aCertificateBoundBearerTokenUsesTheConnectionsCertificate() throws Exception {
        byte[] der = {7, 7, 7};
        X509Certificate cert = mock(X509Certificate.class);
        when(cert.getEncoded()).thenReturn(der);
        var claims = this.f.claims();
        claims.setClaim("cnf", Map.of("x5t#S256", java.util.Base64.getUrlEncoder().withoutPadding()
                .encodeToString(java.security.MessageDigest.getInstance("SHA-256").digest(der))));
        String token = this.f.token(claims);
        DelegatedTokenValidator mtls = this.f.builder(new InMemoryReplayStore()).mtls(true).dpop(false).build();

        HttpServletRequest request = this.request(List.of("Bearer " + token), List.of(), null);
        when(request.getAttribute(ResourceServerFilter.CERTIFICATE_ATTRIBUTE)).thenReturn(new X509Certificate[] {cert});
        this.run(this.filter(mtls), request);
        verify(this.chain).doFilter(eq(request), any());

        HttpServletRequest without = this.request(List.of("Bearer " + token), List.of(), null);
        when(without.getAttribute(ResourceServerFilter.CERTIFICATE_ATTRIBUTE)).thenReturn(new X509Certificate[0]);
        this.run(this.filter(mtls), without);
        assertEquals(List.of("Bearer realm=\"https://rs.example.com\", error=\"invalid_token\", error_description="
                + "\"the access token is certificate-bound and the connection presented no client certificate\""),
                this.sent.get("WWW-Authenticate"));
    }

    @Test
    void anUnavailableStoreIsA503WithoutAChallenge() throws Exception {
        DelegatedTokenValidator v = this.f.builder((k, w) -> {
            throw new java.io.IOException("down");
        }).build();
        String token = this.f.token();
        this.run(this.filter(v), this.request(List.of("DPoP " + token), List.of(this.f.proof(token)), null));
        assertEquals(503, this.status[0]);
        assertTrue(!this.sent.containsKey("WWW-Authenticate"));
    }

    /**
     * RFC 6750 §3: "Values for the "error" and "error_description" attributes ... MUST NOT include characters outside
     * the set %x20-21 / %x23-5B / %x5D-7E."
     */
    @Test
    @Requirement("RFC6750 §3")
    void anErrorDescriptionCarriesOnlyTheCharactersRfc6750Allows() {
        assertEquals("kid ?x?y??z", ResourceServerFilter.description("kid \"x\\y\néz"));
        assertEquals(200, ResourceServerFilter.description("a".repeat(500)).length());
        assertEquals("", ResourceServerFilter.description(null));
    }

    @Test
    void theSchemeNameIsCaseInsensitive() {
        assertSame(DelegatedTokenValidator.Scheme.DPOP, ResourceServerFilter.scheme("dPoP"));
        assertSame(DelegatedTokenValidator.Scheme.BEARER, ResourceServerFilter.scheme("BEARER"));
        assertEquals(null, ResourceServerFilter.scheme("Basic"));
    }

    @Test
    void theBaseUrlIsAnOriginOnly() {
        for (String bad : new String[] {"rs.example.com", "ftp://rs.example.com", "https://rs.example.com/api",
                "https://rs.example.com?x", "https://rs.example.com#f", "https://u@rs.example.com", "https:///x", "http://[bad", "https:opaque"}) {
            assertThrows(IllegalArgumentException.class, () -> ResourceServerFilter.checkedBaseUrl(bad), bad);
        }
        assertEquals("http://localhost:8080", ResourceServerFilter.checkedBaseUrl("http://localhost:8080"));
    }

    @Test
    void aRequestThatIsNotHttpIsRefused() {
        ResourceServerFilter filter = this.filter(this.validator);
        assertThrows(ServletException.class,
                () -> filter.doFilter(mock(ServletRequest.class), mock(ServletResponse.class), this.chain));
        assertThrows(ServletException.class,
                () -> filter.doFilter(mock(HttpServletRequest.class), mock(ServletResponse.class), this.chain));
    }
}
