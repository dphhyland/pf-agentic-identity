package com.pingidentity.ps.oidf.servlet.clientregistration;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.pingidentity.ps.oidf.conformance.Requirement;
import com.pingidentity.ps.oidf.pf.BridgeSigners;
import com.pingidentity.ps.oidf.pf.FederationRuntimeConfig;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.function.Function;
import org.jose4j.jwk.EcJwkGenerator;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.NumericDate;
import org.jose4j.keys.EllipticCurves;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * The filter binds a presentation to this server from its configuration, not from what the request says about
 * itself.
 *
 * <p>The PoP's {@code aud} must be the issuer alone (ABCA-10 §5.1: "When the JWT is presented to an Authorization
 * Server, the [RFC8414] issuer identifier URL of the Authorization Server MUST be used"). A combined-mode DPoP
 * proof's {@code htu} must be the URL PingFederate advertises for the endpoint: the issuer (or, at the token
 * endpoint, its token endpoint base URL) followed by the path (RFC 9449 §4.3, item 9). Until 0.4.0 both were
 * checked against {@code getRequestURL()}, which the container rebuilds from the {@code Host} header, so a
 * presentation minted for another server - every PingFederate's token endpoint has this path - passed with a
 * {@code Host} header naming that server. The requests below carry such a header, and the {@code X-Forwarded-*}
 * pair a proxy would add, and the issuer resolver is the configured one throughout.
 */
class ClientAttestationAuthFilterEndpointTest {
    private static final String ATTESTER = "https://attester.example.com";
    private static final String CLIENT = "https://rp.example.com/agent-1";
    private static final String ISSUER = "https://as.example.com";
    private static final String TOKEN_PATH = "/as/token.oauth2";
    private static final String PAR_PATH = "/as/par.oauth2";
    private static final String TOKEN_ENDPOINT = ISSUER + TOKEN_PATH;
    private static final String PAR_ENDPOINT = ISSUER + PAR_PATH;
    /** Another server the client presents to, and the Host header that names it. */
    private static final String OTHER_HOST = "other-bank.example";
    private static final String OTHER_ISSUER = "https://" + OTHER_HOST;
    private static final String OTHER_TOKEN_ENDPOINT = OTHER_ISSUER + TOKEN_PATH;
    private static final Function<HttpServletRequest, String> CONFIGURED_ISSUER = r -> ISSUER;

    private PublicJsonWebKey attesterKey;
    private PublicJsonWebKey instanceKey;

    @BeforeEach
    void configure(@TempDir Path dir) throws Exception {
        attesterKey = ecKey("attester-1");
        instanceKey = ecKey("instance-1");
        Path keys = dir.resolve("bridge-keys.json");
        Files.writeString(keys, "{\"" + CLIENT + "\":{\"jwk\":"
                + ecKey("bridge-1").toJson(JsonWebKey.OutputControlLevel.INCLUDE_PRIVATE)
                + ",\"attesters\":[\"" + ATTESTER + "\"]}}");
        System.setProperty("oidf.bridge.signer.backing", "config");
        System.setProperty("oidf.bridge.signing.keys", keys.toString());
        Path attesters = dir.resolve("mock-attesters.json");
        Files.writeString(attesters, "{\"" + ATTESTER + "\":{\"keys\":["
                + attesterKey.toJson(JsonWebKey.OutputControlLevel.PUBLIC_ONLY) + "]}}");
        System.setProperty("oidf.mock.attesters", attesters.toString());
        System.setProperty("oidf.federation.trust.controller.host", "https://trust-controller.example.com");
        resetSingletons();
    }

    @AfterEach
    void clear() throws Exception {
        System.clearProperty("oidf.bridge.signer.backing");
        System.clearProperty("oidf.bridge.signing.keys");
        System.clearProperty("oidf.mock.attesters");
        System.clearProperty("oidf.federation.trust.controller.host");
        resetSingletons();
    }

    /** The memoised configuration holders, as ClientAttestationAuthFilterTest resets them. */
    private static void resetSingletons() throws Exception {
        FederationRuntimeConfig.resetForTests();
        java.lang.reflect.Method bridge = BridgeSigners.class.getDeclaredMethod("resetForTest");
        bridge.setAccessible(true);
        bridge.invoke(null);
        java.lang.reflect.Method mock = Class.forName(
                "com.pingidentity.ps.oidf.servlet.clientregistration.utils.ClientAttestationUtils")
                .getDeclaredMethod("resetMockAttesterResolverForTest");
        mock.setAccessible(true);
        mock.invoke(null);
    }

    private static PublicJsonWebKey ecKey(String kid) throws Exception {
        PublicJsonWebKey key = EcJwkGenerator.generateJwk(EllipticCurves.P256);
        key.setKeyId(kid);
        return key;
    }

    private static String sign(PublicJsonWebKey key, String typ, JwtClaims claims, boolean jwkHeader) throws Exception {
        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(claims.toJson());
        jws.setKey(key.getPrivateKey());
        jws.setAlgorithmHeaderValue("ES256");
        jws.setHeader("typ", typ);
        if (jwkHeader) {
            jws.setJwkHeader((PublicJsonWebKey) JsonWebKey.Factory.newJwk(
                    key.toParams(JsonWebKey.OutputControlLevel.PUBLIC_ONLY)));
        }
        return jws.getCompactSerialization();
    }

    private String attestation() throws Exception {
        JwtClaims c = new JwtClaims();
        c.setIssuer(ATTESTER);
        c.setSubject(CLIENT);
        c.setIssuedAtToNow();
        c.setExpirationTime(NumericDate.fromSeconds(NumericDate.now().getValue() + 600L));
        c.setClaim("cnf", Map.of("jwk", instanceKey.toParams(JsonWebKey.OutputControlLevel.PUBLIC_ONLY)));
        return sign(attesterKey, "oauth-client-attestation+jwt", c, false);
    }

    private String pop(Object audience) throws Exception {
        JwtClaims c = new JwtClaims();
        c.setIssuer(CLIENT);
        c.setClaim("aud", audience);
        c.setJwtId(UUID.randomUUID().toString());
        c.setIssuedAtToNow();
        return sign(instanceKey, "oauth-client-attestation-pop+jwt", c, false);
    }

    private String dpop(String htu) throws Exception {
        JwtClaims c = new JwtClaims();
        c.setClaim("htm", "POST");
        c.setClaim("htu", htu);
        c.setJwtId(UUID.randomUUID().toString());
        c.setIssuedAtToNow();
        return sign(instanceKey, "dpop+jwt", c, true);
    }

    /**
     * A POST to {@code servletPath} whose {@code Host} (and the request URL the container rebuilds from it, and the
     * {@code X-Forwarded-*} a proxy would add) names {@code host}. {@code servletPath} is what PingFederate's
     * {@code *.oauth2} extension mapping makes it: the whole path.
     */
    private static HttpServletRequest request(String host, String servletPath, String attestation, String pop,
                                              String dpop) {
        HttpServletRequest req = mock(HttpServletRequest.class);
        when(req.getHeaders("OAuth-Client-Attestation")).thenReturn(Collections.enumeration(List.of(attestation)));
        when(req.getHeaders("OAuth-Client-Attestation-PoP"))
                .thenReturn(Collections.enumeration(pop == null ? List.of() : List.of(pop)));
        when(req.getHeaders("DPoP")).thenReturn(Collections.enumeration(dpop == null ? List.of() : List.of(dpop)));
        when(req.getHeader("Host")).thenReturn(host);
        when(req.getHeader("X-Forwarded-Host")).thenReturn(host);
        when(req.getHeader("X-Forwarded-Proto")).thenReturn("https");
        when(req.getServerName()).thenReturn(host);
        when(req.getScheme()).thenReturn("https");
        when(req.getServerPort()).thenReturn(443);
        when(req.getRequestURL()).thenReturn(servletPath == null ? null : new StringBuffer("https://" + host + servletPath));
        when(req.getRequestURI()).thenReturn(servletPath);
        when(req.getContextPath()).thenReturn("");
        when(req.getServletPath()).thenReturn(servletPath);
        when(req.getMethod()).thenReturn("POST");
        Map<String, String[]> params = new HashMap<>();
        params.put("grant_type", new String[]{"client_credentials"});
        when(req.getParameterMap()).thenReturn(params);
        when(req.getParameter(org.mockito.ArgumentMatchers.anyString())).thenAnswer(inv -> {
            String[] v = params.get((String) inv.getArgument(0));
            return v == null ? null : v[0];
        });
        return req;
    }

    /** Runs the filter; the body it wrote is empty when it forwarded the request. */
    private static String filter(ClientAttestationAuthFilter filter, HttpServletRequest req, FilterChain chain)
            throws Exception {
        StringWriter body = new StringWriter();
        HttpServletResponse resp = mock(HttpServletResponse.class);
        when(resp.getWriter()).thenReturn(new PrintWriter(body));
        filter.doFilter(req, resp, chain);
        return body.toString();
    }

    private ClientAttestationAuthFilter filter() throws Exception {
        ClientAttestationAuthFilter filter = new ClientAttestationAuthFilter(CONFIGURED_ISSUER);
        filter.init(null);
        return filter;
    }

    private void accepted(ClientAttestationAuthFilter filter, HttpServletRequest req) throws Exception {
        FilterChain chain = mock(FilterChain.class);
        String body = filter(filter, req, chain);
        assertTrue(body.isEmpty(), "expected the request to be forwarded, got " + body);
        verify(chain).doFilter(any(), any());
    }

    private void refused(ClientAttestationAuthFilter filter, HttpServletRequest req, String because) throws Exception {
        FilterChain chain = mock(FilterChain.class);
        String body = filter(filter, req, chain);
        assertTrue(body.contains("invalid_client") && body.contains(because), body);
        verify(chain, never()).doFilter(any(), any());
    }

    // ---- PoP mode: the audience -------------------------------------------------------------------------------

    @Test
    @Requirement({"ABCA-10 §5.1", "ABCA-10 §7.2(7)"})
    void aPopAddressedToTheIssuerAuthenticates() throws Exception {
        accepted(filter(), request("as.example.com", TOKEN_PATH, attestation(), pop(ISSUER), null));
    }

    /** What 0.3.0 accepted because the request URL was an accepted audience. */
    @Test
    @Requirement("ABCA-10 §7.2(7)")
    void aPopAddressedToTheTokenEndpointIsRefused() throws Exception {
        refused(filter(), request("as.example.com", TOKEN_PATH, attestation(), pop(TOKEN_ENDPOINT), null), "'aud'");
    }

    /**
     * A PoP another server received, replayed here with a {@code Host} header naming that server: the request URL
     * is then exactly the PoP's audience, which is what 0.3.0 compared it with.
     */
    @Test
    @Requirement("ABCA-10 §7.2(7)")
    void aPopForAnotherServerIsRefusedWhateverTheHostHeaderSays() throws Exception {
        ClientAttestationAuthFilter filter = filter();

        refused(filter, request(OTHER_HOST, TOKEN_PATH, attestation(), pop(OTHER_TOKEN_ENDPOINT), null), "'aud'");
        refused(filter, request(OTHER_HOST, TOKEN_PATH, attestation(), pop(OTHER_ISSUER), null), "'aud'");
        refused(filter, request(OTHER_HOST, TOKEN_PATH, attestation(), pop(List.of(ISSUER, OTHER_ISSUER)), null), "'aud'");
    }

    /** The other side of the same rule: a Host header this server does not use changes nothing for a right PoP. */
    @Test
    @Requirement({"ABCA-10 §5.1", "ABCA-10 §7.2(7)"})
    void aPopAddressedToTheIssuerAuthenticatesWhateverTheHostHeaderSays() throws Exception {
        accepted(filter(), request(OTHER_HOST, TOKEN_PATH, attestation(), pop(ISSUER), null));
    }

    // ---- DPoP combined mode: the htu --------------------------------------------------------------------------

    @Test
    @Requirement("RFC9449 §4.3(9)")
    void aProofForTheConfiguredTokenEndpointAuthenticates() throws Exception {
        accepted(filter(), request("as.example.com", TOKEN_PATH, attestation(), null, dpop(TOKEN_ENDPOINT)));
    }

    /**
     * The request URL rebuilt from this Host header is the proof's {@code htu} exactly, so 0.3.0 accepted it. It is
     * not a URL of this server.
     */
    @Test
    @Requirement("RFC9449 §4.3(9)")
    void aProofForAnotherServerIsRefusedWhenTheHostHeaderNamesThatServer() throws Exception {
        refused(filter(), request(OTHER_HOST, TOKEN_PATH, attestation(), null, dpop(OTHER_TOKEN_ENDPOINT)), "htu");
    }

    /**
     * A proxy that rewrote the {@code Host} header to an internal name (and says the public one in
     * {@code X-Forwarded-Host}, which is read nowhere) does not stop a proof for the configured URL.
     */
    @Test
    @Requirement("RFC9449 §4.3(9)")
    void aProofForTheConfiguredEndpointAuthenticatesWhateverTheHostHeaderSays() throws Exception {
        accepted(filter(), request("pingfederate.internal:9031", TOKEN_PATH, attestation(), null, dpop(TOKEN_ENDPOINT)));
    }

    /** Each endpoint is its own URL: PAR is the issuer followed by /as/par.oauth2. */
    @Test
    @Requirement("RFC9449 §4.3(9)")
    void atParTheProofMustNamePar() throws Exception {
        ClientAttestationAuthFilter filter = filter();

        accepted(filter, request("as.example.com", PAR_PATH, attestation(), null, dpop(PAR_ENDPOINT)));
        refused(filter, request("as.example.com", PAR_PATH, attestation(), null, dpop(TOKEN_ENDPOINT)), "htu");
    }

    /**
     * PingFederate advertises {@code token_endpoint} under its token endpoint base URL when one is set, and every
     * other endpoint under the issuer (ProviderConfigurationInfoHandler, 13.1.3).
     */
    @Test
    @Requirement("RFC9449 §4.3(9)")
    void theTokenEndpointBaseUrlMovesTheTokenEndpointAndNothingElse() throws Exception {
        String base = "https://mtls.as.example.com:8443";
        ClientAttestationAuthFilter filter = new ClientAttestationAuthFilter(CONFIGURED_ISSUER, () -> base);
        filter.init(null);

        accepted(filter, request("mtls.as.example.com:8443", TOKEN_PATH, attestation(), null, dpop(base + TOKEN_PATH)));
        refused(filter, request("as.example.com", TOKEN_PATH, attestation(), null, dpop(TOKEN_ENDPOINT)), "htu");
        accepted(filter, request("as.example.com", PAR_PATH, attestation(), null, dpop(PAR_ENDPOINT)));
    }

    /**
     * PingFederate under a runtime context path: {@code pf.runtime.context.path=/sso} and a base URL ending in
     * {@code /sso}, which 13.1.3's {@code run.properties} says the two must agree on. Discovery then advertises
     * {@code https://as.example.com/sso/as/token.oauth2}, and that is the {@code htu}, with the context path once.
     */
    @Test
    @Requirement("RFC9449 §4.3(9)")
    void underARuntimeContextPathTheProofNamesTheAdvertisedUrl() throws Exception {
        String issuer = ISSUER + "/sso";
        ClientAttestationAuthFilter filter = new ClientAttestationAuthFilter(r -> issuer);
        filter.init(null);

        accepted(filter, underSso(request("as.example.com", TOKEN_PATH, attestation(), null, dpop(issuer + TOKEN_PATH))));
        refused(filter, underSso(request("as.example.com", TOKEN_PATH, attestation(), null,
                dpop(issuer + "/sso" + TOKEN_PATH))), "htu");
        accepted(filter, underSso(request("as.example.com", PAR_PATH, attestation(), null, dpop(issuer + PAR_PATH))));
    }

    /** The same request routed to the runtime web application at context path {@code /sso}. */
    private static HttpServletRequest underSso(HttpServletRequest req) {
        String servletPath = req.getServletPath();
        when(req.getContextPath()).thenReturn("/sso");
        when(req.getRequestURI()).thenReturn("/sso" + servletPath);
        when(req.getRequestURL()).thenReturn(new StringBuffer("https://as.example.com/sso" + servletPath));
        return req;
    }

    /** No path, no endpoint URL: combined mode is refused rather than compared with nothing. */
    @Test
    void withNoEndpointPathCombinedModeIsRefused() throws Exception {
        refused(filter(), request("as.example.com", null, attestation(), null, dpop(TOKEN_ENDPOINT)), "no expected DPoP htu");
    }
}
