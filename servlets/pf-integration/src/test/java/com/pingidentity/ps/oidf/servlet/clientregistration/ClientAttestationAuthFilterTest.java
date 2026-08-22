package com.pingidentity.ps.oidf.servlet.clientregistration;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.pingidentity.ps.oidf.jose.JwsSigner;
import com.pingidentity.ps.oidf.pf.BridgeSigners;
import com.pingidentity.ps.oidf.pf.FederationRuntimeConfig;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.jose4j.jwk.EcJwkGenerator;
import org.jose4j.jwk.EllipticCurveJsonWebKey;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.NumericDate;
import org.jose4j.keys.EllipticCurves;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.ArgumentCaptor;

/**
 * The token-endpoint filter that turns a verified Client Attestation into the credential PF understands.
 *
 * <p>Signing keys are PER CLIENT. What {@code init} checks is whether bridge signing is configured at
 * all: a deployment that registers clients for attestation authentication with none configured is one
 * where this filter passes everything through and those clients are authenticated by nothing. That is
 * the load-bearing case, and it must refuse to start rather than degrade quietly.
 *
 * <p>A single client missing a key is a different thing — a 401 for that client, not a boot failure for
 * everyone — and is asserted separately.
 */
class ClientAttestationAuthFilterTest {

    private static final String BACKING_PROP = "oidf.bridge.signer.backing";
    private static final String KEYS_PROP = "oidf.bridge.signing.keys";
    private static final String LEGACY_KEY_PROP = "oidf.bridge.private.jwk";
    private static final String LEGACY_PREV_KEY_PROP = "oidf.bridge.previous.public.jwk";
    private static final String REQUIRE_PROP = "oidf.attestation.require.bridge.key";

    @AfterEach
    void clearProps() throws Exception {
        System.clearProperty(BACKING_PROP);
        System.clearProperty(KEYS_PROP);
        System.clearProperty(LEGACY_KEY_PROP);
        System.clearProperty(LEGACY_PREV_KEY_PROP);
        System.clearProperty(REQUIRE_PROP);
        resetSingletons();
    }

    /** Both holders memoise; a test that changes the environment has to clear them. */
    private static void resetSingletons() throws Exception {
        java.lang.reflect.Field instance = FederationRuntimeConfig.class.getDeclaredField("instance");
        instance.setAccessible(true);
        instance.set(null, null);
        java.lang.reflect.Method reset = BridgeSigners.class.getDeclaredMethod("resetForTest");
        reset.setAccessible(true);
        reset.invoke(null);
    }

    private static String privateJwkJson(String kid) throws Exception {
        EllipticCurveJsonWebKey key = EcJwkGenerator.generateJwk(EllipticCurves.P256);
        key.setKeyId(kid);
        return key.toJson(JsonWebKey.OutputControlLevel.INCLUDE_PRIVATE);
    }

    /** A config-backed key map naming exactly the clients given. */
    private static void configureKeysFor(Path dir, String... clientIds) throws Exception {
        StringBuilder json = new StringBuilder("{");
        for (int i = 0; i < clientIds.length; i++) {
            json.append(i > 0 ? "," : "")
                .append('"').append(clientIds[i]).append("\":{\"jwk\":")
                .append(privateJwkJson("k" + i)).append('}');
        }
        json.append('}');
        Path file = dir.resolve("bridge-keys.json");
        Files.writeString(file, json.toString());
        System.setProperty(BACKING_PROP, "config");
        System.setProperty(KEYS_PROP, file.toString());
        resetSingletons();
    }

    private static HttpServletRequest requestWithoutAttestation() {
        HttpServletRequest req = mock(HttpServletRequest.class);
        when(req.getHeader(any())).thenReturn(null);
        return req;
    }

    // ---- init: is bridge signing configured at all? ------------------------------------------------

    @Test
    void refusesToStartWhenNoBridgeSigningIsConfiguredAndItIsRequired() throws Exception {
        resetSingletons();

        ServletException e = assertThrows(ServletException.class,
                () -> new ClientAttestationAuthFilter().init(null));

        assertTrue(e.getMessage().contains(BridgeSigners.BACKING_ENV), e.getMessage());
        assertTrue(e.getMessage().contains(FederationRuntimeConfig.REQUIRE_BRIDGE_KEY_ENV),
                "the failure must name the opt-out, or an operator cannot act on it: " + e.getMessage());
    }

    @Test
    void startsWithoutBridgeSigningOnlyWhenExplicitlyOptedOut() throws Exception {
        System.setProperty(REQUIRE_PROP, "false");
        resetSingletons();

        assertDoesNotThrow(() -> new ClientAttestationAuthFilter().init(null));
    }

    @Test
    void startsWhenBridgeSigningIsConfigured(@TempDir Path dir) throws Exception {
        configureKeysFor(dir, "https://rp.example.com/agent-1");

        assertDoesNotThrow(() -> new ClientAttestationAuthFilter().init(null));
    }

    /**
     * The superseded single-key variable must not be silently ignored. A security setting that looks
     * configured and does nothing is worse than one that is absent.
     */
    @Test
    void refusesToStartWhenTheSupersededSingleKeyVariableIsStillSet(@TempDir Path dir) throws Exception {
        configureKeysFor(dir, "https://rp.example.com/agent-1");
        System.setProperty(LEGACY_KEY_PROP, privateJwkJson("old-deployment-key"));
        resetSingletons();

        ServletException e = assertThrows(ServletException.class,
                () -> new ClientAttestationAuthFilter().init(null));

        assertTrue(e.getMessage().contains(FederationRuntimeConfig.BRIDGE_KEY_ENV),
                "must name the variable that is now inert: " + e.getMessage());
        assertTrue(e.getMessage().contains(BridgeSigners.KEYS_ENV),
                "must say where the key should move to: " + e.getMessage());
    }

    /**
     * The rotation-overlap variable is superseded too, and was easier to miss than its sibling: it kept
     * a SUPERSEDED deployment-wide public key in every client's JWKS while clients picked up the new
     * one. There is no deployment-wide key any more, and {@code withBridgeKeys} - the only thing that
     * ever read it - is deleted. An operator part-way through a rotation would otherwise set it and
     * believe an overlap was in place while nothing read it at all.
     */
    @Test
    void refusesToStartWhenTheSupersededRotationOverlapKeyIsStillSet(@TempDir Path dir) throws Exception {
        configureKeysFor(dir, "https://rp.example.com/agent-1");
        System.setProperty(LEGACY_PREV_KEY_PROP, privateJwkJson("outgoing-deployment-key"));
        resetSingletons();

        ServletException e = assertThrows(ServletException.class,
                () -> new ClientAttestationAuthFilter().init(null));

        assertTrue(e.getMessage().contains(FederationRuntimeConfig.BRIDGE_PREVIOUS_PUBLIC_KEY_ENV),
                "must name the variable that is now inert: " + e.getMessage());
        assertTrue(e.getMessage().contains(KEYS_PROP.replace("oidf.bridge.signing.keys", BridgeSigners.KEYS_ENV))
                        || e.getMessage().contains(BridgeSigners.KEYS_ENV),
                "must say what rotating a client looks like now: " + e.getMessage());
    }

    // ---- per-client resolution ---------------------------------------------------------------------

    @Test
    void eachClientGetsItsOwnSigner(@TempDir Path dir) throws Exception {
        configureKeysFor(dir, "https://rp.example.com/agent-1", "https://rp.example.com/agent-2");

        JwsSigner one = BridgeSigners.forClient("https://rp.example.com/agent-1").orElseThrow();
        JwsSigner two = BridgeSigners.forClient("https://rp.example.com/agent-2").orElseThrow();

        assertTrue(!one.keyId().equals(two.keyId()),
                "distinct clients must not share a signing key - that was the whole defect");
    }

    @Test
    void aClientWithNoKeyResolvesToNothingRatherThanBorrowingAnothers(@TempDir Path dir) throws Exception {
        configureKeysFor(dir, "https://rp.example.com/agent-1");

        assertTrue(BridgeSigners.forClient("https://rp.example.com/agent-unknown").isEmpty());
    }

    /** The backing is an assertion about the deployment, enforced so a demo key cannot ride into prod. */
    @Test
    void aVaultDeploymentRefusesAnInlineKey(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("keys.json");
        Files.writeString(file, "{\"https://rp.example.com/a\":{\"jwk\":" + privateJwkJson("inline") + "}}");
        System.setProperty(BACKING_PROP, "vault");
        System.setProperty(KEYS_PROP, file.toString());
        resetSingletons();

        IllegalStateException e = assertThrows(IllegalStateException.class,
                () -> BridgeSigners.forClient("https://rp.example.com/a"));
        assertTrue(e.getMessage().contains("vault"), e.getMessage());
    }

    @Test
    void aKeyWithBothFormsIsRefused(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("keys.json");
        Files.writeString(file, "{\"https://rp.example.com/a\":{\"key_ref\":\"k\",\"jwk\":"
                + privateJwkJson("inline") + "}}");
        System.setProperty(BACKING_PROP, "config");
        System.setProperty(KEYS_PROP, file.toString());
        resetSingletons();

        IllegalStateException e = assertThrows(IllegalStateException.class,
                () -> BridgeSigners.forClient("https://rp.example.com/a"));
        assertTrue(e.getMessage().contains("exactly one"), e.getMessage());
    }

    @Test
    void anUnreadableKeyMapIsADeploymentErrorNotAnEmptyResult() throws Exception {
        System.setProperty(BACKING_PROP, "config");
        System.setProperty(KEYS_PROP, "/nonexistent/bridge-keys.json");
        resetSingletons();

        assertThrows(IllegalStateException.class,
                () -> BridgeSigners.forClient("https://rp.example.com/a"),
                "falling through to 'no key' would silently disable attestation auth");
    }

    // ---- pass-through -------------------------------------------------------------------------------

    @Test
    void aRequestWithNoAttestationHeaderIsForwardedUntouched(@TempDir Path dir) throws Exception {
        configureKeysFor(dir, "https://rp.example.com/agent-1");
        ClientAttestationAuthFilter filter = new ClientAttestationAuthFilter();
        filter.init(null);
        HttpServletRequest req = requestWithoutAttestation();
        javax.servlet.http.HttpServletResponse resp = mock(javax.servlet.http.HttpServletResponse.class);
        FilterChain chain = mock(FilterChain.class);

        filter.doFilter(req, resp, chain);

        // The ORIGINAL request, not a BridgeAuthRequest wrapper: with no attestation the filter must not
        // substitute a credential, or it would widen access rather than translate one.
        verify(chain).doFilter(req, resp);
    }

    // ---- doFilter: real attestation verification ----------------------------------------------------
    //
    // OAuthIssuerUtils.getInstance() - the PF SDK singleton the filter used to call directly for the
    // OP issuer - reaches into PF's HiveMind registry at class-init and cannot run outside a booted
    // server (confirmed: NoClassDefFoundError for org.apache.hivemind.impl.RegistryBuilder even on the
    // full test classpath). That made every doFilter() path past the "no attestation header" early
    // return untestable - the filter had no seam to avoid it. The package-private constructor added
    // alongside these tests injects the OP-issuer resolver (mirroring the same seam already on
    // TokenEndpointAutoRegistrationFilter) so the real verification path - the security-critical part
    // of this filter - can actually be exercised here.

    private static final String ATTESTER_ISSUER = "https://attester.example.com";
    private static final String DOFILTER_CLIENT_ID = "https://rp.example.com/agent-1";
    private static final String OP_ISSUER = "https://as.example.com";
    private static final String TOKEN_ENDPOINT = OP_ISSUER + "/as/token.oauth2";
    private static final java.util.function.Function<HttpServletRequest, String> FIXED_ISSUER = r -> OP_ISSUER;

    private static PublicJsonWebKey ecKey(String kid) throws Exception {
        EllipticCurveJsonWebKey key = EcJwkGenerator.generateJwk(EllipticCurves.P256);
        key.setKeyId(kid);
        return key;
    }

    private static String sign(PublicJsonWebKey key, String typ, JwtClaims claims) throws Exception {
        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(claims.toJson());
        jws.setKey(key.getPrivateKey());
        jws.setAlgorithmHeaderValue("ES256");
        jws.setHeader("typ", typ);
        return jws.getCompactSerialization();
    }

    private static String attestationJwt(PublicJsonWebKey attesterKey, PublicJsonWebKey instanceKey,
            String clientId) throws Exception {
        JwtClaims claims = new JwtClaims();
        claims.setIssuer(ATTESTER_ISSUER);
        claims.setSubject(clientId);
        claims.setIssuedAtToNow();
        claims.setExpirationTime(NumericDate.fromSeconds(NumericDate.now().getValue() + 600L));
        claims.setClaim("cnf", Map.of("jwk", instanceKey.toParams(JsonWebKey.OutputControlLevel.PUBLIC_ONLY)));
        return sign(attesterKey, "oauth-client-attestation+jwt", claims);
    }

    private static String popJwt(PublicJsonWebKey instanceKey, String clientId, String audience) throws Exception {
        JwtClaims claims = new JwtClaims();
        claims.setIssuer(clientId);
        claims.setAudience(audience);
        claims.setJwtId(UUID.randomUUID().toString());
        claims.setIssuedAtToNow();
        return sign(instanceKey, "oauth-client-attestation-pop+jwt", claims);
    }

    /**
     * Points {@code oidf.mock.attesters} at a fresh JWKS file trusting exactly {@code attesterKey}.
     *
     * <p>Also sets a (never actually reached) trust-controller host: {@code ClientAttestationUtils}
     * builds the federation-backed {@code TrustChainValidator} eagerly, before the static resolver gets
     * a chance to short-circuit for an attester it already knows - so its constructor's
     * "knownTrustAnchor required" check runs even in a test that only ever exercises the static path.
     */
    private static void trustAttester(Path dir, PublicJsonWebKey attesterKey) throws Exception {
        Path file = dir.resolve("mock-attesters.json");
        String jwk = attesterKey.toJson(JsonWebKey.OutputControlLevel.PUBLIC_ONLY);
        Files.writeString(file, "{\"" + ATTESTER_ISSUER + "\":{\"keys\":[" + jwk + "]}}");
        System.setProperty("oidf.mock.attesters", file.toString());
        System.setProperty("oidf.federation.trust.controller.host", "https://trust-controller.example.com");
        resetMockAttesterResolver();
        resetSingletons();
    }

    /**
     * Clears {@code ClientAttestationUtils}'s memoised mock-attester resolution so this test's trust
     * file is honoured regardless of what ran earlier in the same JVM (surefire reuses one fork for the
     * whole module) - the same concern {@link #resetSingletons} addresses for the bridge/runtime
     * statics. Reflection because the reset method is deliberately not part of any public surface.
     */
    private static void resetMockAttesterResolver() throws Exception {
        Class<?> utils = Class.forName(
                "com.pingidentity.ps.oidf.servlet.clientregistration.utils.ClientAttestationUtils");
        java.lang.reflect.Method reset = utils.getDeclaredMethod("resetMockAttesterResolverForTest");
        reset.setAccessible(true);
        reset.invoke(null);
    }

    @AfterEach
    void clearMockAttesterProperty() throws Exception {
        System.clearProperty("oidf.mock.attesters");
        System.clearProperty("oidf.federation.trust.controller.host");
        resetMockAttesterResolver();
    }

    /** A servlet request carrying the given attestation headers, backed by a real parameter map. */
    private static HttpServletRequest attestedRequest(String attestation, String pop, Map<String, String[]> params) {
        HttpServletRequest req = mock(HttpServletRequest.class);
        when(req.getHeaders(ATTESTATION_HEADER_NAME)).thenReturn(
                java.util.Collections.enumeration(attestation == null ? java.util.List.of() : java.util.List.of(attestation)));
        when(req.getHeaders(POP_HEADER_NAME)).thenReturn(
                java.util.Collections.enumeration(pop == null ? java.util.List.of() : java.util.List.of(pop)));
        when(req.getHeaders("DPoP")).thenReturn(java.util.Collections.enumeration(java.util.List.of()));
        when(req.getHeader("Authorization")).thenReturn("Basic c29tZS1zdGFsZS1zZWNyZXQ=");
        when(req.getRequestURL()).thenReturn(new StringBuffer(TOKEN_ENDPOINT));
        when(req.getMethod()).thenReturn("POST");
        Map<String, String[]> effectiveParams = params == null ? new HashMap<>() : new HashMap<>(params);
        when(req.getParameterMap()).thenReturn(effectiveParams);
        when(req.getParameter(org.mockito.ArgumentMatchers.anyString())).thenAnswer(inv -> {
            String[] v = effectiveParams.get((String) inv.getArgument(0));
            return v == null || v.length == 0 ? null : v[0];
        });
        return req;
    }

    private static final String ATTESTATION_HEADER_NAME = "OAuth-Client-Attestation";
    private static final String POP_HEADER_NAME = "OAuth-Client-Attestation-PoP";

    private static HttpServletResponse responseCapturingBody(java.io.StringWriter body) throws Exception {
        HttpServletResponse resp = mock(HttpServletResponse.class);
        when(resp.getWriter()).thenReturn(new java.io.PrintWriter(body));
        return resp;
    }

    @Test
    void aValidAttestationIsVerifiedAndForwardedAsPrivateKeyJwt(@TempDir Path dir) throws Exception {
        configureKeysFor(dir, DOFILTER_CLIENT_ID);
        PublicJsonWebKey attesterKey = ecKey("attester-1");
        PublicJsonWebKey instanceKey = ecKey("instance-1");
        trustAttester(dir, attesterKey);
        ClientAttestationAuthFilter filter = new ClientAttestationAuthFilter(FIXED_ISSUER);
        filter.init(null);
        String attestation = attestationJwt(attesterKey, instanceKey, DOFILTER_CLIENT_ID);
        String pop = popJwt(instanceKey, DOFILTER_CLIENT_ID, OP_ISSUER);
        Map<String, String[]> params = new HashMap<>();
        params.put("client_secret", new String[]{"a-stale-secret"});
        params.put("grant_type", new String[]{"client_credentials"});
        HttpServletRequest req = attestedRequest(attestation, pop, params);
        java.io.StringWriter body = new java.io.StringWriter();
        HttpServletResponse resp = responseCapturingBody(body);
        FilterChain chain = mock(FilterChain.class);

        filter.doFilter(req, resp, chain);
        assertTrue(body.toString().isEmpty(), "a successful verification must not write an error body: " + body);

        ArgumentCaptor<ServletRequest> forwarded = ArgumentCaptor.forClass(ServletRequest.class);
        verify(chain).doFilter(forwarded.capture(), org.mockito.ArgumentMatchers.any());
        HttpServletRequest wrapped = (HttpServletRequest) forwarded.getValue();
        assertTrue(wrapped != req, "must forward a wrapper carrying the bridge credential, not the raw request");
        assertEquals(DOFILTER_CLIENT_ID, wrapped.getParameter("client_id"));
        assertEquals("urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                wrapped.getParameter("client_assertion_type"));
        assertTrue(wrapped.getParameter("client_secret") == null,
                "a stale client_secret must not ride into PF's own authentication");
        assertEquals("client_credentials", wrapped.getParameter("grant_type"),
                "unrelated parameters must pass through unchanged");
        assertTrue(wrapped.getHeader("Authorization") == null,
                "Basic credentials that no longer match the injected parameters must not reach PF");
        String assertion = wrapped.getParameter("client_assertion");
        Map<String, Object> assertionClaims = org.jose4j.json.JsonUtil.parseJson(
                new String(java.util.Base64.getUrlDecoder().decode(assertion.split("\\.")[1]),
                        java.nio.charset.StandardCharsets.UTF_8));
        assertEquals(DOFILTER_CLIENT_ID, assertionClaims.get("iss"));
        assertEquals(DOFILTER_CLIENT_ID, assertionClaims.get("sub"));
    }

    @Test
    void anAttestationSignedByAnUntrustedKeyIsRejectedWith401(@TempDir Path dir) throws Exception {
        configureKeysFor(dir, DOFILTER_CLIENT_ID);
        PublicJsonWebKey attesterKey = ecKey("attester-1");
        PublicJsonWebKey imposterKey = ecKey("imposter-1"); // not registered in the trust file
        PublicJsonWebKey instanceKey = ecKey("instance-1");
        trustAttester(dir, attesterKey);
        ClientAttestationAuthFilter filter = new ClientAttestationAuthFilter(FIXED_ISSUER);
        filter.init(null);
        // Signed by a key the attester trust file does NOT contain - a forged attestation.
        String forgedAttestation = attestationJwt(imposterKey, instanceKey, DOFILTER_CLIENT_ID);
        String pop = popJwt(instanceKey, DOFILTER_CLIENT_ID, OP_ISSUER);
        HttpServletRequest req = attestedRequest(forgedAttestation, pop, null);
        java.io.StringWriter body = new java.io.StringWriter();
        HttpServletResponse resp = responseCapturingBody(body);
        FilterChain chain = mock(FilterChain.class);

        filter.doFilter(req, resp, chain);

        verify(resp).setStatus(401);
        org.mockito.Mockito.verifyNoInteractions(chain);
        assertTrue(body.toString().contains("invalid_client"), body.toString());
    }

    @Test
    void multipleAttestationHeadersAreRejectedWith400(@TempDir Path dir) throws Exception {
        configureKeysFor(dir, DOFILTER_CLIENT_ID);
        ClientAttestationAuthFilter filter = new ClientAttestationAuthFilter(FIXED_ISSUER);
        filter.init(null);
        HttpServletRequest req = mock(HttpServletRequest.class);
        when(req.getHeaders(ATTESTATION_HEADER_NAME)).thenReturn(
                java.util.Collections.enumeration(java.util.List.of("one", "two")));
        java.io.StringWriter body = new java.io.StringWriter();
        HttpServletResponse resp = responseCapturingBody(body);
        FilterChain chain = mock(FilterChain.class);

        filter.doFilter(req, resp, chain);

        verify(resp).setStatus(400);
        org.mockito.Mockito.verifyNoInteractions(chain);
        assertTrue(body.toString().contains("invalid_request"), body.toString());
    }

    @Test
    void aValidAttestationForAClientWithNoBridgeKeyIsRejectedWith401RatherThanPassingThrough(
            @TempDir Path dir) throws Exception {
        // Bridge signing is configured for a DIFFERENT client only - this client authenticates
        // perfectly well but has no bridge key, so the filter must refuse it rather than let an
        // unauthenticated request through.
        configureKeysFor(dir, "https://rp.example.com/some-other-agent");
        PublicJsonWebKey attesterKey = ecKey("attester-1");
        PublicJsonWebKey instanceKey = ecKey("instance-1");
        trustAttester(dir, attesterKey);
        ClientAttestationAuthFilter filter = new ClientAttestationAuthFilter(FIXED_ISSUER);
        filter.init(null);
        String attestation = attestationJwt(attesterKey, instanceKey, DOFILTER_CLIENT_ID);
        String pop = popJwt(instanceKey, DOFILTER_CLIENT_ID, OP_ISSUER);
        HttpServletRequest req = attestedRequest(attestation, pop, null);
        java.io.StringWriter body = new java.io.StringWriter();
        HttpServletResponse resp = responseCapturingBody(body);
        FilterChain chain = mock(FilterChain.class);

        filter.doFilter(req, resp, chain);

        verify(resp).setStatus(401);
        org.mockito.Mockito.verifyNoInteractions(chain);
        assertTrue(body.toString().contains("invalid_client"), body.toString());
    }
}
