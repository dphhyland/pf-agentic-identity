package com.pingidentity.ps.oidf.servlet.clientregistration;

import com.pingidentity.ps.oidf.servlet.oauth.PublicErrorsAssert;
import com.pingidentity.ps.oidf.servlet.oauth.RefusalLog;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.pingidentity.ps.oidf.jose.JwsSigner;
import com.pingidentity.ps.oidf.pf.BridgeSigners;
import com.pingidentity.ps.oidf.conformance.Requirement;
import com.pingidentity.ps.oidf.pf.FederationRuntimeConfig;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import com.pingidentity.ps.oidf.servlet.clientregistration.utils.ClientAttestationUtils;
import java.util.Map;
import java.util.List;
import java.util.UUID;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.jose4j.jwk.EcJwkGenerator;
import org.jose4j.jwk.EllipticCurveJsonWebKey;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.NumericDate;
import org.jose4j.keys.EllipticCurves;
import com.pingidentity.ps.oidf.conformance.Requirement;
import org.junit.jupiter.api.AfterEach;
import com.pingidentity.ps.oidf.clientattestation.ClientAttestationException;
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
    private static final String HOST_PROP = "oidf.federation.trust.controller.host";
    private static final String ANCHOR_JWKS_PROP = "oidf.federation.trust.anchor.jwks";

    @AfterEach
    void clearProps() throws Exception {
        System.clearProperty(BACKING_PROP);
        System.clearProperty(KEYS_PROP);
        System.clearProperty(LEGACY_KEY_PROP);
        System.clearProperty(LEGACY_PREV_KEY_PROP);
        System.clearProperty(REQUIRE_PROP);
        System.clearProperty(HOST_PROP);
        System.clearProperty(ANCHOR_JWKS_PROP);
        resetSingletons();
    }

    /** Both holders memoise; a test that changes the environment has to clear them. */
    private static void resetSingletons() throws Exception {
        FederationRuntimeConfig.resetForTests();
        java.lang.reflect.Method reset = BridgeSigners.class.getDeclaredMethod("resetForTest");
        reset.setAccessible(true);
        reset.invoke(null);
    }

    private static String privateJwkJson(String kid) throws Exception {
        EllipticCurveJsonWebKey key = EcJwkGenerator.generateJwk(EllipticCurves.P256);
        key.setKeyId(kid);
        return key.toJson(JsonWebKey.OutputControlLevel.INCLUDE_PRIVATE);
    }

    /**
     * A config-backed key map naming exactly the clients given, each bound to the attester the doFilter
     * cases present ({@code ATTESTER_ISSUER}) - a properly configured deployment. The binding cases
     * below build their own maps.
     */
    private static void configureKeysFor(Path dir, String... clientIds) throws Exception {
        configureKeysBoundTo(dir, java.util.List.of("https://attester.example.com"), clientIds);
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

        assertDoesNotThrow(() -> new ClientAttestationAuthFilter().init(null));
        assertEquals(com.pingidentity.ps.oidf.platform.component.ComponentState.FAILED_CONFIG, com.pingidentity.ps.oidf.servlet.GateTesting.part("ClientAttestationAuthFilter").state());
        String eReason = com.pingidentity.ps.oidf.servlet.GateTesting.part("ClientAttestationAuthFilter").reason();

        assertTrue(eReason.contains(BridgeSigners.BACKING_ENV), eReason);
        assertTrue(eReason.contains(com.pingidentity.ps.oidf.platform.component.ComponentSwitches.ATTESTATION_AUTH),
                "the failure must name the opt-out, or an operator cannot act on it: " + eReason);
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

    // ---- init: is the trust anchor's key pinned? ----------------------------------------------------

    @Test
    void startsWhenATrustControllerIsNamedWithoutPinnedAnchorKeysSoTheWebAppCanServeItsOwnEntityConfiguration(@TempDir Path dir) throws Exception {
        System.setProperty(HOST_PROP, "https://anchor.example");
        configureKeysFor(dir, "https://rp.example.com/agent-1");

        assertDoesNotThrow(() -> new ClientAttestationAuthFilter().init(null));
    }

    @Test
    void refusesToStartWhenThePinnedAnchorKeysAreNotAUsableKeySet(@TempDir Path dir) throws Exception {
        System.setProperty(HOST_PROP, "https://anchor.example");
        System.setProperty(ANCHOR_JWKS_PROP, "{ not json");
        configureKeysFor(dir, "https://rp.example.com/agent-1");

        assertDoesNotThrow(() -> new ClientAttestationAuthFilter().init(null));
        assertEquals(com.pingidentity.ps.oidf.platform.component.ComponentState.FAILED_CONFIG, com.pingidentity.ps.oidf.servlet.GateTesting.part("ClientAttestationAuthFilter").state());
        String eReason = com.pingidentity.ps.oidf.servlet.GateTesting.part("ClientAttestationAuthFilter").reason();

        assertTrue(eReason.contains("not a JSON object"), eReason);

        // One JSON object that is not a usable key set: the setting parses, and the anchor built from it is refused.
        System.setProperty(ANCHOR_JWKS_PROP, "{\"keys\": [{\"kty\": \"oct\", \"kid\": \"s\", \"k\": \"c2VjcmV0\"}]}");
        resetSingletons();
        assertDoesNotThrow(() -> new ClientAttestationAuthFilter().init(null));
        assertEquals(com.pingidentity.ps.oidf.platform.component.ComponentState.FAILED_CONFIG, com.pingidentity.ps.oidf.servlet.GateTesting.part("ClientAttestationAuthFilter").state());
        assertTrue(com.pingidentity.ps.oidf.servlet.GateTesting.part("ClientAttestationAuthFilter").reason().startsWith("attest_jwt_client_auth: "),
                com.pingidentity.ps.oidf.servlet.GateTesting.part("ClientAttestationAuthFilter").reason());
    }

    @Test
    void startsWhenTheTrustControllersKeysArePinned(@TempDir Path dir) throws Exception {
        EllipticCurveJsonWebKey anchor = EcJwkGenerator.generateJwk(EllipticCurves.P256);
        anchor.setKeyId("anchor-1");
        System.setProperty(HOST_PROP, "https://anchor.example");
        System.setProperty(ANCHOR_JWKS_PROP, "{\"keys\":[" + anchor.toJson(JsonWebKey.OutputControlLevel.PUBLIC_ONLY) + "]}");
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

        assertDoesNotThrow(() -> new ClientAttestationAuthFilter().init(null));
        assertEquals(com.pingidentity.ps.oidf.platform.component.ComponentState.FAILED_CONFIG, com.pingidentity.ps.oidf.servlet.GateTesting.part("ClientAttestationAuthFilter").state());
        String eReason = com.pingidentity.ps.oidf.servlet.GateTesting.part("ClientAttestationAuthFilter").reason();

        // The catalogue refuses the removed name as it was set, here its system property (plan item ST-5).
        assertTrue(eReason.contains(LEGACY_KEY_PROP), "must name the variable that is now inert: " + eReason);
        assertTrue(eReason.contains(BridgeSigners.KEYS_ENV),
                "must say where the key should move to: " + eReason);
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

        assertDoesNotThrow(() -> new ClientAttestationAuthFilter().init(null));
        assertEquals(com.pingidentity.ps.oidf.platform.component.ComponentState.FAILED_CONFIG, com.pingidentity.ps.oidf.servlet.GateTesting.part("ClientAttestationAuthFilter").state());
        String eReason = com.pingidentity.ps.oidf.servlet.GateTesting.part("ClientAttestationAuthFilter").reason();

        assertTrue(eReason.contains(LEGACY_PREV_KEY_PROP), "must name the variable that is now inert: " + eReason);
        // The part's reason is cut at 256 characters; the whole message is in the log and here: nothing replaces it.
        String message = assertThrows(IllegalStateException.class, BridgeSigners::isConfigured).getMessage();
        assertTrue(message.contains("nothing replaces it; unset it"), "must say to unset it: " + message);
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
        jakarta.servlet.http.HttpServletResponse resp = mock(jakarta.servlet.http.HttpServletResponse.class);
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
     * <p>Also sets a (never actually reached) trust-controller host, and deliberately pins no anchor
     * keys: a statically trusted attester resolves without the federation validator ever being built,
     * which is what lets a mock-attester or self-anchored deployment work before its anchor is pinned.
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
    @Requirement("FAPI2-SP §5.3.3.1(2.5)")
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
        // One audience, the issuer PF resolves for the request, as a JSON string and not an array of one:
        // FAPI 2.0 §5.3.3.1, and what 13.1.3 with Rfc7523bisCompliantAudienceVerification on accepts. The
        // request URL is not in it, as it was when the bridge sent [issuer, request URL].
        assertInstanceOf(String.class, assertionClaims.get("aud"), "aud must be a JSON string, not an array");
        assertEquals(OP_ISSUER, assertionClaims.get("aud"), "aud must be the issuer as a single string");
        Map<String, Object> assertionHeader = org.jose4j.json.JsonUtil.parseJson(
                new String(java.util.Base64.getUrlDecoder().decode(assertion.split("\\.")[0]),
                        java.nio.charset.StandardCharsets.UTF_8));
        assertEquals("client-authentication+jwt", assertionHeader.get("typ"));
    }

    @Test
    @Requirement("OIDFED §4")
    void anAttesterOnlyTheFederationCouldVouchForIsRefusedWhileTheAnchorIsUnpinned(@TempDir Path dir) throws Exception {
        configureKeysFor(dir, DOFILTER_CLIENT_ID);
        PublicJsonWebKey registeredAttester = ecKey("attester-1");
        PublicJsonWebKey unknownAttester = ecKey("unknown-attester-1");
        PublicJsonWebKey instanceKey = ecKey("instance-1");
        trustAttester(dir, registeredAttester);
        ClientAttestationAuthFilter filter = new ClientAttestationAuthFilter(FIXED_ISSUER);
        filter.init(null);
        // Issued by an attester the static file does not list, so it falls through to the federation,
        // which cannot be built without the anchor's pinned keys.
        JwtClaims claims = new JwtClaims();
        claims.setIssuer("https://federated-attester.example.com");
        claims.setSubject(DOFILTER_CLIENT_ID);
        claims.setIssuedAtToNow();
        claims.setExpirationTime(NumericDate.fromSeconds(NumericDate.now().getValue() + 600L));
        claims.setClaim("cnf", Map.of("jwk", instanceKey.toParams(JsonWebKey.OutputControlLevel.PUBLIC_ONLY)));
        String attestation = sign(unknownAttester, "oauth-client-attestation+jwt", claims);
        HttpServletRequest req = attestedRequest(attestation, popJwt(instanceKey, DOFILTER_CLIENT_ID, OP_ISSUER), null);
        java.io.StringWriter body = new java.io.StringWriter();
        HttpServletResponse resp = responseCapturingBody(body);
        FilterChain chain = mock(FilterChain.class);

        filter.doFilter(req, resp, chain);

        org.mockito.Mockito.verifyNoInteractions(chain);
        assertTrue(!body.toString().isEmpty(), "refused with an error body, never passed through");
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

    /**
     * H-FED-4 (F-0046): what the request chose - the client an attestation names, the audience of its proof, a
     * header's value - never reaches the response of a caller that has not authenticated. Each refusal is the code's
     * fixed description and a reference; the detail is on the server's log line.
     */
    @Test
    void aHostileMarkerNeverReachesTheResponse(@TempDir Path dir) throws Exception {
        String marker = "hfede-marker-" + UUID.randomUUID();
        String markedClient = "https://rp.example/" + marker;
        configureKeysFor(dir, DOFILTER_CLIENT_ID);
        PublicJsonWebKey attesterKey = ecKey("attester-1");
        PublicJsonWebKey imposterKey = ecKey("imposter-1");
        PublicJsonWebKey instanceKey = ecKey("instance-1");
        trustAttester(dir, attesterKey);
        ClientAttestationAuthFilter filter = new ClientAttestationAuthFilter(FIXED_ISSUER);
        filter.init(null);
        List<HttpServletRequest> hostile = List.of(
                // a trusted attester vouching for a client with no bridge key, the client named by the marker
                attestedRequest(attestationJwt(attesterKey, instanceKey, markedClient), popJwt(instanceKey, markedClient, OP_ISSUER), null),
                // a forged attestation naming the marker
                attestedRequest(attestationJwt(imposterKey, instanceKey, markedClient), popJwt(instanceKey, markedClient, OP_ISSUER), null),
                // a proof addressed to the marker
                attestedRequest(attestationJwt(attesterKey, instanceKey, DOFILTER_CLIENT_ID),
                        popJwt(instanceKey, DOFILTER_CLIENT_ID, markedClient), null),
                // an attestation that is the marker
                attestedRequest(marker, marker, null),
                // a repeated details parameter carrying it
                attestedRequest(attestationJwt(attesterKey, instanceKey, DOFILTER_CLIENT_ID),
                        popJwt(instanceKey, DOFILTER_CLIENT_ID, OP_ISSUER),
                        Map.of("authorization_details", new String[] {marker, marker})));
        boolean logged = false;
        for (HttpServletRequest req : hostile) {
            try (com.pingidentity.ps.oidf.servlet.oauth.RefusalLog log = com.pingidentity.ps.oidf.servlet.oauth.RefusalLog.open()) {
                java.io.StringWriter body = new java.io.StringWriter();
                filter.doFilter(req, responseCapturingBody(body), mock(FilterChain.class));
                org.junit.jupiter.api.Assertions.assertFalse(body.toString().contains(marker), body.toString());
                Map<String, Object> json = org.jose4j.json.JsonUtil.parseJson(body.toString());
                com.pingidentity.ps.oidf.servlet.oauth.PublicErrorsAssert.assertGeneric((String) json.get("error"), body.toString());
                logged |= log.lines().stream().anyMatch(line -> line.contains(marker));
            }
        }
        assertTrue(logged, "the detail, marker and all, is the server log's");
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

    /**
     * The filter must publish the verified context under BOTH keys, because they are read by two
     * consumers with different deployment conditions.
     *
     * <p>{@code VERIFIED_ATTESTATION_ATTRIBUTE} is read by the OGNL issuance criterion, so that the same
     * request is not verified twice (verify() consumes the challenge and burns the PoP jti).
     * {@code RAR_ATTESTATION_CONTEXT_ATTRIBUTE} is read by the RAR → PingAuthorize processor, which turns
     * it into the ceiling policy evaluates against.
     *
     * <p>The filter previously published only the first. The criterion publishes both — so a deployment
     * that ran the filter and did NOT put the criterion on its access-token mapping (which
     * {@code OIDF_ATTESTATION_REQUIRE_BRIDGE_KEY=false} explicitly supports) authenticated the client
     * correctly and then lost the attested entitlement on the way to the PDP, which fell back to
     * treating the client as its own subject. Nothing failed; the ceiling simply was not there.
     */
    @Test
    void theVerifiedContextIsPublishedForBothTheCriterionAndTheRarProcessor(@TempDir Path dir)
            throws Exception {
        configureKeysFor(dir, DOFILTER_CLIENT_ID);
        PublicJsonWebKey attesterKey = ecKey("attester-1");
        PublicJsonWebKey instanceKey = ecKey("instance-1");
        trustAttester(dir, attesterKey);
        ClientAttestationAuthFilter filter = new ClientAttestationAuthFilter(FIXED_ISSUER);
        filter.init(null);
        HttpServletRequest req = attestedRequest(
                attestationJwt(attesterKey, instanceKey, DOFILTER_CLIENT_ID),
                popJwt(instanceKey, DOFILTER_CLIENT_ID, OP_ISSUER),
                new HashMap<>());
        java.io.StringWriter body = new java.io.StringWriter();

        filter.doFilter(req, responseCapturingBody(body), mock(FilterChain.class));
        assertTrue(body.toString().isEmpty(), "expected a clean verification, got: " + body);

        ArgumentCaptor<Object> verified = ArgumentCaptor.forClass(Object.class);
        verify(req).setAttribute(
                org.mockito.ArgumentMatchers.eq(ClientAttestationUtils.VERIFIED_ATTESTATION_ATTRIBUTE),
                verified.capture());
        ArgumentCaptor<Object> rar = ArgumentCaptor.forClass(Object.class);
        verify(req).setAttribute(
                org.mockito.ArgumentMatchers.eq(ClientAttestationUtils.RAR_ATTESTATION_CONTEXT_ATTRIBUTE),
                rar.capture());

        assertEquals(verified.getValue(), rar.getValue(),
                "both keys must carry the same already-verified context - the second is not a second "
                        + "verification, it is the same Map reachable by the other consumer");
        assertTrue(rar.getValue() instanceof Map,
                "a plain Map is the only thing that crosses the servlet/engine classloader split");
        assertEquals(DOFILTER_CLIENT_ID, ((Map<?, ?>) rar.getValue()).get("client_id"));
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

    // ---- attester-to-client binding ------------------------------------------------------------------
    //
    // Trust in an attester is federation-wide: any issuer whose chain reaches the anchor (or that the
    // mock file lists) resolves keys. Nothing about that says WHICH clients an attester may vouch for.
    // Without a binding, any trusted attester - any federation member that can get a leaf resolved -
    // mints an attestation with sub = some other client, and this filter bridges to PF as that client.
    // The binding lives beside the bridge key, in the same per-client entry of OIDF_BRIDGE_SIGNING_KEYS,
    // because that entry is already the deployment's statement of "this client authenticates by
    // attestation" - it is the natural place to say by whose.

    private static final String BINDING_PROP = "oidf.attestation.require.attester.binding";

    /** A config-backed key map naming exactly the clients given, each bound to the given attesters (null = no binding). */
    private static void configureKeysBoundTo(Path dir, java.util.List<String> attesters, String... clientIds) throws Exception {
        StringBuilder json = new StringBuilder("{");
        for (int i = 0; i < clientIds.length; i++) {
            json.append(i > 0 ? "," : "")
                .append('"').append(clientIds[i]).append("\":{\"jwk\":")
                .append(privateJwkJson("k" + i));
            if (attesters != null) {
                json.append(",\"attesters\":[");
                for (int a = 0; a < attesters.size(); a++) {
                    json.append(a > 0 ? "," : "").append('"').append(attesters.get(a)).append('"');
                }
                json.append(']');
            }
            json.append('}');
        }
        json.append('}');
        Path file = dir.resolve("bridge-keys.json");
        Files.writeString(file, json.toString());
        System.setProperty(BACKING_PROP, "config");
        System.setProperty(KEYS_PROP, file.toString());
        resetSingletons();
    }

    @AfterEach
    void clearBindingProperty() {
        System.clearProperty(BINDING_PROP);
    }

    private static String rejectedWith(HttpServletRequest req, ClientAttestationAuthFilter filter, FilterChain chain) throws Exception {
        java.io.StringWriter body = new java.io.StringWriter();
        HttpServletResponse resp = responseCapturingBody(body);
        filter.doFilter(req, resp, chain);
        return body.toString();
    }

    @Test
    @Requirement("CAS §6")
    void anAttestationFromAnAttesterNotBoundToTheClientIsRefused(@TempDir Path dir) throws Exception {
        configureKeysBoundTo(dir, java.util.List.of("https://the-clients-real-attester.example.com"), DOFILTER_CLIENT_ID);
        PublicJsonWebKey attesterKey = ecKey("attester-1");
        PublicJsonWebKey instanceKey = ecKey("instance-1");
        // ATTESTER_ISSUER is trusted by this AS - just not for this client.
        trustAttester(dir, attesterKey);
        ClientAttestationAuthFilter filter = new ClientAttestationAuthFilter(FIXED_ISSUER);
        filter.init(null);
        HttpServletRequest req = attestedRequest(
                attestationJwt(attesterKey, instanceKey, DOFILTER_CLIENT_ID),
                popJwt(instanceKey, DOFILTER_CLIENT_ID, OP_ISSUER), new HashMap<>());
        FilterChain chain = mock(FilterChain.class);

        String body = rejectedWith(req, filter, chain);

        assertTrue(body.contains("invalid_client"), "a trusted attester vouching for a client it is not bound to: " + body);
        verify(chain, org.mockito.Mockito.never()).doFilter(any(), any());
    }

    @Test
    @Requirement("CAS §6")
    void anAttestationFromABoundAttesterIsBridged(@TempDir Path dir) throws Exception {
        configureKeysBoundTo(dir, java.util.List.of("https://some-other-attester.example.com", ATTESTER_ISSUER), DOFILTER_CLIENT_ID);
        PublicJsonWebKey attesterKey = ecKey("attester-1");
        PublicJsonWebKey instanceKey = ecKey("instance-1");
        trustAttester(dir, attesterKey);
        ClientAttestationAuthFilter filter = new ClientAttestationAuthFilter(FIXED_ISSUER);
        filter.init(null);
        HttpServletRequest req = attestedRequest(
                attestationJwt(attesterKey, instanceKey, DOFILTER_CLIENT_ID),
                popJwt(instanceKey, DOFILTER_CLIENT_ID, OP_ISSUER), new HashMap<>());
        FilterChain chain = mock(FilterChain.class);

        String body = rejectedWith(req, filter, chain);

        assertTrue(body.isEmpty(), body);
        verify(chain).doFilter(any(), any());
    }

    /**
     * A client entry with a bridge key but no {@code attesters} is a client anyone trusted may vouch
     * for. That is the defect, so by default it is a refusal for that client - naming the setting - not
     * a silent acceptance. Per-client, like a missing key: a 401 for this client, not a boot failure.
     */
    @Test
    @Requirement("CAS §6")
    void aClientWithNoBoundAttestersIsRefusedByDefault(@TempDir Path dir) throws Exception {
        configureKeysBoundTo(dir, null, DOFILTER_CLIENT_ID);
        PublicJsonWebKey attesterKey = ecKey("attester-1");
        PublicJsonWebKey instanceKey = ecKey("instance-1");
        trustAttester(dir, attesterKey);
        ClientAttestationAuthFilter filter = new ClientAttestationAuthFilter(FIXED_ISSUER);
        filter.init(null);
        HttpServletRequest req = attestedRequest(
                attestationJwt(attesterKey, instanceKey, DOFILTER_CLIENT_ID),
                popJwt(instanceKey, DOFILTER_CLIENT_ID, OP_ISSUER), new HashMap<>());
        FilterChain chain = mock(FilterChain.class);

        try (RefusalLog log = RefusalLog.open()) {
            String body = rejectedWith(req, filter, chain);

            PublicErrorsAssert.assertGeneric("invalid_client", body);
            org.junit.jupiter.api.Assertions.assertFalse(body.contains("attesters"), "what to configure is the operator's, not the caller's: " + body);
            log.assertDetail("attesters");
        }
        verify(chain, org.mockito.Mockito.never()).doFilter(any(), any());
    }

    /** The explicit opt-out, for a deployment that has one attester and knows it. Unbound clients then accept any trusted attester. */
    @Test
    void anUnboundClientAcceptsAnyTrustedAttesterOnlyWhenBindingIsExplicitlyRelaxed(@TempDir Path dir) throws Exception {
        System.setProperty(BINDING_PROP, "false");
        configureKeysBoundTo(dir, null, DOFILTER_CLIENT_ID);
        PublicJsonWebKey attesterKey = ecKey("attester-1");
        PublicJsonWebKey instanceKey = ecKey("instance-1");
        trustAttester(dir, attesterKey);
        ClientAttestationAuthFilter filter = new ClientAttestationAuthFilter(FIXED_ISSUER);
        filter.init(null);
        HttpServletRequest req = attestedRequest(
                attestationJwt(attesterKey, instanceKey, DOFILTER_CLIENT_ID),
                popJwt(instanceKey, DOFILTER_CLIENT_ID, OP_ISSUER), new HashMap<>());
        FilterChain chain = mock(FilterChain.class);

        String body = rejectedWith(req, filter, chain);

        assertTrue(body.isEmpty(), body);
        verify(chain).doFilter(any(), any());
    }

    /** Relaxing the default relaxes only the UNBOUND case: an explicit binding is still enforced. */
    @Test
    @Requirement("CAS §6")
    void anExplicitBindingIsEnforcedEvenWhenTheDefaultIsRelaxed(@TempDir Path dir) throws Exception {
        System.setProperty(BINDING_PROP, "false");
        configureKeysBoundTo(dir, java.util.List.of("https://the-clients-real-attester.example.com"), DOFILTER_CLIENT_ID);
        PublicJsonWebKey attesterKey = ecKey("attester-1");
        PublicJsonWebKey instanceKey = ecKey("instance-1");
        trustAttester(dir, attesterKey);
        ClientAttestationAuthFilter filter = new ClientAttestationAuthFilter(FIXED_ISSUER);
        filter.init(null);
        HttpServletRequest req = attestedRequest(
                attestationJwt(attesterKey, instanceKey, DOFILTER_CLIENT_ID),
                popJwt(instanceKey, DOFILTER_CLIENT_ID, OP_ISSUER), new HashMap<>());
        FilterChain chain = mock(FilterChain.class);

        String body = rejectedWith(req, filter, chain);

        assertTrue(body.contains("invalid_client"), body);
        verify(chain, org.mockito.Mockito.never()).doFilter(any(), any());
    }

    // ---------------------------------------------------------------- the agent's standing at this authority

    private static final String AUTHORITY = "https://bank.example";

    private static com.pingidentity.ps.oidf.authority.InMemoryHostedEntityRegistry registryWith(String slug,
            com.pingidentity.ps.oidf.authority.EntityStatus status, java.time.Instant notAfter) throws Exception {
        var registry = new com.pingidentity.ps.oidf.authority.InMemoryHostedEntityRegistry();
        String entityId = AUTHORITY + ClientAttestationAuthFilter.AGENTS_PATH + slug;
        registry.register(new com.pingidentity.ps.oidf.authority.HostedEntity(entityId,
                com.pingidentity.ps.oidf.authority.HostingMode.AUTHORITY_SIGNED, "hosting-key", Map.of(), Map.of(),
                com.pingidentity.ps.oidf.authority.EntityStatus.ACTIVE, false, "owner", java.time.Instant.now(), notAfter));
        if (status != com.pingidentity.ps.oidf.authority.EntityStatus.ACTIVE) {
            registry.setStatus(entityId, status, "test");
        }
        return registry;
    }

    private static String standing(String agentId, com.pingidentity.ps.oidf.authority.HostedEntityRegistry registry,
            boolean requireHosted) throws Exception {
        return ClientAttestationAuthFilter.agentStandingProblem(agentId, java.util.Optional.of(AUTHORITY),
                java.util.Optional.ofNullable(registry), requireHosted, java.time.Instant.now());
    }

    @Test
    void anActiveHostedAgentAuthenticates() throws Exception {
        var registry = registryWith("a1", com.pingidentity.ps.oidf.authority.EntityStatus.ACTIVE, null);
        assertEquals(null, standing("a1", registry, true));
    }

    @Test
    void aRevokedOrSuspendedHostedAgentIsRefusedHereNotOnlyAtPartners() throws Exception {
        String revoked = standing("a1", registryWith("a1", com.pingidentity.ps.oidf.authority.EntityStatus.REVOKED, null), false);
        assertEquals("agent https://bank.example/federation/agents/a1 is revoked at this authority", revoked);
        String suspended = standing("a1", registryWith("a1", com.pingidentity.ps.oidf.authority.EntityStatus.SUSPENDED, null), false);
        assertTrue(suspended.endsWith("is suspended at this authority"), suspended);
    }

    @Test
    void anExpiredMembershipIsRefused() throws Exception {
        var registry = registryWith("a1", com.pingidentity.ps.oidf.authority.EntityStatus.ACTIVE, java.time.Instant.now().minusSeconds(5));
        assertTrue(standing("a1", registry, false).endsWith("federation membership has expired"));
    }

    @Test
    void anAgentThisAuthorityDoesNotHostPassesUnlessMembershipIsRequired() throws Exception {
        var registry = registryWith("a1", com.pingidentity.ps.oidf.authority.EntityStatus.ACTIVE, null);
        assertEquals(null, standing("someone-else", registry, false));
        assertEquals("agent https://bank.example/federation/agents/someone-else is not a member of this authority's federation",
                standing("someone-else", registry, true));
    }

    @Test
    void nothingIsJudgedWithoutAnAgentIdOrAConfiguredAuthority() throws Exception {
        var registry = registryWith("a1", com.pingidentity.ps.oidf.authority.EntityStatus.REVOKED, null);
        assertEquals(null, standing(null, registry, true)); // a workload or device attestation, not a hosted agent
        assertEquals(null, standing("a1", null, true)); // nobody has configured the registry yet
        assertEquals(null, ClientAttestationAuthFilter.agentStandingProblem("a1", java.util.Optional.empty(),
                java.util.Optional.of(registry), true, java.time.Instant.now()));
    }

    @Test
    void readingTheStandingNeverCreatesTheRegistry() {
        // registryIfConfigured() must not install the in-memory fallback that registry() would, or a JDBC
        // registry configured later by the authority servlet would be ignored.
        java.util.Optional<com.pingidentity.ps.oidf.authority.HostedEntityRegistry> before =
                com.pingidentity.ps.oidf.authority.AuthoritySupport.registryIfConfigured();
        if (before.isEmpty()) {
            com.pingidentity.ps.oidf.authority.AuthoritySupport.registryIfConfigured();
            assertTrue(com.pingidentity.ps.oidf.authority.AuthoritySupport.registryIfConfigured().isEmpty());
        }
    }

    private static final String REQUIRE_HOSTED_AGENT_PROP = "oidf.attestation.require_hosted_agent";

    /** The hosted-agent requirement with this system property and this environment variable, and nothing else. */
    private static boolean hostedAgent(String property, String environment) {
        java.util.Map<String, String> props = new java.util.HashMap<>();
        java.util.Map<String, String> env = new java.util.HashMap<>();
        if (property != null) {
            props.put(REQUIRE_HOSTED_AGENT_PROP, property);
        }
        if (environment != null) {
            env.put(ClientAttestationAuthFilter.REQUIRE_HOSTED_AGENT_ENV, environment);
        }
        return ClientAttestationAuthFilter.requireHostedAgentSetting(com.pingidentity.ps.oidf.platform.settings.Sources.of(env::get,
                props::get, null));
    }

    @Test
    void membershipRequirementIsReadFromThePropertyThenTheEnvironment(@TempDir Path dir) throws Exception {
        assertTrue(hostedAgent("true", null));
        assertTrue(hostedAgent(" ", "true")); // a blank property defers
        assertTrue(hostedAgent(null, "true"));
        assertEquals(false, hostedAgent("false", "true"));
        assertEquals(false, hostedAgent(null, null));
        // Strict from 0.6.0 (plan item ST-5): anything but true or false is refused, naming the setting, where the reader
        // before read it as false; under development a legacy spelling is read as that reader read it, with a warning.
        com.pingidentity.ps.oidf.platform.settings.SettingRefused refused = assertThrows(
                com.pingidentity.ps.oidf.platform.settings.SettingRefused.class, () -> hostedAgent(null, "yes"));
        assertEquals(ClientAttestationAuthFilter.REQUIRE_HOSTED_AGENT_ENV, refused.setting());
        assertEquals(false, ClientAttestationAuthFilter.requireHostedAgentSetting(com.pingidentity.ps.oidf.platform.settings.Sources.of(
                Map.of("OIDF_DEPLOYMENT_PROFILE", "development", ClientAttestationAuthFilter.REQUIRE_HOSTED_AGENT_ENV, "yes")::get,
                name -> null, null)));

        // Read by a filter that starts: a switched-off one (OIDF_ATTESTATION_AUTH_ENABLED=false) reads nothing.
        System.setProperty(REQUIRE_HOSTED_AGENT_PROP, "true");
        resetSingletons();
        configureKeysFor(dir, DOFILTER_CLIENT_ID);
        try {
            ClientAttestationAuthFilter filter = new ClientAttestationAuthFilter();
            filter.init(null);
            assertTrue(filter.requiresHostedAgent());
        } finally {
            System.clearProperty(REQUIRE_HOSTED_AGENT_PROP);
        }
    }

    @SuppressWarnings("unchecked")
    private static java.util.List<Map<String, Object>> entries(String json) throws Exception {
        return (java.util.List<Map<String, Object>>) org.jose4j.json.JsonUtil.parseJson("{\"v\":" + json + "}").get("v");
    }

    @Test
    void theVerifiedAgentRidesInEveryEntryAndAClientCannotPlantItsOwn() throws Exception {
        java.util.List<Map<String, Object>> granted = java.util.List.of(
                new java.util.LinkedHashMap<>(Map.of("type", "a", "_agent_id", "forged")),
                new java.util.LinkedHashMap<>(Map.of("type", "b", "purpose", "p")));
        String marked = GrantedDetails.forwarded(granted, java.util.List.of(), "agent-7");
        java.util.List<Map<String, Object>> parsed = entries(marked);
        assertEquals("agent-7", parsed.get(0).get(ClientAttestationAuthFilter.AGENT_MARKER));
        assertEquals("agent-7", parsed.get(1).get(ClientAttestationAuthFilter.AGENT_MARKER));
        assertEquals("p", parsed.get(1).get("purpose"));
    }

    @Test
    void anUnverifiedAgentCarriesNoMarkerAndNothingGrantedForwardsNothing() throws Exception {
        assertTrue(!entries(GrantedDetails.forwarded(java.util.List.of(new java.util.LinkedHashMap<>(Map.of("type", "a",
                "_agent_id", "forged"))), java.util.List.of(), null)).get(0).containsKey(ClientAttestationAuthFilter.AGENT_MARKER));
        assertEquals(null, GrantedDetails.forwarded(java.util.List.of(), java.util.List.of(), "agent-7"));
        assertEquals(null, GrantedDetails.forwarded(null, java.util.List.of(), "agent-7"));
    }

    // ---- S3a: the status a verification failure answers with -----------------------------------------

    /**
     * A store that cannot answer is the 503, and the only one; a challenge to fetch is 400 and everything the
     * client got wrong is 401.
     *
     * RFC 6749 defines the code in §4.1.2.1 for the authorization endpoint's redirect: "The authorization server
     * is currently unable to handle the request due to a temporary overloading or maintenance of the server. (This
     * error code is needed because a 503 Service Unavailable HTTP status code cannot be returned to the client via
     * an HTTP redirect.)" §5.2, the token endpoint's list, does not include it. Using it here, with the 503 as well,
     * is this project's decision (plan item S3a), not a requirement of either section, so the test carries no
     * {@code @Requirement}.
     */
    @Test
    void anUnavailableStoreIs503AChallengeToFetchIs400AndTheRestIs401() {
        assertEquals(503, ClientAttestationAuthFilter.statusFor(ClientAttestationException.temporarilyUnavailable("store down")));
        assertEquals(400, ClientAttestationAuthFilter.statusFor(ClientAttestationException.useChallenge("fetch one")));
        assertEquals(401, ClientAttestationAuthFilter.statusFor(ClientAttestationException.invalidClient("replay")));
        assertEquals(401, ClientAttestationAuthFilter.statusFor(ClientAttestationException.accessDenied("ceiling")));
    }

    // ---- S1b: the token gate - authorization_details against the attestation's --------------------------
    //
    // CAS §7.1: an authorization server "MUST, when authenticating a client via an attestation containing
    // authorization_details, ensure that any authority granted in issued tokens is a subset of the attestation's
    // authorization_details (same subset semantics as Section 7 rule 1), and MUST reject requests exceeding it with
    // invalid_authorization_details [RFC9396]." RFC 6749 §5.2 sets the status: "The authorization server responds
    // with an HTTP 400 (Bad Request) status code (unless specified otherwise)".

    /**
     * RFC 9396 §6 at the token endpoint: "Otherwise, the AS refuses the request with the error code
     * invalid_authorization_details (similar to invalid_scope)." - and invalid_scope is a 400 under RFC 6749 §5.2.
     */
    @Test
    @Requirement({"RFC9396 §6", "RFC6749 §5.2"})
    void anInvalidAuthorizationDetailsRefusalIs400() {
        assertEquals(400, ClientAttestationAuthFilter.statusFor(
                ClientAttestationException.invalidAuthorizationDetails("authorization_details is malformed")));
    }

    private static void rarModelsFrom(Map<String, String> env) throws Exception {
        java.lang.reflect.Method reset = com.pingidentity.ps.oidf.clientattestation.AttestationRarModels.class
                .getDeclaredMethod("resetForTest", Map.class);
        reset.setAccessible(true);
        reset.invoke(null, env);
    }

    @AfterEach
    void readTheModelsFromTheProcessEnvironmentAgain() throws Exception {
        rarModelsFrom(null);
    }

    /**
     * A models document the filter cannot read would leave the token gate enforcing something other than what the
     * deployment wrote, so the filter refuses to start - naming the setting - as it does for a broken bridge
     * configuration. Plan item S-9 (Phase 3) turns this into a filter that starts and refuses its own traffic.
     */
    @Test
    void refusesToStartWhenTheRarModelsDocumentCannotBeRead(@TempDir Path dir) throws Exception {
        configureKeysFor(dir, DOFILTER_CLIENT_ID);
        rarModelsFrom(Map.of(com.pingidentity.ps.oidf.rar.model.RarModels.ENV_MODELS, "{\"types\":"));

        assertDoesNotThrow(() -> new ClientAttestationAuthFilter(FIXED_ISSUER).init(null));
        assertEquals(com.pingidentity.ps.oidf.platform.component.ComponentState.FAILED_CONFIG, com.pingidentity.ps.oidf.servlet.GateTesting.part("ClientAttestationAuthFilter").state());
        String eReason = com.pingidentity.ps.oidf.servlet.GateTesting.part("ClientAttestationAuthFilter").reason();

        assertTrue(eReason.contains(com.pingidentity.ps.oidf.rar.model.RarModels.ENV_MODELS_FILE), eReason);
    }

    /** A filter that authenticates nothing enforces nothing, so it has no models to load. */
    @Test
    void aFilterThatAuthenticatesNothingDoesNotLoadTheModels() throws Exception {
        System.setProperty(REQUIRE_PROP, "false");
        resetSingletons();
        rarModelsFrom(Map.of(com.pingidentity.ps.oidf.rar.model.RarModels.ENV_MODELS, "{\"types\":"));

        assertDoesNotThrow(() -> new ClientAttestationAuthFilter().init(null));
    }

    private static final String SALES_EMEA = "[{\"type\":\"sales_agent\",\"sales_regions\":[\"EMEA\"]}]";

    /** An attestation carrying {@code claims} beside the usual ones. */
    private static String attestationWith(PublicJsonWebKey attesterKey, PublicJsonWebKey instanceKey,
            Map<String, Object> claims) throws Exception {
        JwtClaims c = new JwtClaims();
        c.setIssuer(ATTESTER_ISSUER);
        c.setSubject(DOFILTER_CLIENT_ID);
        c.setIssuedAtToNow();
        c.setExpirationTime(NumericDate.fromSeconds(NumericDate.now().getValue() + 600L));
        c.setClaim("cnf", Map.of("jwk", instanceKey.toParams(JsonWebKey.OutputControlLevel.PUBLIC_ONLY)));
        claims.forEach(c::setClaim);
        return sign(attesterKey, "oauth-client-attestation+jwt", c);
    }

    /** What doFilter did with one attested token request. */
    private record Filtered(HttpServletRequest request, HttpServletResponse response, FilterChain chain, String body) {
    }

    private static Filtered filter(Path dir, Map<String, Object> attestationClaims, String authorizationDetails)
            throws Exception {
        configureKeysFor(dir, DOFILTER_CLIENT_ID);
        PublicJsonWebKey attesterKey = ecKey("attester-1");
        PublicJsonWebKey instanceKey = ecKey("instance-1");
        trustAttester(dir, attesterKey);
        rarModelsFrom(Map.of());
        ClientAttestationAuthFilter filter = new ClientAttestationAuthFilter(FIXED_ISSUER);
        filter.init(null);
        Map<String, String[]> params = new HashMap<>();
        params.put("grant_type", new String[]{"client_credentials"});
        params.put("authorization_details", new String[]{authorizationDetails});
        HttpServletRequest req = attestedRequest(attestationWith(attesterKey, instanceKey, attestationClaims),
                popJwt(instanceKey, DOFILTER_CLIENT_ID, OP_ISSUER), params);
        java.io.StringWriter body = new java.io.StringWriter();
        HttpServletResponse resp = responseCapturingBody(body);
        FilterChain chain = mock(FilterChain.class);
        filter.doFilter(req, resp, chain);
        return new Filtered(req, resp, chain, body.toString());
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> errorBody(String body) throws Exception {
        return org.jose4j.json.JsonUtil.parseJson(body);
    }

    /** 0.3.0 answered this 401 access_denied (F-0038). */
    @Test
    @Requirement({"CAS §7.1", "RFC9396 §6"})
    void aRequestOutsideTheAttestationsDetailsIs400InvalidAuthorizationDetails(@TempDir Path dir) throws Exception {
        Filtered f = filter(dir, Map.of("authorization_details", entries(SALES_EMEA)),
                "[{\"type\":\"sales_agent\",\"sales_regions\":[\"AMER\"]}]");

        verify(f.response()).setStatus(400);
        org.mockito.Mockito.verifyNoInteractions(f.chain());
        assertEquals("invalid_authorization_details", errorBody(f.body()).get("error"));
        PublicErrorsAssert.assertGenericDescription("invalid_authorization_details", errorBody(f.body()).get("error_description"));
    }

    /**
     * RFC 9396 §5: "is an object of known type but containing unknown fields" is refused with
     * invalid_authorization_details. The description is fixed - the field's name and value stay in the log.
     */
    @Test
    @Requirement("RFC9396 §5")
    void aRequestTheModelRefusesIs400WithAFixedDescription(@TempDir Path dir) throws Exception {
        Filtered f = filter(dir, Map.of("authorization_details", entries(SALES_EMEA)),
                "[{\"type\":\"sales_agent\",\"sales_regions\":[\"EMEA\"],\"discount_code\":\"STAFF-50\"}]");

        verify(f.response()).setStatus(400);
        org.mockito.Mockito.verifyNoInteractions(f.chain());
        assertEquals("invalid_authorization_details", errorBody(f.body()).get("error"));
        PublicErrorsAssert.assertGenericDescription("invalid_authorization_details", errorBody(f.body()).get("error_description"));
        assertTrue(!f.body().contains("STAFF-50") && !f.body().contains("discount_code"), f.body());
    }

    /** Details the attester wrote and this server has no model for are the credential's fault: 401 invalid_client. */
    @Test
    void anAttestationWhoseDetailsTheModelRefusesIs401InvalidClient(@TempDir Path dir) throws Exception {
        Filtered f = filter(dir, Map.of("authorization_details", entries("[{\"type\":\"no-such-type\"}]")),
                SALES_EMEA);

        verify(f.response()).setStatus(401);
        org.mockito.Mockito.verifyNoInteractions(f.chain());
        assertEquals("invalid_client", errorBody(f.body()).get("error"));
        PublicErrorsAssert.assertGenericDescription("invalid_client", errorBody(f.body()).get("error_description"));
    }

    /**
     * A BFF's request carries {@code _principal_sub}, and a client may have written {@code _agent_id}: the gate takes
     * both off before it asks the model, so the request passes, and what PingFederate receives still has the
     * principal for the RAR plugin to read and the verified agent in place of the client's. The published context
     * names the model set that checked the request.
     */
    @Test
    void aBffRequestPassesAndKeepsItsPrincipalForThePluginWithTheVerifiedAgent(@TempDir Path dir) throws Exception {
        Filtered f = filter(dir, Map.of("authorization_details", entries(SALES_EMEA), "agent_id", "agent-7"),
                "[{\"type\":\"sales_agent\",\"sales_regions\":[\"EMEA\"],\"_principal_sub\":\"alice\","
                        + "\"_agent_id\":\"forged\"}]");

        assertTrue(f.body().isEmpty(), "expected a clean verification, got: " + f.body());
        ArgumentCaptor<ServletRequest> forwarded = ArgumentCaptor.forClass(ServletRequest.class);
        verify(f.chain()).doFilter(forwarded.capture(), org.mockito.ArgumentMatchers.any());
        Map<String, Object> detail = entries(((HttpServletRequest) forwarded.getValue()).getParameter("authorization_details")).get(0);
        assertEquals("alice", detail.get("_principal_sub"));
        assertEquals("agent-7", detail.get(ClientAttestationAuthFilter.AGENT_MARKER));

        ArgumentCaptor<Object> context = ArgumentCaptor.forClass(Object.class);
        verify(f.request()).setAttribute(
                org.mockito.ArgumentMatchers.eq(ClientAttestationUtils.RAR_ATTESTATION_CONTEXT_ATTRIBUTE), context.capture());
        assertEquals(com.pingidentity.ps.oidf.rar.model.RarModels.builtIn().fingerprint(),
                ((Map<?, ?>) context.getValue()).get("rar_models_fingerprint"));
    }
}
