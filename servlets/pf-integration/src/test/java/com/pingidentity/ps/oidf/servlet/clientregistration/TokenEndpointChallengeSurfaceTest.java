package com.pingidentity.ps.oidf.servlet.clientregistration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.pingidentity.ps.oidf.clientattestation.AttestationChallengeService.Consumption;
import com.pingidentity.ps.oidf.clientattestation.AttestationSupport;
import com.pingidentity.ps.oidf.clientattestation.StoreNamespace;
import com.pingidentity.ps.oidf.conformance.Requirement;
import com.pingidentity.ps.oidf.pf.BridgeSigners;
import com.pingidentity.ps.oidf.pf.FederationRuntimeConfig;
import com.pingidentity.ps.oidf.pf.FederationRuntimeConfigTestAccess;
import com.pingidentity.ps.oidf.servlet.clientregistration.utils.ClientAttestationUtils;
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
import org.sourceid.saml20.adapter.attribute.AttributeValue;

/**
 * The token endpoint takes the authorization server's challenges and refuses the attester's, at both places that
 * verify a Client Attestation PoP there: {@link ClientAttestationAuthFilter} and the issuance criterion
 * ({@link ClientAttestationUtils#validateClientAttestation(Object)}, for a deployment without the filter).
 *
 * <p>CAS §4.1: "[ABCA]'s challenge freshens the PoP presented *to the AS*; this one freshens the Instance Key Proof
 * presented *to the CAS* - and a challenge issued by one party MUST NOT be accepted by the other." The authorization
 * server's endpoint issues into {@code oidf:as:challenge:*} and the attester's into {@code oidf:cas:challenge:*};
 * these tests issue into each store directly and drive the real filter and criterion, so they fail if either
 * verifier is built over the attester's store, or over none.
 */
class TokenEndpointChallengeSurfaceTest {

    private static final String BACKING_PROP = "oidf.bridge.signer.backing";
    private static final String KEYS_PROP = "oidf.bridge.signing.keys";
    private static final String MOCK_ATTESTERS_PROP = "oidf.mock.attesters";
    private static final String HOST_PROP = "oidf.federation.trust.controller.host";

    private static final String ATTESTER_ISSUER = "https://attester.example.com";
    private static final String CLIENT_ID = "https://rp.example.com/agent-1";
    private static final String OP_ISSUER = "https://as.example.com";
    private static final String TOKEN_ENDPOINT = OP_ISSUER + "/as/token.oauth2";

    private final PublicJsonWebKey attesterKey = ecKey("attester-1");
    private final PublicJsonWebKey instanceKey = ecKey("instance-1");

    @AfterEach
    void clearProps() throws Exception {
        System.clearProperty(BACKING_PROP);
        System.clearProperty(KEYS_PROP);
        System.clearProperty(MOCK_ATTESTERS_PROP);
        System.clearProperty(HOST_PROP);
        resetSingletons();
    }

    // ---- ClientAttestationAuthFilter ---------------------------------------------------------------

    @Test
    @Requirement("CAS §4.1")
    void theFilterRefusesAChallengeFromTheAttestersStoreAndLeavesItUnspent(@TempDir Path dir) throws Exception {
        ClientAttestationAuthFilter filter = configuredFilter(dir);
        String challenge = AttestationSupport.challengeService(StoreNamespace.CAS).issue();
        StringWriter body = new StringWriter();
        HttpServletResponse resp = responseCapturing(body);
        FilterChain chain = mock(FilterChain.class);

        filter.doFilter(request(popWithChallenge(challenge)), resp, chain);

        verify(resp).setStatus(400);
        assertTrue(body.toString().contains("\"use_attestation_challenge\""), body.toString());
        verify(chain, never()).doFilter(any(), any());
        assertEquals(Consumption.CONSUMED, AttestationSupport.challengeService(StoreNamespace.CAS).consumeChallenge(challenge),
                "the refusal left the attester's challenge for the attester");
    }

    @Test
    @Requirement("ABCA-10 §6.1")
    void theFilterTakesAChallengeFromTheAuthorizationServersStoreOnce(@TempDir Path dir) throws Exception {
        ClientAttestationAuthFilter filter = configuredFilter(dir);
        String challenge = AttestationSupport.challengeService(StoreNamespace.AS).issue();
        StringWriter body = new StringWriter();
        FilterChain chain = mock(FilterChain.class);

        filter.doFilter(request(popWithChallenge(challenge)), responseCapturing(body), chain);

        assertTrue(body.toString().isEmpty(), "a verified request writes no error body: " + body);
        verify(chain).doFilter(any(), any());
        assertEquals(Consumption.UNKNOWN, AttestationSupport.challengeService(StoreNamespace.AS).consumeChallenge(challenge),
                "the filter spent the authorization server's challenge");
    }

    // ---- the issuance criterion ---------------------------------------------------------------------

    @Test
    @Requirement("CAS §4.1")
    void theCriterionRefusesAChallengeFromTheAttestersStoreAndLeavesItUnspent(@TempDir Path dir) throws Exception {
        trustAttester(dir);
        String challenge = AttestationSupport.challengeService(StoreNamespace.CAS).issue();

        assertFalse(criterion(request(popWithChallenge(challenge))), "the attester's challenge satisfied the criterion");
        assertEquals(Consumption.CONSUMED, AttestationSupport.challengeService(StoreNamespace.CAS).consumeChallenge(challenge),
                "the refusal left the attester's challenge for the attester");
    }

    @Test
    @Requirement("ABCA-10 §6.1")
    void theCriterionTakesAChallengeFromTheAuthorizationServersStoreOnce(@TempDir Path dir) throws Exception {
        trustAttester(dir);
        String challenge = AttestationSupport.challengeService(StoreNamespace.AS).issue();

        assertTrue(criterion(request(popWithChallenge(challenge))), "the authorization server's challenge was refused");
        assertEquals(Consumption.UNKNOWN, AttestationSupport.challengeService(StoreNamespace.AS).consumeChallenge(challenge),
                "the criterion spent the authorization server's challenge");
    }

    // ---- fixtures -------------------------------------------------------------------------------------

    /** A filter with bridge signing for {@link #CLIENT_ID}, bound to the trusted attester, as a deployment runs it. */
    private ClientAttestationAuthFilter configuredFilter(Path dir) throws Exception {
        EllipticCurveJsonWebKey bridgeKey = EcJwkGenerator.generateJwk(EllipticCurves.P256);
        bridgeKey.setKeyId("bridge-1");
        Path keys = dir.resolve("bridge-keys.json");
        Files.writeString(keys, "{\"" + CLIENT_ID + "\":{\"jwk\":"
                + bridgeKey.toJson(JsonWebKey.OutputControlLevel.INCLUDE_PRIVATE)
                + ",\"attesters\":[\"" + ATTESTER_ISSUER + "\"]}}");
        System.setProperty(BACKING_PROP, "config");
        System.setProperty(KEYS_PROP, keys.toString());
        trustAttester(dir);
        ClientAttestationAuthFilter filter = new ClientAttestationAuthFilter(r -> OP_ISSUER);
        filter.init(null);
        return filter;
    }

    /** Trusts {@link #attesterKey} for {@link #ATTESTER_ISSUER} through {@code oidf.mock.attesters}. */
    private void trustAttester(Path dir) throws Exception {
        Path file = dir.resolve("mock-attesters.json");
        Files.writeString(file, "{\"" + ATTESTER_ISSUER + "\":{\"keys\":["
                + this.attesterKey.toJson(JsonWebKey.OutputControlLevel.PUBLIC_ONLY) + "]}}");
        System.setProperty(MOCK_ATTESTERS_PROP, file.toString());
        System.setProperty(HOST_PROP, "https://trust-controller.example.com");
        resetSingletons();
    }

    /** Runs the issuance criterion as PingFederate's OGNL hands it a token request, the issuer resolving to {@link #OP_ISSUER}. */
    private static boolean criterion(HttpServletRequest request) {
        Map<String, Object> in = new HashMap<>();
        AttributeValue requestValue = mock(AttributeValue.class);
        when(requestValue.getObjectValue()).thenReturn(request);
        in.put("context.HttpRequest", requestValue);
        AttributeValue clientValue = mock(AttributeValue.class);
        when(clientValue.getValue()).thenReturn(CLIENT_ID);
        in.put("context.ClientId", clientValue);
        FederationRuntimeConfig runtime = FederationRuntimeConfig.get();
        java.util.function.Function<HttpServletRequest, String> issuerOf = r -> OP_ISSUER;
        return criterionWithIssuer(in, runtime.ignoreSslErrors(), runtime.trustControllerHost(),
                runtime.trustControllerBaseUrl(), issuerOf);
    }

    /**
     * {@code ClientAttestationUtils}' issuer seam, the package-private overload the public criterion delegates to;
     * PingFederate's {@code OAuthIssuerUtils} cannot initialise outside a booted server. By reflection, as this
     * test sits in the filter's package.
     */
    private static boolean criterionWithIssuer(Map<String, Object> in, Boolean ignoreSslErrors, String trustControllerHost,
            String trustControllerBaseUrl, java.util.function.Function<HttpServletRequest, String> issuerOf) {
        try {
            java.lang.reflect.Method criterion = ClientAttestationUtils.class.getDeclaredMethod("validateClientAttestationInner",
                    Object.class, Boolean.class, String.class, String.class, java.util.function.Function.class,
                    java.util.function.Supplier.class,
                    com.pingidentity.ps.oidf.servlet.clientregistration.utils.AttestationPolicyResolver.class,
                    com.pingidentity.ps.oidf.servlet.clientregistration.utils.SubjectTokenVerifier.class);
            criterion.setAccessible(true);
            java.util.function.Supplier<String> noBase = () -> null;
            return (Boolean) criterion.invoke(null, in, ignoreSslErrors, trustControllerHost, trustControllerBaseUrl, issuerOf,
                    noBase, com.pingidentity.ps.oidf.servlet.clientregistration.utils.AttestationPolicyResolver.over(
                            id -> null, java.time.Clock.systemUTC(), () -> false),
                    new com.pingidentity.ps.oidf.servlet.clientregistration.utils.SubjectTokenVerifier(() -> null));
        } catch (ReflectiveOperationException e) {
            throw new IllegalStateException(e);
        }
    }

    /** A token request carrying an attestation for {@link #CLIENT_ID} and the given PoP. */
    private HttpServletRequest request(String pop) throws Exception {
        String attestation = this.attestation();
        HttpServletRequest req = mock(HttpServletRequest.class);
        when(req.getHeaders("OAuth-Client-Attestation")).thenAnswer(i -> Collections.enumeration(List.of(attestation)));
        when(req.getHeaders("OAuth-Client-Attestation-PoP")).thenAnswer(i -> Collections.enumeration(List.of(pop)));
        when(req.getHeaders("DPoP")).thenAnswer(i -> Collections.enumeration(List.of()));
        when(req.getRequestURL()).thenAnswer(i -> new StringBuffer(TOKEN_ENDPOINT));
        // Routed as PingFederate routes a token request: no context path, the *.oauth2 servlet path.
        when(req.getContextPath()).thenReturn("");
        when(req.getServletPath()).thenReturn("/as/token.oauth2");
        when(req.getRequestURI()).thenReturn("/as/token.oauth2");
        when(req.getMethod()).thenReturn("POST");
        Map<String, String[]> params = new HashMap<>();
        params.put("grant_type", new String[]{"client_credentials"});
        when(req.getParameterMap()).thenReturn(params);
        when(req.getParameter(org.mockito.ArgumentMatchers.anyString())).thenAnswer(i -> {
            String[] v = params.get((String) i.getArgument(0));
            return v == null || v.length == 0 ? null : v[0];
        });
        return req;
    }

    private String attestation() throws Exception {
        JwtClaims claims = new JwtClaims();
        claims.setIssuer(ATTESTER_ISSUER);
        claims.setSubject(CLIENT_ID);
        claims.setIssuedAtToNow();
        claims.setExpirationTime(NumericDate.fromSeconds(NumericDate.now().getValue() + 600L));
        claims.setClaim("cnf", Map.of("jwk", this.instanceKey.toParams(JsonWebKey.OutputControlLevel.PUBLIC_ONLY)));
        return sign(this.attesterKey, "oauth-client-attestation+jwt", claims);
    }

    private String popWithChallenge(String challenge) throws Exception {
        JwtClaims claims = new JwtClaims();
        claims.setIssuer(CLIENT_ID);
        claims.setAudience(OP_ISSUER);
        claims.setJwtId(UUID.randomUUID().toString());
        claims.setIssuedAtToNow();
        claims.setClaim("challenge", challenge);
        return sign(this.instanceKey, "oauth-client-attestation-pop+jwt", claims);
    }

    private static String sign(PublicJsonWebKey key, String typ, JwtClaims claims) throws Exception {
        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(claims.toJson());
        jws.setKey(key.getPrivateKey());
        jws.setAlgorithmHeaderValue("ES256");
        jws.setHeader("typ", typ);
        return jws.getCompactSerialization();
    }

    private static HttpServletResponse responseCapturing(StringWriter body) throws Exception {
        HttpServletResponse resp = mock(HttpServletResponse.class);
        when(resp.getWriter()).thenReturn(new PrintWriter(body, true));
        return resp;
    }

    private static PublicJsonWebKey ecKey(String kid) {
        try {
            EllipticCurveJsonWebKey key = EcJwkGenerator.generateJwk(EllipticCurves.P256);
            key.setKeyId(kid);
            return key;
        } catch (org.jose4j.lang.JoseException e) {
            throw new IllegalStateException(e);
        }
    }

    /** The runtime, bridge and mock-attester holders memoise what they read; each test starts from its own settings. */
    private static void resetSingletons() throws Exception {
        FederationRuntimeConfigTestAccess.reset();
        java.lang.reflect.Method bridge = BridgeSigners.class.getDeclaredMethod("resetForTest");
        bridge.setAccessible(true);
        bridge.invoke(null);
        java.lang.reflect.Method attesters = ClientAttestationUtils.class.getDeclaredMethod("resetMockAttesterResolverForTest");
        attesters.setAccessible(true);
        attesters.invoke(null);
    }
}
