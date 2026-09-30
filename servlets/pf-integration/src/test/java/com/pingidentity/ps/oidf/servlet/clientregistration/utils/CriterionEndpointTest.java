package com.pingidentity.ps.oidf.servlet.clientregistration.utils;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.pingidentity.ps.oidf.conformance.Requirement;
import com.pingidentity.ps.oidf.pf.FederationRuntimeConfig;
import com.pingidentity.ps.oidf.pf.FederationRuntimeConfigTestAccess;
import jakarta.servlet.http.HttpServletRequest;
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
import org.sourceid.saml20.adapter.attribute.AttributeValue;

/**
 * The OGNL issuance criterion binds a presentation to this server from its configuration, as the token-endpoint
 * filter does (ClientAttestationAuthFilterEndpointTest). It is the only gate in a deployment without the filter, so it
 * is driven here on its own: no verification is published on the request, and every request carries a {@code Host}
 * header, a request URL and an {@code X-Forwarded-Host} naming another server.
 *
 * <p>The PoP's {@code aud} must be the issuer alone (ABCA-10 §5.1), and a combined-mode DPoP proof's {@code htu} the
 * URL PingFederate advertises for the endpoint (RFC 9449 §4.3, item 9). Until 0.4.0 the criterion compared both with
 * {@code getRequestURL()}.
 */
class CriterionEndpointTest {
    private static final String ATTESTER = "https://attester.example.com";
    private static final String CLIENT = "https://rp.example.com/agent-1";
    private static final String ISSUER = "https://as.example.com";
    private static final String TOKEN_PATH = "/as/token.oauth2";
    private static final String OTHER_HOST = "other-bank.example";
    private static final String OTHER_TOKEN_ENDPOINT = "https://" + OTHER_HOST + TOKEN_PATH;
    private static final Function<HttpServletRequest, String> CONFIGURED_ISSUER = r -> ISSUER;

    private PublicJsonWebKey attesterKey;
    private PublicJsonWebKey instanceKey;

    @BeforeEach
    void configure(@TempDir Path dir) throws Exception {
        attesterKey = ecKey("attester-1");
        instanceKey = ecKey("instance-1");
        Path attesters = dir.resolve("mock-attesters.json");
        Files.writeString(attesters, "{\"" + ATTESTER + "\":{\"keys\":["
                + attesterKey.toJson(JsonWebKey.OutputControlLevel.PUBLIC_ONLY) + "]}}");
        System.setProperty("oidf.mock.attesters", attesters.toString());
        resetSingletons();
    }

    @AfterEach
    void clear() throws Exception {
        System.clearProperty("oidf.mock.attesters");
        resetSingletons();
    }

    private static void resetSingletons() throws Exception {
        FederationRuntimeConfigTestAccess.reset();
        java.lang.reflect.Method mock = ClientAttestationUtils.class.getDeclaredMethod("resetMockAttesterResolverForTest");
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

    /** A token request whose Host header, request URL and X-Forwarded-Host all name {@code host}. */
    private static HttpServletRequest request(String host, String attestation, String pop, String dpop) {
        HttpServletRequest req = mock(HttpServletRequest.class);
        when(req.getHeaders("OAuth-Client-Attestation")).thenReturn(Collections.enumeration(List.of(attestation)));
        when(req.getHeaders("OAuth-Client-Attestation-PoP"))
                .thenReturn(Collections.enumeration(pop == null ? List.of() : List.of(pop)));
        when(req.getHeaders("DPoP")).thenReturn(Collections.enumeration(dpop == null ? List.of() : List.of(dpop)));
        when(req.getHeader("Host")).thenReturn(host);
        when(req.getHeader("X-Forwarded-Host")).thenReturn(host);
        when(req.getServerName()).thenReturn(host);
        when(req.getScheme()).thenReturn("https");
        when(req.getServerPort()).thenReturn(443);
        when(req.getRequestURL()).thenReturn(new StringBuffer("https://" + host + TOKEN_PATH));
        when(req.getRequestURI()).thenReturn(TOKEN_PATH);
        when(req.getContextPath()).thenReturn("");
        when(req.getServletPath()).thenReturn(TOKEN_PATH);
        when(req.getMethod()).thenReturn("POST");
        Map<String, Object> attributes = new HashMap<>();
        when(req.getAttribute(anyString())).thenAnswer(i -> attributes.get(i.getArgument(0)));
        org.mockito.Mockito.doAnswer(i -> attributes.put(i.getArgument(0), i.getArgument(1)))
                .when(req).setAttribute(anyString(), any());
        return req;
    }

    /** The OGNL in-parameter map the criterion is handed. */
    private static Map<String, Object> inParams(HttpServletRequest request) {
        Map<String, Object> in = new HashMap<>();
        AttributeValue requestValue = mock(AttributeValue.class);
        when(requestValue.getObjectValue()).thenReturn(request);
        in.put("context.HttpRequest", requestValue);
        AttributeValue clientValue = mock(AttributeValue.class);
        when(clientValue.getValue()).thenReturn(CLIENT);
        in.put("context.ClientId", clientValue);
        return in;
    }

    private static boolean criterion(HttpServletRequest request) {
        return ClientAttestationUtils.validateClientAttestationInner(inParams(request), false,
                "https://trust-controller.example.com", "https://trust-controller.example.com", CONFIGURED_ISSUER,
                () -> null, CriterionTesting.NO_CLIENTS, CriterionTesting.NO_SUBJECT_TOKENS);
    }

    @Test
    @Requirement("RFC9449 §4.3(9)")
    void aProofForTheConfiguredEndpointPassesWhateverTheHostHeaderSays() throws Exception {
        assertTrue(criterion(request(OTHER_HOST, attestation(), null, dpop(ISSUER + TOKEN_PATH))));
    }

    /** The request URL rebuilt from this Host header is the proof's htu exactly, which 0.3.0 compared it with. */
    @Test
    @Requirement("RFC9449 §4.3(9)")
    void aProofForAnotherServerIsRefusedWhenTheHostHeaderNamesThatServer() throws Exception {
        assertFalse(criterion(request(OTHER_HOST, attestation(), null, dpop(OTHER_TOKEN_ENDPOINT))));
    }

    @Test
    @Requirement({"ABCA-10 §5.1", "ABCA-10 §7.2(7)"})
    void aPopAddressedToTheIssuerAloneAuthenticates() throws Exception {
        assertTrue(criterion(request(OTHER_HOST, attestation(), pop(ISSUER), null)));
    }

    /** What 0.3.0 accepted, the request URL being an accepted audience. */
    @Test
    @Requirement("ABCA-10 §7.2(7)")
    void aPopAddressedToTheRequestUrlIsRefused() throws Exception {
        assertFalse(criterion(request(OTHER_HOST, attestation(), pop(OTHER_TOKEN_ENDPOINT), null)));
        assertFalse(criterion(request("as.example.com", attestation(), pop(ISSUER + TOKEN_PATH), null)));
    }

    /** The token endpoint base URL moves the token endpoint the criterion expects, as it does discovery's. */
    @Test
    @Requirement("RFC9449 §4.3(9)")
    void theTokenEndpointBaseUrlIsTheCriterionsTokenEndpoint() throws Exception {
        String base = "https://mtls.as.example.com:8443";
        HttpServletRequest atBase = request(OTHER_HOST, attestation(), null, dpop(base + TOKEN_PATH));
        HttpServletRequest atIssuer = request(OTHER_HOST, attestation(), null, dpop(ISSUER + TOKEN_PATH));

        assertTrue(ClientAttestationUtils.validateClientAttestationInner(inParams(atBase), false,
                "https://trust-controller.example.com", "https://trust-controller.example.com", CONFIGURED_ISSUER,
                () -> base, CriterionTesting.NO_CLIENTS, CriterionTesting.NO_SUBJECT_TOKENS));
        assertFalse(ClientAttestationUtils.validateClientAttestationInner(inParams(atIssuer), false,
                "https://trust-controller.example.com", "https://trust-controller.example.com", CONFIGURED_ISSUER,
                () -> base, CriterionTesting.NO_CLIENTS, CriterionTesting.NO_SUBJECT_TOKENS));
    }
}
