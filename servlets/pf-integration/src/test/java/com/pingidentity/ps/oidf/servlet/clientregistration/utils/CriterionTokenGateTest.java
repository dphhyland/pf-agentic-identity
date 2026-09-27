package com.pingidentity.ps.oidf.servlet.clientregistration.utils;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.pingidentity.ps.oidf.clientattestation.AttestationRarModels;
import com.pingidentity.ps.oidf.conformance.Requirement;
import com.pingidentity.ps.oidf.rar.model.RarModels;
import jakarta.servlet.http.HttpServletRequest;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.function.Function;
import java.util.logging.Handler;
import java.util.logging.LogRecord;
import java.util.logging.Logger;
import org.jose4j.json.JsonUtil;
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
 * The token gate on the issuance criterion's own path - idp-agentic-demo's only gate, where no filter verified the
 * request first. The criterion asks the same {@code ClientAttestationVerifier} as the filter; these tests drive it
 * end to end with a real attestation and proof, through the OP-issuer seam, so a change to what the criterion loads,
 * asks or stashes is caught here and not only in the verifier's own tests.
 *
 * <p>CAS section 7.1: an authorization server "MUST, when authenticating a client via an attestation containing
 * authorization_details, ensure that any authority granted in issued tokens is a subset of the attestation's
 * authorization_details (same subset semantics as Section 7 rule 1), and MUST reject requests exceeding it with
 * invalid_authorization_details [RFC9396]."
 */
class CriterionTokenGateTest {

    private static final String ATTESTER_ISSUER = "https://attester.example.com";
    private static final String CLIENT_ID = "https://rp.example.com/agent-1";
    private static final String OP_ISSUER = "https://as.example.com";
    private static final String TOKEN_ENDPOINT = OP_ISSUER + "/as/token.oauth2";
    private static final Function<HttpServletRequest, String> FIXED_ISSUER = r -> OP_ISSUER;
    private static final String SALES_EMEA = "[{\"type\":\"sales_agent\",\"sales_regions\":[\"EMEA\"]}]";

    private final List<String> logged = new ArrayList<>();
    private final Handler capture = new Handler() {
        @Override
        public void publish(LogRecord record) {
            logged.add(record.getMessage() + (record.getThrown() == null ? "" : " / " + record.getThrown().getMessage()));
        }

        @Override
        public void flush() {
        }

        @Override
        public void close() {
        }
    };

    @AfterEach
    void clearTheDeployment() throws Exception {
        Logger.getLogger(ClientAttestationUtils.class.getName()).removeHandler(capture);
        System.clearProperty("oidf.mock.attesters");
        invokeReset(ClientAttestationUtils.class, "resetMockAttesterResolverForTest");
        rarModelsFrom(null);
    }

    private static void invokeReset(Class<?> owner, String name) throws Exception {
        java.lang.reflect.Method reset = owner.getDeclaredMethod(name);
        reset.setAccessible(true);
        reset.invoke(null);
    }

    private static void rarModelsFrom(Map<String, String> env) throws Exception {
        java.lang.reflect.Method reset = AttestationRarModels.class.getDeclaredMethod("resetForTest", Map.class);
        reset.setAccessible(true);
        reset.invoke(null, env);
    }

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

    /** One attested token request as the criterion sees it: the OGNL in-parameters and the request behind them. */
    private record Criterion(Map<String, Object> in, HttpServletRequest request, Map<String, Object> attributes) {
    }

    /**
     * A trusted attester whose attestation carries {@code attested} as its authorization_details (none when null),
     * and a token request carrying {@code params}.
     */
    private Criterion criterion(Path dir, String attested, Map<String, String[]> params) throws Exception {
        PublicJsonWebKey attesterKey = ecKey("attester-1");
        PublicJsonWebKey instanceKey = ecKey("instance-1");
        Path trust = dir.resolve("mock-attesters.json");
        Files.writeString(trust, "{\"" + ATTESTER_ISSUER + "\":{\"keys\":["
                + attesterKey.toJson(JsonWebKey.OutputControlLevel.PUBLIC_ONLY) + "]}}");
        System.setProperty("oidf.mock.attesters", trust.toString());
        invokeReset(ClientAttestationUtils.class, "resetMockAttesterResolverForTest");

        JwtClaims a = new JwtClaims();
        a.setIssuer(ATTESTER_ISSUER);
        a.setSubject(CLIENT_ID);
        a.setIssuedAtToNow();
        a.setExpirationTime(NumericDate.fromSeconds(NumericDate.now().getValue() + 600L));
        a.setClaim("cnf", Map.of("jwk", instanceKey.toParams(JsonWebKey.OutputControlLevel.PUBLIC_ONLY)));
        if (attested != null) {
            a.setClaim("authorization_details", JsonUtil.parseJson("{\"d\":" + attested + "}").get("d"));
        }
        JwtClaims p = new JwtClaims();
        p.setIssuer(CLIENT_ID);
        p.setAudience(OP_ISSUER);
        p.setJwtId(UUID.randomUUID().toString());
        p.setIssuedAtToNow();

        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getHeaders("OAuth-Client-Attestation")).thenReturn(
                Collections.enumeration(List.of(sign(attesterKey, "oauth-client-attestation+jwt", a))));
        when(request.getHeaders("OAuth-Client-Attestation-PoP")).thenReturn(
                Collections.enumeration(List.of(sign(instanceKey, "oauth-client-attestation-pop+jwt", p))));
        when(request.getHeaders("DPoP")).thenReturn(Collections.enumeration(List.of()));
        when(request.getRequestURL()).thenReturn(new StringBuffer(TOKEN_ENDPOINT));
        when(request.getMethod()).thenReturn("POST");
        when(request.getParameterValues(anyString())).thenAnswer(i -> params.get((String) i.getArgument(0)));
        when(request.getParameter(anyString())).thenAnswer(i -> {
            String[] v = params.get((String) i.getArgument(0));
            return v == null || v.length == 0 ? null : v[0];
        });
        Map<String, Object> attributes = new HashMap<>();
        when(request.getAttribute(anyString())).thenAnswer(i -> attributes.get((String) i.getArgument(0)));
        org.mockito.Mockito.doAnswer(i -> attributes.put(i.getArgument(0), i.getArgument(1)))
                .when(request).setAttribute(anyString(), any());

        Map<String, Object> in = new HashMap<>();
        AttributeValue requestValue = mock(AttributeValue.class);
        when(requestValue.getObjectValue()).thenReturn(request);
        in.put("context.HttpRequest", requestValue);
        AttributeValue clientValue = mock(AttributeValue.class);
        when(clientValue.getValue()).thenReturn(CLIENT_ID);
        in.put("context.ClientId", clientValue);
        Logger.getLogger(ClientAttestationUtils.class.getName()).addHandler(capture);
        return new Criterion(in, request, attributes);
    }

    private static boolean ask(Criterion c) {
        return ClientAttestationUtils.validateClientAttestation(c.in(), false, "https://trust-controller.example.com",
                "https://trust-controller.example.com", FIXED_ISSUER);
    }

    private static Map<String, String[]> params(String name, String... values) {
        Map<String, String[]> params = new HashMap<>();
        params.put("grant_type", new String[]{"client_credentials"});
        params.put(name, values);
        return params;
    }

    /**
     * A request within the attestation's details passes. What an access-token mapping can read is the request's own
     * details without the {@code _principal_sub} and {@code _agent_id} markers, and the context the RAR plugin reads
     * names the model set that checked them.
     */
    @Test
    @Requirement({"CAS §7.1", "RFC9396 §6.1"})
    void aRequestWithinTheAttestationPassesAndIsStashedWithoutItsMarkers(@TempDir Path dir) throws Exception {
        rarModelsFrom(Map.of());
        Criterion c = criterion(dir, SALES_EMEA, params("authorization_details",
                "[{\"type\":\"sales_agent\",\"sales_regions\":[\"EMEA\"],\"_principal_sub\":\"alice\",\"_agent_id\":\"agent-7\"}]"));

        assertTrue(ask(c), logged.toString());

        List<?> stashed = (List<?>) JsonUtil.parseJson("{\"d\":" + c.attributes().get("oidf.authorization_details") + "}").get("d");
        assertEquals(List.of(Map.of("type", "sales_agent", "sales_regions", List.of("EMEA"))), stashed);
        Map<?, ?> context = (Map<?, ?>) c.attributes().get(ClientAttestationUtils.RAR_ATTESTATION_CONTEXT_ATTRIBUTE);
        assertEquals(RarModels.builtIn().fingerprint(), context.get("rar_models_fingerprint"));
        assertEquals(context, c.attributes().get(ClientAttestationUtils.VERIFIED_ATTESTATION_ATTRIBUTE));
    }

    /**
     * A request outside the attestation's details is refused, and the log line carries the model's own reason. The
     * criterion refuses the token; PingFederate answers with the Error Result configured on it.
     */
    @Test
    @Requirement({"CAS §7.1", "RFC9396 §6.1"})
    void aRequestOutsideTheAttestationIsRefusedWithTheModelsReasonInTheLog(@TempDir Path dir) throws Exception {
        rarModelsFrom(Map.of());
        Criterion c = criterion(dir, SALES_EMEA, params("authorization_details",
                "[{\"type\":\"sales_agent\",\"sales_regions\":[\"AMER\"]}]"));

        assertFalse(ask(c));

        assertTrue(logged.stream().anyMatch(m -> m.contains("[invalid_authorization_details]")
                && m.contains("authorization_details exceeds what the client attestation allows")
                && m.contains("sales_agent") && !m.contains("AMER")), logged.toString());
        assertNull(c.attributes().get("oidf.authorization_details"));
        assertNull(c.attributes().get(ClientAttestationUtils.RAR_ATTESTATION_CONTEXT_ATTRIBUTE));
    }

    /**
     * The same request, which the built-in models let through, is refused when the deployment's models document
     * cannot be read: the criterion does not fall back to the built-ins.
     */
    @Test
    void aModelsDocumentThatCannotBeReadRefusesARequestTheBuiltInsWouldPass(@TempDir Path dir) throws Exception {
        rarModelsFrom(Map.of(RarModels.ENV_MODELS, "{\"types\":"));
        Criterion c = criterion(dir, SALES_EMEA, params("authorization_details", SALES_EMEA));

        assertFalse(ask(c));

        assertTrue(logged.stream().anyMatch(m -> m.contains("RAR containment models could not be loaded")), logged.toString());
        assertNull(c.attributes().get(ClientAttestationUtils.RAR_ATTESTATION_CONTEXT_ATTRIBUTE));
    }

    /**
     * PingFederate refuses an unregistered authorization_details type before the criterion runs, so a blank
     * authorization_details falls back to {@code oidf_requested_access}, which is checked the same way.
     */
    @Test
    @Requirement("CAS §7.1")
    void aBlankAuthorizationDetailsFallsBackToTheDedicatedParameter(@TempDir Path dir) throws Exception {
        rarModelsFrom(Map.of());
        Map<String, String[]> params = params("authorization_details", " ");
        params.put("oidf_requested_access", new String[]{"[{\"type\":\"sales_agent\",\"sales_regions\":[\"AMER\"]}]"});
        Criterion c = criterion(dir, SALES_EMEA, params);

        assertFalse(ask(c), "the fallback parameter must be checked, not skipped");

        params.put("oidf_requested_access", new String[]{SALES_EMEA});
        Criterion within = criterion(dir, SALES_EMEA, params);
        assertTrue(ask(within), logged.toString());
        assertEquals(List.of(Map.of("type", "sales_agent", "sales_regions", List.of("EMEA"))),
                JsonUtil.parseJson("{\"d\":" + within.attributes().get("oidf.authorization_details") + "}").get("d"));
    }

    /** A request that asks for nothing is authenticated and has nothing stashed (asking for nothing is S4d's, F-0032). */
    @Test
    void aRequestThatAsksForNothingStashesNothing(@TempDir Path dir) throws Exception {
        rarModelsFrom(Map.of());
        Criterion c = criterion(dir, SALES_EMEA, params("scope", "openid"));

        assertTrue(ask(c), logged.toString());

        assertNull(c.attributes().get("oidf.authorization_details"));
        assertTrue(c.attributes().get(ClientAttestationUtils.RAR_ATTESTATION_CONTEXT_ATTRIBUTE) instanceof Map);
    }

    /**
     * RFC 6749 section 3.2: "Request and response parameters MUST NOT be included more than once." The criterion
     * checks the first value, and with no filter in front nothing decides which one PingFederate reads, so a repeated
     * authorization_details - or its fallback - is refused, even when the first value is within the attestation.
     */
    @Test
    @Requirement("RFC6749 §3.2")
    void aRepeatedAuthorizationDetailsIsRefused(@TempDir Path dir) throws Exception {
        rarModelsFrom(Map.of());
        Criterion repeated = criterion(dir, SALES_EMEA, params("authorization_details", SALES_EMEA,
                "[{\"type\":\"sales_agent\",\"sales_regions\":[\"AMER\"]}]"));
        assertFalse(ask(repeated));

        Criterion fallback = criterion(dir, SALES_EMEA, params("oidf_requested_access", SALES_EMEA, SALES_EMEA));
        assertFalse(ask(fallback));

        assertTrue(logged.stream().anyMatch(m -> m.contains("Multiple 'authorization_details' parameters")), logged.toString());
        assertTrue(logged.stream().anyMatch(m -> m.contains("Multiple 'oidf_requested_access' parameters")), logged.toString());
    }
}
