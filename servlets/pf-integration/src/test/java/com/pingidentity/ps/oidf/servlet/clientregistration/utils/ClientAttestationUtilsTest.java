package com.pingidentity.ps.oidf.servlet.clientregistration.utils;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.when;

import com.pingidentity.ps.oidf.clientattestation.AttestationRarModels;
import com.pingidentity.ps.oidf.clientattestation.ClientAttestationException;
import com.pingidentity.ps.oidf.clientattestation.ClientAttestationResult;
import com.pingidentity.ps.oidf.rar.model.RarModelException;
import com.pingidentity.ps.oidf.rar.model.RarModels;
import jakarta.servlet.http.HttpServletRequest;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Handler;
import java.util.logging.LogRecord;
import java.util.logging.Logger;
import org.jose4j.jwk.EcJwkGenerator;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.keys.EllipticCurves;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.sourceid.saml20.adapter.attribute.AttributeValue;

/**
 * {@link ClientAttestationUtils}' own decisions: the RFC 8693 acting-party sub fallback (Phase 2.8), what the
 * attestation context tells the RAR plugin about the model set that checked the request (plan item S1b), and the
 * log line a refusal leaves. {@code VerifyOnceTest} and {@code AttestationClaimSourceTest} cover the criterion and
 * the token-mapping reads.
 */
class ClientAttestationUtilsTest {

    @AfterEach
    void readTheModelsFromTheProcessEnvironmentAgain() throws Exception {
        rarModelsFrom(null);
    }

    private static void rarModelsFrom(Map<String, String> env) throws Exception {
        java.lang.reflect.Method reset = AttestationRarModels.class.getDeclaredMethod("resetForTest", Map.class);
        reset.setAccessible(true);
        reset.invoke(null, env);
    }

    @Test
    void prefersAgentIdWhenPresent() {
        assertEquals("agent-id-1", ClientAttestationUtils.actingPartySub("agent-id-1", "https://rp.example.com"));
    }

    @Test
    void fallsBackToClientIdWhenAgentIdIsNull() {
        assertEquals("https://rp.example.com", ClientAttestationUtils.actingPartySub(null, "https://rp.example.com"));
    }

    @Test
    void fallsBackToClientIdWhenAgentIdIsBlank() {
        assertEquals("https://rp.example.com", ClientAttestationUtils.actingPartySub("   ", "https://rp.example.com"));
        assertEquals("https://rp.example.com", ClientAttestationUtils.actingPartySub("", "https://rp.example.com"));
    }

    private static ClientAttestationResult result(String fingerprint) throws Exception {
        Map<String, Object> cnf = EcJwkGenerator.generateJwk(EllipticCurves.P256).toParams(JsonWebKey.OutputControlLevel.PUBLIC_ONLY);
        return new ClientAttestationResult("https://rp.example.com", cnf, ClientAttestationResult.Mode.POP_JWT,
                "https://attester.example.com", "jti-1", List.of(Map.of("type", "sales_agent")), List.of(), Map.of(),
                null, fingerprint);
    }

    /**
     * {@code rar_models_fingerprint} is exactly {@code RarModels.fingerprint()} of the set that checked the request -
     * lower-case hex SHA-256 - which the RAR plugin compares with its own (plan item S1c).
     */
    @Test
    void theContextNamesTheModelSetThatCheckedTheRequest() throws Exception {
        String fingerprint = RarModels.builtIn().fingerprint();

        Map<String, Object> context = ClientAttestationUtils.attestationContext(result(fingerprint));

        assertEquals(fingerprint, context.get("rar_models_fingerprint"));
        assertTrue(fingerprint.matches("[0-9a-f]{64}"), fingerprint);
        assertFalse(ClientAttestationUtils.attestationContext(result(null)).containsKey("rar_models_fingerprint"),
                "a result no model checked says nothing about one");
    }

    /**
     * Everything else the context says is what the verified result carries, and nothing it does not: an agent and
     * an attester only when non-blank, the workload flat as well as nested, and no thumbprint for a key that has
     * none.
     */
    @Test
    void theContextCarriesWhatTheResultHasAndNothingItDoesNot() throws Exception {
        Map<String, Object> cnf = EcJwkGenerator.generateJwk(EllipticCurves.P256).toParams(JsonWebKey.OutputControlLevel.PUBLIC_ONLY);
        Map<String, Object> full = ClientAttestationUtils.attestationContext(new ClientAttestationResult("client-1", cnf,
                ClientAttestationResult.Mode.DPOP, "https://attester.example.com", "jti-1", List.of(), List.of(),
                Map.of("spiffe_id", "spiffe://example.org/agent", "attested_by", "spiffe"), "agent-7", "f".repeat(64)));
        assertEquals("agent-7", full.get("agent_id"));
        assertEquals("https://attester.example.com", full.get("iss"));
        assertEquals("spiffe://example.org/agent", full.get("spiffe_id"));
        assertEquals("spiffe", full.get("attested_by"));
        assertTrue(full.get("cnf_thumbprint") instanceof String);

        Map<String, Object> bare = ClientAttestationUtils.attestationContext(new ClientAttestationResult("client-1",
                Map.of("kty", "EC"), ClientAttestationResult.Mode.POP_JWT, "  ", "jti-1", List.of(), List.of(),
                Map.of("region", "EMEA"), "  ", null));
        for (String absent : List.of("agent_id", "iss", "spiffe_id", "attested_by", "cnf_thumbprint", "rar_models_fingerprint")) {
            assertFalse(bare.containsKey(absent), absent + " in " + bare);
        }
        assertEquals(Map.of("region", "EMEA"), bare.get("workload"));

        Map<String, Object> none = ClientAttestationUtils.attestationContext(new ClientAttestationResult("client-1", cnf,
                ClientAttestationResult.Mode.POP_JWT, null, "jti-1", List.of(), List.of(), Map.of(), null, null));
        assertFalse(none.containsKey("workload") || none.containsKey("iss") || none.containsKey("agent_id"), none.toString());
    }

    @Test
    void aRefusalsLogLineCarriesTheModelsReasonAndNothingElseDoes() {
        RarModelException model = new RarModelException(RarModelException.Reason.UNDECLARED_FIELD,
                "candidate authorization_details[0] carries 'discount', which sales_agent does not declare");

        assertEquals(" (" + model.getMessage() + ")", ClientAttestationUtils.refusalDetail(new ClientAttestationException(
                ClientAttestationException.INVALID_AUTHORIZATION_DETAILS, "authorization_details carries a field its type does not define", model)));
        assertEquals("", ClientAttestationUtils.refusalDetail(ClientAttestationException.invalidClient("replay")));
        assertEquals("", ClientAttestationUtils.refusalDetail(ClientAttestationException.invalidClient("bad",
                new IllegalStateException("not the model's"))));
    }

    /**
     * The engine classloader has no start-up hook, so the criterion loads the models on its first call; when the
     * document cannot be read it refuses - before reading anything from the request - and says why.
     */
    @Test
    void aCriterionWhoseModelsCannotBeLoadedRefuses() throws Exception {
        rarModelsFrom(Map.of(RarModels.ENV_MODELS, "{\"types\":"));
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getAttribute(anyString())).thenReturn(null);
        Map<String, Object> in = new HashMap<>();
        AttributeValue requestValue = mock(AttributeValue.class);
        when(requestValue.getObjectValue()).thenReturn(request);
        in.put("context.HttpRequest", requestValue);
        List<String> logged = new java.util.ArrayList<>();
        Logger logger = Logger.getLogger(ClientAttestationUtils.class.getName());
        Handler capture = new Handler() {
            @Override
            public void publish(LogRecord record) {
                logged.add(record.getMessage());
            }

            @Override
            public void flush() {
            }

            @Override
            public void close() {
            }
        };
        logger.addHandler(capture);
        try {
            assertFalse(ClientAttestationUtils.validateClientAttestation(in, false, "https://ta.example.com"));
        } finally {
            logger.removeHandler(capture);
        }

        assertTrue(logged.stream().anyMatch(m -> m.contains("RAR containment models could not be loaded")), logged.toString());
        verify(request, never()).getHeaders(anyString());
    }
}
