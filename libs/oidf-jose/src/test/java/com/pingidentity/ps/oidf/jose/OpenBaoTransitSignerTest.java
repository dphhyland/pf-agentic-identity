package com.pingidentity.ps.oidf.jose;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.json.JsonUtil;
import org.jose4j.jws.JsonWebSignature;
import org.junit.jupiter.api.Test;

/**
 * {@link OpenBaoTransitSigner} tested in isolation, against an in-process fake of the vault's transit
 * API. The {@code AttesterSigningKey} resolver that chooses between this and {@link LocalJwkSigner}
 * per-client is an issuance-specific concern and stays tested in {@code servlets/attestation-issuer}
 * (its own {@code AttesterSigningKeyTest}, against its own copy of {@link FakeBaoServer} — this
 * codebase's established pattern for a small, self-contained test double needed by more than one
 * module, matching how {@code TestJwts} is deliberately duplicated rather than shared).
 */
class OpenBaoTransitSignerTest {

    private static final String TOKEN = "test-token";

    /** A compact JWS assembled from a JwsSigner must verify under the signer's advertised public JWK. */
    @Test
    void transitSignatureVerifies() throws Exception {
        try (FakeBaoServer bao = new FakeBaoServer(TOKEN)) {
            OpenBaoTransitSigner signer = new OpenBaoTransitSigner(bao.url(), TOKEN, FakeBaoServer.KEY_NAME);
            assertEquals("ES256", signer.algorithm());
            assertNotNull(signer.keyId());
            assertEquals("EC", signer.publicJwk().get("kty"));

            String compact = compactJws(signer, "{\"hello\":\"world\"}");
            assertTrue(verify(compact, signer.publicJwk()));
        }
    }

    /** Fail-closed: an unreachable vault surfaces as an error, not a silent unsigned result. */
    @Test
    void failsClosedWhenVaultUnreachable() throws Exception {
        FakeBaoServer bao = new FakeBaoServer(TOKEN);
        String url = bao.url();
        bao.close();
        assertThrows(RuntimeException.class, () -> new OpenBaoTransitSigner(url, TOKEN, FakeBaoServer.KEY_NAME));
    }

    // ---- helpers ----

    private static String compactJws(JwsSigner signer, String payloadJson) {
        Map<String, Object> header = new LinkedHashMap<>();
        header.put("alg", signer.algorithm());
        header.put("typ", "test+jwt");
        header.put("kid", signer.keyId());
        Base64.Encoder b64 = Base64.getUrlEncoder().withoutPadding();
        String signingInput = b64.encodeToString(JsonUtil.toJson(header).getBytes(StandardCharsets.UTF_8))
                + "." + b64.encodeToString(payloadJson.getBytes(StandardCharsets.UTF_8));
        byte[] sig = signer.sign(signingInput.getBytes(StandardCharsets.US_ASCII));
        return signingInput + "." + b64.encodeToString(sig);
    }

    private static boolean verify(String compact, Map<String, Object> publicJwk) throws Exception {
        JsonWebSignature jws = new JsonWebSignature();
        jws.setCompactSerialization(compact);
        jws.setKey(((PublicJsonWebKey) JsonWebKey.Factory.newJwk(publicJwk)).getPublicKey());
        return jws.verifySignature();
    }
}
