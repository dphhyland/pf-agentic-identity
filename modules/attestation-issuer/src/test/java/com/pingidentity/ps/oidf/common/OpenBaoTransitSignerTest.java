package com.pingidentity.ps.oidf.common;

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

    /** The resolver picks the transit signer when a key ref is set. */
    @Test
    void resolverSelectsTransitByKeyRef() throws Exception {
        try (FakeBaoServer bao = new FakeBaoServer(TOKEN)) {
            AttesterSigningKey resolver = new AttesterSigningKey(bao.url(), TOKEN);
            JwsSigner signer = resolver.signerFor(FakeBaoServer.KEY_NAME, null);
            assertTrue(signer instanceof OpenBaoTransitSigner);
        }
    }

    /** The resolver picks the local signer when an inline JWK is set. */
    @Test
    void resolverSelectsLocalByInlineJwk() throws Exception {
        PublicJsonWebKey attester = TestJwts.ec("att-1");
        AttesterSigningKey resolver = new AttesterSigningKey(null, null);
        JwsSigner signer = resolver.signerFor(null, TestJwts.privateParams(attester));
        assertTrue(signer instanceof LocalJwkSigner);
        assertEquals("ES256", signer.algorithm());
    }

    @Test
    void resolverRejectsNeitherOrBoth() throws Exception {
        AttesterSigningKey resolver = new AttesterSigningKey("http://bao", "t");
        IssuanceException neither = assertThrows(IssuanceException.class, () -> resolver.signerFor(null, null));
        assertEquals("invalid_client", neither.error());
        IssuanceException both = assertThrows(IssuanceException.class,
                () -> resolver.signerFor("k", TestJwts.privateParams(TestJwts.ec("x"))));
        assertEquals("invalid_client", both.error());
    }

    @Test
    void resolverRejectsTransitWithoutVaultConfigured() {
        AttesterSigningKey resolver = new AttesterSigningKey(null, null);
        IssuanceException e = assertThrows(IssuanceException.class, () -> resolver.signerFor("some-key", null));
        assertEquals("server_error", e.error());
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
