package com.pingidentity.ps.oidf.jose;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import org.jose4j.jwk.EcJwkGenerator;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.json.JsonUtil;
import org.jose4j.keys.EllipticCurves;
import org.junit.jupiter.api.Test;

class CompactJwsTest {

    @Test
    void assembledJwsVerifiesUnderTheSignersPublicKey() throws Exception {
        PublicJsonWebKey key = EcJwkGenerator.generateJwk(EllipticCurves.P256);
        key.setKeyId("k1");
        LocalJwkSigner signer = new LocalJwkSigner(key.toParams(JsonWebKey.OutputControlLevel.INCLUDE_PRIVATE));

        Map<String, Object> header = new LinkedHashMap<>();
        header.put("alg", signer.algorithm());
        header.put("typ", "test+jwt");
        header.put("kid", signer.keyId());
        Map<String, Object> payload = Map.of("iss", "https://issuer.example.com", "sub", "https://issuer.example.com");

        String compact = CompactJws.sign(header, payload, signer);

        JsonWebSignature jws = new JsonWebSignature();
        jws.setCompactSerialization(compact);
        jws.setKey(((PublicJsonWebKey) JsonWebKey.Factory.newJwk(signer.publicJwk())).getPublicKey());
        assertTrue(jws.verifySignature());
        assertEquals("test+jwt", jws.getHeaders().getStringHeaderValue("typ"));
    }

    @Test
    void headerAndPayloadEncodeAsIndependentBase64UrlSegments() throws Exception {
        Map<String, Object> header = Map.of("alg", "none");
        Map<String, Object> payload = Map.of("sub", "x");
        JwsSigner noopSigner = new JwsSigner() {
            @Override public String algorithm() {
                return "none";
            }
            @Override public String keyId() {
                return "noop";
            }
            @Override public Map<String, Object> publicJwk() {
                return Map.of();
            }
            @Override public byte[] sign(byte[] signingInput) {
                return new byte[0];
            }
        };
        String compact = CompactJws.sign(header, payload, noopSigner);
        String[] parts = compact.split("\\.", -1);
        assertEquals(3, parts.length);
        Map<String, Object> decodedHeader = JsonUtil.parseJson(
                new String(Base64.getUrlDecoder().decode(parts[0]), StandardCharsets.UTF_8));
        assertEquals("none", decodedHeader.get("alg"));
    }
}
