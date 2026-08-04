/*
 * Assembles a compact JWS from a JwsSigner, which produces only the raw signature bytes.
 */
package com.pingidentity.ps.oidf.common;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;
import org.jose4j.json.JsonUtil;

/**
 * {@link JwsSigner} deliberately produces only the raw JWS signature bytes over a signing input it is
 * handed — it knows nothing about JSON, headers or claims, which is what lets the same interface cover
 * an in-process key and a vault transit engine identically. This does the JOSE-layer assembly: encode
 * header and payload, hand the signing input to the signer, and concatenate the result into a compact
 * serialization.
 */
public final class CompactJws {

    private CompactJws() {
    }

    /** Signs {@code header} and {@code payload} with {@code signer}, returning the compact JWS. */
    public static String sign(Map<String, Object> header, Map<String, Object> payload, JwsSigner signer) {
        Base64.Encoder b64 = Base64.getUrlEncoder().withoutPadding();
        String encodedHeader = b64.encodeToString(JsonUtil.toJson(header).getBytes(StandardCharsets.UTF_8));
        String encodedPayload = b64.encodeToString(JsonUtil.toJson(payload).getBytes(StandardCharsets.UTF_8));
        String signingInput = encodedHeader + "." + encodedPayload;
        byte[] signature = signer.sign(signingInput.getBytes(StandardCharsets.US_ASCII));
        return signingInput + "." + b64.encodeToString(signature);
    }
}
