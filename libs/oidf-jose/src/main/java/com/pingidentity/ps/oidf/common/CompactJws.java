/*
 * Assembles a compact JWS from a header + payload and a JwsSigner (which produces only raw signature bytes).
 */
package com.pingidentity.ps.oidf.common;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import org.jose4j.json.JsonUtil;

/**
 * Builds {@code BASE64URL(header).BASE64URL(payload).BASE64URL(signature)} over a {@link JwsSigner}.
 *
 * <p>{@link JwsSigner} deliberately produces only the raw JWS signature bytes over a signing input it is
 * handed — it knows nothing about JSON, headers or claims, which is what lets the same interface cover an
 * in-process key and a vault transit engine identically. This class does the JOSE-layer assembly so the
 * several attestation minters in this codebase share one path rather than each re-deriving it. The signing
 * input must be the exact bytes the header and payload serialise to — re-serialising either after signing
 * changes the signature — so the encoded parts are computed once here and never rebuilt.
 *
 * <p>The header carries {@code alg}, {@code typ} and the signer's {@code kid}. Issuing keys are referenced
 * by id, never embedded: a verifier resolves the key through a trust path (a federation chain, a pinned
 * JWKS), not from the token asserting its own key.
 */
public final class CompactJws {

    private static final Base64.Encoder B64 = Base64.getUrlEncoder().withoutPadding();

    private CompactJws() {
    }

    /**
     * Signs {@code payloadJson} with {@code typ} in the header (the header's {@code alg}/{@code kid} come
     * from the signer).
     *
     * @param typ         the media type, e.g. {@code oauth-client-attestation+jwt}
     * @param payloadJson the serialised claims — used verbatim, not reparsed
     * @param signer      supplies {@code alg}, {@code kid} and the signature
     */
    public static String sign(String typ, String payloadJson, JwsSigner signer) {
        Map<String, Object> header = new LinkedHashMap<>();
        header.put("alg", signer.algorithm());
        header.put("typ", typ);
        header.put("kid", signer.keyId());
        return sign(header, payloadJson, signer);
    }

    /** As {@link #sign(String, String, JwsSigner)}, with a caller-built header and a pre-serialised payload. */
    public static String sign(Map<String, Object> header, String payloadJson, JwsSigner signer) {
        String signingInput = B64.encodeToString(JsonUtil.toJson(header).getBytes(StandardCharsets.UTF_8))
                + "." + B64.encodeToString(payloadJson.getBytes(StandardCharsets.UTF_8));
        byte[] signature = signer.sign(signingInput.getBytes(StandardCharsets.US_ASCII));
        return signingInput + "." + B64.encodeToString(signature);
    }

    /** As {@link #sign(Map, String, JwsSigner)}, serialising {@code payload} to JSON first. */
    public static String sign(Map<String, Object> header, Map<String, Object> payload, JwsSigner signer) {
        return sign(header, JsonUtil.toJson(payload), signer);
    }
}
