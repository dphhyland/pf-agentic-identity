/*
 * Minimal SD-JWT (selective disclosure JWT) parsing + reconstruction for the optional SD-JWT attestation
 * encoding. Framework-agnostic; the caller verifies the issuer JWT signature (via JwtCodec) separately.
 */
package com.pingidentity.ps.oidf.common;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Parses an SD-JWT presentation ({@code issuer-jwt~disclosure~...~[kb-jwt]}) and reconstructs the disclosed
 * claim set, per <a href="https://datatracker.ietf.org/doc/draft-ietf-oauth-selective-disclosure-jwt/">SD-JWT</a>.
 * Only the pieces the attestation verifier needs are implemented: split, digest, and merge of disclosed object
 * properties ({@code _sd}) and array elements ({@code {"...": digest}}). Signature verification of the issuer
 * JWT and the Key-Binding JWT are the caller's responsibility.
 *
 * <p>Also exposes {@link #objectDisclosure}/{@link #arrayDisclosure}/{@link #digest} so an attester (or test)
 * can build an SD-JWT.
 */
public final class SdJwt {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final Base64.Encoder B64 = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder B64D = Base64.getUrlDecoder();
    private static final String ARRAY_PLACEHOLDER = "...";

    private SdJwt() {
    }

    /** Splits {@code issuer-jwt~disc~...~[kb-jwt]}; a trailing {@code ~} means no Key-Binding JWT. */
    public static Parsed parse(String presentation) {
        if (presentation == null || presentation.isBlank()) {
            throw new SdJwtException("empty SD-JWT presentation");
        }
        String[] parts = presentation.split("~", -1);
        String issuer = parts[0];
        String kb = parts.length > 1 ? parts[parts.length - 1] : "";
        List<String> disclosures = new ArrayList<>();
        for (int i = 1; i < parts.length - 1; i++) {
            if (!parts[i].isEmpty()) {
                disclosures.add(parts[i]);
            }
        }
        return new Parsed(issuer, disclosures, kb.isEmpty() ? null : kb);
    }

    /**
     * Reconstructs the disclosed claims from the issuer JWT payload and the presented disclosures. Removes
     * {@code _sd}/{@code _sd_alg}, merges each disclosed object property and array element, and drops
     * undisclosed ones. Rejects a presentation carrying a disclosure that matches no digest.
     */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> reconstruct(Map<String, Object> issuerPayload, List<String> disclosures) {
        String alg = issuerPayload.get("_sd_alg") instanceof String ? (String) issuerPayload.get("_sd_alg") : "sha-256";
        Map<String, List<Object>> byDigest = new HashMap<>();
        for (String d : disclosures) {
            byDigest.put(digest(d, alg), decodeDisclosure(d));
        }
        Set<String> used = new HashSet<>();
        Object out = process(issuerPayload, byDigest, used);
        if (used.size() != byDigest.size()) {
            throw new SdJwtException("one or more disclosures did not match a digest in the SD-JWT");
        }
        return (Map<String, Object>) out;
    }

    @SuppressWarnings("unchecked")
    private static Object process(Object node, Map<String, List<Object>> byDigest, Set<String> used) {
        if (node instanceof Map) {
            Map<String, Object> in = (Map<String, Object>) node;
            Map<String, Object> out = new LinkedHashMap<>();
            for (Map.Entry<String, Object> e : in.entrySet()) {
                if ("_sd".equals(e.getKey()) || "_sd_alg".equals(e.getKey())) {
                    continue;
                }
                out.put(e.getKey(), process(e.getValue(), byDigest, used));
            }
            if (in.get("_sd") instanceof List) {
                for (Object dg : (List<Object>) in.get("_sd")) {
                    List<Object> disc = byDigest.get(String.valueOf(dg));
                    if (disc != null && disc.size() == 3) {
                        used.add(String.valueOf(dg));
                        out.put(String.valueOf(disc.get(1)), process(disc.get(2), byDigest, used));
                    }
                }
            }
            return out;
        }
        if (node instanceof List) {
            List<Object> out = new ArrayList<>();
            for (Object elem : (List<Object>) node) {
                if (elem instanceof Map && ((Map<?, ?>) elem).size() == 1 && ((Map<?, ?>) elem).containsKey(ARRAY_PLACEHOLDER)) {
                    String dg = String.valueOf(((Map<?, ?>) elem).get(ARRAY_PLACEHOLDER));
                    List<Object> disc = byDigest.get(dg);
                    if (disc != null && disc.size() == 2) {
                        used.add(dg);
                        out.add(process(disc.get(1), byDigest, used));
                    }
                    // undisclosed array element → omitted
                } else {
                    out.add(process(elem, byDigest, used));
                }
            }
            return out;
        }
        return node;
    }

    /** {@code base64url(no-pad)} of the SHA-256 over the ASCII disclosure string. */
    public static String digest(String disclosureB64) {
        return digest(disclosureB64, "sha-256");
    }

    public static String digest(String disclosureB64, String alg) {
        String jca = "sha-256".equalsIgnoreCase(alg) ? "SHA-256" : alg;
        try {
            byte[] h = MessageDigest.getInstance(jca).digest(disclosureB64.getBytes(StandardCharsets.US_ASCII));
            return B64.encodeToString(h);
        } catch (NoSuchAlgorithmException e) {
            throw new SdJwtException("unsupported _sd_alg: " + alg);
        }
    }

    /** Builds a base64url object-property disclosure {@code [salt, name, value]}. */
    public static String objectDisclosure(String salt, String name, Object value) {
        return encode(List.of(salt, name, value));
    }

    /** Builds a base64url array-element disclosure {@code [salt, value]}. */
    public static String arrayDisclosure(String salt, Object value) {
        return encode(List.of(salt, value));
    }

    private static String encode(List<Object> disclosure) {
        try {
            return B64.encodeToString(MAPPER.writeValueAsBytes(disclosure));
        } catch (Exception e) {
            throw new SdJwtException("could not encode disclosure", e);
        }
    }

    @SuppressWarnings("unchecked")
    private static List<Object> decodeDisclosure(String disclosureB64) {
        try {
            return MAPPER.readValue(B64D.decode(disclosureB64), List.class);
        } catch (Exception e) {
            throw new SdJwtException("invalid disclosure encoding", e);
        }
    }

    /** Split parts of an SD-JWT presentation. */
    public static final class Parsed {
        private final String issuerJwt;
        private final List<String> disclosures;
        private final String kbJwt;

        Parsed(String issuerJwt, List<String> disclosures, String kbJwt) {
            this.issuerJwt = issuerJwt;
            this.disclosures = disclosures;
            this.kbJwt = kbJwt;
        }

        public String issuerJwt() {
            return issuerJwt;
        }

        public List<String> disclosures() {
            return disclosures;
        }

        /** The Key-Binding JWT (holder proof), or {@code null} when absent. */
        public String kbJwt() {
            return kbJwt;
        }
    }
}
