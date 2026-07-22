/*
 * JWK helpers for attestation-based client authentication.
 */
package com.pingidentity.ps.oidf.common;

import java.security.Key;
import java.util.Map;
import java.util.Set;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.lang.JoseException;

/**
 * Small helpers for working with JWKs that are exchanged as JSON objects (RFC 7800 {@code cnf}
 * claims and RFC 9449 DPoP {@code jwk} headers): building a {@link JsonWebKey} from a parsed map,
 * computing RFC 7638 thumbprints, asserting two keys are the same key, and asserting that a key
 * carries no private material.
 */
public final class Jwks {
    /** JWK members that indicate the presence of private key material (RSA/EC/OKP {@code d}, RSA CRT params, symmetric {@code k}). */
    private static final Set<String> PRIVATE_MEMBERS = Set.of("d", "p", "q", "dp", "dq", "qi", "k");

    private Jwks() {
    }

    public static JsonWebKey fromMap(Map<String, Object> jwk) throws JoseException {
        if (jwk == null || jwk.isEmpty()) {
            throw new IllegalArgumentException("jwk is missing or empty");
        }
        return JsonWebKey.Factory.newJwk(jwk);
    }

    /** RFC 7638 JWK SHA-256 thumbprint, base64url-encoded. */
    public static String thumbprint(JsonWebKey jwk) throws JoseException {
        return jwk.calculateBase64urlEncodedThumbprint("SHA-256");
    }

    public static String thumbprint(Map<String, Object> jwk) throws JoseException {
        return thumbprint(Jwks.fromMap(jwk));
    }

    /**
     * Asserts that {@code other} is the same key as the supplied {@code cnf} JWK by comparing RFC 7638
     * thumbprints. Used to bind a DPoP proof key (or any presented key) to the attestation {@code cnf}.
     */
    public static void assertSameKey(Map<String, Object> cnfJwk, JsonWebKey other) throws JoseException {
        if (other == null) {
            throw new IllegalArgumentException("Presented key is missing");
        }
        String expected = Jwks.thumbprint(Jwks.fromMap(cnfJwk));
        String actual = Jwks.thumbprint(other);
        if (!expected.equals(actual)) {
            throw new IllegalArgumentException("Proof-of-possession key does not match the attestation cnf key");
        }
    }

    /**
     * Rejects symmetric keys and any key that carries private material. A {@code cnf} key, a PoP signing
     * key and a DPoP {@code jwk} header MUST all be asymmetric public keys; receiving a private key is a
     * sign of a malformed or malicious request.
     */
    public static void assertPublicOnly(Map<String, Object> jwk) {
        if (jwk == null || jwk.isEmpty()) {
            throw new IllegalArgumentException("jwk is missing or empty");
        }
        if ("oct".equals(jwk.get("kty"))) {
            throw new IllegalArgumentException("Symmetric (oct) keys are not allowed for proof of possession");
        }
        for (String member : PRIVATE_MEMBERS) {
            if (jwk.containsKey(member)) {
                throw new IllegalArgumentException("Key must not contain private key material (found member '" + member + "')");
            }
        }
    }

    /** Returns the {@link Key} (public) for an asymmetric JWK map, rejecting symmetric keys. */
    public static Key publicKey(Map<String, Object> jwk) throws JoseException {
        JsonWebKey parsed = Jwks.fromMap(jwk);
        if (!(parsed instanceof PublicJsonWebKey)) {
            throw new IllegalArgumentException("Expected an asymmetric (public) JWK but got kty=" + parsed.getKeyType());
        }
        return ((PublicJsonWebKey) parsed).getPublicKey();
    }
}
