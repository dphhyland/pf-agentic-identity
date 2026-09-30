/*
 * The claims of a JWT read before - or without - checking its signature.
 */
package com.pingidentity.ps.oidf.jose;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import org.jose4j.jwt.JwtClaims;

/**
 * The claims of a JWT whose signature nobody has checked: what {@link JwtCodec#parseUnverifiedClaims} returns.
 *
 * <p>Anyone can write any claim into a JWT they send, so a value read here is what the sender says, nothing more.
 * RFC 8725 §3.1 and §3.2 (JWT BCP) require the algorithm and the key to be the verifier's choice; this type is the
 * other half of that rule, for the claims: a value read before the signature is checked may choose <em>where to
 * look</em> - which key set, which registration, which statement - and then the verified value is compared with it,
 * or it may be logged; it never decides anything by itself. The oidf-jose README ("Reading a JWT before its signature
 * is checked") lists every call site and which of those it is.
 *
 * <p>The type is not a {@link JwtClaims} and hands none out, so it cannot be passed where verified claims are
 * expected: every accessor says {@code unverified} in its name, and the verifiers ({@link JwtCodec#verifyAgainstKeys},
 * {@link JwtCodec#verifySignature}, {@link JwtCodec#verifyAttestationPop}) are the only way to a {@code JwtClaims}.
 * Its {@link #toString()} carries no claim, so a log line that prints one prints nothing the sender wrote.
 */
public final class UnverifiedClaims {

    private final JwtClaims claims;

    UnverifiedClaims(JwtClaims claims) {
        this.claims = Objects.requireNonNull(claims, "claims");
    }

    /** The {@code iss} claim as the sender wrote it, or null when absent or not a string. */
    public String unverifiedIssuer() {
        return this.unverifiedString("iss");
    }

    /** The {@code sub} claim as the sender wrote it, or null when absent or not a string. */
    public String unverifiedSubject() {
        return this.unverifiedString("sub");
    }

    /** The named claim when it is a string, else null. */
    public String unverifiedString(String name) {
        return this.claims.getClaimValue(name) instanceof String s ? s : null;
    }

    /** The named claim's raw value (a String, Number, Boolean, List or Map), or null when absent. */
    public Object unverifiedClaim(String name) {
        return this.claims.getClaimValue(name);
    }

    /** Whether the sender wrote the named claim at all. */
    public boolean hasUnverifiedClaim(String name) {
        return this.claims.hasClaim(name);
    }

    /** The named claim as whole seconds when it is a JSON number, else null ({@code exp}, {@code iat}, {@code nbf}). */
    public Long unverifiedNumericDate(String name) {
        return this.claims.getClaimValue(name) instanceof Number n ? n.longValue() : null;
    }

    /** The named claim when it is a JSON object, else an empty map; never null. */
    @SuppressWarnings("unchecked")
    public Map<String, Object> unverifiedMap(String name) {
        return this.claims.getClaimValue(name) instanceof Map<?, ?> map ? (Map<String, Object>) map : Map.of();
    }

    /** The named claim's items as strings when it is a JSON array, else an empty list; never null. */
    public List<String> unverifiedStringList(String name) {
        if (!(this.claims.getClaimValue(name) instanceof List<?> list)) {
            return List.of();
        }
        List<String> result = new ArrayList<>(list.size());
        for (Object item : list) {
            result.add(String.valueOf(item));
        }
        return result;
    }

    /** Every claim, as a copy: for a syntax check that walks them all before any signature is looked at. */
    public Map<String, Object> unverifiedClaimsMap() {
        return new LinkedHashMap<>(this.claims.getClaimsMap());
    }

    /** Names no claim: a log line that prints this prints nothing the sender wrote. */
    @Override
    public String toString() {
        return "UnverifiedClaims[" + this.claims.getClaimNames().size() + " claims, signature not checked]";
    }
}
