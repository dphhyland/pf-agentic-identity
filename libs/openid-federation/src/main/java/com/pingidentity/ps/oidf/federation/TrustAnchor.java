package com.pingidentity.ps.oidf.federation;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.function.Supplier;
import org.jose4j.json.JsonUtil;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.lang.JoseException;
import com.pingidentity.ps.oidf.jose.Claims;
import com.pingidentity.ps.oidf.jose.Jwks;
import com.pingidentity.ps.oidf.jose.JwtCodec;
import com.pingidentity.ps.oidf.jose.VerificationPolicy;

/**
 * A Trust Anchor as this validator knows it: an entity identifier and the Federation Entity Keys the
 * operator configured for it, out of band.
 *
 * <p>OpenID Federation 1.0 §2.1 is explicit that the federation's trust mechanism does not rely on Web
 * PKI / TLS for signing keys, and §4 says the Trust Anchor's public keys are distributed "in some
 * secure out-of-band way". Until
 * this class existed, the validator fetched the anchor's Entity Configuration over HTTPS and believed
 * whatever {@code jwks} it found there, so "the anchor" was whoever answered at that URL — a hosting
 * compromise, a mis-issued certificate or an egress proxy could each stand in for it. Every
 * statement the anchor issues (§4: its Subordinate Statement about the entity below it, and its own
 * Entity Configuration) is now verified against these keys and nothing fetched.
 *
 * <p>Only public keys are accepted. An operator who pastes the anchor's private JWK here has leaked
 * it into every consumer's configuration, and a symmetric key can sign nothing anyone else can
 * verify — both are refused rather than quietly working.
 *
 * <p>Key rollover at the anchor is an out-of-band event (§11.2): the configured set is replaced, not
 * refreshed from the network. A statement signed by a key not in the set is rejected until the
 * configuration is updated, which is the intended failure.
 */
public final class TrustAnchor {
    private final String entityId;
    private final List<JsonWebKey> keys;
    private final Supplier<Map<String, Object>> liveKeys;

    private TrustAnchor(String entityId, List<JsonWebKey> keys) {
        this.entityId = entityId;
        this.keys = List.copyOf(keys);
        this.liveKeys = null;
    }

    private TrustAnchor(String entityId, Supplier<Map<String, Object>> liveKeys) {
        this.entityId = entityId;
        this.keys = List.of();
        this.liveKeys = liveKeys;
    }

    /**
     * An anchor whose keys are read from {@code jwks} every time they are needed - for this deployment's
     * <em>own</em> identity when it is also a Trust Anchor (for the entities it hosts). Its keys are the
     * ones it signs with, which rotate with its signing key store; pinning a copy in configuration would
     * go stale at the first rotation. Every read goes through the same rules as {@link #of}: public keys,
     * unique {@code kid}s, at least one key.
     */
    public static TrustAnchor live(String entityId, Supplier<Map<String, Object>> jwks) {
        Claims.requireNonBlank(entityId, "trust anchor entity id");
        return new TrustAnchor(entityId, Objects.requireNonNull(jwks, "jwks"));
    }

    /**
     * @param entityId the anchor's entity identifier, as it appears in {@code iss} of the statements it
     *                 issues and in leaf {@code authority_hints}
     * @param jwksJson the anchor's Federation Entity Keys as a JWK Set document ({@code {"keys":[...]}}),
     *                 public keys only — typically the {@code jwks} claim of its Entity Configuration,
     *                 captured once at provisioning time from a position the operator trusts
     * @throws IllegalArgumentException when the document is absent, is not JSON, or holds no usable key
     */
    public static TrustAnchor parse(String entityId, String jwksJson) {
        if (jwksJson == null || jwksJson.isBlank()) {
            throw new IllegalArgumentException("Trust anchor " + entityId + " has no configured JWKS: its Federation "
                    + "Entity Keys must be supplied out of band (OpenID Federation 1.0 §4), not fetched");
        }
        Map<String, Object> jwks;
        try {
            jwks = JsonUtil.parseJson(jwksJson);
        } catch (JoseException e) {
            throw new IllegalArgumentException("Trust anchor " + entityId + " JWKS is not a JSON object: " + e.getMessage(), e);
        }
        return of(entityId, jwks);
    }

    /**
     * @param jwks the anchor's Federation Entity Keys as a parsed JWK Set ({@code keys} → list of JWK
     *             objects), public keys only
     * @throws IllegalArgumentException when the set holds no key, an entry is not a JWK object, a key is
     *                                  symmetric or carries private material, or a key does not parse
     */
    public static TrustAnchor of(String entityId, Map<String, Object> jwks) {
        Claims.requireNonBlank(entityId, "trust anchor entity id");
        Object rawKeys = jwks == null ? null : jwks.get("keys");
        if (!(rawKeys instanceof List) || ((List<?>) rawKeys).isEmpty()) {
            throw new IllegalArgumentException("Trust anchor " + entityId + " JWKS carries no keys: expected "
                    + "{\"keys\":[...]} holding the anchor's public Federation Entity Keys");
        }
        ArrayList<JsonWebKey> keys = new ArrayList<JsonWebKey>();
        java.util.HashSet<String> kids = new java.util.HashSet<String>();
        for (Object raw : (List<?>) rawKeys) {
            if (!(raw instanceof Map)) {
                throw new IllegalArgumentException("Trust anchor " + entityId + " JWKS entry is not a JWK object: " + raw);
            }
            @SuppressWarnings("unchecked")
            Map<String, Object> jwk = (Map<String, Object>) raw;
            // §3.1.1: every JWK in a Federation Entity Key set MUST have a unique kid. The kid in a
            // statement's header is how a verifier picks the key, so an absent or repeated one makes
            // that choice ambiguous.
            Object kid = jwk.get("kid");
            if (!(kid instanceof String) || ((String) kid).isBlank() || !kids.add((String) kid)) {
                throw new IllegalArgumentException("Trust anchor " + entityId + " JWKS key has a missing or duplicate kid (" + kid
                        + "): every key needs a unique one (OpenID Federation 1.0 §3.1.1)");
            }
            try {
                Jwks.assertPublicOnly(jwk);
                keys.add(Jwks.fromMap(jwk));
            } catch (JoseException | IllegalArgumentException e) {
                throw new IllegalArgumentException("Trust anchor " + entityId + " JWKS key " + jwk.get("kid")
                        + " is not usable: " + e.getMessage(), e);
            }
        }
        return new TrustAnchor(entityId, keys);
    }

    public String entityId() {
        return this.entityId;
    }

    /** The configured public keys, in configuration order (for a {@link #live} anchor, as read now). */
    public List<JsonWebKey> keys() {
        if (this.liveKeys == null) {
            return this.keys;
        }
        return of(this.entityId, this.liveKeys.get()).keys;
    }

    /** True for an anchor built by {@link #live}. */
    public boolean isLive() {
        return this.liveKeys != null;
    }

    /**
     * Verifies a statement this anchor issued — its Subordinate Statement about the entity below it,
     * or its own Entity Configuration — against the configured keys and nothing else. {@code iss} must
     * be this anchor's identifier.
     *
     * @throws Exception when the signature does not verify against any configured key, the issuer is
     *                   not this anchor, the algorithm is not accepted, or the statement is expired or
     *                   malformed
     */
    public JwtClaims verify(String jwt, Set<String> acceptedSigningAlgorithms) throws Exception {
        return JwtCodec.verifyAgainstKeys(jwt, this.keys(), this.entityId, acceptedSigningAlgorithms);
    }

    /** As {@link #verify(String, Set)}, under the given verification policy (kid, iat, typ, clock). */
    public JwtClaims verify(String jwt, Set<String> acceptedSigningAlgorithms, VerificationPolicy policy) throws Exception {
        return JwtCodec.verifyAgainstKeys(jwt, this.keys(), this.entityId, acceptedSigningAlgorithms, policy);
    }

    @Override
    public String toString() {
        if (this.liveKeys != null) {
            return "TrustAnchor[" + this.entityId + ", live keys]";
        }
        ArrayList<String> kids = new ArrayList<String>(this.keys.size());
        for (JsonWebKey key : this.keys) {
            kids.add(key.getKeyId());
        }
        return "TrustAnchor[" + this.entityId + ", kids=" + kids + "]";
    }
}
