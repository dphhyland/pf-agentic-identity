/*
 * Validation of the Entity Configuration a SELF_SIGNED hosted entity publishes through its authority.
 */
package com.pingidentity.ps.oidf.authority;

import java.time.Instant;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.jose4j.json.JsonUtil;
import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.JsonWebKeySet;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;

/**
 * A self-signed hosted entity holds its own Federation Entity Key - on a laptop, in a Secure Enclave or on
 * a YubiKey - and signs its own Entity Configuration with it. The authority cannot forge that configuration;
 * it only serves it at {@code <entityId>/.well-known/openid-federation} (the entity has no public URL of its
 * own) and vouches for the entity's key in the Subordinate Statement it issues.
 *
 * <p>So the authority accepts a configuration only if it is exactly what the rest of the chain will check:
 * OpenID Federation 1.0 §3 shape, signed by a key the authority registered for this entity, publishing no
 * key the authority did not register (else the Entity Configuration and the Subordinate Statement would
 * disagree about the entity's keys), naming the authority as a superior, and short-lived enough that a key
 * change or a revocation cannot be outlived by a stale copy.
 *
 * <p>The signature is the authorisation to publish: only the key holder can produce a configuration that
 * passes, so this path needs no bearer token.
 */
public final class SelfSignedEntityConfigurations {

    static final String TYP = "entity-statement+jwt";
    /** OpenID Federation signing algorithms this authority will serve (never {@code none}, never HMAC). */
    static final Set<String> ALGORITHMS = Set.of("ES256", "ES384", "ES512", "PS256", "RS256", "EdDSA");
    /** Seven days: the entity re-publishes well before; the authority never serves an expired copy. */
    public static final long MAX_LIFETIME_SECONDS = 7L * 24 * 3600;
    private static final long CLOCK_SKEW_SECONDS = 60L;
    private static final List<String> SUBORDINATE_ONLY_CLAIMS =
            List.of("metadata_policy", "metadata_policy_crit", "constraints", "source_endpoint");
    private static final List<String> TRUST_ANCHOR_ONLY_CLAIMS = List.of("trust_mark_issuers", "trust_mark_owners");

    private SelfSignedEntityConfigurations() {
    }

    /** Thrown when a submitted configuration must not be served; the message says why. */
    public static final class InvalidConfigurationException extends Exception {
        private static final long serialVersionUID = 1L;

        InvalidConfigurationException(String message) {
            super(message);
        }
    }

    /** Validates {@code jwt} for {@code entity} and returns it, trimmed, ready to store and serve verbatim. */
    public static String validate(String jwt, HostedEntity entity, String authorityEntityId, Instant now)
            throws InvalidConfigurationException {
        if (entity.hostingMode() != HostingMode.SELF_SIGNED) {
            throw new InvalidConfigurationException("only a self-signed entity publishes its own Entity Configuration");
        }
        String compact = jwt == null ? "" : jwt.trim();
        JsonWebSignature jws = new JsonWebSignature();
        JwtClaims claims;
        try {
            jws.setCompactSerialization(compact);
            if (!TYP.equals(jws.getHeader("typ"))) {
                throw new InvalidConfigurationException("typ must be " + TYP);
            }
            String alg = jws.getAlgorithmHeaderValue();
            if (alg == null || !ALGORITHMS.contains(alg)) {
                throw new InvalidConfigurationException("alg " + alg + " is not accepted");
            }
            String kid = jws.getKeyIdHeaderValue();
            if (kid == null || kid.isBlank()) {
                throw new InvalidConfigurationException("the header must name the signing key (kid)");
            }
            List<JsonWebKey> registered = registeredKeys(entity);
            JsonWebKey signingKey = registered.stream().filter(k -> kid.equals(k.getKeyId())).findFirst()
                    .orElseThrow(() -> new InvalidConfigurationException(
                            "signed by a key the authority did not register for this entity (kid " + kid + ")"));
            jws.setKey(((PublicJsonWebKey) signingKey).getPublicKey());
            jws.setAlgorithmConstraints(new AlgorithmConstraints(AlgorithmConstraints.ConstraintType.PERMIT, alg));
            if (!jws.verifySignature()) {
                throw new InvalidConfigurationException("the signature does not verify under the registered federation key");
            }
            claims = JwtClaims.parse(jws.getPayload());
        } catch (InvalidConfigurationException e) {
            throw e;
        } catch (Exception e) {
            throw new InvalidConfigurationException("not a well-formed signed Entity Configuration: " + e.getMessage());
        }

        try {
            if (!entity.entityId().equals(claims.getIssuer()) || !entity.entityId().equals(claims.getSubject())) {
                throw new InvalidConfigurationException("iss and sub must both be " + entity.entityId());
            }
            if (claims.getIssuedAt() == null || claims.getExpirationTime() == null) {
                throw new InvalidConfigurationException("iat and exp are required");
            }
            long iat = claims.getIssuedAt().getValue();
            long exp = claims.getExpirationTime().getValue();
            if (iat > now.getEpochSecond() + CLOCK_SKEW_SECONDS) {
                throw new InvalidConfigurationException("iat is in the future");
            }
            if (exp <= now.getEpochSecond()) {
                throw new InvalidConfigurationException("the configuration has already expired");
            }
            if (exp - iat > MAX_LIFETIME_SECONDS) {
                throw new InvalidConfigurationException("lifetime exceeds " + MAX_LIFETIME_SECONDS + " seconds");
            }
            Object jwks = claims.getClaimValue("jwks");
            if (!(jwks instanceof Map)) {
                throw new InvalidConfigurationException("the jwks claim is required");
            }
            Set<String> registeredThumbprints = new HashSet<>();
            for (JsonWebKey k : registeredKeys(entity)) {
                registeredThumbprints.add(k.calculateBase64urlEncodedThumbprint("SHA-256"));
            }
            List<JsonWebKey> published = new JsonWebKeySet(JsonUtil.toJson(castMap(jwks))).getJsonWebKeys();
            if (published.isEmpty()) {
                throw new InvalidConfigurationException("jwks must not be empty");
            }
            for (JsonWebKey k : published) {
                if (!registeredThumbprints.contains(k.calculateBase64urlEncodedThumbprint("SHA-256"))) {
                    throw new InvalidConfigurationException(
                            "jwks publishes a key the authority did not register for this entity");
                }
            }
            Object hints = claims.getClaimValue("authority_hints");
            if (!(hints instanceof List) || !((List<?>) hints).contains(authorityEntityId)) {
                throw new InvalidConfigurationException("authority_hints must name " + authorityEntityId);
            }
            for (String claim : SUBORDINATE_ONLY_CLAIMS) {
                if (claims.hasClaim(claim)) {
                    throw new InvalidConfigurationException(claim + " MUST NOT appear in an Entity Configuration");
                }
            }
            for (String claim : TRUST_ANCHOR_ONLY_CLAIMS) {
                if (claims.hasClaim(claim)) {
                    throw new InvalidConfigurationException(claim + " belongs to a Trust Anchor's configuration");
                }
            }
        } catch (InvalidConfigurationException e) {
            throw e;
        } catch (Exception e) {
            throw new InvalidConfigurationException("the configuration's claims are malformed: " + e.getMessage());
        }
        return compact;
    }

    /** {@code exp} of a stored configuration, for serving: an expired copy is never served. */
    public static boolean expired(String jwt, Instant now) {
        try {
            JsonWebSignature jws = new JsonWebSignature();
            jws.setCompactSerialization(jwt);
            return JwtClaims.parse(jws.getUnverifiedPayload()).getExpirationTime().getValue() <= now.getEpochSecond();
        } catch (Exception e) {
            return true;
        }
    }

    static List<JsonWebKey> registeredKeys(HostedEntity entity) throws InvalidConfigurationException {
        try {
            return new ArrayList<>(new JsonWebKeySet(JsonUtil.toJson(entity.federationJwks())).getJsonWebKeys());
        } catch (Exception e) {
            throw new InvalidConfigurationException("the entity's registered federation keys are unreadable");
        }
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> castMap(Object o) {
        return (Map<String, Object>) o;
    }
}
