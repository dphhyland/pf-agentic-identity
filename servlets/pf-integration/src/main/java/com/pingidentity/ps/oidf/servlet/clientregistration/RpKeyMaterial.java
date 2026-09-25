/*
 * The keys an RP publishes for openid_relying_party.
 */
package com.pingidentity.ps.oidf.servlet.clientregistration;

import com.pingidentity.ps.oidf.federation.EntityId;
import com.pingidentity.ps.oidf.jose.HttpGetClient;
import com.pingidentity.ps.oidf.jose.Jwks;
import com.pingidentity.ps.oidf.jose.JwtCodec;
import com.pingidentity.ps.oidf.jose.JwtVerificationException;
import java.net.URI;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import org.jose4j.json.JsonUtil;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwt.JwtClaims;

/**
 * The keys an RP publishes for the {@code openid_relying_party} Entity Type (OpenID Federation 1.0 §5.2.1) - the
 * keys §12.1.1.1.2 says a request object is verified with, and so the ones its client is registered with. They
 * are distinct from its Federation Entity Keys, which sign its Entity Statements.
 *
 * <p>In order: {@code jwks} by value; else {@code signed_jwks_uri}, a {@code jwk-set+jwt} signed with a Federation
 * Entity Key, fetched and verified (and registered as the snapshot it verified); else {@code jwks_uri}, fetched to
 * verify the request in hand and registered by reference so PingFederate follows the RP's rotations. An RP that
 * publishes none of them has no keys to register.
 */
final class RpKeyMaterial {
    private static final String SIGNED_JWKS_TYP = "jwk-set+jwt";

    /**
     * The keys, and how the client carries them: {@code jwks} (a JWK Set, as JSON) or {@code jwksUri}, one of them.
     *
     * @param verificationKeys the keys a signature from the RP may be checked with - its signing keys
     * @param source           which metadata parameter they came from
     */
    record Keys(List<JsonWebKey> verificationKeys, String jwks, String jwksUri, String source) {
    }

    /** How long a registered client's jwks_uri answer is used, so a stream of requests in its name costs one fetch. */
    static final long REGISTERED_KEYS_SECONDS = 60L;
    private static final int REGISTERED_KEYS_KEPT = 256;

    private record Fetched(List<JsonWebKey> keys, long at) {
    }

    private final HttpGetClient http;
    private final java.time.Clock clock;
    private final Map<String, Fetched> fetched = java.util.Collections.synchronizedMap(new java.util.LinkedHashMap<>(16, 0.75f, true) {
        @Override
        protected boolean removeEldestEntry(Map.Entry<String, Fetched> eldest) {
            return this.size() > REGISTERED_KEYS_KEPT;
        }
    });

    RpKeyMaterial(HttpGetClient http, java.time.Clock clock) {
        this.http = Objects.requireNonNull(http, "http");
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    /**
     * @param rpMetadata     the RP's resolved {@code openid_relying_party} metadata
     * @param federationJwks the {@code jwks} of its verified Entity Configuration, which a signed JWK Set is checked with
     * @param entityId       the RP's Entity Identifier
     * @throws RegistrationRejectedException {@code invalid_client_metadata} when it publishes no usable keys,
     *                                       {@code temporarily_unavailable} when a key set cannot be fetched
     */
    Keys resolve(Map<String, Object> rpMetadata, Map<String, Object> federationJwks, String entityId) throws RegistrationRejectedException {
        Object jwks = rpMetadata.get("jwks");
        if (jwks != null) {
            Map<String, Object> set = asMap(jwks, "jwks");
            return new Keys(signingKeys(set, "jwks"), toJson(set), null, "jwks");
        }
        Object signedJwksUri = rpMetadata.get("signed_jwks_uri");
        if (signedJwksUri != null) {
            String uri = httpsUrl(signedJwksUri, "signed_jwks_uri");
            Map<String, Object> set = this.verifiedSignedJwks(this.fetch(uri, "application/jwk-set+jwt"), federationJwks, entityId);
            return new Keys(signingKeys(set, "signed_jwks_uri"), toJson(set), null, "signed_jwks_uri");
        }
        Object jwksUri = rpMetadata.get("jwks_uri");
        if (jwksUri != null) {
            String uri = httpsUrl(jwksUri, "jwks_uri");
            Map<String, Object> set = parseJson(this.fetch(uri, "application/json"), "jwks_uri");
            return new Keys(signingKeys(set, "jwks_uri"), null, uri, "jwks_uri");
        }
        throw metadata("the RP publishes no keys for openid_relying_party (jwks, signed_jwks_uri or jwks_uri), so it cannot"
                + " prove it sent this request (OpenID Federation 1.0 §12.1.1.1.2)");
    }

    /**
     * §5.2.1: typed {@code jwk-set+jwt}, a {@code kid} header, signed with a Federation Entity Key, {@code iss} and
     * {@code sub} the RP (the keys are its own), not expired, not issued in the future, and carrying {@code keys}.
     */
    private Map<String, Object> verifiedSignedJwks(String jwt, Map<String, Object> federationJwks, String entityId)
            throws RegistrationRejectedException {
        JwtClaims claims;
        try {
            Map<String, Object> header = JwtCodec.getJwtHeaders(jwt);
            JwtCodec.requireType(header, SIGNED_JWKS_TYP);
            JwtCodec.requireKid(header);
            claims = JwtCodec.verifySignature(jwt, Jwks.parseFederationKeySet(federationJwks), Set.of());
        } catch (JwtVerificationException | IllegalArgumentException e) {
            throw metadata("the RP's signed_jwks_uri did not return a jwk-set+jwt signed with one of its Federation Entity Keys");
        }
        long now = this.clock.instant().getEpochSecond();
        Object exp = claims.getClaimValue("exp");
        Object iat = claims.getClaimValue("iat");
        if (!EntityId.same(String.valueOf(claims.getClaimValue("iss")), entityId)
                || !EntityId.same(String.valueOf(claims.getClaimValue("sub")), entityId)
                || exp != null && !(exp instanceof Number n && n.longValue() > now - RequestObject.CLOCK_SKEW_SECONDS)
                || iat != null && !(iat instanceof Number m && m.longValue() <= now + RequestObject.CLOCK_SKEW_SECONDS)) {
            throw metadata("the RP's signed JWK Set is not its own, or is not current");
        }
        return claims.getClaimsMap();
    }

    /**
     * The keys a client this module registered checks with, as it was registered: its JWK Set ({@code jwks}), or what
     * its {@code jwks_uri} serves now, kept {@value #REGISTERED_KEYS_SECONDS} seconds.
     *
     * @throws RegistrationRejectedException {@code invalid_client} when it was registered with neither, or with keys
     *                                       that are no longer usable; {@code temporarily_unavailable} when they cannot
     *                                       be fetched
     */
    List<JsonWebKey> registered(String jwks, String jwksUri) throws RegistrationRejectedException {
        if (jwks != null && !jwks.isBlank()) {
            return signingKeys(parseJson(jwks, "registered jwks"), "registered jwks");
        }
        if (jwksUri == null || jwksUri.isBlank()) {
            throw RegistrationRejectedException.request(401, "invalid_client", "the client is registered with no keys to check its request with");
        }
        long now = this.clock.instant().getEpochSecond();
        Fetched kept = this.fetched.get(jwksUri);
        if (kept != null && now - kept.at() < REGISTERED_KEYS_SECONDS) {
            return kept.keys();
        }
        List<JsonWebKey> keys = signingKeys(parseJson(this.fetch(jwksUri, "application/json"), "jwks_uri"), "jwks_uri");
        this.fetched.put(jwksUri, new Fetched(keys, now));
        return keys;
    }

    private String fetch(String uri, String accept) throws RegistrationRejectedException {
        try {
            return this.http.get(uri, accept);
        } catch (Exception e) {
            throw new RegistrationRejectedException(503, "temporarily_unavailable", "the RP's keys at " + uri + " could not be fetched",
                    RegistrationRejectedException.Kind.TRANSPORT, null);
        }
    }

    /**
     * The keys a signature from the RP may be checked with: every public asymmetric key not marked for encryption.
     * A set with a private or symmetric key in it is refused whole - it is not something an RP should publish.
     */
    static List<JsonWebKey> signingKeys(Map<String, Object> set, String parameter) throws RegistrationRejectedException {
        Object raw = set.get("keys");
        if (!(raw instanceof List<?> list) || list.isEmpty()) {
            throw metadata("the RP's " + parameter + " holds no keys");
        }
        List<JsonWebKey> keys = new ArrayList<>();
        Set<String> kids = new HashSet<>();
        for (Object entry : list) {
            if (!(entry instanceof Map<?, ?>)) {
                throw metadata("the RP's " + parameter + " holds something that is not a JWK");
            }
            @SuppressWarnings("unchecked")
            Map<String, Object> jwk = (Map<String, Object>) entry;
            JsonWebKey key;
            try {
                // Public-only rules out oct and private members; what parses after that is an asymmetric public key.
                Jwks.assertPublicOnly(jwk);
                key = Jwks.fromMap(jwk);
            } catch (Exception e) {
                throw metadata("the RP's " + parameter + " holds a private, symmetric or unreadable key");
            }
            if (key.getKeyId() != null && !kids.add(key.getKeyId())) {
                throw metadata("the RP's " + parameter + " has two keys with kid " + key.getKeyId());
            }
            if (!"enc".equals(key.getUse())) {
                keys.add(key);
            }
        }
        if (keys.isEmpty()) {
            throw metadata("the RP's " + parameter + " holds no signing keys");
        }
        return List.copyOf(keys);
    }

    private static String httpsUrl(Object value, String parameter) throws RegistrationRejectedException {
        try {
            URI uri = URI.create(String.valueOf(value));
            if ("https".equalsIgnoreCase(uri.getScheme()) && uri.getHost() != null) {
                return uri.toString();
            }
        } catch (IllegalArgumentException e) {
            // fall through to the refusal
        }
        throw metadata("the RP's " + parameter + " is not an https URL (OpenID Federation 1.0 §5.2.1)");
    }

    private static Map<String, Object> parseJson(String body, String parameter) throws RegistrationRejectedException {
        try {
            return JsonUtil.parseJson(body);
        } catch (Exception e) {
            throw metadata("the RP's " + parameter + " did not return a JWK Set");
        }
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> asMap(Object value, String parameter) throws RegistrationRejectedException {
        if (value instanceof Map<?, ?>) {
            return (Map<String, Object>) value;
        }
        throw metadata("the RP's " + parameter + " is not a JWK Set");
    }

    private static String toJson(Map<String, Object> set) {
        return JsonUtil.toJson(Map.of("keys", set.get("keys")));
    }

    private static RegistrationRejectedException metadata(String description) {
        return new RegistrationRejectedException(400, "invalid_client_metadata", description, RegistrationRejectedException.Kind.METADATA, null);
    }
}
