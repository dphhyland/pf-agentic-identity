/*
 * Verifies inbound Security Event Tokens against a transmitter's keys (receiver side).
 */
package com.pingidentity.ps.oidf.signals;

import java.time.Clock;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import org.jose4j.json.JsonUtil;
import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;

/**
 * Receiver-side SET verification against a supplied key set. An inbound compact JWS is accepted only when:
 *
 * <ul>
 *   <li>its {@code typ} is {@code secevent+jwt}, with or without the {@code application/} prefix and in any case
 *       (SSF 1.0 §4.1.1: "SSF events MUST use explicit typing as defined in Section 2.3 of [RFC8417]"; RFC 7515
 *       §4.1.9: media types are case insensitive, and a recipient "MUST treat it as if "application/" were
 *       prepended to any "typ" value not containing a '/'");</li>
 *   <li>its {@code alg} is an asymmetric signature algorithm and the signature verifies against one of the
 *       transmitter's keys (matching {@code kid} when the header has one, and once more after a refresh);</li>
 *   <li>{@code iss} is the expected issuer (RFC 8417 §2.2: "This claim is REQUIRED"; SSF 1.0 §4.1.6: "Receivers
 *       MUST validate that this claim matches");</li>
 *   <li>{@code aud}, a string or an array (SSF 1.0 §4.1.8), contains the expected audience when one is
 *       configured (RFC 8417 §2.2 makes {@code aud} only RECOMMENDED, so a verifier with no audience does not
 *       ask);</li>
 *   <li>{@code iat} is a number (RFC 8417 §2.2: "This claim is REQUIRED") and {@code jti} a non-blank string
 *       ("This claim is REQUIRED");</li>
 *   <li>{@code exp}, when present, is a number and not past, less a small leeway (RFC 8417 §2.2 defines it as "the
 *       time after which the JWT MUST NOT be accepted for processing"; RFC 7519 §4.1.4 allows "some small leeway,
 *       usually no more than a few minutes");</li>
 *   <li>{@code events} is an object with at least one member (RFC 8417 §2: "The "events" claim value MUST be a
 *       JSON object that contains at least one member") and every value an object (§2.2: "For each name present,
 *       the corresponding value MUST be a JSON object");</li>
 *   <li>{@code sub_id}, when present, is a subject in a format this verifier accepts ({@link SubjectId}).</li>
 * </ul>
 *
 * <p>SSF 1.0 goes further than RFC 8417 on two claims - §4.1.7: "The "exp" claim MUST NOT be used in SETs", and
 * §4.1.2: "The JWT "sub" claim MUST NOT be present" - but both are written to the transmitter; this verifier
 * honours an {@code exp} as RFC 8417 does and ignores {@code sub} (docs/findings/F-0246.yaml).
 *
 * <p>Keys come from a {@link JwksSource}; this class makes no network call. Failures throw
 * {@link SetVerificationException} carrying the RFC 8935 error code the push endpoint must return
 * ({@code invalid_request} / {@code invalid_key} / {@code invalid_issuer} / {@code invalid_audience}).
 */
public final class SetVerifier {

    /** Supplies the transmitter's current signing keys; {@code refresh} forces a re-fetch (key rotation). */
    public interface JwksSource {
        List<JsonWebKey> keys(boolean refresh) throws Exception;
    }

    /** A verification failure, carrying the RFC 8935 {@code err} code for the push response. */
    public static final class SetVerificationException extends Exception {
        private static final long serialVersionUID = 1L;
        private final String errorCode;

        public SetVerificationException(String errorCode, String message) {
            super(message);
            this.errorCode = errorCode;
        }

        public String errorCode() {
            return this.errorCode;
        }
    }

    /** The leeway on {@code exp}, for clock skew between transmitter and receiver. */
    public static final long EXP_LEEWAY_SECONDS = 60;

    /** The signature algorithms a SET may carry: asymmetric only, so a public key can never be used as a MAC key. */
    public static final Set<String> ALGORITHMS = Set.of(
            AlgorithmIdentifiers.RSA_USING_SHA256, AlgorithmIdentifiers.RSA_USING_SHA384,
            AlgorithmIdentifiers.RSA_USING_SHA512, AlgorithmIdentifiers.RSA_PSS_USING_SHA256,
            AlgorithmIdentifiers.RSA_PSS_USING_SHA384, AlgorithmIdentifiers.RSA_PSS_USING_SHA512,
            AlgorithmIdentifiers.ECDSA_USING_P256_CURVE_AND_SHA256,
            AlgorithmIdentifiers.ECDSA_USING_P384_CURVE_AND_SHA384,
            AlgorithmIdentifiers.ECDSA_USING_P521_CURVE_AND_SHA512, AlgorithmIdentifiers.EDDSA);

    private static final String SET_TYP = "application/secevent+jwt";

    private final String expectedIssuer;
    private final String expectedAudience;
    private final JwksSource jwksSource;
    private final Clock clock;
    private final Set<String> subjectFormats;

    /** A verifier that accepts every subject format {@link SubjectId} parses, on the system clock. */
    public SetVerifier(String expectedIssuer, String expectedAudience, JwksSource jwksSource) {
        this(expectedIssuer, expectedAudience, jwksSource, Clock.systemUTC(), SubjectId.FORMATS);
    }

    /**
     * @param expectedAudience null to skip the {@code aud} check
     * @param subjectFormats   the {@code sub_id} formats accepted at the top level; others are {@code invalid_request}
     */
    public SetVerifier(String expectedIssuer, String expectedAudience, JwksSource jwksSource, Clock clock,
                       Set<String> subjectFormats) {
        this.expectedIssuer = Objects.requireNonNull(expectedIssuer, "expectedIssuer");
        this.expectedAudience = expectedAudience;
        this.jwksSource = Objects.requireNonNull(jwksSource, "jwksSource");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.subjectFormats = Set.copyOf(subjectFormats);
    }

    /** Verify and parse an inbound SET. */
    public ReceivedSet verify(String compactJws) throws SetVerificationException {
        JsonWebSignature jws = new JsonWebSignature();
        try {
            jws.setCompactSerialization(compactJws);
        } catch (Exception e) {
            throw new SetVerificationException("invalid_request", "not a compact JWS: " + e.getMessage());
        }
        String typ = jws.getHeader("typ");
        if (!isSetType(typ)) {
            throw new SetVerificationException("invalid_request", "typ is not secevent+jwt: " + typ);
        }
        String alg = jws.getAlgorithmHeaderValue();
        if (!ALGORITHMS.contains(alg)) {
            throw new SetVerificationException("invalid_request", "alg is not an accepted signature algorithm: " + alg);
        }
        jws.setAlgorithmConstraints(new AlgorithmConstraints(AlgorithmConstraints.ConstraintType.PERMIT,
                ALGORITHMS.toArray(new String[0])));
        if (!signatureVerifies(jws, false) && !signatureVerifies(jws, true)) {
            throw new SetVerificationException("invalid_key", "SET signature does not verify against the transmitter JWKS");
        }
        Map<String, Object> claims;
        try {
            claims = JsonUtil.parseJson(jws.getUnverifiedPayload());
        } catch (Exception e) {
            throw new SetVerificationException("invalid_request", "SET payload is not JSON");
        }

        Object iss = claims.get("iss");
        if (!this.expectedIssuer.equals(iss)) {
            throw new SetVerificationException("invalid_issuer", "unexpected iss: " + iss);
        }
        if (this.expectedAudience != null && !audMatches(claims.get("aud"))) {
            throw new SetVerificationException("invalid_audience", "aud does not include " + this.expectedAudience);
        }
        Object jti = claims.get("jti");
        if (!(jti instanceof String) || ((String) jti).isBlank()) {
            throw new SetVerificationException("invalid_request", "SET missing jti");
        }
        long iat = requireNumericDate(claims, "iat");
        if (claims.containsKey("exp")) {
            long exp = requireNumericDate(claims, "exp");
            if (this.clock.instant().getEpochSecond() - EXP_LEEWAY_SECONDS >= exp) {
                throw new SetVerificationException("invalid_request", "SET expired at " + exp);
            }
        }
        Map<String, Object> events = requireEvents(claims.get("events"));

        SubjectId subject = null;
        if (claims.containsKey("sub_id")) {
            Object subId = claims.get("sub_id");
            if (!(subId instanceof Map)) {
                throw new SetVerificationException("invalid_request", "sub_id is not a subject identifier");
            }
            try {
                @SuppressWarnings("unchecked")
                Map<String, Object> subMap = (Map<String, Object>) subId;
                subject = SubjectId.fromMap(subMap, this.subjectFormats);
            } catch (IllegalArgumentException e) {
                throw new SetVerificationException("invalid_request", "unparseable sub_id: " + e.getMessage());
            }
        }
        return new ReceivedSet((String) iss, (String) jti, iat, subject, events, compactJws);
    }

    /** RFC 8417 §2.3's media type, compared as RFC 7515 §4.1.9 says a {@code typ} is. */
    static boolean isSetType(String typ) {
        if (typ == null) {
            return false;
        }
        String t = typ.toLowerCase(Locale.ROOT);
        return SET_TYP.equals(t.indexOf('/') < 0 ? "application/" + t : t);
    }

    static long requireNumericDate(Map<String, Object> claims, String name) throws SetVerificationException {
        Object v = claims.get(name);
        if (!(v instanceof Number)) {
            throw new SetVerificationException("invalid_request", "SET " + name + " is not a NumericDate");
        }
        return ((Number) v).longValue();
    }

    @SuppressWarnings("unchecked")
    static Map<String, Object> requireEvents(Object events) throws SetVerificationException {
        if (!(events instanceof Map) || ((Map<?, ?>) events).isEmpty()) {
            throw new SetVerificationException("invalid_request", "SET missing events");
        }
        for (Map.Entry<String, Object> e : ((Map<String, Object>) events).entrySet()) {
            if (!(e.getValue() instanceof Map)) {
                throw new SetVerificationException("invalid_request", "event " + e.getKey() + " is not a JSON object");
            }
        }
        return (Map<String, Object>) events;
    }

    private boolean signatureVerifies(JsonWebSignature jws, boolean refresh) {
        List<JsonWebKey> keys;
        try {
            keys = this.jwksSource.keys(refresh);
        } catch (Exception e) {
            return false;
        }
        String kid = jws.getKeyIdHeaderValue();
        for (JsonWebKey key : keys) {
            if (kid != null && key.getKeyId() != null && !kid.equals(key.getKeyId())) {
                continue;
            }
            try {
                jws.setKey(key.getKey());
                if (jws.verifySignature()) {
                    return true;
                }
            } catch (Exception ignored) {
                // try the next key
            }
        }
        return false;
    }

    private boolean audMatches(Object aud) {
        if (aud instanceof String) {
            return this.expectedAudience.equals(aud);
        }
        if (aud instanceof Iterable) {
            for (Object a : (Iterable<?>) aud) {
                if (this.expectedAudience.equals(a)) {
                    return true;
                }
            }
        }
        return false;
    }
}
