/*
 * DPoP proof validation (RFC 9449) for attestation "combined mode".
 */
package com.pingidentity.ps.oidf.common;

import java.net.URI;
import java.time.Instant;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;

/**
 * Validates a DPoP proof JWT per RFC 9449, as far as is meaningful for client authentication at the
 * token endpoint (attestation combined mode). The proof is self-signed with the key carried in its
 * {@code jwk} header; this validator verifies that signature, checks the {@code typ}, the signing
 * algorithm, {@code htm}/{@code htu} and {@code iat} freshness, and requires {@code jti}. It does
 * <em>not</em> perform {@code jti} replay detection (the caller owns the replay cache) nor challenge
 * binding (the caller compares {@link DpopProof#nonce()} against the issued challenge).
 */
public final class DpopProofValidator {
    private static final String DPOP_TYP = "dpop+jwt";

    private final Set<String> acceptedAlgorithms;
    private final int allowedClockSkewSeconds;
    private final long maxAgeSeconds;

    public DpopProofValidator(Set<String> acceptedAlgorithms, int allowedClockSkewSeconds, long maxAgeSeconds) {
        if (acceptedAlgorithms == null || acceptedAlgorithms.isEmpty()) {
            throw new IllegalArgumentException("acceptedAlgorithms must be non-empty");
        }
        this.acceptedAlgorithms = Set.copyOf(acceptedAlgorithms);
        this.allowedClockSkewSeconds = allowedClockSkewSeconds;
        this.maxAgeSeconds = maxAgeSeconds;
    }

    /**
     * Verifies the DPoP proof and returns its parsed form.
     *
     * @param dpop           the {@code DPoP} header value (compact JWS)
     * @param expectedMethod expected HTTP method for the {@code htm} check, or {@code null} to skip
     * @param expectedHtu    expected HTTP target URI for the {@code htu} check, or {@code null} to skip
     * @throws Exception if the proof is structurally invalid, the signature fails, or a check fails
     */
    public DpopProof validate(String dpop, String expectedMethod, String expectedHtu) throws Exception {
        if (dpop == null || dpop.isBlank()) {
            throw new IllegalArgumentException("DPoP proof is missing");
        }
        Map<String, Object> headers = JwtCodec.getJwtHeaders(dpop);
        JwtCodec.requireType(headers, DPOP_TYP);

        Object rawJwk = headers.get("jwk");
        if (!(rawJwk instanceof Map)) {
            throw new IllegalArgumentException("DPoP proof is missing the 'jwk' header");
        }
        @SuppressWarnings("unchecked")
        Map<String, Object> jwkHeaderMap = (Map<String, Object>) rawJwk;
        Jwks.assertPublicOnly(jwkHeaderMap);

        JsonWebSignature jws = new JsonWebSignature();
        jws.setCompactSerialization(dpop);
        jws.setAlgorithmConstraints(new AlgorithmConstraints(AlgorithmConstraints.ConstraintType.PERMIT, this.acceptedAlgorithms.toArray(new String[0])));
        PublicJsonWebKey proofKey = jws.getJwkHeader();
        if (proofKey == null) {
            throw new IllegalArgumentException("DPoP proof 'jwk' header is not a public key");
        }
        jws.setKey(proofKey.getPublicKey());
        if (!jws.verifySignature()) {
            throw new IllegalArgumentException("DPoP proof signature did not verify");
        }

        JwtClaims claims = JwtClaims.parse(jws.getPayload());
        String htm = Claims.requireNonBlank(claims.getStringClaimValue("htm"), "htm");
        String htu = Claims.requireNonBlank(claims.getStringClaimValue("htu"), "htu");
        String jti = Claims.requireNonBlank(claims.getStringClaimValue("jti"), "jti");
        if (!claims.hasClaim("iat")) {
            throw new IllegalArgumentException("DPoP proof is missing 'iat'");
        }
        long iat = claims.getIssuedAt().getValue();
        String nonce = claims.hasClaim("nonce") ? claims.getStringClaimValue("nonce") : null;
        String ath = claims.hasClaim("ath") ? claims.getStringClaimValue("ath") : null;

        if (expectedMethod != null && !expectedMethod.equalsIgnoreCase(htm)) {
            throw new IllegalArgumentException("DPoP 'htm' mismatch: got '" + htm + "', expected '" + expectedMethod + "'");
        }
        if (expectedHtu != null && !DpopProofValidator.normalizeHtu(expectedHtu).equals(DpopProofValidator.normalizeHtu(htu))) {
            throw new IllegalArgumentException("DPoP 'htu' mismatch: got '" + htu + "', expected '" + expectedHtu + "'");
        }
        this.assertFresh(iat);

        return new DpopProof(proofKey, htm, htu, iat, jti, nonce, ath, dpop);
    }

    private void assertFresh(long iat) {
        long now = Instant.now().getEpochSecond();
        if (iat - now > this.allowedClockSkewSeconds) {
            throw new IllegalArgumentException("DPoP 'iat' is too far in the future");
        }
        if (this.maxAgeSeconds > 0L && now - iat > this.maxAgeSeconds + this.allowedClockSkewSeconds) {
            throw new IllegalArgumentException("DPoP proof is stale (iat older than " + this.maxAgeSeconds + "s)");
        }
    }

    /** Normalizes an {@code htu} for comparison: lower-cased scheme/host, default ports dropped, query and fragment removed. */
    static String normalizeHtu(String url) {
        String trimmed = url.trim();
        try {
            URI u = URI.create(trimmed);
            String scheme = u.getScheme() == null ? "" : u.getScheme().toLowerCase(Locale.ROOT);
            String host = u.getHost() == null ? "" : u.getHost().toLowerCase(Locale.ROOT);
            int port = u.getPort();
            boolean defaultPort = port == -1 || ("https".equals(scheme) && port == 443) || ("http".equals(scheme) && port == 80);
            String path = u.getPath() == null ? "" : u.getPath();
            StringBuilder sb = new StringBuilder();
            sb.append(scheme).append("://").append(host);
            if (!defaultPort) {
                sb.append(':').append(port);
            }
            return sb.append(path).toString();
        } catch (RuntimeException e) {
            String s = trimmed;
            int q = s.indexOf('?');
            if (q >= 0) {
                s = s.substring(0, q);
            }
            int h = s.indexOf('#');
            if (h >= 0) {
                s = s.substring(0, h);
            }
            return s;
        }
    }
}
