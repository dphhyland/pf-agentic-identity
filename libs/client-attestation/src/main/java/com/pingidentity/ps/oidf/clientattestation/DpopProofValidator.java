/*
 * DPoP proof validation (RFC 9449) for attestation "combined mode".
 */
package com.pingidentity.ps.oidf.clientattestation;

import java.net.URI;
import java.net.URISyntaxException;
import java.time.Instant;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import com.pingidentity.ps.oidf.jose.JwtCodec;
import com.pingidentity.ps.oidf.jose.Jwks;
import com.pingidentity.ps.oidf.jose.Claims;

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
            throw new IllegalArgumentException("DPoP 'htm' mismatch: got '" + DpopProofValidator.shown(htm)
                    + "', expected '" + expectedMethod + "'");
        }
        if (expectedHtu != null) {
            DpopProofValidator.requireHtu(htu, expectedHtu);
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

    /**
     * Refuses a proof whose {@code htu} does not name {@code expectedHtu}.
     *
     * <p>RFC 9449 §4.3, item 9: "The htu claim matches the HTTP URI value for the HTTP request in which the JWT
     * was received, ignoring any query and fragment parts." And after the list: "To reduce the likelihood of
     * false negatives, servers SHOULD employ syntax-based normalization (Section 6.2.2 of [RFC3986]) and
     * scheme-based normalization (Section 6.2.3 of [RFC3986]) before comparing the htu claim." Both sides go
     * through {@link #normalizeHtu}; an {@code htu} that is not an absolute http or https URI names no endpoint
     * of this server and is refused, and an expected value that is not one is this server's misconfiguration.
     */
    static void requireHtu(String htu, String expectedHtu) {
        String expected = DpopProofValidator.normalizeHtu(expectedHtu);
        if (expected == null) {
            throw new IllegalArgumentException("the expected DPoP 'htu' is not an absolute http or https URI: '"
                    + expectedHtu + "'");
        }
        if (!expected.equals(DpopProofValidator.normalizeHtu(htu))) {
            throw new IllegalArgumentException("DPoP 'htu' mismatch: got '" + DpopProofValidator.shown(htu)
                    + "', expected '" + expectedHtu + "'");
        }
    }

    /** Longest part of a proof's own claim a refusal repeats. */
    static final int SHOWN_LIMIT = 256;

    /**
     * A claim from the proof as a refusal may repeat it: the proof is the caller's to write, and the message reaches
     * the token endpoint's error_description and the server log, so a control character becomes '?' and anything past
     * {@link #SHOWN_LIMIT} characters is cut, rather than letting a proof forge log lines or fill them.
     */
    static String shown(String claim) {
        StringBuilder out = new StringBuilder(Math.min(claim.length(), SHOWN_LIMIT) + 3);
        for (int i = 0; i < claim.length() && i < SHOWN_LIMIT; i++) {
            char c = claim.charAt(i);
            out.append(c < 0x20 || c == 0x7f ? '?' : c);
        }
        return claim.length() > SHOWN_LIMIT ? out.append("...").toString() : out.toString();
    }

    /**
     * The form an {@code htu} is compared in, or {@code null} when {@code url} is not an absolute http or https
     * URI with a host.
     *
     * <p>RFC 3986 §6.2.2 syntax-based normalization: the scheme and host in lower case (§6.2.2.1), percent-encoded
     * unreserved characters decoded and the hex digits of every other percent-encoding in upper case (§6.2.2.1,
     * §6.2.2.2), and dot-segments removed (§6.2.2.3). §6.2.3 scheme-based normalization for http and https: a
     * port that is empty or the scheme's default dropped, and an empty path made "/". The query and the fragment
     * are dropped (RFC 9449 §4.3, item 9). Nothing else is: the user information, a trailing slash and the case
     * of the path all still count, because §6.2.2 leaves them significant.
     */
    static String normalizeHtu(String url) {
        if (url == null) {
            return null;
        }
        URI u;
        try {
            u = new URI(url);
        } catch (URISyntaxException e) {
            return null;
        }
        String scheme = u.getScheme() == null ? "" : u.getScheme().toLowerCase(Locale.ROOT);
        boolean https = "https".equals(scheme);
        if ((!https && !"http".equals(scheme)) || u.getHost() == null) {
            return null;
        }
        StringBuilder sb = new StringBuilder(scheme).append("://");
        if (u.getRawUserInfo() != null) {
            sb.append(DpopProofValidator.normalizePercentEncoding(u.getRawUserInfo())).append('@');
        }
        sb.append(u.getHost().toLowerCase(Locale.ROOT));
        int port = u.getPort();
        if (port != -1 && port != (https ? 443 : 80)) {
            sb.append(':').append(port);
        }
        String path = DpopProofValidator.removeDotSegments(
                DpopProofValidator.normalizePercentEncoding(u.getRawPath()));
        return sb.append(path.isEmpty() ? "/" : path).toString();
    }

    /**
     * RFC 3986 §6.2.2.2 and the hex-digit half of §6.2.2.1: a percent-encoded octet that is an unreserved
     * character (§2.3: {@code ALPHA / DIGIT / "-" / "." / "_" / "~"}) is decoded, and any other keeps its
     * encoding with its hex digits in upper case. The input has already parsed as a URI, so every {@code %}
     * starts a well-formed triplet.
     */
    static String normalizePercentEncoding(String raw) {
        StringBuilder out = new StringBuilder(raw.length());
        for (int i = 0; i < raw.length(); i++) {
            char c = raw.charAt(i);
            if (c != '%') {
                out.append(c);
                continue;
            }
            int octet = Integer.parseInt(raw.substring(i + 1, i + 3), 16);
            char decoded = (char) octet;
            boolean unreserved = decoded >= 'A' && decoded <= 'Z' || decoded >= 'a' && decoded <= 'z'
                    || decoded >= '0' && decoded <= '9' || decoded == '-' || decoded == '.' || decoded == '_'
                    || decoded == '~';
            if (unreserved) {
                out.append(decoded);
            } else {
                out.append('%').append(raw.substring(i + 1, i + 3).toUpperCase(Locale.ROOT));
            }
            i += 2;
        }
        return out.toString();
    }

    /**
     * RFC 3986 §5.2.4 remove_dot_segments, step for step (the letters are the RFC's). The input buffer is
     * {@code path} from {@code i} to {@code end} rather than a string cut down at each step, so a long path costs
     * linear time: the {@code htu} is read before the proof's key is compared with the attestation's, so anyone
     * holding an attestation can send one. "Replace that prefix with "/"" is a move of {@code i} to the prefix's last
     * "/", or, when the prefix is the whole buffer, a move of {@code end} to just after its first.
     */
    static String removeDotSegments(String path) {
        StringBuilder out = new StringBuilder(path.length());
        int i = 0;
        int end = path.length();
        while (i < end) {
            int left = end - i;
            if (path.startsWith("../", i)) {                                          // A
                i += 3;
            } else if (path.startsWith("./", i)) {                                    // A
                i += 2;
            } else if (path.startsWith("/./", i)) {                                   // B
                i += 2;
            } else if (left == 2 && path.startsWith("/.", i)) {                       // B
                end = i + 1;
            } else if (path.startsWith("/../", i) || left == 3 && path.startsWith("/..", i)) { // C
                if (left == 3) {
                    end = i + 1;
                } else {
                    i += 3;
                }
                out.setLength(Math.max(out.lastIndexOf("/"), 0));
            } else if (left == 1 && path.charAt(i) == '.' || left == 2 && path.startsWith("..", i)) { // D
                i = end;
            } else {                                                                  // E
                // end moves only for a buffer of "/." or "/..", and what lies past it then is dots, so a "/"
                // found here is never beyond it.
                int next = path.indexOf('/', i + 1);
                int stop = next < 0 ? end : next;
                out.append(path, i, stop);
                i = stop;
            }
        }
        return out.toString();
    }
}
