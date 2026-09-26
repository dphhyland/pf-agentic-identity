/*
 * The two FAPI 2.0 rules PingFederate cannot be configured to enforce per client, as decisions on a request.
 */
package com.pingidentity.ps.oidf.servlet.fapi2;

import java.util.Map;
import java.util.Set;
import org.jose4j.base64url.Base64Url;
import org.jose4j.json.JsonUtil;
import org.jose4j.jwx.CompactSerializer;

/**
 * What {@link Fapi2ProfileFilter} decides, with no servlet and no PingFederate in it.
 *
 * <p>Both checks read a JWT nobody has verified yet, and that is sound only because of the direction
 * they work in: each can refuse a request and neither can admit one. PingFederate still verifies every
 * signature afterwards. So the question a check has to get right is never "is this JWT genuine" but
 * "could something PingFederate would go on to accept get past here looking different" - and the answer
 * to that is to refuse whatever cannot be read, rather than wave it through for PingFederate to read its
 * own way. A request reaches PingFederate only if this class could parse the JWT and liked what it saw.
 *
 * <p>The parsing is jose4j's, on purpose. In {@code pf-protocolengine} 13.0.3 and 13.1.3 both
 * {@code org.sourceid.oauth20.dpop.DpopUtil} and {@code ...validate.ClientPrivateKeyJwtValidator}
 * reference {@code org.jose4j} (read from their constant pools; PingFederate's source is not available
 * to read), so the two sides are, as far as that shows, reading the same bytes with the same library.
 * It matters most for a JSON object with a member twice: jose4j refuses it rather than choosing one.
 */
final class Fapi2RequestPolicy {

    /** FAPI 2.0 Security Profile §5.4.1: PS256, ES256 or EdDSA, for any JWT created or processed. */
    static final Set<String> ALLOWED_ALGORITHMS = Set.of("PS256", "ES256", "EdDSA");

    /** A refusal: the OAuth error code, and a description with no character a JSON string must escape. */
    static final class Violation {
        final String error;
        final String description;

        Violation(String error, String description) {
            this.error = error;
            this.description = description;
        }
    }

    private Fapi2RequestPolicy() {
    }

    /**
     * FAPI 2.0 Security Profile §5.3.2.1: the authorization server "shall only accept its issuer
     * identifier value ... as a string in the aud claim received in client authentication assertions".
     *
     * <p>Observed on PingFederate 13.0.3, at the PAR endpoint, with the OpenID conformance suite: an
     * {@code aud} of the token endpoint URL is accepted, so is one of the PAR endpoint URL, and so is the
     * array {@code [issuer, token endpoint]}. 13.0.3 has no setting for this.
     *
     * <p>13.1 adds {@code Rfc7523bisCompliantAudienceVerification} ({@code AuthzServerManagerImpl.xml}), on
     * in a fresh 13.1.3 install and off in an archive upgraded from 13.0. It does not replace this rule, for
     * two reasons (read with javap from 13.1.3's {@code pf-protocolengine}, 2026-09-26):
     * <ul>
     *   <li>It is one switch for the whole server: {@code AuthzServerManager} reads it with no client in
     *       view. An ordinary client may address the token endpoint, as OpenID Connect Core §9 tells it to -
     *       the conformance suite's Shared Signals client does - and a server-wide rule refuses it; the
     *       conformance rig keeps the switch off for that reason.</li>
     *   <li>Even on, it is wider than §5.3.2.1. It accepts any single audience from its own list - the
     *       base URL, the issuer, any additional allowed audience, and the token endpoint base URL when one
     *       is set - and it reads the claim with jose4j's {@code getAudience()}, which gives a one-member
     *       array and a string alike. draft-ietf-oauth-rfc7523bis-11 allows that array; FAPI 2.0 does not.</li>
     * </ul>
     *
     * @return the refusal, or {@code null} if the assertion's audience is the issuer and only the issuer
     */
    static Violation checkClientAssertion(String assertion, String issuer) {
        Map<String, Object> claims = part(assertion, 1);
        if (claims == null) {
            return new Violation("invalid_client", "client assertion is not a JWT this server can read");
        }
        Object aud = claims.get("aud");
        if (aud instanceof String && aud.equals(issuer)) {
            return null;
        }
        return new Violation("invalid_client",
                "client assertion aud must be this authorization server's issuer identifier, as a single string");
    }

    /**
     * FAPI 2.0 Security Profile §5.4.1, applied to a DPoP proof. Observed on PingFederate 13.0.3 and
     * 13.1.3: an RS256-signed proof is accepted at the UserInfo endpoint. In 13.0.3 and 13.1.3 the list is a
     * constant - {@code DpopUtil.SUPPORTED_SIGNING_ALGORITHMS}, RS, ES and PS at 256, 384 and 512 - and the
     * only keys that class reads from its config file are {@code MaxJtiLength} and {@code DpopClockSkewSeconds},
     * so it cannot be narrowed by configuration (13.1.3 re-read with javap, 2026-09-26). 13.1's new per-client
     * DPoP settings are replay, lifetime and nonce; no algorithm list was found there either.
     *
     * @return the refusal, or {@code null} if the proof is signed with a permitted algorithm
     */
    static Violation checkDpopProof(String proof) {
        Map<String, Object> header = part(proof, 0);
        if (header == null) {
            return new Violation("invalid_dpop_proof", "DPoP proof is not a JWT this server can read");
        }
        Object alg = header.get("alg");
        if (alg instanceof String && ALLOWED_ALGORITHMS.contains(alg)) {
            return null;
        }
        return new Violation("invalid_dpop_proof", "DPoP proof must be signed with PS256, ES256 or EdDSA");
    }

    /**
     * Whose assertion this says it is: its {@code sub}, which is the client PingFederate will go on to
     * authenticate it as, or {@code null} if it cannot be read or names nobody.
     */
    static String subjectOf(String assertion) {
        Map<String, Object> claims = part(assertion, 1);
        Object sub = claims == null ? null : claims.get("sub");
        return sub instanceof String && !((String) sub).isBlank() ? (String) sub : null;
    }

    /**
     * The client a JWT access token says it was issued to, from an {@code Authorization} header of
     * either scheme, or {@code null} - no header, a reference token, a JWT with no {@code client_id}.
     */
    static String clientOfAccessToken(String authorization) {
        int space = authorization == null ? -1 : authorization.trim().indexOf(' ');
        if (space < 0) {
            return null;
        }
        Map<String, Object> claims = part(authorization.trim().substring(space + 1), 1);
        Object client = claims == null ? null : claims.get("client_id");
        return client instanceof String && !((String) client).isBlank() ? (String) client : null;
    }

    /** The JSON object in one part of a compact JWS, or {@code null} if it is not there to be read. */
    private static Map<String, Object> part(String compact, int index) {
        if (compact == null || compact.isBlank()) {
            return null;
        }
        try {
            String[] parts = CompactSerializer.deserialize(compact.trim());
            if (parts.length != 3) { // a JWS: five parts is a JWE, which nothing here can look inside
                return null;
            }
            return JsonUtil.parseJson(Base64Url.decodeToUtf8String(parts[index]));
        }
        catch (Exception e) {
            return null;
        }
    }
}
