/*
 * What a front-channel request offers as proof that it comes from the RP it names.
 */
package com.pingidentity.ps.oidf.servlet.clientregistration;

import com.pingidentity.ps.oidf.federation.EntityId;
import com.pingidentity.ps.oidf.jose.JwtCodec;
import com.pingidentity.ps.oidf.jose.JwtVerificationException;
import com.pingidentity.ps.oidf.platform.profile.DeploymentProfile;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwt.JwtClaims;

/**
 * The JWT a request at the authorization or PAR endpoint offers as proof that it comes from the RP it names -
 * OpenID Federation 1.0 §12.1.1: "Authentication requests MUST demonstrate that the requesting Entity controls
 * the Entity's RP keys". That is its request object (§12.1.1.1) or, at PAR, its {@code private_key_jwt} client
 * assertion (§12.1.1.2).
 *
 * <p>Read unverified first: its header names the chain to try ({@code trust_chain}, §4.3) and its claims are held
 * to the profile before anything is fetched, so a request that could never be accepted costs nothing. Then, once
 * the RP's keys are known, {@link #verify} checks the signature and spends the {@code jti}. An encrypted request
 * object can only be read as far as its header: its claims and signature are PingFederate's to check once it has
 * decrypted it, against the keys registered here - so in production it never registers a client
 * ({@link #registeringFromEncrypted}), and only goes ahead on a registration its RP already has.
 */
final class RequestObject {
    private static final Log LOGGER = LogFactory.getLog(RequestObject.class);
    /** The {@code typ} values a request object may carry: none, the generic JWT, or RFC 9101's. */
    private static final Set<String> REQUEST_OBJECT_TYPES = Set.of("jwt", "oauth-authz-req+jwt");
    /** Leeway for {@code exp} and {@code iat}, as for every other JWT this module reads. */
    static final long CLOCK_SKEW_SECONDS = 60L;
    /** The longest a spent {@code jti} is remembered, whatever the JWT's own {@code exp} says. */
    static final long MAX_REPLAY_WINDOW_SECONDS = 86_400L;

    /** Which proof this is. */
    enum Kind {
        /** A {@code request} parameter (§12.1.1.1). */
        REQUEST_OBJECT,
        /** A {@code client_assertion} at the PAR endpoint (§12.1.1.2). */
        CLIENT_ASSERTION
    }

    private final Kind kind;
    private final String compact;
    private final Map<String, Object> header;
    private final JwtClaims claims;

    private RequestObject(Kind kind, String compact, Map<String, Object> header, JwtClaims claims) {
        this.kind = kind;
        this.compact = compact;
        this.header = header;
        this.claims = claims;
    }

    /**
     * Reads {@code compact} without verifying anything.
     *
     * @throws RegistrationRejectedException {@code invalid_request_object} when it is not a compact JWS or JWE
     */
    static RequestObject read(Kind kind, String compact) throws RegistrationRejectedException {
        try {
            Map<String, Object> header = JwtCodec.compactProtectedHeader(compact);
            JwtClaims claims = JwtCodec.isCompactJwe(compact) ? null : JwtCodec.parseUnverifiedClaims(compact);
            return new RequestObject(kind, compact, header, claims);
        } catch (Exception e) {
            throw RegistrationRejectedException.request(400, errorFor(kind), what(kind) + " is not a compact JWS or JWE");
        }
    }

    Kind kind() {
        return this.kind;
    }

    boolean encrypted() {
        return this.claims == null;
    }

    /**
     * The chain it hints at: the {@code trust_chain} header (§4.3, RECOMMENDED), else the {@code trust_chain} claim
     * of a request object (§12.1.1.1, "retained for historical reasons"). Empty when it carries neither.
     */
    List<String> trustChain() {
        List<String> fromHeader = strings(this.header.get("trust_chain"));
        if (!fromHeader.isEmpty() || this.claims == null || this.kind != Kind.REQUEST_OBJECT) {
            return fromHeader;
        }
        return strings(this.claims.getClaimValue("trust_chain"));
    }

    /**
     * The JWS {@code alg} it is signed with, or null. Always null for an encrypted object: the {@code alg} of a JWE's
     * header is its key-management algorithm (RFC 7516 §4.1.1: it "identifies the cryptographic algorithm used to
     * encrypt or determine the value of the CEK"), such as {@code RSA-OAEP} or {@code ECDH-ES}, and says nothing about
     * how the request inside is signed - so it must never become a client's {@code request_object_signing_alg}.
     */
    String algorithm() {
        if (this.encrypted()) {
            return null;
        }
        Object alg = this.header.get("alg");
        return alg instanceof String s ? s : null;
    }

    /**
     * What registering {@code clientId} from an encrypted proof - one whose {@link #algorithm()} is null - comes to
     * under {@code profile}. OpenID Federation 1.0 §12.1.1: "Authentication requests MUST demonstrate that the
     * requesting Entity controls the Entity's RP keys, using one of the methods described below. Attempted
     * authentication requests that do not do so MUST be rejected." This module cannot decrypt a request object - it
     * is encrypted to PingFederate's key - so it never sees the JWS inside, and {@link #verify} has nothing to check.
     * PingFederate decrypts and checks it only after the client has been registered from the RP's published metadata:
     * by then the registration has been written on the word of a request that showed nothing. So production refuses
     * it ({@code invalid_request_object}, 400; a failure of the request, never held against the RP) and development
     * accepts it with a warning. An RP registers with a signed request object, or at PAR with its client assertion;
     * its later requests on a current registration may be encrypted, as before.
     *
     * @throws RegistrationRejectedException under the production profile
     */
    static void registeringFromEncrypted(String clientId, DeploymentProfile profile) throws RegistrationRejectedException {
        if (profile.isProduction()) {
            throw RegistrationRejectedException.request(400, "invalid_request_object", "an encrypted request object cannot register a"
                    + " client: its signature cannot be checked before the registration is written (OpenID Federation 1.0 §12.1.1)."
                    + " Register with a signed request object, or at the PAR endpoint");
        }
        LOGGER.warn((Object)("Development profile: registering " + clientId + " from an encrypted request object, whose signature"
                + " cannot be checked until PingFederate decrypts it - after the registration is written. Production refuses this"
                + " (OpenID Federation 1.0 §12.1.1)"));
    }

    private static List<String> strings(Object raw) {
        List<String> out = new ArrayList<>();
        if (raw instanceof List<?> list) {
            for (Object item : list) {
                if (item instanceof String s && !s.isBlank()) {
                    out.add(s);
                }
            }
        }
        return out;
    }

    /**
     * Holds the claims to the profile before anything is fetched: §12.1.1.1 for a request object, §12.1.1.2 and
     * {@code private_key_jwt} for a client assertion. An encrypted request object is only held to its size.
     *
     * @param clientId the client the request names
     * @param opIssuer this OP's Entity Identifier, the only audience either may name
     * @throws RegistrationRejectedException naming the first rule it breaks
     */
    void checkProfile(String clientId, String opIssuer, long now, int maxBytes) throws RegistrationRejectedException {
        if (this.compact.length() > maxBytes) {
            throw this.refused(what(this.kind) + " is larger than the " + maxBytes + " bytes accepted");
        }
        if (this.encrypted()) {
            return;
        }
        String alg = this.algorithm();
        if (alg == null || "none".equalsIgnoreCase(alg) || alg.toUpperCase(Locale.ROOT).startsWith("HS")) {
            throw this.refused(what(this.kind) + " must be signed with one of the RP's keys (alg " + alg + " is not accepted)");
        }
        Object typ = this.header.get("typ");
        if (this.kind == Kind.REQUEST_OBJECT && typ != null && !(typ instanceof String t && REQUEST_OBJECT_TYPES.contains(t.toLowerCase(Locale.ROOT)))) {
            throw this.refused("the request object's typ must be oauth-authz-req+jwt, if it has one");
        }
        if (this.kind == Kind.REQUEST_OBJECT) {
            this.require(clientId.equals(this.claims.getClaimValue("client_id")), "its client_id must be the client_id of the request");
            this.require(this.claims.getClaimValue("sub") == null, "it must not carry sub (OpenID Federation 1.0 §12.1.1.1)");
        } else {
            this.require(clientId.equals(this.claims.getClaimValue("sub")), "its sub must be the client's Entity Identifier");
        }
        this.require(clientId.equals(this.claims.getClaimValue("iss")), "its iss must be the client's Entity Identifier");
        this.require(onlyAudience(this.claims.getClaimValue("aud"), opIssuer), "its aud must be this OP's Entity Identifier and nothing else");
        Object jti = this.claims.getClaimValue("jti");
        this.require(jti instanceof String s && !s.isBlank(), "it must carry a jti");
        Object exp = this.claims.getClaimValue("exp");
        this.require(exp instanceof Number, "it must carry exp");
        this.require(((Number) exp).longValue() > now - CLOCK_SKEW_SECONDS, "it has expired");
        Object iat = this.claims.getClaimValue("iat");
        this.require(iat == null || iat instanceof Number n && n.longValue() <= now + CLOCK_SKEW_SECONDS, "its iat is in the future");
    }

    private static boolean onlyAudience(Object aud, String opIssuer) {
        if (aud instanceof String s) {
            return EntityId.same(s, opIssuer);
        }
        return aud instanceof List<?> list && list.size() == 1 && list.get(0) instanceof String s && EntityId.same(s, opIssuer);
    }

    private void require(boolean holds, String rule) throws RegistrationRejectedException {
        if (!holds) {
            throw this.refused(what(this.kind) + ": " + rule);
        }
    }

    /** A bad request object is a 400; a bad client assertion is a failed client authentication, 401 (RFC 6749 §5.2). */
    private RegistrationRejectedException refused(String description) {
        return RegistrationRejectedException.request(this.kind == Kind.REQUEST_OBJECT ? 400 : 401, errorFor(this.kind), description);
    }

    /**
     * §12.1.1.1.2: the OP "MUST verify that the client was actually the one sending the Authentication Request by
     * verifying the signature of the Request Object using the key material the client published in its metadata for
     * the openid_relying_party Entity Type" - and then spends its {@code jti}, which "MUST only be used once".
     * An encrypted request object passes here: PingFederate decrypts and verifies it against the keys registered. It
     * reaches this point only on a registration the RP already has, or in development
     * ({@link #registeringFromEncrypted}).
     *
     * @throws RegistrationRejectedException {@code invalid_client} (401) when no RP key verifies it, the profile
     *                                       error when its {@code jti} was spent before
     */
    void verify(List<JsonWebKey> rpKeys, String clientId, ReplayGuard replay, long now) throws RegistrationRejectedException {
        if (this.encrypted()) {
            return;
        }
        try {
            JwtCodec.verifySignature(this.compact, rpKeys, Set.of());
        } catch (JwtVerificationException e) {
            throw RegistrationRejectedException.request(401, "invalid_client", what(this.kind)
                    + " is not signed by a key the RP publishes for openid_relying_party (" + e.code() + ")");
        }
        long exp = ((Number) this.claims.getClaimValue("exp")).longValue();
        long window = Math.max(CLOCK_SKEW_SECONDS, Math.min(exp - now + CLOCK_SKEW_SECONDS, MAX_REPLAY_WINDOW_SECONDS));
        if (!replay.firstSeen(clientId, (String) this.claims.getClaimValue("jti"), window)) {
            throw this.refused(what(this.kind) + " has been used before (its jti is spent)");
        }
    }

    private static String errorFor(Kind kind) {
        return kind == Kind.REQUEST_OBJECT ? "invalid_request_object" : "invalid_client";
    }

    private static String what(Kind kind) {
        return kind == Kind.REQUEST_OBJECT ? "the request object" : "the client assertion";
    }

    /** Where a spent {@code jti} is recorded - the attestation replay cache, which is Redis when one is configured. */
    @FunctionalInterface
    interface ReplayGuard {
        boolean firstSeen(String clientId, String jti, long ttlSeconds);
    }
}
