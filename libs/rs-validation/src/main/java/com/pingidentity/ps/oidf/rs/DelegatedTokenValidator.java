/*
 * Validates a sender-constrained, delegated access token at the resource server.
 */
package com.pingidentity.ps.oidf.rs;

import com.pingidentity.ps.oidf.clientattestation.DpopProof;
import com.pingidentity.ps.oidf.clientattestation.DpopProofValidator;
import com.pingidentity.ps.oidf.jose.Jwks;
import com.pingidentity.ps.oidf.platform.profile.DeploymentProfile;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Base64;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.NumericDate;

/**
 * What a resource server must check before believing an agent is acting for a human.
 *
 * <ol>
 *   <li>The access token is a JWS from the authorisation server: its {@code typ} is what {@link AccessTokenType}
 *       says, its {@code alg} is permitted, its {@code kid} names exactly one of the server's keys (no fallback to
 *       trying every key), the signature verifies, {@code iss} is the issuer, {@code aud} contains this resource,
 *       {@code exp} has not passed and {@code nbf}, when present, has.</li>
 *   <li>The token is sender-constrained, and the sender proves it: {@code cnf.jkt} with a DPoP proof (RFC 9449)
 *       whose key has that thumbprint, whose {@code ath} is this token's hash, whose {@code htm} and {@code htu} are
 *       this request's, and - with {@link DpopNonces} on - whose {@code nonce} this server issued; and
 *       {@code cnf.x5t#S256} against the client certificate of the TLS connection (RFC 8705 §3). A token with
 *       neither is refused: there is no bearer mode.</li>
 *   <li>The RFC 8693 {@code act} claim is a JSON object chain ({@link ActChain}); a malformed one is refused, and
 *       so is the legacy string form unless a development deployment switched it on.</li>
 *   <li>The DPoP proof has not been seen before: the {@link ReplayStore} is asked last, once everything else has
 *       passed, and a store that cannot answer refuses the request as unavailable.</li>
 * </ol>
 *
 * <p>Refusals are {@link RsException}s carrying the RFC 6750 or RFC 9449 error code and the status;
 * {@link ResourceServerFilter} turns them into the {@code WWW-Authenticate} challenge.
 */
public final class DelegatedTokenValidator {

    /** The algorithms accepted by default, for the access token and the DPoP proof. */
    public static final Set<String> DEFAULT_ALGORITHMS = Set.of("ES256", "PS256", "RS256");
    public static final Duration DEFAULT_CLOCK_SKEW = Duration.ofSeconds(60);
    public static final Duration DEFAULT_PROOF_MAX_AGE = Duration.ofSeconds(300);

    public static final String INVALID_REQUEST = "invalid_request";
    public static final String INVALID_TOKEN = "invalid_token";
    public static final String INVALID_DPOP_PROOF = "invalid_dpop_proof";
    public static final String USE_DPOP_NONCE = "use_dpop_nonce";

    /** How the access token arrived: the {@code Authorization} scheme. */
    public enum Scheme {
        /** {@code Authorization: DPoP <token>} with a {@code DPoP} proof header (RFC 9449 §7.1). */
        DPOP,
        /** {@code Authorization: Bearer <token>}: accepted only for a certificate-bound token (RFC 8705 §3). */
        BEARER
    }

    /**
     * One request's credentials.
     *
     * @param scheme            the {@code Authorization} scheme the token came under
     * @param accessToken       the token
     * @param dpopProofs        every {@code DPoP} header value, in order; RFC 9449 §4.3 allows exactly one
     * @param method            the request's method, for {@code htm}; required
     * @param uri               the request's URI as the client addressed it, for {@code htu}; required
     * @param clientCertificate the TLS client certificate, or null when the connection presented none
     */
    public record Presentation(Scheme scheme, String accessToken, List<String> dpopProofs, String method, String uri,
                               X509Certificate clientCertificate) {
        public Presentation {
            Objects.requireNonNull(scheme, "scheme");
            dpopProofs = dpopProofs == null ? List.of() : List.copyOf(dpopProofs);
            if (method == null || method.isBlank()) {
                throw new IllegalArgumentException("the request method is required, for the DPoP htm check");
            }
            if (uri == null || uri.isBlank()) {
                throw new IllegalArgumentException("the request URI is required, for the DPoP htu check");
            }
        }
    }

    private final JwksSource keys;
    private final String expectedIssuer;
    private final String expectedAudience;
    private final Set<String> tokenAlgorithms;
    private final Set<String> proofAlgorithms;
    private final AccessTokenType tokenType;
    private final long clockSkewSeconds;
    private final long proofMaxAgeSeconds;
    private final DpopProofValidator dpop;
    private final ReplayStore replayStore;
    private final DpopNonces nonces;
    private final boolean acceptDpop;
    private final boolean acceptMtls;
    private final boolean allowLegacyStringAct;

    private DelegatedTokenValidator(Builder b) {
        this.keys = b.keys;
        this.expectedIssuer = b.expectedIssuer;
        this.expectedAudience = b.expectedAudience;
        this.tokenAlgorithms = b.tokenAlgorithms;
        this.proofAlgorithms = b.proofAlgorithms;
        this.tokenType = b.tokenType;
        this.clockSkewSeconds = b.clockSkew.toSeconds();
        this.proofMaxAgeSeconds = b.proofMaxAge.toSeconds();
        this.dpop = new DpopProofValidator(b.proofAlgorithms, (int) this.clockSkewSeconds, this.proofMaxAgeSeconds);
        this.replayStore = b.replayStore;
        this.nonces = b.nonces;
        this.acceptDpop = b.acceptDpop;
        this.acceptMtls = b.acceptMtls;
        this.allowLegacyStringAct = b.allowLegacyStringAct;
    }

    /** A builder for a validator that expects tokens from {@code expectedIssuer} for {@code expectedAudience}. */
    public static Builder builder(String expectedIssuer, String expectedAudience) {
        return new Builder(expectedIssuer, expectedAudience);
    }

    /** The DPoP proof algorithms, for the {@code algs} parameter of a DPoP challenge. */
    public Set<String> proofAlgorithms() {
        return this.proofAlgorithms;
    }

    /** Whether the DPoP scheme is accepted. */
    public boolean acceptsDpop() {
        return this.acceptDpop;
    }

    /** Whether the Bearer scheme is accepted for certificate-bound tokens. */
    public boolean acceptsMtls() {
        return this.acceptMtls;
    }

    /** The current DPoP nonce, when nonces are on. */
    public Optional<String> currentNonce() {
        return this.nonces == null ? Optional.empty() : Optional.of(this.nonces.current());
    }

    /**
     * Validates a DPoP request: {@code Authorization: DPoP <accessToken>} with one {@code DPoP} header.
     *
     * @param dpopProof the {@code DPoP} header, or null when there was none
     * @param method    the HTTP method, for {@code htm}; required
     * @param url       the request URL, for {@code htu}; required
     */
    public Result validate(String accessToken, String dpopProof, String method, String url) throws RsException {
        return this.validate(new Presentation(Scheme.DPOP, accessToken,
                dpopProof == null ? List.of() : List.of(dpopProof), method, url, null));
    }

    /** Validates a request's credentials. */
    public Result validate(Presentation p) throws RsException {
        if (p.accessToken() == null || p.accessToken().isBlank()) {
            throw new RsException(INVALID_TOKEN, 401, "no access token presented");
        }
        if (p.scheme() == Scheme.DPOP ? !this.acceptDpop : !this.acceptMtls) {
            // RFC 6750 §3.1: a request "attempted using an unsupported authentication method" carries no error.
            throw new RsException(null, 401, "this resource does not accept the " + p.scheme() + " scheme");
        }
        JwtClaims claims = this.verifyAccessToken(p.accessToken());
        Map<String, Object> claimMap = claims.getClaimsMap();
        ActChain.Parsed act = this.checkAct(ActChain.parse(claimMap));
        Confirmation cnf = confirmation(claims);

        String jti = null;
        String nextNonce = null;
        DpopProof proof = null;
        if (p.scheme() == Scheme.DPOP) {
            if (cnf.jkt() == null) {
                throw new RsException(INVALID_TOKEN, 401,
                        "the access token is not DPoP-bound (its cnf carries no jkt), so it cannot be sent as DPoP");
            }
            proof = this.checkProof(p, cnf.jkt());
            jti = proof.jti();
            nextNonce = this.checkNonce(proof);
        } else if (cnf.jkt() != null) {
            // RFC 9449 §7.2: "such a protected resource MUST reject a DPoP-bound access token received as a bearer
            // token per [RFC6750]." Otherwise the token is certificate-bound: confirmation() refuses a cnf with
            // neither member, so a Bearer token without jkt has x5t#S256, checked next.
            throw new RsException(INVALID_TOKEN, 401, "a DPoP-bound access token was sent as a bearer token");
        }
        if (cnf.x5tS256() != null) {
            checkCertificate(cnf.x5tS256(), p.clientCertificate());
        }
        if (proof != null) {
            this.checkReplay(proof, cnf.jkt());
        }
        return new Result(claims.getClaimValueAsString("sub"), act, jti, scopes(claims), claimMap, nextNonce);
    }

    // ---- the access token ---------------------------------------------------------------------------------------

    private JwtClaims verifyAccessToken(String accessToken) throws RsException {
        JsonWebSignature jws = new JsonWebSignature();
        String kid;
        String algorithm;
        String typ;
        try {
            jws.setCompactSerialization(accessToken);
            kid = jws.getKeyIdHeaderValue();
            algorithm = jws.getAlgorithmHeaderValue();
            typ = jws.getHeader("typ");
        } catch (Exception e) {
            throw new RsException(INVALID_TOKEN, 401, "access token is not a well-formed JWS");
        }
        if (!this.tokenType.accepts(typ)) {
            throw new RsException(INVALID_TOKEN, 401,
                    "access token typ is " + (typ == null ? "absent" : "'" + typ + "'") + ", not " + this.tokenType);
        }
        if (algorithm == null || !this.tokenAlgorithms.contains(algorithm)) {
            throw new RsException(INVALID_TOKEN, 401, "access token algorithm " + algorithm + " is not permitted");
        }
        PublicJsonWebKey key = this.selectKey(kid, algorithm);
        try {
            jws.setKey(key.getPublicKey());
            jws.setAlgorithmConstraints(new AlgorithmConstraints(AlgorithmConstraints.ConstraintType.PERMIT, algorithm));
            if (!jws.verifySignature()) {
                throw new RsException(INVALID_TOKEN, 401, "access token signature did not verify");
            }
        } catch (RsException e) {
            throw e;
        } catch (Exception e) {
            throw new RsException(INVALID_TOKEN, 401, "access token signature could not be verified");
        }
        JwtClaims claims;
        try {
            claims = JwtClaims.parse(jws.getUnverifiedPayload());
        } catch (Exception e) {
            throw new RsException(INVALID_TOKEN, 401, "access token payload is not valid JWT claims");
        }
        this.checkClaims(claims);
        return claims;
    }

    /**
     * The one key the token names. RFC 9068 §4: "The resource server MUST use the keys provided by the authorization
     * server." A token without a {@code kid}, a {@code kid} the server does not publish, a {@code kid} two published
     * keys share, and a key whose own {@code alg} or type does not fit the token's algorithm are all refused: the
     * token is checked against the key it names, or not at all.
     */
    private PublicJsonWebKey selectKey(String kid, String algorithm) throws RsException {
        if (kid == null || kid.isEmpty()) {
            throw new RsException(INVALID_TOKEN, 401, "access token carries no kid, so no key is named to verify it");
        }
        List<PublicJsonWebKey> candidates;
        try {
            candidates = this.keys.keys(kid);
        } catch (IOException e) {
            throw new RsException(null, 503, "the authorisation server's keys are unavailable: " + e.getMessage());
        }
        if (candidates.isEmpty()) {
            throw new RsException(INVALID_TOKEN, 401, "no authorisation server key matches the token kid: " + kid);
        }
        if (candidates.size() > 1) {
            throw new RsException(INVALID_TOKEN, 401, "more than one authorisation server key has the kid " + kid);
        }
        PublicJsonWebKey key = candidates.get(0);
        String keyType = algorithm.startsWith("ES") ? "EC" : "RSA";
        if (!keyType.equals(key.getKeyType()) || key.getAlgorithm() != null && !algorithm.equals(key.getAlgorithm())) {
            throw new RsException(INVALID_TOKEN, 401, "the key " + kid + " is not for " + algorithm);
        }
        return key;
    }

    private void checkClaims(JwtClaims claims) throws RsException {
        try {
            if (!this.expectedIssuer.equals(claims.getIssuer())) {
                throw new RsException(INVALID_TOKEN, 401, "access token issuer is not the expected AS");
            }
            // jose4j reads an absent aud as an empty list; were it ever null, the catch below refuses the token.
            if (!claims.getAudience().contains(this.expectedAudience)) {
                throw new RsException(INVALID_TOKEN, 401, "access token audience is not this resource");
            }
            long now = NumericDate.now().getValue();
            NumericDate exp = claims.getExpirationTime();
            if (exp == null || exp.getValue() + this.clockSkewSeconds < now) {
                throw new RsException(INVALID_TOKEN, 401, "access token has expired");
            }
            NumericDate nbf = claims.getNotBefore();
            if (nbf != null && nbf.getValue() - this.clockSkewSeconds > now) {
                throw new RsException(INVALID_TOKEN, 401, "access token is not valid yet (nbf)");
            }
        } catch (RsException e) {
            throw e;
        } catch (Exception e) {
            throw new RsException(INVALID_TOKEN, 401, "access token claims are malformed");
        }
    }

    /**
     * RFC 8693 §4.1: "The "act" claim value is a JSON object". A chain that is malformed is refused, and the legacy
     * string form is refused unless development switched it on ({@link Builder#allowLegacyStringAct}).
     */
    private ActChain.Parsed checkAct(ActChain.Parsed act) throws RsException {
        if (act.malformed()) {
            throw new RsException(INVALID_TOKEN, 401, "access token act claim is not an RFC 8693 actor chain");
        }
        if (act.legacyStringForm() && !this.allowLegacyStringAct) {
            throw new RsException(INVALID_TOKEN, 401,
                    "access token act claim is a string; RFC 8693 section 4.1 makes it a JSON object");
        }
        return act;
    }

    /** The token's confirmation members this server checks. */
    record Confirmation(String jkt, String x5tS256) {
    }

    static Confirmation confirmation(JwtClaims claims) throws RsException {
        Object cnf = claims.getClaimValue("cnf");
        if (!(cnf instanceof Map<?, ?> members)) {
            throw new RsException(INVALID_TOKEN, 401, "access token carries no cnf, so it is not sender-constrained");
        }
        String jkt = member(members, "jkt");
        String x5t = member(members, "x5t#S256");
        if (jkt == null && x5t == null) {
            throw new RsException(INVALID_TOKEN, 401, "access token cnf carries neither jkt nor x5t#S256");
        }
        return new Confirmation(jkt, x5t);
    }

    private static String member(Map<?, ?> cnf, String name) throws RsException {
        Object value = cnf.get(name);
        if (value == null) {
            return null;
        }
        if (!(value instanceof String text) || text.isEmpty()) {
            throw new RsException(INVALID_TOKEN, 401, "access token cnf " + name + " is not a string");
        }
        return text;
    }

    // ---- the DPoP proof -----------------------------------------------------------------------------------------

    private DpopProof checkProof(Presentation p, String jkt) throws RsException {
        if (p.dpopProofs().isEmpty()) {
            // A missing proof is not "fall back to bearer": on this path there is no bearer mode.
            throw new RsException(INVALID_TOKEN, 401,
                    "no DPoP proof presented; this resource accepts only sender-constrained tokens");
        }
        if (p.dpopProofs().size() > 1) {
            throw new RsException(INVALID_DPOP_PROOF, 401, "more than one DPoP header");
        }
        DpopProof proof;
        try {
            proof = this.dpop.validate(p.dpopProofs().get(0), p.method(), p.uri());
        } catch (Exception e) {
            throw new RsException(INVALID_DPOP_PROOF, 401, "DPoP proof rejected: " + e.getMessage());
        }
        // The check that makes sender-constraining mean anything.
        if (!jkt.equals(thumbprint(proof))) {
            throw new RsException(INVALID_TOKEN, 401,
                    "the access token is bound to a different key than the DPoP proof presents");
        }
        // Without ath, a proof captured for one token is replayable against any other token bound to the same key.
        if (proof.ath() == null || proof.ath().isBlank()) {
            throw new RsException(INVALID_DPOP_PROOF, 401,
                    "DPoP proof carries no 'ath', so it is not bound to this access token");
        }
        if (!accessTokenHash(p.accessToken()).equals(proof.ath())) {
            throw new RsException(INVALID_DPOP_PROOF, 401, "DPoP proof 'ath' is for a different access token");
        }
        return proof;
    }

    /** The RFC 7638 thumbprint of the proof's key, which DpopProofValidator has already parsed as a public JWK. */
    private static String thumbprint(DpopProof proof) throws RsException {
        try {
            return Jwks.thumbprint(proof.jwk());
        } catch (Exception e) {
            throw new RsException(INVALID_DPOP_PROOF, 401, "DPoP proof key is not a well-formed JWK");
        }
    }

    /** The nonce the response should carry for the client's next proof, or null. */
    private String checkNonce(DpopProof proof) throws RsException {
        if (this.nonces == null) {
            return null;
        }
        if (proof.nonce() == null) {
            throw new RsException(USE_DPOP_NONCE, 401, "Resource server requires nonce in DPoP proof",
                    this.nonces.current());
        }
        DpopNonces.Check check = this.nonces.check(proof.nonce());
        if (check == DpopNonces.Check.INVALID) {
            throw new RsException(USE_DPOP_NONCE, 401, "DPoP proof nonce is not current", this.nonces.current());
        }
        return check == DpopNonces.Check.PREVIOUS ? this.nonces.current() : null;
    }

    /**
     * RFC 8705 §3: "The protected resource MUST obtain, from its TLS implementation layer, the client certificate used
     * for mutual TLS and MUST verify that the certificate matches the certificate associated with the access token.
     * If they do not match, the resource access attempt MUST be rejected with an error, per [RFC6750], using an HTTP
     * 401 status code and the "invalid_token" error code."
     */
    static void checkCertificate(String x5tS256, X509Certificate certificate) throws RsException {
        if (certificate == null) {
            throw new RsException(INVALID_TOKEN, 401,
                    "the access token is certificate-bound and the connection presented no client certificate");
        }
        byte[] presented;
        try {
            presented = sha256(certificate.getEncoded());
        } catch (CertificateEncodingException e) {
            throw new RsException(INVALID_TOKEN, 401, "the client certificate could not be encoded");
        }
        byte[] bound;
        try {
            bound = Base64.getUrlDecoder().decode(x5tS256);
        } catch (IllegalArgumentException e) {
            throw new RsException(INVALID_TOKEN, 401, "access token cnf x5t#S256 is not base64url");
        }
        if (!MessageDigest.isEqual(presented, bound)) {
            throw new RsException(INVALID_TOKEN, 401,
                    "the access token is bound to a different certificate than the connection presented");
        }
    }

    /**
     * Refuses a proof this server has accepted before. RFC 9449 §11.1: "servers can store the jti value of each DPoP
     * proof for the time window in which the respective DPoP proof JWT would be accepted to prevent multiple uses of
     * the same DPoP proof." The key is {@link #replayKey}; the window is how much longer the proof would pass the
     * freshness check.
     */
    private void checkReplay(DpopProof proof, String jkt) throws RsException {
        boolean first;
        try {
            first = this.replayStore.firstUse(replayKey(jkt, proof.jti()),
                    replayWindow(proof.iatEpochSeconds(), System.currentTimeMillis(), this.proofMaxAgeSeconds,
                            this.clockSkewSeconds));
        } catch (IOException e) {
            throw new RsException(null, 503, "the DPoP replay store is unavailable: " + e.getMessage());
        }
        if (!first) {
            throw new RsException(INVALID_DPOP_PROOF, 401, "DPoP proof has been used before");
        }
    }

    /**
     * The replay key: base64url(SHA-256(jkt ":" jti)). A hash, so a large {@code jti} costs the store nothing, and
     * scoped to the proof's key, so a party that sees another client's {@code jti} cannot spend it first. It is not
     * scoped to the target URI, which RFC 9449 §11.1 allows: a {@code jti} is refused at every URI once seen.
     */
    static String replayKey(String jkt, String jti) {
        return Base64.getUrlEncoder().withoutPadding()
                .encodeToString(sha256((jkt + ":" + jti).getBytes(StandardCharsets.UTF_8)));
    }

    /**
     * How long a proof issued at {@code iat} stays acceptable after {@code nowMillis}: {@code DpopProofValidator}
     * accepts it until {@code iat + maxAge + skew} seconds, and a second more covers the rounding of {@code iat} to
     * whole seconds. Never less than a second.
     */
    static Duration replayWindow(long iat, long nowMillis, long maxAgeSeconds, long skewSeconds) {
        long until = (iat + maxAgeSeconds + skewSeconds + 1) * 1000L;
        return Duration.ofMillis(Math.max(until - nowMillis, 1000L));
    }

    /** RFC 9449 {@code ath}: base64url(SHA-256(access token)), over the ASCII of the compact form. */
    static String accessTokenHash(String accessToken) {
        return Base64.getUrlEncoder().withoutPadding()
                .encodeToString(sha256(accessToken.getBytes(StandardCharsets.US_ASCII)));
    }

    private static byte[] sha256(byte[] input) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(input);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    private static List<String> scopes(JwtClaims claims) {
        String scope = claims.getClaimValueAsString("scope");
        return scope == null || scope.isBlank() ? List.of() : List.of(scope.trim().split("\\s+"));
    }

    // ---- building -----------------------------------------------------------------------------------------------

    /** Builds a {@link DelegatedTokenValidator}. The keys and the replay store are required. */
    public static final class Builder {
        private final String expectedIssuer;
        private final String expectedAudience;
        private JwksSource keys;
        private ReplayStore replayStore;
        private Set<String> tokenAlgorithms = DEFAULT_ALGORITHMS;
        private Set<String> proofAlgorithms = DEFAULT_ALGORITHMS;
        private AccessTokenType tokenType = AccessTokenType.RFC9068;
        private Duration clockSkew = DEFAULT_CLOCK_SKEW;
        private Duration proofMaxAge = DEFAULT_PROOF_MAX_AGE;
        private DpopNonces nonces;
        private boolean acceptDpop = true;
        private boolean acceptMtls;
        private boolean allowLegacyStringAct;

        private Builder(String expectedIssuer, String expectedAudience) {
            this.expectedIssuer = Objects.requireNonNull(expectedIssuer, "expectedIssuer");
            this.expectedAudience = Objects.requireNonNull(expectedAudience, "expectedAudience");
        }

        /** Where the authorisation server's keys come from: {@link RemoteJwks}, or {@link StaticJwks}. */
        public Builder keys(JwksSource source) {
            this.keys = Objects.requireNonNull(source, "keys");
            return this;
        }

        /** A fixed set of the authorisation server's public keys. */
        public Builder keys(Collection<? extends JsonWebKey> fixed) {
            return this.keys(new StaticJwks(fixed));
        }

        /** Required: where accepted DPoP proofs are remembered. */
        public Builder replayStore(ReplayStore store) {
            this.replayStore = Objects.requireNonNull(store, "replayStore");
            return this;
        }

        /** The access token's permitted {@code alg} values; {@link #DEFAULT_ALGORITHMS} by default. */
        public Builder tokenAlgorithms(Set<String> algorithms) {
            this.tokenAlgorithms = asymmetric(algorithms);
            return this;
        }

        /** The DPoP proof's permitted {@code alg} values; {@link #DEFAULT_ALGORITHMS} by default. */
        public Builder proofAlgorithms(Set<String> algorithms) {
            this.proofAlgorithms = asymmetric(algorithms);
            return this;
        }

        /** The {@code typ} the access token must carry; {@link AccessTokenType#RFC9068} by default. */
        public Builder accessTokenType(AccessTokenType type) {
            this.tokenType = Objects.requireNonNull(type, "type");
            return this;
        }

        /** Leeway for {@code exp}, {@code nbf} and a proof's {@code iat}; 60 s by default, at most 5 minutes. */
        public Builder clockSkew(Duration skew) {
            if (skew.isNegative() || skew.compareTo(Duration.ofMinutes(5)) > 0) {
                throw new IllegalArgumentException("clock skew must be between 0 and 5 minutes, not " + skew);
            }
            this.clockSkew = skew;
            return this;
        }

        /** How long after its {@code iat} a DPoP proof is accepted; 300 s by default, 1 s to 1 hour. */
        public Builder proofMaxAge(Duration maxAge) {
            if (maxAge.compareTo(Duration.ofSeconds(1)) < 0 || maxAge.compareTo(Duration.ofHours(1)) > 0) {
                throw new IllegalArgumentException("a DPoP proof's maximum age must be between 1 s and 1 hour, not "
                        + maxAge);
            }
            this.proofMaxAge = maxAge;
            return this;
        }

        /** Requires DPoP nonces this server issued (RFC 9449 §9); off by default. */
        public Builder nonces(DpopNonces value) {
            this.nonces = Objects.requireNonNull(value, "nonces");
            return this;
        }

        /** Whether the DPoP scheme is accepted; on by default. */
        public Builder dpop(boolean accept) {
            this.acceptDpop = accept;
            return this;
        }

        /** Whether a certificate-bound token is accepted under the Bearer scheme (RFC 8705 §3); off by default. */
        public Builder mtls(boolean accept) {
            this.acceptMtls = accept;
            return this;
        }

        /**
         * Accepts the legacy string form of {@code act} - a JSON object serialised into a string - which RFC 8693
         * §4.1 does not allow and this platform's PingFederate mapping once emitted. Development only: refused under
         * the production profile, so a deployment cannot carry the deviation into production by accident.
         *
         * @param profile the deployment profile, normally {@link DeploymentProfile#current()}
         * @throws IllegalStateException under the production profile
         */
        public Builder allowLegacyStringAct(DeploymentProfile profile) {
            if (Objects.requireNonNull(profile, "profile").isProduction()) {
                throw new IllegalStateException("the legacy string form of act is accepted only under "
                        + DeploymentProfile.SETTING + "=development; production requires the RFC 8693 JSON object");
            }
            this.allowLegacyStringAct = true;
            return this;
        }

        /**
         * @throws IllegalStateException without keys or a replay store, or with neither scheme accepted
         */
        public DelegatedTokenValidator build() {
            if (this.keys == null) {
                throw new IllegalStateException("the authorisation server's keys are required");
            }
            if (this.replayStore == null) {
                throw new IllegalStateException("a replay store is required: RFC 9449 section 11.1 proofs are"
                        + " accepted once (InMemoryReplayStore for one node, RedisReplayStore for more)");
            }
            if (!this.acceptDpop && !this.acceptMtls) {
                throw new IllegalStateException("accept DPoP, mTLS-bound tokens, or both");
            }
            return new DelegatedTokenValidator(this);
        }

        private static Set<String> asymmetric(Set<String> algorithms) {
            Set<String> copy = Set.copyOf(algorithms);
            for (String alg : copy) {
                if (!alg.matches("(ES|RS|PS)(256|384|512)")) {
                    throw new IllegalArgumentException("only ES, RS and PS algorithms are accepted, not " + alg);
                }
            }
            if (copy.isEmpty()) {
                throw new IllegalArgumentException("at least one algorithm is required");
            }
            return copy;
        }
    }

    // ---- results ------------------------------------------------------------------------------------------------

    /**
     * A validated request.
     *
     * @param dpopJti       the accepted proof's {@code jti}, already recorded in the replay store; null for an
     *                      mTLS-bound token
     * @param nextDpopNonce the nonce the response should carry in {@code DPoP-Nonce}, or null when the client's is
     *                      current
     */
    public record Result(String subject, ActChain.Parsed act, String dpopJti, List<String> scopes,
                         Map<String, Object> claims, String nextDpopNonce) {

        /** Whether an agent is acting here at all, as opposed to a human calling directly. */
        public boolean isDelegated() {
            return !this.act.isEmpty();
        }

        /** The acting agent instance, when delegated. The only actor that may be authorised on. */
        public Optional<String> actingInstance() {
            return this.act.currentActor().map(ActChain.Actor::subject);
        }

        /** What a demo endpoint can safely echo: no device data, no raw token. */
        public Map<String, Object> describe() {
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("subject", this.subject);
            out.put("delegated", isDelegated());
            out.put("acting_instance", actingInstance().orElse(null));
            out.put("prior_actors", this.act.priorActors().stream().map(ActChain.Actor::subject).toList());
            out.put("scopes", this.scopes);
            out.put("act_legacy_string_form", this.act.legacyStringForm());
            return out;
        }
    }

    /**
     * A refusal, with the error code a {@code WWW-Authenticate} challenge carries: {@code invalid_request},
     * {@code invalid_token} (RFC 6750 §3.1), {@code invalid_dpop_proof} or {@code use_dpop_nonce} (RFC 9449 §7.1,
     * §9). {@link #error()} is null when there is no code to send - a request that used a scheme this resource does
     * not accept (401) and a store or key source that could not answer (503).
     */
    public static class RsException extends Exception {
        private static final long serialVersionUID = 1L;

        private final String error;
        private final int status;
        private final String dpopNonce;

        public RsException(String error, int status, String message) {
            this(error, status, message, null);
        }

        public RsException(String error, int status, String message, String dpopNonce) {
            super(message);
            this.error = error;
            this.status = status;
            this.dpopNonce = dpopNonce;
        }

        public String error() {
            return this.error;
        }

        public int status() {
            return this.status;
        }

        /** The nonce for a {@code DPoP-Nonce} header, with {@code use_dpop_nonce}; otherwise null. */
        public String dpopNonce() {
            return this.dpopNonce;
        }
    }
}
