/*
 * Orchestrates attestation-based client authentication (draft-ietf-oauth-attestation-based-client-auth).
 */
package com.pingidentity.ps.oidf.clientattestation;

import java.security.Key;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwt.JwtClaims;
import com.pingidentity.ps.oidf.jose.Jwks;
import com.pingidentity.ps.oidf.jose.JwtCodec;
import com.pingidentity.ps.oidf.jose.JwtVerificationException;
import com.pingidentity.ps.oidf.jose.Claims;
import com.pingidentity.ps.oidf.rar.model.RarModels;

/**
 * Verifies an attestation-based client authentication ({@code attest_jwt_client_auth}), in either
 * proof-of-possession method of draft -10:
 * <ul>
 *   <li>{@code attestation_pop_jwt} — a Client Attestation JWT plus a dedicated Client Attestation
 *       PoP JWT (headers {@code OAuth-Client-Attestation} + {@code OAuth-Client-Attestation-PoP}); and</li>
 *   <li>{@code dpop_combined} — DPoP combined mode: a Client Attestation JWT plus a DPoP proof
 *       (headers {@code OAuth-Client-Attestation} + {@code DPoP}, and no PoP header), where the DPoP key
 *       must equal the attestation {@code cnf} key.</li>
 * </ul>
 *
 * <p>Trust in the Attester comes solely from {@link AttesterKeyResolver}; the proof of possession is
 * bound to the attestation's {@code cnf} key; freshness/replay are enforced via {@link AttestationReplayCache}
 * and (optionally) {@link AttestationChallengeService}.
 */
public final class ClientAttestationVerifier {
    private static final Log LOGGER = LogFactory.getLog(ClientAttestationVerifier.class);
    /** Required-claim names already warned about. Static because the verifier is built per request. */
    private static final Set<String> WARNED_UNKNOWN_REQUIRED_CLAIMS = ConcurrentHashMap.newKeySet();
    /** Bound on the above so a misconfigured deployment cannot grow it without limit. */
    private static final int MAX_WARNED_UNKNOWN_REQUIRED_CLAIMS = 64;
    private static final String ATTESTATION_TYP = "oauth-client-attestation+jwt";
    private static final String POP_TYP = "oauth-client-attestation-pop+jwt";

    private final AttesterKeyResolver attesterKeyResolver;
    private final ClientAttestationConfig config;
    private final AttestationReplayCache replayCache;
    private final AttestationChallengeService challengeService;
    private final RarModels rarModels;

    /**
     * A verifier that checks {@code authorization_details} with this classloader's model set
     * ({@link AttestationRarModels}).
     *
     * @throws IllegalStateException when that model set could not be loaded
     */
    public ClientAttestationVerifier(AttesterKeyResolver attesterKeyResolver, ClientAttestationConfig config,
                                     AttestationReplayCache replayCache, AttestationChallengeService challengeService) {
        this(attesterKeyResolver, config, replayCache, challengeService, AttestationRarModels.require());
    }

    private ClientAttestationVerifier(AttesterKeyResolver attesterKeyResolver, ClientAttestationConfig config,
                                      AttestationReplayCache replayCache, AttestationChallengeService challengeService,
                                      RarModels rarModels) {
        this.attesterKeyResolver = Objects.requireNonNull(attesterKeyResolver, "attesterKeyResolver");
        this.config = Objects.requireNonNull(config, "config");
        this.replayCache = Objects.requireNonNull(replayCache, "replayCache");
        this.challengeService = challengeService;
        this.rarModels = Objects.requireNonNull(rarModels, "rarModels");
    }

    /**
     * A verifier that checks {@code authorization_details} with the model set given: the one a component loaded
     * at start-up, so a request never meets a model set it could not load. A factory rather than a second public
     * constructor, because the flow harness builds a verifier from {@code getConstructors()[0]}.
     */
    public static ClientAttestationVerifier withRarModels(AttesterKeyResolver attesterKeyResolver,
                                                          ClientAttestationConfig config,
                                                          AttestationReplayCache replayCache,
                                                          AttestationChallengeService challengeService,
                                                          RarModels rarModels) {
        return new ClientAttestationVerifier(attesterKeyResolver, config, replayCache, challengeService, rarModels);
    }

    /**
     * Verifies the presented attestation + proof of possession.
     *
     * @param attestationHeader  the {@code OAuth-Client-Attestation} value (required)
     * @param popHeader          the {@code OAuth-Client-Attestation-PoP} value (PoP-JWT mode), or null
     * @param dpopHeader         the {@code DPoP} value (combined mode), or null
     * @param requestMethod      the HTTP method of the token request (for DPoP {@code htm}), or null
     * @param requestUri         the URL of the endpoint the request was sent to, as this server's configuration
     *                           gives it - never one rebuilt from the {@code Host} header - for the DPoP
     *                           {@code htu} when the config names no {@link ClientAttestationConfig#expectedHtu()};
     *                           with neither, DPoP combined mode is refused
     * @param requestedClientId  the {@code client_id} request parameter, if any, to cross-check {@code sub}
     * @return the authenticated client identity and confirmed key
     * @throws ClientAttestationException with the appropriate OAuth error code on any failure
     */
    public ClientAttestationResult verify(String attestationHeader, String popHeader, String dpopHeader,
                                          String requestMethod, String requestUri, String requestedClientId)
            throws ClientAttestationException {
        return this.verify(attestationHeader, popHeader, dpopHeader, requestMethod, requestUri, requestedClientId, null);
    }

    /**
     * As {@link #verify(String, String, String, String, String, String)}, additionally checking the request's
     * RFC 9396 {@code authorization_details} against the attestation's own, strictly
     * ({@link AuthorizationDetailsGate}: CAS §7.1). Authentication (attestation + proof of possession) is verified
     * first; only then is the requested access checked. The returned result carries the attestation's details,
     * the granted ones (the request's own, without this repository's two markers) and the fingerprint of the
     * model set that checked them.
     *
     * @param requestedAuthorizationDetailsJson the {@code authorization_details} request parameter (JSON array), or null
     */
    public ClientAttestationResult verify(String attestationHeader, String popHeader, String dpopHeader,
                                          String requestMethod, String requestUri, String requestedClientId,
                                          String requestedAuthorizationDetailsJson)
            throws ClientAttestationException {
        try {
            if (attestationHeader == null || attestationHeader.isBlank()) {
                throw ClientAttestationException.invalidClient("Missing OAuth-Client-Attestation header");
            }
            boolean hasPop = popHeader != null && !popHeader.isBlank();
            boolean hasDpop = dpopHeader != null && !dpopHeader.isBlank();
            // A PoP JWT present means PoP mode, even when a DPoP proof rides along. draft-ietf-oauth-
            // attestation-based-client-auth-11 §5.2: "DPoP can also be used alongside the Client Attestation
            // PoP JWT without this combined mode. In this case, the DPoP proof is validated according to
            // [RFC9449] independently of this specification and its public key is not required to match the
            // key in the cnf claim." Combined mode is the DPoP proof standing in for a missing PoP JWT. This
            // used to reject the pair outright, which left a client that keeps its client-authentication key
            // and its token-binding (DPoP) key apart - as the three-key rule asks - unable to obtain a
            // sender-constrained token at all. The DPoP header stays on the request for the AS to process.
            if (!hasPop && !hasDpop) {
                throw ClientAttestationException.invalidClient(
                        "Missing proof of possession: provide OAuth-Client-Attestation-PoP or DPoP");
            }

            // '~' marks the retired SD-JWT presentation encoding; only plain attestation JWTs are accepted.
            if (attestationHeader.contains("~")) {
                throw ClientAttestationException.invalidClient(
                        "SD-JWT-encoded client attestations are no longer supported; present a plain attestation JWT");
            }
            ClientAttestation attestation = this.verifyAttestation(attestationHeader);
            Jwks.assertPublicOnly(attestation.cnfJwk());

            if (requestedClientId != null && !requestedClientId.isBlank()
                    && !requestedClientId.equals(attestation.clientId())) {
                throw ClientAttestationException.invalidClient(
                        "client_id request parameter does not match the attestation 'sub'");
            }

            // Reject an attestation that omits a claim this AS declares it requires (e.g. workload).
            this.enforceRequiredDisclosures(attestation);

            // Authenticate (attestation + proof of possession) first ...
            ClientAttestationResult authenticated = hasPop
                    ? this.verifyPopMode(attestation, popHeader)
                    : this.verifyDpopMode(attestation, dpopHeader, requestMethod, requestUri);

            // ... then check the requested access against the attestation's own (CAS §7.1).
            List<Map<String, Object>> granted = AuthorizationDetailsGate.check(this.rarModels,
                    requestedAuthorizationDetailsJson, attestationHeader);
            return new ClientAttestationResult(authenticated.clientId(), authenticated.cnfJwk(),
                    authenticated.mode(), authenticated.attesterIssuer(), authenticated.proofJti(),
                    attestation.authorizationDetails(), granted, attestation.workload(), attestation.agentId(),
                    this.rarModels.fingerprint());
        } catch (ClientAttestationException e) {
            throw e;
        } catch (Exception e) {
            throw ClientAttestationException.invalidClient(
                    "Attestation-based client authentication failed: " + e.getMessage(), e);
        }
    }

    /**
     * Enforces the AS's required-claims policy: every claim named in
     * {@link ClientAttestationConfig#requiredDisclosedClaims()} must be present and non-empty in the
     * attestation. Lets an AS declare, per its position in the federation, which claims it needs and
     * reject an attestation minted without them. Known groups: {@code workload},
     * {@code authorization_details} and {@code agent_id}; an unrecognised name is treated as
     * satisfied and warned about once - see {@link #warnUnknownRequiredClaim(String)} for why it is
     * not rejected.
     */
    private void enforceRequiredDisclosures(ClientAttestation attestation) throws ClientAttestationException {
        for (String claim : this.config.requiredDisclosedClaims()) {
            boolean present;
            switch (claim) {
                case "workload":
                    present = attestation.workload() != null && !attestation.workload().isEmpty();
                    break;
                case "authorization_details":
                    present = attestation.authorizationDetails() != null && !attestation.authorizationDetails().isEmpty();
                    break;
                case "agent_id":
                    present = attestation.agentId() != null && !attestation.agentId().isBlank();
                    break;
                default:
                    // Unrecognised names are treated as satisfied, so a typo in a client's
                    // extproperties.attestation_required_claims silently disables the requirement
                    // rather than enforcing it. Kept permissive deliberately - this config is built
                    // per authentication request from per-client properties, so rejecting here would
                    // fail that client's authentication in production rather than at startup - but
                    // warned so the misconfiguration is visible instead of silent.
                    present = true;
                    ClientAttestationVerifier.warnUnknownRequiredClaim(claim);
            }
            if (!present) {
                throw ClientAttestationException.insufficientDisclosure(
                        "attestation does not disclose the AS-required claim '" + claim + "'");
            }
        }
    }

    /**
     * Warns, once per distinct name, that a required-claim name is not recognised and so is not being
     * enforced. Deduplicated through a static set because a new verifier is constructed for every
     * authentication request; bounded by {@link #MAX_WARNED_UNKNOWN_REQUIRED_CLAIMS}, past which
     * further distinct names go unwarned rather than growing the set without limit.
     */
    private static void warnUnknownRequiredClaim(String claim) {
        if (WARNED_UNKNOWN_REQUIRED_CLAIMS.size() >= MAX_WARNED_UNKNOWN_REQUIRED_CLAIMS
                || !WARNED_UNKNOWN_REQUIRED_CLAIMS.add(claim)) {
            return;
        }
        LOGGER.warn((Object) ("required-claims policy names '" + claim + "', which is not a recognised "
                + "claim name and is therefore treated as satisfied - the requirement is NOT being "
                + "enforced. Recognised names: workload, authorization_details, agent_id. Check "
                + "extproperties.attestation_required_claims and the oidf.attestation.required.claims "
                + "system property for a typo."));
    }

    private ClientAttestation verifyAttestation(String attestationHeader) throws Exception {
        Map<String, Object> headers = JwtCodec.getJwtHeaders(attestationHeader);
        JwtCodec.requireType(headers, ATTESTATION_TYP);
        JwtClaims unverified = JwtCodec.parseUnverifiedClaims(attestationHeader);
        String attesterIssuer = Claims.requireNonBlank(unverified.getIssuer(), "iss");
        List<String> trustChain = ClientAttestationVerifier.trustChainHeader(headers);

        List<JsonWebKey> attesterKeys = this.attesterKeyResolver.resolve(attesterIssuer, trustChain);

        JwtClaims verified;
        try {
            verified = JwtCodec.verifyAgainstKeys(attestationHeader, attesterKeys, attesterIssuer, this.config.attestationAlgorithms());
        } catch (JwtVerificationException e) {
            if (e.isExpired()) {
                throw ClientAttestationException.useFreshAttestation("Client Attestation has expired");
            }
            // JwtVerificationException's message is a fixed sentence per reason: it never carries the
            // attestation or its claims, so it is safe in error_description and in the log.
            throw ClientAttestationException.invalidClient("Client Attestation verification failed: " + e.getMessage(), e);
        }
        ClientAttestation attestation = ClientAttestation.fromVerifiedClaims(verified, attestationHeader);
        this.enforceLifetimeCeiling(attestation);
        return attestation;
    }

    /**
     * Rejects an attestation the attester minted with a longer life than this AS accepts. {@code exp}
     * itself is already enforced during signature verification; this bounds {@code exp - iat}, which is
     * how long a stale posture may be presented as current. Disabled unless
     * {@link ClientAttestationConfig#maxAttestationLifetimeSeconds()} is set.
     *
     * <p>A missing {@code iat} is rejected rather than exempted: the ceiling cannot be evaluated
     * without one, so skipping the check would let an attester escape the policy by omitting a claim.
     */
    private void enforceLifetimeCeiling(ClientAttestation attestation) throws ClientAttestationException {
        long ceiling = this.config.maxAttestationLifetimeSeconds();
        if (ceiling <= ClientAttestationConfig.NO_MAX_ATTESTATION_LIFETIME) {
            return;
        }
        long iat = attestation.iatEpochSeconds();
        if (iat <= 0L) {
            throw ClientAttestationException.invalidClient(
                    "Client Attestation has no 'iat'; its lifetime cannot be checked against the "
                            + ceiling + "s ceiling this AS enforces");
        }
        long lifetime = attestation.expEpochSeconds() - iat;
        if (lifetime > ceiling) {
            throw ClientAttestationException.invalidClient(
                    "Client Attestation lifetime " + lifetime + "s exceeds the " + ceiling
                            + "s ceiling this AS enforces");
        }
    }

    private ClientAttestationResult verifyPopMode(ClientAttestation attestation, String popHeader) throws Exception {
        String expectedAudience = this.config.expectedAudience();
        if (expectedAudience == null) {
            throw ClientAttestationException.invalidClient("Server misconfigured: no expected PoP audience");
        }
        Map<String, Object> headers = JwtCodec.getJwtHeaders(popHeader);
        JwtCodec.requireType(headers, POP_TYP);
        Key cnfKey = Jwks.publicKey(attestation.cnfJwk());

        JwtClaims pop;
        try {
            pop = JwtCodec.verifyAttestationPop(popHeader, cnfKey, this.config.popAlgorithms(),
                    Set.of(expectedAudience), this.config.allowedClockSkewSeconds());
        } catch (JwtVerificationException e) {
            if (e.reason() == JwtVerificationException.Reason.AUDIENCE) {
                throw ClientAttestationException.invalidClient(WRONG_POP_AUDIENCE, e);
            }
            throw ClientAttestationException.invalidClient("Client Attestation PoP verification failed: " + e.getMessage(), e);
        }
        // jose4j accepts an aud that CONTAINS an expected value, so ["<this issuer>", "<anyone>"] got through
        // it. The draft allows one audience, and it is this server.
        ClientAttestationVerifier.requireSoleAudience(pop, expectedAudience);

        String popIssuer = pop.hasClaim("iss") ? pop.getIssuer() : null;
        if (popIssuer != null && !popIssuer.equals(attestation.clientId())) {
            throw ClientAttestationException.invalidClient("PoP 'iss' does not match the attestation 'sub'");
        }
        long iat = pop.getIssuedAt().getValue();
        this.assertFresh(iat, this.config.popMaxAgeSeconds(), "PoP");

        String challenge = pop.hasClaim("challenge") ? pop.getStringClaimValue("challenge") : null;
        this.enforceChallenge(challenge);

        String jti = pop.getJwtId();
        this.enforceNoReplay(attestation.clientId(), jti, this.config.popMaxAgeSeconds());

        LOGGER.debug((Object) ("attestation PoP verified for client_id=" + attestation.clientId()));
        return new ClientAttestationResult(attestation.clientId(), attestation.cnfJwk(),
                ClientAttestationResult.Mode.POP_JWT, attestation.attesterIssuer(), jti,
                java.util.List.of(), java.util.List.of(), attestation.workload(), attestation.agentId());
    }

    /**
     * Refuses a PoP whose {@code aud} is anything but {@code expected} alone.
     *
     * <p>draft-ietf-oauth-attestation-based-client-auth-10 §5.1: "aud: REQUIRED. The aud (audience) claim MUST
     * specify a value that identifies the intended audience of the JWT. When the JWT is presented to an
     * Authorization Server, the [RFC8414] issuer identifier URL of the Authorization Server MUST be used. [...]
     * A Client Attestation PoP JWT is intended for a single audience, Clients MUST generate JWTs for each
     * target." §7.2, item 7: "The audience claim in the Client Attestation PoP JWT identifies the receiving
     * server: when validated by an Authorization Server, it MUST be the issuer identifier URL of the
     * Authorization Server as described in [RFC8414]".
     *
     * <p>What that leaves: the issuer as a string, or as the one member of an array. The draft asks for "a
     * value" and never says "as a string", and RFC 7519 §4.1.3 writes one audience either way: "In the general
     * case, the "aud" value is an array of case-sensitive strings [...] In the special case when the JWT has
     * one audience, the "aud" value MAY be a single case-sensitive string". An array with a second member,
     * even a second copy of the issuer, is not a single audience; the token endpoint URL is not the issuer
     * identifier. The comparison is exact: RFC 7519 compares StringOrURI values "as case-sensitive strings
     * with no transformations or canonicalizations applied" (§2), so a trailing slash or a change of case is
     * another audience.
     */
    static void requireSoleAudience(JwtClaims pop, String expected) throws Exception {
        List<String> audiences = pop.getAudience();
        if (audiences.size() != 1 || !expected.equals(audiences.get(0))) {
            throw ClientAttestationException.invalidClient(WRONG_POP_AUDIENCE);
        }
    }

    /** Every refusal of a PoP's {@code aud} says the same thing, whichever check found it. */
    static final String WRONG_POP_AUDIENCE =
            "Client Attestation PoP 'aud' must be this server's issuer identifier and nothing else";

    private ClientAttestationResult verifyDpopMode(ClientAttestation attestation, String dpopHeader,
                                                   String requestMethod, String requestUri) throws Exception {
        DpopProofValidator validator = new DpopProofValidator(this.config.dpopAlgorithms(),
                this.config.allowedClockSkewSeconds(), this.config.dpopMaxAgeSeconds());
        String expectedHtm = requestMethod != null && !requestMethod.isBlank() ? requestMethod : this.config.expectedHtm();
        String expectedHtu = this.config.expectedHtu() != null ? this.config.expectedHtu() : requestUri;
        // DpopProofValidator skips the htu comparison when it is given no URL. That skip is a caller's choice
        // there; here it would let a proof minted for any server authenticate at this one, so no URL is a
        // misconfiguration, as no audience is in PoP mode.
        if (expectedHtu == null || expectedHtu.isBlank()) {
            throw ClientAttestationException.invalidClient("Server misconfigured: no expected DPoP htu");
        }

        DpopProof proof;
        try {
            proof = validator.validate(dpopHeader, expectedHtm, expectedHtu);
        } catch (Exception e) {
            throw ClientAttestationException.invalidClient("DPoP proof verification failed: " + e.getMessage(), e);
        }

        Jwks.assertSameKey(attestation.cnfJwk(), proof.jwk());
        this.enforceChallenge(proof.nonce());
        this.enforceNoReplay(attestation.clientId(), proof.jti(), this.config.dpopMaxAgeSeconds());

        LOGGER.debug((Object) ("attestation DPoP (combined) verified for client_id=" + attestation.clientId()));
        return new ClientAttestationResult(attestation.clientId(), attestation.cnfJwk(),
                ClientAttestationResult.Mode.DPOP, attestation.attesterIssuer(), proof.jti(),
                java.util.List.of(), java.util.List.of(), attestation.workload(), attestation.agentId());
    }

    private void assertFresh(long iat, long maxAgeSeconds, String label) throws ClientAttestationException {
        long now = Instant.now().getEpochSecond();
        if (iat - now > this.config.allowedClockSkewSeconds()) {
            throw ClientAttestationException.invalidClient(label + " 'iat' is in the future");
        }
        if (maxAgeSeconds > 0L && now - iat > maxAgeSeconds + this.config.allowedClockSkewSeconds()) {
            throw ClientAttestationException.invalidClient(label + " is stale (older than " + maxAgeSeconds + "s)");
        }
    }

    /** Applies challenge policy: required-but-missing or invalid challenge yields {@code use_attestation_challenge}. */
    private void enforceChallenge(String presentedChallenge) throws ClientAttestationException {
        boolean present = presentedChallenge != null && !presentedChallenge.isBlank();
        if (!present) {
            if (this.config.challengeRequired()) {
                throw ClientAttestationException.useChallenge("A server-issued attestation challenge is required");
            }
            return;
        }
        if (this.challengeService == null) {
            throw ClientAttestationException.useChallenge("Unknown or expired attestation challenge");
        }
        switch (this.challengeService.consumeChallenge(presentedChallenge)) {
            case CONSUMED:
                return;
            case STORE_UNAVAILABLE:
                // An outage of ours, not a stale challenge of theirs: 503, so the client retries the same
                // challenge later instead of fetching a new one that would meet the same store.
                throw ClientAttestationException.temporarilyUnavailable("The attestation challenge store is unavailable");
            default:
                throw ClientAttestationException.useChallenge("Unknown or expired attestation challenge");
        }
    }

    private void enforceNoReplay(String clientId, String jti, long maxAgeSeconds) throws ClientAttestationException {
        long ttl = maxAgeSeconds + this.config.allowedClockSkewSeconds();
        switch (this.replayCache.record(clientId, jti, ttl)) {
            case FIRST_USE:
                return;
            case STORE_UNAVAILABLE:
                throw ClientAttestationException.temporarilyUnavailable("The attestation replay store is unavailable");
            default:
                throw ClientAttestationException.invalidClient("Replay detected for proof jti");
        }
    }

    private static List<String> trustChainHeader(Map<String, Object> headers) {
        Object raw = headers.get("trust_chain");
        if (!(raw instanceof List)) {
            return List.of();
        }
        List<?> list = (List<?>) raw;
        ArrayList<String> out = new ArrayList<>(list.size());
        for (Object item : list) {
            if (item != null) {
                out.add(String.valueOf(item));
            }
        }
        return out;
    }
}
