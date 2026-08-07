/*
 * Orchestrates attestation-based client authentication (draft-ietf-oauth-attestation-based-client-auth).
 */
package com.pingidentity.ps.oidf.common;

import java.security.Key;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.consumer.InvalidJwtException;

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
    private static final String ATTESTATION_TYP = "oauth-client-attestation+jwt";
    private static final String POP_TYP = "oauth-client-attestation-pop+jwt";

    private final AttesterKeyResolver attesterKeyResolver;
    private final ClientAttestationConfig config;
    private final AttestationReplayCache replayCache;
    private final AttestationChallengeService challengeService;

    public ClientAttestationVerifier(AttesterKeyResolver attesterKeyResolver, ClientAttestationConfig config,
                                     AttestationReplayCache replayCache, AttestationChallengeService challengeService) {
        this.attesterKeyResolver = Objects.requireNonNull(attesterKeyResolver, "attesterKeyResolver");
        this.config = Objects.requireNonNull(config, "config");
        this.replayCache = Objects.requireNonNull(replayCache, "replayCache");
        this.challengeService = challengeService;
    }

    /**
     * Verifies the presented attestation + proof of possession.
     *
     * @param attestationHeader  the {@code OAuth-Client-Attestation} value (required)
     * @param popHeader          the {@code OAuth-Client-Attestation-PoP} value (PoP-JWT mode), or null
     * @param dpopHeader         the {@code DPoP} value (combined mode), or null
     * @param requestMethod      the HTTP method of the token request (for DPoP {@code htm}), or null
     * @param requestUri         the HTTP target URI of the token request (for DPoP {@code htu}), or null
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
     * As {@link #verify(String, String, String, String, String, String)}, additionally authorizing the
     * token request's RFC 9396 {@code authorization_details} against the entitlement the attestation
     * asserts. Authentication (attestation + proof of possession) is verified first; only then is the
     * requested access authorized. The returned result carries both the attested entitlement and the
     * granted (authorized) details.
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
            if (hasPop && hasDpop) {
                throw ClientAttestationException.invalidClient(
                        "Both OAuth-Client-Attestation-PoP and DPoP present; combined mode forbids a separate PoP header");
            }
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

            // ... then authorize the requested access against the attested RFC 9396 entitlement.
            List<Map<String, Object>> entitled = attestation.authorizationDetails();
            List<Map<String, Object>> granted =
                    RarEntitlement.authorize(RarEntitlement.parseArray(requestedAuthorizationDetailsJson), entitled);
            return new ClientAttestationResult(authenticated.clientId(), authenticated.cnfJwk(),
                    authenticated.mode(), authenticated.attesterIssuer(), authenticated.proofJti(), entitled, granted,
                    attestation.workload());
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
     * reject an attestation minted without them. Known groups: {@code workload} and
     * {@code authorization_details}; an unrecognised name is treated as satisfied.
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
                default:
                    present = true;
            }
            if (!present) {
                throw ClientAttestationException.insufficientDisclosure(
                        "attestation does not disclose the AS-required claim '" + claim + "'");
            }
        }
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
        } catch (InvalidJwtException e) {
            if (e.hasExpired()) {
                throw ClientAttestationException.useFreshAttestation("Client Attestation has expired");
            }
            throw ClientAttestationException.invalidClient("Client Attestation verification failed: " + e.getMessage(), e);
        }
        return ClientAttestation.fromVerifiedClaims(verified, attestationHeader);
    }

    private ClientAttestationResult verifyPopMode(ClientAttestation attestation, String popHeader) throws Exception {
        if (this.config.acceptedAudiences().isEmpty()) {
            throw ClientAttestationException.invalidClient("Server misconfigured: no expected PoP audience");
        }
        Map<String, Object> headers = JwtCodec.getJwtHeaders(popHeader);
        JwtCodec.requireType(headers, POP_TYP);
        Key cnfKey = Jwks.publicKey(attestation.cnfJwk());

        JwtClaims pop;
        try {
            pop = JwtCodec.verifyAttestationPop(popHeader, cnfKey, this.config.popAlgorithms(),
                    this.config.acceptedAudiences(), this.config.allowedClockSkewSeconds());
        } catch (InvalidJwtException e) {
            throw ClientAttestationException.invalidClient("Client Attestation PoP verification failed: " + e.getMessage(), e);
        }

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
                java.util.List.of(), java.util.List.of(), attestation.workload());
    }

    private ClientAttestationResult verifyDpopMode(ClientAttestation attestation, String dpopHeader,
                                                   String requestMethod, String requestUri) throws Exception {
        DpopProofValidator validator = new DpopProofValidator(this.config.dpopAlgorithms(),
                this.config.allowedClockSkewSeconds(), this.config.dpopMaxAgeSeconds());
        String expectedHtm = requestMethod != null && !requestMethod.isBlank() ? requestMethod : this.config.expectedHtm();
        String expectedHtu = this.config.expectedHtu() != null ? this.config.expectedHtu() : requestUri;

        DpopProof proof;
        try {
            proof = validator.validate(dpopHeader, expectedHtm, expectedHtu);
        } catch (ClientAttestationException e) {
            throw e;
        } catch (Exception e) {
            throw ClientAttestationException.invalidClient("DPoP proof verification failed: " + e.getMessage(), e);
        }

        Jwks.assertSameKey(attestation.cnfJwk(), proof.jwk());
        this.enforceChallenge(proof.nonce());
        this.enforceNoReplay(attestation.clientId(), proof.jti(), this.config.dpopMaxAgeSeconds());

        LOGGER.debug((Object) ("attestation DPoP (combined) verified for client_id=" + attestation.clientId()));
        return new ClientAttestationResult(attestation.clientId(), attestation.cnfJwk(),
                ClientAttestationResult.Mode.DPOP, attestation.attesterIssuer(), proof.jti(),
                java.util.List.of(), java.util.List.of(), attestation.workload());
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
        if (this.challengeService == null || !this.challengeService.consume(presentedChallenge)) {
            throw ClientAttestationException.useChallenge("Unknown or expired attestation challenge");
        }
    }

    private void enforceNoReplay(String clientId, String jti, long maxAgeSeconds) throws ClientAttestationException {
        long ttl = maxAgeSeconds + this.config.allowedClockSkewSeconds();
        if (!this.replayCache.firstSeen(clientId, jti, ttl)) {
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
