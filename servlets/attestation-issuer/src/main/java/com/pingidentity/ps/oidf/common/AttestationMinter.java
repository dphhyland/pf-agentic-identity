/*
 * Mints a Client Attestation JWT, signed via a JwsSigner (the attester side, server-hosted).
 */
package com.pingidentity.ps.oidf.common;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.jose4j.json.JsonUtil;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.NumericDate;

/**
 * Server-side minter for a Client Attestation JWT (header {@code typ=oauth-client-attestation+jwt}), per
 * draft-ietf-oauth-attestation-based-client-auth. It names the client ({@code sub} = {@code client_id}),
 * binds the workload's instance key via the RFC 7800 {@code cnf.jwk} claim, and carries the attester's
 * {@code workload} attestation and the RFC 9396 {@code authorization_details} entitlement. Signing is
 * delegated to a {@link JwsSigner}, so the attester key may live in an OpenBao/Vault transit engine
 * ({@link OpenBaoTransitSigner}) or be an inline JWK ({@link LocalJwkSigner}).
 *
 * <p>The claim layout mirrors the proven client-side {@code ClientAttestationBuilder}, and the emitted
 * artifact verifies unchanged through {@link ClientAttestationVerifier}.
 */
public final class AttestationMinter {

    public static final String TYP = "oauth-client-attestation+jwt";

    private AttestationMinter() {
    }

    /**
     * Builds and signs a Client Attestation for a validated instance identity (any format), with no
     * {@code agent_id} claim. Retained so existing callers (and their tests) are unaffected; equivalent
     * to calling the 9-argument overload with {@code agentId = null}.
     *
     * @param issuer               the attester entity identifier ({@code iss})
     * @param clientId             the attested client ({@code sub})
     * @param instancePublicJwk    the workload instance public key to bind as {@code cnf.jwk}
     * @param instance             the validated instance identity (its {@code format} → {@code attested_by},
     *                             and its {@code workloadClaims} ride in {@code workload})
     * @param workloadMetadata     per-instance attributes surfaced as {@code workload.attributes} (may be empty)
     * @param authorizationDetails the granted RFC 9396 entitlement (may be empty)
     * @param ttlSeconds           lifetime; {@code exp = iat + ttlSeconds}
     * @param signer               the attester signer
     * @return the compact Client Attestation JWT
     */
    public static String mint(String issuer, String clientId, Map<String, Object> instancePublicJwk,
                              InstanceIdentity instance, Map<String, Object> workloadMetadata,
                              List<Map<String, Object>> authorizationDetails, long ttlSeconds, JwsSigner signer) {
        return mint(issuer, clientId, instancePublicJwk, instance, workloadMetadata, authorizationDetails,
                ttlSeconds, signer, null);
    }

    /**
     * As above, with an optional {@code agent_id} (Phase 2.1/2.2): the stable, pseudonymous identifier of
     * this specific running instance, minted by an {@code AgentRegistry} — distinct from {@code sub}
     * (the client/agent <em>type</em>) and from {@code workload.subject} (the proven instance identifier
     * the registry minted it against). Omitted from the JWT entirely when {@code agentId} is
     * {@code null} or blank, rather than emitted as an empty claim.
     *
     * @param agentId the minted agent identity, or {@code null} if no registry is configured
     */
    public static String mint(String issuer, String clientId, Map<String, Object> instancePublicJwk,
                              InstanceIdentity instance, Map<String, Object> workloadMetadata,
                              List<Map<String, Object>> authorizationDetails, long ttlSeconds, JwsSigner signer,
                              String agentId) {
        long iat = NumericDate.now().getValue();
        JwtClaims claims = new JwtClaims();
        claims.setIssuer(issuer);
        claims.setSubject(clientId);
        claims.setIssuedAt(NumericDate.fromSeconds(iat));
        claims.setExpirationTime(NumericDate.fromSeconds(iat + ttlSeconds));

        Map<String, Object> cnf = new LinkedHashMap<>();
        cnf.put("jwk", instancePublicJwk);
        claims.setClaim("cnf", cnf);

        Map<String, Object> workload = new LinkedHashMap<>();
        workload.put("attested_by", instance.format());
        workload.putAll(instance.workloadClaims());
        // The spec's format-neutral instance identifier, set after workloadClaims so it is authoritative
        // even if a format's own claims happen to use the same key.
        workload.put("subject", instance.subject());
        if (workloadMetadata != null && !workloadMetadata.isEmpty()) {
            workload.put("attributes", workloadMetadata);
        }
        claims.setClaim("workload", workload);

        if (authorizationDetails != null && !authorizationDetails.isEmpty()) {
            claims.setClaim("authorization_details", authorizationDetails);
        }

        if (agentId != null && !agentId.isBlank()) {
            claims.setClaim("agent_id", agentId);
        }

        return sign(claims.toJson(), signer);
    }

    /**
     * Convenience overload for a SPIFFE JWT-SVID — adapts it via {@link InstanceIdentity#ofSpiffe} and mints
     * exactly as before. Retained so SPIFFE callers (and their tests) are unaffected by the generalisation.
     */
    public static String mint(String issuer, String clientId, Map<String, Object> instancePublicJwk,
                              SpiffeSvid svid, Map<String, Object> workloadMetadata,
                              List<Map<String, Object>> authorizationDetails, long ttlSeconds, JwsSigner signer) {
        return mint(issuer, clientId, instancePublicJwk, InstanceIdentity.ofSpiffe(svid),
                workloadMetadata, authorizationDetails, ttlSeconds, signer);
    }

    /** Assembly is shared with the other minters — see {@link CompactJws}. */
    private static String sign(String payloadJson, JwsSigner signer) {
        return CompactJws.sign(TYP, payloadJson, signer);
    }
}
