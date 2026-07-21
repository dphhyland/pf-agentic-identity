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
     * Builds and signs a Client Attestation.
     *
     * @param issuer               the attester entity identifier ({@code iss})
     * @param clientId             the attested client ({@code sub})
     * @param instancePublicJwk    the workload instance public key to bind as {@code cnf.jwk}
     * @param svid                 the validated SVID (its {@code spiffe_id} and raw token ride in {@code workload})
     * @param workloadMetadata     per-instance attributes surfaced as {@code workload.attributes} (may be empty)
     * @param authorizationDetails the granted RFC 9396 entitlement (may be empty)
     * @param ttlSeconds           lifetime; {@code exp = iat + ttlSeconds}
     * @param signer               the attester signer
     * @return the compact Client Attestation JWT
     */
    public static String mint(String issuer, String clientId, Map<String, Object> instancePublicJwk,
                              SpiffeSvid svid, Map<String, Object> workloadMetadata,
                              List<Map<String, Object>> authorizationDetails, long ttlSeconds, JwsSigner signer) {
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
        workload.put("attested_by", "spiffe");
        workload.put("spiffe_id", svid.spiffeId());
        if (workloadMetadata != null && !workloadMetadata.isEmpty()) {
            workload.put("attributes", workloadMetadata);
        }
        workload.put("svid", svid.raw());
        claims.setClaim("workload", workload);

        if (authorizationDetails != null && !authorizationDetails.isEmpty()) {
            claims.setClaim("authorization_details", authorizationDetails);
        }

        return sign(claims.toJson(), signer);
    }

    /**
     * Assembles the compact JWS: {@code BASE64URL(header).BASE64URL(payload)} is signed by the
     * {@link JwsSigner} (which returns the raw JWS signature), and the three parts are joined. The header
     * carries {@code alg}, {@code typ} and the signer's {@code kid} (issuing keys are referenced by id,
     * never embedded).
     */
    private static String sign(String payloadJson, JwsSigner signer) {
        Map<String, Object> header = new LinkedHashMap<>();
        header.put("alg", signer.algorithm());
        header.put("typ", TYP);
        header.put("kid", signer.keyId());
        Base64.Encoder b64 = Base64.getUrlEncoder().withoutPadding();
        String signingInput = b64.encodeToString(JsonUtil.toJson(header).getBytes(StandardCharsets.UTF_8))
                + "." + b64.encodeToString(payloadJson.getBytes(StandardCharsets.UTF_8));
        byte[] signature = signer.sign(signingInput.getBytes(StandardCharsets.US_ASCII));
        return signingInput + "." + b64.encodeToString(signature);
    }
}
