/*
 * Parsed Client Attestation JWT (draft-ietf-oauth-attestation-based-client-auth).
 */
package com.pingidentity.ps.oidf.common;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.jose4j.json.JsonUtil;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.MalformedClaimException;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.lang.JoseException;

/**
 * Immutable view of a verified Client Attestation JWT. The Attestation is issued by a Client Attester
 * ({@code iss}), names the client ({@code sub} = {@code client_id}) and binds the client instance key
 * via the RFC 7800 {@code cnf} claim ({@code cnf.jwk}). It carries {@code exp} (required) and may carry
 * {@code iat}.
 */
public final class ClientAttestation {
    private final String attesterIssuer;
    private final String clientId;
    private final Map<String, Object> cnfJwk;
    private final long expEpochSeconds;
    private final long iatEpochSeconds;
    private final List<Map<String, Object>> authorizationDetails;
    private final Map<String, Object> workload;
    private final String raw;

    public ClientAttestation(String attesterIssuer, String clientId, Map<String, Object> cnfJwk, long expEpochSeconds, long iatEpochSeconds, List<Map<String, Object>> authorizationDetails, Map<String, Object> workload, String raw) {
        this.attesterIssuer = attesterIssuer;
        this.clientId = clientId;
        this.cnfJwk = cnfJwk;
        this.expEpochSeconds = expEpochSeconds;
        this.iatEpochSeconds = iatEpochSeconds;
        this.authorizationDetails = authorizationDetails;
        this.workload = workload;
        this.raw = raw;
    }

    /**
     * Builds a {@link ClientAttestation} from already signature-verified claims, enforcing the presence
     * of {@code sub} and {@code cnf.jwk}. ({@code iss}/{@code exp} are enforced during signature
     * verification by {@link JwtCodec#verifyAgainstKeys}.)
     */
    public static ClientAttestation fromVerifiedClaims(JwtClaims claims, String raw) throws MalformedClaimException {
        String attester = Claims.requireNonBlank(claims.getIssuer(), "iss");
        String clientId = Claims.requireNonBlank(claims.getSubject(), "sub");
        Map<String, Object> cnf = Claims.requiredMap(claims, "cnf");
        Map<String, Object> jwk = Claims.optionalNestedMap(cnf, "jwk");
        if (jwk.isEmpty()) {
            throw new IllegalArgumentException("Client Attestation 'cnf' claim must use the 'jwk' confirmation method");
        }
        long exp = claims.hasClaim("exp") ? claims.getExpirationTime().getValue() : 0L;
        long iat = claims.hasClaim("iat") ? claims.getIssuedAt().getValue() : 0L;
        return new ClientAttestation(attester, clientId, jwk, exp, iat, authorizationDetails(claims), workload(claims), raw);
    }

    /**
     * Builds a {@link ClientAttestation} from a verified SD-JWT (the optional attestation encoding): the
     * issuer JWT's already-signature-verified {@code issuerClaims} plus the presented {@code disclosures}.
     * The disclosed claim set is reconstructed ({@link SdJwt#reconstruct}) and then run through the same
     * required-claim checks as {@link #fromVerifiedClaims}. The caller verifies the issuer signature and the
     * Key-Binding JWT separately.
     */
    public static ClientAttestation fromSdJwt(JwtClaims issuerClaims, List<String> disclosures, String raw)
            throws MalformedClaimException {
        JwtClaims disclosed;
        try {
            Map<String, Object> payload = JsonUtil.parseJson(issuerClaims.toJson());
            Map<String, Object> reconstructed = SdJwt.reconstruct(payload, disclosures);
            disclosed = JwtClaims.parse(JsonUtil.toJson(reconstructed));
        } catch (JoseException | InvalidJwtException e) {
            throw new IllegalArgumentException("invalid SD-JWT presentation", e);
        }
        return fromVerifiedClaims(disclosed, raw);
    }

    /** The optional RFC 9396 {@code authorization_details} entitlement asserted by the attester. */
    @SuppressWarnings("unchecked")
    private static List<Map<String, Object>> authorizationDetails(JwtClaims claims) {
        Object value = claims.getClaimValue("authorization_details");
        if (!(value instanceof List)) {
            return List.of();
        }
        ArrayList<Map<String, Object>> out = new ArrayList<>();
        for (Object item : (List<?>) value) {
            if (item instanceof Map) {
                out.add((Map<String, Object>) item);
            }
        }
        return out;
    }

    /** The optional attester-asserted {@code workload} claim (workload attributes); empty if none/withheld. */
    @SuppressWarnings("unchecked")
    private static Map<String, Object> workload(JwtClaims claims) {
        Object value = claims.getClaimValue("workload");
        return value instanceof Map ? (Map<String, Object>) value : Map.of();
    }

    public String attesterIssuer() {
        return this.attesterIssuer;
    }

    public String clientId() {
        return this.clientId;
    }

    public Map<String, Object> cnfJwk() {
        return this.cnfJwk;
    }

    public long expEpochSeconds() {
        return this.expEpochSeconds;
    }

    public long iatEpochSeconds() {
        return this.iatEpochSeconds;
    }

    /** The attester-asserted RFC 9396 entitlement ({@code authorization_details}); empty if none. */
    public List<Map<String, Object>> authorizationDetails() {
        return this.authorizationDetails;
    }

    /** The attester-asserted {@code workload} attributes actually disclosed to this AS; empty if none/withheld. */
    public Map<String, Object> workload() {
        return this.workload;
    }

    public String raw() {
        return this.raw;
    }
}
