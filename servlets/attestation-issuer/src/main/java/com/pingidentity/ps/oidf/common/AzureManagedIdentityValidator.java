/*
 * EvidenceValidator for Entra-signed Azure managed-identity tokens (Container Apps / VM / Functions).
 */
package com.pingidentity.ps.oidf.common;

import java.security.Key;
import java.util.List;
import java.util.Set;
import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.NumericDate;

/**
 * The {@code azure-mi-token} evidence type: an Entra-signed OAuth token issued to an Azure managed identity
 * (obtained by the workload from Azure Instance Metadata Service, with a custom {@code resource} set to
 * this attester), validated against Entra's public JWKS. This is the evidence available to workloads whose
 * platform identity is a managed identity rather than a Kubernetes one — Container Apps, VMs, and Functions
 * all qualify — the Azure analogue of {@link GcpSaTokenValidator}.
 *
 * <p>The token's {@code sub} is opaque and MI-shape-dependent; the stable identifier is the {@code oid}
 * claim (the identity's object id — stable across both system- and user-assigned managed identities), so
 * the mapped SPIFFE ID is {@code spiffe://<attestation_trust_domain>/azure/mi/<oid>} (the trust domain is
 * required in this mode and names the identifier namespace — e.g. {@code <tenant>.azure.demo} by deployment
 * convention; Azure defines no canonical SPIFFE mapping for managed identities, matching AWS's IAM-role
 * synthesis in {@link AwsStsWebIdentityValidator}). Bindings then list exactly the object ids permitted to
 * act as instances of the client.
 *
 * <p>Checks mirror the other validators: signature under an asymmetric-only constraint with the bundle key
 * selected by {@code kid} (the bundle is the tenant's rotating JWKS at
 * {@code https://login.microsoftonline.com/<tenant>/discovery/v2.0/keys} — configure it by URL);
 * {@code iss} must equal the client's pinned {@code attestation_evidence_issuer}
 * ({@code https://login.microsoftonline.com/<tenant>/v2.0}) when set; {@code aud} must include the attester
 * issuer; {@code exp} required and unexpired; {@code oid} required. Failures throw {@code invalid_svid}.
 */
public final class AzureManagedIdentityValidator implements InstanceAttestationValidator {

    private static final Set<String> PERMITTED_ALGORITHMS = ClientAttestationConfig.DEFAULT_ASYMMETRIC_ALGORITHMS;

    private final long allowedClockSkewSeconds;

    public AzureManagedIdentityValidator() {
        this(ClientAttestationConfig.DEFAULT_CLOCK_SKEW_SECONDS);
    }

    public AzureManagedIdentityValidator(long allowedClockSkewSeconds) {
        this.allowedClockSkewSeconds = allowedClockSkewSeconds;
    }

    @Override
    public String id() {
        return AttestationIssuanceConfig.EVIDENCE_AZURE_MI_TOKEN;
    }

    @Override
    public String format() {
        return SpiffeInstanceAttestationValidator.FORMAT;
    }

    /** Azure has no canonical SPIFFE mapping — the ID is synthesised from the identity's object id. */
    @Override
    public boolean requiresTrustDomain() {
        return true;
    }

    @Override
    public String title() {
        return "Azure managed-identity token";
    }

    @Override
    public String description() {
        return "An Entra-signed Azure managed-identity token (Container Apps / VM / Functions), verified "
                + "against the tenant's public JWKS and mapped onto a synthetic SPIFFE ID from its object id.";
    }

    @Override
    public InstanceIdentity validate(String evidence, List<JsonWebKey> bundleKeys, AttestationIssuanceConfig config)
            throws IssuanceException {
        return InstanceIdentity.ofSpiffe(validateSvid(evidence, bundleKeys, config));
    }

    /**
     * The SPIFFE-typed validation, kept public so the mapping detail (trust domain, path, raw token) stays
     * independently assertable; {@link #validate} adapts the result to an {@link InstanceIdentity}.
     */
    public SpiffeSvid validateSvid(String evidence, List<JsonWebKey> bundleKeys, AttestationIssuanceConfig config)
            throws IssuanceException {
        if (evidence == null || evidence.isBlank()) {
            throw IssuanceException.invalidSvid("no managed-identity token presented");
        }
        if (bundleKeys == null || bundleKeys.isEmpty()) {
            throw IssuanceException.invalidSvid("no trust bundle configured for this client");
        }
        String trustDomain = config.expectedTrustDomain();
        if (trustDomain == null || trustDomain.isBlank()) {
            throw IssuanceException.invalidClient(
                    AttestationIssuanceConfig.P_TRUST_DOMAIN + " is required for azure-mi-token evidence");
        }

        JsonWebSignature jws = new JsonWebSignature();
        String kid;
        String alg;
        try {
            jws.setCompactSerialization(evidence);
            kid = jws.getKeyIdHeaderValue();
            alg = jws.getAlgorithmHeaderValue();
        } catch (Exception e) {
            throw IssuanceException.invalidSvid("token is not a well-formed compact JWS");
        }
        if (alg == null || !PERMITTED_ALGORITHMS.contains(alg)) {
            throw IssuanceException.invalidSvid("token uses an unsupported signing algorithm: " + alg);
        }

        Key verificationKey = SpiffeSvidValidator.selectKey(bundleKeys, kid);
        jws.setKey(verificationKey);
        jws.setAlgorithmConstraints(new AlgorithmConstraints(AlgorithmConstraints.ConstraintType.PERMIT, alg));
        try {
            if (!jws.verifySignature()) {
                throw IssuanceException.invalidSvid("token signature did not verify against the trust bundle");
            }
        } catch (IssuanceException e) {
            throw e;
        } catch (Exception e) {
            throw IssuanceException.invalidSvid("token signature verification failed");
        }

        JwtClaims claims;
        try {
            claims = JwtClaims.parse(jws.getPayload());
        } catch (Exception e) {
            throw IssuanceException.invalidSvid("token payload is not valid JWT claims");
        }

        String expectedIssuer = config.evidenceIssuer();
        String issuer = claims.getClaimValueAsString("iss");
        if (expectedIssuer != null && !expectedIssuer.equals(issuer)) {
            throw IssuanceException.invalidSvid(
                    "token issuer '" + issuer + "' does not match expected '" + expectedIssuer + "'");
        }

        String oid = claims.getClaimValueAsString("oid");
        if (oid == null || oid.isBlank()) {
            throw IssuanceException.invalidSvid("token has no 'oid' (managed-identity object id) claim");
        }

        long now = NumericDate.now().getValue();
        long exp;
        try {
            if (!claims.hasClaim("exp")) {
                throw IssuanceException.invalidSvid("token has no 'exp'");
            }
            exp = claims.getExpirationTime().getValue();
        } catch (IssuanceException e) {
            throw e;
        } catch (Exception e) {
            throw IssuanceException.invalidSvid("token 'exp' is malformed");
        }
        if (exp + this.allowedClockSkewSeconds < now) {
            throw IssuanceException.invalidSvid("token has expired");
        }
        long iat = 0L;
        try {
            if (claims.hasClaim("iat")) {
                iat = claims.getIssuedAt().getValue();
            }
        } catch (Exception ignored) {
            iat = 0L;
        }

        List<String> audiences;
        try {
            audiences = claims.getAudience();
        } catch (Exception e) {
            throw IssuanceException.invalidSvid("token 'aud' is malformed");
        }
        if (audiences == null || !audiences.contains(config.issuer())) {
            throw IssuanceException.invalidSvid("token audience does not include this issuer: " + config.issuer());
        }

        String path = "/azure/mi/" + oid;
        String spiffeId = "spiffe://" + trustDomain + path;
        return new SpiffeSvid(spiffeId, trustDomain, path, audiences, exp, iat, evidence);
    }
}
