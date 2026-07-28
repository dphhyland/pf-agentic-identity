/*
 * EvidenceValidator for AWS-signed OIDC tokens from sts:GetWebIdentityToken (AWS Outbound Identity
 * Federation): the JWT evidence path for any AWS workload, including Bedrock AgentCore.
 */
package com.pingidentity.ps.oidf.common;

import java.security.Key;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.NumericDate;

/**
 * The {@code aws-sts-web-identity} evidence type: an AWS-signed OIDC token minted by
 * {@code sts:GetWebIdentityToken} (AWS Outbound Identity Federation, GA re:Invent 2025). A workload running
 * under an IAM role — an EC2 instance, a Lambda, an ECS task, or a <em>Bedrock AgentCore</em> agent — calls
 * the STS API and receives a JWT signed by an account-specific issuer
 * ({@code https://<uuid>.tokens.sts.global.api.aws}) with a public JWKS at
 * {@code <issuer>/.well-known/jwks.json}. This is the AWS analogue of {@link GcpSaTokenValidator}: it gives
 * an AWS workload a JWKS-verifiable identity to present off-platform, which AgentCore's own opaque,
 * first-party workload access token cannot.
 *
 * <p>The token's {@code sub} is the caller's IAM principal ARN — {@code arn:aws:iam::<account>:role/<Role>}
 * or {@code arn:aws:sts::<account>:assumed-role/<Role>/<session>}. There is no canonical AWS SPIFFE mapping,
 * so the identity is projected to {@code spiffe://<attestation_trust_domain>/aws/<account>/role/<Role>}
 * using the client's pinned trust domain (a deployment convention, e.g. {@code <account>.aws.example}). The
 * ephemeral session name is dropped so the SPIFFE ID is stable per role. Bindings then list the role ARNs
 * (as their mapped SPIFFE IDs) permitted to act as instances of the client.
 *
 * <p>Checks mirror {@link GcpSaTokenValidator}: signature under an asymmetric-only constraint (RS256/ES384)
 * with the bundle key selected by {@code kid}; {@code exp} required and unexpired; {@code aud} must include
 * the attester issuer (the audience the caller passed to {@code GetWebIdentityToken}); optionally
 * {@code iss} must equal the client's pinned {@code attestation_evidence_issuer} (the account issuer URL).
 * The trust domain is required. Failures throw {@code invalid_svid}.
 */
public final class AwsStsWebIdentityValidator implements EvidenceValidator {

    /** {@code arn:aws:iam::<account>:role/<path/name>} — group 1 account, group 2 the role path+name. */
    private static final Pattern IAM_ROLE_ARN =
            Pattern.compile("arn:aws[a-z-]*:iam::(\\d{12}):role/(.+)");
    /** {@code arn:aws:sts::<account>:assumed-role/<name>/<session>} — group 1 account, group 2 role name. */
    private static final Pattern ASSUMED_ROLE_ARN =
            Pattern.compile("arn:aws[a-z-]*:sts::(\\d{12}):assumed-role/([^/]+)/.+");

    private static final Set<String> PERMITTED_ALGORITHMS = ClientAttestationConfig.DEFAULT_ASYMMETRIC_ALGORITHMS;

    private final long allowedClockSkewSeconds;

    public AwsStsWebIdentityValidator() {
        this(ClientAttestationConfig.DEFAULT_CLOCK_SKEW_SECONDS);
    }

    public AwsStsWebIdentityValidator(long allowedClockSkewSeconds) {
        this.allowedClockSkewSeconds = allowedClockSkewSeconds;
    }

    @Override
    public SpiffeSvid validate(String evidence, List<JsonWebKey> bundleKeys, AttestationIssuanceConfig config)
            throws IssuanceException {
        if (evidence == null || evidence.isBlank()) {
            throw IssuanceException.invalidSvid("no web-identity token presented");
        }
        if (bundleKeys == null || bundleKeys.isEmpty()) {
            throw IssuanceException.invalidSvid("no trust bundle configured for this client");
        }
        String trustDomain = config.expectedTrustDomain();
        if (trustDomain == null || trustDomain.isBlank()) {
            throw IssuanceException.invalidClient(
                    AttestationIssuanceConfig.P_TRUST_DOMAIN + " is required for aws-sts-web-identity evidence");
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

        String subject = claims.getClaimValueAsString("sub");
        if (subject == null || subject.isBlank()) {
            throw IssuanceException.invalidSvid("token has no 'sub'");
        }
        String account;
        String role;
        Matcher iam = IAM_ROLE_ARN.matcher(subject);
        Matcher sts = ASSUMED_ROLE_ARN.matcher(subject);
        if (iam.matches()) {
            account = iam.group(1);
            role = iam.group(2);
        } else if (sts.matches()) {
            account = sts.group(1);
            role = sts.group(2);
        } else {
            throw IssuanceException.invalidSvid("token 'sub' is not an IAM role ARN: " + subject);
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

        String path = "/aws/" + account + "/role/" + role;
        String spiffeId = "spiffe://" + trustDomain + path;
        return new SpiffeSvid(spiffeId, trustDomain, path, audiences, exp, iat, evidence);
    }
}
