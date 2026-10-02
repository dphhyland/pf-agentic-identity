/*
 * EvidenceValidator for AWS-signed OIDC tokens from sts:GetWebIdentityToken (AWS Outbound Identity
 * Federation): the JWT evidence path for any AWS workload, including Bedrock AgentCore.
 */
package com.pingidentity.ps.oidf.issuer;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Supplier;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.jose4j.jwt.JwtClaims;
import com.pingidentity.ps.oidf.clientattestation.ClientAttestationConfig;

/**
 * The {@code aws-sts-web-identity} evidence type: an AWS-signed token from {@code sts:GetWebIdentityToken} (IAM
 * outbound identity federation). A workload under an IAM role - EC2, Lambda, ECS, a Bedrock AgentCore agent - asks
 * STS and receives a JWT from its account's issuer, {@code https://<id>.tokens.sts.global.api.aws}, whose {@code sub}
 * is "The ARN of the IAM principal that requested the token" (AWS, Understanding token claims, read 2026-09-30).
 * It maps onto {@code spiffe://<attestation_trust_domain>/aws/<account>/role/<role>}, the session name dropped.
 *
 * <p>Beyond {@link CloudTokenValidator}'s checks: the account in {@code sub} is one {@code OIDF_ATTESTER_AWS_ACCOUNTS}
 * lists, when it is set, and equals the token's {@code https://sts.amazonaws.com/} {@code aws_account} when that is
 * present.
 */
public final class AwsStsWebIdentityValidator extends CloudTokenValidator {

    /** {@code arn:aws:iam::<account>:role/<path/name>} - group 1 account, group 2 the role path and name. */
    private static final Pattern IAM_ROLE_ARN = Pattern.compile("arn:aws[a-z-]*:iam::(\\d{12}):role/(.+)");
    /** {@code arn:aws:sts::<account>:assumed-role/<name>/<session>} - group 1 account, group 2 role name. */
    private static final Pattern ASSUMED_ROLE_ARN = Pattern.compile("arn:aws[a-z-]*:sts::(\\d{12}):assumed-role/([^/]+)/.+");
    /** An account's STS issuer: development's default when no issuer is pinned. */
    static final Pattern ACCOUNT_ISSUER = Pattern.compile("https://[A-Za-z0-9-]+\\.tokens\\.sts\\.global\\.api\\.aws");

    /** The selector names this validator proves. */
    static final List<String> SELECTOR_NAMES = List.of("issuer", "account", "role");

    public AwsStsWebIdentityValidator() {
        this(ClientAttestationConfig.DEFAULT_CLOCK_SKEW_SECONDS, Policy::process);
    }

    public AwsStsWebIdentityValidator(Policy policy) {
        this(ClientAttestationConfig.DEFAULT_CLOCK_SKEW_SECONDS, () -> policy);
    }

    AwsStsWebIdentityValidator(long allowedClockSkewSeconds, Supplier<Policy> policy) {
        super(allowedClockSkewSeconds, policy);
    }

    @Override
    public String id() {
        return AttestationIssuanceConfig.EVIDENCE_AWS_STS_WEB_IDENTITY;
    }

    @Override
    public String title() {
        return "AWS STS web-identity token";
    }

    @Override
    public String description() {
        return "An AWS-signed OIDC token from sts:GetWebIdentityToken (any AWS workload, including "
                + "Bedrock AgentCore), mapped onto a synthetic SPIFFE ID from its IAM role ARN.";
    }

    @Override
    public List<String> selectorNames() {
        return SELECTOR_NAMES;
    }

    @Override
    protected Pattern developmentIssuer() {
        return ACCOUNT_ISSUER;
    }

    @Override
    protected Mapped map(JwtClaims claims, Policy policy, AttestationIssuanceConfig config) throws IssuanceException {
        String subject = EvidenceSelectors.stringClaim(claims, "sub");
        Matcher iam = IAM_ROLE_ARN.matcher(subject == null ? "" : subject);
        Matcher sts = ASSUMED_ROLE_ARN.matcher(subject == null ? "" : subject);
        Matcher arn = iam.matches() ? iam : sts.matches() ? sts : null;
        if (arn == null) {
            throw refused("subject", "token 'sub' is not an IAM role ARN");
        }
        String account = arn.group(1);
        Set<String> accounts = policy.awsAccounts();
        Object namespace = claims.getClaimValue("https://sts.amazonaws.com/");
        Object stated = namespace instanceof Map ? ((Map<?, ?>) namespace).get("aws_account") : null;
        if ((accounts != null && !accounts.contains(account)) || (stated != null && !account.equals(stated))) {
            throw refused("account", "token's account is not one " + Policy.AWS_ACCOUNTS + " lists, or disagrees with "
                    + "its aws_account claim");
        }
        return new Mapped("/aws/" + account + "/role/" + arn.group(2), this.selectors("issuer",
                EvidenceSelectors.stringClaim(claims, "iss"), "account", account, "role", arn.group(2)));
    }
}
