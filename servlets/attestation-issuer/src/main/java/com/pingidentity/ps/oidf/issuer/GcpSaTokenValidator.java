/*
 * EvidenceValidator for Google-signed service-account ID tokens (Agent Engine / Cloud Run / GCE).
 */
package com.pingidentity.ps.oidf.issuer;

import java.util.List;
import java.util.Set;
import java.util.function.Supplier;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.jose4j.jwt.JwtClaims;
import com.pingidentity.ps.oidf.clientattestation.ClientAttestationConfig;

/**
 * The {@code gcp-id-token} evidence type: a Google-signed ID token for a service account, requested with this attester
 * as its audience (the metadata server's {@code identity} endpoint, or IAM Credentials {@code generateIdToken}). Its
 * {@code iss} is "always set to https://accounts.google.com", and its audience "can be freely chosen by the token
 * requester" (Google, Token types, read 2026-09-30), so any service account in any project can mint one for this
 * attester: the project, not the issuer, is what ties it to the deployment.
 *
 * <p>The identity is the {@code email} claim, mapped onto {@code spiffe://<attestation_trust_domain>/sa/<email>}.
 * Beyond {@link CloudTokenValidator}'s checks: the email is a user-managed account,
 * {@code <account>@<project>.iam.gserviceaccount.com}, whose project {@code OIDF_ATTESTER_GCP_PROJECTS} lists
 * (production refuses the type with no list); and the client's bindings follow {@link #checkAccountBindings}.
 */
public final class GcpSaTokenValidator extends CloudTokenValidator {

    /** The selector names this validator proves. */
    static final List<String> SELECTOR_NAMES = List.of("issuer", "email");

    /** Development's default issuer: the one Google always sets. */
    static final Pattern GOOGLE_ISSUER = Pattern.compile("https://accounts\\.google\\.com");

    /**
     * A user-managed service account's email, {@code <account>@<project>.iam.gserviceaccount.com}: the account "between
     * 6 and 30 characters" of "lowercase alphanumeric characters and dashes" (Google, Create service accounts, read
     * 2026-09-30), the project a project ID. Group 1 is the account, group 2 the project. A service agent's domain,
     * {@code gcp-sa-<service>}, has the shape of a project and names a service, so it is refused separately.
     */
    static final Pattern ACCOUNT_EMAIL = Pattern.compile(
            "([a-z0-9-]{6,30})@(" + Policy.PROJECT_ID.pattern() + ")\\.iam\\.gserviceaccount\\.com");

    public GcpSaTokenValidator() {
        this(ClientAttestationConfig.DEFAULT_CLOCK_SKEW_SECONDS, Policy::process);
    }

    public GcpSaTokenValidator(Policy policy) {
        this(ClientAttestationConfig.DEFAULT_CLOCK_SKEW_SECONDS, () -> policy);
    }

    GcpSaTokenValidator(long allowedClockSkewSeconds, Supplier<Policy> policy) {
        super(allowedClockSkewSeconds, policy);
    }

    @Override
    public String id() {
        return AttestationIssuanceConfig.EVIDENCE_GCP_ID_TOKEN;
    }

    @Override
    public String title() {
        return "GCP service-account ID token";
    }

    @Override
    public String description() {
        return "A Google-signed service-account ID token (Agent Engine / Cloud Run / GCE), verified "
                + "against Google's public JWKS and mapped onto a synthetic SPIFFE ID from its email claim.";
    }

    @Override
    public List<String> selectorNames() {
        return SELECTOR_NAMES;
    }

    @Override
    protected Pattern developmentIssuer() {
        return GOOGLE_ISSUER;
    }

    @Override
    protected void checkBindings(AttestationIssuanceConfig config, Policy policy) throws IssuanceException {
        if (policy.gcpProjects() == null && policy.production()) {
            throw misconfigured("project", "no Google Cloud project is listed for gcp-id-token evidence: set "
                    + Policy.GCP_PROJECTS + " (production refuses the type without it)");
        }
        String problem = checkAccountBindings(config, policy.gcpProjects());
        if (problem != null) {
            throw misconfigured("binding_pattern", problem);
        }
    }

    @Override
    protected Mapped map(JwtClaims claims, Policy policy, AttestationIssuanceConfig config) throws IssuanceException {
        String email = EvidenceSelectors.stringClaim(claims, "email");
        if (email == null || email.isBlank()) {
            throw refused("subject", "token has no 'email' (service-account identity) claim");
        }
        Set<String> projects = policy.gcpProjects();
        String project = projectOf(email);
        if (projects != null && (project == null || !projects.contains(project))) {
            throw refused("project", "token's service account is not a user-managed account of a project "
                    + Policy.GCP_PROJECTS + " lists");
        }
        return new Mapped("/sa/" + email, this.selectors("issuer", EvidenceSelectors.stringClaim(claims, "iss"),
                "email", email));
    }

    /** The project of a user-managed account's email, or null for any other email (a service agent's included). */
    static String projectOf(String email) {
        Matcher matcher = ACCOUNT_EMAIL.matcher(email);
        return matcher.matches() && !matcher.group(2).startsWith("gcp-sa-") ? matcher.group(2) : null;
    }

    /**
     * The grammar of a {@code gcp-id-token} client's bindings: each exactly
     * {@code spiffe://<attestation_trust_domain>/sa/<account>@<project>.iam.gserviceaccount.com}, with no {@code *},
     * the email a user-managed account and its project one {@code projects} lists when it is set. A binding's
     * {@code *} matches any suffix ({@link SpiffeBinding#matches}), and the project comes after the {@code @}, so any
     * wildcard in an email binding crosses the {@code @} into every project; none is accepted.
     *
     * @return what is wrong, naming the rule and not the pattern, or null
     */
    static String checkAccountBindings(AttestationIssuanceConfig config, Set<String> projects) {
        String prefix = "spiffe://" + config.expectedTrustDomain() + "/sa/";
        for (SpiffeBinding binding : config.bindings()) {
            String pattern = binding.spiffeId();
            if (pattern.indexOf('*') >= 0) {
                return "a gcp-id-token binding may not use '*': it would match service accounts across '@' and across "
                        + "projects; list each account as spiffe://<trust-domain>/sa/<account>@<project>.iam.gserviceaccount.com";
            }
            String project = pattern.startsWith(prefix) ? projectOf(pattern.substring(prefix.length())) : null;
            if (project == null) {
                return "a gcp-id-token binding is not spiffe://<trust-domain>/sa/<account>@<project>.iam.gserviceaccount.com "
                        + "for a user-managed service account";
            }
            if (projects != null && !projects.contains(project)) {
                return "a gcp-id-token binding names a project " + Policy.GCP_PROJECTS + " does not list";
            }
        }
        return null;
    }

    /**
     * The grammar of a {@code gke-sa-token} client's bindings: each {@code spiffe://<attestation_trust_domain>/ns/}
     * followed by a namespace and service account, where a {@code *} may appear only last, and only after that prefix,
     * so it can never widen the trust domain, which holds the project ({@code PROJECT_ID.svc.id.goog}). When
     * {@code projects} is set and the trust domain has that form, its project is one of them.
     *
     * @return what is wrong, naming the rule and not the pattern, or null
     */
    static String checkWorkloadBindings(AttestationIssuanceConfig config, Set<String> projects) {
        String trustDomain = config.expectedTrustDomain();
        if (projects != null && trustDomain.endsWith(".svc.id.goog")
                && !projects.contains(trustDomain.substring(0, trustDomain.length() - ".svc.id.goog".length()))) {
            return AttestationIssuanceConfig.P_TRUST_DOMAIN + " names a workload identity pool of a project "
                    + Policy.GCP_PROJECTS + " does not list";
        }
        String prefix = "spiffe://" + trustDomain + "/ns/";
        for (SpiffeBinding binding : config.bindings()) {
            String pattern = binding.spiffeId();
            int star = pattern.indexOf('*');
            if (!pattern.startsWith(prefix) || pattern.length() == prefix.length()
                    || (star >= 0 && star != pattern.length() - 1)) {
                return "a gke-sa-token binding is not spiffe://<trust-domain>/ns/<namespace>/sa/<name>, with at most one "
                        + "'*', last, after spiffe://<trust-domain>/ns/: a wildcard may not cross the project";
            }
        }
        return null;
    }
}
