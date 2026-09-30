/*
 * The one base of the six cloud-token evidence validators: every check they share, in one place (plan item H-ATT-1).
 */
package com.pingidentity.ps.oidf.issuer;

import java.security.Key;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;
import java.util.function.Supplier;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwk.EllipticCurveJsonWebKey;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.OctetKeyPairJsonWebKey;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jwk.RsaJsonWebKey;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.NumericDate;
import org.jose4j.keys.EllipticCurves;
import com.pingidentity.ps.oidf.clientattestation.ClientAttestationConfig;
import com.pingidentity.ps.oidf.platform.metrics.Counter;
import com.pingidentity.ps.oidf.platform.metrics.Label;
import com.pingidentity.ps.oidf.platform.metrics.Metrics;
import com.pingidentity.ps.oidf.platform.profile.DeploymentProfile;
import com.pingidentity.ps.oidf.platform.settings.Catalogue;
import com.pingidentity.ps.oidf.platform.settings.SettingRefused;
import com.pingidentity.ps.oidf.platform.settings.Settings;
import com.pingidentity.ps.oidf.platform.settings.Sources;

/**
 * Verifies a cloud platform's signed token and maps it onto a SPIFFE identity. The checks every cloud type shares
 * are here, in this order; a subclass adds only what its token says about its own platform ({@link #map}).
 *
 * <ol>
 *   <li>The client's configuration: a trust bundle and {@code attestation_trust_domain}, the issuers this type may
 *       come from ({@link Policy#issuers}, narrowed by the client's {@code attestation_evidence_issuer}), and, for a
 *       type that says so, its bindings' patterns ({@link #checkBindings}).</li>
 *   <li>The signature: an asymmetric algorithm, the bundle key the {@code kid} names (the only key when there is no
 *       {@code kid}), among keys whose {@code use} is absent or {@code sig} (RFC 7517 §4.2), whose type fits the
 *       algorithm and whose {@code alg}, when present, is the header's.</li>
 *   <li>The claims: {@code iss} one of the pinned issuers; {@code aud} containing the client's
 *       {@code attestation_issuer} (and nothing else when {@code OIDF_ATTESTER_REQUIRE_SINGLE_AUDIENCE_EVIDENCE} is
 *       {@code true}); {@code exp} required and not past, {@code nbf} when present and not ahead, {@code iat} required
 *       and not ahead, each with the clock skew; {@code exp - iat} no longer than
 *       {@code OIDF_ATTESTER_MAX_CLOUD_TOKEN_LIFETIME_SECONDS} ({@link Policy#maxTokenLifetimeSeconds(String)}).</li>
 * </ol>
 *
 * <p>A refusal keeps the code it had before 0.6.0 ({@code invalid_svid} for the evidence, {@code invalid_client} for a
 * client's configuration), never repeats what the token says, and is counted in
 * {@code oidf_attester_cloud_evidence_refusals_total} by evidence type and failed check.
 */
public abstract class CloudTokenValidator implements InstanceAttestationValidator {

    private static final Log LOGGER = LogFactory.getLog(CloudTokenValidator.class);
    private static final Set<String> PERMITTED_ALGORITHMS = ClientAttestationConfig.DEFAULT_ASYMMETRIC_ALGORITHMS;

    /** The checks a refusal is counted under. */
    static final List<String> CHECKS = List.of("config", "iss_pin", "binding_pattern", "malformed", "alg", "key",
            "signature", "iss", "aud", "exp", "nbf", "iat", "lifetime", "subject", "project", "tenant",
            "managed_identity", "account", "selectors");

    private static final Counter REFUSALS = Metrics.counter("oidf_attester_cloud_evidence_refusals_total",
            "Cloud evidence tokens the attester refused, by evidence type and the check that failed",
            Label.oneOf("type", Policy.TYPES), Label.oneOf("check", CHECKS));

    /** The types whose missing pin, or development default, has been logged once in this copy. */
    private static final Set<String> WARNED = ConcurrentHashMap.newKeySet();

    private final long allowedClockSkewSeconds;
    private final Supplier<Policy> policy;

    protected CloudTokenValidator(long allowedClockSkewSeconds, Supplier<Policy> policy) {
        this.allowedClockSkewSeconds = allowedClockSkewSeconds;
        this.policy = policy;
    }

    /** What a subclass maps a verified token onto: the SPIFFE path under the client's trust domain, and the selectors. */
    protected record Mapped(String path, EvidenceSelectors selectors) {
    }

    /** A Kubernetes service-account subject, {@code system:serviceaccount:<namespace>:<name>}. */
    private static final Pattern KSA_SUBJECT = Pattern.compile("system:serviceaccount:([^:]+):([^:]+)");

    /** The selector names of the three Kubernetes token types. */
    static final List<String> KUBERNETES_SELECTORS = List.of("issuer", "namespace", "service_account");

    /** What the token's type makes of its verified claims, after every shared check has passed. */
    protected abstract Mapped map(JwtClaims claims, Policy policy, AttestationIssuanceConfig config)
            throws IssuanceException;

    /** The provider's published issuer, as a pattern: what development accepts for a type with no pin. */
    protected abstract Pattern developmentIssuer();

    /** A client configuration fault this type refuses before the token is read: none, unless the type says so. */
    protected void checkBindings(AttestationIssuanceConfig config, Policy policy) throws IssuanceException {
    }

    @Override
    public final String format() {
        return SpiffeInstanceAttestationValidator.FORMAT;
    }

    /** No cloud platform names a SPIFFE trust domain, so the client's anchors the path. */
    @Override
    public final boolean requiresTrustDomain() {
        return true;
    }

    @Override
    public final InstanceIdentity validate(String evidence, List<JsonWebKey> bundleKeys, AttestationIssuanceConfig config)
            throws IssuanceException {
        VerifiedSvid verified = verify(evidence, bundleKeys, config);
        return InstanceIdentity.ofSpiffe(verified.svid(), this.id(), verified.selectors());
    }

    /** The SPIFFE-typed validation, so the mapping (trust domain, path, raw token) stays assertable on its own. */
    public final SpiffeSvid validateSvid(String evidence, List<JsonWebKey> bundleKeys, AttestationIssuanceConfig config)
            throws IssuanceException {
        return verify(evidence, bundleKeys, config).svid();
    }

    private VerifiedSvid verify(String evidence, List<JsonWebKey> bundleKeys, AttestationIssuanceConfig config)
            throws IssuanceException {
        if (evidence == null || evidence.isBlank()) {
            throw refused("malformed", "no " + this.id() + " evidence presented");
        }
        List<JsonWebKey> keys = RemoteJwksCache.signingKeys(bundleKeys);
        if (keys.isEmpty()) {
            throw refused("config", "no trust bundle with a signing key is configured for this client");
        }
        String trustDomain = config.expectedTrustDomain();
        if (trustDomain == null) {
            throw misconfigured("config", AttestationIssuanceConfig.P_TRUST_DOMAIN + " is required for " + this.id() + " evidence");
        }
        Policy policy = this.policy();
        IssuerRule issuers = this.issuers(config, policy);
        this.checkBindings(config, policy);

        JwtClaims claims = this.verifiedClaims(evidence, keys);
        if (!issuers.accepts(claims.getClaimValueAsString("iss"))) {
            throw refused("iss", "token issuer is not one this attester accepts for " + this.id() + " evidence ("
                    + issuers.source + ")");
        }
        List<String> audiences = this.audiences(claims, config, policy);
        long[] times = this.times(claims, policy);
        Mapped mapped = this.map(claims, policy, config);
        String spiffeId = "spiffe://" + trustDomain + mapped.path();
        return new VerifiedSvid(new SpiffeSvid(spiffeId, trustDomain, mapped.path(), audiences, times[0], times[1], evidence),
                mapped.selectors());
    }

    /** The policy, read once from the process for the built-in registry; a bad value was FAILED_CONFIG at deploy. */
    private Policy policy() throws IssuanceException {
        try {
            return this.policy.get();
        } catch (IllegalArgumentException e) {
            throw count("config", IssuanceException.serverError("the attester's cloud evidence policy is misconfigured: "
                    + e.getMessage()));
        }
    }

    /**
     * The issuers this client's evidence may name: the type's pins, narrowed to the client's
     * {@code attestation_evidence_issuer} when it is one of them. A client may not name an issuer the deployment did not
     * pin; a type with no pin is refused in production and takes the provider's published issuer in development.
     */
    IssuerRule issuers(AttestationIssuanceConfig config, Policy policy) throws IssuanceException {
        String setting = Policy.issuersSetting(this.id());
        Set<String> pins = policy.issuers(this.id());
        String client = config.evidenceIssuer();
        if (pins != null) {
            if (client == null) {
                return IssuerRule.anyOf(pins, setting);
            }
            if (!pins.contains(client)) {
                throw misconfigured("iss_pin", AttestationIssuanceConfig.P_EVIDENCE_ISSUER + " names an issuer " + setting
                        + " does not pin for " + this.id() + " evidence; a client may only narrow the deployment's pins");
            }
            return IssuerRule.anyOf(Set.of(client), AttestationIssuanceConfig.P_EVIDENCE_ISSUER);
        }
        if (policy.production()) {
            warnOnce(this.id() + ":unpinned", "no issuer is pinned for " + this.id() + " evidence, so every " + this.id()
                    + " client is refused (invalid_client); set " + setting);
            throw misconfigured("iss_pin", "no issuer is pinned for " + this.id() + " evidence: set " + setting
                    + " (production refuses a cloud evidence type without one)");
        }
        if (client != null) {
            return IssuerRule.anyOf(Set.of(client), AttestationIssuanceConfig.P_EVIDENCE_ISSUER);
        }
        warnOnce(this.id() + ":default", "no issuer is pinned for " + this.id() + " evidence; under development the "
                + "provider's published issuer is accepted (" + this.developmentIssuer().pattern() + "). Set " + setting
                + " before production, which refuses the type without it");
        return IssuerRule.matching(this.developmentIssuer(), "the provider's published issuer, development only");
    }

    /** The token's claims, once its signature verifies under a signing key of the bundle that fits its algorithm. */
    private JwtClaims verifiedClaims(String evidence, List<JsonWebKey> keys) throws IssuanceException {
        JsonWebSignature jws = new JsonWebSignature();
        String kid;
        String alg;
        try {
            jws.setCompactSerialization(evidence);
            kid = jws.getKeyIdHeaderValue();
            alg = jws.getAlgorithmHeaderValue();
        } catch (Exception e) {
            throw refused("malformed", "token is not a well-formed compact JWS");
        }
        if (alg == null || !PERMITTED_ALGORITHMS.contains(alg)) {
            throw refused("alg", "token is not signed with an asymmetric algorithm this attester accepts");
        }
        jws.setKey(this.verificationKey(keys, kid, alg));
        jws.setAlgorithmConstraints(new AlgorithmConstraints(AlgorithmConstraints.ConstraintType.PERMIT, alg));
        if (!verifies(jws)) {
            throw refused("signature", "token signature did not verify against the trust bundle");
        }
        try {
            return JwtClaims.parse(jws.getPayload());
        } catch (Exception e) {
            throw refused("malformed", "token payload is not valid JWT claims");
        }
    }

    /** Whether the signature verifies; a verification that throws does not. */
    private static boolean verifies(JsonWebSignature jws) {
        try {
            return jws.verifySignature();
        } catch (Exception e) {
            return false;
        }
    }

    /** The bundle key for {@code kid}, or the only key when there is none, provided it fits {@code alg}. */
    Key verificationKey(List<JsonWebKey> keys, String kid, String alg) throws IssuanceException {
        JsonWebKey chosen = null;
        if (kid != null) {
            for (JsonWebKey k : keys) {
                if (kid.equals(k.getKeyId())) {
                    chosen = k;
                    break;
                }
            }
            if (chosen == null) {
                throw refused("key", "no signing key in the trust bundle matches the token's kid");
            }
        } else if (keys.size() == 1) {
            chosen = keys.get(0);
        } else {
            throw refused("key", "token has no kid and the trust bundle holds more than one signing key");
        }
        if (!(chosen instanceof PublicJsonWebKey) || !fits(chosen, alg)) {
            throw refused("key", "the trust-bundle key the token names does not fit its algorithm");
        }
        return ((PublicJsonWebKey) chosen).getPublicKey();
    }

    /** Whether a key's type (and curve) is the one {@code alg} signs with, and its own {@code alg}, if any, is {@code alg}. */
    static boolean fits(JsonWebKey key, String alg) {
        if (key.getAlgorithm() != null && !key.getAlgorithm().equals(alg)) {
            return false;
        }
        if (alg.startsWith("RS") || alg.startsWith("PS")) {
            return key instanceof RsaJsonWebKey;
        }
        if (alg.startsWith("ES")) {
            if (!(key instanceof EllipticCurveJsonWebKey)) {
                return false;
            }
            String curve = ((EllipticCurveJsonWebKey) key).getCurveName();
            return switch (alg) {
                case "ES256" -> EllipticCurves.P_256.equals(curve);
                case "ES384" -> EllipticCurves.P_384.equals(curve);
                default -> EllipticCurves.P_521.equals(curve);
            };
        }
        return key instanceof OctetKeyPairJsonWebKey;
    }

    /** {@code aud}: the client's {@code attestation_issuer} among them, and alone when the policy says so. */
    private List<String> audiences(JwtClaims claims, AttestationIssuanceConfig config, Policy policy)
            throws IssuanceException {
        List<String> audiences;
        try {
            audiences = Objects.requireNonNullElse(claims.getAudience(), List.of());
        } catch (Exception e) {
            throw refused("aud", "token 'aud' is malformed");
        }
        if (!audiences.contains(config.issuer())) {
            throw refused("aud", "token audience does not include this attester (" + AttestationIssuanceConfig.P_ISSUER + ")");
        }
        if (policy.requireSingleAudience() && audiences.size() > 1) {
            throw refused("aud", "token names more than one audience and this attester requires one ("
                    + Policy.SINGLE_AUDIENCE + ")");
        }
        return audiences;
    }

    /** {@code exp}, {@code nbf} and {@code iat} against now with the skew, and the lifetime; {exp, iat}. */
    long[] times(JwtClaims claims, Policy policy) throws IssuanceException {
        long now = NumericDate.now().getValue();
        long exp = this.time(claims, "exp", true);
        if (exp + this.allowedClockSkewSeconds < now) {
            throw refused("exp", "token has expired");
        }
        long nbf = this.time(claims, "nbf", false);
        if (nbf > 0L && nbf - this.allowedClockSkewSeconds > now) {
            throw refused("nbf", "token is not valid yet (nbf)");
        }
        long iat = this.time(claims, "iat", true);
        if (iat - this.allowedClockSkewSeconds > now) {
            throw refused("iat", "token was issued in the future (iat)");
        }
        long max = policy.maxTokenLifetimeSeconds(this.id());
        if (exp - iat > max) {
            throw refused("lifetime", "token was issued to live longer than the " + max
                    + " s this attester accepts of " + this.id() + " evidence (" + Policy.MAX_LIFETIME + ")");
        }
        return new long[] {exp, iat};
    }

    /** A NumericDate claim's seconds; 0 for an absent optional one. */
    private long time(JwtClaims claims, String name, boolean required) throws IssuanceException {
        Object value = claims.getClaimValue(name);
        if (value == null) {
            if (required) {
                throw refused(name, "token has no '" + name + "'");
            }
            return 0L;
        }
        if (!(value instanceof Number)) {
            throw refused(name, "token '" + name + "' is not a NumericDate");
        }
        return ((Number) value).longValue();
    }

    /**
     * A Kubernetes-projected token's mapping (GKE, EKS, AKS): {@code /ns/<namespace>/sa/<name>} from its {@code sub},
     * and the {@code issuer}, {@code namespace} and {@code service_account} selectors.
     */
    protected final Mapped kubernetes(JwtClaims claims) throws IssuanceException {
        String subject = EvidenceSelectors.stringClaim(claims, "sub");
        Matcher matcher = subject == null ? null : KSA_SUBJECT.matcher(subject);
        if (matcher == null || !matcher.matches()) {
            throw refused("subject", "token 'sub' is not a Kubernetes service account");
        }
        return new Mapped("/ns/" + matcher.group(1) + "/sa/" + matcher.group(2), this.selectors("issuer",
                EvidenceSelectors.stringClaim(claims, "iss"), "namespace", matcher.group(1), "service_account", matcher.group(2)));
    }

    /**
     * The selectors a subclass proved, from its fixed list of names, in name, value pairs; a value over the selector
     * bounds is refused {@code invalid_svid} and counted under {@code selectors}.
     */
    protected final EvidenceSelectors selectors(String... nameValuePairs) throws IssuanceException {
        return EvidenceSelectors.of(this.id(), this.selectorNames(), message -> this.refused("selectors", message),
                nameValuePairs);
    }

    /** The evidence refused for {@code check}: {@code invalid_svid}, counted. */
    protected final IssuanceException refused(String check, String message) {
        return count(check, IssuanceException.invalidSvid(message));
    }

    /** The client's configuration refused for {@code check}: {@code invalid_client}, counted. */
    protected final IssuanceException misconfigured(String check, String message) {
        return count(check, IssuanceException.invalidClient(message));
    }

    private IssuanceException count(String check, IssuanceException e) {
        REFUSALS.inc(this.id(), check);
        return e;
    }

    /** This copy's refusals of {@code type} for {@code check}. */
    static long refusals(String type, String check) {
        return REFUSALS.get(type, check);
    }

    private static void warnOnce(String key, String message) {
        if (WARNED.add(key)) {
            LOGGER.warn((Object) message);
        }
    }

    /** Which issuers a token may name, and the setting or property that says so (never the token's own value). */
    static final class IssuerRule {
        private final Set<String> exact;
        private final Pattern pattern;
        final String source;

        private IssuerRule(Set<String> exact, Pattern pattern, String source) {
            this.exact = exact;
            this.pattern = pattern;
            this.source = source;
        }

        static IssuerRule anyOf(Set<String> issuers, String source) {
            return new IssuerRule(Set.copyOf(issuers), null, source);
        }

        static IssuerRule matching(Pattern pattern, String source) {
            return new IssuerRule(Set.of(), pattern, source);
        }

        boolean accepts(String issuer) {
            if (issuer == null) {
                return false;
            }
            return this.pattern != null ? this.pattern.matcher(issuer).matches() : this.exact.contains(issuer);
        }
    }

    /**
     * The deployment's cloud evidence policy, read through the evidence-policy catalogue: the issuers pinned per type,
     * the projects, accounts, tenants and managed identities accepted, the longest token lifetime, and the profile.
     * Every list is optional in the catalogue; production refuses a type with no pinned issuer when evidence of it is
     * presented, and {@code gcp-id-token} with no project list.
     */
    public static final class Policy {
        /** The six cloud evidence types, in the registry's order. */
        static final List<String> TYPES = List.of(AttestationIssuanceConfig.EVIDENCE_GKE_SA_TOKEN,
                AttestationIssuanceConfig.EVIDENCE_GCP_ID_TOKEN, AttestationIssuanceConfig.EVIDENCE_EKS_SA_TOKEN,
                AttestationIssuanceConfig.EVIDENCE_AWS_STS_WEB_IDENTITY, AttestationIssuanceConfig.EVIDENCE_AKS_SA_TOKEN,
                AttestationIssuanceConfig.EVIDENCE_AZURE_MI_TOKEN);

        public static final String GKE_ISSUERS = "OIDF_ATTESTER_GKE_SA_TOKEN_ISSUERS";
        public static final String GCP_ISSUERS = "OIDF_ATTESTER_GCP_ID_TOKEN_ISSUERS";
        public static final String EKS_ISSUERS = "OIDF_ATTESTER_EKS_SA_TOKEN_ISSUERS";
        public static final String AWS_STS_ISSUERS = "OIDF_ATTESTER_AWS_STS_WEB_IDENTITY_ISSUERS";
        public static final String AKS_ISSUERS = "OIDF_ATTESTER_AKS_SA_TOKEN_ISSUERS";
        public static final String AZURE_MI_ISSUERS = "OIDF_ATTESTER_AZURE_MI_TOKEN_ISSUERS";
        public static final String MAX_LIFETIME = "OIDF_ATTESTER_MAX_CLOUD_TOKEN_LIFETIME_SECONDS";
        public static final String GCP_PROJECTS = "OIDF_ATTESTER_GCP_PROJECTS";
        public static final String AWS_ACCOUNTS = "OIDF_ATTESTER_AWS_ACCOUNTS";
        public static final String AZURE_TENANTS = "OIDF_ATTESTER_AZURE_TENANTS";
        public static final String AZURE_MANAGED_IDENTITIES = "OIDF_ATTESTER_AZURE_MANAGED_IDENTITIES";
        static final String SINGLE_AUDIENCE = "OIDF_ATTESTER_REQUIRE_SINGLE_AUDIENCE_EVIDENCE";
        public static final long DEFAULT_MAX_LIFETIME_SECONDS = 3600L;
        /**
         * {@code azure-mi-token}'s longest lifetime when {@link #MAX_LIFETIME} is not set: Microsoft "assigns a random
         * value ranging between 60-90 minutes" as an access token's default lifetime (Microsoft identity platform access
         * tokens, read 2026-09-30), and the IMDS sample response's {@code not_before} is 3900 s before its
         * {@code expires_on} with {@code expires_in} 3599 (How to use managed identities on a VM to acquire an access
         * token, read 2026-09-30), so a token is dated up to five minutes before it is issued: 90 minutes and five.
         */
        public static final long AZURE_MI_DEFAULT_MAX_LIFETIME_SECONDS = 5700L;

        /**
         * A Google Cloud project ID: "6 to 30 characters", "only lowercase letters, numbers, and hyphens", "must start
         * with a letter", "cannot end with a hyphen" (Google, Creating and managing projects, read 2026-09-30).
         */
        static final Pattern PROJECT_ID = Pattern.compile("[a-z][a-z0-9-]{4,28}[a-z0-9]");
        /** An AWS account ID: twelve digits, as the ARN in {@code sub} carries it. */
        static final Pattern ACCOUNT_ID = Pattern.compile("\\d{12}");
        /** A GUID, as Entra's {@code tid} and {@code oid} are: "String, a GUID". */
        static final Pattern GUID = Pattern.compile("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}");

        private static volatile Policy process;

        private final Map<String, Set<String>> issuers;
        private final long maxTokenLifetimeSeconds;
        private final boolean lifetimeDefaulted;
        private final Set<String> gcpProjects;
        private final Set<String> awsAccounts;
        private final Set<String> azureTenants;
        private final Set<String> azureManagedIdentities;
        private final boolean requireSingleAudience;
        private final boolean production;

        private Policy(Map<String, Set<String>> issuers, long maxTokenLifetimeSeconds, boolean lifetimeDefaulted,
                       Set<String> gcpProjects, Set<String> awsAccounts, Set<String> azureTenants,
                       Set<String> azureManagedIdentities, boolean requireSingleAudience, boolean production) {
            this.issuers = Collections.unmodifiableMap(new LinkedHashMap<>(issuers));
            this.maxTokenLifetimeSeconds = maxTokenLifetimeSeconds;
            this.lifetimeDefaulted = lifetimeDefaulted;
            this.gcpProjects = gcpProjects;
            this.awsAccounts = awsAccounts;
            this.azureTenants = azureTenants;
            this.azureManagedIdentities = azureManagedIdentities;
            this.requireSingleAudience = requireSingleAudience;
            this.production = production;
        }

        /** The setting that pins {@code type}'s issuers. */
        static String issuersSetting(String type) {
            return switch (type) {
                case AttestationIssuanceConfig.EVIDENCE_GKE_SA_TOKEN -> GKE_ISSUERS;
                case AttestationIssuanceConfig.EVIDENCE_GCP_ID_TOKEN -> GCP_ISSUERS;
                case AttestationIssuanceConfig.EVIDENCE_EKS_SA_TOKEN -> EKS_ISSUERS;
                case AttestationIssuanceConfig.EVIDENCE_AWS_STS_WEB_IDENTITY -> AWS_STS_ISSUERS;
                case AttestationIssuanceConfig.EVIDENCE_AKS_SA_TOKEN -> AKS_ISSUERS;
                case AttestationIssuanceConfig.EVIDENCE_AZURE_MI_TOKEN -> AZURE_MI_ISSUERS;
                default -> throw new IllegalArgumentException(type + " is not a cloud evidence type");
            };
        }

        /** The process's policy, read once; a value its entry refuses is an {@link IllegalArgumentException}. */
        static Policy process() {
            Policy local = process;
            if (local == null) {
                local = fromEnvironment(System::getProperty, System::getenv);
                process = local;
            }
            return local;
        }

        /**
         * The policy the sources describe, strictly: each issuer an https URL, each project a project ID and never a
         * pattern, each account twelve digits, each tenant and managed identity a GUID, the lifetime 60-86400 s.
         *
         * @throws IllegalArgumentException naming the setting a value is refused for
         */
        public static Policy fromEnvironment(Function<String, String> props, Function<String, String> env) {
            Settings settings = Settings.of(CatalogueHolder.CATALOGUE, Sources.of(env, props, null));
            try {
                Map<String, Set<String>> issuers = new LinkedHashMap<>();
                issuers.put(AttestationIssuanceConfig.EVIDENCE_GKE_SA_TOKEN, issuerList(GKE_ISSUERS, settings.words(GKE_ISSUERS)));
                issuers.put(AttestationIssuanceConfig.EVIDENCE_GCP_ID_TOKEN, issuerList(GCP_ISSUERS, settings.words(GCP_ISSUERS)));
                issuers.put(AttestationIssuanceConfig.EVIDENCE_EKS_SA_TOKEN, issuerList(EKS_ISSUERS, settings.words(EKS_ISSUERS)));
                issuers.put(AttestationIssuanceConfig.EVIDENCE_AWS_STS_WEB_IDENTITY,
                        issuerList(AWS_STS_ISSUERS, settings.words(AWS_STS_ISSUERS)));
                issuers.put(AttestationIssuanceConfig.EVIDENCE_AKS_SA_TOKEN, issuerList(AKS_ISSUERS, settings.words(AKS_ISSUERS)));
                issuers.put(AttestationIssuanceConfig.EVIDENCE_AZURE_MI_TOKEN,
                        issuerList(AZURE_MI_ISSUERS, settings.words(AZURE_MI_ISSUERS)));
                return new Policy(issuers, settings.duration(MAX_LIFETIME).getSeconds(),
                        settings.resolve(MAX_LIFETIME).provenance().isDefault(),
                        list(GCP_PROJECTS, settings.words(GCP_PROJECTS), PROJECT_ID, "a Google Cloud project ID (no wildcard)"),
                        list(AWS_ACCOUNTS, settings.words(AWS_ACCOUNTS), ACCOUNT_ID, "a twelve-digit AWS account ID"),
                        list(AZURE_TENANTS, settings.words(AZURE_TENANTS), GUID, "a tenant ID (a GUID)"),
                        list(AZURE_MANAGED_IDENTITIES, settings.words(AZURE_MANAGED_IDENTITIES), GUID,
                                "a managed identity's object ID (a GUID)"),
                        settings.bool(SINGLE_AUDIENCE), DeploymentProfile.of(env).isProduction());
            } catch (SettingRefused e) {
                throw new IllegalArgumentException(e.getMessage(), e);
            }
        }

        /** A policy for a test or an embedding: the pins per type, and the lists; null for a list not configured. */
        public static Policy of(Map<String, Set<String>> issuers, long maxTokenLifetimeSeconds, Set<String> gcpProjects,
                                Set<String> awsAccounts, Set<String> azureTenants, Set<String> azureManagedIdentities,
                                boolean requireSingleAudience, boolean production) {
            return new Policy(issuers, maxTokenLifetimeSeconds, false, gcpProjects, awsAccounts, azureTenants,
                    azureManagedIdentities, requireSingleAudience, production);
        }

        private static Set<String> issuerList(String name, Set<String> words) {
            if (words == null) {
                return null;
            }
            for (String word : words) {
                java.net.URI uri;
                try {
                    uri = new java.net.URI(word);
                } catch (java.net.URISyntaxException e) {
                    throw new IllegalArgumentException(name + " lists a value that is not a URL; each is an https issuer URL", e);
                }
                if (!"https".equals(uri.getScheme()) || uri.getHost() == null || uri.getRawQuery() != null
                        || uri.getRawFragment() != null) {
                    throw new IllegalArgumentException(name + " lists a value that is not an https issuer URL with a host "
                            + "and no query or fragment");
                }
            }
            return Set.copyOf(words);
        }

        private static Set<String> list(String name, Set<String> words, Pattern grammar, String what) {
            if (words == null) {
                return null;
            }
            List<String> out = new ArrayList<>();
            for (String word : words) {
                String value = word.toLowerCase(Locale.ROOT);
                if (!grammar.matcher(value).matches()) {
                    throw new IllegalArgumentException(name + " lists a value that is not " + what);
                }
                out.add(value);
            }
            return Set.copyOf(out);
        }

        /** The issuers pinned for {@code type}, or null when none are. */
        Set<String> issuers(String type) {
            return this.issuers.get(type);
        }

        long maxTokenLifetimeSeconds() {
            return this.maxTokenLifetimeSeconds;
        }

        /**
         * The longest {@code type}'s tokens may be issued to live: the setting when it is set, for every type; unset,
         * {@value #DEFAULT_MAX_LIFETIME_SECONDS} s, except {@code azure-mi-token}'s
         * {@value #AZURE_MI_DEFAULT_MAX_LIFETIME_SECONDS} s, since Entra chooses a managed identity's token lifetime and
         * the caller cannot ask for a shorter one.
         */
        long maxTokenLifetimeSeconds(String type) {
            if (this.lifetimeDefaulted && AttestationIssuanceConfig.EVIDENCE_AZURE_MI_TOKEN.equals(type)) {
                return AZURE_MI_DEFAULT_MAX_LIFETIME_SECONDS;
            }
            return this.maxTokenLifetimeSeconds;
        }

        /** The Google Cloud projects accepted, or null when the list is not set. */
        Set<String> gcpProjects() {
            return this.gcpProjects;
        }

        Set<String> awsAccounts() {
            return this.awsAccounts;
        }

        Set<String> azureTenants() {
            return this.azureTenants;
        }

        Set<String> azureManagedIdentities() {
            return this.azureManagedIdentities;
        }

        boolean requireSingleAudience() {
            return this.requireSingleAudience;
        }

        boolean production() {
            return this.production;
        }

        /** The evidence-policy catalogue, loaded once from this class's loader. */
        private static final class CatalogueHolder {
            static final Catalogue CATALOGUE = Catalogue.load(CloudTokenValidator.class.getClassLoader(), EvidencePolicy.SETTINGS);
        }
    }
}
