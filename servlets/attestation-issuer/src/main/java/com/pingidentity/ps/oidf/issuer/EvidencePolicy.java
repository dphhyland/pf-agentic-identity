/*
 * What the attester accepts of a piece of evidence beyond its validity: how long it may live, how many audiences it may name.
 */
package com.pingidentity.ps.oidf.issuer;

import java.util.Locale;
import java.util.function.Function;
import com.pingidentity.ps.oidf.clientattestation.ClientAttestationConfig;
import com.pingidentity.ps.oidf.platform.profile.DeploymentProfile;

/**
 * The deployment-wide policy on instance evidence, read from the environment once and applied to every
 * validated {@link InstanceIdentity} before it is bound and minted against.
 *
 * <ul>
 *   <li>{@code OIDF_ATTESTER_MAX_EVIDENCE_LIFETIME_SECONDS} (system property
 *       {@code oidf.attester.max.evidence.lifetime.seconds}): the longest lifetime the attester accepts of a
 *       piece of evidence, default {@value #PRODUCTION_MAX_EVIDENCE_LIFETIME_SECONDS} s (a day). It caps the
 *       whole lifetime ({@code exp - iat}) when the evidence has an {@code iat}, and what is left of it
 *       ({@code exp - now}, with {@value #CLOCK_SKEW_SECONDS} s allowed for a clock behind the issuer's)
 *       always. Evidence is bound to its first presenter for as long as it lives, so this is also how long a
 *       stolen token can be presented before it dies, and why the production profile refuses a longer value:
 *       a rig may set one, production may only shorten it.</li>
 *   <li>{@code OIDF_ATTESTER_REQUIRE_SINGLE_AUDIENCE_EVIDENCE}: {@code true} refuses evidence whose {@code aud}
 *       names more than one party. Evidence minted for several audiences is presentable to every one of
 *       them, so the attester cannot know it was the intended recipient; default {@code false}, because the
 *       platforms that mint the cloud tokens decide their audience lists.</li>
 * </ul>
 *
 * <p>The profile is platform's {@link DeploymentProfile} (plan item PR-1), the one rule every module reads.
 */
public final class EvidencePolicy {
    public static final String MAX_LIFETIME_ENV = "OIDF_ATTESTER_MAX_EVIDENCE_LIFETIME_SECONDS";
    public static final String MAX_LIFETIME_PROPERTY = "oidf.attester.max.evidence.lifetime.seconds";
    public static final String SINGLE_AUDIENCE_ENV = "OIDF_ATTESTER_REQUIRE_SINGLE_AUDIENCE_EVIDENCE";
    public static final String SINGLE_AUDIENCE_PROPERTY = "oidf.attester.require.single.audience.evidence";
    public static final String PROFILE_ENV = DeploymentProfile.SETTING;
    public static final long PRODUCTION_MAX_EVIDENCE_LIFETIME_SECONDS = 86400L;
    /** Allowed on the remaining-life check, for a clock behind the evidence issuer's: the verifier's usual skew. */
    public static final long CLOCK_SKEW_SECONDS = ClientAttestationConfig.DEFAULT_CLOCK_SKEW_SECONDS;

    private final long maxEvidenceLifetimeSeconds;
    private final boolean requireSingleAudience;

    public EvidencePolicy(long maxEvidenceLifetimeSeconds, boolean requireSingleAudience) {
        if (maxEvidenceLifetimeSeconds <= 0L) {
            throw new IllegalArgumentException(MAX_LIFETIME_ENV + " must be positive, got " + maxEvidenceLifetimeSeconds);
        }
        this.maxEvidenceLifetimeSeconds = maxEvidenceLifetimeSeconds;
        this.requireSingleAudience = requireSingleAudience;
    }

    public static EvidencePolicy defaults() {
        return new EvidencePolicy(PRODUCTION_MAX_EVIDENCE_LIFETIME_SECONDS, false);
    }

    public static EvidencePolicy fromEnvironment() {
        return fromEnvironment(System::getProperty, System::getenv);
    }

    /**
     * @throws IllegalArgumentException for a value that is not a positive number, a switch that is neither
     *                                  {@code true} nor {@code false}, or a lifetime above the production cap
     *                                  under the production profile - each naming the variable
     */
    public static EvidencePolicy fromEnvironment(Function<String, String> props, Function<String, String> env) {
        long lifetime = PRODUCTION_MAX_EVIDENCE_LIFETIME_SECONDS;
        String raw = firstSet(props.apply(MAX_LIFETIME_PROPERTY), env.apply(MAX_LIFETIME_ENV));
        if (raw != null) {
            try {
                lifetime = Long.parseLong(raw);
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException(MAX_LIFETIME_ENV + " is not a number: " + raw);
            }
            if (lifetime <= 0L) {
                throw new IllegalArgumentException(MAX_LIFETIME_ENV + " must be positive, got " + raw);
            }
            if (lifetime > PRODUCTION_MAX_EVIDENCE_LIFETIME_SECONDS && isProduction(env)) {
                throw new IllegalArgumentException(MAX_LIFETIME_ENV + "=" + raw + " is above the production cap of "
                        + PRODUCTION_MAX_EVIDENCE_LIFETIME_SECONDS + " s; production may only shorten it. Set "
                        + PROFILE_ENV + "=development on a rig that needs longer-lived evidence");
            }
        }
        boolean single = false;
        String switchValue = firstSet(props.apply(SINGLE_AUDIENCE_PROPERTY), env.apply(SINGLE_AUDIENCE_ENV));
        if (switchValue != null) {
            String lower = switchValue.toLowerCase(Locale.ROOT);
            if ("true".equals(lower)) {
                single = true;
            } else if (!"false".equals(lower)) {
                throw new IllegalArgumentException(SINGLE_AUDIENCE_ENV + " must be true or false, got " + switchValue);
            }
        }
        return new EvidencePolicy(lifetime, single);
    }

    /** Everything but {@code OIDF_DEPLOYMENT_PROFILE=development} is production, an unset variable included. */
    public static boolean isProduction(Function<String, String> env) {
        return DeploymentProfile.of(env).isProduction();
    }

    public long maxEvidenceLifetimeSeconds() {
        return this.maxEvidenceLifetimeSeconds;
    }

    public boolean requireSingleAudience() {
        return this.requireSingleAudience;
    }

    /**
     * Applies the policy to validated evidence.
     *
     * @throws IssuanceException {@code invalid_svid} (a SPIFFE identity) or {@code invalid_instance_attestation}
     *                           when the evidence lives longer than accepted or names more audiences than allowed
     */
    public void check(InstanceIdentity instance, long nowEpochSeconds) throws IssuanceException {
        long lifetime = instance.iatEpochSeconds() > 0L ? instance.expEpochSeconds() - instance.iatEpochSeconds() : 0L;
        if (lifetime > this.maxEvidenceLifetimeSeconds) {
            throw refuse(instance, "the evidence was issued to live " + lifetime + " s, more than the " + this.maxEvidenceLifetimeSeconds
                    + " s this attester accepts (" + MAX_LIFETIME_ENV + "); present shorter-lived evidence");
        }
        long remaining = instance.expEpochSeconds() - nowEpochSeconds;
        if (remaining > this.maxEvidenceLifetimeSeconds + CLOCK_SKEW_SECONDS) {
            throw refuse(instance, "the evidence has " + remaining + " s of life left, more than the " + this.maxEvidenceLifetimeSeconds
                    + " s this attester accepts (" + MAX_LIFETIME_ENV + "); present shorter-lived evidence");
        }
        if (this.requireSingleAudience && instance.audiences().size() > 1) {
            throw refuse(instance, "evidence names " + instance.audiences().size() + " audiences and this attester requires one ("
                    + SINGLE_AUDIENCE_ENV + ")");
        }
    }

    /** The attestation lifetime: the client's configured TTL, and never past the evidence. */
    public static long effectiveTtlSeconds(long configuredTtlSeconds, InstanceIdentity instance, long nowEpochSeconds) {
        return Math.max(1L, Math.min(configuredTtlSeconds, instance.expEpochSeconds() - nowEpochSeconds));
    }

    private static IssuanceException refuse(InstanceIdentity instance, String message) {
        return SpiffeInstanceAttestationValidator.FORMAT.equals(instance.format())
                ? IssuanceException.invalidSvid(message)
                : IssuanceException.invalidInstanceAttestation(message);
    }

    private static String firstSet(String a, String b) {
        if (a != null && !a.isBlank()) {
            return a.trim();
        }
        if (b != null && !b.isBlank()) {
            return b.trim();
        }
        return null;
    }
}
