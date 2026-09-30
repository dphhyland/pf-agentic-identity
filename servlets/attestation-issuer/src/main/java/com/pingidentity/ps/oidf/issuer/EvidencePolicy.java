/*
 * What the attester accepts of a piece of evidence beyond its validity: how long it may live, how many audiences it may name.
 */
package com.pingidentity.ps.oidf.issuer;

import java.util.function.Function;
import com.pingidentity.ps.oidf.clientattestation.ClientAttestationConfig;
import com.pingidentity.ps.oidf.platform.profile.DeploymentProfile;
import com.pingidentity.ps.oidf.platform.settings.Catalogue;
import com.pingidentity.ps.oidf.platform.settings.SettingRefused;
import com.pingidentity.ps.oidf.platform.settings.Settings;
import com.pingidentity.ps.oidf.platform.settings.Sources;

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
     * The policy the sources describe, read through the {@value #SETTINGS} settings catalogue, strictly (plan item
     * ST-5): the lifetime a whole number of seconds from 1, the switch {@code true} or {@code false} in any case. The
     * reader before 0.6.0 refused any other spelling of the switch in both profiles; production still does, and under
     * development platform's legacy rule now reads {@code yes}, {@code no}, {@code 1}, {@code 0}, {@code on} and
     * {@code off} as {@code false}, with a warning naming the strict spelling.
     *
     * @throws IllegalArgumentException for a value its entry refuses, or a lifetime above the production cap under the
     *                                  production profile - each naming the variable
     */
    public static EvidencePolicy fromEnvironment(Function<String, String> props, Function<String, String> env) {
        Settings settings = Settings.of(CatalogueHolder.CATALOGUE, Sources.of(env, props, null));
        long lifetime;
        boolean single;
        try {
            lifetime = settings.duration(MAX_LIFETIME_ENV).getSeconds();
            single = settings.bool(SINGLE_AUDIENCE_ENV);
        } catch (SettingRefused e) {
            throw new IllegalArgumentException(e.getMessage(), e);
        }
        if (lifetime > PRODUCTION_MAX_EVIDENCE_LIFETIME_SECONDS && isProduction(env)) {
            throw new IllegalArgumentException(MAX_LIFETIME_ENV + "=" + lifetime + " is above the production cap of "
                    + PRODUCTION_MAX_EVIDENCE_LIFETIME_SECONDS + " s; production may only shorten it. Set "
                    + PROFILE_ENV + "=development on a rig that needs longer-lived evidence");
        }
        return new EvidencePolicy(lifetime, single);
    }

    /** The settings catalogue the policy is read through. */
    public static final String SETTINGS = "evidence-policy";

    /** The catalogue, loaded once from this class's loader. */
    private static final class CatalogueHolder {
        static final Catalogue CATALOGUE = Catalogue.load(EvidencePolicy.class.getClassLoader(), SETTINGS);
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
}
