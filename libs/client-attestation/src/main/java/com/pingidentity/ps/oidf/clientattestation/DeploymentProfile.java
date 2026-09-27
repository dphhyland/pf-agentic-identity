/*
 * The deployment profile, read from the environment: everything but "development" is production.
 */
package com.pingidentity.ps.oidf.clientattestation;

import java.util.Locale;
import java.util.function.Function;

/**
 * Whether this process runs under the production profile. {@code OIDF_DEPLOYMENT_PROFILE=development} means a
 * rig or a demo; unset, {@code production} or any other value means production, so a typo lands on the safe
 * side.
 *
 * <p>The profile is read from the environment directly, here as in the image's entrypoint and the CIBA
 * simulator. Plan item PR-1 (Phase 2) centralises it; until then this is the whole definition.
 */
final class DeploymentProfile {
    static final String PROFILE_ENV = "OIDF_DEPLOYMENT_PROFILE";

    private DeploymentProfile() {
    }

    /** Everything but {@code OIDF_DEPLOYMENT_PROFILE=development} is production, an unset variable included. */
    static boolean isProduction(Function<String, String> env) {
        String value = env.apply(PROFILE_ENV);
        return value == null || !"development".equals(value.trim().toLowerCase(Locale.ROOT));
    }
}
