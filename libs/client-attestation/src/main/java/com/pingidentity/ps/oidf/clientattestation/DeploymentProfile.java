/*
 * The deployment profile, as platform reads it: everything but "development" is production.
 */
package com.pingidentity.ps.oidf.clientattestation;

import java.util.function.Function;

/**
 * Whether this process runs under the production profile, asked of
 * {@link com.pingidentity.ps.oidf.platform.profile.DeploymentProfile}, the one rule (plan item PR-1):
 * {@code OIDF_DEPLOYMENT_PROFILE=development} means a rig or a demo; unset, {@code production} or any other value
 * means production, so a typo lands on the safe side.
 */
final class DeploymentProfile {
    static final String PROFILE_ENV = com.pingidentity.ps.oidf.platform.profile.DeploymentProfile.SETTING;

    private DeploymentProfile() {
    }

    /** Everything but {@code OIDF_DEPLOYMENT_PROFILE=development} is production, an unset variable included. */
    static boolean isProduction(Function<String, String> env) {
        return com.pingidentity.ps.oidf.platform.profile.DeploymentProfile.of(env).isProduction();
    }
}
