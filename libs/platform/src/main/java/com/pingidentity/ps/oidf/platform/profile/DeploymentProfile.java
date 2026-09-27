/*
 * The deployment profile: development for a rig or a demo, production for everything else.
 */
package com.pingidentity.ps.oidf.platform.profile;

import java.util.Locale;
import java.util.function.Function;

/**
 * Which profile this process runs under, read from {@value #SETTING}. The one rule, for every module (plan item
 * PR-1): {@code development} - trimmed, in any case - is development; unset, blank, {@code production} and any
 * other value are production, so a typo lands on the safe side. The image's entrypoint applies the same rule in
 * shell ({@code is_development} in build/pingfederate/pf-entrypoint.sh), and {@code DeploymentProfileShellTest}
 * runs one table through both.
 *
 * <p>There is no third profile. The environment is the only source: a system property of the same meaning does
 * not exist, so a JVM flag cannot turn a production container into a development one.
 */
public enum DeploymentProfile {
    DEVELOPMENT("development"),
    PRODUCTION("production");

    /** The environment variable that names the profile. */
    public static final String SETTING = "OIDF_DEPLOYMENT_PROFILE";

    private final String value;

    DeploymentProfile(String value) {
        this.value = value;
    }

    /** The profile's name as {@value #SETTING} spells it: {@code development} or {@code production}. */
    public String value() {
        return this.value;
    }

    public boolean isProduction() {
        return this == PRODUCTION;
    }

    public boolean isDevelopment() {
        return this == DEVELOPMENT;
    }

    /** This process's profile, from its environment. */
    public static DeploymentProfile current() {
        return of(System::getenv);
    }

    /** The profile an environment names; {@code env} maps a variable's name to its value, or null when unset. */
    public static DeploymentProfile of(Function<String, String> env) {
        return parse(env.apply(SETTING));
    }

    /** The profile a value of {@value #SETTING} names: development for {@code development} (trimmed, any case) only. */
    public static DeploymentProfile parse(String value) {
        return value != null && DEVELOPMENT.value.equals(value.trim().toLowerCase(Locale.ROOT)) ? DEVELOPMENT : PRODUCTION;
    }

    /**
     * rar-model's stricter reading, kept as it was (finding F-0160): development only for exactly
     * {@code development} after trimming, lower case. {@code Development} is development everywhere else but
     * leaves rar-model's common-fields fallback off - the safe side. PR-2 decides whether the two meet.
     */
    public static boolean isExactlyDevelopment(Function<String, String> env) {
        String value = env.apply(SETTING);
        return value != null && DEVELOPMENT.value.equals(value.trim());
    }

    /**
     * How a refusal names the profile an environment is in when it is production: {@code OIDF_DEPLOYMENT_PROFILE is
     * unset, which is production} or {@code OIDF_DEPLOYMENT_PROFILE is 'x', which counts as production}. For
     * development it says {@code OIDF_DEPLOYMENT_PROFILE is 'development'}, as the variable spells it.
     */
    public static String describe(Function<String, String> env) {
        String value = env.apply(SETTING);
        if (value == null) {
            return SETTING + " is unset, which is production";
        }
        return SETTING + " is '" + value + "'" + (parse(value).isProduction() ? ", which counts as production" : "");
    }
}
