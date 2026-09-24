/*
 * Where this deployment asks a policy decision point.
 */
package com.pingidentity.ps.oidf.federation.policy;

import java.util.Locale;

/** The decisions a policy decision point is asked for, and the AuthZEN action name each one sends. */
public enum DecisionPoint {
    EXPLICIT_REGISTRATION("federation.register.explicit"),
    AUTOMATIC_REGISTRATION("federation.register.automatic"),
    HOSTED_ENTITY_ENROL("federation.hosted_entity.enrol");

    private final String action;

    DecisionPoint(String action) {
        this.action = action;
    }

    /** The AuthZEN {@code action.name}. */
    public String action() {
        return this.action;
    }

    /** The configuration name: {@code explicit_registration}, and so on. */
    public String settingName() {
        return this.name().toLowerCase(Locale.ROOT);
    }
}
