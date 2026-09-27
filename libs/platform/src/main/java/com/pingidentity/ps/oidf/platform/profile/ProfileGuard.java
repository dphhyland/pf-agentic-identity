/*
 * The three questions a governed switch asks of the deployment profile.
 */
package com.pingidentity.ps.oidf.platform.profile;

import java.util.Objects;

/**
 * What the production profile says about a switch (plan decision 4): an insecure switch is forbidden, a secure
 * one may be required, and a risky but legitimate one needs its risk in {@value AcceptedRisks#SETTING}. Under the
 * development profile every answer is yes. Each question returns null when the setting is allowed and a
 * {@link Refusal} naming the setting and the reason when it is not.
 *
 * <p>This is the mechanism only. Nothing asks these questions yet: PR-2 (Phase 3) wires each governed switch to
 * one, and PR-5 turns the answers into a refused component; until then the start-up audit (F-2) reports
 * (PLAN.md decision 7).
 */
public final class ProfileGuard {
    private final DeploymentProfile profile;
    private final AcceptedRisks risks;

    private ProfileGuard(DeploymentProfile profile, AcceptedRisks risks) {
        this.profile = Objects.requireNonNull(profile, "profile");
        this.risks = Objects.requireNonNull(risks, "risks");
    }

    /** This process's guard: its profile and accepted risks, from its environment. */
    public static ProfileGuard current() {
        return of(DeploymentProfile.current(), AcceptedRisks.current());
    }

    public static ProfileGuard of(DeploymentProfile profile, AcceptedRisks risks) {
        return new ProfileGuard(profile, risks);
    }

    public DeploymentProfile profile() {
        return this.profile;
    }

    public AcceptedRisks risks() {
        return this.risks;
    }

    /**
     * An insecure switch: refused when it is on under the production profile.
     *
     * @param setting the switch as an operator sets it, for example {@code OIDF_FEDERATION_IGNORE_SSL_ERRORS}
     * @param on      whether it is on
     * @param reason  why production forbids it, as a clause
     */
    public Refusal forbidInProduction(String setting, boolean on, String reason) {
        if (!on || this.profile.isDevelopment()) {
            return null;
        }
        return new Refusal(setting, setting + " is forbidden under the production profile: " + reason + ". Turn it off, or set "
                + DeploymentProfile.SETTING + "=development on a rig");
    }

    /**
     * A secure switch production depends on: refused when it is off under the production profile.
     *
     * @param on whether it is on (or set, for a setting production needs a value for)
     */
    public Refusal requireInProduction(String setting, boolean on, String reason) {
        if (on || this.profile.isDevelopment()) {
            return null;
        }
        return new Refusal(setting, setting + " is required under the production profile: " + reason + ". Set it, or set "
                + DeploymentProfile.SETTING + "=development on a rig");
    }

    /**
     * A risky but legitimate switch: refused when it is on under the production profile and {@code risk} is not
     * accepted - not listed, or listed and refused, for example because it expired.
     */
    public Refusal requireRisk(String setting, boolean on, AcceptedRisk risk, String reason) {
        Objects.requireNonNull(risk, "risk");
        if (!on || this.profile.isDevelopment() || this.risks.accepts(risk)) {
            return null;
        }
        return new Refusal(setting, setting + " is on under the production profile and " + AcceptedRisks.SETTING
                + " does not accept '" + risk.id() + "': " + reason + ". Turn it off, or add " + risk.id()
                + (risk.dated() ? "@YYYY-MM-DD" : " (or " + risk.id() + "@YYYY-MM-DD, to make it expire)") + " to "
                + AcceptedRisks.SETTING);
    }

    /** Why a setting is not allowed: the setting, and a message that names it and the reason. */
    public record Refusal(String setting, String message) {
        public Refusal {
            Objects.requireNonNull(setting, "setting");
            Objects.requireNonNull(message, "message");
        }
    }
}
