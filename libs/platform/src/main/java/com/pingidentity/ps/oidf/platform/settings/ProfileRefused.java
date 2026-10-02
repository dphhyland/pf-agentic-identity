/*
 * A setting refused by the production profile.
 */
package com.pingidentity.ps.oidf.platform.settings;

import java.util.Objects;

/**
 * A setting, or a condition in code, the production profile refuses (plan item PR-5): a {@link SettingRefused}
 * carrying the {@link ProfileAudit.Violation}, so a part's {@code init} that lets it out is recorded
 * {@code REFUSED} rather than {@code FAILED_CONFIG} ({@code platform.health.ComponentParts}), and its reason is the
 * violation's.
 */
public final class ProfileRefused extends SettingRefused {

    private static final long serialVersionUID = 1L;

    private final transient ProfileAudit.Violation violation;

    public ProfileRefused(ProfileAudit.Violation violation) {
        super(Objects.requireNonNull(violation, "violation").setting(), violation.message());
        this.violation = violation;
    }

    /** What was refused, why, the fix and the components. */
    public ProfileAudit.Violation violation() {
        return this.violation;
    }
}
