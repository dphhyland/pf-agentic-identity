/*
 * How a setting stands with the deployment profile.
 */
package com.pingidentity.ps.oidf.platform.settings;

import java.util.regex.Pattern;

/**
 * How a setting stands with the deployment profile (plan items PR-1, PR-2): allowed in {@code any} profile,
 * {@code forbidden-in-production}, allowed in production only under an {@code accepted-risk:<id>}, or
 * {@code required-in-production}. Recorded here; the profile package (PR1) and the start-up audit (PR-5,
 * Phase 3) are what act on it.
 *
 * @param kind   which of the four
 * @param riskId the accepted risk's id, for {@link Kind#ACCEPTED_RISK}; null otherwise
 */
public record ProfileClass(Kind kind, String riskId) {

    /** A risk id: lower-case words joined by single hyphens, at most 64 characters. */
    private static final Pattern RISK_ID = Pattern.compile("[a-z0-9]+(-[a-z0-9]+)*");

    /** The four classes. */
    public enum Kind { ANY, FORBIDDEN_IN_PRODUCTION, ACCEPTED_RISK, REQUIRED_IN_PRODUCTION }

    /** Allowed in any profile. */
    public static final ProfileClass ANY = new ProfileClass(Kind.ANY, null);

    /**
     * The class a catalogue spells {@code text}.
     *
     * @throws IllegalArgumentException for anything else, or a risk id that is not lower-case words joined by hyphens
     */
    public static ProfileClass parse(String text) {
        switch (text) {
            case "any":
                return ANY;
            case "forbidden-in-production":
                return new ProfileClass(Kind.FORBIDDEN_IN_PRODUCTION, null);
            case "required-in-production":
                return new ProfileClass(Kind.REQUIRED_IN_PRODUCTION, null);
            default:
                String prefix = "accepted-risk:";
                if (text.startsWith(prefix)) {
                    String id = text.substring(prefix.length());
                    if (id.length() <= 64 && RISK_ID.matcher(id).matches()) {
                        return new ProfileClass(Kind.ACCEPTED_RISK, id);
                    }
                }
                throw new IllegalArgumentException("profile must be any, forbidden-in-production, required-in-production"
                        + " or accepted-risk:<id> (lower-case words joined by hyphens), not " + text);
        }
    }

    /** The catalogue's spelling. */
    @Override
    public String toString() {
        switch (this.kind) {
            case ANY:
                return "any";
            case FORBIDDEN_IN_PRODUCTION:
                return "forbidden-in-production";
            case REQUIRED_IN_PRODUCTION:
                return "required-in-production";
            default:
                return "accepted-risk:" + this.riskId;
        }
    }
}
