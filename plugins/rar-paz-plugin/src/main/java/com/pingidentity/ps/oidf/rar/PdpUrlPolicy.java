/*
 * The one rule about where a decision may be sent: over TLS, unless this is a development deployment.
 */
package com.pingidentity.ps.oidf.rar;

import org.sourceid.saml20.adapter.conf.Field;
import org.sourceid.saml20.adapter.gui.validation.FieldValidator;
import org.sourceid.saml20.adapter.gui.validation.ValidationException;

import java.net.URI;
import java.net.URISyntaxException;

/**
 * A PDP URL is {@code https} unless {@code OIDF_DEPLOYMENT_PROFILE=development}. The decision about a payment
 * travels on it, with the shared secret in a header; plaintext is a production misconfiguration, not a
 * choice. Checked twice on purpose: {@link Validator} runs in the admin console and the admin API, where the
 * message reaches the person typing, and {@link #check} runs at configure time, which is the only check an
 * archive import gets.
 *
 * <p>The profile is platform's {@code DeploymentProfile} (plan item PR-1), shaded into this jar: unset means
 * production.
 */
final class PdpUrlPolicy {

    // Through GovernanceEngineConfig, which calls DeploymentProfile. Naming DeploymentProfile.SETTING here left an
    // unrelocated class entry for it in the shaded jar: javac 20 records the class whose constant it inlines, and
    // nothing in this class used the entry, so the shade plugin did not rewrite it (javap, 2026-09-28;
    // ShadedJarCheck).
    static final String PROFILE_ENV = GovernanceEngineConfig.PROFILE_ENV;

    private PdpUrlPolicy() { }

    /**
     * @return {@code null} when the URL is acceptable under the profile, else the reason it is not
     */
    static String problem(String url, String profile) {
        if (url == null || url.isBlank()) {
            return "PDP URL is required";
        }
        URI uri;
        try {
            uri = new URI(url.trim());
        } catch (URISyntaxException e) {
            return "PDP URL is not a URL: " + e.getMessage();
        }
        String scheme = uri.getScheme() == null ? "" : uri.getScheme().toLowerCase(java.util.Locale.ROOT);
        if (uri.getHost() == null) {
            return "PDP URL has no host";
        }
        if ("https".equals(scheme)) {
            return null;
        }
        if ("http".equals(scheme) && GovernanceEngineConfig.PROFILE_DEVELOPMENT.equals(profile)) {
            return null;
        }
        if ("http".equals(scheme)) {
            return "PDP URL must be https: a plaintext PDP URL is allowed only when " + PROFILE_ENV
                    + "=development, and this deployment is " + profile;
        }
        return "PDP URL scheme must be https (or http in development), not '" + uri.getScheme() + "'";
    }

    /** {@link #problem}, thrown, for configure time. */
    static String check(String url, String profile) {
        String problem = problem(url, profile);
        if (problem != null) {
            throw new IllegalStateException(problem);
        }
        return url.trim();
    }

    /** The admin-console half: the same rule as a field validator on the PDP URL field. */
    static final class Validator implements FieldValidator {

        private final String profile;

        Validator(String profile) {
            this.profile = profile;
        }

        @Override
        public void validate(Field field) throws ValidationException {
            String problem = problem(field == null ? null : field.getValue(), profile);
            if (problem != null) {
                throw new ValidationException(problem);
            }
        }
    }
}
