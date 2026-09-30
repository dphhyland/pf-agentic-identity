/*
 * The production profile's rules for the processor's own fields, from its settings catalogue (plan item PR-3).
 */
package com.pingidentity.ps.oidf.rar;

import com.pingidentity.ps.oidf.platform.profile.DeploymentProfile;
import com.pingidentity.ps.oidf.platform.settings.Catalogue;
import com.pingidentity.ps.oidf.platform.settings.ProfileRefused;
import com.pingidentity.ps.oidf.platform.settings.SettingRefused;
import com.pingidentity.ps.oidf.platform.settings.Settings;
import com.pingidentity.ps.oidf.platform.settings.Sources;
import org.sourceid.saml20.adapter.conf.Configuration;
import org.sourceid.saml20.adapter.gui.validation.ConfigurationValidator;
import org.sourceid.saml20.adapter.gui.validation.ValidationException;

import java.util.List;
import java.util.Set;
import java.util.function.Function;

/**
 * Refuses, under the production profile, a processor configuration that sets a field its catalogue
 * ({@value #CATALOGUE}.json) classes {@code forbidden-in-production} or {@code accepted-risk:<id>} to a value the entry
 * governs, the risk not accepted in {@code OIDF_ACCEPTED_RISKS}: "Skip TLS verification (dev only)" and "Trust a
 * client-asserted principal" on, and "Fail open on engine error" on without {@code pdp-fail-open}. The rule is
 * platform's read-time rule for a plugin field ({@code Settings.parse}, {@code ProfileAudit.atRead}, PR5), so the
 * message names the field, the value, the fix and the development escape as every other refusal does.
 *
 * <p>Checked twice, like the processor's other checked fields: {@link Validator} when the admin console or the admin
 * API saves the instance, where the message reaches the person saving it, and {@link #problem} at configure, the only
 * check an archive import gets - a configuration it refuses leaves the instance unconfigured, and an unconfigured
 * instance refuses every request that reaches it. In development nothing here refuses: the switches save and take
 * effect as before.
 *
 * <p>The PDP URL and the AuthZEN batch URL are classed {@code forbidden-in-production} for {@code http} too, and keep
 * their own rule ({@link PdpUrlPolicy}), which also refuses a URL that is not one; they are left out here so a
 * plaintext URL is refused once, in that rule's words.
 */
final class ProfileRules {

    /** The processor's settings catalogue. */
    static final String CATALOGUE = "rar-pdp-processor";

    static final String SKIP_TLS = "Skip TLS verification (dev only)";
    static final String CLIENT_ASSERTED = "Trust a client-asserted principal";
    static final String FAIL_OPEN = "Fail open on engine error";

    /**
     * The fields this rule judges, by constant so the settings scan can name each read: every plugin field the catalogue
     * classes other than {@code any}, but the two in {@link #OWN_RULE} (ProfileRulesTest holds the two lists together).
     */
    static final List<String> JUDGED = List.of(SKIP_TLS, CLIENT_ASSERTED, FAIL_OPEN);

    /** Classed entries whose own rule, on save and at configure, already refuses the governed values. */
    static final Set<String> OWN_RULE = Set.of("PDP URL", PdpResilience.BATCH_URL);

    private ProfileRules() {
    }

    /**
     * The first refusal the profile {@code env} names makes of these fields, or {@code null}: always {@code null} in
     * development.
     *
     * @param fields each field's stored value by name, or null
     * @param env    the environment the profile and the accepted risks are read from
     */
    static String problem(Function<String, String> fields, Function<String, String> env) {
        if (DeploymentProfile.of(env).isDevelopment()) {
            return null;
        }
        Settings settings = Settings.of(Holder.CATALOGUE, Sources.of(env, name -> null, null));
        for (String field : List.of(SKIP_TLS, CLIENT_ASSERTED, FAIL_OPEN)) {
            try {
                settings.parse(field, fields.apply(field));
            } catch (ProfileRefused refused) {
                return refused.violation().message();
            } catch (SettingRefused refused) {
                return refused.getMessage();
            }
        }
        return null;
    }

    /** {@link #problem}, thrown, for configure time. */
    static void check(Function<String, String> fields, Function<String, String> env) {
        String problem = problem(fields, env);
        if (problem != null) {
            throw new IllegalStateException(problem);
        }
    }

    /** The admin-console half: the rule above, on save, under this process's profile and accepted risks. */
    static final class Validator implements ConfigurationValidator {

        private final Function<String, String> env;

        Validator(Function<String, String> env) {
            this.env = env;
        }

        @Override
        public void validate(Configuration configuration) throws ValidationException {
            String problem = problem(configuration::getFieldValue, env);
            if (problem != null) {
                throw new ValidationException(problem);
            }
        }
    }

    /** The catalogue, loaded once from this class's loader: the plugin jar, with platform shaded beside it. */
    private static final class Holder {
        static final Catalogue CATALOGUE = Catalogue.load(ProfileRules.class.getClassLoader(), ProfileRules.CATALOGUE);
    }
}
