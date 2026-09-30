package com.pingidentity.ps.oidf.rar;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import com.pingidentity.ps.oidf.platform.settings.Catalogue;
import com.pingidentity.ps.oidf.platform.settings.EntryKind;
import com.pingidentity.ps.oidf.platform.settings.ProfileClass;
import com.pingidentity.ps.oidf.platform.settings.Setting;
import com.pingidentity.sdk.authorizationdetails.AuthorizationDetail;
import com.pingidentity.sdk.authorizationdetails.AuthorizationDetailProcessingException;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import org.junit.jupiter.api.Test;
import org.sourceid.saml20.adapter.conf.Configuration;
import org.sourceid.saml20.adapter.conf.Field;
import org.sourceid.saml20.adapter.gui.validation.ConfigurationValidator;
import org.sourceid.saml20.adapter.gui.validation.ValidationException;

/**
 * Plan item PR-3, the plugin half: in production the processor refuses its development-only switches, and failing open
 * without the accepted risk, on save (the descriptor's validation chain, which the admin console and the admin API run)
 * and at configure (the only check an archive import gets). In development all of it still saves and configures.
 */
class ProfileRulesTest {

    private static final String PDP_URL = "https://pdp.example/governance-engine";
    private static final String SKIP_TLS = "Skip TLS verification (dev only)";
    private static final String CLIENT_ASSERTED = "Trust a client-asserted principal";
    private static final String FAIL_OPEN = "Fail open on engine error";

    private static final Function<String, String> PRODUCTION = name -> null;
    private static final Function<String, String> DEVELOPMENT = env("OIDF_DEPLOYMENT_PROFILE", "development");

    private static Function<String, String> env(String... namesAndValues) {
        Map<String, String> map = new java.util.HashMap<>();
        for (int i = 0; i + 1 < namesAndValues.length; i += 2) {
            map.put(namesAndValues[i], namesAndValues[i + 1]);
        }
        return map::get;
    }

    private static Configuration stored(String... namesAndValues) {
        Configuration configuration = new Configuration();
        configuration.addField(new Field("PDP URL", PDP_URL));
        for (int i = 0; i + 1 < namesAndValues.length; i += 2) {
            configuration.addField(new Field(namesAndValues[i], namesAndValues[i + 1]));
        }
        return configuration;
    }

    private static void save(Configuration configuration, Function<String, String> env) throws ValidationException {
        new ProfileRules.Validator(env).validate(configuration);
    }

    // ---- on save ----------------------------------------------------------------------------------------------

    @Test
    void savingADevelopmentSwitchOnIsRefusedInProductionNamingTheField() {
        for (String field : List.of(SKIP_TLS, CLIENT_ASSERTED)) {
            ValidationException e = assertThrows(ValidationException.class, () -> save(stored(field, "true"), PRODUCTION), field);
            String message = e.getErrorMessages().get(0);
            assertTrue(message.startsWith(field + "=true, which the production profile forbids"), message);
            assertTrue(message.contains("Set the field \"" + field + "\" to false"), message);
            assertDoesNotThrow(() -> save(stored(field, "true"), DEVELOPMENT), field + " still saves in development");
            assertDoesNotThrow(() -> save(stored(field, "false"), PRODUCTION), field + " off saves in production");
        }
    }

    @Test
    void savingFailOpenInProductionNeedsThePdpFailOpenRisk() throws ValidationException {
        ValidationException e = assertThrows(ValidationException.class, () -> save(stored(FAIL_OPEN, "true"), PRODUCTION));
        String message = e.getErrorMessages().get(0);
        assertTrue(message.startsWith(FAIL_OPEN + "=true, which the production profile allows only with the risk"
                + " 'pdp-fail-open' accepted"), message);
        assertTrue(message.contains("OIDF_ACCEPTED_RISKS"), message);
        save(stored(FAIL_OPEN, "true"), env("OIDF_ACCEPTED_RISKS", "pdp-fail-open"));
        save(stored(FAIL_OPEN, "true"), DEVELOPMENT);
        ValidationException other = assertThrows(ValidationException.class,
                () -> save(stored(FAIL_OPEN, "true"), env("OIDF_ACCEPTED_RISKS", "in-memory-state")), "another risk is not this one");
        assertTrue(other.getErrorMessages().get(0).contains("pdp-fail-open"), other.getErrorMessages().toString());
    }

    /** A switch stored as something other than true or false cannot be judged, so production refuses it rather than guess. */
    @Test
    void aSwitchThatDoesNotParseIsRefusedInProductionOnly() throws ValidationException {
        ValidationException e = assertThrows(ValidationException.class, () -> save(stored(SKIP_TLS, "maybe"), PRODUCTION));
        assertTrue(e.getErrorMessages().get(0).contains(SKIP_TLS), e.getErrorMessages().toString());
        save(stored(SKIP_TLS, "maybe"), DEVELOPMENT);
    }

    /** The plaintext PDP URL and the payment and principal types in the decision cache keep their own rules. */
    @Test
    void thePdpUrlAndTheCacheTypesAreRefusedByTheirOwnRules() throws ValidationException {
        Configuration plaintext = new Configuration();
        plaintext.addField(new Field("PDP URL", "http://pdp.internal/decide"));
        save(plaintext, PRODUCTION);
        assertNotNull(PdpUrlPolicy.problem("http://pdp.internal/decide", "production"), "PdpUrlPolicy's rule refuses it once");
        assertNull(PdpUrlPolicy.problem("http://pdp.internal/decide", "development"));
        Configuration cached = stored(PdpResilience.CACHE_TYPES, "payment_initiation");
        for (String profile : List.of("production", "development")) {
            assertNotNull(PdpResilience.problem(cached, profile, false, GovernanceEngineConfig.DEFAULT_AUTHENTICATED_PRINCIPAL_TYPES),
                    "a payment is never cached, in " + profile);
            assertNotNull(PdpResilience.problem(stored(PdpResilience.CACHE_TYPES, "account_information"), profile, false,
                    GovernanceEngineConfig.DEFAULT_AUTHENTICATED_PRINCIPAL_TYPES), "nor a principal-required type, in " + profile);
        }
    }

    /** The descriptor carries the rule last in its chain, under this process's profile (unset here: production). */
    @Test
    void theDescriptorsChainRefusesOnSave() {
        assumeTrue(System.getenv("OIDF_DEPLOYMENT_PROFILE") == null, "the test process names no profile");
        assumeTrue(System.getenv("OIDF_ACCEPTED_RISKS") == null, "and accepts no risk");
        List<ConfigurationValidator> chain = new AttestationAwareRarProcessor().getPluginDescriptor().getGuiConfigDescriptor()
                .getValidationChain();
        assertTrue(chain.get(chain.size() - 1) instanceof ProfileRules.Validator, "the profile's rule speaks last");
        for (String field : List.of(SKIP_TLS, CLIENT_ASSERTED, FAIL_OPEN)) {
            Configuration configuration = stored(field, "true", "Shared Secret", "s");
            assertThrows(ValidationException.class, () -> {
                for (ConfigurationValidator validator : chain) {
                    validator.validate(configuration);
                }
            }, field);
        }
    }

    // ---- at configure (an archive import) ---------------------------------------------------------------------

    @Test
    void configureRefusesEachSwitchInProductionAndTheInstanceRefusesEveryRequest() {
        for (String field : List.of(SKIP_TLS, CLIENT_ASSERTED, FAIL_OPEN)) {
            AttestationAwareRarProcessor processor = new AttestationAwareRarProcessor();
            IllegalStateException e = assertThrows(IllegalStateException.class,
                    () -> processor.configure(stored(field, "true"), "production", PRODUCTION), field);
            assertTrue(e.getMessage().startsWith(field + "=true"), e.getMessage());
            assertNull(processor.decisions(), "nothing is built for " + field);
            AuthorizationDetail detail = new AuthorizationDetail(new java.util.HashMap<>(Map.of("type", "sales_agent")));
            AuthorizationDetailProcessingException refused = assertThrows(AuthorizationDetailProcessingException.class,
                    () -> processor.enrich(detail, null, Map.of()));
            assertTrue(refused.getMessage().contains("is not configured"), refused.getMessage());
        }
    }

    @Test
    void configureTakesEachSwitchInDevelopmentAndFailOpenWithItsRisk() {
        for (String field : List.of(SKIP_TLS, CLIENT_ASSERTED, FAIL_OPEN)) {
            AttestationAwareRarProcessor processor = new AttestationAwareRarProcessor();
            processor.configure(stored(field, "true"), "development", PRODUCTION);
            assertNotNull(processor.decisions(), field + " configures in development, whatever the environment says");
        }
        AttestationAwareRarProcessor accepted = new AttestationAwareRarProcessor();
        accepted.configure(stored(FAIL_OPEN, "true"), "production", env("OIDF_ACCEPTED_RISKS", "pdp-fail-open"));
        assertNotNull(accepted.decisions(), "fail-open configures in production with pdp-fail-open accepted");
    }

    // ---- the catalogue is the rule ----------------------------------------------------------------------------

    /**
     * Every classed plugin field of the catalogue is refused in production when set to a governed value, by this rule
     * or, for the two URLs, by PdpUrlPolicy - so a class in the catalogue is never only documentation.
     */
    @Test
    void everyClassedFieldIsEnforced() {
        Catalogue catalogue = Catalogue.load(ProfileRulesTest.class.getClassLoader(), ProfileRules.CATALOGUE);
        int classed = 0;
        for (Setting setting : catalogue.settings()) {
            if (setting.kind() != EntryKind.PLUGIN_FIELD || setting.profile().kind() == ProfileClass.Kind.ANY) {
                continue;
            }
            classed++;
            if (ProfileRules.OWN_RULE.contains(setting.name())) {
                assertEquals(List.of("http"), setting.governed().values(), setting.name());
                assertNotNull(PdpUrlPolicy.problem("http://pdp.internal/x", "production"), setting.name());
                continue;
            }
            String name = setting.name();
            assertTrue(ProfileRules.JUDGED.contains(name), name + " is classed and nothing judges it");
            assertNotNull(ProfileRules.problem(field -> field.equals(name) ? "true" : null, PRODUCTION), name);
            assertNull(ProfileRules.problem(field -> field.equals(name) ? "true" : null, DEVELOPMENT), name);
        }
        assertEquals(5, classed, "the three switches and the two URLs");
        assertEquals(3, ProfileRules.JUDGED.size());
    }
}
