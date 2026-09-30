package com.pingidentity.ps.oidf.platform.settings;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * What the profile does to a {@link Settings} read: a legacy spelling in each profile (Phase 3 plan, decision 11), and
 * the read-time refusal of a governed init-param, plugin field or extended property (PR-5).
 */
class SettingsProfileTest {

    private static final String READS = "{\"format\": 1, \"component\": \"reads\", \"module\": \"libs/platform\","
            + " \"package\": \"com.pingidentity.ps.oidf.platform.settings\", \"families\": [\"OIDF_READS_\"],"
            + " \"components\": [\"FEDERATION\"], \"settings\": ["
            + ProfileAuditTest.entry("OIDF_READS_SWITCH", "env", "\"type\": \"bool\", \"default\": true, \"profile\": \"any\"") + ","
            + ProfileAuditTest.entry("OIDF_READS_COUNT", "env", "\"type\": \"int\", \"default\": 3, \"min\": 0, \"max\": 9,"
                    + " \"profile\": \"any\"") + ","
            + ProfileAuditTest.entry("OIDF_READS_NO_DEFAULT", "env", "\"type\": \"bool\", \"default\": false, \"profile\": \"any\"") + ","
            + ProfileAuditTest.entry("readsInsecure", "init-param", "\"type\": \"bool\", \"default\": false,"
                    + " \"profile\": \"forbidden-in-production\"") + ","
            + "{\"name\": \"OIDF_READS_DISCOVERY\", \"kind\": \"env\", \"type\": \"choice\", \"default\": \"known\","
            + " \"choices\": [\"known\", \"any\"], \"profile\": \"accepted-risk:resolve-any\", \"description\": \"d\","
            + " \"when_wrong\": {\"effect\": \"not-checked\", \"detail\": \"d\"}, \"security\": true, \"sources\": ["
            + "{\"from\": \"init-param\", \"name\": \"readsDiscovery\"}, {\"from\": \"env\", \"name\": \"OIDF_READS_DISCOVERY\"}],"
            + " \"aliases\": [], \"file\": false},"
            + "{\"name\": \"Skip TLS\", \"kind\": \"plugin-field\", \"type\": \"bool\", \"default\": false,"
            + " \"profile\": \"forbidden-in-production\", \"description\": \"d\", \"when_wrong\": {\"effect\": \"not-checked\","
            + " \"detail\": \"d\"}, \"security\": true, \"sources\": [], \"aliases\": [], \"file\": false},"
            + "{\"name\": \"reads_insecure\", \"kind\": \"extended-property\", \"type\": \"bool\", \"default\": false,"
            + " \"profile\": \"forbidden-in-production\", \"description\": \"d\", \"when_wrong\": {\"effect\": \"not-checked\","
            + " \"detail\": \"d\"}, \"security\": true, \"sources\": [], \"aliases\": [], \"file\": false}"
            + "], \"removed\": []}";

    private final List<String> warned = new ArrayList<>();

    private Settings settings(String profile, Map<String, String> env, Map<String, String> initParams) {
        Map<String, String> all = new HashMap<>(env);
        if (profile != null) {
            all.put("OIDF_DEPLOYMENT_PROFILE", profile);
        }
        return Settings.of(Catalogue.parse(READS, "reads.json"), Sources.of(all::get, name -> null, initParams::get))
                .warningsTo(this.warned::add);
    }

    @Test
    void eachLegacySpellingOfASwitchIsReadAsFalseInDevelopmentWithAWarning() {
        for (String spelling : List.of("yes", "YES", " no ", "1", "0", "On", "off")) {
            this.warned.clear();
            Settings dev = settings("development", Map.of("OIDF_READS_SWITCH", spelling), Map.of());
            assertFalse(dev.bool("OIDF_READS_SWITCH"), spelling + " is false, as Boolean.parseBoolean read it");
            Resolved r = dev.resolve("OIDF_READS_SWITCH");
            assertTrue(r.legacy());
            assertEquals(spelling.trim(), r.legacySpelling());
            assertEquals("OIDF_READS_SWITCH is '" + spelling.trim() + "', a spelling only the reader before 0.6.0 took; it is read as"
                    + " false, as that reader read it. Write false (or the value you meant): the production profile refuses this"
                    + " spelling, and development stops taking it at 1.0", this.warned.get(0));
            assertTrue(Settings.legacySpellings().contains("OIDF_READS_SWITCH = '" + spelling.trim() + "', read as false"),
                    Settings.legacySpellings().toString());
        }
    }

    @Test
    void eachLegacySpellingIsRefusedInProductionAsAnyValueThatDoesNotParse() {
        for (String spelling : Parsers.LEGACY_BOOLEAN) {
            SettingRefused refused = assertThrows(SettingRefused.class,
                    () -> settings(null, Map.of("OIDF_READS_SWITCH", spelling), Map.of()).bool("OIDF_READS_SWITCH"), spelling);
            assertEquals("OIDF_READS_SWITCH must be true or false, not " + spelling, refused.getMessage());
            assertFalse(refused instanceof ProfileRefused, "a parse refusal, not the profile's");
        }
    }

    @Test
    void aStrictSpellingIsNoLegacyAndAnythingElseIsRefusedInBothProfiles() {
        Resolved strict = settings("development", Map.of("OIDF_READS_SWITCH", " TRUE "), Map.of()).resolve("OIDF_READS_SWITCH");
        assertFalse(strict.legacy(), "true in any case, trimmed, was always strict");
        assertNull(strict.legacySpelling());
        assertThrows(SettingRefused.class, () -> settings("development", Map.of("OIDF_READS_SWITCH", "enabled"), Map.of())
                .bool("OIDF_READS_SWITCH"));
        assertEquals(Integer.valueOf(4), settings("development", Map.of("OIDF_READS_COUNT", " +4 "), Map.of()).integer("OIDF_READS_COUNT"),
                "a number with blanks round it and a leading + is strict already: Long.parseLong takes it");
        assertThrows(SettingRefused.class, () -> settings("development", Map.of("OIDF_READS_COUNT", "four"), Map.of())
                .integer("OIDF_READS_COUNT"), "a number has no legacy spelling");
        assertNull(Parsers.legacyBoolean(null));
        assertNull(Parsers.legacyBoolean("true"));
        assertEquals(Boolean.FALSE, Parsers.legacyBoolean(" Off "));
        assertEquals(Boolean.FALSE, Catalogue.parse(READS, "reads.json").setting("OIDF_READS_NO_DEFAULT").legacy("yes"));
        assertNull(Catalogue.parse(READS, "reads.json").setting("OIDF_READS_COUNT").legacy("yes"));
    }

    @Test
    void aGovernedInitParamIsRefusedWhenReadInProduction() {
        ProfileRefused refused = assertThrows(ProfileRefused.class,
                () -> settings(null, Map.of(), Map.of("readsInsecure", "true")).bool("readsInsecure"));
        assertEquals("readsInsecure", refused.setting());
        assertEquals(ProfileAudit.Kind.FORBIDDEN, refused.violation().kind());
        assertEquals(List.of("FEDERATION"), refused.violation().components());
        assertEquals(refused.violation().message(), refused.getMessage());
        assertTrue(refused instanceof SettingRefused, "a SettingRefused, so every caller that catches one catches it");
        assertTrue(settings("development", Map.of(), Map.of("readsInsecure", "true")).bool("readsInsecure"));
        assertFalse(settings(null, Map.of(), Map.of("readsInsecure", "false")).bool("readsInsecure"));
        assertFalse(settings(null, Map.of(), Map.of()).bool("readsInsecure"));
    }

    @Test
    void anEnvEntryReadFromItsInitParamIsHeldToTheSameRule() {
        assertThrows(ProfileRefused.class, () -> settings(null, Map.of(), Map.of("readsDiscovery", "any")).choice("OIDF_READS_DISCOVERY"));
        assertEquals("any", settings(null, Map.of("OIDF_READS_DISCOVERY", "any"), Map.of()).choice("OIDF_READS_DISCOVERY"),
                "from the environment it is the start-up sweep's to refuse");
        assertEquals("any", settings(null, Map.of("OIDF_ACCEPTED_RISKS", "resolve-any"), Map.of("readsDiscovery", "any"))
                .choice("OIDF_READS_DISCOVERY"), "the risk accepted");
    }

    @Test
    void aGovernedPluginFieldOrExtendedPropertyIsRefusedWhenParsedInProduction() {
        Settings prod = settings(null, Map.of(), Map.of());
        assertEquals("Skip TLS", assertThrows(ProfileRefused.class, () -> prod.parse("Skip TLS", "true")).setting());
        assertEquals("reads_insecure", assertThrows(ProfileRefused.class, () -> prod.parse("reads_insecure", "TRUE")).setting());
        assertEquals(Boolean.FALSE, prod.parse("Skip TLS", "false"));
        assertNull(prod.parse("Skip TLS", " "));
        assertEquals(Boolean.TRUE, settings("development", Map.of(), Map.of()).parse("Skip TLS", "true"));
        assertEquals(Boolean.TRUE, prod.parse("readsInsecure", "true"), "parse of an init-param entry is a value the caller holds");
    }
}
