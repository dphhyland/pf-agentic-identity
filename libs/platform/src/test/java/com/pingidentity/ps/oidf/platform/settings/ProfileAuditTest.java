package com.pingidentity.ps.oidf.platform.settings;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.LocalDate;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import com.pingidentity.ps.oidf.platform.profile.AcceptedRisks;
import com.pingidentity.ps.oidf.platform.profile.DeploymentProfile;
import org.junit.jupiter.api.Test;

/**
 * PR-5's sweep: each kind of violation under both profiles, what each one names, and what it never quotes.
 */
class ProfileAuditTest {

    private static final LocalDate TODAY = LocalDate.of(2026, 9, 30);
    private static final DeploymentProfile PROD = DeploymentProfile.PRODUCTION;
    private static final DeploymentProfile DEV = DeploymentProfile.DEVELOPMENT;

    /** A catalogue named audit, owning OIDF_AUDIT_, whose settings refuse AUTO_REGISTRATION. */
    static final String CATALOGUE = "{\"format\": 1, \"component\": \"audit\", \"module\": \"libs/platform\","
            + " \"package\": \"com.pingidentity.ps.oidf.platform.settings\", \"families\": [\"OIDF_AUDIT_\"],"
            + " \"components\": [\"AUTO_REGISTRATION\"], \"settings\": ["
            + entry("OIDF_AUDIT_INSECURE", "env", "\"type\": \"bool\", \"default\": false, \"profile\": \"forbidden-in-production\"") + ","
            + entry("OIDF_AUDIT_PKCE", "env", "\"type\": \"bool\", \"default\": true, \"profile\": \"accepted-risk:pkce-off\"") + ","
            + entry("OIDF_AUDIT_EXPIRY", "env", "\"type\": \"choice\", \"default\": \"refuse\", \"choices\": [\"refuse\", \"disable\","
                    + " \"log\"], \"profile\": \"accepted-risk:expiry-log-mode\", \"governed\": [\"disable\", \"log\"]") + ","
            + entry("OIDF_AUDIT_AUDIENCE", "env", "\"type\": \"string\", \"default\": null, \"profile\": \"required-in-production\"") + ","
            + entry("OIDF_AUDIT_JDBC_URL", "env", "\"type\": \"string\", \"default\": null, \"profile\": \"forbidden-in-production\","
                    + " \"components\": [\"HOSTING\"]") + ","
            + entry("OIDF_AUDIT_REDIS_URL", "env", "\"type\": \"secret\", \"default\": null, \"profile\": \"forbidden-in-production\","
                    + " \"governed\": {\"schemes\": [\"redis\"]}") + ","
            + entry("OIDF_AUDIT_FALLBACK_URL", "env", "\"type\": \"secret\", \"default\": null, \"profile\": \"forbidden-in-production\","
                    + " \"governed\": {\"schemes\": [\"redis\"], \"unless_set\": [\"OIDF_AUDIT_REDIS_URL\", \"oidf.audit.note\"]}") + ","
            + entry("OIDF_AUDIT_MODE", "env", "\"type\": \"choice\", \"default\": \"a\", \"choices\": [\"a\", \"b\"], \"profile\": \"any\"") + ","
            + entry("OIDF_AUDIT_UNKNOWN_RISK", "env", "\"type\": \"bool\", \"default\": false, \"profile\": \"accepted-risk:no-such-risk\"") + ","
            + entry("oidf.audit.flag", "system-property", "\"type\": \"string\", \"default\": null, \"profile\": \"forbidden-in-production\"") + ","
            + entry("OIDF_AUDIT_PDP_URL", "env", "\"type\": \"url\", \"default\": \"https://pdp\", \"profile\": \"forbidden-in-production\","
                    + " \"governed\": {\"schemes\": [\"http\"]}") + ","
            + entry("oidf.audit.note", "system-property", "\"type\": \"string\", \"default\": null, \"profile\": \"any\"") + ","
            + entry("oidf.audit.switch", "system-property", "\"type\": \"bool\", \"default\": false, \"profile\": \"forbidden-in-production\"") + ","
            + entry("auditInitParam", "init-param", "\"type\": \"bool\", \"default\": false, \"profile\": \"forbidden-in-production\"") + ","
            + "{\"name\": \"Skip checks\", \"kind\": \"plugin-field\", \"type\": \"bool\", \"default\": false,"
            + " \"profile\": \"forbidden-in-production\", \"description\": \"skips the checks\","
            + " \"when_wrong\": {\"effect\": \"not-checked\", \"detail\": \"d\"}, \"security\": true, \"sources\": [], \"aliases\": [],"
            + " \"file\": false}"
            + "], \"removed\": []}";

    static String entry(String name, String kind, String members) {
        String sources = kind.equals("env") ? "[{\"from\": \"env\", \"name\": \"" + name + "\"}]"
                : kind.equals("system-property") ? "[{\"from\": \"system-property\", \"name\": \"" + name + "\"}]"
                : "[{\"from\": \"init-param\", \"name\": \"" + name + "\"}]";
        return "{\"name\": \"" + name + "\", \"kind\": \"" + kind + "\", " + members + ", \"description\": \"what " + name
                + " does\", \"when_wrong\": {\"effect\": \"not-checked\", \"detail\": \"d\"}, \"security\": true, \"sources\": "
                + sources + ", \"aliases\": [], \"file\": false}";
    }

    static Catalogue audit() {
        return Catalogue.parse(CATALOGUE, "audit.json");
    }

    /** The environment {@code pairs} gives, with the profile it names or production. */
    static Map<String, String> env(String... pairs) {
        Map<String, String> env = new HashMap<>();
        env.put("OIDF_AUDIT_AUDIENCE", "an audience");
        for (int i = 0; i < pairs.length; i += 2) {
            if (pairs[i + 1] == null) {
                env.remove(pairs[i]);
            } else {
                env.put(pairs[i], pairs[i + 1]);
            }
        }
        return env;
    }

    static ProfileAudit.Result evaluate(DeploymentProfile profile, Map<String, String> env, Map<String, String> properties) {
        return ProfileAudit.evaluate(Sources.of(env, properties), List.of(audit()), profile, AcceptedRisks.of(env::get, TODAY));
    }

    static ProfileAudit.Violation only(ProfileAudit.Result result) {
        assertEquals(1, result.violations().size(), result.violations().toString());
        return result.violations().get(0);
    }

    @Test
    void aCleanEnvironmentViolatesNothingInEitherProfile() {
        ProfileAudit.Result prod = evaluate(PROD, env(), Map.of());
        assertEquals(List.of(), prod.violations());
        assertFalse(prod.refuses());
        assertEquals(List.of(), prod.warnings());
        assertFalse(evaluate(DEV, env("OIDF_AUDIT_AUDIENCE", null), Map.of()).refuses());
        assertEquals(ProfileAudit.Result.empty(PROD), new ProfileAudit.Result(PROD, List.of(), List.of()));
    }

    @Test
    void aForbiddenSwitchSetRefusesItsComponentsInProductionAndWarnsInDevelopment() {
        ProfileAudit.Violation v = only(evaluate(PROD, env("OIDF_AUDIT_INSECURE", "TRUE"), Map.of()));
        assertEquals(ProfileAudit.Kind.FORBIDDEN, v.kind());
        assertEquals("OIDF_AUDIT_INSECURE", v.setting());
        assertEquals("OIDF_AUDIT_INSECURE=true, which the production profile forbids (what OIDF_AUDIT_INSECURE does)", v.reason());
        assertEquals("Set OIDF_AUDIT_INSECURE to false, or unset it (a rig or a demo sets OIDF_DEPLOYMENT_PROFILE=development"
                + " instead)", v.fix());
        assertEquals(List.of("AUTO_REGISTRATION"), v.components());
        assertEquals(v.reason() + ". " + v.fix(), v.message());
        assertEquals(v.message() + " [AUTO_REGISTRATION]", v.line());
        assertTrue(evaluate(PROD, env("OIDF_AUDIT_INSECURE", "true"), Map.of()).refuses());
        ProfileAudit.Result dev = evaluate(DEV, env("OIDF_AUDIT_INSECURE", "true"), Map.of());
        assertEquals(1, dev.violations().size(), "the same violation, listed");
        assertFalse(dev.refuses(), "development refuses nothing");
        assertEquals(List.of(), evaluate(PROD, env("OIDF_AUDIT_INSECURE", "false"), Map.of()).violations(), "the default is not governed");
    }

    @Test
    void aRiskySwitchNeedsItsRiskAcceptedInProduction() {
        ProfileAudit.Violation v = only(evaluate(PROD, env("OIDF_AUDIT_PKCE", "false"), Map.of()));
        assertEquals(ProfileAudit.Kind.ACCEPTED_RISK, v.kind());
        assertEquals("OIDF_AUDIT_PKCE=false, which the production profile allows only with the risk 'pkce-off' accepted"
                + " (front-channel relying parties are registered without requiring PKCE)", v.reason());
        assertEquals("Accept the risk by adding pkce-off to OIDF_ACCEPTED_RISKS, or set OIDF_AUDIT_PKCE to true, or unset it",
                v.fix());
        assertEquals(List.of(), evaluate(PROD, env("OIDF_AUDIT_PKCE", "false", "OIDF_ACCEPTED_RISKS", "pkce-off"), Map.of())
                .violations(), "accepted");
        ProfileAudit.Violation dated = only(evaluate(PROD, env("OIDF_AUDIT_EXPIRY", "log"), Map.of()));
        assertTrue(dated.fix().startsWith("Accept the risk by adding expiry-log-mode@YYYY-MM-DD to OIDF_ACCEPTED_RISKS"), dated.fix());
        ProfileAudit.Result undated = evaluate(PROD, env("OIDF_AUDIT_EXPIRY", "Disable", "OIDF_ACCEPTED_RISKS", "expiry-log-mode"),
                Map.of());
        assertEquals("OIDF_AUDIT_EXPIRY=disable", only(undated).reason().substring(0, 25));
        assertTrue(undated.warnings().stream().anyMatch(w -> w.startsWith("OIDF_ACCEPTED_RISKS accepts 'expiry-log-mode' without an"
                + " expiry") && w.endsWith(" - that risk is not accepted")), "a refused entry is a warning, and its risk is"
                        + " simply not accepted: " + undated.warnings());
        assertEquals(List.of(), evaluate(PROD, env("OIDF_AUDIT_EXPIRY", "log", "OIDF_ACCEPTED_RISKS", "expiry-log-mode@2026-12-31"),
                Map.of()).violations());
        assertEquals(List.of(), evaluate(PROD, env("OIDF_AUDIT_EXPIRY", "refuse"), Map.of()).violations());
        ProfileAudit.Violation unknown = only(evaluate(PROD, env("OIDF_AUDIT_UNKNOWN_RISK", "true"), Map.of()));
        assertEquals("No release accepts 'no-such-risk'; set OIDF_AUDIT_UNKNOWN_RISK to false, or unset it", unknown.fix());
        assertFalse(unknown.reason().contains("("), "a risk no release registers has no description to give");
    }

    @Test
    void aRequiredSettingUnsetIsAViolation() {
        ProfileAudit.Violation v = only(evaluate(PROD, env("OIDF_AUDIT_AUDIENCE", " "), Map.of()));
        assertEquals(ProfileAudit.Kind.REQUIRED, v.kind());
        assertEquals("OIDF_AUDIT_AUDIENCE is unset, and the production profile requires it (what OIDF_AUDIT_AUDIENCE does)", v.reason());
        assertEquals("Set OIDF_AUDIT_AUDIENCE (a rig or a demo sets OIDF_DEPLOYMENT_PROFILE=development instead)", v.fix());
        assertFalse(evaluate(DEV, env("OIDF_AUDIT_AUDIENCE", null), Map.of()).refuses());
    }

    @Test
    void aGovernedValueThatCannotBeReadIsRefusedAsIfItAskedForTheGovernedValue() {
        ProfileAudit.Violation v = only(evaluate(PROD, env("OIDF_AUDIT_INSECURE", "maybe"), Map.of()));
        assertEquals(ProfileAudit.Kind.UNREADABLE, v.kind());
        assertEquals("OIDF_AUDIT_INSECURE cannot be read (OIDF_AUDIT_INSECURE must be true or false, not maybe), so the production"
                + " profile cannot tell whether it asks for true, which it governs", v.reason());
        assertEquals("Write OIDF_AUDIT_INSECURE as its type reads it: true or false (a rig or a demo sets"
                + " OIDF_DEPLOYMENT_PROFILE=development instead)", v.fix());
        ProfileAudit.Violation choice = only(evaluate(PROD, env("OIDF_AUDIT_EXPIRY", "lg"), Map.of()));
        assertEquals(ProfileAudit.Kind.UNREADABLE, choice.kind());
        assertTrue(choice.fix().startsWith("Write OIDF_AUDIT_EXPIRY as its type reads it (a rig"), choice.fix());
        assertEquals(List.of(), evaluate(PROD, env("OIDF_AUDIT_MODE", "zzz"), Map.of()).violations(),
                "an entry classed any is its reader's business");
    }

    @Test
    void aLegacySpellingIsReadAsTheOldReaderReadItInDevelopmentAndRefusedInProduction() {
        for (String spelling : Parsers.LEGACY_BOOLEAN) {
            ProfileAudit.Violation prod = only(evaluate(PROD, env("OIDF_AUDIT_PKCE", spelling), Map.of()));
            assertEquals(ProfileAudit.Kind.UNREADABLE, prod.kind(), spelling);
            ProfileAudit.Result dev = evaluate(DEV, env("OIDF_AUDIT_PKCE", spelling), Map.of());
            ProfileAudit.Violation read = only(dev);
            assertEquals(ProfileAudit.Kind.ACCEPTED_RISK, read.kind(), spelling + " is read as false, which the risk governs");
            assertEquals("OIDF_AUDIT_PKCE is '" + spelling + "', a legacy spelling this check takes as false under the"
                    + " development profile (what the setting's own reader makes of it is in docs/development/"
                    + "settings-catalogue.md, \"Legacy spellings\"); write true or false", dev.warnings().get(0));
            ProfileAudit.Result insecure = evaluate(DEV, env("OIDF_AUDIT_INSECURE", spelling), Map.of());
            assertEquals(List.of(), insecure.violations(), spelling + " never turned a switch on");
            assertEquals(1, insecure.warnings().size());
        }
    }

    @Test
    void aFallbackTheReaderDoesNotReachIsNotJudged() {
        // REDIS_URL's shape: read only while OIDF_REDIS_URL and its property are unset (RedisConfig.url).
        assertEquals("OIDF_AUDIT_FALLBACK_URL", only(evaluate(PROD, env("OIDF_AUDIT_FALLBACK_URL", "redis://cache:6379"),
                Map.of())).setting(), "judged when nothing shadows it");
        assertEquals(List.of(), evaluate(PROD, env("OIDF_AUDIT_FALLBACK_URL", "redis://cache:6379", "OIDF_AUDIT_REDIS_URL",
                "rediss://cache:6380"), Map.of()).violations(), "the reader takes OIDF_AUDIT_REDIS_URL and never reads it");
        assertEquals(List.of(), evaluate(PROD, env("OIDF_AUDIT_FALLBACK_URL", "redis://cache:6379"),
                Map.of("oidf.audit.note", "set")).violations(), "any entry unless_set names shadows it");
        assertEquals("OIDF_AUDIT_FALLBACK_URL", only(evaluate(PROD, env("OIDF_AUDIT_FALLBACK_URL", "redis://cache:6379",
                "OIDF_AUDIT_REDIS_URL", " "), Map.of())).setting(), "a blank one is unset, and the reader goes on to it");
        assertEquals("OIDF_AUDIT_REDIS_URL", only(evaluate(PROD, env("OIDF_AUDIT_FALLBACK_URL", "rediss://cache:6380",
                "OIDF_AUDIT_REDIS_URL", "redis://cache:6379"), Map.of())).setting(), "the one read is still judged");
    }

    @Test
    void anEntrySetToWhatItsResolverRefusesStillShadows() {
        Catalogue c = Catalogue.parse("{\"format\": 1, \"component\": \"shadow\", \"module\": \"libs/platform\","
                + " \"package\": \"com.pingidentity.ps.oidf.platform.settings\", \"families\": [], \"settings\": ["
                + entry("OIDF_SHADOW_PORT", "env", "\"type\": \"int\", \"min\": 1, \"max\": 9, \"default\": null, \"profile\": \"any\"")
                + "," + entry("OIDF_SHADOW_URL", "env", "\"type\": \"secret\", \"default\": null, \"profile\": \"forbidden-in-production\","
                        + " \"governed\": {\"schemes\": [\"redis\"], \"unless_set\": [\"OIDF_SHADOW_PORT\"]}")
                + "], \"removed\": []}", "shadow.json");
        Setting url = c.setting("OIDF_SHADOW_URL");
        assertTrue(ProfileAudit.shadowed(url, c, Sources.of(Map.of("OIDF_SHADOW_PORT", "not a number"), Map.of())));
        assertFalse(ProfileAudit.shadowed(url, c, Sources.of(Map.of(), Map.of())));
        assertFalse(ProfileAudit.shadowed(c.setting("OIDF_SHADOW_PORT"), c, Sources.of(Map.of(), Map.of())), "governs nothing");
    }

    @Test
    void aValueSetUnderAnEntryWithNoDefaultIsNeverQuoted() {
        ProfileAudit.Violation v = only(evaluate(PROD, env("OIDF_AUDIT_JDBC_URL", "jdbc:postgresql://db/x?password=hunter2"), Map.of()));
        assertEquals("OIDF_AUDIT_JDBC_URL is set, which the production profile forbids (what OIDF_AUDIT_JDBC_URL does)", v.reason());
        assertEquals("Unset OIDF_AUDIT_JDBC_URL (a rig or a demo sets OIDF_DEPLOYMENT_PROFILE=development instead)", v.fix());
        assertEquals(List.of("HOSTING"), v.components(), "the entry's own components win over the catalogue's");
        assertFalse(v.line().contains("hunter2"));
        ProfileAudit.Violation redis = only(evaluate(PROD, env("OIDF_AUDIT_REDIS_URL", "redis://:hunter2@cache:6379"), Map.of()));
        assertEquals("OIDF_AUDIT_REDIS_URL is a redis:// URL, which the production profile forbids (what OIDF_AUDIT_REDIS_URL"
                + " does)", redis.reason());
        assertEquals("Give OIDF_AUDIT_REDIS_URL a URL of another scheme (redis is the one governed), or unset it (a rig or a demo"
                + " sets OIDF_DEPLOYMENT_PROFILE=development instead)", redis.fix());
        assertFalse(redis.line().contains("hunter2"));
        assertEquals(List.of(), evaluate(PROD, env("OIDF_AUDIT_REDIS_URL", "rediss://cache:6380"), Map.of()).violations());
        assertEquals("Give OIDF_AUDIT_PDP_URL a URL of another scheme (http is the one governed), or unset it (a rig or a demo"
                + " sets OIDF_DEPLOYMENT_PROFILE=development instead)", only(evaluate(PROD, env("OIDF_AUDIT_PDP_URL", "http://pdp"),
                        Map.of())).fix(), "a URL with a default is never quoted, and its fix names the scheme");
    }

    @Test
    void aSystemPropertyIsSweptAndOneWhosePresenceIsForbiddenCountsEvenBlank() {
        ProfileAudit.Violation v = only(evaluate(PROD, env(), Map.of("oidf.audit.flag", "false")));
        assertEquals(ProfileAudit.Kind.FORBIDDEN, v.kind());
        assertEquals("Remove -Doidf.audit.flag from the JVM's options (JAVA_OPTS) (a rig or a demo sets"
                + " OIDF_DEPLOYMENT_PROFILE=development instead)", v.fix());
        assertEquals(ProfileAudit.Kind.FORBIDDEN, only(evaluate(PROD, env(), Map.of("oidf.audit.flag", ""))).kind(),
                "the JDK reads -Dflag with no value as set; so does the sweep");
        assertEquals(List.of(), evaluate(PROD, env(), Map.of()).violations());
        assertFalse(ProfileAudit.presentButBlank(audit().setting("OIDF_AUDIT_JDBC_URL"), Sources.of(Map.of("OIDF_AUDIT_JDBC_URL", ""),
                Map.of())), "an environment variable blank is unset");
        assertFalse(ProfileAudit.presentButBlank(audit().setting("OIDF_AUDIT_MODE"), Sources.of(Map.of(), Map.of())));
        assertFalse(ProfileAudit.presentButBlank(audit().setting("oidf.audit.note"), Sources.of(Map.of(), Map.of("oidf.audit.note", ""))),
                "a property the profile does not govern");
        assertFalse(ProfileAudit.presentButBlank(audit().setting("oidf.audit.switch"), Sources.of(Map.of(),
                Map.of("oidf.audit.switch", " "))), "a switch blank is unset, as its reader takes it");
        assertEquals(List.of(), evaluate(PROD, env(), Map.of("oidf.audit.switch", " ")).violations());
    }

    @Test
    void theStartUpSweepLeavesInitParamsPluginFieldsAndExtendedPropertiesToTheirReads() {
        assertEquals(List.of(), evaluate(PROD, env("auditInitParam", "true"), Map.of("auditInitParam", "true")).violations());
        Catalogue c = audit();
        Setting param = c.setting("auditInitParam");
        AcceptedRisks none = AcceptedRisks.none();
        ProfileAudit.Violation v = ProfileAudit.atRead(param, " true ", c.componentsOf(param), PROD, none);
        assertEquals(ProfileAudit.Kind.FORBIDDEN, v.kind());
        assertNull(ProfileAudit.atRead(param, "true", List.of(), DEV, none));
        assertNull(ProfileAudit.atRead(param, "false", List.of(), PROD, none));
        assertNull(ProfileAudit.atRead(param, " ", List.of(), PROD, none));
        assertNull(ProfileAudit.atRead(param, "nope", List.of(), PROD, none), "its parser refuses that");
        assertNull(ProfileAudit.atRead(c.setting("OIDF_AUDIT_MODE"), "b", List.of(), PROD, none));
        Setting field = c.setting("Skip checks");
        assertEquals("Set the field \"Skip checks\" to false, or unset it (a rig or a demo sets OIDF_DEPLOYMENT_PROFILE=development"
                + " instead)", ProfileAudit.atRead(field, "true", List.of("X"), PROD, none).fix());
        Setting pkce = c.setting("OIDF_AUDIT_PKCE");
        assertNull(ProfileAudit.atRead(pkce, "false", List.of(), PROD, AcceptedRisks.parse("pkce-off", TODAY)));
    }

    @Test
    void anUnknownNameUnderAFamilyRefusesThatFamilysComponentsAndOneUnderNoFamilyIsAWarning() {
        Catalogue second = Catalogue.parse(CATALOGUE.replace("\"component\": \"audit\"", "\"component\": \"audit-two\"")
                .replace("\"components\": [\"AUTO_REGISTRATION\"]", "\"components\": [\"FAPI\", \"AUTO_REGISTRATION\"]")
                .replace("\"families\": [\"OIDF_AUDIT_\"]", "\"families\": [\"OIDF_AUDIT_\", \"OIDF_AUDIT_X_\"]")
                .replace("OIDF_AUDIT_", "OIDF_AUDTWO_").replace("\"OIDF_AUDTWO_\", \"OIDF_AUDTWO_X_\"", "\"OIDF_AUDIT_\", \"OIDF_AUDIT_X_\"")
                .replace("oidf.audit.flag", "oidf.audtwo.flag").replace("auditInitParam", "audtwoInitParam"), "audit-two.json");
        Map<String, String> env = env("OIDF_AUDIT_X_TYPO", "1", "OIDF_AUDIT_INSECURE", "false", "OIDF_ELSEWHERE", "x", "PATH", "/bin");
        ProfileAudit.Result result = ProfileAudit.evaluate(Sources.of(env, Map.of()), List.of(audit(), second), PROD,
                AcceptedRisks.none());
        List<ProfileAudit.Violation> unknown = result.violations().stream().filter(v -> v.kind() == ProfileAudit.Kind.UNKNOWN_KEY)
                .toList();
        assertEquals(1, unknown.size(), result.violations().toString());
        ProfileAudit.Violation v = unknown.get(0);
        assertEquals("OIDF_AUDIT_X_TYPO", v.setting());
        assertEquals("OIDF_AUDIT_X_TYPO is set, under the OIDF_AUDIT_ and OIDF_AUDIT_X_ families, and no settings catalogue"
                + " declares it", v.reason());
        assertTrue(v.fix().startsWith("Correct the name - a misspelling is the usual cause - or unset it"), v.fix());
        assertEquals(List.of("AUTO_REGISTRATION", "FAPI"), v.components(), "the union of the families' owners, once each");
        assertEquals(List.of("OIDF_ELSEWHERE is set and no settings catalogue declares it; it is under no catalogue's family, so"
                + " nothing refuses it - check the spelling"), result.warnings());
        ProfileAudit.Result one = ProfileAudit.evaluate(Sources.of(env("OIDF_AUDIT_TYPO", "x"), Map.of()), List.of(audit()), DEV,
                AcceptedRisks.none());
        assertTrue(one.violations().get(0).reason().contains("under the OIDF_AUDIT_ family,"), one.violations().toString());
        assertEquals(List.of(), ProfileAudit.evaluate(Sources.of(n -> "x", n -> null, null), List.of(audit()), PROD,
                AcceptedRisks.none()).violations().stream().filter(x -> x.kind() == ProfileAudit.Kind.UNKNOWN_KEY).toList(),
                "sources from lookups list no names, so none is unknown");
    }

    @Test
    void aCatalogueThatCannotBeLoadedRefusesItsComponentsAndAResolverRefusalIsUnreadable() {
        ProfileAudit.Result result = ProfileAudit.evaluate(Sources.of(env(), Map.of()),
                new Catalogues.Loaded(List.of(audit()), List.of(new Catalogues.Problem("ssf-transmitter", "two copies differ"))),
                PROD, AcceptedRisks.none());
        ProfileAudit.Violation v = only(result);
        assertEquals(ProfileAudit.Kind.CATALOGUE, v.kind());
        assertEquals("The settings catalogue ssf-transmitter could not be loaded (two copies differ), so its settings cannot be"
                + " checked against the production profile", v.reason());
        assertEquals(List.of("SSF", "SSF_RECEIVER"), v.components());
        assertEquals(List.of(v), result.of("SSF"));
        assertEquals(List.of(), result.of("FAPI"));
        String secret = "{\"format\": 1, \"component\": \"s\", \"module\": \"libs/platform\", \"package\": \"a.b\", \"families\": [],"
                + " \"settings\": [{\"name\": \"OIDF_S_KEY\", \"kind\": \"env\", \"type\": \"secret\", \"default\": null,"
                + " \"profile\": \"forbidden-in-production\", \"description\": \"d\", \"when_wrong\": {\"effect\": \"not-checked\","
                + " \"detail\": \"d\"}, \"security\": true, \"sources\": [{\"from\": \"env\", \"name\": \"OIDF_S_KEY\"}], \"aliases\": [],"
                + " \"file\": true}, {\"name\": \"OIDF_S_NEEDED\", \"kind\": \"env\", \"type\": \"secret\", \"default\": null,"
                + " \"profile\": \"required-in-production\", \"description\": \"d\", \"when_wrong\": {\"effect\": \"not-checked\","
                + " \"detail\": \"d\"}, \"security\": true, \"sources\": [{\"from\": \"env\", \"name\": \"OIDF_S_NEEDED\"}], \"aliases\": [],"
                + " \"file\": true}, " + entry("OIDF_S_OTHER", "env", "\"type\": \"string\", \"default\": null, \"profile\": \"any\"")
                        .replace("\"aliases\": []", "\"aliases\": [{\"name\": \"OIDF_S_OLD\", \"sources\": [{\"from\": \"env\", \"name\": \"OIDF_S_OLD\"}]}]")
                + "], \"removed\": []}";
        Catalogue s = Catalogue.parse(secret, "s.json");
        ProfileAudit.Violation both = only(ProfileAudit.evaluate(Sources.of(Map.of("OIDF_S_KEY", "k", "OIDF_S_KEY_FILE", "/f",
                "OIDF_S_OTHER", "a", "OIDF_S_OLD", "b", "OIDF_S_NEEDED", "n", "OIDF_S_NEEDED_FILE", "/f"), Map.of()), List.of(s), PROD,
                AcceptedRisks.none()));
        assertEquals(ProfileAudit.Kind.UNREADABLE, both.kind());
        assertEquals("OIDF_S_KEY cannot be read (its value was refused), so the production profile cannot tell whether it asks for"
                + " any value, which it governs", both.reason(), "a secret's refusal is never repeated; an ungoverned one is not"
                        + " the profile's business");
    }
}
