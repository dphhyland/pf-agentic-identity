/*
 * device-enrolment's start-up: the production profile's audit over its catalogue, and every setting read strictly.
 */
package com.pingidentity.ps.oidf.enrolment;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.platform.profile.DeploymentProfile;
import com.pingidentity.ps.oidf.platform.settings.SettingRefused;
import com.pingidentity.ps.oidf.platform.settings.Settings;
import com.pingidentity.ps.oidf.platform.settings.Sources;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import org.jose4j.jwk.EcJwkGenerator;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.keys.EllipticCurves;
import org.junit.jupiter.api.Test;

/**
 * Plan items ST-5, PR-3 and PR-5 for a standalone service: under the production profile a forbidden switch, a governed
 * one that does not parse, or an in-memory registry without its risk stops the process with exit status 1 and every
 * violation on stderr; a setting that does not parse stops it naming the setting; under development the same values
 * are warnings, and a legacy spelling is read as the old reader read it.
 */
class MainStartupTest {

    /** What run() wrote to stderr, and what it returned. */
    private record Outcome(int status, String err) {
    }

    private static Outcome audit(Map<String, String> env) {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        boolean passed = Main.audit(Main.catalogue(), env::get, name -> null, new PrintStream(bytes, true, StandardCharsets.UTF_8));
        return new Outcome(passed ? 0 : Main.REFUSED, bytes.toString(StandardCharsets.UTF_8));
    }

    private static Outcome run(Map<String, String> env) throws Exception {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        int status = Main.run(env::get, name -> null, new PrintStream(bytes, true, StandardCharsets.UTF_8));
        return new Outcome(status, bytes.toString(StandardCharsets.UTF_8));
    }

    private static Map<String, String> production(String... pairs) {
        Map<String, String> env = new HashMap<>();
        for (int i = 0; i < pairs.length; i += 2) {
            env.put(pairs[i], pairs[i + 1]);
        }
        return env;
    }

    private static Map<String, String> development(String... pairs) {
        Map<String, String> env = production(pairs);
        env.put(DeploymentProfile.SETTING, "development");
        return env;
    }

    /** Everything wire() needs with no database and no network: an in-memory registry and a signing key. */
    private static Map<String, String> wirable(Map<String, String> env) throws Exception {
        env.put("ENROLMENT_ISSUER", "https://enrol.example");
        env.put("ENROLMENT_SIGNING_JWK", EcJwkGenerator.generateJwk(EllipticCurves.P256).toJson(JsonWebKey.OutputControlLevel.INCLUDE_PRIVATE));
        env.put("REGISTRY", "memory");
        env.put("OIDF_ACCEPTED_RISKS", "in-memory-state");
        env.put("PORT", "0");
        return env;
    }

    private static Settings settings(Map<String, String> env) {
        return Settings.of(Main.catalogue(), Sources.of(env::get, name -> null, null));
    }

    // ---- the audit ---------------------------------------------------------------------------------------------------

    @Test
    void eachForbiddenSwitchStopsTheServiceInProductionNamingIt() throws Exception {
        String[][] forbidden = {
                {"REQUIRE_COMPLIANT_DEVICE", "false"},
                {"APPLE_ALLOW_DEVELOPMENT", "true"},
                {"PF_AUTHORITY_INSECURE_TLS", "true"},
                {"PF_AUTHORITY_ADMIN_TOKEN", "static-bearer"},
        };
        for (String[] setting : forbidden) {
            Outcome outcome = run(production(setting[0], setting[1]));
            assertEquals(Main.REFUSED, outcome.status(), setting[0]);
            assertTrue(outcome.err().contains("refused to start by the production profile"), outcome.err());
            assertTrue(outcome.err().contains(setting[0]), outcome.err());
            assertFalse(outcome.err().contains("static-bearer"), "a secret's value is never repeated");
        }
    }

    @Test
    void everyViolationIsListedAtOnce() {
        Outcome outcome = audit(production("REQUIRE_COMPLIANT_DEVICE", "false", "APPLE_ALLOW_DEVELOPMENT", "true",
                "REGISTRY", "memory"));
        assertEquals(Main.REFUSED, outcome.status());
        assertTrue(outcome.err().contains("for 3 setting(s)"), outcome.err());
        for (String name : List.of("REQUIRE_COMPLIANT_DEVICE", "APPLE_ALLOW_DEVELOPMENT", "REGISTRY")) {
            assertTrue(outcome.err().contains(name), name + " in " + outcome.err());
        }
        assertTrue(outcome.err().contains("in-memory-state"), "the risk that would allow the in-memory registry is named");
    }

    @Test
    void aGovernedSwitchThatDoesNotParseIsRefusedInProduction() {
        for (String legacy : List.of("yes", "0", "TRUE-ish")) {
            Outcome outcome = audit(production("REQUIRE_COMPLIANT_DEVICE", legacy));
            assertEquals(Main.REFUSED, outcome.status(), legacy);
            assertTrue(outcome.err().contains("REQUIRE_COMPLIANT_DEVICE cannot be read"), outcome.err());
        }
    }

    @Test
    void theSameValuesAreWarningsUnderDevelopment() {
        assertEquals(0, audit(development("REQUIRE_COMPLIANT_DEVICE", "false", "APPLE_ALLOW_DEVELOPMENT", "true",
                "PF_AUTHORITY_INSECURE_TLS", "true", "REGISTRY", "memory")).status());
        assertEquals(0, audit(development("REQUIRE_COMPLIANT_DEVICE", "no")).status(), "a legacy spelling, read as false");
        assertEquals(0, audit(production()).status(), "nothing set is nothing to refuse");
        assertEquals(0, audit(production("REQUIRE_COMPLIANT_DEVICE", "true", "APPLE_ALLOW_DEVELOPMENT", "false")).status(),
                "the safe values");
        assertEquals(0, audit(production("REGISTRY", "memory", "OIDF_ACCEPTED_RISKS", "in-memory-state")).status(),
                "an in-memory registry with its risk accepted");
    }

    // ---- strict reads ------------------------------------------------------------------------------------------------

    @Test
    void aSettingThatDoesNotParseStopsTheServiceNamingIt() throws Exception {
        for (String[] bad : new String[][] {{"UV_MAX_AGE_SECONDS", "five minutes"}, {"PORT", "70000"},
                {"REGISTRY", "postgres"}, {"OIDF_ATTESTATION_SUB", "instance"}, {"ALLOW_SELF_ASSERTED_KEYS", "maybe"},
                {"APPLE_MACOS_REQUIRE_KEY_POLICY", "yes"}}) {
            Map<String, String> env = wirable(production());
            env.put(bad[0], bad[1]);
            Outcome outcome = run(env);
            assertEquals(Main.REFUSED, outcome.status(), bad[0]);
            assertTrue(outcome.err().startsWith("device-enrolment did not start: " + bad[0])
                    // REGISTRY is governed (memory needs a risk), so the audit refuses a value it cannot read first.
                    || outcome.err().contains(bad[0] + " cannot be read"), outcome.err());
        }
        Outcome missing = run(production());
        assertEquals(Main.REFUSED, missing.status());
        assertTrue(missing.err().contains("ENROLMENT_ISSUER must be set"), missing.err());
    }

    @Test
    void underDevelopmentALegacySpellingIsReadAsTheOldReaderReadIt() throws Exception {
        Settings dev = settings(development("ALLOW_SELF_ASSERTED_KEYS", "yes", "APPLE_MACOS_REQUIRE_KEY_POLICY", "on",
                "UV_MAX_AGE_SECONDS", " 120 "));
        assertFalse(dev.bool("ALLOW_SELF_ASSERTED_KEYS"));
        assertFalse(dev.bool("APPLE_MACOS_REQUIRE_KEY_POLICY"), "Boolean.parseBoolean read anything but true as false");
        assertEquals(120, dev.duration("UV_MAX_AGE_SECONDS").toSeconds());
        SettingRefused refused = assertThrows(SettingRefused.class,
                () -> settings(production("ALLOW_SELF_ASSERTED_KEYS", "yes")).bool("ALLOW_SELF_ASSERTED_KEYS"));
        assertTrue(refused.getMessage().contains("ALLOW_SELF_ASSERTED_KEYS"), refused.getMessage());
    }

    @Test
    void theServiceWiresFromItsSettings() throws Exception {
        EnrolmentHttpServer server = Main.wire(settings(wirable(development("REQUIRE_COMPLIANT_DEVICE", "false",
                "CONNECTOR_BUILDS", "a,b", "PINGONE_ACR_AAL2", "passkey"))), DeploymentProfile.DEVELOPMENT);
        server.stop();
        EnrolmentHttpServer secure = Main.wire(settings(wirable(production())), DeploymentProfile.PRODUCTION);
        secure.stop();
        IllegalStateException subject = assertThrows(IllegalStateException.class, () -> Main.wire(settings(wirable(production(
                "OIDF_ATTESTATION_SUB", "client_id"))), DeploymentProfile.PRODUCTION));
        assertTrue(subject.getMessage().contains("OIDF_AGENT_CLIENT_ID"), subject.getMessage());
    }

    @Test
    void aJdbcUrlForAnotherDatabaseIsRefusedWithoutItsCredentials() {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> Main.toJdbcUrl("jdbc:mysql://db/iom?password=hunter2"));
        assertTrue(e.getMessage().contains("jdbc:mysql:") && e.getMessage().contains("PostgreSQL only"), e.getMessage());
        assertFalse(e.getMessage().contains("hunter2"));
        assertEquals("jdbc:postgresql://host/db?user=u", Main.toJdbcUrl("postgresql://u@host/db"), "a user with no password");
        assertEquals("jdbc:postgresql://host/db", Main.toJdbcUrl("postgresql://@host/db?"), "an empty user and query");
        assertEquals("jdbc:postgresql://host/", Main.toJdbcUrl("postgres://host"), "no database named");
        IllegalArgumentException malformed = assertThrows(IllegalArgumentException.class,
                () -> Main.toJdbcUrl("postgresql://ho st/db"));
        assertTrue(malformed.getMessage().startsWith("malformed Postgres URL"), malformed.getMessage());
        IllegalArgumentException bare = assertThrows(IllegalArgumentException.class, () -> Main.toJdbcUrl("jdbc:nothing"));
        assertTrue(bare.getMessage().contains("names a non-JDBC database"), bare.getMessage());
        assertEquals("jdbc:PostgreSQL://db/iom", Main.toJdbcUrl("jdbc:PostgreSQL://db/iom"), "the driver's name in any case");
    }

    // ---- the process -------------------------------------------------------------------------------------------------

    @Test
    void theProcessExitsWithStatusOneAndTheViolationsOnStderr() throws Exception {
        String java = ProcessHandle.current().info().command().orElse("java");
        ProcessBuilder builder = new ProcessBuilder(java, "-cp", System.getProperty("java.class.path"), Main.class.getName());
        builder.environment().remove(DeploymentProfile.SETTING);
        builder.environment().put("REQUIRE_COMPLIANT_DEVICE", "false");
        Path err = Files.createTempFile("device-enrolment-", ".err");
        builder.redirectError(err.toFile()).redirectOutput(ProcessBuilder.Redirect.DISCARD);
        try {
            Process process = builder.start();
            assertTrue(process.waitFor(60, TimeUnit.SECONDS), "the process ends");
            assertEquals(1, process.exitValue());
            String stderr = Files.readString(err);
            assertTrue(stderr.contains("device-enrolment refused to start by the production profile"), stderr);
            assertTrue(stderr.contains("REQUIRE_COMPLIANT_DEVICE=false"), stderr);
        } finally {
            Files.deleteIfExists(err);
        }
    }
}
