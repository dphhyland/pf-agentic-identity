package com.pingidentity.ps.oidf.platform.settings;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDate;
import java.util.List;
import java.util.Map;
import com.pingidentity.ps.oidf.platform.component.ComponentSwitches;
import com.pingidentity.ps.oidf.platform.profile.DeploymentProfile;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Preflight's exit codes, its reading of an env file and JAVA_OPTS, and what it prints. */
class PreflightTest {

    private static final LocalDate TODAY = LocalDate.of(2026, 9, 30);

    @TempDir
    Path dir;

    private final ByteArrayOutputStream out = new ByteArrayOutputStream();
    private final ByteArrayOutputStream err = new ByteArrayOutputStream();

    private int run(String... args) {
        return Preflight.run(args, new PrintStream(this.out, true, StandardCharsets.UTF_8),
                new PrintStream(this.err, true, StandardCharsets.UTF_8), getClass().getClassLoader(), TODAY);
    }

    private String file(String... lines) throws IOException {
        Path file = this.dir.resolve("env");
        Files.write(file, List.of(lines));
        return file.toString();
    }

    private String out() {
        return this.out.toString(StandardCharsets.UTF_8);
    }

    @Test
    void aCleanProductionFileExitsZero() throws IOException {
        assertEquals(Preflight.CLEAN, run("--env-file", file("# nothing governed", "", "OIDF_REDIS_URL=rediss://cache:6380",
                "OIDF_EXAMPLE_TOKEN=t")));
        assertTrue(out().endsWith("clean under the production profile: nothing would be refused" + System.lineSeparator()), out());
    }

    @Test
    void aForbiddenSwitchExitsOneAndPrintsWhatTheServerWouldLog() throws IOException {
        assertEquals(Preflight.REFUSED, run("--env-file", file("export OIDF_REDIS_URL='redis://:pw@cache:6379'", "OIDF_EXAMPLE_TOKEN=t")));
        String printed = out();
        assertTrue(printed.startsWith("REFUSED: OIDF_REDIS_URL is a redis:// URL, which the production profile forbids"), printed);
        assertTrue(printed.contains("[ATTESTATION_AUTH, ATTESTATION_ISSUER, OPERATOR_API]"), printed);
        assertTrue(printed.contains("1 line(s) under the production profile refuse the components named; each answers 503 until it"
                + " is fixed"), printed);
        assertTrue(!printed.contains(":pw@"), "never the URL");
    }

    @Test
    void theJvmFlagInJavaOptsRefusesEveryComponent() throws IOException {
        assertEquals(Preflight.REFUSED, run("--env-file", file("JAVA_OPTS=\"-Xmx1g -Djdk.internal.httpclient.disableHostnameVerification"
                + " -Dother=1\"", "OIDF_EXAMPLE_TOKEN=t")));
        assertTrue(out().contains("REFUSED: jdk.internal.httpclient.disableHostnameVerification is set, which the production profile"
                + " forbids"), out());
        assertTrue(out().contains("[FEDERATION, AUTO_REGISTRATION, ATTESTATION_AUTH, ATTESTATION_ISSUER, HOSTING, SSF, SSF_RECEIVER,"
                + " OPERATOR_API, FAPI]"), out());
    }

    @Test
    void theDevelopmentProfileRefusesNothingAndSaysWhatProductionWould() throws IOException {
        String file = file("OIDF_DEPLOYMENT_PROFILE=development", "OIDF_REDIS_URL=redis://cache", "OIDF_EXAMPLE_TYPO=1",
                "OIDF_EXAMPLE_TOKEN=t");
        assertEquals(Preflight.CLEAN, run("--env-file", file));
        assertTrue(out().contains("not refused (development): OIDF_REDIS_URL is a redis:// URL"), out());
        assertTrue(out().contains("not refused (development): OIDF_EXAMPLE_TYPO is set, under the OIDF_EXAMPLE_ family"), out());
        assertTrue(out().contains("clean under the development profile: nothing would be refused (2 violation(s) listed that"
                + " refuse nothing here; the production profile would judge them)"), out());
        this.out.reset();
        assertEquals(Preflight.REFUSED, run("--env-file", file, "--profile", "production"), "--profile wins over the file");
        this.out.reset();
        assertEquals(Preflight.CLEAN, run("--profile", "development", "--env-file", file("OIDF_REDIS_URL=redis://cache")));
    }

    private static final ProfileAudit.Violation REQUIRED = new ProfileAudit.Violation(ProfileAudit.Kind.REQUIRED,
            "OIDF_OPERATOR_AUDIENCE", "OIDF_OPERATOR_AUDIENCE is unset", "Set it", List.of("OPERATOR_API"));
    private static final ProfileAudit.Violation FORBIDDEN = new ProfileAudit.Violation(ProfileAudit.Kind.FORBIDDEN,
            "OIDF_FEDERATION_X", "OIDF_FEDERATION_X=true, which the production profile forbids", "Unset it", List.of("FEDERATION"));

    /** report() on {@code violations} under production, with the switches {@code env} sets. */
    private int report(Map<String, String> env, ProfileAudit.Violation... violations) {
        this.out.reset();
        return Preflight.report(new ProfileAudit.Result(DeploymentProfile.PRODUCTION, List.of(violations), List.of()),
                ComponentSwitches.of(env::get, name -> null), new PrintStream(this.out, true, StandardCharsets.UTF_8));
    }

    @Test
    void aRequiredSettingRefusesOnlyAComponentSwitchedOnAsTheServerDoes() {
        assertEquals(Preflight.CLEAN, report(Map.of(), REQUIRED), "the operator API not switched on");
        assertTrue(out().startsWith("not refused (not switched on): OIDF_OPERATOR_AUDIENCE is unset. Set it [OPERATOR_API]"), out());
        assertTrue(out().contains("clean under the production profile: nothing would be refused (1 violation(s) listed that"
                + " refuse nothing here)"), out());
        assertEquals(Preflight.CLEAN, report(Map.of("OIDF_OPERATOR_API_ENABLED", "false"), REQUIRED), "switched off");
        assertEquals(Preflight.REFUSED, report(Map.of("OIDF_OPERATOR_API_ENABLED", "true"), REQUIRED), "switched on");
        assertTrue(out().startsWith("REFUSED: OIDF_OPERATOR_AUDIENCE is unset"), out());
    }

    @Test
    void aComponentSwitchedOffIsNeverRefused() {
        assertEquals(Preflight.REFUSED, report(Map.of(), FORBIDDEN), "inferred, as the server's Startup.begin refuses it");
        assertEquals(Preflight.CLEAN, report(Map.of("OIDF_FEDERATION_ENABLED", "false"), FORBIDDEN));
        assertTrue(out().startsWith("not refused (switched off): OIDF_FEDERATION_X=true"), out());
        assertEquals(Preflight.CLEAN, report(Map.of(), new ProfileAudit.Violation(ProfileAudit.Kind.CATALOGUE, "x", "x cannot be"
                + " loaded", "Deploy one copy", List.of())));
        assertTrue(out().startsWith("not refused (names no component): x cannot be loaded"), out());
    }

    @Test
    void aSwitchThatDoesNotParseRefusesItsComponentInEitherProfile() throws IOException {
        assertEquals(Preflight.REFUSED, report(Map.of("OIDF_FEDERATION_ENABLED", "maybe")));
        assertTrue(out().startsWith("REFUSED: "), out());
        assertTrue(out().contains("[FEDERATION]"), out());
        this.out.reset();
        assertEquals(Preflight.REFUSED, run("--env-file", file("OIDF_DEPLOYMENT_PROFILE=development", "OIDF_FEDERATION_ENABLED=maybe")));
    }

    @Test
    void aWarningAloneExitsZero() throws IOException {
        assertEquals(Preflight.CLEAN, run("--env-file", file("OIDF_EXAMPLE_TOKEN=t", "OIDF_ACCEPTED_RISKS=nope")));
        assertTrue(out().contains("warning: OIDF_ACCEPTED_RISKS names 'nope'"), out());
    }

    @Test
    void usageAndUnreadableFilesExitTwo() throws IOException {
        assertEquals(Preflight.USAGE, run());
        assertEquals(Preflight.USAGE, run("--env-file"));
        assertEquals(Preflight.USAGE, run("--env-file", "x", "--profile", "staging"));
        assertEquals(Preflight.USAGE, run("--what", "x"));
        assertTrue(this.err.toString(StandardCharsets.UTF_8).contains("usage: Preflight --env-file FILE"));
        assertEquals(Preflight.USAGE, run("--env-file", this.dir.resolve("missing").toString()));
        assertTrue(this.err.toString(StandardCharsets.UTF_8).contains("cannot be read (NoSuchFileException)"));
        assertEquals(Preflight.USAGE, run("--env-file", "a\0b"));
        assertEquals(Preflight.USAGE, run("--env-file", file("NOT A PAIR")));
        assertTrue(this.err.toString(StandardCharsets.UTF_8).contains(": line 1 is not NAME=value"));
    }

    @Test
    void anEnvFileIsReadAsAShellWouldReadItsPairs() {
        assertEquals(Map.of("A", "1", "B", "two words", "C", "'x", "D", "", "E", "=x"), Preflight.readEnvFile(List.of("A=0", "A=1",
                "  export B=\"two words\"  ", "# C=nothing", "C='x", "D=", "E==x")));
        assertEquals("line 2 is not NAME=value", assertThrows(IllegalArgumentException.class,
                () -> Preflight.readEnvFile(List.of("A=1", "1A=2"))).getMessage());
        assertEquals("x", Preflight.unquote("'x'"));
        assertEquals("\"x'", Preflight.unquote("\"x'"));
        assertEquals("\"", Preflight.unquote("\""));
        assertEquals(Map.of(), Preflight.systemProperties(null));
        assertEquals(Map.of("a", "1", "b", "", "c", "x=y"), Preflight.systemProperties("  -Xmx1g -Da=1 -Db -D '-Dc=x=y'"));
    }
}
