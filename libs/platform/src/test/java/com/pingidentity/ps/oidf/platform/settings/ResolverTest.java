package com.pingidentity.ps.oidf.platform.settings;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * How one setting is resolved: precedence per source, provenance, aliases, removed names and the {@code _FILE}
 * variant of a secret. Uses the worked example catalogue, META-INF/oidf-settings/example.json in the test resources.
 */
class ResolverTest {

    private final Map<String, String> env = new HashMap<>();
    private final Map<String, String> props = new HashMap<>();
    private final Map<String, String> initParams = new HashMap<>();
    private final List<String> warnings = new ArrayList<>();

    @TempDir
    Path dir;

    private Settings settings() {
        return Settings.load(ResolverTest.class.getClassLoader(), "example")
                .with(Sources.of(this.env::get, this.props::get, this.initParams::get))
                .warningsTo(this.warnings::add);
    }

    private Resolved resolve(String name) {
        return settings().resolve(name);
    }

    private SettingRefused refused(String name) {
        return assertThrows(SettingRefused.class, () -> resolve(name));
    }

    // ---- precedence and provenance --------------------------------------------------------------------

    @Test
    void unsetIsTheDefaultAndSaysSo() {
        Resolved r = resolve("OIDF_EXAMPLE_TIMEOUT_MS");

        assertEquals(Duration.ofMillis(2000), r.value());
        assertTrue(r.provenance().isDefault());
        assertEquals(new Provenance(Source.DEFAULT, "OIDF_EXAMPLE_TIMEOUT_MS", null), r.provenance());
        assertEquals("default", r.provenance().toString());
        assertEquals(List.of(), r.warnings());
    }

    @Test
    void noDefaultIsNull() {
        Resolved r = resolve("OIDF_EXAMPLE_URL");

        assertNull(r.value());
        assertTrue(r.provenance().isDefault());
    }

    @Test
    void theEnvironmentSuppliesAValueAndIsNamedAsItsSource() {
        this.env.put("OIDF_EXAMPLE_TIMEOUT_MS", " 500 ");

        Resolved r = resolve("OIDF_EXAMPLE_TIMEOUT_MS");
        assertEquals(Duration.ofMillis(500), r.value());
        assertEquals(new Provenance(Source.ENV, "OIDF_EXAMPLE_TIMEOUT_MS", null), r.provenance());
        assertEquals("env OIDF_EXAMPLE_TIMEOUT_MS", r.provenance().toString());
        assertFalse(r.provenance().isDefault());
    }

    @Test
    void aSystemPropertyBeatsTheEnvironmentWhenTheCatalogueListsItFirst() {
        this.env.put("OIDF_EXAMPLE_TIMEOUT_MS", "500");
        this.props.put("oidf.example.timeout.ms", "700");

        Resolved r = resolve("OIDF_EXAMPLE_TIMEOUT_MS");
        assertEquals(Duration.ofMillis(700), r.value());
        assertEquals(new Provenance(Source.SYSTEM_PROPERTY, "oidf.example.timeout.ms", null), r.provenance());
    }

    @Test
    void aBlankSourceFallsThroughToTheNext() {
        this.props.put("oidf.example.timeout.ms", "  ");
        this.env.put("OIDF_EXAMPLE_TIMEOUT_MS", "500");

        assertEquals(Source.ENV, resolve("OIDF_EXAMPLE_TIMEOUT_MS").provenance().source());
    }

    @Test
    void anInitParamBeatsTheEnvironmentWhenTheCatalogueListsItFirst() {
        this.env.put("OIDF_EXAMPLE_CORS_ORIGINS", "https://env.example");
        this.initParams.put("exampleCorsOrigins", "https://a.example, https://b.example");

        Resolved r = resolve("exampleCorsOrigins");
        assertEquals(List.of("https://a.example", "https://b.example"), new ArrayList<>((java.util.Set<?>) r.value()));
        assertEquals(new Provenance(Source.INIT_PARAM, "exampleCorsOrigins", null), r.provenance());

        this.initParams.clear();
        assertEquals(new Provenance(Source.ENV, "OIDF_EXAMPLE_CORS_ORIGINS", null), resolve("exampleCorsOrigins").provenance());
    }

    @Test
    void aSourceTheSettingDoesNotListIsNotRead() {
        this.initParams.put("OIDF_EXAMPLE_TIMEOUT_MS", "500");
        this.props.put("OIDF_EXAMPLE_TIMEOUT_MS", "500");

        assertTrue(resolve("OIDF_EXAMPLE_TIMEOUT_MS").provenance().isDefault());
    }

    @Test
    void aWrongValueIsRefusedNamingTheSetting() {
        this.env.put("OIDF_EXAMPLE_TIMEOUT_MS", "0");

        SettingRefused e = refused("OIDF_EXAMPLE_TIMEOUT_MS");
        assertEquals("OIDF_EXAMPLE_TIMEOUT_MS must be between 1 and 60000, not 0", e.getMessage());
        assertEquals("OIDF_EXAMPLE_TIMEOUT_MS", e.setting());
    }

    // ---- aliases -------------------------------------------------------------------------------------

    @Test
    void anOldNameIsUsedWhenTheNewOneIsUnsetAndWarns() {
        this.env.put("OIDF_EXAMPLE_REFUSE_ON_FAILURE", "false");

        Resolved r = resolve("OIDF_EXAMPLE_FAIL_CLOSED");
        assertEquals(Boolean.FALSE, r.value());
        assertEquals(new Provenance(Source.ENV, "OIDF_EXAMPLE_REFUSE_ON_FAILURE", null), r.provenance(),
                "provenance names the old name that supplied the value");
        assertEquals(List.of("OIDF_EXAMPLE_REFUSE_ON_FAILURE is deprecated; set OIDF_EXAMPLE_FAIL_CLOSED instead (the value was"
                + " taken from OIDF_EXAMPLE_REFUSE_ON_FAILURE)"), r.warnings());
    }

    @Test
    void anOldNameIsReadWithItsOwnPrecedence() {
        this.props.put("oidf.example.refuse.on.failure", "false");
        this.env.put("OIDF_EXAMPLE_REFUSE_ON_FAILURE", "true");

        Resolved r = resolve("OIDF_EXAMPLE_FAIL_CLOSED");
        assertEquals(Boolean.FALSE, r.value());
        assertEquals(new Provenance(Source.SYSTEM_PROPERTY, "oidf.example.refuse.on.failure", null), r.provenance());
    }

    @Test
    void theSameValueUnderBothNamesWarnsThatTheOldOneIsRedundant() {
        this.env.put("OIDF_EXAMPLE_FAIL_CLOSED", "false");
        this.env.put("OIDF_EXAMPLE_REFUSE_ON_FAILURE", "false");

        Resolved r = resolve("OIDF_EXAMPLE_FAIL_CLOSED");
        assertEquals(Boolean.FALSE, r.value());
        assertEquals(Source.ENV, r.provenance().source());
        assertEquals("OIDF_EXAMPLE_FAIL_CLOSED", r.provenance().name(), "the current name supplied it");
        assertEquals(List.of("OIDF_EXAMPLE_REFUSE_ON_FAILURE is deprecated and redundant beside OIDF_EXAMPLE_FAIL_CLOSED; remove it"),
                r.warnings());
    }

    @Test
    void differentValuesUnderTheOldAndNewNamesAreRefusedNamingBoth() {
        this.env.put("OIDF_EXAMPLE_FAIL_CLOSED", "true");
        this.env.put("OIDF_EXAMPLE_REFUSE_ON_FAILURE", "false");

        assertEquals("OIDF_EXAMPLE_FAIL_CLOSED and its superseded name OIDF_EXAMPLE_REFUSE_ON_FAILURE are both set, to different"
                + " values. They name one thing - set only OIDF_EXAMPLE_FAIL_CLOSED", refused("OIDF_EXAMPLE_FAIL_CLOSED").getMessage());
    }

    @Test
    void anOldNameWarnsOnceHoweverOftenItIsResolved() {
        this.env.put("OIDF_EXAMPLE_REFUSE_ON_FAILURE", "false");
        Settings logged = Settings.load(ResolverTest.class.getClassLoader(), "example").with(Sources.of(this.env::get, null, null));

        assertFalse(logged.bool("OIDF_EXAMPLE_FAIL_CLOSED"));
        assertFalse(logged.bool("OIDF_EXAMPLE_FAIL_CLOSED"));
        String warning = "OIDF_EXAMPLE_REFUSE_ON_FAILURE is deprecated; set OIDF_EXAMPLE_FAIL_CLOSED instead (the value was taken"
                + " from OIDF_EXAMPLE_REFUSE_ON_FAILURE)";
        assertFalse(Settings.warnOnce(warning), "the first resolve logged it; nothing logs it again");
        assertTrue(Settings.warnOnce("a warning nobody has logged yet " + System.nanoTime()));
    }

    // ---- removed names -------------------------------------------------------------------------------

    @Test
    void aRemovedNameIsRefusedNamingItsReplacementAndTheRelease() {
        this.env.put("OIDF_EXAMPLE_STRICT", "true");

        SettingRefused e = refused("OIDF_EXAMPLE_FAIL_CLOSED");
        assertEquals("OIDF_EXAMPLE_STRICT was removed in 0.4.0; set OIDF_EXAMPLE_FAIL_CLOSED instead", e.getMessage());
        assertEquals("OIDF_EXAMPLE_STRICT", e.setting());
    }

    @Test
    void aBlankRemovedNameIsNotRefused() {
        this.env.put("OIDF_EXAMPLE_STRICT", " ");

        assertEquals(Boolean.TRUE, resolve("OIDF_EXAMPLE_FAIL_CLOSED").value());
    }

    @Test
    void aRemovedNameIsRefusedOnlyWhenItsReplacementIsResolved() {
        this.env.put("OIDF_EXAMPLE_STRICT", "true");
        this.env.put("OIDF_EXAMPLE_LEGACY_CACHE", "on");

        assertEquals("local", resolve("OIDF_EXAMPLE_MODE").value());
    }

    @Test
    void aRemovedNameWithNoReplacementSaysSo() {
        Removed gone = Catalogue.load(ResolverTest.class.getClassLoader(), "example").removed().get(1);

        assertEquals("OIDF_EXAMPLE_LEGACY_CACHE was removed in 0.3.0 and nothing replaces it; unset it", gone.refusal().getMessage());
    }

    // ---- secrets and their _FILE variant --------------------------------------------------------------

    @Test
    void aSecretIsReadDirectlyAndNeverShown() {
        this.env.put("OIDF_EXAMPLE_TOKEN", " tok-123 ");

        Resolved r = resolve("OIDF_EXAMPLE_TOKEN");
        assertEquals("tok-123", ((Secret) r.value()).reveal());
        assertEquals("[secret]", r.value().toString());
        assertFalse(r.toString().contains("tok-123"), "a resolved secret printed by mistake shows nothing");
    }

    @Test
    void aSecretIsReadFromTheFileItsFileVariantNamesWithOneNewlineTrimmed() throws IOException {
        Path file = Files.writeString(this.dir.resolve("token"), " tok-456\n\n", StandardCharsets.UTF_8);
        this.env.put("OIDF_EXAMPLE_TOKEN_FILE", " " + file + " ");

        Resolved r = resolve("OIDF_EXAMPLE_TOKEN");
        assertEquals(" tok-456\n", ((Secret) r.value()).reveal(), "one trailing newline goes; nothing else is touched");
        assertEquals(new Provenance(Source.ENV, "OIDF_EXAMPLE_TOKEN_FILE", file), r.provenance());
        assertEquals("env OIDF_EXAMPLE_TOKEN_FILE (" + file + ")", r.provenance().toString());
    }

    @Test
    void aWindowsNewlineIsOneNewline() throws IOException {
        this.env.put("OIDF_EXAMPLE_TOKEN_FILE", Files.writeString(this.dir.resolve("token"), "tok\r\n").toString());

        assertEquals("tok", ((Secret) resolve("OIDF_EXAMPLE_TOKEN").value()).reveal());
    }

    @Test
    void aFileWithNoNewlineIsReadAsItIs() throws IOException {
        this.env.put("OIDF_EXAMPLE_TOKEN_FILE", Files.writeString(this.dir.resolve("token"), "tok").toString());

        assertEquals("tok", ((Secret) resolve("OIDF_EXAMPLE_TOKEN").value()).reveal());
    }

    @Test
    void theNameAndItsFileVariantBothSetAreRefusedNamingBoth() throws IOException {
        this.env.put("OIDF_EXAMPLE_TOKEN", "tok-direct");
        this.env.put("OIDF_EXAMPLE_TOKEN_FILE", Files.writeString(this.dir.resolve("token"), "tok-file").toString());

        SettingRefused e = refused("OIDF_EXAMPLE_TOKEN");
        assertEquals("OIDF_EXAMPLE_TOKEN and OIDF_EXAMPLE_TOKEN_FILE are both set; set one of them", e.getMessage());
        assertFalse(e.getMessage().contains("tok-"));
    }

    @Test
    void anUnreadableFileIsRefusedNamingThePathNeverTheContent() {
        Path missing = this.dir.resolve("missing");
        this.env.put("OIDF_EXAMPLE_TOKEN_FILE", missing.toString());

        assertEquals("OIDF_EXAMPLE_TOKEN_FILE names " + missing + ", which cannot be read (NoSuchFileException)",
                refused("OIDF_EXAMPLE_TOKEN").getMessage());
        this.env.put("OIDF_EXAMPLE_TOKEN_FILE", this.dir.toString());
        assertTrue(refused("OIDF_EXAMPLE_TOKEN").getMessage().startsWith("OIDF_EXAMPLE_TOKEN_FILE names " + this.dir + ", which cannot be read"),
                "a directory is not a file");
    }

    @Test
    void anEmptyFileIsRefused() throws IOException {
        Path file = Files.writeString(this.dir.resolve("token"), "\n");
        this.env.put("OIDF_EXAMPLE_TOKEN_FILE", file.toString());

        assertEquals("OIDF_EXAMPLE_TOKEN_FILE names " + file + ", which is empty", refused("OIDF_EXAMPLE_TOKEN").getMessage());
    }

    @Test
    void anOversizedFileIsRefusedWithoutReadingItAll() throws IOException {
        Path file = Files.write(this.dir.resolve("token"), new byte[Setting.MAX_FILE_BYTES + 1]);
        this.env.put("OIDF_EXAMPLE_TOKEN_FILE", file.toString());

        assertEquals("OIDF_EXAMPLE_TOKEN_FILE names " + file + ", which holds more than 65536 bytes", refused("OIDF_EXAMPLE_TOKEN").getMessage());
        Files.write(file, new byte[Setting.MAX_FILE_BYTES]);
        assertEquals(Setting.MAX_FILE_BYTES, ((Secret) resolve("OIDF_EXAMPLE_TOKEN").value()).reveal().length(), "the limit itself is allowed");
    }

    @Test
    void onlyASecretHasFileVariants() {
        Catalogue example = Catalogue.load(ResolverTest.class.getClassLoader(), "example");

        assertEquals(List.of(new SourceName(Source.ENV, "OIDF_EXAMPLE_TOKEN_FILE")), example.setting("OIDF_EXAMPLE_TOKEN").fileVariants());
        assertEquals(List.of(), example.setting("OIDF_EXAMPLE_URL").fileVariants());
        this.env.put("OIDF_EXAMPLE_URL_FILE", "/etc/passwd");
        assertNull(resolve("OIDF_EXAMPLE_URL").value(), "a _FILE name is read only for a secret whose entry allows it");
        assertEquals("oidf.x.file", Source.SYSTEM_PROPERTY.fileVariant("oidf.x"));
        assertEquals("xFile", Source.INIT_PARAM.fileVariant("x"));
    }

    // ---- PingFederate-supplied kinds --------------------------------------------------------------------

    @Test
    void aPluginFieldIsParsedNotResolved() {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> resolve("Request timeout (ms)"));
        assertEquals("Request timeout (ms) is a plugin-field, which PingFederate supplies; parse the value it gives instead of"
                + " resolving one", e.getMessage());
        assertEquals(250, settings().parse("Request timeout (ms)", " 250 "));
        assertEquals(Duration.ofSeconds(30), settings().parse("example_max_age", "30"));
        assertNull(settings().parse("example_max_age", ""));
    }

    @Test
    void theProcessSourcesReadTheProcess() {
        Sources process = Sources.process();

        assertEquals(System.getProperty("java.version"), process.get(Source.SYSTEM_PROPERTY, "java.version"));
        assertEquals(System.getenv("PATH"), process.get(Source.ENV, "PATH"));
        assertNull(process.get(Source.INIT_PARAM, "anything"));
        assertThrows(IllegalArgumentException.class, () -> process.get(Source.DEFAULT, "x"));
        assertEquals("v", process.withInitParams(name -> "v").get(Source.INIT_PARAM, "anything"));
    }
}
