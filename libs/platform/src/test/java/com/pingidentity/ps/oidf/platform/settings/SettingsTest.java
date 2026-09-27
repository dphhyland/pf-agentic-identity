package com.pingidentity.ps.oidf.platform.settings;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigDecimal;
import java.net.URI;
import java.nio.file.Path;
import java.time.Duration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;

/** The typed accessors: each resolves with its entry's metadata, and asking for the wrong type is a bug. */
class SettingsTest {

    /** One entry of every type, all read from the environment under their own names. */
    private static final String EVERY_TYPE;

    static {
        StringBuilder settings = new StringBuilder();
        String[][] entries = {
            {"OIDF_T_BOOL", "bool", "\"default\": false"},
            {"OIDF_T_INT", "int", "\"min\": -5, \"max\": 5, \"default\": null"},
            {"OIDF_T_LONG", "long", "\"min\": 0, \"max\": 9223372036854775807, \"default\": \"4\""},
            {"OIDF_T_SECONDS", "seconds", "\"min\": 0, \"max\": 86400, \"default\": 60"},
            {"OIDF_T_MILLIS", "millis", "\"min\": 1, \"max\": 1000, \"default\": null"},
            {"OIDF_T_STRING", "string", "\"default\": \"openid\""},
            {"OIDF_T_CHOICE", "choice", "\"choices\": [\"off\", \"local\", \"authzen\"], \"default\": \"local\""},
            {"OIDF_T_HTTPS_URL", "https-url", "\"default\": null"},
            {"OIDF_T_URL", "url", "\"default\": \"http://localhost:8080\""},
            {"OIDF_T_JSON_OBJECT", "json-object", "\"default\": \"{}\""},
            {"OIDF_T_WORDS", "words", "\"default\": \"RS256 PS256\""},
            {"OIDF_T_PATH", "path", "\"default\": null"},
            {"OIDF_T_SECRET", "secret", "\"default\": null"},
        };
        for (String[] entry : entries) {
            if (settings.length() > 0) {
                settings.append(',');
            }
            settings.append("{\"name\": \"").append(entry[0]).append("\", \"kind\": \"env\", \"type\": \"").append(entry[1]).append("\", ")
                    .append(entry[2]).append(", \"description\": \"d\", \"when_wrong\": {\"effect\": \"doesnt-start\", \"detail\": \"w\"},"
                            + " \"profile\": \"any\", \"security\": true, \"sources\": [{\"from\": \"env\", \"name\": \"")
                    .append(entry[0]).append("\"}], \"aliases\": [], \"file\": false}");
        }
        EVERY_TYPE = "{\"format\": 1, \"component\": \"types\", \"module\": \"libs/platform\", \"package\": \"com.example.types\","
                + " \"families\": [\"OIDF_T_\"], \"settings\": [" + settings + "], \"removed\": []}";
    }

    private final Map<String, String> env = new HashMap<>();

    private Settings settings() {
        return Settings.of(Catalogue.parse(EVERY_TYPE, "types.json"), Sources.of(this.env::get, null, null));
    }

    @Test
    void everyTypeReadsItsDefault() {
        Settings s = settings();

        assertEquals(false, s.bool("OIDF_T_BOOL"));
        assertNull(s.integer("OIDF_T_INT"));
        assertEquals(4L, s.longValue("OIDF_T_LONG"));
        assertEquals(Duration.ofSeconds(60), s.duration("OIDF_T_SECONDS"));
        assertNull(s.duration("OIDF_T_MILLIS"));
        assertEquals("openid", s.string("OIDF_T_STRING"));
        assertEquals("local", s.choice("OIDF_T_CHOICE"));
        assertNull(s.httpsUrl("OIDF_T_HTTPS_URL"));
        assertEquals(URI.create("http://localhost:8080"), s.url("OIDF_T_URL"));
        assertEquals(Map.of(), s.jsonObject("OIDF_T_JSON_OBJECT"));
        assertEquals(Set.of("RS256", "PS256"), s.words("OIDF_T_WORDS"));
        assertNull(s.path("OIDF_T_PATH"));
        assertNull(s.secret("OIDF_T_SECRET"));
    }

    @Test
    void everyTypeReadsASetValue() {
        this.env.putAll(Map.ofEntries(
                Map.entry("OIDF_T_BOOL", "TRUE"),
                Map.entry("OIDF_T_INT", "-5"),
                Map.entry("OIDF_T_LONG", "9223372036854775807"),
                Map.entry("OIDF_T_SECONDS", "0"),
                Map.entry("OIDF_T_MILLIS", "1000"),
                Map.entry("OIDF_T_STRING", "  openid profile "),
                Map.entry("OIDF_T_CHOICE", "AuthZEN"),
                Map.entry("OIDF_T_HTTPS_URL", "https://pdp.example"),
                Map.entry("OIDF_T_URL", "https://pdp.example"),
                Map.entry("OIDF_T_JSON_OBJECT", "{\"a\": 1.50}"),
                Map.entry("OIDF_T_WORDS", "a,b"),
                Map.entry("OIDF_T_PATH", "/run/x"),
                Map.entry("OIDF_T_SECRET", "s")));
        Settings s = settings();

        assertEquals(true, s.bool("OIDF_T_BOOL"));
        assertEquals(-5, s.integer("OIDF_T_INT"));
        assertEquals(Long.MAX_VALUE, s.longValue("OIDF_T_LONG"));
        assertEquals(Duration.ZERO, s.duration("OIDF_T_SECONDS"));
        assertEquals(Duration.ofSeconds(1), s.duration("OIDF_T_MILLIS"));
        assertEquals("openid profile", s.string("OIDF_T_STRING"));
        assertEquals("authzen", s.choice("OIDF_T_CHOICE"), "a choice is returned as the catalogue spells it");
        assertEquals(URI.create("https://pdp.example"), s.httpsUrl("OIDF_T_HTTPS_URL"));
        assertEquals(URI.create("https://pdp.example"), s.url("OIDF_T_URL"));
        assertEquals(Map.of("a", new BigDecimal("1.50")), s.jsonObject("OIDF_T_JSON_OBJECT"));
        assertEquals(Set.of("a", "b"), s.words("OIDF_T_WORDS"));
        assertEquals(Path.of("/run/x"), s.path("OIDF_T_PATH"));
        assertEquals("s", s.secret("OIDF_T_SECRET").reveal());
    }

    @Test
    void eachTypeRefusesWhatItCannotRead() {
        Map<String, String> wrong = Map.ofEntries(
                Map.entry("OIDF_T_BOOL", "yes"),
                Map.entry("OIDF_T_INT", "6"),
                Map.entry("OIDF_T_LONG", "-1"),
                Map.entry("OIDF_T_SECONDS", "1m"),
                Map.entry("OIDF_T_MILLIS", "0"),
                Map.entry("OIDF_T_CHOICE", "remote"),
                Map.entry("OIDF_T_HTTPS_URL", "http://pdp.example"),
                Map.entry("OIDF_T_URL", "file:///etc/passwd"),
                Map.entry("OIDF_T_JSON_OBJECT", "null"),
                Map.entry("OIDF_T_WORDS", ","),
                Map.entry("OIDF_T_PATH", "a\u0000b"));
        for (Map.Entry<String, String> entry : wrong.entrySet()) {
            this.env.clear();
            this.env.put(entry.getKey(), entry.getValue());
            SettingRefused e = assertThrows(SettingRefused.class, () -> settings().resolve(entry.getKey()), entry.getKey());
            assertEquals(entry.getKey(), e.setting());
            assertTrue(e.getMessage().startsWith(entry.getKey()), e.getMessage());
        }
        this.env.clear();
        this.env.put("OIDF_T_JSON_OBJECT", "[1]");
        assertEquals("OIDF_T_JSON_OBJECT: not a JSON object", assertThrows(SettingRefused.class,
                () -> settings().jsonObject("OIDF_T_JSON_OBJECT")).getMessage());
    }

    @Test
    void askingForTheWrongTypeOrAnUncataloguedNameIsABug() {
        Settings s = settings();

        assertEquals("OIDF_T_CHOICE is a choice setting, not bool",
                assertThrows(IllegalArgumentException.class, () -> s.bool("OIDF_T_CHOICE")).getMessage());
        assertEquals("OIDF_T_BOOL is a bool setting, not seconds",
                assertThrows(IllegalArgumentException.class, () -> s.duration("OIDF_T_BOOL")).getMessage());
        assertEquals("OIDF_T_NOPE is not in the types settings catalogue",
                assertThrows(IllegalArgumentException.class, () -> s.string("OIDF_T_NOPE")).getMessage());
    }

    @Test
    void ofReadsTheCataloguesOnTheCallersLoader() {
        Settings example = Settings.of("example");

        assertEquals("example", example.catalogue().component());
        assertEquals("local", example.choice("OIDF_EXAMPLE_MODE"), "nothing in this process sets it");
        assertEquals("local", Settings.of(example.catalogue(), Sources.process()).choice("OIDF_EXAMPLE_MODE"));
    }

    @Test
    void aClassOnTheBootstrapLoaderReadsTheSystemLoader() {
        assertEquals(ClassLoader.getSystemClassLoader(), Settings.loaderOf(String.class));
        assertEquals(SettingsTest.class.getClassLoader(), Settings.loaderOf(SettingsTest.class));
    }

    @Test
    void theParsedEntryKeepsItsMetadata() {
        Setting timeout = Settings.of("example").catalogue().setting("OIDF_EXAMPLE_TIMEOUT_MS");

        assertEquals(EntryKind.ENV, timeout.kind());
        assertEquals(SettingType.MILLIS, timeout.type());
        assertEquals("2000", timeout.defaultValue());
        assertEquals(1L, timeout.min());
        assertEquals(60000L, timeout.max());
        assertEquals(List.of(), timeout.choices());
        assertEquals("How long a call to the example service may take", timeout.description());
        assertEquals(new WhenWrong(WhenWrong.Effect.DOESNT_START, "Not a whole number from 1 to 60000"), timeout.whenWrong());
        assertEquals(ProfileClass.ANY, timeout.profile());
        assertEquals(false, timeout.security());
        assertEquals(List.of(new SourceName(Source.SYSTEM_PROPERTY, "oidf.example.timeout.ms"), new SourceName(Source.ENV, "OIDF_EXAMPLE_TIMEOUT_MS")),
                timeout.sources());
        assertEquals(List.of(), timeout.aliases());
        assertEquals(false, timeout.file());
        assertEquals("OIDF_EXAMPLE_TIMEOUT_MS (millis)", timeout.toString());
        assertEquals("env OIDF_EXAMPLE_TIMEOUT_MS", timeout.sources().get(1).toString());
        Setting failClosed = Settings.of("example").catalogue().setting("OIDF_EXAMPLE_FAIL_CLOSED");
        assertEquals("accepted-risk:example-fail-open", failClosed.profile().toString());
        assertEquals("example-fail-open", failClosed.profile().riskId());
        assertEquals("OIDF_EXAMPLE_REFUSE_ON_FAILURE", failClosed.aliases().get(0).name());
        assertEquals("required-in-production", Settings.of("example").catalogue().setting("OIDF_EXAMPLE_TOKEN").profile().toString());
    }
}
