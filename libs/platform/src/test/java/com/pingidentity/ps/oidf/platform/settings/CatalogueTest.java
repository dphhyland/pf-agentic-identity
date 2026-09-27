package com.pingidentity.ps.oidf.platform.settings;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigDecimal;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Consumer;
import com.pingidentity.ps.oidf.platform.json.Json;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * The catalogue format and its validator: the worked example loads, and every rule refuses what breaks it,
 * naming the file, the entry and the member.
 */
class CatalogueTest {

    private static final String WHERE = "example.json";

    @TempDir
    Path dir;

    private static String example() {
        try (InputStream in = CatalogueTest.class.getClassLoader().getResourceAsStream("META-INF/oidf-settings/example.json")) {
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> document() {
        return (Map<String, Object>) Json.copy(Json.parse(example()));
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> entry(Map<String, Object> document, int index) {
        return (Map<String, Object>) settings(document).get(index);
    }

    @SuppressWarnings("unchecked")
    private static List<Object> settings(Map<String, Object> document) {
        return (List<Object>) document.get("settings");
    }

    /** The refusal for the example with {@code change} made to it. */
    private static String refusal(Consumer<Map<String, Object>> change) {
        Map<String, Object> document = document();
        change.accept(document);
        return assertThrows(IllegalArgumentException.class, () -> Catalogue.parse(Json.write(document), WHERE)).getMessage();
    }

    /** The refusal for the example with {@code change} made to entry {@code index}. */
    private static String entryRefusal(int index, Consumer<Map<String, Object>> change) {
        return refusal(document -> change.accept(entry(document, index)));
    }

    // ---- the worked example -----------------------------------------------------------------------------

    @Test
    void theWorkedExampleLoads() {
        Catalogue c = Catalogue.load(CatalogueTest.class.getClassLoader(), "example");

        assertEquals("example", c.component());
        assertEquals("libs/platform", c.module());
        assertEquals("com.pingidentity.ps.oidf.platform.settings", c.owningPackage());
        assertEquals(List.of("OIDF_EXAMPLE_"), c.families());
        assertEquals(8, c.settings().size());
        assertEquals("OIDF_EXAMPLE_FAIL_CLOSED", c.settings().get(0).name(), "entries keep the file's order");
        assertEquals(2, c.removed().size());
        assertEquals(new Removed("OIDF_EXAMPLE_STRICT", Source.ENV, "OIDF_EXAMPLE_FAIL_CLOSED", "0.4.0"), c.removed().get(0));
        assertEquals(Set.of("OIDF_EXAMPLE_FAIL_CLOSED", "OIDF_EXAMPLE_REFUSE_ON_FAILURE", "OIDF_EXAMPLE_TIMEOUT_MS", "OIDF_EXAMPLE_MODE",
                "OIDF_EXAMPLE_URL", "OIDF_EXAMPLE_TOKEN", "OIDF_EXAMPLE_TOKEN_FILE", "OIDF_EXAMPLE_CORS_ORIGINS", "OIDF_EXAMPLE_STRICT",
                "OIDF_EXAMPLE_LEGACY_CACHE"), c.declaredEnvironmentNames());
        assertEquals(Catalogue.parse(Json.write(document()), WHERE).settings().size(), 8, "the canonical form reads the same");
    }

    // ---- loading ------------------------------------------------------------------------------------------

    @Test
    void aComponentNameIsLowerCaseWordsJoinedByHyphens() {
        ClassLoader loader = CatalogueTest.class.getClassLoader();
        for (String bad : new String[] {null, "Example", "../example", "example-", "ex ample"}) {
            IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> Catalogue.load(loader, bad));
            assertTrue(e.getMessage().startsWith("a settings component is lower-case words joined by hyphens, not "), e.getMessage());
        }
    }

    @Test
    void aMissingCatalogueIsRefused() {
        assertEquals("no settings catalogue META-INF/oidf-settings/absent.json on the class path", assertThrows(IllegalArgumentException.class,
                () -> Catalogue.load(CatalogueTest.class.getClassLoader(), "absent")).getMessage());
    }

    @Test
    void aCatalogueOnTheClassPathTwiceIsRefused() throws IOException {
        for (String jar : new String[] {"a", "b"}) {
            Path file = this.dir.resolve(jar).resolve("META-INF/oidf-settings/example.json");
            Files.createDirectories(file.getParent());
            Files.writeString(file, example());
        }
        try (URLClassLoader loader = new URLClassLoader(new URL[] {this.dir.resolve("a").toUri().toURL(), this.dir.resolve("b").toUri().toURL()}, null)) {
            String message = assertThrows(IllegalArgumentException.class, () -> Catalogue.load(loader, "example")).getMessage();
            assertTrue(message.startsWith("META-INF/oidf-settings/example.json is on the class path 2 times ("), message);
            assertTrue(message.endsWith("); a catalogue has exactly one owning module"), message);
        }
    }

    @Test
    void aFileNamedForAnotherComponentIsRefused() throws IOException {
        Path file = this.dir.resolve("META-INF/oidf-settings/other.json");
        Files.createDirectories(file.getParent());
        Files.writeString(file, example());
        try (URLClassLoader loader = new URLClassLoader(new URL[] {this.dir.toUri().toURL()}, null)) {
            assertEquals("META-INF/oidf-settings/other.json names its component example; the file and the component are named alike",
                    assertThrows(IllegalArgumentException.class, () -> Catalogue.load(loader, "other")).getMessage());
        }
    }

    @Test
    void aClassPathThatCannotBeSearchedOrReadIsRefused() throws IOException {
        ClassLoader unsearchable = new ClassLoader(null) {
            @Override
            public Enumeration<URL> getResources(String name) throws IOException {
                throw new IOException("broken");
            }
        };
        assertEquals("the class path could not be searched for META-INF/oidf-settings/example.json",
                assertThrows(IllegalArgumentException.class, () -> Catalogue.load(unsearchable, "example")).getMessage());
        URL gone = this.dir.resolve("gone.json").toUri().toURL();
        ClassLoader unreadable = new ClassLoader(null) {
            @Override
            public Enumeration<URL> getResources(String name) {
                return Collections.enumeration(List.of(gone));
            }
        };
        assertEquals("META-INF/oidf-settings/example.json could not be read",
                assertThrows(IllegalArgumentException.class, () -> Catalogue.load(unreadable, "example")).getMessage());
    }

    // ---- the document ---------------------------------------------------------------------------------------

    @Test
    void theDocumentIsOneJsonObject() {
        assertEquals(WHERE + ": JSON: expected a member name at offset 1",
                assertThrows(IllegalArgumentException.class, () -> Catalogue.parse("{", WHERE)).getMessage());
        assertEquals(WHERE + ": the document: is not a JSON object",
                assertThrows(IllegalArgumentException.class, () -> Catalogue.parse("[]", WHERE)).getMessage());
    }

    @Test
    void theDocumentsMembersAreAllRequiredAndNoOthersAllowed() {
        assertEquals(WHERE + ": the document: unknown member 'comment'", refusal(d -> d.put("comment", "x")));
        for (String member : List.of("format", "component", "module", "package", "families", "settings", "removed")) {
            assertEquals(WHERE + ": the document: no member '" + member + "'", refusal(d -> d.remove(member)));
        }
    }

    @Test
    void theDocumentsMembersAreChecked() {
        assertEquals(WHERE + ": the document: format is 2; this reader reads format 1", refusal(d -> d.put("format", new BigDecimal(2))));
        assertEquals(WHERE + ": the document: format must be a number, not '1'", refusal(d -> d.put("format", "1")));
        assertEquals(WHERE + ": the document: component must be lower-case words joined by hyphens, not 'Example'",
                refusal(d -> d.put("component", "Example")));
        assertEquals(WHERE + ": the document: component must be text, not null", refusal(d -> d.put("component", null)));
        assertEquals(WHERE + ": the document: component must be text, not ' '", refusal(d -> d.put("component", " ")));
        assertEquals(WHERE + ": the document: component must be one line with no spaces around it", refusal(d -> d.put("component", " example")));
        assertEquals(WHERE + ": the document: component must be one line with no spaces around it", refusal(d -> d.put("component", "ex\u007fample")));
        assertEquals(WHERE + ": the document: module must be a module's path from the repository root, not '/libs/platform'",
                refusal(d -> d.put("module", "/libs/platform")));
        assertEquals(WHERE + ": the document: package must be one Java package, not 'platform'", refusal(d -> d.put("package", "platform")));
        assertEquals(WHERE + ": the document: families must be a list, not 'OIDF_EXAMPLE_'", refusal(d -> d.put("families", "OIDF_EXAMPLE_")));
        assertEquals(WHERE + ": families: each family is a prefix such as OIDF_FEDERATION_, not 'OIDF_EXAMPLE'",
                refusal(d -> d.put("families", List.of("OIDF_EXAMPLE"))));
        assertEquals(WHERE + ": families: each family is a prefix such as OIDF_FEDERATION_, not 'OIDF_'",
                refusal(d -> d.put("families", List.of("OIDF_"))));
        assertEquals(WHERE + ": families: each family is a prefix such as OIDF_FEDERATION_, not a number",
                refusal(d -> d.put("families", List.of(BigDecimal.ONE))));
        assertEquals(WHERE + ": families: OIDF_EXAMPLE_ is listed twice", refusal(d -> d.put("families", List.of("OIDF_EXAMPLE_", "OIDF_EXAMPLE_"))));
        assertEquals(WHERE + ": the document: settings must be a list, not an object", refusal(d -> d.put("settings", Map.of())));
    }

    // ---- an entry -------------------------------------------------------------------------------------------

    @Test
    void anEntryIsAnObjectWithEveryMember() {
        assertEquals(WHERE + ": settings[0]: is not a JSON object", refusal(d -> d.put("settings", List.of("OIDF_X"))));
        for (String member : List.of("name", "kind", "type", "default", "description", "when_wrong", "profile", "security", "sources",
                "aliases", "file")) {
            String message = entryRefusal(1, e -> e.remove(member));
            assertEquals(WHERE + ": settings[1]: no member '" + member + "'", message);
        }
        assertEquals(WHERE + ": settings[1]: unknown member 'owner'", entryRefusal(1, e -> e.put("owner", "x")));
    }

    @Test
    void anEntrysKindAndTypeAreOnesTheFormatKnows() {
        assertEquals(WHERE + ": settings[1] (OIDF_EXAMPLE_TIMEOUT_MS): kind must be env, system-property, init-param, plugin-field or"
                + " extended-property, not 'environment'", entryRefusal(1, e -> e.put("kind", "environment")));
        assertEquals(WHERE + ": settings[1] (OIDF_EXAMPLE_TIMEOUT_MS): kind must be env, system-property, init-param, plugin-field or"
                + " extended-property, not null", entryRefusal(1, e -> e.put("kind", null)));
        assertEquals(WHERE + ": settings[1] (OIDF_EXAMPLE_TIMEOUT_MS): type must be one of bool, int, long, seconds, millis, string,"
                + " choice, https-url, url, json-object, words, path, secret, not 'duration'", entryRefusal(1, e -> e.put("type", "duration")));
        assertEquals(WHERE + ": settings[1] (OIDF_EXAMPLE_TIMEOUT_MS): type must be one of bool, int, long, seconds, millis, string,"
                + " choice, https-url, url, json-object, words, path, secret, not true", entryRefusal(1, e -> e.put("type", true)));
    }

    @Test
    void aRangedTypeHasARangeAndNoOtherTypeHasOne() {
        String at = WHERE + ": settings[1] (OIDF_EXAMPLE_TIMEOUT_MS): ";
        assertEquals(at + "no member 'min'", entryRefusal(1, e -> e.remove("min")));
        assertEquals(at + "no member 'max'", entryRefusal(1, e -> e.remove("max")));
        assertEquals(at + "min is more than max", entryRefusal(1, e -> e.put("min", new BigDecimal(60001))));
        assertEquals(at + "min must be a whole number from -9223372036854775808 to 9223372036854775807, not 1.5",
                entryRefusal(1, e -> e.put("min", new BigDecimal("1.5"))));
        assertEquals(at + "max must be a whole number from -9223372036854775808 to 9223372036854775807, not 9223372036854775808",
                entryRefusal(1, e -> e.put("max", new BigDecimal("9223372036854775808"))));
        assertEquals(WHERE + ": settings[6] (Request timeout (ms)): max must be a whole number from -2147483648 to 2147483647, not 2147483648",
                entryRefusal(6, e -> e.put("max", new BigDecimal("2147483648"))));
        assertEquals(WHERE + ": settings[6] (Request timeout (ms)): min must be a whole number from -2147483648 to 2147483647, not -2147483649",
                entryRefusal(6, e -> e.put("min", new BigDecimal("-2147483649"))));
        assertEquals(at + "min must be a number, not '1'", entryRefusal(1, e -> e.put("min", "1")));
        assertEquals(WHERE + ": settings[2] (OIDF_EXAMPLE_MODE): a choice setting has no member 'min'",
                entryRefusal(2, e -> e.put("min", BigDecimal.ONE)));
        assertEquals(at + "the default is refused: OIDF_EXAMPLE_TIMEOUT_MS must be between 1 and 60000, not 0",
                entryRefusal(1, e -> e.put("default", BigDecimal.ZERO)));
    }

    @Test
    void aChoiceListsDistinctChoicesAndOnlyAChoiceDoes() {
        String at = WHERE + ": settings[2] (OIDF_EXAMPLE_MODE): ";
        assertEquals(at + "no member 'choices'", entryRefusal(2, e -> e.remove("choices")));
        assertEquals(at + "a choice setting lists its choices", entryRefusal(2, e -> {
            e.put("choices", List.of());
            e.put("default", null);
        }));
        assertEquals(at + "choice 'LOCAL' is listed twice (choices are read in any case)", entryRefusal(2, e -> e.put("choices", List.of("local", "LOCAL"))));
        assertEquals(at + "each choice is a word, not ' '", entryRefusal(2, e -> e.put("choices", List.of(" "))));
        assertEquals(at + "each choice is a word, not ' local'", entryRefusal(2, e -> e.put("choices", List.of(" local"))));
        assertEquals(at + "each choice is a word, not a number", entryRefusal(2, e -> e.put("choices", List.of(BigDecimal.ONE))));
        assertEquals(at + "the default is refused: OIDF_EXAMPLE_MODE must be one of off, remote, not local",
                entryRefusal(2, e -> e.put("choices", List.of("off", "remote"))));
        assertEquals(WHERE + ": settings[1] (OIDF_EXAMPLE_TIMEOUT_MS): a millis setting has no member 'choices'",
                entryRefusal(1, e -> e.put("choices", List.of("a"))));
    }

    @Test
    void whatItDoesAndWhenItIsWrongAreWrittenDown() {
        String at = WHERE + ": settings[1] (OIDF_EXAMPLE_TIMEOUT_MS)";
        assertEquals(at + ": description must be text, not ''", entryRefusal(1, e -> e.put("description", "")));
        assertEquals(at + ".when_wrong: is not a JSON object", entryRefusal(1, e -> e.put("when_wrong", "doesnt-start")));
        assertEquals(at + ".when_wrong: no member 'detail'", entryRefusal(1, e -> e.put("when_wrong", Map.of("effect", "doesnt-start"))));
        assertEquals(at + ".when_wrong: effect must be doesnt-start, first-request, per-request or not-checked, not 'crashes'",
                entryRefusal(1, e -> e.put("when_wrong", Map.of("effect", "crashes", "detail", "x"))));
        assertEquals(at + ".when_wrong: effect must be doesnt-start, first-request, per-request or not-checked, not a number",
                entryRefusal(1, e -> e.put("when_wrong", Map.of("effect", BigDecimal.ONE, "detail", "x"))));
        assertEquals(at + ".when_wrong: detail must be text, not ''", entryRefusal(1, e -> e.put("when_wrong", Map.of("effect", "first-request", "detail", ""))));
        for (WhenWrong.Effect effect : WhenWrong.Effect.values()) {
            Map<String, Object> document = document();
            entry(document, 1).put("when_wrong", Map.of("effect", effect.id(), "detail", "x"));
            assertEquals(effect, Catalogue.parse(Json.write(document), WHERE).setting("OIDF_EXAMPLE_TIMEOUT_MS").whenWrong().effect());
        }
    }

    @Test
    void aProfileClassIsOneOfTheFour() {
        String at = WHERE + ": settings[1] (OIDF_EXAMPLE_TIMEOUT_MS): ";
        for (String bad : List.of("production", "accepted-risk:", "accepted-risk:Upper", "accepted-risk:a--b", "accepted-risk:" + "a".repeat(65))) {
            assertEquals(at + "profile must be any, forbidden-in-production, required-in-production or accepted-risk:<id> (lower-case words"
                    + " joined by hyphens), not " + bad, entryRefusal(1, e -> e.put("profile", bad)));
        }
        assertEquals(new ProfileClass(ProfileClass.Kind.ACCEPTED_RISK, "a".repeat(64)), ProfileClass.parse("accepted-risk:" + "a".repeat(64)));
        for (String good : List.of("any", "forbidden-in-production", "required-in-production", "accepted-risk:pdp-fail-open")) {
            assertEquals(good, ProfileClass.parse(good).toString());
        }
    }

    @Test
    void theFlagsAreBooleans() {
        String at = WHERE + ": settings[1] (OIDF_EXAMPLE_TIMEOUT_MS): ";
        assertEquals(at + "security must be true or false, not 'no'", entryRefusal(1, e -> e.put("security", "no")));
        assertEquals(at + "file must be true or false, not null", entryRefusal(1, e -> e.put("file", null)));
    }

    // ---- sources, aliases and names --------------------------------------------------------------------------

    @Test
    void sourcesAreAListOfPlacesEachReadOnce() {
        String at = WHERE + ": settings[1] (OIDF_EXAMPLE_TIMEOUT_MS)";
        assertEquals(at + ": sources must be a list, not an object", entryRefusal(1, e -> e.put("sources", Map.of())));
        assertEquals(at + ".sources[0]: from must be env, system-property or init-param, not 'default'",
                entryRefusal(1, e -> e.put("sources", List.of(Map.of("from", "default", "name", "x")))));
        Map<String, Object> noFrom = new LinkedHashMap<>();
        noFrom.put("from", null);
        noFrom.put("name", "x");
        assertEquals(at + ".sources[0]: from must be env, system-property or init-param, not null",
                entryRefusal(1, e -> e.put("sources", List.of(noFrom))));
        assertEquals(at + ".sources[1]: a setting is read from env once", entryRefusal(1, e -> e.put("sources",
                List.of(Map.of("from", "env", "name", "OIDF_EXAMPLE_TIMEOUT_MS"), Map.of("from", "env", "name", "OIDF_EXAMPLE_TIMEOUT")))));
        assertEquals(at + ".sources[0]: unknown member 'default'",
                entryRefusal(1, e -> e.put("sources", List.of(Map.of("from", "env", "name", "OIDF_EXAMPLE_TIMEOUT_MS", "default", "1")))));
    }

    @Test
    void eachSourceSpellsItsNamesItsOwnWay() {
        String at = WHERE + ": settings[1] (OIDF_EXAMPLE_TIMEOUT_MS).sources[";
        assertEquals(at + "1]: 'oidf_example_timeout_ms' is not an environment variable's name",
                entryRefusal(1, e -> e.put("sources", List.of(Map.of("from", "system-property", "name", "oidf.example.timeout.ms"),
                        Map.of("from", "env", "name", "oidf_example_timeout_ms")))));
        assertEquals(at + "0]: 'OIDF.EXAMPLE' is not a system property's name",
                entryRefusal(1, e -> e.put("sources", List.of(Map.of("from", "system-property", "name", "OIDF.EXAMPLE")))));
        assertEquals(at + "0]: 'a b' is not an init-param's name",
                entryRefusal(1, e -> e.put("sources", List.of(Map.of("from", "init-param", "name", "a b")))));
        assertEquals(at + "0]: a number is not an init-param's name",
                entryRefusal(1, e -> e.put("sources", List.of(Map.of("from", "init-param", "name", BigDecimal.ONE)))));
    }

    @Test
    void aResolvedEntryIsReadUnderItsOwnName() {
        assertEquals(WHERE + ": settings[1] (OIDF_EXAMPLE_TIMEOUT_MS): an env entry is read from env under its own name",
                entryRefusal(1, e -> e.put("sources", List.of(Map.of("from", "system-property", "name", "oidf.example.timeout.ms")))));
        assertEquals(WHERE + ": settings[5] (exampleCorsOrigins): an init-param entry is read from init-param under its own name",
                entryRefusal(5, e -> e.put("sources", List.of(Map.of("from", "env", "name", "OIDF_EXAMPLE_CORS_ORIGINS")))));
        Map<String, Object> document = document();
        entry(document, 1).put("kind", "system-property");
        entry(document, 1).put("name", "oidf.example.timeout.ms");
        assertEquals(EntryKind.SYSTEM_PROPERTY, Catalogue.parse(Json.write(document), WHERE).setting("oidf.example.timeout.ms").kind());
        entry(document, 1).put("sources", List.of(Map.of("from", "env", "name", "OIDF_EXAMPLE_TIMEOUT_MS")));
        assertEquals(WHERE + ": settings[1] (oidf.example.timeout.ms): an system-property entry is read from system-property under its own name",
                assertThrows(IllegalArgumentException.class, () -> Catalogue.parse(Json.write(document), WHERE)).getMessage());
    }

    @Test
    void aPingFederateSuppliedEntryHasNoSourcesAliasesOrFile() {
        String at = WHERE + ": settings[6] (Request timeout (ms)): a plugin-field is supplied by PingFederate: it has no sources, aliases or file";
        assertEquals(at, entryRefusal(6, e -> e.put("sources", List.of(Map.of("from", "env", "name", "OIDF_EXAMPLE_PLUGIN_TIMEOUT")))));
        assertEquals(at, entryRefusal(6, e -> e.put("aliases", List.of(Map.of("name", "OIDF_EXAMPLE_OLD_TIMEOUT",
                "sources", List.of(Map.of("from", "env", "name", "OIDF_EXAMPLE_OLD_TIMEOUT")))))));
        assertEquals(at, entryRefusal(6, e -> e.put("file", true)));
    }

    @Test
    void anAliasIsNamedAndReadFromSomewhere() {
        String at = WHERE + ": settings[0] (OIDF_EXAMPLE_FAIL_CLOSED)";
        assertEquals(at + ": aliases must be a list, not an object", entryRefusal(0, e -> e.put("aliases", Map.of())));
        assertEquals(at + ".aliases[0]: is not a JSON object", entryRefusal(0, e -> e.put("aliases", List.of("OIDF_OLD"))));
        assertEquals(at + ".aliases[0]: no member 'sources'", entryRefusal(0, e -> e.put("aliases", List.of(Map.of("name", "OIDF_OLD")))));
        assertEquals(at + ".aliases[0]: one of an alias's sources has the alias's name", entryRefusal(0, e -> e.put("aliases",
                List.of(Map.of("name", "OIDF_EXAMPLE_OLD", "sources", List.of(Map.of("from", "env", "name", "OIDF_EXAMPLE_OTHER")))))));
        assertEquals(at + ".aliases[0]: one of an alias's sources has the alias's name", entryRefusal(0, e -> e.put("aliases",
                List.of(Map.of("name", "OIDF_EXAMPLE_OLD", "sources", List.of())))));
    }

    @Test
    void aNameIsDeclaredOnceInACatalogue() {
        assertEquals(WHERE + ": settings[0] (OIDF_EXAMPLE_FAIL_CLOSED).aliases[0].sources[1]: env OIDF_EXAMPLE_FAIL_CLOSED is declared twice in"
                + " this catalogue", entryRefusal(0, e -> e.put("aliases", List.of(Map.of("name", "oidf.example.old", "sources",
                        List.of(Map.of("from", "system-property", "name", "oidf.example.old"), Map.of("from", "env", "name", "OIDF_EXAMPLE_FAIL_CLOSED")))))));
        assertEquals(WHERE + ": settings[4] (OIDF_EXAMPLE_TOKEN).sources[0]: env OIDF_EXAMPLE_TOKEN is declared twice in this catalogue",
                refusal(d -> settings(d).set(1, entry(d, 4))));
        assertEquals(WHERE + ": removed[0]: env OIDF_EXAMPLE_MODE is declared twice in this catalogue",
                refusal(d -> d.put("removed", List.of(Map.of("name", "OIDF_EXAMPLE_MODE", "from", "env", "replacement", "OIDF_X", "release", "0.4.0")))));
    }

    @Test
    void theFileVariantsNameIsClaimedToo() {
        assertEquals(WHERE + ": settings[4] (OIDF_EXAMPLE_TOKEN) (the file variant): env OIDF_EXAMPLE_TOKEN_FILE is declared twice in this"
                + " catalogue", entryRefusal(3, e -> {
                    e.put("name", "OIDF_EXAMPLE_TOKEN_FILE");
                    e.put("sources", List.of(Map.of("from", "env", "name", "OIDF_EXAMPLE_TOKEN_FILE")));
                }));
    }

    @Test
    void onlyASecretIsReadFromAFileAndASecretBearsOnSecurityAndHasNoDefault() {
        assertEquals(WHERE + ": settings[3] (OIDF_EXAMPLE_URL): only a secret is read from a file", entryRefusal(3, e -> e.put("file", true)));
        assertEquals(WHERE + ": settings[4] (OIDF_EXAMPLE_TOKEN): a secret bears on security", entryRefusal(4, e -> e.put("security", false)));
        assertEquals(WHERE + ": settings[4] (OIDF_EXAMPLE_TOKEN): a secret has no default", entryRefusal(4, e -> e.put("default", "x")));
    }

    @Test
    void aSwitchHasADefaultThatParses() {
        assertEquals(WHERE + ": settings[0] (OIDF_EXAMPLE_FAIL_CLOSED): a switch has a default", entryRefusal(0, e -> e.put("default", null)));
        assertEquals(WHERE + ": settings[0] (OIDF_EXAMPLE_FAIL_CLOSED): the default is refused: OIDF_EXAMPLE_FAIL_CLOSED must be true or false,"
                + " not yes", entryRefusal(0, e -> e.put("default", "yes")));
        assertEquals(WHERE + ": settings[0] (OIDF_EXAMPLE_FAIL_CLOSED): default must be text, a number, true, false or null, not a list",
                entryRefusal(0, e -> e.put("default", List.of())));
        Map<String, Object> document = document();
        entry(document, 0).put("default", "false");
        assertEquals("false", Catalogue.parse(Json.write(document), WHERE).setting("OIDF_EXAMPLE_FAIL_CLOSED").defaultValue());
    }

    @Test
    void anEntryIsCataloguedOnce() {
        assertEquals(WHERE + ": settings[8]: Request timeout (ms) is catalogued twice", refusal(d -> settings(d).add(Json.copy(settings(d).get(6)))));
    }

    // ---- removed names --------------------------------------------------------------------------------------

    @Test
    void aRemovedNameIsCompleteAndNamesARelease() {
        assertEquals(WHERE + ": the document: removed must be a list, not an object", refusal(d -> d.put("removed", Map.of())));
        assertEquals(WHERE + ": removed[0]: no member 'replacement'",
                refusal(d -> d.put("removed", List.of(Map.of("name", "OIDF_EXAMPLE_GONE", "from", "env", "release", "0.4.0")))));
        assertEquals(WHERE + ": removed[0]: from must be env, system-property or init-param, not 'plugin-field'",
                refusal(d -> d.put("removed", List.of(Map.of("name", "OIDF_EXAMPLE_GONE", "from", "plugin-field", "replacement", "X", "release", "0.4.0")))));
        assertEquals(WHERE + ": removed[0]: from must be env, system-property or init-param, not a number",
                refusal(d -> d.put("removed", List.of(Map.of("name", "OIDF_EXAMPLE_GONE", "from", BigDecimal.ONE, "replacement", "X", "release", "0.4.0")))));
        assertEquals(WHERE + ": removed[0]: replacement must be the name to set instead, or null, not ' '",
                refusal(d -> d.put("removed", List.of(Map.of("name", "OIDF_EXAMPLE_GONE", "from", "env", "replacement", " ", "release", "0.4.0")))));
        assertEquals(WHERE + ": removed[0]: replacement must be the name to set instead, or null, not true",
                refusal(d -> d.put("removed", List.of(Map.of("name", "OIDF_EXAMPLE_GONE", "from", "env", "replacement", true, "release", "0.4.0")))));
        assertEquals(WHERE + ": removed[0]: release must be a release such as 0.4.0, not 'v0.4.0'",
                refusal(d -> d.put("removed", List.of(Map.of("name", "OIDF_EXAMPLE_GONE", "from", "env", "replacement", "X", "release", "v0.4.0")))));
        List<Object> removed = new ArrayList<>();
        removed.add(Map.of("name", "oidf.example.gone", "from", "system-property", "replacement", "X", "release", "10.0.12"));
        Map<String, Object> document = document();
        document.put("removed", removed);
        Catalogue parsed = Catalogue.parse(Json.write(document), WHERE);
        assertEquals(new Removed("oidf.example.gone", Source.SYSTEM_PROPERTY, "X", "10.0.12"), parsed.removed().get(0));
        assertTrue(parsed.declaredEnvironmentNames().stream().allMatch(name -> name.startsWith("OIDF_EXAMPLE_")),
                "a removed system property is not an environment variable");
    }

    @Test
    void eachKindSaysWhereItIsNamedAndWhetherItIsResolved() {
        assertEquals(Source.ENV, EntryKind.ENV.namingSource());
        assertEquals(Source.SYSTEM_PROPERTY, EntryKind.SYSTEM_PROPERTY.namingSource());
        assertEquals(Source.INIT_PARAM, EntryKind.INIT_PARAM.namingSource());
        for (EntryKind supplied : new EntryKind[] {EntryKind.PLUGIN_FIELD, EntryKind.EXTENDED_PROPERTY}) {
            assertEquals(null, supplied.namingSource());
            assertEquals(false, supplied.resolved());
        }
    }
}
