package com.pingidentity.ps.oidf.pf;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.federation.event.FederationEvents;
import com.pingidentity.ps.oidf.platform.events.Event;
import com.pingidentity.ps.oidf.platform.events.EventCatalogue;
import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * Every event the reactor's main code emits is catalogued, with every field it carries, and every catalogued code is
 * emitted or marked {@code declaredOnly} (plan item O-1). The catalogues are read from source, every
 * {@code src/main/resources/META-INF/oidf-events/*.json} in the reactor, and the emitters are every
 * {@code FederationEvents.event(...)} call in main code up to its {@code .emit()}: its code (a FederationEvents
 * constant, a string literal, or a constant of the same file), the fields it adds, whether it marks the event audit and
 * whether a failure. A call whose code is a variable (a helper that emits for its callers) is checked against every
 * FederationEvents code its file names outside such calls.
 *
 * <p>Code that emits through {@code platform.events} directly is not scanned yet: nothing does today, and the test
 * fails when something starts to, so that the package that adds it (O-2) extends the scan.
 */
@SuppressWarnings("removal")
class EventsCataloguedTest {
    private static final Path ROOT = Path.of("../..");
    private static final List<String> TREES = List.of("libs", "servlets", "plugins", "services");
    private static final Pattern EVENT = Pattern.compile("FederationEvents\\.event\\(([^)]*)\\)");
    private static final Pattern CONSTANT = Pattern.compile("FederationEvents\\.([A-Z_]+)\\b");
    private static final Pattern FIELD = Pattern.compile("\\.field\\(\\s*\"([^\"]+)\"");
    private static final Pattern LITERAL = Pattern.compile("\"([^\"]+)\"");
    private static final Pattern PLATFORM_EMIT = Pattern.compile("\\b(Events\\.event|Event\\.builder)\\(");

    /** One emit site: where, the codes it can emit, the fields it adds, and whether it marks audit and failure. */
    private record Site(String where, Set<String> codes, List<String> fields, boolean audit, boolean failure) {
    }

    private static Map<String, EventCatalogue.Code> catalogued;
    private static List<Site> sites;
    private static final List<String> PLATFORM_EMITTERS = new ArrayList<>();

    @BeforeAll
    static void scan() throws IOException, IllegalAccessException {
        Map<String, String> constants = new LinkedHashMap<>();
        for (Field field : FederationEvents.class.getFields()) {
            if (Modifier.isStatic(field.getModifiers()) && field.getType() == String.class) {
                constants.put(field.getName(), (String) field.get(null));
            }
        }
        catalogued = new LinkedHashMap<>();
        sites = new ArrayList<>();
        for (String tree : TREES) {
            try (Stream<Path> files = Files.walk(ROOT.resolve(tree))) {
                for (Path file : files.filter(Files::isRegularFile).toList()) {
                    String path = ROOT.relativize(file).toString().replace('\\', '/');
                    if (path.contains("/target/")) {
                        continue;
                    }
                    if (path.contains("/src/main/resources/META-INF/oidf-events/") && path.endsWith(".json")) {
                        catalogue(file, path);
                    } else if (path.contains("/src/main/java/") && path.endsWith(".java")) {
                        emitters(file, path, constants);
                    }
                }
            }
        }
    }

    private static void catalogue(Path file, String path) throws IOException {
        EventCatalogue catalogue = EventCatalogue.parse(Files.readString(file));
        String name = file.getFileName().toString().replace(".json", "");
        assertEquals(name, catalogue.component(), path + " names another component");
        String index = Files.readString(file.resolveSibling("index.txt"));
        assertTrue(index.lines().map(String::strip).anyMatch(name::equals), path + " is not in its index.txt");
        for (EventCatalogue.Code code : catalogue.codes().values()) {
            assertTrue(catalogued.put(code.code(), code) == null, code.code() + " is catalogued twice");
        }
    }

    private static void emitters(Path file, String path, Map<String, String> constants) throws IOException {
        String source = Files.readString(file);
        if (!path.startsWith("libs/platform/") && !path.contains("/federation/event/") && PLATFORM_EMIT.matcher(source).find()) {
            PLATFORM_EMITTERS.add(path);
        }
        if (!source.contains("FederationEvents.event(") || path.contains("/federation/event/")) {
            return;
        }
        Set<String> named = new TreeSet<>();
        Matcher reference = CONSTANT.matcher(source);
        while (reference.find()) {
            String before = source.substring(Math.max(0, reference.start() - "FederationEvents.event(".length()), reference.start());
            if (!before.endsWith("FederationEvents.event(") && constants.containsKey(reference.group(1))) {
                named.add(constants.get(reference.group(1)));
            }
        }
        Matcher call = EVENT.matcher(source);
        while (call.find()) {
            String argument = call.group(1).strip();
            int end = source.indexOf(".emit()", call.end());
            assertTrue(end > 0, path + ": an event call with no .emit() after it");
            String chain = source.substring(call.start(), end);
            Set<String> codes = new LinkedHashSet<>();
            Matcher literal = LITERAL.matcher(argument);
            Matcher local = Pattern.compile("static final String " + Pattern.quote(argument) + "\\s*=\\s*\"([^\"]+)\"")
                    .matcher(source);
            if (argument.startsWith("FederationEvents.")) {
                codes.add(constants.get(argument.substring("FederationEvents.".length())));
            } else if (literal.matches()) {
                codes.add(literal.group(1));
            } else if (local.find()) {
                codes.add(local.group(1));
            } else {
                codes.addAll(named);
            }
            List<String> fields = new ArrayList<>();
            Matcher field = FIELD.matcher(chain);
            while (field.find()) {
                fields.add(field.group(1));
            }
            String where = path + ":" + (source.substring(0, call.start()).split("\n", -1).length);
            assertTrue(!codes.isEmpty() && !codes.contains(null), where + ": could not tell which code this emits");
            sites.add(new Site(where, codes, fields, chain.contains(".audit()"), chain.contains(".failure(")));
        }
    }

    @Test
    void theScanFoundTheEmittersAndTheCatalogues() {
        assertTrue(sites.size() > 30, "the scan found the emit sites, not an empty tree: " + sites.size());
        assertTrue(catalogued.containsKey(FederationEvents.CHAIN_VALIDATED));
        assertTrue(catalogued.containsKey("attestation.evidence.conflict"));
    }

    @Test
    void everyEmittedCodeIsCatalogued() {
        List<String> missing = new ArrayList<>();
        for (Site site : sites) {
            for (String code : site.codes()) {
                if (!catalogued.containsKey(code)) {
                    missing.add(site.where() + " " + code);
                }
            }
        }
        assertEquals(List.of(), missing, "add these codes to their module's META-INF/oidf-events catalogue");
    }

    @Test
    void everyCataloguedCodeIsEmittedOrMarkedDeclaredOnly() {
        Set<String> emitted = new TreeSet<>();
        sites.forEach(site -> emitted.addAll(site.codes()));
        List<String> wrong = new ArrayList<>();
        for (EventCatalogue.Code code : catalogued.values()) {
            if (code.declaredOnly() == emitted.contains(code.code())) {
                wrong.add(code.code() + (code.declaredOnly() ? " is emitted but marked declaredOnly" : " is never emitted"));
            }
        }
        assertEquals(List.of(), wrong);
        assertTrue(catalogued.get(FederationEvents.ATTESTATION_VERIFIED).declaredOnly());
        assertTrue(catalogued.get(FederationEvents.ATTESTATION_REFUSED).declaredOnly());
    }

    @Test
    void everyFieldAnEmitterAddsIsDeclaredForItsCode() {
        List<String> undeclared = new ArrayList<>();
        for (Site site : sites) {
            for (String code : site.codes()) {
                EventCatalogue.Code declared = catalogued.get(code);
                for (String field : site.fields()) {
                    if (declared != null && !declared.declares(field)) {
                        undeclared.add(site.where() + " " + code + " " + field);
                    }
                }
            }
        }
        assertEquals(List.of(), undeclared, "a field its catalogue does not declare is dropped at run time");
    }

    @Test
    void theCataloguesAuditFlagAndOutcomesCoverEveryEmitter() {
        List<String> wrong = new ArrayList<>();
        for (Site site : sites) {
            for (String code : site.codes()) {
                EventCatalogue.Code declared = catalogued.get(code);
                if (declared == null) {
                    continue;
                }
                if (site.audit() && !declared.audit()) {
                    wrong.add(site.where() + " " + code + " is audited but catalogued audit: false");
                }
                Event.Outcome outcome = site.failure() ? Event.Outcome.FAILURE : Event.Outcome.SUCCESS;
                if (!declared.outcomes().contains(outcome)) {
                    wrong.add(site.where() + " " + code + " can be a " + outcome.code() + ", which its catalogue omits");
                }
            }
        }
        assertEquals(List.of(), wrong);
    }

    @Test
    void nothingEmitsThroughPlatformEventsDirectlyYet() {
        assertEquals(List.of(), PLATFORM_EMITTERS,
                "these emit through platform.events directly: extend this scan to them (plan item O-2)");
    }
}
