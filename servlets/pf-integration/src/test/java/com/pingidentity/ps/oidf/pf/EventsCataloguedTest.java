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
 * <p>Platform's own {@code Events.event(component, code)} calls are scanned the same way (plan item S8a; Phase 3
 * decision 7, so later packages can emit through platform directly): the component and the code are each a string
 * literal or a {@code static final String} constant of the same file, and the code must be catalogued under that
 * component. A call whose component or code is anything else - a variable, a method call, another class's constant -
 * fails the scan, because it cannot be checked, and so do a qualified call and a static import of {@code event}.
 *
 * <p>Code that emits any other way - platform's {@code Events.emit}, {@code Event.builder} or constructor, or the
 * façade's {@code FederationEvent.builder}, constructor or {@code FederationEvents.emit} - is not scanned: nothing
 * does today, and the test fails when something starts to, so that the package that adds it extends the scan.
 */
@SuppressWarnings("removal")
class EventsCataloguedTest {
    private static final Path ROOT = Path.of("../..");
    private static final List<String> TREES = List.of("libs", "servlets", "plugins", "services");
    private static final Pattern EVENT = Pattern.compile("FederationEvents\\.event\\(([^)]*)\\)");
    private static final Pattern CONSTANT = Pattern.compile("FederationEvents\\.([A-Z_]+)\\b");
    private static final Pattern FIELD = Pattern.compile("\\.field\\(\\s*\"([^\"]+)\"");
    private static final Pattern LITERAL = Pattern.compile("\"([^\"]+)\"");
    /** Platform's {@code Events.event(component, code)}, not the façade's {@code FederationEvents.event(code)}. */
    private static final Pattern PLATFORM_EVENT = Pattern.compile(
            "(?<![A-Za-z0-9_.])Events\\.event\\(\\s*([^,()]+?)\\s*,\\s*([^,()]+?)\\s*\\)");
    /**
     * Any call of platform's {@code Events.event}, qualified or not: each must be one {@link #PLATFORM_EVENT} resolves,
     * so a call with a computed or qualified argument fails the scan rather than going unchecked.
     */
    private static final Pattern ANY_PLATFORM_EVENT = Pattern.compile("(?<![A-Za-z0-9_])Events\\.event\\(");
    /** A static import of platform's {@code event}, whose bare {@code event(a, b)} calls the scan cannot find. */
    private static final Pattern STATIC_EVENT_IMPORT = Pattern.compile(
            "import\\s+static\\s+[A-Za-z0-9_.]*\\bEvents\\.(event|\\*)\\s*;");
    /**
     * Every other way to build or hand over an event: platform's builder and registry, and the façade's builder,
     * constructor and {@code emit}. A main-code file outside the event packages that uses one is not understood by
     * the scan, so it fails the test until the scan is extended.
     */
    private static final Pattern PLATFORM_EMIT = Pattern.compile(
            "\\b(Events\\.emit|Event\\.builder|new Event|FederationEvent\\.builder|new FederationEvent"
                    + "|FederationEvents\\.emit)\\(");

    /** One emit site: where, the codes it can emit, the fields it adds, and whether it marks audit and failure. */
    private record Site(String where, Set<String> codes, List<String> fields, boolean audit, boolean failure) {
    }

    private static Map<String, EventCatalogue.Code> catalogued;
    /** Each catalogued code's component. */
    private static final Map<String, String> COMPONENT_OF = new LinkedHashMap<>();
    /** The platform {@code Events.event(component, code)} sites, as "where component code". */
    private static final List<String> PLATFORM_SITES = new ArrayList<>();
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
            COMPONENT_OF.put(code.code(), catalogue.component());
        }
    }

    private static void emitters(Path file, String path, Map<String, String> constants) throws IOException {
        String source = Files.readString(file);
        if (!path.startsWith("libs/platform/") && !path.contains("/federation/event/") && PLATFORM_EMIT.matcher(source).find()) {
            PLATFORM_EMITTERS.add(path);
        }
        if (!path.contains("/platform/events/")) {
            platformEmitters(source, path);
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

    /**
     * Each platform {@code Events.event(component, code)} call: its component and code resolved from a literal or a
     * constant of the same file, recorded as a {@link Site} like a façade call.
     */
    private static void platformEmitters(String source, String path) {
        assertTrue(!STATIC_EVENT_IMPORT.matcher(source).find(), path + ": a static import of Events.event - call it"
                + " as Events.event(component, code) so this scan can check it");
        assertEquals(count(ANY_PLATFORM_EVENT, source), count(PLATFORM_EVENT, source), path + ": an Events.event call"
                + " this scan cannot read - the call must be unqualified and its component and code each a string"
                + " literal or a static final String constant of the same file");
        Matcher call = PLATFORM_EVENT.matcher(source);
        while (call.find()) {
            String where = path + ":" + (source.substring(0, call.start()).split("\n", -1).length);
            String component = resolve(call.group(1), source);
            String code = resolve(call.group(2), source);
            assertTrue(component != null && code != null, where + ": Events.event(" + call.group(1) + ", "
                    + call.group(2) + ") - the component and the code must each be a string literal or a static final"
                    + " String constant of the same file, so this scan can check them");
            int end = source.indexOf(".emit()", call.end());
            assertTrue(end > 0, where + ": an event call with no .emit() after it");
            String chain = source.substring(call.start(), end);
            List<String> fields = new ArrayList<>();
            Matcher field = FIELD.matcher(chain);
            while (field.find()) {
                fields.add(field.group(1));
            }
            PLATFORM_SITES.add(where + " " + component + " " + code);
            sites.add(new Site(where, Set.of(code), fields, chain.contains(".audit()"), chain.contains(".failure(")));
        }
    }

    private static long count(Pattern pattern, String source) {
        return pattern.matcher(source).results().count();
    }

    /** A string literal, or a {@code static final String} constant of {@code source}; null for anything else. */
    private static String resolve(String argument, String source) {
        Matcher literal = LITERAL.matcher(argument);
        if (literal.matches()) {
            return literal.group(1);
        }
        if (!argument.matches("[A-Za-z_][A-Za-z0-9_]*")) {
            return null;
        }
        Matcher constant = Pattern.compile("static final String " + Pattern.quote(argument) + "\\s*=\\s*\"([^\"]+)\"")
                .matcher(source);
        return constant.find() ? constant.group(1) : null;
    }

    @Test
    void theScanFoundTheEmittersAndTheCatalogues() {
        assertTrue(sites.size() > 30, "the scan found the emit sites, not an empty tree: " + sites.size());
        assertTrue(catalogued.containsKey(FederationEvents.CHAIN_VALIDATED));
        assertTrue(catalogued.containsKey("attestation.evidence.conflict"));
        assertTrue(catalogued.containsKey("admin.request.authorised"), "platform-pf's operator catalogue");
        assertTrue(PLATFORM_SITES.stream().anyMatch(s -> s.endsWith(" operator admin.request.refused")), PLATFORM_SITES
                .toString());
    }

    /** A platform call names its component, and its code is catalogued under that component, not another. */
    @Test
    void everyPlatformEmitSitesCodeIsCataloguedUnderItsComponent() {
        List<String> wrong = new ArrayList<>();
        for (String site : PLATFORM_SITES) {
            String[] parts = site.split(" ");
            String component = parts[parts.length - 2];
            String code = parts[parts.length - 1];
            if (catalogued.containsKey(code) && !component.equals(COMPONENT_OF.get(code))) {
                wrong.add(site + " is catalogued under " + COMPONENT_OF.get(code));
            }
        }
        assertEquals(List.of(), wrong);
    }

    @Test
    void theScanResolvesLiteralsAndConstantsOnly() {
        String source = "static final String CODE = \"a.b\";";
        assertEquals("a.b", resolve("CODE", source));
        assertEquals("x.y", resolve("\"x.y\"", source));
        assertEquals(null, resolve("OTHER", source));
        assertEquals(null, resolve("Other.CODE", source));
        assertTrue(PLATFORM_EVENT.matcher("Events.event(COMPONENT, CODE)").find());
        assertTrue(!PLATFORM_EVENT.matcher("FederationEvents.event(CODE)").find());
        assertTrue(!PLATFORM_EVENT.matcher("platform.Events.event(A, B)").find(), "a qualified call is not understood");
        String computed = "Events.event(COMPONENT, codeFor(x)).emit();";
        assertEquals(1, count(ANY_PLATFORM_EVENT, computed));
        assertEquals(0, count(PLATFORM_EVENT, computed), "a method-call argument is not resolved, so the counts differ");
        String qualified = "com.pingidentity.ps.oidf.platform.events.Events.event(\"a\", \"b\").emit();";
        assertEquals(1, count(ANY_PLATFORM_EVENT, qualified));
        assertEquals(0, count(PLATFORM_EVENT, qualified), "a qualified call is not resolved, so the counts differ");
        assertEquals(0, count(ANY_PLATFORM_EVENT, "FederationEvents.event(CODE)"));
        assertTrue(STATIC_EVENT_IMPORT.matcher("import static com.pingidentity.ps.oidf.platform.events.Events.event;")
                .find());
        assertTrue(STATIC_EVENT_IMPORT.matcher("import static com.pingidentity.ps.oidf.platform.events.Events.*;")
                .find());
        assertTrue(!STATIC_EVENT_IMPORT.matcher("import com.pingidentity.ps.oidf.platform.events.Events;").find());
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
    void theCataloguesAuditFlagMatchesEveryEmitterAndItsOutcomesCoverThem() {
        List<String> wrong = new ArrayList<>();
        for (Site site : sites) {
            for (String code : site.codes()) {
                EventCatalogue.Code declared = catalogued.get(code);
                if (declared == null) {
                    continue;
                }
                if (site.audit() != declared.audit()) {
                    wrong.add(site.where() + " " + code + (site.audit() ? " is audited but catalogued audit: false"
                            : " is not audited but catalogued audit: true"));
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
    void nothingEmitsOtherThanThroughTheCallsThisScanUnderstands() {
        assertEquals(List.of(), PLATFORM_EMITTERS, "these emit other than through FederationEvents.event(...) or"
                + " Events.event(component, code): extend this scan to them");
    }
}
