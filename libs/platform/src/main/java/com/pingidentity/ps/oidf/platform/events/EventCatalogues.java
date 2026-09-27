/*
 * Every event catalogue a loader can see, and the rule that nothing uncatalogued reaches a log.
 */
package com.pingidentity.ps.oidf.platform.events;

import com.pingidentity.ps.oidf.platform.log.PlatformLog;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.net.URLConnection;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicLong;

/**
 * The catalogues of one loader, looked up by component and by code, and the admission rule every logging sink
 * applies: a field the event's code does not declare is dropped and counted, never logged.
 *
 * <p>A module lists its components in {@link EventCatalogue#INDEX}, one name per line ({@code #} starts a
 * comment), beside one {@code <component>.json} per name; {@link #load} reads every index the loader can see and
 * each catalogue from the same jar as its index. In PingFederate the modules sit in the war and on the engine's
 * classpath alike, so a loader can see one module twice: the same document twice is read once, and a second,
 * different document for a component, or a code declared by two components, is set aside and reported, the first
 * kept. A catalogue that cannot be read or does not validate is reported and left out: its codes are then
 * uncatalogued, so their events keep their code, outcome and parties and lose their fields. Every problem is
 * logged once, at ERROR, when the catalogues are loaded, and kept in {@link #problems()}.
 *
 * <p>{@link #current()} is the catalogues of the loader this copy of platform was loaded by, read on first use.
 */
public final class EventCatalogues {
    /** The most (code, field) pairs whose drop is logged; later drops are only counted. */
    static final int MAX_WARNED = 256;

    private static final PlatformLog LOG = PlatformLog.get(EventCatalogues.class);
    private static final Object LOCK = new Object();
    private static volatile EventCatalogues current;

    private final Map<String, EventCatalogue> components;
    private final Map<String, EventCatalogue.Code> codes;
    private final List<String> problems;
    private final AtomicLong droppedFields = new AtomicLong();
    private final AtomicLong uncataloguedEvents = new AtomicLong();
    private final Set<String> warned = Collections.synchronizedSet(new LinkedHashSet<>());

    EventCatalogues(Map<String, EventCatalogue> components, Map<String, EventCatalogue.Code> codes,
                            List<String> problems) {
        this.components = Collections.unmodifiableMap(components);
        this.codes = Collections.unmodifiableMap(codes);
        this.problems = List.copyOf(problems);
    }

    /** The catalogues of the loader this copy of platform was loaded by. */
    public static EventCatalogues current() {
        EventCatalogues local = current;
        return local != null ? local : loadOnce();
    }

    private static EventCatalogues loadOnce() {
        synchronized (LOCK) {
            if (current == null) {
                current = load(EventCatalogues.class.getClassLoader());
            }
            return current;
        }
    }

    /** Tests only: use {@code catalogues} as this loader's until {@link #forget()}. */
    public static void install(EventCatalogues catalogues) {
        synchronized (LOCK) {
            current = catalogues;
        }
    }

    /** Tests only: read the loader's catalogues again on next use. */
    public static void forget() {
        synchronized (LOCK) {
            current = null;
        }
    }

    /** A set of catalogues, with the same duplicate rules {@link #load} applies. */
    public static EventCatalogues of(List<EventCatalogue> catalogues) {
        CatalogueCollector builder = new CatalogueCollector();
        for (EventCatalogue catalogue : catalogues) {
            builder.add(catalogue, null, "a catalogue passed in");
        }
        return builder.build();
    }

    /** Every catalogue {@code loader} can see, read through the indexes; every problem logged once, at ERROR. */
    public static EventCatalogues load(ClassLoader loader) {
        CatalogueCollector collector = new CatalogueCollector();
        try {
            Enumeration<URL> indexes = loader.getResources(EventCatalogue.INDEX);
            while (indexes.hasMoreElements()) {
                readIndex(collector, indexes.nextElement());
            }
        } catch (IOException e) {
            collector.problem("the event catalogue indexes could not be listed: " + e.getMessage());
        }
        EventCatalogues loaded = collector.build();
        for (String problem : loaded.problems()) {
            LOG.error("Event catalogue: " + LogSafe.value(problem), null);
        }
        return loaded;
    }

    /** Reads every component {@code index} lists; {@code #} starts a comment line. */
    static void readIndex(CatalogueCollector collector, URL index) {
        String text;
        try {
            text = read(index);
        } catch (IOException e) {
            collector.problem(index + " could not be read: " + e.getMessage());
            return;
        }
        for (String line : text.split("\n")) {
            String name = line.strip();
            if (!name.isEmpty() && !name.startsWith("#")) {
                collector.read(index, name);
            }
        }
    }

    /**
     * The text at {@code url}, read without the JDK's jar cache, so that reading a catalogue out of a webapp's
     * jar does not hold the jar open after an undeploy.
     */
    static String read(URL url) throws IOException {
        URLConnection connection = url.openConnection();
        connection.setUseCaches(false);
        try (InputStream in = connection.getInputStream()) {
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    /** Every catalogue, by component. */
    public Map<String, EventCatalogue> components() {
        return this.components;
    }

    public Optional<EventCatalogue> component(String name) {
        return Optional.ofNullable(this.components.get(name));
    }

    public Optional<EventCatalogue.Code> code(String code) {
        return Optional.ofNullable(this.codes.get(code));
    }

    /** The component whose catalogue declares {@code code}. */
    public Optional<String> componentOf(String code) {
        return this.code(code).map(EventCatalogue.Code::component);
    }

    /** What went wrong while loading, one line each; empty when nothing did. */
    public List<String> problems() {
        return this.problems;
    }

    /** How many fields {@link #admit} has dropped because their event's code does not declare them. */
    public long droppedFields() {
        return this.droppedFields.get();
    }

    /** How many events {@link #admit} has seen whose code no catalogue declares. */
    public long uncataloguedEvents() {
        return this.uncataloguedEvents.get();
    }

    /**
     * The event as its catalogue allows it: its component set to the catalogue's that declares its code, and every
     * field that code does not declare dropped and counted. The first drop of each (code, field) pair is logged at
     * WARN with the field's name, never its value. An event whose code no catalogue declares keeps its code,
     * outcome, parties and description, loses every field, and is counted. {@link Events#emit} admits each event
     * once, so each event is counted once; a sink behind it uses {@link #readmit}.
     */
    public Event admit(Event event) {
        return this.admit(event, true);
    }

    /**
     * The same rule as {@link #admit}, not counted: what a sink applies to the event {@link Events#emit} has
     * already admitted and counted, so that one event counts once however many sinks see it. Readmitting an
     * admitted event changes nothing. A drop is still logged the first time its (code, field) pair is seen.
     */
    public Event readmit(Event event) {
        return this.admit(event, false);
    }

    private Event admit(Event event, boolean count) {
        EventCatalogue.Code declared = this.codes.get(event.code());
        if (declared == null) {
            if (count) {
                this.uncataloguedEvents.incrementAndGet();
            }
            this.warnOnce(event.code(), null);
        }
        Map<String, String> kept = new LinkedHashMap<>();
        for (Map.Entry<String, String> field : event.fields().entrySet()) {
            if (declared != null && declared.declares(field.getKey())) {
                kept.put(field.getKey(), field.getValue());
            } else {
                if (count) {
                    this.droppedFields.incrementAndGet();
                }
                if (declared != null) {
                    this.warnOnce(event.code(), field.getKey());
                }
            }
        }
        String component = declared == null ? event.component() : declared.component();
        if (kept.size() == event.fields().size() && component.equals(event.component())) {
            return event;
        }
        return new Event(event.code(), event.outcome(), event.reason(), event.subject(), event.partner(), event.role(),
                event.description(), kept, event.requestJti(), event.audit(), event.category(), component);
    }

    private void warnOnce(String code, String field) {
        String key = field == null ? code : code + " " + field;
        if (this.warned.size() >= MAX_WARNED || !this.warned.add(key)) {
            return;
        }
        if (field == null) {
            LOG.warn("Event " + LogSafe.quoted(code) + " is in no event catalogue; its fields are dropped");
        } else {
            LOG.warn("Event " + LogSafe.quoted(code) + " carried the field " + LogSafe.quoted(field)
                    + ", which its catalogue does not declare; it was dropped");
        }
    }
}
