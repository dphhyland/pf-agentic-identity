/*
 * One component's event catalogue: its codes and the fields they carry.
 */
package com.pingidentity.ps.oidf.platform.events;

import com.pingidentity.ps.oidf.platform.json.Json;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * The events one component declares, read from {@code META-INF/oidf-events/<component>.json} in the module that
 * declares the codes (plan item O-1; data, not code, as the settings catalogues are - Phase 2 plan, decision 1).
 *
 * <p>A document names its {@code component}, the {@code module} it lives in, a {@code description}, the
 * {@code logger} its events are written under in server.log (the event's category is appended) and the
 * {@code auditProtocol} PingFederate's audit log records for them. {@code fields} gives every field any of its
 * events may carry one {@link PiiClass} and a description, and {@code events} gives every code a description,
 * whether it belongs in the audit log, the outcomes it can have, the level server.log writes it at, the fields
 * it may carry, and whether it is declared but not yet emitted ({@code declaredOnly}).
 *
 * <p>{@link #parse} is strict: an unknown member, a missing one, a value of the wrong type, a code or field name
 * outside the naming rules, an event field the document does not classify, or a classified field no event
 * carries is refused with {@link IllegalArgumentException} naming what is wrong. A catalogue is written by hand
 * and read at start-up, so a mistake in one is a bug for its module's tests to find.
 */
public final class EventCatalogue {
    /** Where a module keeps its catalogues. */
    public static final String DIRECTORY = "META-INF/oidf-events/";

    /** The file in {@link #DIRECTORY} listing a module's components, one per line. */
    public static final String INDEX = DIRECTORY + "index.txt";

    static final Pattern COMPONENT = Pattern.compile("[a-z][a-z0-9-]{0,63}");
    static final Pattern CODE = Pattern.compile("[a-z][a-z0-9_]*(\\.[a-z][a-z0-9_]*){1,5}");
    static final Pattern FIELD = Pattern.compile("[a-z][a-z0-9_]{0,63}");
    static final Pattern LOGGER = Pattern.compile("[A-Za-z_][A-Za-z0-9_]*(\\.[A-Za-z_][A-Za-z0-9_]*)*");

    private static final Set<String> TOP = Set.of("component", "module", "description", "logger", "auditProtocol",
            "fields", "events");
    private static final Set<String> FIELD_MEMBERS = Set.of("pii", "description");
    private static final Set<String> EVENT_MEMBERS = Set.of("description", "audit", "outcomes", "level", "fields",
            "declaredOnly");

    /** The level server.log writes an event at, before a security refusal raises it to WARN. */
    public enum Level { DEBUG, INFO }

    /** One field: its class and what it holds. */
    public record Field(String name, PiiClass pii, String description) {
    }

    /** One code: what it records and what it may carry. */
    public record Code(String code, String component, String description, boolean audit, Set<Event.Outcome> outcomes,
                       Level level, List<String> fields, boolean declaredOnly) {
        /** Whether this code may carry {@code field}. */
        public boolean declares(String field) {
            return this.fields.contains(field);
        }
    }

    private final String component;
    private final String module;
    private final String description;
    private final String logger;
    private final String auditProtocol;
    private final Map<String, Field> fields;
    private final Map<String, Code> codes;

    private EventCatalogue(String component, String module, String description, String logger, String auditProtocol,
                           Map<String, Field> fields, Map<String, Code> codes) {
        this.component = component;
        this.module = module;
        this.description = description;
        this.logger = logger;
        this.auditProtocol = auditProtocol;
        this.fields = Collections.unmodifiableMap(fields);
        this.codes = Collections.unmodifiableMap(codes);
    }

    public String component() {
        return this.component;
    }

    public String module() {
        return this.module;
    }

    public String description() {
        return this.description;
    }

    /** The logger prefix: an event is written on {@code <logger>.<category>}. */
    public String logger() {
        return this.logger;
    }

    /** What PingFederate's audit log records in its {@code protocol} column for this component's events. */
    public String auditProtocol() {
        return this.auditProtocol;
    }

    /** Every classified field, by name, in document order. */
    public Map<String, Field> fields() {
        return this.fields;
    }

    /** Every code, in document order. */
    public Map<String, Code> codes() {
        return this.codes;
    }

    public Optional<Code> code(String code) {
        return Optional.ofNullable(this.codes.get(code));
    }

    /** The class of {@code field}, when this catalogue classifies it. */
    public Optional<PiiClass> classOf(String field) {
        Field found = this.fields.get(field);
        return found == null ? Optional.empty() : Optional.of(found.pii());
    }

    /** Reads and validates one catalogue document. */
    public static EventCatalogue parse(String json) {
        Object root;
        try {
            root = Json.parse(json);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("the event catalogue is not valid JSON: " + e.getMessage(), e);
        }
        Map<String, Object> top = object(root, "the event catalogue");
        members(top, TOP, "the event catalogue");
        String component = matching(top, "component", COMPONENT, "the event catalogue");
        String where = "event catalogue " + component;
        String module = text(top, "module", where);
        String description = text(top, "description", where);
        String logger = matching(top, "logger", LOGGER, where);
        String auditProtocol = text(top, "auditProtocol", where);

        Map<String, Field> fields = new LinkedHashMap<>();
        for (Map.Entry<String, Object> entry : object(top.get("fields"), where + ": fields").entrySet()) {
            String name = name(entry.getKey(), FIELD, where + ": field");
            String at = where + ": field " + name;
            Map<String, Object> field = object(entry.getValue(), at);
            members(field, FIELD_MEMBERS, at);
            fields.put(name, new Field(name, pii(text(field, "pii", at), at), text(field, "description", at)));
        }

        Map<String, Code> codes = new LinkedHashMap<>();
        Set<String> carried = new LinkedHashSet<>();
        for (Map.Entry<String, Object> entry : object(top.get("events"), where + ": events").entrySet()) {
            String code = name(entry.getKey(), CODE, where + ": event");
            String at = where + ": event " + code;
            Map<String, Object> event = object(entry.getValue(), at);
            members(event, EVENT_MEMBERS, at);
            List<String> eventFields = new ArrayList<>();
            for (Object item : list(event.get("fields"), at + ": fields")) {
                if (!(item instanceof String name) || !fields.containsKey(name)) {
                    throw new IllegalArgumentException(at + " carries " + describe(item)
                            + ", which the catalogue's fields do not classify");
                }
                if (eventFields.contains(name)) {
                    throw new IllegalArgumentException(at + " lists the field " + name + " twice");
                }
                eventFields.add(name);
            }
            carried.addAll(eventFields);
            codes.put(code, new Code(code, component, text(event, "description", at), bool(event, "audit", at),
                    outcomes(event.get("outcomes"), at), level(text(event, "level", at), at),
                    List.copyOf(eventFields), bool(event, "declaredOnly", at)));
        }
        if (codes.isEmpty()) {
            throw new IllegalArgumentException(where + " declares no events");
        }
        for (String name : fields.keySet()) {
            if (!carried.contains(name)) {
                throw new IllegalArgumentException(where + " classifies the field " + name + ", which no event carries");
            }
        }
        return new EventCatalogue(component, module, description, logger, auditProtocol, fields, codes);
    }

    @SuppressWarnings("unchecked")
    static Map<String, Object> object(Object value, String where) {
        if (!(value instanceof Map<?, ?>)) {
            throw new IllegalArgumentException(where + " must be a JSON object");
        }
        return (Map<String, Object>) value;
    }

    static List<?> list(Object value, String where) {
        if (!(value instanceof List<?> items)) {
            throw new IllegalArgumentException(where + " must be a JSON array");
        }
        return items;
    }

    /** Refuses a missing member and an unknown one. */
    static void members(Map<String, Object> object, Set<String> expected, String where) {
        for (String name : object.keySet()) {
            if (!expected.contains(name)) {
                throw new IllegalArgumentException(where + " has an unknown member " + Json.quote(name));
            }
        }
        for (String name : expected) {
            if (!object.containsKey(name)) {
                throw new IllegalArgumentException(where + " lacks the member " + name);
            }
        }
    }

    static String text(Map<String, Object> object, String member, String where) {
        Object value = object.get(member);
        if (!(value instanceof String text) || text.isBlank()) {
            throw new IllegalArgumentException(where + ": " + member + " must be a non-empty string");
        }
        return text;
    }

    static String matching(Map<String, Object> object, String member, Pattern rule, String where) {
        return name(text(object, member, where), rule, where + ": " + member);
    }

    static String name(String value, Pattern rule, String where) {
        if (!rule.matcher(value).matches()) {
            throw new IllegalArgumentException(where + " " + Json.quote(value) + " breaks the naming rule " + rule.pattern());
        }
        return value;
    }

    static boolean bool(Map<String, Object> object, String member, String where) {
        if (!(object.get(member) instanceof Boolean value)) {
            throw new IllegalArgumentException(where + ": " + member + " must be true or false");
        }
        return value;
    }

    static PiiClass pii(String value, String where) {
        for (PiiClass candidate : PiiClass.values()) {
            if (candidate.name().equals(value)) {
                return candidate;
            }
        }
        throw new IllegalArgumentException(where + ": pii " + Json.quote(value) + " is not one of "
                + List.of(PiiClass.values()));
    }

    static Level level(String value, String where) {
        for (Level candidate : Level.values()) {
            if (candidate.name().toLowerCase(Locale.ROOT).equals(value)) {
                return candidate;
            }
        }
        throw new IllegalArgumentException(where + ": level " + Json.quote(value) + " is neither debug nor info");
    }

    static Set<Event.Outcome> outcomes(Object value, String where) {
        List<?> items = list(value, where + ": outcomes");
        Set<Event.Outcome> outcomes = new LinkedHashSet<>();
        for (Object item : items) {
            Event.Outcome outcome = null;
            for (Event.Outcome candidate : Event.Outcome.values()) {
                if (candidate.code().equals(item)) {
                    outcome = candidate;
                }
            }
            if (outcome == null || !outcomes.add(outcome)) {
                throw new IllegalArgumentException(where + ": outcomes may hold success and failure, once each, not "
                        + describe(item));
            }
        }
        if (outcomes.isEmpty()) {
            throw new IllegalArgumentException(where + ": outcomes must name success, failure or both");
        }
        return Collections.unmodifiableSet(outcomes);
    }

    private static String describe(Object item) {
        return item instanceof String text ? Json.quote(text) : String.valueOf(item);
    }
}
