/*
 * One component's settings catalogue: the JSON document, loaded and checked.
 */
package com.pingidentity.ps.oidf.platform.settings;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigDecimal;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import java.util.regex.Pattern;
import com.pingidentity.ps.oidf.platform.json.Json;

/**
 * One component's settings catalogue (plan decision 1): a JSON document at
 * {@code src/main/resources/META-INF/oidf-settings/<component>.json} in the module that reads the settings,
 * naming the component, its owning module and package, the {@code OIDF_*} families it owns, its settings and
 * the names it no longer reads. The format is in docs/development/settings-catalogue.md.
 *
 * <p>{@link #parse} is strict: a member it does not know is refused, and so is an entry missing one, because a
 * catalogue is what a configuration reference and a start-up audit are generated from, and a half-written entry
 * would document and check half a setting. A catalogue that fails is a bug in the module that ships it, so the
 * refusal is an {@link IllegalArgumentException} naming the file, the entry and the member.
 */
public final class Catalogue {

    /** Where a catalogue lives on the class path; the file is {@code <component>.json}. */
    public static final String RESOURCE_DIRECTORY = "META-INF/oidf-settings/";

    /** The format version this reader reads. */
    public static final int FORMAT = 1;

    private static final Pattern COMPONENT = Pattern.compile("[a-z][a-z0-9]*(-[a-z0-9]+)*");
    private static final Pattern MODULE = Pattern.compile("[a-z0-9][a-z0-9-]*(/[a-z0-9][a-z0-9-]*)*");
    private static final Pattern PACKAGE = Pattern.compile("[a-z][a-z0-9_]*(\\.[a-z][a-z0-9_]*)+");
    private static final Pattern FAMILY = Pattern.compile("OIDF_([A-Z0-9]+_)+");
    private static final Pattern RELEASE = Pattern.compile("(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)");
    private static final Pattern ENV_NAME = Pattern.compile("[A-Z][A-Z0-9_]*");
    /**
     * A system property's name. Upper-case letters are allowed (PR-5): the JDK's
     * {@code jdk.internal.httpclient.disableHostnameVerification} (F-0195) and SSF's {@code oidf.ssf.<camelCase>}
     * properties (F-0235) are named so.
     */
    private static final Pattern PROPERTY_NAME = Pattern.compile("[A-Za-z][A-Za-z0-9_-]*(\\.[A-Za-z0-9_-]+)*");
    /** A component's name, as S-9 spells one: {@code SSF_RECEIVER}. */
    private static final Pattern COMPONENT_NAME = Pattern.compile("[A-Z][A-Z0-9_]{0,63}");
    private static final Pattern INIT_PARAM_NAME = Pattern.compile("[A-Za-z][A-Za-z0-9_.-]*");

    private static final Set<String> TOP = Set.of("format", "component", "module", "package", "families", "settings", "removed");
    /** Optional in format 1 (PR-5), so every catalogue written before it still loads. */
    private static final Set<String> TOP_OPTIONAL = Set.of("components");
    private static final Set<String> ENTRY_OPTIONAL = Set.of("governed", "components");
    private static final Set<String> SCHEMES = Set.of("schemes");
    private static final Set<String> ENTRY = Set.of("name", "kind", "type", "default", "description", "when_wrong", "profile",
            "security", "sources", "aliases", "file");
    private static final Set<String> RANGE = Set.of("min", "max");
    private static final Set<String> CHOICES = Set.of("choices");
    private static final Set<String> WHEN_WRONG = Set.of("effect", "detail");
    private static final Set<String> SOURCE = Set.of("from", "name");
    private static final Set<String> ALIAS = Set.of("name", "sources");
    private static final Set<String> REMOVED = Set.of("name", "from", "replacement", "release");

    private final String component;
    private final String module;
    private final String owningPackage;
    private final List<String> families;
    private final Map<String, Setting> settings;
    private final List<Removed> removed;
    private final List<String> components;
    private final boolean componentsDeclared;

    private Catalogue(String component, String module, String owningPackage, List<String> families,
            Map<String, Setting> settings, List<Removed> removed, List<String> components) {
        this.component = component;
        this.module = module;
        this.owningPackage = owningPackage;
        this.families = List.copyOf(families);
        this.settings = Collections.unmodifiableMap(settings);
        this.removed = List.copyOf(removed);
        this.componentsDeclared = components != null;
        this.components = components != null ? List.copyOf(components) : DefaultComponents.of(component);
    }

    /** The component, which is also the file's name. */
    public String component() {
        return this.component;
    }

    /** The module that ships it, as a path from the repository root: {@code servlets/pf-integration}. */
    public String module() {
        return this.module;
    }

    /** The one Java package that reads these settings and owns the file. */
    public String owningPackage() {
        return this.owningPackage;
    }

    /** The {@code OIDF_*} prefixes this component owns, for {@link UnknownKeys}. */
    public List<String> families() {
        return this.families;
    }

    /** The settings, in the file's order. */
    public List<Setting> settings() {
        return List.copyOf(this.settings.values());
    }

    /** The entry named {@code name}. */
    public Setting setting(String name) {
        Setting setting = this.settings.get(name);
        if (setting == null) {
            throw new IllegalArgumentException(name + " is not in the " + this.component + " settings catalogue");
        }
        return setting;
    }

    /**
     * The components this catalogue's settings belong to: its {@code components} member, or, when it has none, its
     * line in the table of docs/development/settings-catalogue.md (empty for a catalogue the table does not list). A
     * profile violation by one of its settings, and an unknown name under one of its families, refuse them (PR-5).
     */
    public List<String> components() {
        return this.components;
    }

    /** Whether {@link #components()} is the catalogue's own member rather than the table's line. */
    public boolean componentsDeclared() {
        return this.componentsDeclared;
    }

    /** The components {@code setting} belongs to: its own {@code components}, or else the catalogue's. */
    public List<String> componentsOf(Setting setting) {
        return setting.components().isEmpty() ? this.components : setting.components();
    }

    /** The names this component no longer reads. */
    public List<Removed> removed() {
        return this.removed;
    }

    /**
     * Every environment variable this catalogue declares: each entry's, its aliases', its {@code _FILE}
     * variants' and its removed names'.
     */
    public Set<String> declaredEnvironmentNames() {
        Set<String> names = new HashSet<>();
        for (Setting setting : this.settings.values()) {
            List<SourceName> all = new ArrayList<>(setting.sources());
            all.addAll(setting.fileVariants());
            for (Alias alias : setting.aliases()) {
                all.addAll(alias.sources());
            }
            for (SourceName name : all) {
                if (name.source() == Source.ENV) {
                    names.add(name.name());
                }
            }
        }
        for (Removed gone : this.removed) {
            if (gone.kind() == EntryKind.ENV) {
                names.add(gone.name());
            }
        }
        return names;
    }

    /**
     * Loads {@code <component>.json} from {@code loader}: the caller's own loader, so a plugin that shades
     * platform reads the catalogue it ships.
     *
     * <p>The same file can be found more than once, and that is accepted when every copy holds the same bytes.
     * PingFederate stages each jar twice - in {@code pf-runtime.war}'s {@code WEB-INF/lib} and in
     * {@code server/default/deploy}, which is on the server loader that is the webapp loader's parent - and
     * Jetty's webapp loader returns both copies from {@code getResources}. Copies that differ are two modules
     * shipping one component, which is refused, naming the first two that differ.
     *
     * @throws IllegalArgumentException when the component name is not one, the file is missing, found more than
     *                                  once with different content (a catalogue has exactly one owning module),
     *                                  or refused
     */
    public static Catalogue load(ClassLoader loader, String component) {
        if (component == null || !COMPONENT.matcher(component).matches()) {
            throw new IllegalArgumentException("a settings component is lower-case words joined by hyphens, not " + Json.quote(component));
        }
        String resource = RESOURCE_DIRECTORY + component + ".json";
        List<URL> found;
        try {
            found = Collections.list(loader.getResources(resource));
        } catch (IOException e) {
            throw new IllegalArgumentException("the class path could not be searched for " + resource, e);
        }
        if (found.isEmpty()) {
            throw new IllegalArgumentException("no settings catalogue " + resource + " on the class path");
        }
        byte[] first = read(found.get(0), resource);
        for (URL other : found.subList(1, found.size())) {
            if (!Arrays.equals(first, read(other, resource))) {
                throw new IllegalArgumentException(resource + " is on the class path " + found.size() + " times and "
                        + found.get(0) + " and " + other + " differ; a catalogue has exactly one owning module");
            }
        }
        Catalogue catalogue = parse(new String(first, StandardCharsets.UTF_8), resource);
        if (!catalogue.component.equals(component)) {
            throw new IllegalArgumentException(resource + " names its component " + catalogue.component + "; the file and the"
                    + " component are named alike");
        }
        return catalogue;
    }

    private static byte[] read(URL url, String resource) {
        try (InputStream in = url.openStream()) {
            return in.readAllBytes();
        } catch (IOException e) {
            throw new IllegalArgumentException(resource + " could not be read", e);
        }
    }

    /**
     * Refuses the first of this catalogue's removed names that {@code from} sets to something not blank, naming
     * its replacement, or saying nothing replaces it, and the release it went in. {@link Settings} calls it
     * before every value it resolves, so a deployment that still sets a removed name is refused on its
     * component's first read, whichever setting that read is for.
     *
     * @throws SettingRefused naming the removed name
     */
    public void refuseRemoved(Sources from) {
        for (Removed gone : this.removed) {
            if (gone.source() != null && Parsers.blankToNull(from.get(gone.source(), gone.name())) != null) {
                throw gone.refusal();
            }
        }
    }

    /**
     * Refuses the first of this catalogue's removed plugin fields that a plugin's configuration still sets to something
     * not blank, as {@link #refuseRemoved} does for the other kinds (F-0231: a plugin's saved configuration keeps a field
     * its descriptor no longer declares). {@code fields} answers a field's value by its name, or null.
     *
     * @throws SettingRefused naming the removed field
     */
    public void refuseRemovedFields(Function<String, String> fields) {
        for (Removed gone : this.removed) {
            if (gone.kind() == EntryKind.PLUGIN_FIELD && Parsers.blankToNull(fields.apply(gone.name())) != null) {
                throw gone.refusal();
            }
        }
    }

    /**
     * Reads and checks a catalogue document.
     *
     * @param json  the document
     * @param where what to call it in a refusal, for example its resource path
     * @throws IllegalArgumentException naming {@code where}, the entry and the member, for anything that is not
     *                                  a complete, consistent catalogue
     */
    public static Catalogue parse(String json, String where) {
        Object root;
        try {
            root = Json.parse(json);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException(where + ": " + e.getMessage());
        }
        Reader r = new Reader(where);
        Map<String, Object> top = r.object(root, "the document", TOP, TOP_OPTIONAL);
        BigDecimal format = r.number(top, "format", "the document");
        if (format.compareTo(BigDecimal.valueOf(FORMAT)) != 0) {
            throw r.refuse("the document", "format is " + format.toPlainString() + "; this reader reads format " + FORMAT);
        }
        String component = r.matching(top, "component", "the document", COMPONENT, "lower-case words joined by hyphens");
        String module = r.matching(top, "module", "the document", MODULE, "a module's path from the repository root");
        String owningPackage = r.matching(top, "package", "the document", PACKAGE, "one Java package");
        List<String> families = new ArrayList<>();
        for (Object family : r.list(top, "families", "the document")) {
            if (!(family instanceof String f) || !FAMILY.matcher(f).matches()) {
                throw r.refuse("families", "each family is a prefix such as OIDF_FEDERATION_, not " + describe(family));
            }
            if (families.contains(f)) {
                throw r.refuse("families", f + " is listed twice");
            }
            families.add(f);
        }
        Set<String> seen = new HashSet<>();
        Map<String, Setting> settings = new LinkedHashMap<>();
        List<Object> entries = r.list(top, "settings", "the document");
        for (int i = 0; i < entries.size(); i++) {
            Setting setting = r.setting(entries.get(i), "settings[" + i + "]", seen);
            if (settings.put(setting.name(), setting) != null) {
                throw r.refuse("settings[" + i + "]", setting.name() + " is catalogued twice");
            }
        }
        List<Removed> removed = new ArrayList<>();
        List<Object> gone = r.list(top, "removed", "the document");
        for (int i = 0; i < gone.size(); i++) {
            removed.add(r.removed(gone.get(i), "removed[" + i + "]", seen, settings));
        }
        List<String> components = top.containsKey("components") ? r.components(top.get("components"), "the document") : null;
        return new Catalogue(component, module, owningPackage, families, settings, removed, components);
    }

    /** A JSON value as a refusal names it: a string quoted, anything else by its JSON kind. */
    private static String describe(Object value) {
        if (value instanceof String s) {
            return Json.quote(s);
        }
        if (value instanceof Map<?, ?>) {
            return "an object";
        }
        if (value instanceof List<?>) {
            return "a list";
        }
        if (value instanceof BigDecimal) {
            return "a number";
        }
        return String.valueOf(value);
    }

    /** Reads one document, refusing with its name. */
    private static final class Reader {
        private final String where;

        Reader(String where) {
            this.where = where;
        }

        IllegalArgumentException refuse(String at, String what) {
            return new IllegalArgumentException(this.where + ": " + at + ": " + what);
        }

        /** An object with every one of {@code required} and nothing but those and {@code optional}. */
        Map<String, Object> object(Object value, String at, Set<String> required, Set<String> optional) {
            if (!(value instanceof Map<?, ?> map)) {
                throw refuse(at, "is not a JSON object");
            }
            @SuppressWarnings("unchecked")
            Map<String, Object> object = (Map<String, Object>) map;
            for (String member : object.keySet()) {
                if (!required.contains(member) && !optional.contains(member)) {
                    throw refuse(at, "unknown member " + Json.quote(member));
                }
            }
            for (String member : required) {
                if (!object.containsKey(member)) {
                    throw refuse(at, "no member " + Json.quote(member));
                }
            }
            return object;
        }

        String text(Map<String, Object> object, String member, String at) {
            if (!(object.get(member) instanceof String s) || s.isBlank()) {
                throw refuse(at, member + " must be text, not " + describe(object.get(member)));
            }
            if (!s.equals(s.strip()) || s.chars().anyMatch(c -> c < 0x20 || c == 0x7f)) {
                throw refuse(at, member + " must be one line with no spaces around it");
            }
            return s;
        }

        String matching(Map<String, Object> object, String member, String at, Pattern pattern, String what) {
            String value = text(object, member, at);
            if (!pattern.matcher(value).matches()) {
                throw refuse(at, member + " must be " + what + ", not " + Json.quote(value));
            }
            return value;
        }

        BigDecimal number(Map<String, Object> object, String member, String at) {
            if (!(object.get(member) instanceof BigDecimal n)) {
                throw refuse(at, member + " must be a number, not " + describe(object.get(member)));
            }
            return n;
        }

        boolean bool(Map<String, Object> object, String member, String at) {
            if (!(object.get(member) instanceof Boolean b)) {
                throw refuse(at, member + " must be true or false, not " + describe(object.get(member)));
            }
            return b;
        }

        List<Object> list(Map<String, Object> object, String member, String at) {
            if (!(object.get(member) instanceof List<?> l)) {
                throw refuse(at, member + " must be a list, not " + describe(object.get(member)));
            }
            return new ArrayList<>(l);
        }

        /** A list of component names, none twice; {@code at} names where it is. */
        List<String> components(Object value, String at) {
            if (!(value instanceof List<?> items)) {
                throw refuse(at, "components must be a list, not " + describe(value));
            }
            List<String> out = new ArrayList<>();
            for (Object item : items) {
                if (!(item instanceof String c) || !COMPONENT_NAME.matcher(c).matches()) {
                    throw refuse(at, "each component is named as S-9 names one (SSF_RECEIVER), not " + describe(item));
                }
                if (out.contains(c)) {
                    throw refuse(at, "component " + c + " is listed twice");
                }
                out.add(c);
            }
            return out;
        }

        /**
         * An entry's {@code governed} member, or the default rule when it has none (see {@link Governed}); null for an
         * entry classed {@code any} or {@code required-in-production}, which may not have one.
         */
        Governed governed(Map<String, Object> entry, String at, ProfileClass profile, SettingType type, String defaultValue,
                List<String> choices, Setting setting) {
            boolean acts = profile.kind() == ProfileClass.Kind.FORBIDDEN_IN_PRODUCTION
                    || profile.kind() == ProfileClass.Kind.ACCEPTED_RISK;
            if (!entry.containsKey("governed")) {
                if (!acts) {
                    return null;
                }
                if (defaultValue == null) {
                    return Governed.anyValue(false);
                }
                if (type == SettingType.BOOL) {
                    return Governed.values(List.of(String.valueOf(!Boolean.parseBoolean(defaultValue))), false);
                }
                if (type == SettingType.CHOICE && choices.size() == 2) {
                    Object spelt = setting.parse(defaultValue);
                    return Governed.values(List.of(choices.get(0).equals(spelt) ? choices.get(1) : choices.get(0)), false);
                }
                throw refuse(at, "an entry of type " + type.id() + (type == SettingType.CHOICE ? " with " + choices.size()
                        + " choices" : "") + " and a default, classed " + profile + ", says in governed which values the"
                        + " profile acts on");
            }
            if (!acts) {
                throw refuse(at, "governed goes with forbidden-in-production or accepted-risk:<id>, not " + profile);
            }
            Object value = entry.get("governed");
            if (value instanceof Map<?, ?>) {
                Map<String, Object> form = object(value, at + ".governed", SCHEMES, Set.of());
                if (type != SettingType.STRING && type != SettingType.SECRET && type != SettingType.URL
                        && type != SettingType.HTTPS_URL) {
                    throw refuse(at, "governed schemes go with a string, secret, url or https-url, not a " + type.id());
                }
                List<String> schemes = new ArrayList<>();
                for (Object scheme : list(form, "schemes", at + ".governed")) {
                    if (!(scheme instanceof String sc) || !Governed.isScheme(sc) || schemes.contains(sc)) {
                        throw refuse(at, "each governed scheme is a lower-case scheme name, listed once, not " + describe(scheme));
                    }
                    schemes.add(sc);
                }
                if (schemes.isEmpty()) {
                    throw refuse(at, "governed schemes lists at least one scheme");
                }
                return Governed.schemes(schemes);
            }
            if (!(value instanceof List<?> items) || items.isEmpty()) {
                throw refuse(at, "governed is a list of values or {\"schemes\": [...]}, not " + describe(value));
            }
            if (type != SettingType.BOOL && type != SettingType.CHOICE) {
                throw refuse(at, "governed values go with a bool or a choice, not a " + type.id());
            }
            List<String> values = new ArrayList<>();
            for (Object item : items) {
                String text = item instanceof Boolean ? Json.write(item) : item instanceof String t ? t : null;
                Object parsed;
                try {
                    parsed = text == null ? null : setting.parse(text);
                } catch (SettingRefused e) {
                    parsed = null;
                }
                if (parsed == null) {
                    throw refuse(at, "governed value " + describe(item) + " is not a value of this " + type.id());
                }
                String spelt = String.valueOf(parsed);
                if (values.contains(spelt)) {
                    throw refuse(at, "governed value " + spelt + " is listed twice");
                }
                if (defaultValue != null && parsed.equals(setting.parse(defaultValue))) {
                    throw refuse(at, "governed value " + spelt + " is the default, so unset would be the case the profile"
                            + " governs and nothing could see it");
                }
                values.add(spelt);
            }
            return Governed.values(values, true);
        }

        /** A name as {@code source} spells one, not claimed yet by another entry of this catalogue. */
        String name(Source source, Object value, String at, Set<String> seen) {
            Pattern pattern = source == Source.ENV ? ENV_NAME : source == Source.SYSTEM_PROPERTY ? PROPERTY_NAME : INIT_PARAM_NAME;
            if (!(value instanceof String s) || !pattern.matcher(s).matches()) {
                throw refuse(at, describe(value) + " is not " + (source == Source.ENV ? "an environment variable's"
                        : source == Source.SYSTEM_PROPERTY ? "a system property's" : "an init-param's") + " name");
            }
            if (!seen.add(source.id() + " " + s)) {
                throw refuse(at, source.id() + " " + s + " is declared twice in this catalogue");
            }
            return s;
        }

        List<SourceName> sources(Object value, String at, Set<String> seen) {
            if (!(value instanceof List<?> items)) {
                throw refuse(at, "sources must be a list, not " + describe(value));
            }
            List<SourceName> out = new ArrayList<>();
            Set<Source> kinds = new HashSet<>();
            for (int i = 0; i < items.size(); i++) {
                String here = at + ".sources[" + i + "]";
                Map<String, Object> item = object(items.get(i), here, SOURCE, Set.of());
                Source source = item.get("from") instanceof String from ? Source.byId(from) : null;
                if (source == null) {
                    throw refuse(here, "from must be env, system-property or init-param, not " + describe(item.get("from")));
                }
                if (!kinds.add(source)) {
                    throw refuse(here, "a setting is read from " + source.id() + " once");
                }
                out.add(new SourceName(source, name(source, item.get("name"), here, seen)));
            }
            return out;
        }

        Setting setting(Object value, String at, Set<String> seen) {
            Map<String, Object> entry = object(value, at, ENTRY, union(union(RANGE, CHOICES), ENTRY_OPTIONAL));
            String name = text(entry, "name", at);
            String here = at + " (" + name + ")";
            EntryKind kind = EntryKind.byId(entry.get("kind") instanceof String k ? k : "");
            if (kind == null) {
                throw refuse(here, "kind must be env, system-property, init-param, plugin-field or extended-property, not "
                        + describe(entry.get("kind")));
            }
            SettingType type = SettingType.byId(entry.get("type") instanceof String t ? t : "");
            if (type == null) {
                throw refuse(here, "type must be one of bool, int, long, seconds, millis, string, choice, https-url, url,"
                        + " json-object, words, path, secret, not " + describe(entry.get("type")));
            }
            only(entry, here, RANGE, type.ranged(), "a " + type.id() + " setting");
            only(entry, here, CHOICES, type == SettingType.CHOICE, "a " + type.id() + " setting");
            Long min = null;
            Long max = null;
            if (type.ranged()) {
                long floor = type == SettingType.INT ? Integer.MIN_VALUE : Long.MIN_VALUE;
                long ceiling = type == SettingType.INT ? Integer.MAX_VALUE : Long.MAX_VALUE;
                min = whole(entry, "min", here, floor, ceiling);
                max = whole(entry, "max", here, floor, ceiling);
                if (min > max) {
                    throw refuse(here, "min is more than max");
                }
            }
            List<String> choices = new ArrayList<>();
            if (type == SettingType.CHOICE) {
                Set<String> folded = new HashSet<>();
                for (Object choice : list(entry, "choices", here)) {
                    if (!(choice instanceof String c) || c.isBlank() || !c.equals(c.strip())) {
                        throw refuse(here, "each choice is a word, not " + describe(choice));
                    }
                    if (!folded.add(c.toLowerCase(Locale.ROOT))) {
                        throw refuse(here, "choice " + Json.quote(c) + " is listed twice (choices are read in any case)");
                    }
                    choices.add(c);
                }
                if (choices.isEmpty()) {
                    throw refuse(here, "a choice setting lists its choices");
                }
            }
            String description = text(entry, "description", here);
            Map<String, Object> wrong = object(entry.get("when_wrong"), here + ".when_wrong", WHEN_WRONG, Set.of());
            WhenWrong.Effect effect = WhenWrong.Effect.byId(wrong.get("effect") instanceof String e ? e : "");
            if (effect == null) {
                throw refuse(here + ".when_wrong", "effect must be doesnt-start, first-request, per-request or not-checked, not "
                        + describe(wrong.get("effect")));
            }
            WhenWrong whenWrong = new WhenWrong(effect, text(wrong, "detail", here + ".when_wrong"));
            ProfileClass profile;
            try {
                profile = ProfileClass.parse(text(entry, "profile", here));
            } catch (IllegalArgumentException e) {
                throw refuse(here, e.getMessage());
            }
            boolean security = bool(entry, "security", here);
            boolean file = bool(entry, "file", here);
            List<SourceName> sources = sources(entry.get("sources"), here, seen);
            List<Alias> aliases = new ArrayList<>();
            List<Object> aliasItems = list(entry, "aliases", here);
            for (int i = 0; i < aliasItems.size(); i++) {
                String aliasAt = here + ".aliases[" + i + "]";
                Map<String, Object> alias = object(aliasItems.get(i), aliasAt, ALIAS, Set.of());
                String aliasName = text(alias, "name", aliasAt);
                List<SourceName> aliasSources = sources(alias.get("sources"), aliasAt, seen);
                if (aliasSources.stream().noneMatch(s -> s.name().equals(aliasName))) {
                    throw refuse(aliasAt, "one of an alias's sources has the alias's name");
                }
                aliases.add(new Alias(aliasName, aliasSources));
            }
            if (kind.resolved()) {
                Source naming = kind.namingSource();
                if (sources.stream().noneMatch(s -> s.source() == naming && s.name().equals(name))) {
                    throw refuse(here, "an " + kind.id() + " entry is read from " + naming.id() + " under its own name");
                }
            } else if (!sources.isEmpty() || !aliases.isEmpty() || file) {
                throw refuse(here, "a " + kind.id() + " is supplied by PingFederate: it has no sources, aliases or file");
            }
            if (file && type != SettingType.SECRET) {
                throw refuse(here, "only a secret is read from a file");
            }
            if (type == SettingType.SECRET && !security) {
                throw refuse(here, "a secret bears on security");
            }
            Setting setting = new Setting(name, kind, type, null, min, max, choices, description, whenWrong, profile, security,
                    sources, aliases, file);
            for (SourceName variant : setting.fileVariants()) {
                name(variant.source(), variant.name(), here + " (the file variant)", seen);
            }
            String defaultValue = defaultOf(entry.get("default"), here);
            if (type == SettingType.SECRET && defaultValue != null) {
                throw refuse(here, "a secret has no default");
            }
            if (type == SettingType.BOOL && defaultValue == null) {
                throw refuse(here, "a switch has a default");
            }
            try {
                setting.parse(defaultValue);
            } catch (SettingRefused e) {
                throw refuse(here, "the default is refused: " + e.getMessage());
            }
            Governed governed = governed(entry, here, profile, type, defaultValue, choices, setting);
            List<String> components = entry.containsKey("components") ? components(entry.get("components"), here) : List.of();
            if (entry.containsKey("components") && components.isEmpty()) {
                throw refuse(here, "an entry's components names at least one; leave it out to take the catalogue's");
            }
            return new Setting(name, kind, type, defaultValue, min, max, choices, description, whenWrong, profile, security,
                    sources, aliases, file, governed, components);
        }

        /** {@code members} are all present when {@code wanted}, and none of them otherwise. */
        void only(Map<String, Object> entry, String at, Set<String> members, boolean wanted, String what) {
            for (String member : members) {
                if (entry.containsKey(member) != wanted) {
                    throw refuse(at, wanted ? "no member " + Json.quote(member) : what + " has no member " + Json.quote(member));
                }
            }
        }

        long whole(Map<String, Object> entry, String member, String at, long floor, long ceiling) {
            BigDecimal n = number(entry, member, at);
            try {
                long value = n.longValueExact();
                if (value >= floor && value <= ceiling) {
                    return value;
                }
            } catch (ArithmeticException e) {
                // not whole, or past a long: refused below
            }
            throw refuse(at, member + " must be a whole number from " + floor + " to " + ceiling + ", not " + n.toPlainString());
        }

        /** A default as text: a string as it is, a boolean or a number as JSON writes it, null for none. */
        String defaultOf(Object value, String at) {
            if (value == null || value instanceof String) {
                return (String) value;
            }
            if (value instanceof Boolean || value instanceof BigDecimal) {
                return Json.write(value);
            }
            throw refuse(at, "default must be text, a number, true, false or null, not " + describe(value));
        }

        Removed removed(Object value, String at, Set<String> seen, Map<String, Setting> settings) {
            Map<String, Object> entry = object(value, at, REMOVED, Set.of());
            Source source = entry.get("from") instanceof String from ? Source.byId(from) : null;
            boolean field = EntryKind.PLUGIN_FIELD.id().equals(entry.get("from"));
            if (source == null && !field) {
                throw refuse(at, "from must be env, system-property, init-param or plugin-field, not " + describe(entry.get("from")));
            }
            String name;
            if (field) {
                name = text(entry, "name", at);
                if (!seen.add(EntryKind.PLUGIN_FIELD.id() + " " + name) || settings.containsKey(name)) {
                    throw refuse(at, "plugin-field " + name + " is declared twice in this catalogue");
                }
            } else {
                name = name(source, entry.get("name"), at, seen);
            }
            Object replacement = entry.get("replacement");
            if (replacement != null && !(replacement instanceof String r && !r.isBlank())) {
                throw refuse(at, "replacement must be the name to set instead, or null, not " + describe(replacement));
            }
            String release = matching(entry, "release", at, RELEASE, "a release such as 0.4.0");
            if (replacement != null && !settings.containsKey(replacement)) {
                throw refuse(at, "replacement " + replacement + " is not a setting of this catalogue");
            }
            return new Removed(name, field ? EntryKind.PLUGIN_FIELD : EntryKind.of(source), (String) replacement, release);
        }

        private static Set<String> union(Set<String> a, Set<String> b) {
            Set<String> out = new HashSet<>(a);
            out.addAll(b);
            return out;
        }
    }
}
