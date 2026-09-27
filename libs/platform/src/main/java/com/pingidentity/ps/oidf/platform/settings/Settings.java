/*
 * Typed reads of one component's catalogued settings.
 */
package com.pingidentity.ps.oidf.platform.settings;

import java.net.URI;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Consumer;
import com.pingidentity.ps.oidf.platform.log.PlatformLog;

/**
 * One component's settings, read through its catalogue: each accessor finds the entry, resolves it from the
 * sources with the entry's own names, precedence, aliases, removed names and {@code _FILE} variant
 * ({@link Setting#resolve}), and parses it as the entry's type with its range or choices.
 *
 * <pre>{@code
 * Settings federation = Settings.of("federation");          // META-INF/oidf-settings/federation.json, this class's loader
 * boolean failClosed = federation.bool("OIDF_AUTO_REGISTRATION_FAIL_CLOSED");
 * Duration grace = federation.duration("OIDF_FEDERATION_KEY_HISTORY_GRACE_SECONDS");
 * Resolved mode = federation.resolve("OIDF_PDP_MODE");      // the value and which source and name supplied it
 * }</pre>
 *
 * <p>An accessor names the type it expects, so a reader converted to it (ST-5) keeps its meaning: asking for a
 * {@code bool} of an entry typed {@code choice} is a bug and an {@link IllegalArgumentException}, as is a
 * name the catalogue does not have. A value that is wrong is a {@link SettingRefused}. Each call resolves
 * again, so a caller that reads a setting once keeps the value itself. A warning (a superseded name in use) is
 * logged once per loaded copy of this class, however often it is resolved.
 */
public final class Settings {

    private static final PlatformLog LOG = PlatformLog.get(Settings.class);

    /** Warnings already logged by this copy of the class. */
    private static final Set<String> WARNED = ConcurrentHashMap.newKeySet();

    private final Catalogue catalogue;
    private final Sources sources;
    private final Consumer<String> warnings;

    private Settings(Catalogue catalogue, Sources sources, Consumer<String> warnings) {
        this.catalogue = Objects.requireNonNull(catalogue, "catalogue");
        this.sources = Objects.requireNonNull(sources, "sources");
        this.warnings = warnings;
    }

    /**
     * {@code component}'s settings, from its catalogue on the calling class's loader, read from this process
     * (environment and system properties; add init-params with {@link #with}).
     */
    public static Settings of(String component) {
        Class<?> caller = StackWalker.getInstance(StackWalker.Option.RETAIN_CLASS_REFERENCE).getCallerClass();
        return load(loaderOf(caller), component);
    }

    /** {@code component}'s settings, from its catalogue on {@code loader}, read from this process. */
    public static Settings load(ClassLoader loader, String component) {
        return of(Catalogue.load(loader, component), Sources.process());
    }

    /** A catalogue's settings read from {@code sources}. */
    public static Settings of(Catalogue catalogue, Sources sources) {
        return new Settings(catalogue, sources, Settings::warnOnce);
    }

    /** These settings read from {@code sources} instead. */
    public Settings with(Sources sources) {
        return new Settings(this.catalogue, sources, this.warnings);
    }

    /** Test seam: these settings with warnings going to {@code sink} rather than the log. */
    Settings warningsTo(Consumer<String> sink) {
        return new Settings(this.catalogue, this.sources, Objects.requireNonNull(sink, "sink"));
    }

    public Catalogue catalogue() {
        return this.catalogue;
    }

    /** The value of {@code name}, typed as its entry says, with its provenance. */
    public Resolved resolve(String name) {
        Resolved resolved = this.catalogue.setting(name).resolve(this.sources, this.catalogue.removed());
        resolved.warnings().forEach(this.warnings);
        return resolved;
    }

    /** A {@code bool} entry's value; a switch always has a default. */
    public boolean bool(String name) {
        return (Boolean) typed(name, SettingType.BOOL);
    }

    /** An {@code int} entry's value, or null when unset with no default. */
    public Integer integer(String name) {
        return (Integer) typed(name, SettingType.INT);
    }

    /** A {@code long} entry's value, or null when unset with no default. */
    public Long longValue(String name) {
        return (Long) typed(name, SettingType.LONG);
    }

    /** A {@code seconds} or {@code millis} entry's value, or null when unset with no default. */
    public Duration duration(String name) {
        return (Duration) typed(name, SettingType.SECONDS, SettingType.MILLIS);
    }

    /** A {@code string} entry's value, trimmed, or null when unset with no default. */
    public String string(String name) {
        return (String) typed(name, SettingType.STRING);
    }

    /** A {@code choice} entry's value, spelt as the entry spells it, or null when unset with no default. */
    public String choice(String name) {
        return (String) typed(name, SettingType.CHOICE);
    }

    /** An {@code https-url} entry's value, or null when unset with no default. */
    public URI httpsUrl(String name) {
        return (URI) typed(name, SettingType.HTTPS_URL);
    }

    /** A {@code url} entry's value, or null when unset with no default. */
    public URI url(String name) {
        return (URI) typed(name, SettingType.URL);
    }

    /** A {@code json-object} entry's value, or null when unset with no default. */
    @SuppressWarnings("unchecked")
    public Map<String, Object> jsonObject(String name) {
        return (Map<String, Object>) typed(name, SettingType.JSON_OBJECT);
    }

    /** A {@code words} entry's value, or null when unset with no default. */
    @SuppressWarnings("unchecked")
    public Set<String> words(String name) {
        return (Set<String>) typed(name, SettingType.WORDS);
    }

    /** A {@code path} entry's value, or null when unset with no default. */
    public Path path(String name) {
        return (Path) typed(name, SettingType.PATH);
    }

    /** A {@code secret} entry's value, or null when unset. */
    public Secret secret(String name) {
        return (Secret) typed(name, SettingType.SECRET);
    }

    /**
     * {@code raw} parsed as {@code name}'s entry says: for a {@code plugin-field} or {@code extended-property},
     * whose value PingFederate hands the caller, or any value a caller already holds.
     */
    public Object parse(String name, String raw) {
        return this.catalogue.setting(name).parse(raw);
    }

    private Object typed(String name, SettingType... expected) {
        Setting setting = this.catalogue.setting(name);
        for (SettingType type : expected) {
            if (setting.type() == type) {
                return resolve(name).value();
            }
        }
        throw new IllegalArgumentException(name + " is a " + setting.type().id() + " setting, not " + expected[0].id());
    }

    /** Logs {@code message} unless this copy of the class has logged it before; answers whether it did. */
    static boolean warnOnce(String message) {
        if (!WARNED.add(message)) {
            return false;
        }
        LOG.warn(message);
        return true;
    }

    static ClassLoader loaderOf(Class<?> caller) {
        ClassLoader loader = caller.getClassLoader();
        return loader == null ? ClassLoader.getSystemClassLoader() : loader;
    }
}
