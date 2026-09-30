/*
 * One catalogued setting: what it is, where it is read, and how its value is resolved and parsed.
 */
package com.pingidentity.ps.oidf.platform.settings;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import com.pingidentity.ps.oidf.platform.json.Json;
import com.pingidentity.ps.oidf.platform.profile.DeploymentProfile;

/**
 * One entry of a settings catalogue ({@link Catalogue}): its name, kind and type, its default and range or
 * choices, what it does and what happens when it is wrong, how it stands with the deployment profile, whether
 * it bears on security, where it is read and in which order, its superseded names, and whether a secret may
 * be read from a file.
 *
 * <p>Entries are read from a catalogue, never built by hand, so every one has been checked complete
 * ({@link Catalogue#parse}). The rules for resolving one are in {@link #resolve}.
 */
public final class Setting {

    /** The most a {@code _FILE} variant's file may hold. A secret is a key or a token, not a document. */
    public static final int MAX_FILE_BYTES = 65_536;

    private final String name;
    private final EntryKind kind;
    private final SettingType type;
    private final String defaultValue;
    private final Long min;
    private final Long max;
    private final List<String> choices;
    private final String description;
    private final WhenWrong whenWrong;
    private final ProfileClass profile;
    private final boolean security;
    private final List<SourceName> sources;
    private final List<Alias> aliases;
    private final boolean file;
    private final Governed governed;
    private final List<String> components;

    Setting(String name, EntryKind kind, SettingType type, String defaultValue, Long min, Long max, List<String> choices,
            String description, WhenWrong whenWrong, ProfileClass profile, boolean security, List<SourceName> sources,
            List<Alias> aliases, boolean file) {
        this(name, kind, type, defaultValue, min, max, choices, description, whenWrong, profile, security, sources, aliases,
                file, null, List.of());
    }

    Setting(String name, EntryKind kind, SettingType type, String defaultValue, Long min, Long max, List<String> choices,
            String description, WhenWrong whenWrong, ProfileClass profile, boolean security, List<SourceName> sources,
            List<Alias> aliases, boolean file, Governed governed, List<String> components) {
        this.name = Objects.requireNonNull(name, "name");
        this.kind = Objects.requireNonNull(kind, "kind");
        this.type = Objects.requireNonNull(type, "type");
        this.defaultValue = defaultValue;
        this.min = min;
        this.max = max;
        this.choices = List.copyOf(choices);
        this.description = Objects.requireNonNull(description, "description");
        this.whenWrong = Objects.requireNonNull(whenWrong, "whenWrong");
        this.profile = Objects.requireNonNull(profile, "profile");
        this.security = security;
        this.sources = List.copyOf(sources);
        this.aliases = List.copyOf(aliases);
        this.file = file;
        this.governed = governed;
        this.components = List.copyOf(components);
    }

    /** The name, as the operator sets it and every message gives it. */
    public String name() {
        return this.name;
    }

    public EntryKind kind() {
        return this.kind;
    }

    public SettingType type() {
        return this.type;
    }

    /** The default as the catalogue writes it, or null when there is none. */
    public String defaultValue() {
        return this.defaultValue;
    }

    /** The smallest value allowed, for a ranged type; null otherwise. */
    public Long min() {
        return this.min;
    }

    /** The largest value allowed, for a ranged type; null otherwise. */
    public Long max() {
        return this.max;
    }

    /** The choices, for {@link SettingType#CHOICE}; empty otherwise. */
    public List<String> choices() {
        return this.choices;
    }

    public String description() {
        return this.description;
    }

    public WhenWrong whenWrong() {
        return this.whenWrong;
    }

    public ProfileClass profile() {
        return this.profile;
    }

    /** Whether the setting bears on security: a configuration reference marks it. */
    public boolean security() {
        return this.security;
    }

    /** Where it is read, in precedence order: the first one set wins. Empty for a PingFederate-supplied kind. */
    public List<SourceName> sources() {
        return this.sources;
    }

    public List<Alias> aliases() {
        return this.aliases;
    }

    /** Whether a {@code _FILE} variant of each source may name a file holding the value (secrets only). */
    public boolean file() {
        return this.file;
    }

    /**
     * The values its profile class applies to ({@link Governed}): for a {@code forbidden-in-production} or
     * {@code accepted-risk} entry, what the catalogue says or the default rule gives; null for {@code any} and
     * {@code required-in-production}.
     */
    public Governed governed() {
        return this.governed;
    }

    /** The components this entry names itself; empty when it belongs to its catalogue's ({@link Catalogue#componentsOf}). */
    public List<String> components() {
        return this.components;
    }

    /** The {@code _FILE} variants, in the sources' order; empty unless {@link #file()}. */
    public List<SourceName> fileVariants() {
        List<SourceName> variants = new ArrayList<>();
        if (this.file) {
            for (SourceName source : this.sources) {
                variants.add(new SourceName(source.source(), source.source().fileVariant(source.name())));
            }
        }
        return variants;
    }

    /**
     * Resolves this setting's value from {@code from}. In order:
     *
     * <ol>
     *   <li>the first of {@link #sources()} set to something not blank supplies the value, trimmed;</li>
     *   <li>for a secret with {@link #file()}, the first {@code _FILE} variant set names a file whose content,
     *       with one trailing newline trimmed, is the value; a direct name and a {@code _FILE} name both set is
     *       refused, naming both; a file that cannot be read, is empty or is larger than {@link #MAX_FILE_BYTES}
     *       is refused, naming the file and never its content, and so is a value that is not a path;</li>
     *   <li>each alias in turn: used, with a warning, when nothing above supplied a value; a warning when it
     *       holds the same value; refused, naming both names and neither value, when it holds another;</li>
     *   <li>otherwise the default, which may be none.</li>
     * </ol>
     *
     * <p>The value is then parsed by {@link #parse}. {@link Settings} is the way in; this is its rule. Removed
     * names are the catalogue's rule, not one setting's: {@link Settings} refuses every one that is set, with
     * {@link Catalogue#refuseRemoved}, before it resolves anything.
     *
     * @throws SettingRefused        for a refusal above or a value its type refuses
     * @throws IllegalArgumentException for a PingFederate-supplied kind, which has nothing to resolve
     */
    Resolved resolve(Sources from) {
        return resolve(from, DeploymentProfile.of(name -> from.get(Source.ENV, name)));
    }

    /**
     * As {@link #resolve(Sources)}, under {@code profile}: in development a value only a legacy spelling makes
     * readable ({@link #legacy}) resolves to what the reader before 0.6.0 read it as, with a warning that names the
     * strict spelling, and the result records the spelling ({@link Resolved#legacySpelling()}); in production it is
     * refused as any value that does not parse is. The escape goes at 1.0 with the deprecated aliases (Phase 3 plan,
     * decision 11).
     */
    Resolved resolve(Sources from, DeploymentProfile profile) {
        Raw raw = resolveRaw(from);
        if (raw.provenance().source() == Source.DEFAULT) {
            return new Resolved(this, parse(this.defaultValue), raw.provenance(), raw.warnings());
        }
        try {
            return new Resolved(this, parse(raw.value()), raw.provenance(), raw.warnings());
        } catch (SettingRefused refused) {
            Object old = profile.isDevelopment() ? legacy(raw.value()) : null;
            if (old == null) {
                throw refused;
            }
            List<String> warnings = new ArrayList<>(raw.warnings());
            warnings.add(this.name + " is '" + raw.value() + "', a spelling only the reader before 0.6.0 took; it is read as "
                    + old + ", as that reader read it. Write " + old + " (or the value you meant): the production profile"
                    + " refuses this spelling, and development stops taking it at 1.0");
            return new Resolved(this, old, raw.provenance(), warnings, raw.value());
        }
    }

    /**
     * What a value the strict parser refuses meant to the reader before 0.6.0, when it is a legacy spelling of this
     * setting's type ({@link Parsers#legacyBoolean}); null when it is not one.
     */
    Object legacy(String value) {
        return this.type == SettingType.BOOL ? Parsers.legacyBoolean(value) : null;
    }

    /** A value found by {@link #resolveRaw}, before it is parsed: trimmed text, or the default's, and where it came from. */
    record Raw(String value, Provenance provenance, List<String> warnings) {
    }

    /**
     * The rule of {@link #resolve(Sources)} up to the value, not parsed: the first source set, a {@code _FILE}
     * variant's file, the aliases, or the default (whose provenance is {@link Source#DEFAULT}).
     *
     * @throws SettingRefused for a refusal of the rule: a name and its {@code _FILE} variant both set, a file that
     *                        cannot be read, an alias holding another value
     */
    Raw resolveRaw(Sources from) {
        if (!this.kind.resolved()) {
            throw new IllegalArgumentException(this.name + " is a " + this.kind.id() + ", which PingFederate supplies;"
                    + " parse the value it gives instead of resolving one");
        }
        List<String> warnings = new ArrayList<>();
        SourceName direct = firstSet(from, this.sources);
        SourceName fileName = firstSet(from, fileVariants());
        String value = null;
        Provenance provenance = null;
        if (direct != null && fileName != null) {
            throw new SettingRefused(this.name, direct.name() + " and " + fileName.name() + " are both set; set one of them");
        }
        if (direct != null) {
            value = Parsers.blankToNull(from.get(direct.source(), direct.name()));
            provenance = new Provenance(direct.source(), direct.name(), null);
        } else if (fileName != null) {
            Path path = pathOf(fileName.name(), Parsers.blankToNull(from.get(fileName.source(), fileName.name())));
            value = readSecretFile(fileName.name(), path);
            provenance = new Provenance(fileName.source(), fileName.name(), path);
        }
        for (Alias alias : this.aliases) {
            SourceName old = firstSet(from, alias.sources());
            if (old == null) {
                continue;
            }
            String before = value;
            value = Parsers.aliased(this.name, value, alias.name(), from.get(old.source(), old.name()), warnings);
            if (before == null) {
                provenance = new Provenance(old.source(), old.name(), null);
            }
        }
        if (provenance == null) {
            return new Raw(this.defaultValue, new Provenance(Source.DEFAULT, this.name, null), warnings);
        }
        return new Raw(value, provenance, warnings);
    }

    /** The first of {@code names} whose value is set and not blank, or null. */
    private static SourceName firstSet(Sources from, List<SourceName> names) {
        for (SourceName candidate : names) {
            if (Parsers.blankToNull(from.get(candidate.source(), candidate.name())) != null) {
                return candidate;
            }
        }
        return null;
    }

    /** A {@code _FILE} variant's value as a path; a value the platform cannot make one of is refused, naming it. */
    private Path pathOf(String variant, String value) {
        try {
            return Path.of(value);
        } catch (InvalidPathException e) {
            throw new SettingRefused(this.name, variant + " names " + Json.quote(value) + ", which is not a path");
        }
    }

    /** A {@code _FILE} variant's file: its content with one trailing newline trimmed; refusals name the file, never its content. */
    private String readSecretFile(String variant, Path path) {
        byte[] bytes;
        try (InputStream in = Files.newInputStream(path)) {
            bytes = in.readNBytes(MAX_FILE_BYTES + 1);
        } catch (IOException | SecurityException e) {
            throw new SettingRefused(this.name, variant + " names " + path + ", which cannot be read (" + e.getClass().getSimpleName() + ")");
        }
        if (bytes.length > MAX_FILE_BYTES) {
            throw new SettingRefused(this.name, variant + " names " + path + ", which holds more than " + MAX_FILE_BYTES + " bytes");
        }
        String content = new String(bytes, StandardCharsets.UTF_8);
        if (content.endsWith("\r\n")) {
            content = content.substring(0, content.length() - 2);
        } else if (content.endsWith("\n")) {
            content = content.substring(0, content.length() - 1);
        }
        if (content.isBlank()) {
            throw new SettingRefused(this.name, variant + " names " + path + ", which is empty");
        }
        return content;
    }

    /**
     * {@code raw} parsed as this setting's type: null for null or blank. The strict parsers of {@link Parsers}
     * do the work, so a refusal reads as it always has; a secret is never parsed and never shown.
     *
     * @throws SettingRefused when the type refuses the value
     */
    public Object parse(String raw) {
        String value = Parsers.blankToNull(raw);
        if (value == null) {
            return null;
        }
        switch (this.type) {
            case BOOL:
                return Parsers.strictBoolean(this.name, value);
            case INT:
                return (int) number(value);
            case LONG:
                return number(value);
            case SECONDS:
                return Duration.ofSeconds(number(value));
            case MILLIS:
                return Duration.ofMillis(number(value));
            case CHOICE:
                return Parsers.choice(this.name, value, null, this.choices.toArray(new String[0]));
            case HTTPS_URL:
                return Parsers.httpsUrl(this.name, value);
            case URL:
                return Parsers.httpOrHttpsUrl(this.name, value);
            case JSON_OBJECT:
                Object object = Parsers.strictly(this.name, () -> Parsers.jsonObject(value));
                if (object == null) {
                    throw new SettingRefused(this.name, this.name + ": not a JSON object");
                }
                return object;
            case WORDS:
                return Parsers.words(this.name, value);
            case PATH:
                return Parsers.path(this.name, value);
            case SECRET:
                return new Secret(raw);
            default:
                return value;
        }
    }

    private long number(String value) {
        return Parsers.inRange(this.name, Parsers.wholeNumber(this.name, value, 0L), this.min, this.max);
    }

    @Override
    public String toString() {
        return this.name + " (" + this.type.id() + ")";
    }
}
