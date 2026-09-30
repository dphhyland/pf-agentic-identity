/*
 * The values of a setting its profile class applies to.
 */
package com.pingidentity.ps.oidf.platform.settings;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.regex.Pattern;

/**
 * Which values of a classed setting (plan items PR-2, PR-5) the production profile acts on: for a
 * {@code forbidden-in-production} entry the values production refuses, and for an {@code accepted-risk:<id>} entry the
 * values that need the risk accepted. An entry's {@code governed} member says it, in one of two forms, or leaves it to
 * the default rule:
 *
 * <ul>
 *   <li>{@code ["log", "disable"]} - these values, for a {@code bool} or a {@code choice} only; each must parse as the
 *       type, and the default may not be one of them (unset would then be the insecure case, and nothing could see
 *       it).</li>
 *   <li>{@code {"schemes": ["redis"]}} - a URL of one of these schemes, compared in any case as the text before
 *       {@code ://}; for a {@code string}, {@code secret}, {@code url} or {@code https-url} only. It may add
 *       {@code "unless_set": ["OIDF_REDIS_URL"]}: entries of the same catalogue that the reader takes first, so that
 *       while any of them is set this entry is not read and the profile does not judge it ({@code REDIS_URL}, read
 *       only when {@code OIDF_REDIS_URL} and its property are unset).</li>
 *   <li>absent - the default rule: a {@code bool} governs every value but its default; a {@code choice} of exactly
 *       two with a default governs the other one; a type with no default governs any value set. Any other entry (a
 *       {@code choice} of more than two, a number or text with a default) must say.</li>
 * </ul>
 *
 * <p>An entry classed {@code any} or {@code required-in-production} has no {@code governed}: {@code any} governs
 * nothing, and for {@code required-in-production} the violation is the value being unset or blank.
 */
public final class Governed {

    /** How a governed value is recognised. */
    public enum Form {
        /** One of {@link #values()}, as the type parses it. */
        VALUES,
        /** A URL whose scheme is one of {@link #values()}. */
        SCHEMES,
        /** Any value set. */
        ANY_VALUE
    }

    private static final Pattern SCHEME = Pattern.compile("[a-z][a-z0-9+.-]*");

    private final Form form;
    private final List<String> values;
    private final boolean explicit;
    private final List<String> unlessSet;

    private Governed(Form form, List<String> values, boolean explicit, List<String> unlessSet) {
        this.form = form;
        this.values = List.copyOf(values);
        this.explicit = explicit;
        this.unlessSet = List.copyOf(unlessSet);
    }

    /** Any value set. */
    static Governed anyValue(boolean explicit) {
        return new Governed(Form.ANY_VALUE, List.of(), explicit, List.of());
    }

    /** These values, as the type spells them. */
    static Governed values(List<String> values, boolean explicit) {
        return new Governed(Form.VALUES, values, explicit, List.of());
    }

    /** URLs of these schemes, lower case. */
    static Governed schemes(List<String> schemes) {
        return schemes(schemes, List.of());
    }

    /** URLs of these schemes, lower case, judged only while none of the entries {@code unlessSet} names is set. */
    static Governed schemes(List<String> schemes, List<String> unlessSet) {
        return new Governed(Form.SCHEMES, schemes, true, unlessSet);
    }

    public Form form() {
        return this.form;
    }

    /** The values, as the type spells them, for {@link Form#VALUES}; the schemes for {@link Form#SCHEMES}; else empty. */
    public List<String> values() {
        return this.values;
    }

    /**
     * The entries of the same catalogue the reader takes before this one: while any of them is set, this entry is not
     * read, so the profile does not judge it. Empty for an entry read on its own.
     */
    public List<String> unlessSet() {
        return this.unlessSet;
    }

    /** Whether the catalogue said it, rather than the default rule. */
    public boolean explicit() {
        return this.explicit;
    }

    /** Whether {@code scheme} is a scheme's name: a lower-case letter, then letters, digits, {@code +}, {@code .} and {@code -}. */
    static boolean isScheme(String scheme) {
        return SCHEME.matcher(scheme).matches();
    }

    /**
     * Whether {@code raw} - set, trimmed, not blank - is governed for {@code setting}.
     *
     * @throws SettingRefused when the form is {@link Form#VALUES} and the value does not parse as the setting's type
     */
    public boolean matches(Setting setting, String raw) {
        Objects.requireNonNull(raw, "raw");
        switch (this.form) {
            case VALUES:
                Object parsed = setting.parse(raw);
                for (String value : this.values) {
                    if (setting.parse(value).equals(parsed)) {
                        return true;
                    }
                }
                return false;
            case SCHEMES:
                int colon = raw.indexOf("://");
                String scheme = colon <= 0 ? "" : raw.substring(0, colon).toLowerCase(Locale.ROOT);
                return this.values.contains(scheme);
            default:
                return true;
        }
    }

    /**
     * The governed values in words, for a violation and a configuration reference: {@code true}, {@code log or disable},
     * {@code a redis:// URL}, {@code any value}.
     */
    public String describe() {
        switch (this.form) {
            case VALUES:
                return String.join(" or ", this.values);
            case SCHEMES:
                List<String> urls = new ArrayList<>();
                for (String scheme : this.values) {
                    urls.add(scheme + "://");
                }
                return "a " + String.join(" or ", urls) + " URL";
            default:
                return "any value";
        }
    }

    @Override
    public boolean equals(Object other) {
        return other instanceof Governed g && g.form == this.form && g.values.equals(this.values) && g.explicit == this.explicit
                && g.unlessSet.equals(this.unlessSet);
    }

    @Override
    public int hashCode() {
        return Objects.hash(this.form, this.values, this.explicit, this.unlessSet);
    }

    @Override
    public String toString() {
        return describe();
    }
}
