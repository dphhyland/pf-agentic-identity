/*
 * A label a metric declares, and the bound on the values it keeps.
 */
package com.pingidentity.ps.oidf.platform.metrics;

import java.util.Arrays;
import java.util.Collection;
import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Pattern;

/**
 * One label name of a metric and the bound on its values: either a declared set ({@link #oneOf}) or a cap on how
 * many distinct values are kept ({@link #capped}). A value outside the set, or past the cap, is counted as
 * {@value #OTHER}, and the registry's fold counter rises. So is a value no label keeps at all: {@code null}, empty,
 * longer than {@value #MAX_VALUE_LENGTH} characters, or holding a control character. The value {@value #OTHER}
 * itself is always kept and takes no place under a cap.
 *
 * <p>A label is a description and holds no state: each metric keeps its own values, so one {@code Label} can be
 * passed to several metrics.
 */
public final class Label {

    /** The value every value a label does not keep is counted under. */
    public static final String OTHER = "other";

    /** The longest value kept, in characters. */
    public static final int MAX_VALUE_LENGTH = 128;

    /** The most values a declared set or a cap may name. */
    public static final int MAX_VALUES = 1024;

    private static final Pattern NAME = Pattern.compile("[a-z][a-z0-9_]{0,63}");

    private final String name;
    private final Set<String> declared;
    private final int cap;

    private Label(String name, Set<String> declared, int cap) {
        this.name = name;
        this.declared = declared;
        this.cap = cap;
    }

    /**
     * A label whose values are a declared set; any other value is counted as {@value #OTHER}.
     *
     * @throws IllegalArgumentException for a bad name, no values, more than {@value #MAX_VALUES}, or a value no
     *                                  label keeps
     */
    public static Label oneOf(String name, String... values) {
        return oneOf(name, Arrays.asList(Objects.requireNonNull(values, "values")));
    }

    /** {@link #oneOf(String, String...)} over a collection, such as the codes a catalogue declares. */
    public static Label oneOf(String name, Collection<String> values) {
        checkName(name);
        Objects.requireNonNull(values, "values");
        if (values.isEmpty() || values.size() > MAX_VALUES) {
            throw new IllegalArgumentException("label " + name + " declares 1-" + MAX_VALUES + " values, not " + values.size());
        }
        Set<String> set = new TreeSet<>();
        for (String v : values) {
            if (!keepable(v)) {
                throw new IllegalArgumentException("label " + name + " declares a value no label keeps: " + v);
            }
            set.add(v);
        }
        return new Label(name, Set.copyOf(set), 0);
    }

    /**
     * A label that keeps the first {@code max} distinct values it sees and counts every later new value as
     * {@value #OTHER}. For values that come from data - a client id, a host - where no set can be declared.
     *
     * @throws IllegalArgumentException for a bad name or a cap outside 1-{@value #MAX_VALUES}
     */
    public static Label capped(String name, int max) {
        checkName(name);
        if (max < 1 || max > MAX_VALUES) {
            throw new IllegalArgumentException("label " + name + " caps at 1-" + MAX_VALUES + " values, not " + max);
        }
        return new Label(name, null, max);
    }

    public String name() {
        return this.name;
    }

    /** Whether the values are a declared set rather than capped. */
    public boolean isDeclared() {
        return this.declared != null;
    }

    /** The declared values, empty for a capped label. */
    public Set<String> declared() {
        return this.declared == null ? Set.of() : this.declared;
    }

    /** The cap, 0 for a declared label. */
    public int cap() {
        return this.cap;
    }

    /** The most distinct values this label can take, {@value #OTHER} included. */
    int maxValues() {
        return (this.declared == null ? this.cap : this.declared.size()) + 1;
    }

    /** A value a label can keep: 1-{@value #MAX_VALUE_LENGTH} characters, none of them a control character. */
    static boolean keepable(String value) {
        if (value == null || value.isEmpty() || value.length() > MAX_VALUE_LENGTH) {
            return false;
        }
        for (int i = 0; i < value.length(); i++) {
            if (Character.isISOControl(value.charAt(i))) {
                return false;
            }
        }
        return true;
    }

    static void checkName(String name) {
        if (name == null || !NAME.matcher(name).matches() || "le".equals(name) || "quantile".equals(name)) {
            throw new IllegalArgumentException("a label name is 1-64 of a-z, 0-9 and '_', starting with a letter, and not le or quantile: " + name);
        }
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof Label l && l.name.equals(this.name) && l.cap == this.cap && Objects.equals(l.declared, this.declared);
    }

    @Override
    public int hashCode() {
        return Objects.hash(this.name, this.declared, this.cap);
    }

    @Override
    public String toString() {
        return this.declared == null ? this.name + " (capped at " + this.cap + ")" : this.name + " " + new TreeSet<>(this.declared);
    }
}
