/*
 * The size limits every authorization_details list is held to before anything reads it.
 */
package com.pingidentity.ps.oidf.rar.model;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Size limits on an {@code authorization_details} list, applied to ceilings and candidates alike and
 * to values from any parser. A list is refused as {@link RarModelException.Reason#TOO_LARGE} when it
 * has more than {@link #MAX_DETAILS} entries, when any container sits deeper than {@link #MAX_DEPTH}
 * (the detail object itself is depth 1), when an array or object has more than {@link #MAX_ENTRIES}
 * members, when a string or member name is longer than {@link #MAX_STRING} characters, or when a number
 * has more than {@link #MAX_DIGITS} digits written out as a plain decimal. A value that is not a JSON
 * value at all - a list entry that is not an object, a member name that is not a string, a Java object
 * of some other class, a {@code double} with no finite value - is
 * {@link RarModelException.Reason#MALFORMED}.
 *
 * <p>The first four numbers are the plan's (S-1). The digit limit is this library's: a string's cost is
 * its length, but a number's is not - {@code 1e999999999} is eleven characters and a billion digits the
 * moment anything writes it out or strips its zeros - so a number is measured by what it would write,
 * without writing it. Every value's cost is then bounded, and the model's work is linear in the size of
 * the lists it is given; {@link #MAX_TEXT} bounds that size for text {@link RarModels#parseDetails}
 * reads, and a caller that parses the text itself bounds it there.
 */
public final class Limits {

    /** The most entries an {@code authorization_details} array may have. */
    public static final int MAX_DETAILS = 16;
    /** The deepest a container may sit; the detail object is depth 1, a value nested in it depth 2. */
    public static final int MAX_DEPTH = 8;
    /** The most members an array or object may have. */
    public static final int MAX_ENTRIES = 256;
    /** The longest string, or member name, in characters. */
    public static final int MAX_STRING = 2048;
    /**
     * The most digits a number may have written out as a plain decimal, the zeros its exponent stands
     * for included: {@code 5E+3} is four ({@code 5000}), {@code 0.05} three. Generous for an amount, with
     * room for an identifier sent as a number.
     */
    public static final int MAX_DIGITS = 64;
    /** The longest {@code authorization_details} text {@link RarModels#parseDetails} reads, in characters. */
    public static final int MAX_TEXT = 262_144;

    private Limits() {
    }

    /**
     * Checks a list's shape and sizes.
     *
     * @param details the list, as parsed by anything
     * @param side    which list this is, for the message ({@code ceiling}, {@code candidate}, ...)
     * @return the same entries as objects
     */
    @SuppressWarnings("unchecked")
    static List<Map<String, Object>> check(List<?> details, String side) throws RarModelException {
        if (details == null) {
            throw RarModelException.malformed(side + " authorization_details is null");
        }
        if (details.size() > MAX_DETAILS) {
            throw RarModelException.tooLarge(side + " authorization_details has more than " + MAX_DETAILS + " entries");
        }
        List<Map<String, Object>> out = new ArrayList<>(details.size());
        int i = 0;
        for (Object item : details) {
            String where = side + " authorization_details[" + i + "]";
            if (!(item instanceof Map)) {
                throw RarModelException.malformed(where + " is not a JSON object");
            }
            walk(item, 1, where);
            out.add((Map<String, Object>) item);
            i++;
        }
        return out;
    }

    /** Walks one value, refusing anything past the limits or not a JSON value. */
    static void walk(Object value, int depth, String where) throws RarModelException {
        if (value == null || value instanceof Boolean) {
            return;
        }
        if (value instanceof String s) {
            if (s.length() > MAX_STRING) {
                throw RarModelException.tooLarge(where + " is a string longer than " + MAX_STRING);
            }
            return;
        }
        if (value instanceof Number n) {
            BigDecimal d;
            try {
                d = Json.exact(n);
            } catch (IllegalArgumentException e) {
                throw RarModelException.malformed(where + " is " + e.getMessage());
            }
            if (digits(d) > MAX_DIGITS) {
                throw RarModelException.tooLarge(where + " is a number of more than " + MAX_DIGITS + " digits");
            }
            return;
        }
        if (depth > MAX_DEPTH) {
            throw RarModelException.tooLarge(where + " is nested deeper than " + MAX_DEPTH);
        }
        if (value instanceof Map<?, ?> m) {
            if (m.size() > MAX_ENTRIES) {
                throw RarModelException.tooLarge(where + " has more than " + MAX_ENTRIES + " members");
            }
            for (Map.Entry<?, ?> e : m.entrySet()) {
                if (!(e.getKey() instanceof String key)) {
                    throw RarModelException.malformed(where + " has a member name that is not a string");
                }
                if (key.length() > MAX_STRING) {
                    throw RarModelException.tooLarge(where + " has a member name longer than " + MAX_STRING);
                }
                walk(e.getValue(), depth + 1, where + "." + RarModelException.quote(key));
            }
            return;
        }
        if (value instanceof List<?> l) {
            if (l.size() > MAX_ENTRIES) {
                throw RarModelException.tooLarge(where + " has more than " + MAX_ENTRIES + " elements");
            }
            int i = 0;
            for (Object item : l) {
                walk(item, depth + 1, where + "[" + i + "]");
                i++;
            }
            return;
        }
        throw RarModelException.malformed(where + " is not a JSON value (" + value.getClass().getName() + ")");
    }

    /**
     * How many digits a number has written out as a plain decimal: {@code 1E+3} four, {@code 0.05} three,
     * {@code 12.5} three. Measured from the scale and the unscaled value's size, never by writing it; past
     * {@link #MAX_DIGITS} the answer is only "more", so a number of a billion digits costs nothing to measure.
     */
    static int digits(BigDecimal d) {
        int scale = d.scale();
        // A decimal digit carries less than four bits, so more than 4 * MAX_DIGITS bits is more than
        // MAX_DIGITS digits; within that, precision() is cheap. Past the scale bounds the count is over too.
        if (scale > MAX_DIGITS || scale < -MAX_DIGITS || d.unscaledValue().bitLength() > 4 * MAX_DIGITS) {
            return MAX_DIGITS + 1;
        }
        int precision = d.precision();
        return scale <= 0 ? precision - scale : Math.max(precision, scale + 1);
    }
}
