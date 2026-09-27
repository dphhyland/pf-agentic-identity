/*
 * The size limits every authorization_details list is held to before anything reads it.
 */
package com.pingidentity.ps.oidf.rar.model;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Size limits on an {@code authorization_details} list, applied to ceilings and candidates alike and
 * to values from any parser. A list is refused as {@link RarModelException.Reason#TOO_LARGE} when it
 * has more than {@link #MAX_DETAILS} entries, when any container sits deeper than {@link #MAX_DEPTH}
 * (the detail object itself is depth 1), when an array or object has more than {@link #MAX_ENTRIES}
 * members, or when a string or member name is longer than {@link #MAX_STRING} characters. A value that
 * is not a JSON value at all - a list entry that is not an object, a member name that is not a string,
 * a Java object of some other class, a {@code double} with no finite value - is
 * {@link RarModelException.Reason#MALFORMED}.
 *
 * <p>The numbers are the plan's (S-1): generous for any real request, small enough that the work a
 * request can cause is bounded before its type is even looked up.
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
            try {
                Json.decimal(n);
            } catch (IllegalArgumentException e) {
                throw RarModelException.malformed(where + " is " + e.getMessage());
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
                walk(e.getValue(), depth + 1, where + "." + key);
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
}
