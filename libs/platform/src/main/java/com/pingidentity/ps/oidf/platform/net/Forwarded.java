/*
 * RFC 7239's Forwarded header, split into its elements and their parameters.
 */
package com.pingidentity.ps.oidf.platform.net;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * The {@code Forwarded} header of RFC 7239 section 4: "Forwarded = 1#forwarded-element", each element
 * "[ forwarded-pair ] *( ";" [ forwarded-pair ] )", each pair "token "=" value", and "value = token / quoted-string".
 * Several instances of the header are one list, element by element, in order. Commas and semicolons inside a quoted
 * string do not split, and a backslash in one quotes the next character (RFC 7230's quoted-pair). Parameter names are
 * case-insensitive (section 4: "The parameter names are case-insensitive"); a repeated one keeps its first value, and
 * an element or pair that cannot be read is kept as an element with no parameters, so the hops still line up.
 */
final class Forwarded {

    /** The header's name. */
    static final String NAME = "Forwarded";

    private Forwarded() {
    }

    /** One element: its parameters, by lower-case name, values unquoted. */
    record Element(Map<String, String> params) {
        /** The parameter's value, or {@code null}. */
        String get(String name) {
            return this.params.get(name);
        }
    }

    /** Every element of every instance of the header, in order. */
    static List<Element> parse(List<String> values) {
        List<Element> out = new ArrayList<>();
        for (String value : values) {
            for (String element : split(value, ',')) {
                if (!element.isBlank()) {
                    out.add(element(element));
                }
            }
        }
        return out;
    }

    private static Element element(String text) {
        Map<String, String> params = new LinkedHashMap<>();
        for (String pair : split(text, ';')) {
            int eq = pair.indexOf('=');
            if (eq <= 0) {
                continue;
            }
            String name = pair.substring(0, eq).trim().toLowerCase(Locale.ROOT);
            String value = unquote(pair.substring(eq + 1).trim());
            if (value != null && !name.isEmpty()) {
                params.putIfAbsent(name, value);
            }
        }
        return new Element(params);
    }

    /** The text of a token or a quoted string; {@code null} for a quoted string that does not close. */
    static String unquote(String value) {
        if (!value.startsWith("\"")) {
            return value;
        }
        StringBuilder out = new StringBuilder();
        for (int i = 1; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c == '\\' && i + 1 < value.length()) {
                out.append(value.charAt(++i));
            } else if (c == '"') {
                return i == value.length() - 1 ? out.toString() : null;
            } else {
                out.append(c);
            }
        }
        return null;
    }

    /** Splits at {@code separator} outside quoted strings. */
    static List<String> split(String text, char separator) {
        List<String> parts = new ArrayList<>();
        StringBuilder part = new StringBuilder();
        boolean quoted = false;
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (quoted && c == '\\' && i + 1 < text.length()) {
                part.append(c).append(text.charAt(++i));
                continue;
            }
            if (c == '"') {
                quoted = !quoted;
            } else if (c == separator && !quoted) {
                parts.add(part.toString());
                part.setLength(0);
                continue;
            }
            part.append(c);
        }
        parts.add(part.toString());
        return parts;
    }
}
