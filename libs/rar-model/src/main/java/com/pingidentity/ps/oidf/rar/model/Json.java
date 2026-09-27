/*
 * A small RFC 8259 reader and canonical writer, so the model needs no JSON library.
 */
package com.pingidentity.ps.oidf.rar.model;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * JSON text to plain Java values and back, with no library behind it.
 *
 * <p>This library is JDK-only on purpose: the RAR plugin shades and relocates everything it bundles, and
 * the servlets borrow jose4j and Jackson from PingFederate's own classpath, so a JSON dependency here
 * would be a third copy in one of them. What the reader returns is the shape every caller already
 * handles - {@link Map} (insertion-ordered), {@link List}, {@link String}, {@link BigDecimal},
 * {@link Boolean} and Java {@code null} for JSON {@code null} - so a detail parsed by PingFederate,
 * jose4j or Jackson and one parsed here look the same to the model. Numbers are kept as
 * {@link BigDecimal}: an amount compared as a {@code double} is the class of bug this library exists
 * to close.
 *
 * <p>The reader is strict where it matters: a duplicate member name is refused (two {@code actions}
 * members in one detail is how a second, unexamined value gets past a check that read the first), a
 * control character inside a string is refused, and nesting deeper than {@link #MAX_NESTING} is refused
 * before the recursion gets anywhere near the stack. The semantic size limits on details
 * ({@link Limits}) are applied by the model on whatever it is given, parsed here or elsewhere.
 *
 * <p>The writer is canonical: object members in code-unit order of their names, no whitespace, numbers
 * as plain decimals with trailing zeros stripped ({@code 5000.0} and {@code 5E+3} both write as
 * {@code 5000}). Two values with the same meaning write to the same text, which is what the model
 * fingerprint and structural equality rest on.
 */
public final class Json {

    /** Deeper nesting than this is refused by the reader. The model's own depth limit is lower. */
    public static final int MAX_NESTING = 32;

    private final String text;
    private int pos;
    private int nesting;

    private Json(String text) {
        this.text = text;
    }

    /**
     * Parses one JSON text.
     *
     * @return a {@link Map}, {@link List}, {@link String}, {@link BigDecimal}, {@link Boolean} or {@code null}
     * @throws IllegalArgumentException when the text is not one well-formed JSON value
     */
    public static Object parse(String text) {
        if (text == null) {
            throw new IllegalArgumentException("JSON text is null");
        }
        Json p = new Json(text);
        p.skipWhitespace();
        Object value = p.readValue();
        p.skipWhitespace();
        if (p.pos != text.length()) {
            throw p.error("trailing content after the JSON value");
        }
        return value;
    }

    /**
     * Writes a value as canonical JSON: members sorted by name, no whitespace, plain decimals.
     *
     * @param value a {@link Map} with String keys, a {@link List}, {@link String}, {@link Number},
     *              {@link Boolean} or {@code null}, nested to any depth
     * @throws IllegalArgumentException for any other Java type, or a number with no finite decimal value
     */
    public static String write(Object value) {
        StringBuilder out = new StringBuilder();
        write(value, out);
        return out.toString();
    }

    /**
     * A deep copy of a JSON value tree: new maps (insertion order kept) and lists, scalars shared.
     * What the model hands back never aliases a ceiling or a candidate the caller still holds.
     */
    public static Object copy(Object value) {
        if (value instanceof Map<?, ?> m) {
            Map<String, Object> out = new LinkedHashMap<>();
            for (Map.Entry<?, ?> e : m.entrySet()) {
                out.put((String) e.getKey(), copy(e.getValue()));
            }
            return out;
        }
        if (value instanceof List<?> l) {
            List<Object> out = new ArrayList<>(l.size());
            for (Object item : l) {
                out.add(copy(item));
            }
            return out;
        }
        return value;
    }

    private static void write(Object value, StringBuilder out) {
        if (value == null) {
            out.append("null");
        } else if (value instanceof String s) {
            writeString(s, out);
        } else if (value instanceof Boolean b) {
            out.append(b ? "true" : "false");
        } else if (value instanceof Number n) {
            out.append(decimal(n).toPlainString());
        } else if (value instanceof Map<?, ?> m) {
            TreeMap<String, Object> sorted = new TreeMap<>();
            for (Map.Entry<?, ?> e : m.entrySet()) {
                if (!(e.getKey() instanceof String key)) {
                    throw new IllegalArgumentException("object member names must be strings");
                }
                sorted.put(key, e.getValue());
            }
            out.append('{');
            boolean first = true;
            for (Map.Entry<String, Object> e : sorted.entrySet()) {
                if (!first) {
                    out.append(',');
                }
                first = false;
                writeString(e.getKey(), out);
                out.append(':');
                write(e.getValue(), out);
            }
            out.append('}');
        } else if (value instanceof List<?> l) {
            out.append('[');
            boolean first = true;
            for (Object item : l) {
                if (!first) {
                    out.append(',');
                }
                first = false;
                write(item, out);
            }
            out.append(']');
        } else {
            throw new IllegalArgumentException("not a JSON value: " + value.getClass().getName());
        }
    }

    /**
     * A number as the decimal it denotes, trailing zeros stripped so that equal values are equal
     * {@link BigDecimal}s under {@link Object#equals}. A {@code double} without a finite value is refused.
     */
    static BigDecimal decimal(Number n) {
        BigDecimal d;
        if (n instanceof BigDecimal b) {
            d = b;
        } else if (n instanceof Double || n instanceof Float) {
            double v = n.doubleValue();
            if (Double.isNaN(v) || Double.isInfinite(v)) {
                throw new IllegalArgumentException("not a finite number: " + n);
            }
            d = new BigDecimal(n.toString());
        } else {
            d = new BigDecimal(n.toString());
        }
        d = d.stripTrailingZeros();
        // stripTrailingZeros keeps zero as 0E-n or 0E+n; one zero is enough.
        return d.signum() == 0 ? BigDecimal.ZERO : d;
    }

    private static void writeString(String s, StringBuilder out) {
        out.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"' -> out.append("\\\"");
                case '\\' -> out.append("\\\\");
                case '\n' -> out.append("\\n");
                case '\r' -> out.append("\\r");
                case '\t' -> out.append("\\t");
                case '\b' -> out.append("\\b");
                case '\f' -> out.append("\\f");
                default -> {
                    if (c < 0x20) {
                        out.append(String.format("\\u%04x", (int) c));
                    } else {
                        out.append(c);
                    }
                }
            }
        }
        out.append('"');
    }

    // ---- reader ----

    private Object readValue() {
        if (pos >= text.length()) {
            throw error("unexpected end of JSON text");
        }
        char c = text.charAt(pos);
        switch (c) {
            case '{':
                return readObject();
            case '[':
                return readArray();
            case '"':
                return readString();
            case 't':
                expectLiteral("true");
                return Boolean.TRUE;
            case 'f':
                expectLiteral("false");
                return Boolean.FALSE;
            case 'n':
                expectLiteral("null");
                return null;
            default:
                if (c == '-' || (c >= '0' && c <= '9')) {
                    return readNumber();
                }
                throw error("unexpected character '" + c + "'");
        }
    }

    private Map<String, Object> readObject() {
        enter();
        pos++; // {
        Map<String, Object> out = new LinkedHashMap<>();
        skipWhitespace();
        if (peek() == '}') {
            pos++;
            nesting--;
            return out;
        }
        while (true) {
            skipWhitespace();
            if (peek() != '"') {
                throw error("expected a member name");
            }
            String name = readString();
            skipWhitespace();
            if (peek() != ':') {
                throw error("expected ':' after the member name");
            }
            pos++;
            skipWhitespace();
            Object value = readValue();
            if (out.containsKey(name)) {
                throw error("duplicate member name '" + name + "'");
            }
            out.put(name, value);
            skipWhitespace();
            char c = peek();
            if (c == ',') {
                pos++;
            } else if (c == '}') {
                pos++;
                nesting--;
                return out;
            } else {
                throw error("expected ',' or '}' in an object");
            }
        }
    }

    private List<Object> readArray() {
        enter();
        pos++; // [
        List<Object> out = new ArrayList<>();
        skipWhitespace();
        if (peek() == ']') {
            pos++;
            nesting--;
            return out;
        }
        while (true) {
            skipWhitespace();
            out.add(readValue());
            skipWhitespace();
            char c = peek();
            if (c == ',') {
                pos++;
            } else if (c == ']') {
                pos++;
                nesting--;
                return out;
            } else {
                throw error("expected ',' or ']' in an array");
            }
        }
    }

    private void enter() {
        if (++nesting > MAX_NESTING) {
            throw error("nesting deeper than " + MAX_NESTING);
        }
    }

    private String readString() {
        pos++; // opening quote
        StringBuilder out = new StringBuilder();
        while (true) {
            if (pos >= text.length()) {
                throw error("unterminated string");
            }
            char c = text.charAt(pos++);
            if (c == '"') {
                return out.toString();
            }
            if (c == '\\') {
                if (pos >= text.length()) {
                    throw error("unterminated escape");
                }
                char e = text.charAt(pos++);
                switch (e) {
                    case '"' -> out.append('"');
                    case '\\' -> out.append('\\');
                    case '/' -> out.append('/');
                    case 'b' -> out.append('\b');
                    case 'f' -> out.append('\f');
                    case 'n' -> out.append('\n');
                    case 'r' -> out.append('\r');
                    case 't' -> out.append('\t');
                    case 'u' -> {
                        if (pos + 4 > text.length()) {
                            throw error("truncated \\u escape");
                        }
                        String hex = text.substring(pos, pos + 4);
                        for (int i = 0; i < 4; i++) {
                            if (Character.digit(hex.charAt(i), 16) < 0) {
                                throw error("bad \\u escape");
                            }
                        }
                        out.append((char) Integer.parseInt(hex, 16));
                        pos += 4;
                    }
                    default -> throw error("bad escape '\\" + e + "'");
                }
            } else if (c < 0x20) {
                throw error("control character in a string");
            } else {
                out.append(c);
            }
        }
    }

    private BigDecimal readNumber() {
        int start = pos;
        if (peek() == '-') {
            pos++;
        }
        if (peek() == '0') {
            pos++;
        } else if (peek() >= '1' && peek() <= '9') {
            while (peek() >= '0' && peek() <= '9') {
                pos++;
            }
        } else {
            throw error("bad number");
        }
        if (peek() == '.') {
            pos++;
            if (!(peek() >= '0' && peek() <= '9')) {
                throw error("bad number: no digits after '.'");
            }
            while (peek() >= '0' && peek() <= '9') {
                pos++;
            }
        }
        if (peek() == 'e' || peek() == 'E') {
            pos++;
            if (peek() == '+' || peek() == '-') {
                pos++;
            }
            if (!(peek() >= '0' && peek() <= '9')) {
                throw error("bad number: no digits in the exponent");
            }
            while (peek() >= '0' && peek() <= '9') {
                pos++;
            }
        }
        return new BigDecimal(text.substring(start, pos));
    }

    private void expectLiteral(String literal) {
        if (!text.startsWith(literal, pos)) {
            throw error("bad literal");
        }
        pos += literal.length();
    }

    private void skipWhitespace() {
        while (pos < text.length()) {
            char c = text.charAt(pos);
            if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
                pos++;
            } else {
                return;
            }
        }
    }

    /** The current character, or NUL at the end - which no grammar rule accepts, so every caller fails cleanly. */
    private char peek() {
        return pos < text.length() ? text.charAt(pos) : '\0';
    }

    private IllegalArgumentException error(String what) {
        return new IllegalArgumentException("JSON: " + what + " at offset " + pos);
    }
}
