/*
 * A small RFC 8259 reader and canonical writer, so the model needs no JSON library.
 */
package com.pingidentity.ps.oidf.rar.model;

import java.math.BigDecimal;
import java.math.BigInteger;
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
 * control character inside a string is refused, a Unicode escape takes ASCII hex digits only, a
 * string holding half a surrogate pair is refused (no UTF-8 text can carry it, so two such names would
 * hash alike), and nesting deeper than {@link #MAX_NESTING} or a number literal longer than
 * {@link #MAX_NUMBER_LITERAL} is refused as {@link TooLarge} before the recursion or the decimal
 * arithmetic costs anything. The semantic size limits on details ({@link Limits}) are applied by the
 * model on whatever it is given, parsed here or elsewhere. Messages name offsets, and the one name a
 * message carries is quoted through {@link RarModelException#quote}, so a request cannot write a line
 * of its own into a log.
 *
 * <p>The writer is canonical: object members in code-unit order of their names, no whitespace, numbers
 * as plain decimals with trailing zeros stripped ({@code 5000.0} and {@code 5E+3} both write as
 * {@code 5000}). Two values with the same meaning write to the same text, which is what the model
 * fingerprint and structural equality rest on. A number of more than {@link Limits#MAX_DIGITS} digits
 * written out is refused rather than written: {@code 1e999999999} is eleven characters to send and a
 * billion digits to write.
 */
public final class Json {

    /** Deeper nesting than this is refused by the reader. The model's own depth limit is lower. */
    public static final int MAX_NESTING = 32;
    /**
     * A longer number literal than this is refused by the reader, before it is read as a decimal: the work
     * on a long literal grows faster than its length (the review measured 8.4 s for a 100 KB one). The
     * model's own limit on a number, {@link Limits#MAX_DIGITS}, is lower.
     */
    public static final int MAX_NUMBER_LITERAL = 128;

    /**
     * A refusal for size rather than syntax - nesting past {@link #MAX_NESTING}, a number literal past
     * {@link #MAX_NUMBER_LITERAL} - so a caller can report it as too large rather than as malformed.
     */
    public static final class TooLarge extends IllegalArgumentException {
        TooLarge(String message) {
            super(message);
        }
    }

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
     * @throws IllegalArgumentException for any other Java type, a number with no finite decimal value, or
     *                                  one of more than {@link Limits#MAX_DIGITS} digits written out
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
     * {@link BigDecimal}s under {@link Object#equals}. Refused: what {@link #exact} refuses, and a number
     * of more than {@link Limits#MAX_DIGITS} digits written out, which is checked before any arithmetic
     * (stripping the zeros of a long number is quadratic, and writing {@code 1e999999999} out is a
     * gigabyte).
     */
    static BigDecimal decimal(Number n) {
        BigDecimal d = exact(n);
        if (Limits.digits(d) > Limits.MAX_DIGITS) {
            throw new IllegalArgumentException("a number of more than " + Limits.MAX_DIGITS + " digits");
        }
        d = d.stripTrailingZeros();
        // stripTrailingZeros keeps zero as 0E-n or 0E+n; one zero is enough.
        return d.signum() == 0 ? BigDecimal.ZERO : d;
    }

    /**
     * A number as the decimal it denotes, scale unchanged and nothing computed from its digits, so any
     * size is cheap here. The classes are the ones JSON parsers produce - {@link BigDecimal},
     * {@link BigInteger}, {@link Long}, {@link Integer}, {@link Short}, {@link Byte}, {@link Double},
     * {@link Float}; any other {@link Number} is refused, as is a {@code double} with no finite value.
     */
    static BigDecimal exact(Number n) {
        if (n instanceof BigDecimal b) {
            return b;
        }
        if (n instanceof BigInteger b) {
            return new BigDecimal(b);
        }
        if (n instanceof Long || n instanceof Integer || n instanceof Short || n instanceof Byte) {
            return BigDecimal.valueOf(n.longValue());
        }
        if (n instanceof Double || n instanceof Float) {
            double v = n.doubleValue();
            if (Double.isNaN(v) || Double.isInfinite(v)) {
                throw new IllegalArgumentException("not a finite number");
            }
            return new BigDecimal(n.toString());
        }
        throw new IllegalArgumentException("not a JSON number (" + n.getClass().getName() + ")");
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
                throw error("unexpected character " + RarModelException.quote(String.valueOf(c)));
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
                throw error("duplicate member name " + RarModelException.quote(name));
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
            throw new TooLarge("JSON: nesting deeper than " + MAX_NESTING + " at offset " + pos);
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
                if (!wellFormed(out)) {
                    throw error("a string holding half a surrogate pair");
                }
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
                        int code = 0;
                        for (int i = 0; i < 4; i++) {
                            int digit = hexDigit(text.charAt(pos + i));
                            if (digit < 0) {
                                throw error("bad \\u escape");
                            }
                            code = code * 16 + digit;
                        }
                        out.append((char) code);
                        pos += 4;
                    }
                    default -> throw error("bad escape");
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
        if (pos - start > MAX_NUMBER_LITERAL) {
            throw new TooLarge("JSON: a number longer than " + MAX_NUMBER_LITERAL + " characters at offset " + start);
        }
        try {
            return new BigDecimal(text.substring(start, pos));
        } catch (NumberFormatException e) {
            // The grammar held; only an exponent past the range of an int is left to refuse.
            throw error("a number whose exponent is out of range");
        }
    }

    /** An ASCII hex digit's value, or -1: {@link Character#digit} would take fullwidth and Arabic-Indic digits too. */
    private static int hexDigit(char c) {
        if (c >= '0' && c <= '9') {
            return c - '0';
        }
        if (c >= 'a' && c <= 'f') {
            return c - 'a' + 10;
        }
        if (c >= 'A' && c <= 'F') {
            return c - 'A' + 10;
        }
        return -1;
    }

    /** Whether every surrogate in the text is half of a pair, in order: what UTF-8 can carry. */
    static boolean wellFormed(CharSequence s) {
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (Character.isHighSurrogate(c) && i + 1 < s.length() && Character.isLowSurrogate(s.charAt(i + 1))) {
                i++;
            } else if (Character.isSurrogate(c)) {
                return false;
            }
        }
        return true;
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
