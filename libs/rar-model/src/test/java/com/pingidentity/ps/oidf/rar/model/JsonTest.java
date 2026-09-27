/*
 * The reader is strict and the writer is canonical.
 */
package com.pingidentity.ps.oidf.rar.model;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.Test;

class JsonTest {

    @Test
    void readsEveryValueKind() {
        Object v = Json.parse(" {\"s\":\"a\\\"b\\\\c\\/\\b\\f\\n\\r\\t\\u00e9\\u0041\", \"n\":-12.50e1, \"t\":true, \"f\":false, "
                + "\"z\":null, \"a\":[1, \"x\", [], {}], \"o\":{\"k\":0}} ");
        Map<?, ?> m = (Map<?, ?>) v;
        assertEquals("a\"b\\c/\b\f\n\r\t\u00e9A", m.get("s"));
        assertEquals(new BigDecimal("-12.50e1"), m.get("n"));
        assertEquals(Boolean.TRUE, m.get("t"));
        assertEquals(Boolean.FALSE, m.get("f"));
        assertTrue(m.containsKey("z"));
        assertNull(m.get("z"));
        assertEquals(List.of(BigDecimal.ONE, "x", List.of(), Map.of()), m.get("a"));
        assertEquals(Map.of("k", BigDecimal.ZERO), m.get("o"));
        assertEquals(List.of("s", "n", "t", "f", "z", "a", "o"), new ArrayList<>(m.keySet()), "insertion order kept");
    }

    @Test
    void whitespaceIsTheFourRfc8259Allows() {
        assertEquals(List.of(BigDecimal.ONE), Json.parse(" \t\r\n[\t1\r]\n "));
        assertThrows(IllegalArgumentException.class, () -> Json.parse("\u000b[1]"), "vertical tab is not JSON whitespace");
        assertThrows(IllegalArgumentException.class, () -> Json.parse("\u00a0[1]"), "nor is a no-break space");
    }

    @Test
    void readsScalarsAtTheTopLevel() {
        assertEquals("x", Json.parse("\"x\""));
        assertEquals(new BigDecimal("0"), Json.parse("0"));
        assertEquals(new BigDecimal("0.5"), Json.parse("0.5"));
        assertEquals(new BigDecimal("1E+2"), Json.parse("1E+2"));
        assertEquals(new BigDecimal("1e-2"), Json.parse("1e-2"));
        assertEquals(Boolean.TRUE, Json.parse("true"));
        assertNull(Json.parse("null"));
    }

    @Test
    void refusesWhatTheGrammarDoesNotAllow() {
        for (String bad : Arrays.asList("", " ", "{", "[", "{\"a\"}", "{\"a\":}", "{\"a\":1,}", "[1,]", "[1 2]", "{\"a\":1 \"b\":2}",
                "{a:1}", "\"unterminated", "\"bad\\escape\"", "\"\\u12\"", "\"\\uZZZZ\"", "\"ctrl\u0001\"", "01", "-", "1.", ".5", "1e",
                "1e+", "+1", "tru", "nul", "fals", "{} x", "[1] 2", "NaN", "Infinity", "'x'", "\"esc\\", "{\"a\":1,\"a\":2}", "-a", "1.a", "1ea",
                "1e+a")) {
            IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> Json.parse(bad), bad);
            assertTrue(e.getMessage().startsWith("JSON: "), e.getMessage());
        }
        assertThrows(IllegalArgumentException.class, () -> Json.parse(null));
    }

    /** A Unicode escape takes ASCII hex digits, either case, and nothing Character.digit would also take. */
    @Test
    void unicodeEscapesTakeAsciiHexOnly() {
        assertEquals("\u00ff\u00FF\u0aBc", Json.parse("\"\\u00ff\\u00FF\\u0aBc\""));
        for (String digit : List.of("\u0660", "\uff10", "\u0966", "g", "G", "/", ":", "@", "`")) {
            String text = "\"\\u00" + digit + "1\"";
            IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> Json.parse(text), text);
            assertTrue(e.getMessage().startsWith("JSON: bad \\u escape"), e.getMessage());
        }
    }

    /** A string holding half a surrogate pair is refused, raw or escaped; a whole pair is a character like any other. */
    @Test
    void surrogatesComeInPairs() {
        assertEquals("\ud83d\ude00", Json.parse("\"\\ud83d\\ude00\""));
        assertEquals("a\ud83d\ude00b", Json.parse("\"a\ud83d\ude00b\""));
        for (String bad : List.of("\"\\ud800\"", "\"\\ud800x\"", "\"\\udc00\"", "\"x\\udfff\"", "\"\\ude00\\ud83d\"",
                "\"\ud800\"", "{\"\\ud801\":1}")) {
            IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> Json.parse(bad), bad);
            assertTrue(e.getMessage().startsWith("JSON: a string holding half a surrogate pair"), e.getMessage());
        }
        assertTrue(Json.wellFormed("plain"));
        assertTrue(Json.wellFormed(""));
    }

    /** A number literal is read as a decimal only when it is short; past the cap it is refused as too large. */
    @Test
    void numberLiteralsHaveACap() {
        String longest = "1".repeat(Json.MAX_NUMBER_LITERAL);
        assertEquals(new BigDecimal(longest), Json.parse(longest));
        Json.TooLarge e = assertThrows(Json.TooLarge.class, () -> Json.parse("[" + longest + "1]"));
        assertEquals("JSON: a number longer than 128 characters at offset 1", e.getMessage());
        assertThrows(Json.TooLarge.class, () -> Json.parse("-0." + "0".repeat(126)));
        assertThrows(Json.TooLarge.class, () -> Json.parse("1" + "0".repeat(100_000)));
        assertEquals(new BigDecimal("1e999999999"), Json.parse("1e999999999"), "short to send, and read lazily: the model refuses it");
        assertEquals(Integer.MIN_VALUE, ((BigDecimal) Json.parse("1e2147483648")).scale(), "the last exponent a scale can hold");
        IllegalArgumentException range = assertThrows(IllegalArgumentException.class, () -> Json.parse("1e2147483649"));
        assertEquals("JSON: a number whose exponent is out of range at offset 12", range.getMessage());
        assertThrows(IllegalArgumentException.class, () -> Json.parse("1e-2147483649"));
    }

    /** What the reader says about a request's text is quoted and cut, so a member name cannot forge a log line. */
    @Test
    void messagesQuoteWhatTheyRepeat() {
        String name = "x\n2026-09-27 INFO forged" + "y".repeat(5000);
        String text = "{\"" + name.replace("\n", "\\n") + "\":1,\"" + name.replace("\n", "\\n") + "\":2}";
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> Json.parse(text));
        assertTrue(e.getMessage().startsWith("JSON: duplicate member name 'x\\u000a2026-09-27 INFO forged"), e.getMessage());
        assertTrue(e.getMessage().length() < 140, e.getMessage());
        assertTrue(e.getMessage().indexOf('\n') < 0);
        IllegalArgumentException c = assertThrows(IllegalArgumentException.class, () -> Json.parse("\u0007"));
        assertEquals("JSON: unexpected character '\\u0007' at offset 0", c.getMessage());
        IllegalArgumentException esc = assertThrows(IllegalArgumentException.class, () -> Json.parse("\"\\\n\""));
        assertEquals("JSON: bad escape at offset 3", esc.getMessage());
    }

    @Test
    void refusesNestingPastTheCap() {
        StringBuilder deep = new StringBuilder();
        for (int i = 0; i < Json.MAX_NESTING; i++) {
            deep.append('[');
        }
        for (int i = 0; i < Json.MAX_NESTING; i++) {
            deep.append(']');
        }
        Json.parse(deep.toString());
        assertThrows(Json.TooLarge.class, () -> Json.parse("[" + deep + "]"));
        StringBuilder objects = new StringBuilder();
        for (int i = 0; i <= Json.MAX_NESTING; i++) {
            objects.append("{\"a\":");
        }
        assertThrows(Json.TooLarge.class, () -> Json.parse(objects + "1" + "}".repeat(Json.MAX_NESTING + 1)));
    }

    @Test
    void writesCanonically() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("z", List.of(new BigDecimal("5000.0"), new BigDecimal("5E+3"), 5000L, 5000.0d, 5000.0f, (short) 1, (byte) 1, 1));
        m.put("a", "q\"\\\n\r\t\b\f\u0001\u00e9");
        Map<String, Object> withNull = new HashMap<>();
        withNull.put("b", true);
        withNull.put("a", null);
        m.put("m", withNull);
        m.put("e", List.of());
        m.put("o", Map.of());
        assertEquals("{\"a\":\"q\\\"\\\\\\n\\r\\t\\b\\f\\u0001\u00e9\",\"e\":[],\"m\":{\"a\":null,\"b\":true},\"o\":{},"
                + "\"z\":[5000,5000,5000,5000,5000,1,1,1]}", Json.write(m));
        assertEquals("0", Json.write(new BigDecimal("0.000")));
        assertEquals("0", Json.write(new BigDecimal("0E+3")));
        assertEquals("-1.5", Json.write(new BigDecimal("-1.50")));
        assertEquals("123.5", Json.write(new BigDecimal("123.50")));
        assertEquals("null", Json.write(null));
        assertEquals("false", Json.write(false));
    }

    @Test
    void writerRefusesWhatIsNotJson() {
        assertThrows(IllegalArgumentException.class, () -> Json.write(new Object()));
        assertThrows(IllegalArgumentException.class, () -> Json.write(Double.NaN));
        assertThrows(IllegalArgumentException.class, () -> Json.write(Double.POSITIVE_INFINITY));
        assertThrows(IllegalArgumentException.class, () -> Json.write(Float.NaN));
        assertEquals("not a JSON number (java.util.concurrent.atomic.AtomicLong)",
                assertThrows(IllegalArgumentException.class, () -> Json.write(new AtomicLong(1))).getMessage());
        Map<Object, Object> badKey = new HashMap<>();
        badKey.put(1, "x");
        assertThrows(IllegalArgumentException.class, () -> Json.write(badKey));
    }

    /** The writer refuses a number it would have to write out at length, before any arithmetic on it. */
    @Test
    void writerRefusesNumbersPastTheDigitLimit() {
        assertEquals("1" + "0".repeat(63), Json.write(new BigDecimal("1E+63")));
        assertEquals("9".repeat(64), Json.write(new BigInteger("9".repeat(64))));
        for (Object n : List.of(new BigDecimal("1e999999999"), new BigDecimal("1e2147483647"), new BigDecimal("100e2147483647"),
                new BigDecimal("1E+64"), BigInteger.TEN.pow(64), 1e300d)) {
            IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> Json.write(List.of(n)), n.toString());
            assertEquals("a number of more than 64 digits", e.getMessage());
        }
    }

    @Test
    void exactKeepsTheScaleAndTakesTheParsersClasses() {
        assertEquals(new BigDecimal("5000.0"), Json.exact(new BigDecimal("5000.0")));
        assertEquals(new BigDecimal("12345678901234567890"), Json.exact(new BigInteger("12345678901234567890")));
        assertEquals(BigDecimal.valueOf(7), Json.exact(7L));
        assertEquals(BigDecimal.valueOf(7), Json.exact((short) 7));
        assertEquals(new BigDecimal("0.1"), Json.exact(0.1d));
        assertEquals(new BigDecimal("0.5"), Json.exact(0.5f));
        assertThrows(IllegalArgumentException.class, () -> Json.exact(Double.NEGATIVE_INFINITY));
        assertThrows(IllegalArgumentException.class, () -> Json.exact(Float.POSITIVE_INFINITY));
        assertThrows(IllegalArgumentException.class, () -> Json.exact(new AtomicLong(1)));
    }

    @Test
    void roundTripsThroughTheWriterAndReader() {
        String text = "{\"a\":[1,{\"b\":\"c\"},null,true],\"d\":\"\\u0000\"}";
        assertEquals(text, Json.write(Json.parse(text)));
    }

    @Test
    void copyIsDeepAndKeepsOrder() {
        Map<String, Object> inner = new LinkedHashMap<>();
        inner.put("b", 1);
        inner.put("a", List.of("x"));
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("inner", inner);
        m.put("s", "str");
        @SuppressWarnings("unchecked")
        Map<String, Object> copy = (Map<String, Object>) Json.copy(m);
        assertEquals(m, copy);
        assertNotSame(m, copy);
        assertNotSame(inner, copy.get("inner"));
        assertNotSame(inner.get("a"), ((Map<?, ?>) copy.get("inner")).get("a"));
        assertSame(m.get("s"), copy.get("s"));
        assertEquals(List.of("b", "a"), new ArrayList<>(((Map<?, ?>) copy.get("inner")).keySet()));
        assertNull(Json.copy(null));
    }
}
