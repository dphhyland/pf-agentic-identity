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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
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
                "1e+", "+1", "tru", "nul", "fals", "{} x", "[1] 2", "NaN", "Infinity", "'x'", "\"esc\\", "{\"a\":1,\"a\":2}")) {
            IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> Json.parse(bad), bad);
            assertTrue(e.getMessage().startsWith("JSON: "), e.getMessage());
        }
        assertThrows(IllegalArgumentException.class, () -> Json.parse(null));
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
        assertThrows(IllegalArgumentException.class, () -> Json.parse("[" + deep + "]"));
        StringBuilder objects = new StringBuilder();
        for (int i = 0; i <= Json.MAX_NESTING; i++) {
            objects.append("{\"a\":");
        }
        assertThrows(IllegalArgumentException.class, () -> Json.parse(objects + "1" + "}".repeat(Json.MAX_NESTING + 1)));
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
        Map<Object, Object> badKey = new HashMap<>();
        badKey.put(1, "x");
        assertThrows(IllegalArgumentException.class, () -> Json.write(badKey));
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
