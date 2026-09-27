/*
 * A type's fields: what the constructor refuses, and the four operations at the edges.
 */
package com.pingidentity.ps.oidf.rar.model;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.Test;

class TypeModelTest {

    private static Map<String, FieldRule> fields(Object... pairs) {
        Map<String, FieldRule> out = new LinkedHashMap<>();
        for (int i = 0; i < pairs.length; i += 2) {
            out.put((String) pairs[i], (FieldRule) pairs[i + 1]);
        }
        return out;
    }

    private static final TypeModel MODEL = new TypeModel("t", fields(
            "actions", FieldRule.of(Rule.SET),
            "amount", FieldRule.limit("currency"),
            "currency", FieldRule.of(Rule.EQUAL),
            "access", FieldRule.object(new TypeModel(null, fields("paths", FieldRule.of(Rule.SET), "mode", FieldRule.of(Rule.EQUAL)))),
            "secret", FieldRule.of(Rule.FORBIDDEN)));

    @Test
    void constructorRefusesWhatCannotWork() {
        assertThrows(IllegalArgumentException.class, () -> new TypeModel("t", fields(" ", FieldRule.of(Rule.SET))));
        assertThrows(IllegalArgumentException.class, () -> new TypeModel("t", fields("type", FieldRule.of(Rule.SET))));
        assertThrows(IllegalArgumentException.class, () -> new TypeModel(null, fields("type", FieldRule.of(Rule.SET))));
        assertThrows(IllegalArgumentException.class, () -> new TypeModel("t", fields("amount", FieldRule.limit("currency"))));
        assertThrows(IllegalArgumentException.class,
                () -> new TypeModel("t", fields("amount", FieldRule.limit("currency"), "currency", FieldRule.of(Rule.SET))));
        Map<String, FieldRule> nullName = new LinkedHashMap<>();
        nullName.put(null, FieldRule.of(Rule.SET));
        assertThrows(IllegalArgumentException.class, () -> new TypeModel("t", nullName));
        assertEquals("t", MODEL.type());
        assertEquals(List.of("actions", "amount", "currency", "access", "secret"), new ArrayList<>(MODEL.fields().keySet()));
        assertNull(MODEL.fields().get("access").nested().type());
    }

    @Test
    void checkSkipsTypeOnlyAtTheTopLevel() throws Exception {
        MODEL.check(Map.of("type", "t", "actions", List.of("a")), "d");
        RarModelException e = assertThrows(RarModelException.class,
                () -> MODEL.check(Map.of("type", "t", "access", Map.of("type", "x")), "d"));
        assertEquals(RarModelException.Reason.UNDECLARED_FIELD, e.reason());
        assertTrue(e.getMessage().startsWith("d.access carries 'type', which the object does not declare"), e.getMessage());
    }

    @Test
    void checkNamesTheOwnerOfAnUndeclaredField() {
        RarModelException e = assertThrows(RarModelException.class, () -> MODEL.check(Map.of("type", "t", "x", 1), "d"));
        assertEquals(RarModelException.Reason.UNDECLARED_FIELD, e.reason());
        assertEquals("d carries 'x', which type 't' does not declare", e.getMessage());
    }

    @Test
    void checkValuesLeavesThePairingToCheck() throws Exception {
        MODEL.checkValues(Map.of("amount", 1), "d");
        assertEquals(RarModelException.Reason.UNDECLARED_FIELD,
                assertThrows(RarModelException.class, () -> MODEL.checkValues(Map.of("x", 1), "d")).reason());
        assertEquals(RarModelException.Reason.MALFORMED,
                assertThrows(RarModelException.class, () -> MODEL.checkValues(Map.of("actions", "a"), "d")).reason());
    }

    @Test
    void checkPairsALimitWithItsUnit() throws Exception {
        MODEL.check(Map.of("currency", "EUR"), "d");
        MODEL.check(Map.of("amount", 1, "currency", "EUR"), "d");
        RarModelException e = assertThrows(RarModelException.class, () -> MODEL.check(Map.of("amount", 1), "d"));
        assertEquals(RarModelException.Reason.MALFORMED, e.reason());
        assertEquals("d.amount needs currency beside it", e.getMessage());
    }

    @Test
    void checkRefusesForbiddenAndMalformed() {
        assertEquals(RarModelException.Reason.MALFORMED,
                assertThrows(RarModelException.class, () -> MODEL.check(Map.of("secret", 1), "d")).reason());
        assertEquals(RarModelException.Reason.MALFORMED,
                assertThrows(RarModelException.class, () -> MODEL.check(Map.of("actions", "a"), "d")).reason());
    }

    @Test
    void containsAtTheEdges() {
        assertTrue(MODEL.contains(Map.of("type", "t"), Map.of("type", "t", "actions", List.of("x"))));
        assertFalse(MODEL.contains(Map.of("actions", List.of("x")), Map.of()));
        assertFalse(MODEL.contains(Map.of("actions", List.of("x")), Map.of("actions", List.of("y"))));
        assertTrue(MODEL.contains(Map.of("actions", List.of("x"), "currency", "EUR"), Map.of("actions", List.of("x"), "currency", "EUR")));
    }

    @Test
    void inheritFillsOmittedFieldsAndObjects() {
        Map<String, Object> ceiling = Map.of("type", "t", "actions", List.of("a"), "access", Map.of("paths", List.of("/a"), "mode", "r"));
        Map<String, Object> candidate = new LinkedHashMap<>(); // Map.of's iteration order is salted per JVM run
        candidate.put("type", "t");
        candidate.put("access", Map.of("paths", List.of("/a")));
        Map<String, Object> got = MODEL.inherit(ceiling, candidate);
        assertEquals(List.of("a"), got.get("actions"));
        assertEquals(Map.of("paths", List.of("/a"), "mode", "r"), got.get("access"));
        assertEquals(List.of("type", "access", "actions"), new ArrayList<>(got.keySet()), "the candidate's order, then inherited fields");
        assertEquals(ceiling.get("access"), MODEL.inherit(ceiling, Map.of("type", "t", "actions", List.of("a"))).get("access"));
        // a wrong-shaped object in the candidate is left for the check to refuse, not recursed into
        assertEquals("all", MODEL.inherit(ceiling, Map.of("type", "t", "access", "all")).get("access"));
        // a field the ceiling omits is not touched
        assertFalse(MODEL.inherit(Map.of("type", "t"), Map.of("type", "t")).containsKey("actions"));
        // inherited values are copies
        Map<String, Object> mutableCeiling = new LinkedHashMap<>();
        List<String> actions = new ArrayList<>(List.of("a"));
        mutableCeiling.put("actions", actions);
        Map<String, Object> inherited = MODEL.inherit(mutableCeiling, Map.of());
        actions.add("b");
        assertEquals(List.of("a"), inherited.get("actions"));
    }

    @Test
    void meetAtTheEdges() {
        Optional<Map<String, Object>> m = MODEL.meet(Map.of("type", "t", "actions", List.of("a", "b"), "currency", "EUR"),
                Map.of("type", "t", "actions", List.of("b"), "amount", 5, "currency", "EUR"));
        assertEquals(List.of("type", "actions", "amount", "currency"), new ArrayList<>(m.orElseThrow().keySet()));
        assertEquals("t", m.get().get("type"));
        assertEquals(List.of("b"), m.get().get("actions"));
        assertEquals(5, m.get().get("amount"));
        assertEquals(Optional.empty(), MODEL.meet(Map.of("currency", "EUR"), Map.of("currency", "USD")));
        TypeModel nested = MODEL.fields().get("access").nested();
        Optional<Map<String, Object>> n = nested.meet(Map.of("paths", List.of("/a")), Map.of("mode", "r"));
        assertFalse(n.orElseThrow().containsKey("type"), "a nested object has no type");
        assertEquals(Map.of("paths", List.of("/a"), "mode", "r"), n.get());
        assertEquals(Optional.of(Map.of()), nested.meet(Map.of(), Map.of()));
    }

    @Test
    void describeSortsFieldsByName() {
        assertEquals(List.of("access", "actions", "amount", "currency", "secret"), new ArrayList<>(MODEL.describeFields().keySet()));
        assertEquals("forbidden", MODEL.describeFields().get("secret"));
    }
}
