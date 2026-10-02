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
        assertEquals(Rule.STRING, new TypeModel("t", fields("amount", FieldRule.limit("currency"), "currency", FieldRule.of(Rule.STRING)))
                .fields().get("currency").rule(), "a unit may be a string");
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
        Map<?, ?> described = (Map<?, ?>) MODEL.describe().get("fields");
        assertEquals(List.of("access", "actions", "amount", "currency", "secret"), new ArrayList<>(described.keySet()));
        assertEquals("forbidden", described.get("secret"));
        assertFalse(MODEL.describe().containsKey("alternatives"), "no alternatives, no member");
        assertEquals(List.of(List.of(List.of("total"), List.of("amount", "currency"))), PAY.describe().get("alternatives"));
    }

    // ---- alternatives: one thing, two spellings ----

    /** A type that says its amount two ways, as payment_initiation does: {@code total}, or {@code amount} with {@code currency}. */
    private static final TypeModel PAY = new TypeModel("p", fields(
            "actions", FieldRule.of(Rule.SET),
            "total", FieldRule.of(Rule.AMOUNT),
            "amount", FieldRule.limit("currency"),
            "currency", FieldRule.of(Rule.STRING),
            "access", FieldRule.object(new TypeModel(null, fields("paths", FieldRule.of(Rule.SET))))),
            List.of(List.of(List.of("total"), List.of("amount", "currency"))));

    private static Map<String, Object> map(Object... pairs) {
        Map<String, Object> out = new LinkedHashMap<>();
        for (int i = 0; i < pairs.length; i += 2) {
            out.put((String) pairs[i], pairs[i + 1]);
        }
        return out;
    }

    private static final Map<String, Object> EUR100 = Map.of("amount", "100", "currency", "EUR");

    @Test
    void alternativesAreHeldToTheirShape() {
        Map<String, FieldRule> f = fields("a", FieldRule.of(Rule.SET), "b", FieldRule.of(Rule.SET), "c", FieldRule.of(Rule.SET),
                "l", FieldRule.limit("u"), "u", FieldRule.of(Rule.STRING));
        assertEquals("alternatives need two spellings or more", assertThrows(IllegalArgumentException.class,
                () -> new TypeModel("t", f, List.of(List.of(List.of("a"))))).getMessage());
        assertEquals("a spelling names no field", assertThrows(IllegalArgumentException.class,
                () -> new TypeModel("t", f, List.of(List.of(List.of("a"), List.of())))).getMessage());
        assertEquals("spelling field 'z' is not a field of the object", assertThrows(IllegalArgumentException.class,
                () -> new TypeModel("t", f, List.of(List.of(List.of("a"), List.of("z"))))).getMessage());
        assertEquals("field 'a' is in two spellings", assertThrows(IllegalArgumentException.class,
                () -> new TypeModel("t", f, List.of(List.of(List.of("a"), List.of("a", "b"))))).getMessage());
        assertEquals("field 'b' is in two spellings", assertThrows(IllegalArgumentException.class,
                () -> new TypeModel("t", f, List.of(List.of(List.of("a"), List.of("b")), List.of(List.of("b"), List.of("c"))))).getMessage());
        assertEquals("field 'l' and its unit_field 'u' must be in the same spelling", assertThrows(IllegalArgumentException.class,
                () -> new TypeModel("t", f, List.of(List.of(List.of("a"), List.of("l"))))).getMessage());
        assertEquals("field 'l' and its unit_field 'u' must be in the same spelling", assertThrows(IllegalArgumentException.class,
                () -> new TypeModel("t", f, List.of(List.of(List.of("l"), List.of("u"))))).getMessage());
        TypeModel ok = new TypeModel("t", f, List.of(List.of(List.of("a"), List.of("l", "u"))));
        assertEquals(List.of(List.of(List.of("a"), List.of("l", "u"))), ok.alternatives());
        assertEquals(List.of(), MODEL.alternatives());
    }

    @Test
    void aDetailUsesOneSpelling() throws Exception {
        PAY.check(map("type", "p", "total", EUR100), "d");
        PAY.check(map("type", "p", "amount", "5", "currency", "EUR"), "d");
        PAY.check(map("type", "p", "currency", "EUR"), "d");
        RarModelException e = assertThrows(RarModelException.class,
                () -> PAY.check(map("type", "p", "total", EUR100, "amount", "5", "currency", "EUR"), "d"));
        assertEquals(RarModelException.Reason.MALFORMED, e.reason());
        assertEquals("d carries 'total' and 'amount', two spellings of one thing; send one", e.getMessage());
        assertEquals(RarModelException.Reason.MALFORMED, assertThrows(RarModelException.class,
                () -> PAY.checkValues(map("currency", "EUR", "total", EUR100), "d")).reason(), "whichever comes first");
    }

    /** Groups are independent: one spelling from each is fine, two from one are not. */
    @Test
    void eachGroupIsItsOwn() throws Exception {
        TypeModel two = new TypeModel("t", fields("a", FieldRule.of(Rule.SET), "b", FieldRule.of(Rule.SET), "c", FieldRule.of(Rule.SET),
                "d", FieldRule.of(Rule.SET)), List.of(List.of(List.of("a"), List.of("b")), List.of(List.of("c"), List.of("d"))));
        two.check(map("type", "t", "a", List.of("x"), "c", List.of("x")), "d");
        two.check(map("type", "t", "b", List.of("x"), "d", List.of("x")), "d");
        assertEquals("d carries 'c' and 'd', two spellings of one thing; send one", assertThrows(RarModelException.class,
                () -> two.check(map("type", "t", "a", List.of("x"), "c", List.of("x"), "d", List.of("x")), "d")).getMessage());
        assertFalse(two.contains(map("a", List.of("x"), "c", List.of("x")), map("a", List.of("x"), "d", List.of("x"))));
        assertTrue(two.contains(map("a", List.of("x")), map("a", List.of("x"), "d", List.of("x"))));
    }

    @Test
    void aCeilingsSpellingBindsTheCandidate() {
        Map<String, Object> total = map("type", "p", "total", EUR100);
        Map<String, Object> flat = map("type", "p", "amount", "42", "currency", "EUR");
        Map<String, Object> currencyOnly = map("type", "p", "currency", "EUR");
        Map<String, Object> neither = map("type", "p", "actions", List.of("initiate"));
        assertTrue(PAY.contains(total, map("type", "p", "total", Map.of("amount", "5", "currency", "EUR"))));
        assertFalse(PAY.contains(total, flat), "the ceiling spells the amount as total; a flat amount is outside it");
        assertFalse(PAY.contains(flat, map("type", "p", "total", Map.of("amount", "5", "currency", "EUR"))));
        assertFalse(PAY.contains(currencyOnly, map("type", "p", "total", Map.of("amount", "1000000", "currency", "EUR"))),
                "a currency alone still picks the spelling");
        assertTrue(PAY.contains(neither, map("type", "p", "actions", List.of("initiate"), "total", EUR100)), "no spelling, no constraint");
        assertTrue(PAY.contains(neither, map("type", "p", "actions", List.of("initiate"), "amount", "1", "currency", "USD")));
    }

    @Test
    void inheritStaysInTheCandidatesSpelling() {
        Map<String, Object> ceiling = map("type", "p", "actions", List.of("initiate"), "total", EUR100);
        Map<String, Object> got = PAY.inherit(ceiling, map("type", "p", "amount", "42"));
        assertEquals(map("type", "p", "amount", "42", "actions", List.of("initiate")), got, "total is not added beside amount");
        assertFalse(PAY.contains(ceiling, got));
        Map<String, Object> flatCeiling = map("type", "p", "amount", "100", "currency", "EUR");
        assertEquals(map("type", "p", "amount", "42", "currency", "EUR"), PAY.inherit(flatCeiling, map("type", "p", "amount", "42")),
                "the same spelling is filled in");
        assertEquals(map("type", "p", "amount", "100", "currency", "EUR"), PAY.inherit(flatCeiling, map("type", "p")),
                "a candidate that uses no spelling takes the ceiling's");
        assertEquals(map("type", "p", "total", EUR100), PAY.inherit(flatCeiling, map("type", "p", "total", EUR100)));
    }

    @Test
    void twoSpellingsHaveNoMeet() {
        assertEquals(Optional.empty(), PAY.meet(map("type", "p", "total", EUR100), map("type", "p", "currency", "EUR")));
        assertEquals(Optional.of(map("type", "p", "actions", List.of("a"), "total", EUR100)),
                PAY.meet(map("type", "p", "total", EUR100), map("type", "p", "actions", List.of("a"))));
        assertEquals(Optional.of(map("type", "p", "amount", "42", "currency", "EUR")),
                PAY.meet(map("type", "p", "amount", "100", "currency", "EUR"), map("type", "p", "amount", "42", "currency", "EUR")));
    }
}
