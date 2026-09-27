/*
 * Each rule's three answers, at the edges the vectors do not reach.
 */
package com.pingidentity.ps.oidf.rar.model;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.Test;

class FieldRuleTest {

    private static final FieldRule SET = FieldRule.of(Rule.SET);
    private static final FieldRule VALUES = FieldRule.of(Rule.SET_OF_VALUES);
    private static final FieldRule LIMIT = FieldRule.of(Rule.LIMIT);
    private static final FieldRule AMOUNT = FieldRule.of(Rule.AMOUNT);
    private static final FieldRule INSTANT = FieldRule.of(Rule.INSTANT_LIMIT);
    private static final FieldRule EQUAL = FieldRule.of(Rule.EQUAL);
    private static final FieldRule FORBIDDEN = FieldRule.of(Rule.FORBIDDEN);

    private static RarModelException malformed(FieldRule rule, Object value) {
        RarModelException e = assertThrows(RarModelException.class, () -> rule.check(value, "d.f"));
        assertEquals(RarModelException.Reason.MALFORMED, e.reason(), e.getMessage());
        assertTrue(e.getMessage().startsWith("d.f"), e.getMessage());
        return e;
    }

    @Test
    void constructorHoldsTheOptionsToTheirRules() {
        assertThrows(IllegalArgumentException.class, () -> new FieldRule(null, null, null));
        assertThrows(IllegalArgumentException.class, () -> new FieldRule(Rule.SET, "unit", null));
        assertThrows(IllegalArgumentException.class, () -> new FieldRule(Rule.OBJECT, null, null));
        assertThrows(IllegalArgumentException.class, () -> new FieldRule(Rule.SET, null, new TypeModel(null, Map.of())));
        assertThrows(IllegalArgumentException.class, () -> FieldRule.of(Rule.OBJECT));
        assertEquals("currency", FieldRule.limit("currency").unitField());
        assertEquals(Rule.OBJECT, FieldRule.object(new TypeModel(null, Map.of("a", SET))).rule());
    }

    @Test
    void setChecks() throws Exception {
        SET.check(List.of("a", ""), "d.f");
        malformed(SET, "a");
        malformed(SET, null);
        malformed(SET, List.of());
        malformed(SET, Arrays.asList("a", null));
        malformed(SET, List.of(1));
    }

    @Test
    void setOfValuesChecks() throws Exception {
        VALUES.check(List.of("a", 1, true, Map.of("k", "v"), List.of("x")), "d.f");
        malformed(VALUES, Map.of());
        malformed(VALUES, List.of());
        malformed(VALUES, Arrays.asList("a", null));
    }

    @Test
    void limitChecks() throws Exception {
        LIMIT.check(5000, "d.f");
        LIMIT.check("-0.5", "d.f");
        LIMIT.check(new BigDecimal("1E+3"), "d.f");
        malformed(LIMIT, "1E+3");
        malformed(LIMIT, "1,000");
        malformed(LIMIT, " 1");
        malformed(LIMIT, true);
        malformed(LIMIT, null);
        malformed(LIMIT, List.of(1));
    }

    @Test
    void amountChecks() throws Exception {
        AMOUNT.check(Map.of("amount", "1", "currency", "EUR"), "d.f");
        AMOUNT.check(Map.of("amount", 1, "currency", "EUR"), "d.f");
        malformed(AMOUNT, "1 EUR");
        malformed(AMOUNT, Map.of("amount", "1"));
        malformed(AMOUNT, Map.of("currency", "EUR"));
        malformed(AMOUNT, Map.of("amount", "1", "currency", "EUR", "x", 1));
        malformed(AMOUNT, Map.of("amount", "1", "unit", "EUR"));
        malformed(AMOUNT, Map.of("value", "1", "currency", "EUR"));
        malformed(AMOUNT, Map.of("amount", "one", "currency", "EUR"));
        malformed(AMOUNT, Map.of("amount", "1", "currency", ""));
        malformed(AMOUNT, Map.of("amount", "1", "currency", 978));
        Map<String, Object> nullCurrency = new HashMap<>();
        nullCurrency.put("amount", "1");
        nullCurrency.put("currency", null);
        malformed(AMOUNT, nullCurrency);
    }

    @Test
    void instantChecks() throws Exception {
        assertEquals(Instant.parse("2026-12-31T22:30:00Z"), FieldRule.instant("2026-12-31T23:30:00+01:00", "d.f"));
        assertEquals(Instant.parse("2027-01-01T00:00:00Z"), FieldRule.instant("2026-12-31", "d.f"));
        assertEquals(Instant.parse("2026-12-31T23:59:59.500Z"), FieldRule.instant("2026-12-31T23:59:59.5Z", "d.f"));
        malformed(INSTANT, "2026-12-31T23:59:59");
        malformed(INSTANT, "2026-13-01");
        malformed(INSTANT, "");
        malformed(INSTANT, 20261231);
        malformed(INSTANT, null);
    }

    @Test
    void equalChecks() throws Exception {
        EQUAL.check("x", "d.f");
        EQUAL.check(0, "d.f");
        EQUAL.check(false, "d.f");
        EQUAL.check(Map.of("a", List.of(Map.of("b", 1))), "d.f");
        EQUAL.check(List.of(List.of("x")), "d.f");
        malformed(EQUAL, null);
        malformed(EQUAL, List.of());
        malformed(EQUAL, Map.of());
        Map<String, Object> nullInside = new HashMap<>();
        nullInside.put("a", null);
        malformed(EQUAL, nullInside);
        malformed(EQUAL, Map.of("a", Map.of("b", Arrays.asList(1, null))));
        malformed(EQUAL, List.of(Map.of("a", Arrays.asList((Object) null))));
    }

    @Test
    void objectChecks() throws Exception {
        FieldRule object = FieldRule.object(new TypeModel(null, Map.of("a", SET)));
        object.check(Map.of("a", List.of("x")), "d.f");
        object.check(Map.of(), "d.f");
        malformed(object, "x");
        malformed(object, List.of());
        RarModelException e = assertThrows(RarModelException.class, () -> object.check(Map.of("b", 1), "d.f"));
        assertEquals(RarModelException.Reason.UNDECLARED_FIELD, e.reason());
    }

    @Test
    void forbiddenIsNeverAllowed() {
        RarModelException e = malformed(FORBIDDEN, "anything");
        assertTrue(e.getMessage().contains("forbidden"), e.getMessage());
        malformed(FORBIDDEN, null);
        assertFalse(FORBIDDEN.contains("a", "a"));
        assertEquals(Optional.empty(), FORBIDDEN.meet("a", "a"));
    }

    @Test
    void containsPerRule() {
        assertTrue(SET.contains(List.of("a", "b"), List.of("b", "a", "a")));
        assertFalse(SET.contains(List.of("a"), List.of("a", "b")));
        assertTrue(VALUES.contains(List.of(Map.of("a", 1, "b", 2)), List.of(Map.of("b", 2.0, "a", 1))));
        assertFalse(VALUES.contains(List.of(Map.of("a", 1)), List.of(Map.of("a", 2))));
        assertTrue(LIMIT.contains("100", 99.999));
        assertTrue(LIMIT.contains(100, "100.00"));
        assertFalse(LIMIT.contains(100, "100.01"));
        assertTrue(AMOUNT.contains(Map.of("amount", "100", "currency", "EUR"), Map.of("amount", 100, "currency", "EUR")));
        assertFalse(AMOUNT.contains(Map.of("amount", "100", "currency", "EUR"), Map.of("amount", 1, "currency", "USD")));
        assertFalse(AMOUNT.contains(Map.of("amount", "100", "currency", "EUR"), Map.of("amount", 101, "currency", "EUR")));
        assertTrue(INSTANT.contains("2026-12-31", "2026-12-31T23:59:59Z"));
        assertFalse(INSTANT.contains("2026-12-31T00:00:00Z", "2026-12-31"));
        assertTrue(EQUAL.contains(Map.of("a", 1), Map.of("a", 1.0)));
        assertFalse(EQUAL.contains("a", "A"));
        FieldRule object = FieldRule.object(new TypeModel(null, Map.of("a", SET)));
        assertTrue(object.contains(Map.of("a", List.of("x", "y")), Map.of("a", List.of("x"))));
        assertFalse(object.contains(Map.of("a", List.of("x")), Map.of()));
    }

    @Test
    void meetPerRule() {
        assertEquals(Optional.of(List.of("a", "b")), SET.meet(List.of("b", "a", "c"), List.of("a", "b", "b")));
        assertEquals(Optional.empty(), SET.meet(List.of("a"), List.of("b")));
        assertEquals(Optional.of(List.of(Map.of("k", 1))), VALUES.meet(List.of(Map.of("k", 1), "x"), List.of(Map.of("k", 1.0))));
        assertEquals(Optional.empty(), VALUES.meet(List.of("x"), List.of("y")));
        assertEquals(Optional.of(new BigDecimal("50")), LIMIT.meet(new BigDecimal("50"), "100"));
        assertEquals(Optional.of("50"), LIMIT.meet("100", "50"));
        assertEquals(Optional.of("100.0"), LIMIT.meet(100, "100.0"), "a tie takes the spelling that sorts first");
        assertEquals(Optional.of("100.0"), LIMIT.meet("100.0", 100));
        assertEquals(Optional.of(100), LIMIT.meet(100, 100));
        Map<String, Object> eur100 = Map.of("amount", "100", "currency", "EUR");
        Map<String, Object> eur50 = Map.of("amount", 50, "currency", "EUR");
        assertEquals(Optional.of(eur50), AMOUNT.meet(eur100, eur50));
        assertEquals(Optional.of(eur50), AMOUNT.meet(eur50, eur100));
        assertEquals(Optional.empty(), AMOUNT.meet(eur100, Map.of("amount", "1", "currency", "USD")));
        assertEquals(Optional.of("2026-06-30"), INSTANT.meet("2026-12-31", "2026-06-30"));
        assertEquals(Optional.of("2026-06-30T00:00:00Z"), INSTANT.meet("2026-06-30T00:00:00Z", "2026-06-30T01:00:00+01:00"),
                "equal instants take the spelling that sorts first");
        assertEquals(Optional.of(Map.of("a", 1)), EQUAL.meet(Map.of("a", 1), Map.of("a", 1.0)));
        assertEquals(Optional.empty(), EQUAL.meet("a", "b"));
        FieldRule object = FieldRule.object(new TypeModel(null, Map.of("a", SET, "b", EQUAL)));
        assertEquals(Optional.of(Map.of("a", List.of("x", "y"), "b", 1)), object.meet(Map.of("a", List.of("x", "y")), Map.of("b", 1)),
                "a field one side omits takes the other side's value");
        assertEquals(Optional.empty(), object.meet(Map.of("b", 1), Map.of("b", 2)));
    }

    @Test
    void meetCopiesRatherThanAliases() {
        Map<String, Object> a = new LinkedHashMap<>(Map.of("k", "v"));
        Object m = EQUAL.meet(a, Map.of("k", "v")).orElseThrow();
        assertEquals(a, m);
        a.put("k", "changed");
        assertEquals("v", ((Map<?, ?>) m).get("k"));
    }

    @Test
    void describeNamesTheRuleAndItsOptions() {
        assertEquals("set", SET.describe());
        assertEquals(Map.of("rule", "limit", "unit_field", "currency"), FieldRule.limit("currency").describe());
        assertEquals("limit", LIMIT.describe());
        assertEquals(Map.of("rule", "object", "fields", Map.of("a", "set")), FieldRule.object(new TypeModel(null, Map.of("a", SET))).describe());
    }

    @Test
    void decimalReader() throws Exception {
        assertEquals(new BigDecimal("1.5"), FieldRule.decimal(1.5d, "w"));
        assertEquals(new BigDecimal("-2"), FieldRule.decimal("-2", "w"));
        assertThrows(RarModelException.class, () -> FieldRule.decimal("2.", "w"));
        assertThrows(RarModelException.class, () -> FieldRule.decimal(List.of(), "w"));
    }
}
