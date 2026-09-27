/*
 * The size limits, edge by edge.
 */
package com.pingidentity.ps.oidf.rar.model;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

class LimitsTest {

    private static RarModelException refused(List<?> details) {
        return assertThrows(RarModelException.class, () -> Limits.check(details, "candidate"));
    }

    @Test
    void theNumbersAreThePlans() {
        assertEquals(16, Limits.MAX_DETAILS);
        assertEquals(8, Limits.MAX_DEPTH);
        assertEquals(256, Limits.MAX_ENTRIES);
        assertEquals(2048, Limits.MAX_STRING);
        assertEquals(64, Limits.MAX_DIGITS, "this library's, not the plan's");
        assertEquals(262_144, Limits.MAX_TEXT, "this library's, not the plan's");
    }

    /** A number is measured by what it would write, from its scale and size, without writing it. */
    @Test
    void digitsCountsThePlainDecimal() {
        assertEquals(4, Limits.digits(new BigDecimal("5E+3")));
        assertEquals(3, Limits.digits(new BigDecimal("0.05")));
        assertEquals(3, Limits.digits(new BigDecimal("12.5")));
        assertEquals(1, Limits.digits(BigDecimal.ZERO));
        assertEquals(4, Limits.digits(new BigDecimal("0.000")));
        assertEquals(64, Limits.digits(new BigDecimal("1E+63")));
        assertEquals(65, Limits.digits(new BigDecimal("1E+64")));
        assertEquals(64, Limits.digits(new BigDecimal("1E-63")));
        assertEquals(65, Limits.digits(new BigDecimal("1E-64")));
        assertEquals(65, Limits.digits(new BigDecimal("1E+65")), "past the scale bound the answer is only 'more'");
        assertEquals(65, Limits.digits(new BigDecimal("1E-65")));
        assertEquals(65, Limits.digits(new BigDecimal("1e999999999")));
        assertEquals(65, Limits.digits(new BigDecimal("1e-999999999")));
        assertEquals(65, Limits.digits(new BigDecimal("100e2147483647")));
        assertEquals(65, Limits.digits(new BigDecimal(BigInteger.TEN.pow(100))), "past 256 bits");
        assertEquals(64, Limits.digits(new BigDecimal("9".repeat(64))));
        assertEquals(65, Limits.digits(new BigDecimal("9".repeat(65))));
        assertEquals(64, Limits.digits(new BigDecimal("-" + "9".repeat(64))), "the sign is not a digit");
    }

    /** Numbers from any parser, in any class a parser produces, are held to the digit limit. */
    @Test
    void numbersAreHeldToTheDigitLimit() throws Exception {
        Limits.check(List.of(Map.of("n", new BigDecimal("9".repeat(64)), "l", Long.MAX_VALUE, "i", 1, "s", (short) 1, "b", (byte) 1,
                "f", 1.5f, "d", 0.1d, "big", BigInteger.TEN.pow(63))), "candidate");
        for (Object tooLarge : List.of(new BigDecimal("1e999999999"), new BigDecimal("1e2147483647"), new BigDecimal("100e2147483647"),
                new BigDecimal("1e-999999999"), new BigDecimal("9".repeat(65)), BigInteger.TEN.pow(64), 1e308d, 4.9e-324d)) {
            RarModelException e = refused(List.of(Map.of("n", tooLarge)));
            assertEquals(RarModelException.Reason.TOO_LARGE, e.reason(), tooLarge.getClass() + " " + e.getMessage());
            assertEquals("candidate authorization_details[0].'n' is a number of more than 64 digits", e.getMessage());
        }
        RarModelException odd = refused(List.of(Map.of("n", new AtomicInteger(1))));
        assertEquals(RarModelException.Reason.MALFORMED, odd.reason(), "a Number no JSON parser produces");
        assertEquals("candidate authorization_details[0].'n' is not a JSON number (java.util.concurrent.atomic.AtomicInteger)", odd.getMessage());
    }

    @Test
    void nullListIsMalformed() {
        RarModelException e = refused(null);
        assertEquals(RarModelException.Reason.MALFORMED, e.reason());
        assertTrue(e.getMessage().startsWith("candidate authorization_details"), e.getMessage());
    }

    @Test
    void tooManyDetails() {
        assertEquals(RarModelException.Reason.TOO_LARGE, refused(Collections.nCopies(17, Map.of("type", "x"))).reason());
    }

    @Test
    void entryThatIsNotAnObject() throws Exception {
        assertEquals(RarModelException.Reason.MALFORMED, refused(List.of("x")).reason());
        assertEquals(1, Limits.check(List.of(Map.of("type", "x")), "ceiling").size());
    }

    @Test
    void scalarsAreWalked() throws Exception {
        Map<String, Object> ok = new HashMap<>();
        ok.put("s", "x".repeat(2048));
        ok.put("n", 1.5d);
        ok.put("b", true);
        ok.put("z", null);
        Limits.check(List.of(ok), "candidate");
        assertEquals(RarModelException.Reason.TOO_LARGE, refused(List.of(Map.of("s", "x".repeat(2049)))).reason());
        assertEquals(RarModelException.Reason.MALFORMED, refused(List.of(Map.of("n", Double.NaN))).reason());
        assertEquals(RarModelException.Reason.MALFORMED, refused(List.of(Map.of("o", new Object()))).reason());
    }

    @Test
    void depthCountsTheDetailAsOne() throws Exception {
        Object v = "leaf";
        for (int i = 0; i < 7; i++) {
            v = Map.of("n", v);
        }
        Limits.check(List.of(Map.of("f", v)), "candidate");
        Object deeper = Map.of("n", v);
        assertEquals(RarModelException.Reason.TOO_LARGE, refused(List.of(Map.of("f", deeper))).reason());
        Object viaList = "leaf";
        for (int i = 0; i < 8; i++) {
            viaList = List.of(viaList);
        }
        assertEquals(RarModelException.Reason.TOO_LARGE, refused(List.of(Map.of("f", viaList))).reason());
    }

    @Test
    void entriesInArraysAndObjects() throws Exception {
        List<Object> list = new ArrayList<>(Collections.nCopies(256, "x"));
        Map<String, Object> obj = new HashMap<>();
        for (int i = 0; i < 256; i++) {
            obj.put("k" + i, i);
        }
        Limits.check(List.of(Map.of("l", list, "o", obj)), "candidate");
        list.add("one more");
        assertEquals(RarModelException.Reason.TOO_LARGE, refused(List.of(Map.of("l", list))).reason());
        obj.put("k256", 256);
        assertEquals(RarModelException.Reason.TOO_LARGE, refused(List.of(Map.of("o", obj))).reason());
    }

    @Test
    void memberNames() {
        Map<Object, Object> badKey = new HashMap<>();
        badKey.put(1, "x");
        assertEquals(RarModelException.Reason.MALFORMED, refused(List.of(badKey)).reason());
        assertEquals(RarModelException.Reason.TOO_LARGE, refused(List.of(Map.of("k".repeat(2049), "x"))).reason());
    }
}
