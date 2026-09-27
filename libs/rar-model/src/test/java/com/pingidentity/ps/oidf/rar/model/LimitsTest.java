/*
 * The size limits, edge by edge.
 */
package com.pingidentity.ps.oidf.rar.model;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
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
