/*
 * No token, newline or oversized value reaches a log through an event.
 */
package com.pingidentity.ps.oidf.platform.events;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

class LogSafeTest {

    @AfterEach
    void reset() {
        LogSafe.configureMaxValueLength(LogSafe.DEFAULT_MAX_VALUE_LENGTH);
    }

    @Test
    void valuesAreCappedAndControlCharactersReplaced() {
        LogSafe.configureMaxValueLength(4);
        assertEquals(16, LogSafe.maxValueLength());
        LogSafe.configureMaxValueLength(20);
        assertEquals("0123456789abcdefghij…", LogSafe.value("0123456789abcdefghijklmnop"));
        assertEquals("0123456789abcdefghi", LogSafe.value("0123456789abcdefghi"));
        assertEquals("a_b_c", LogSafe.value("a\rb\tc"));
        assertNull(LogSafe.value(null));
    }

    @Test
    void quotingIsOnlyWhereTheLineNeedsIt() {
        assertEquals("-", LogSafe.quoted(null));
        assertEquals("\"\"", LogSafe.quoted(""));
        assertEquals("\"say \\\"hi\\\"\"", LogSafe.quoted("say \"hi\""));
        assertEquals("\"a=b\"", LogSafe.quoted("a=b"));
        assertEquals("\"a b\"", LogSafe.quoted("a b"));
        assertEquals("plain", LogSafe.quoted("plain"));
        assertEquals("\"a\\\"b\"", LogSafe.quoted("a\"b"));
    }

    @Test
    void aJwsOrJweBecomesItsDigest() {
        String jws = "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJodHRwczovL2EifQ.c2lnbmF0dXJl";
        String jwe = "eyJhbGciOiJSU0EtT0FFUCJ9.a2V5.aXY.Y2lwaGVy.dGFn";
        assertEquals(LogSafe.jwtDigest(jwe), LogSafe.value(jwe));
        String line = LogSafe.value("bad token " + jws + " seen");
        assertFalse(line.contains("eyJpc3MiOiJodHRwczovL2EifQ"), line);
        assertTrue(line.contains(LogSafe.jwtDigest(jws)), line);
        assertEquals("no eyJ token here", LogSafe.value("no eyJ token here"));
        assertEquals("no token", LogSafe.digestTokens("no token"));
        assertTrue(LogSafe.jwtDigest("x").startsWith("jwt:sha256:"));
        assertEquals(23, LogSafe.jwtDigest("x").length());
        assertEquals(12, LogSafe.sha256Hex12("x").length());
    }
}
