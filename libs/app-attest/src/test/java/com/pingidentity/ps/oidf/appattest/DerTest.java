package com.pingidentity.ps.oidf.appattest;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.HexFormat;
import org.junit.jupiter.api.Test;

/** The DER reader: Apple's high tag numbers, both length forms, and every malformed input. */
class DerTest {

    private static Der read(String hex) {
        return Der.read(HexFormat.of().parseHex(hex));
    }

    private static void malformed(String hex) {
        assertThrows(IllegalArgumentException.class, () -> read(hex));
    }

    @Test
    void readsHighTagNumbers() {
        Der d = read("bf8a7806040432372e32");
        assertEquals(Der.CONTEXT, d.tagClass());
        assertEquals(1400, d.tag());
        assertTrue(d.constructed());
        assertEquals("27.2", d.only().text());
    }

    @Test
    void readsLongLengths() {
        Der one = read("0481" + "03" + "616263");
        assertArrayEquals("abc".getBytes(), one.value());
        Der two = read("0482" + "0001" + "61");
        assertEquals("a", two.text());
    }

    @Test
    void readsScalars() {
        assertEquals(1L, read("020101").integer());
        assertEquals(-1L, read("0201ff").integer());
        assertTrue(read("0101ff").bool());
        assertFalse(read("010100").bool());
    }

    @Test
    void refusesWhatIsNotThere() {
        assertThrows(IllegalArgumentException.class, () -> Der.read(null));
        malformed("");                 // nothing
        malformed("04");               // no length
        malformed("0405616263");       // shorter than it says
        malformed("04000400");         // trailing bytes
        malformed("bf");               // high tag, cut short
        malformed("bf8080808001" + "00"); // tag number over four groups
        malformed("0480");             // indefinite length
        malformed("048400000001" + "00"); // four length octets
        malformed("0482");             // long length, cut short
    }

    @Test
    void refusesTheWrongKindOfRead() {
        assertThrows(IllegalArgumentException.class, () -> read("0400").children());
        assertThrows(IllegalArgumentException.class, () -> read("3000").only());
        assertThrows(IllegalArgumentException.class, () -> read("300404000400").only());
        assertThrows(IllegalArgumentException.class, () -> read("3000").text());
        assertThrows(IllegalArgumentException.class, () -> read("0400").integer());
        assertThrows(IllegalArgumentException.class, () -> read("0200").integer());
        assertThrows(IllegalArgumentException.class, () -> read("0209010203040506070809").integer());
        assertThrows(IllegalArgumentException.class, () -> read("020101").bool());
        assertThrows(IllegalArgumentException.class, () -> read("01020000").bool());
    }
}
