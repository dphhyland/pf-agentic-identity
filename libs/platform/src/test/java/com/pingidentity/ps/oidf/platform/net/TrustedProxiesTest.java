/*
 * TrustedProxies: whose forwarding headers are believed, and what they are believed to say.
 */
package com.pingidentity.ps.oidf.platform.net;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.platform.settings.Catalogue;
import com.pingidentity.ps.oidf.platform.settings.SettingRefused;
import com.pingidentity.ps.oidf.platform.settings.Settings;
import com.pingidentity.ps.oidf.platform.settings.Sources;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

class TrustedProxiesTest {

    private static final TrustedProxies LB = TrustedProxies.of(List.of("10.0.0.0/8", "2001:db8:1::/48"),
            TrustedProxies.HeaderFamily.X_FORWARDED);
    private static final TrustedProxies LB_7239 = TrustedProxies.of(List.of("10.0.0.0/8", "2001:db8:1::/48"),
            TrustedProxies.HeaderFamily.FORWARDED);

    @AfterEach
    void clearProperties() {
        System.clearProperty("oidf.trusted.proxies");
        System.clearProperty("oidf.trusted.proxies.headers");
    }

    /** Headers as a request would carry them: each name to its instances. */
    private static TrustedProxies.Headers headers(String... nameValue) {
        Map<String, List<String>> map = new HashMap<>();
        for (int i = 0; i < nameValue.length; i += 2) {
            map.computeIfAbsent(nameValue[i], k -> new java.util.ArrayList<>()).add(nameValue[i + 1]);
        }
        return map::get;
    }

    // ---- who is believed ------------------------------------------------------------------------------------------

    @Test
    void anEmptyListBelievesNoHeaderFromAnyone() {
        TrustedProxies none = TrustedProxies.none();
        assertTrue(none.isEmpty());
        assertEquals("10.1.2.3", none.clientAddress("10.1.2.3", headers("X-Forwarded-For", "198.51.100.7")));
        assertEquals(TrustedProxies.Origin.NONE, none.origin("10.1.2.3", headers("X-Forwarded-Proto", "https",
                "X-Forwarded-Host", "evil.example")));
        assertSame(none, TrustedProxies.of(null, TrustedProxies.HeaderFamily.X_FORWARDED));
        assertSame(none, TrustedProxies.of(List.of(), TrustedProxies.HeaderFamily.X_FORWARDED));
        TrustedProxies rfc7239 = TrustedProxies.of(List.of(), TrustedProxies.HeaderFamily.FORWARDED);
        assertTrue(rfc7239.isEmpty());
        assertEquals(TrustedProxies.HeaderFamily.FORWARDED, rfc7239.family());
    }

    @Test
    void anUntrustedSenderIsTakenAtItsWord() {
        assertEquals("198.51.100.7", LB.clientAddress("198.51.100.7", headers("X-Forwarded-For", "10.9.9.9, 192.0.2.1")));
        assertEquals(TrustedProxies.Origin.NONE, LB.origin("198.51.100.7", headers("X-Forwarded-Host", "evil.example")));
    }

    @Test
    void aTrustedProxyNamesTheRightMostUntrustedHop() {
        assertEquals("192.0.2.1", LB.clientAddress("10.0.0.5", headers("X-Forwarded-For", "192.0.2.1")));
        // Two proxies of ours: the inner one appended the outer one's address, which is skipped.
        assertEquals("192.0.2.1", LB.clientAddress("10.0.0.5", headers("X-Forwarded-For", "192.0.2.1, 10.2.3.4")));
    }

    @Test
    void aSpoofedChainToTheLeftIsIgnored() {
        // The client wrote "1.1.1.1, 10.0.0.9" itself; our proxy appended the address it saw, 203.0.113.50.
        assertEquals("203.0.113.50", LB.clientAddress("10.0.0.5",
                headers("X-Forwarded-For", "1.1.1.1, 10.0.0.9, 203.0.113.50")));
        // Several header instances are one list, in order.
        assertEquals("203.0.113.50", LB.clientAddress("10.0.0.5",
                headers("X-Forwarded-For", "1.1.1.1", "X-Forwarded-For", "203.0.113.50")));
    }

    @Test
    void aChainOfOnlyTrustedHopsNamesTheLeftMost() {
        assertEquals("10.0.0.1", LB.clientAddress("10.0.0.5", headers("X-Forwarded-For", "10.0.0.1, 10.0.0.2")));
    }

    @Test
    void aTrustedProxyWithNoHeaderIsTheClient() {
        assertEquals("10.0.0.5", LB.clientAddress("10.0.0.5", headers()));
        assertEquals("10.0.0.5", LB.clientAddress("10.0.0.5", null));
        assertEquals("10.0.0.5", LB.clientAddress("10.0.0.5", name -> java.util.Arrays.asList(null, " , ")));
    }

    @Test
    void aHopThatIsNotAnAddressEndsTheWalkAtTheLastVouchedHop() {
        assertEquals("10.0.0.5", LB.clientAddress("10.0.0.5", headers("X-Forwarded-For", "192.0.2.1, unknown")));
        assertEquals("10.2.0.1", LB.clientAddress("10.0.0.5", headers("X-Forwarded-For", "evil.example, 10.2.0.1")));
    }

    @Test
    void addressesAreCanonicalSoAKeyCannotBeRespelt() {
        assertEquals("192.0.2.1", LB.clientAddress("10.0.0.5", headers("X-Forwarded-For", "::ffff:192.0.2.1")));
        assertEquals("192.0.2.1", LB.clientAddress("10.0.0.5", headers("X-Forwarded-For", "192.0.2.1:4711")));
        assertEquals("2001:db8:0:0:0:0:0:7", LB.clientAddress("10.0.0.5", headers("X-Forwarded-For", "[2001:DB8::7]:443")));
        assertEquals("2001:db8:0:0:0:0:0:7", LB.clientAddress("2001:db8::7", headers()));
        // A leading zero is not an octet: never read as octal or decimal, the hop is not an address.
        assertEquals("10.0.0.5", LB.clientAddress("10.0.0.5", headers("X-Forwarded-For", "010.1.1.1")));
    }

    @Test
    void ipv6ProxiesAndClients() {
        assertEquals("2001:db8:2:0:0:0:0:9", LB.clientAddress("[2001:db8:1::5]",
                headers("X-Forwarded-For", "2001:db8:2::9, 2001:db8:1::77")));
        assertTrue(LB.trusts("2001:db8:1:ffff::1"));
        assertFalse(LB.trusts("2001:db8:2::1"));
        assertFalse(LB.trusts("::ffff:11.0.0.1"));
        assertTrue(LB.trusts("::ffff:10.0.0.1"), "an IPv4-mapped address is its IPv4 address");
        assertFalse(LB.trusts("not-an-address"));
        assertFalse(LB.trusts(null));
    }

    @Test
    void aRemoteAddressThatIsNotAnAddressIsReturnedAsGiven() {
        assertEquals("unix-socket", LB.clientAddress("unix-socket", headers("X-Forwarded-For", "192.0.2.1")));
        assertNull(LB.clientAddress(null, headers("X-Forwarded-For", "192.0.2.1")));
    }

    // ---- what a trusted proxy says of the scheme and host ----------------------------------------------------------

    @Test
    void theOriginComesFromATrustedProxyOnly() {
        TrustedProxies.Headers h = headers("X-Forwarded-Proto", "https", "X-Forwarded-Host", "attester.example",
                "X-Forwarded-Port", "8443", "X-Forwarded-For", "192.0.2.1");
        assertEquals(new TrustedProxies.Origin("https", "attester.example", 8443), LB.origin("10.0.0.5", h));
        assertEquals(TrustedProxies.Origin.NONE, LB.origin("192.0.2.99", h));
    }

    @Test
    void aPerHopHeaderIsReadAtTheClientsHopElseTheRightMost() {
        // Two of our proxies, each appending: the edge (index 0 of the XFF list) saw https and edge.example.
        TrustedProxies.Headers perHop = headers("X-Forwarded-For", "192.0.2.1, 10.2.3.4",
                "X-Forwarded-Proto", "https, http", "X-Forwarded-Host", "edge.example, inner");
        assertEquals(new TrustedProxies.Origin("https", "edge.example", null), LB.origin("10.0.0.5", perHop));
        // Lengths that do not line up: the right-most, which the nearest proxy wrote.
        TrustedProxies.Headers ragged = headers("X-Forwarded-For", "192.0.2.1, 10.2.3.4, 10.2.3.5",
                "X-Forwarded-Proto", "http, https");
        assertEquals("https", LB.origin("10.0.0.5", ragged).scheme());
        // No XFF at all: the right-most.
        assertEquals("inner", LB.origin("10.0.0.5", headers("X-Forwarded-Host", "edge.example, inner")).host());
    }

    @Test
    void anUnbelievableSchemeHostOrPortIsDropped() {
        TrustedProxies.Origin o = LB.origin("10.0.0.5", headers("X-Forwarded-Proto", "javascript",
                "X-Forwarded-Host", "evil.example/path?x", "X-Forwarded-Port", "99999"));
        assertEquals(TrustedProxies.Origin.NONE, o);
        assertNull(LB.origin("10.0.0.5", headers("X-Forwarded-Host", "user@evil.example")).host());
        assertNull(LB.origin("10.0.0.5", headers("X-Forwarded-Host", "a".repeat(262))).host());
        assertNull(LB.origin("10.0.0.5", headers("X-Forwarded-Port", "0")).port());
        assertEquals("HTTPS".toLowerCase(), LB.origin("10.0.0.5", headers("X-Forwarded-Proto", "HTTPS")).scheme());
        assertEquals("http", LB.origin("10.0.0.5", headers("X-Forwarded-Proto", "http")).scheme());
        assertEquals("[2001:db8::1]:8443", LB.origin("10.0.0.5", headers("X-Forwarded-Host", "[2001:db8::1]:8443")).host());
        assertEquals("attester.example:8443", LB.origin("10.0.0.5",
                headers("X-Forwarded-Host", "attester.example:8443")).host());
    }

    // ---- RFC 7239 Forwarded ---------------------------------------------------------------------------------------

    @Test
    void forwardedIsReadOnlyWhenChosen() {
        TrustedProxies.Headers h = headers("Forwarded", "for=192.0.2.60;proto=https;host=attester.example",
                "X-Forwarded-For", "198.51.100.1");
        assertEquals("192.0.2.60", LB_7239.clientAddress("10.0.0.5", h));
        assertEquals(new TrustedProxies.Origin("https", "attester.example", null), LB_7239.origin("10.0.0.5", h));
        assertEquals("198.51.100.1", LB.clientAddress("10.0.0.5", h), "x-forwarded reads no Forwarded");
        assertEquals(TrustedProxies.HeaderFamily.FORWARDED, LB_7239.family());
    }

    @Test
    void forwardedElementsAreHopsAndTheClientsElementCarriesItsOrigin() {
        // RFC 7239 section 4's examples: a quoted IPv6 with a port, and a chain.
        TrustedProxies.Headers h = headers("Forwarded", "for=\"_gazonk\"",
                "Forwarded", "For=\"[2001:db8:cafe::17]:4711\";proto=https;host=\"edge.example\", for=10.2.3.4;proto=http;host=inner");
        assertEquals("2001:db8:cafe:0:0:0:0:17", LB_7239.clientAddress("10.0.0.5", h));
        assertEquals(new TrustedProxies.Origin("https", "edge.example", null), LB_7239.origin("10.0.0.5", h));
        // An obfuscated identifier right of our proxies ends the walk at the last vouched hop.
        assertEquals("10.0.0.5", LB_7239.clientAddress("10.0.0.5", headers("Forwarded", "for=unknown")));
        assertEquals(TrustedProxies.Origin.NONE, LB_7239.origin("10.0.0.5", headers()));
        assertEquals("http", LB_7239.origin("10.0.0.5", headers("Forwarded", "for=unknown;proto=http")).scheme());
    }

    @Test
    void forwardedParsingRespectsQuotesAndSkipsWhatItCannotRead() {
        List<Forwarded.Element> elements = Forwarded.parse(List.of(
                "for=\"a,b;c\";by=x, ;noequals;=empty;HOST=\"h\\\"q\";host=second, for=\"unterminated"));
        assertEquals(3, elements.size());
        assertEquals("a,b;c", elements.get(0).get("for"));
        assertEquals("x", elements.get(0).get("by"));
        assertEquals("h\"q", elements.get(1).get("host"), "a repeated name keeps its first value");
        assertNull(elements.get(2).get("for"));
        assertNull(Forwarded.unquote("\"closed\"early"));
        assertNull(Forwarded.unquote("\"ends in a backslash\\"));
        assertEquals(List.of("\"a\\"), Forwarded.split("\"a\\", ','));
        assertEquals(2, Forwarded.parse(List.of("for=192.0.2.1, , for=192.0.2.2")).size(), "an empty element is no hop");
        assertTrue(Forwarded.parse(List.of(" =x")).get(0).params().isEmpty());
        assertEquals("token", Forwarded.unquote("token"));
    }

    // ---- ranges and literals --------------------------------------------------------------------------------------

    @Test
    void rangesAndAddressesParse() {
        assertEquals("10.0.0.0/8", IpAddresses.cidr("10.0.0.0/8").toString());
        assertEquals("192.0.2.7/32", IpAddresses.cidr("192.0.2.7").toString());
        assertEquals("0:0:0:0:0:0:0:1/128", IpAddresses.cidr("::1").toString());
        assertTrue(IpAddresses.cidr("10.1.2.0/23").contains(IpAddresses.address("10.1.3.200")));
        assertFalse(IpAddresses.cidr("10.1.2.0/23").contains(IpAddresses.address("10.1.4.1")));
        assertTrue(IpAddresses.cidr("0.0.0.0/0").contains(IpAddresses.address("203.0.113.1")));
        assertEquals(IpAddresses.cidr("10.0.0.0/8"), IpAddresses.cidr("10.0.0.0/8"));
        assertEquals(IpAddresses.cidr("10.0.0.0/8").hashCode(), IpAddresses.cidr("10.0.0.0/8").hashCode());
        assertFalse(IpAddresses.cidr("10.0.0.0/8").equals("10.0.0.0/8"));
        for (String bad : List.of("10.0.0.0/33", "10.0.0.0/", "10.0.0.0/08", "::/129", "10.0.0", "300.1.1.1", "host.example",
                "::ffff:10.0.0.0/104", "1:2:3:4:5:6:7:8:9", "1::2::3", "fe80::1%eth0", "12345::", "", "1.2.3.4.5")) {
            assertThrows(IllegalArgumentException.class, () -> IpAddresses.cidr(bad), bad);
        }
    }

    @Test
    void literalsParseWithoutTheResolver() {
        assertEquals("0:0:0:0:0:0:0:0", IpAddresses.text(IpAddresses.address("::")));
        assertEquals("1:0:0:0:0:0:0:0", IpAddresses.text(IpAddresses.address("1::")));
        assertEquals("0:0:0:0:0:0:102:304", IpAddresses.text(IpAddresses.address("::1.2.3.4")));
        assertEquals("1:2:3:4:5:6:708:90a", IpAddresses.text(IpAddresses.address("1:2:3:4:5:6:7.8.9.10")));
        assertEquals("0:0:0:0:0:ff00:102:304", IpAddresses.text(IpAddresses.address("::ff00:1.2.3.4")), "not IPv4-mapped");
        for (String bad : List.of("[::1", "[::1]x", "[::1]:0", "[::1]:65536", "1.2.3.4:x", "1.2.3.4:", ":1", "1:2:3:4:5:6:7",
                "1.2.3.4::1", "1:2:3:4:5:6:7:1.2.3.4", "g::1", "1::2:3:4:5:6:7:8", "[1.2.3.4]", "-1.2.3.4",
                "1:2:3:4:5:6:7:8:1.2.3.4", "1:2:3:4:5:6:1.2.3.4:5", "12345.1.1.1", "a".repeat(46), "1.2.3.4::",
                "::1.2.3.999", "1:2:3:4:5:6:7:", "[::1]:123456", "[]", "[" + "1:".repeat(30) + "]")) {
            assertNull(IpAddresses.address(bad), bad);
        }
        assertNull(IpAddresses.address(null));
    }

    // ---- the process's rule, from the catalogue -------------------------------------------------------------------

    private static Settings settings(Map<String, String> env) {
        return Settings.of(Catalogue.load(TrustedProxies.class.getClassLoader(), TrustedProxies.COMPONENT),
                Sources.of(env, Map.of()));
    }

    @Test
    void theCatalogueDefaultTrustsNoOne() {
        TrustedProxies rule = TrustedProxies.current(settings(Map.of()));
        assertTrue(rule.isEmpty());
        assertEquals(TrustedProxies.HeaderFamily.X_FORWARDED, rule.family());
    }

    @Test
    void theCatalogueNamesTheProxiesAndTheFamily() {
        TrustedProxies rule = TrustedProxies.current(settings(Map.of(TrustedProxies.SETTING, "10.0.0.0/8, 192.0.2.7",
                TrustedProxies.HEADERS_SETTING, "FORWARDED")));
        assertTrue(rule.trusts("192.0.2.7"));
        assertEquals(TrustedProxies.HeaderFamily.FORWARDED, rule.family());
        // The same values again are the same rule, not a new one.
        assertSame(rule, TrustedProxies.current(settings(Map.of(TrustedProxies.SETTING, "10.0.0.0/8, 192.0.2.7",
                TrustedProxies.HEADERS_SETTING, "FORWARDED"))));
        // The same proxies with the other family is a new rule.
        assertEquals(TrustedProxies.HeaderFamily.X_FORWARDED, TrustedProxies.current(settings(Map.of(
                TrustedProxies.SETTING, "10.0.0.0/8, 192.0.2.7"))).family());
    }

    @Test
    void aValueThatIsNotARangeIsRefusedNamingTheSetting() {
        SettingRefused e = assertThrows(SettingRefused.class,
                () -> TrustedProxies.current(settings(Map.of(TrustedProxies.SETTING, "10.0.0.0/8 proxy.internal"))));
        assertEquals(TrustedProxies.SETTING, e.setting());
        assertTrue(e.getMessage().contains("proxy.internal"), e.getMessage());
        SettingRefused family = assertThrows(SettingRefused.class,
                () -> TrustedProxies.current(settings(Map.of(TrustedProxies.HEADERS_SETTING, "both"))));
        assertEquals(TrustedProxies.HEADERS_SETTING, family.setting());
    }

    @Test
    void aSlashZeroRangeTrustsEveryone() {
        TrustedProxies rule = TrustedProxies.current(settings(Map.of(TrustedProxies.SETTING, "0.0.0.0/0")));
        assertTrue(rule.trustsEveryone());
        assertFalse(LB.trustsEveryone());
    }

    @Test
    void theProcessRuleReadsSystemPropertiesAndNeverThrows() {
        System.setProperty("oidf.trusted.proxies", "10.0.0.0/8");
        assertTrue(TrustedProxies.current().trusts("10.1.1.1"));
        assertTrue(TrustedProxies.check().trusts("10.1.1.1"));
        System.setProperty("oidf.trusted.proxies", "not-a-range");
        assertTrue(TrustedProxies.current().isEmpty(), "a bad value believes no forwarding header");
        assertTrue(TrustedProxies.current().isEmpty(), "and is logged once, not again");
        assertThrows(SettingRefused.class, TrustedProxies::check);
        System.clearProperty("oidf.trusted.proxies");
        assertTrue(TrustedProxies.current().isEmpty());
    }

    @Test
    void headerFamilyNames() {
        assertEquals(TrustedProxies.HeaderFamily.X_FORWARDED, TrustedProxies.HeaderFamily.of(null));
        assertEquals(TrustedProxies.HeaderFamily.FORWARDED, TrustedProxies.HeaderFamily.of(" Forwarded "));
        assertEquals("x-forwarded", TrustedProxies.HeaderFamily.X_FORWARDED.setting());
        assertThrows(IllegalArgumentException.class, () -> TrustedProxies.HeaderFamily.of("both"));
    }
}
