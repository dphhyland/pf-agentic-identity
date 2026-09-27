package com.pingidentity.ps.oidf.platform.http;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.platform.http.OutboundHttpException.Reason;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.URI;
import java.net.UnknownHostException;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

/** The address policy's URL rules, its address classification and its exemptions. */
class AddressPolicyTest {

    private static final InetAddress PUBLIC = address("93.184.215.14");

    private static InetAddress address(String literal) {
        try {
            return InetAddress.getByName(literal);
        } catch (UnknownHostException e) {
            throw new IllegalStateException(e);
        }
    }

    /** A 16-byte address kept as IPv6 even when it is IPv4-mapped (InetAddress.getByName would unwrap that). */
    private static InetAddress v6(String literal) {
        try {
            return Inet6Address.getByAddress(null, InetAddress.getByName(literal).getAddress().length == 16
                    ? InetAddress.getByName(literal).getAddress() : mapped(InetAddress.getByName(literal).getAddress()), -1);
        } catch (UnknownHostException e) {
            throw new IllegalStateException(e);
        }
    }

    private static byte[] mapped(byte[] v4) {
        byte[] bytes = new byte[16];
        bytes[10] = (byte) 0xFF;
        bytes[11] = (byte) 0xFF;
        System.arraycopy(v4, 0, bytes, 12, 4);
        return bytes;
    }

    private static AddressPolicy.Builder resolvingTo(InetAddress... addresses) {
        return AddressPolicy.builder().resolver(host -> addresses);
    }

    private static Reason refusal(AddressPolicy policy, String url) {
        return assertThrows(OutboundHttpException.class, () -> policy.check(url)).reason();
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "0.0.0.0", "0.1.2.3", "10.0.0.1", "100.64.0.1", "100.127.255.255", "127.0.0.1", "169.254.169.254",
        "172.16.0.1", "172.31.255.255", "192.0.0.8", "192.0.2.1", "192.168.1.1", "198.18.0.1", "198.19.255.255",
        "198.51.100.7", "203.0.113.9", "224.0.0.1", "239.255.255.255", "240.0.0.1", "255.255.255.255",
        "::", "::1", "::10.0.0.1", "::8.8.8.8", "100::1", "2001::1", "2001:0:4136:e378:8000:63bf:3fff:fdd2",
        "2001:db8::1", "fc00::1", "fd12:3456::1", "fe80::1", "febf::1", "fec0::1", "feff::1", "ff02::1",
        "64:ff9b::a00:1", "64:ff9b::7f00:1", "2002:a00:1::1", "2002:7f00:1::", "::ffff:0:a00:1",
        "64:ff9b:1:a00:1::", "64:ff9b:1:0:a00:100::", "64:ff9b:1:0:a:1:0:0", "64:ff9b:1::a00:1"
    })
    void aNonPublicAddressIsNamedAsSuch(String literal) {
        InetAddress address = address(literal);
        assertFalse(AddressPolicy.isPublic(address), literal);
        assertTrue(AddressPolicy.nonPublicReason(address).startsWith("in ")
                || AddressPolicy.nonPublicReason(address).contains("embedding"), AddressPolicy.nonPublicReason(address));
    }

    @ParameterizedTest
    @ValueSource(strings = {"10.0.0.1", "127.0.0.1", "169.254.169.254", "0.0.0.0", "240.1.1.1"})
    void anIpv4MappedAddressKeptAsIpv6IsJudgedByTheAddressItEmbeds(String v4) {
        InetAddress mapped = v6(v4);
        assertEquals(16, mapped.getAddress().length);
        assertTrue(AddressPolicy.nonPublicReason(mapped).startsWith("IPv4-mapped"), AddressPolicy.nonPublicReason(mapped));
        assertTrue(AddressPolicy.isPublic(v6("8.8.8.8")));
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "1.1.1.1", "8.8.8.8", "93.184.215.14", "100.63.255.255", "100.128.0.0", "172.15.255.255", "172.32.0.0",
        "192.0.1.1", "192.0.3.1", "192.167.0.1", "198.17.0.1", "198.20.0.1", "198.51.101.1", "203.0.114.1",
        "169.253.0.1", "223.255.255.255", "11.0.0.1", "126.0.0.1", "192.169.0.1", "203.1.113.1", "198.50.100.1",
        "2606:4700::1111", "2a00:1450::1", "2001:4860:4860::8888", "64:ff9b::808:808", "2002:808:808::1",
        "::ffff:0:808:808", "64:ff9b:1:808:8:808:808:808", "64:ff9b:2::1", "2001:db9::1", "2001:1::1",
        "101::1", "100:0:0:1::1", "fe00::1", "0:0:0:1::1", "1::", "::1:0:0:0", "64::1", "64:ff00::1",
        "64:ff9b:100::1", "2001:d00::1", "2003::1", "::ffff:1:808:808", "::ff00:808:808"
    })
    void aPublicAddressPasses(String literal) {
        assertNull(AddressPolicy.nonPublicReason(address(literal)), literal);
        assertTrue(AddressPolicy.isPublic(address(literal)));
    }

    @Test
    void nat64LocalUseIsReadAtEveryPrefixLength() {
        // 64:ff9b:1::/48 with 10.0.0.1 at /48, /56, /64 and /96 in turn; public 8.8.8.8 elsewhere.
        assertTrue(AddressPolicy.nonPublicReason(address("64:ff9b:1:a00:0:100::")).contains("10.0.0.1"));
        assertTrue(AddressPolicy.nonPublicReason(address("64:ff9b:1:80a:0:1::")).contains("10.0.0.1"));
        assertTrue(AddressPolicy.nonPublicReason(address("64:ff9b:1:808:a:0:100::")).contains("10.0.0.1"));
        assertTrue(AddressPolicy.nonPublicReason(address("64:ff9b:1:808:8:808:a00:1")).contains("10.0.0.1"));
        assertNull(AddressPolicy.nonPublicReason(address("64:ff9b:1:808:8:808:808:808")));
        // The usual /96 deployment pads with zeros, which read as 0.0.0.0/8 at the shorter positions and are skipped.
        assertNull(AddressPolicy.nonPublicReason(address("64:ff9b:1::808:808")));
        assertTrue(AddressPolicy.nonPublicReason(address("64:ff9b:1::1")).contains("0.0.0.1"));
    }

    @Test
    void theStrictPolicyTakesHttpsToPublicAddressesOnly() throws Exception {
        AddressPolicy policy = resolvingTo(PUBLIC).build();
        AddressPolicy.Target target = policy.check("https://Example.COM/entity");
        assertTrue(target.tls());
        assertEquals("example.com", target.host());
        assertEquals(443, target.port());
        assertEquals(List.of(PUBLIC), target.addresses());
        assertEquals("https://example.com:443", target.origin());
        assertEquals(URI.create("https://Example.COM/entity"), target.uri());
        assertEquals(Reason.REFUSED_URL, refusal(policy, "http://example.com/"));
        assertEquals(Reason.REFUSED_URL, refusal(policy, "ftp://example.com/"));
        assertEquals(Reason.REFUSED_URL, refusal(policy, "example.com/path"));
        assertEquals(Reason.REFUSED_URL, refusal(policy, "https:///nohost"));
        assertEquals(Reason.REFUSED_URL, refusal(policy, "https://user:pass@example.com/"));
        assertEquals(Reason.REFUSED_URL, refusal(policy, "https://example.com:0/"));
        assertEquals(Reason.REFUSED_URL, refusal(policy, "https://example.com:65536/"));
        assertEquals(Reason.REFUSED_URL, refusal(policy, "https://exa mple.com/"));
        assertEquals(Reason.REFUSED_URL, refusal(policy, "https://under_score.com/"));
        assertEquals(65535, policy.check("https://example.com:65535/").port());
        assertEquals(1, policy.check("https://example.com:1/").port());
        assertThrows(NullPointerException.class, () -> policy.check((String) null));
        assertThrows(NullPointerException.class, () -> policy.check((URI) null));
    }

    @Test
    void httpIsAllowedOnlyWhenAskedAndThenOnPort80ByDefault() throws Exception {
        AddressPolicy.Target target = resolvingTo(PUBLIC).allowHttp(true).build().check("http://example.com/");
        assertFalse(target.tls());
        assertEquals(80, target.port());
        assertEquals("http://example.com:80", target.origin());
    }

    @Test
    void anIpv6LiteralLosesItsBracketsForTheHostAndKeepsThemInTheOrigin() throws Exception {
        AddressPolicy.Target target = AddressPolicy.builder().allowPrivateNetworks(true).build().check("https://[::1]:8443/");
        assertEquals("::1", target.host());
        assertEquals("https://[::1]:8443", target.origin());
    }

    @Test
    void oneNonPublicAddressAmongPublicOnesRefusesTheName() {
        OutboundHttpException e = assertThrows(OutboundHttpException.class,
                () -> resolvingTo(PUBLIC, address("169.254.169.254")).build().check("https://mixed.example/"));
        assertEquals(Reason.REFUSED_ADDRESS, e.reason());
        assertTrue(e.getMessage().contains("169.254.169.254") && e.getMessage().contains("link-local"), e.getMessage());
    }

    @Test
    void aTestRuleThatNamesNoReasonStillRefuses() {
        OutboundHttpException e = assertThrows(OutboundHttpException.class,
                () -> resolvingTo(PUBLIC).publicAddress(a -> false).build().check("https://example.com/"));
        assertTrue(e.getMessage().endsWith("which is not a public address"), e.getMessage());
    }

    @Test
    void privateNetworksMayBeAllowedAltogether() throws Exception {
        assertEquals(1, resolvingTo(address("10.0.0.1")).allowPrivateNetworks(true).build()
                .check("https://internal/").addresses().size());
    }

    @Test
    void anAddressExemptHostAndItsSubdomainsMayResolvePrivatelyButNotItsLookalikes() throws Exception {
        AddressPolicy policy = resolvingTo(address("10.0.0.1"))
                .addressExemptHosts(java.util.Arrays.asList("Railway.Internal", " ", null, "spire")).build();
        assertEquals(address("10.0.0.1"), policy.check("https://controller.railway.internal/").addresses().get(0));
        assertEquals(address("10.0.0.1"), policy.check("https://railway.internal/").addresses().get(0));
        assertEquals(address("10.0.0.1"), policy.check("https://spire/").addresses().get(0));
        assertEquals(Reason.REFUSED_ADDRESS, refusal(policy, "https://evilrailway.internal/"));
        assertEquals(Reason.REFUSED_URL, refusal(policy, "http://railway.internal/"));
    }

    @Test
    void aTrustedEndpointIsExemptOnlyAtItsOriginAndPathPrefix() throws Exception {
        AddressPolicy policy = resolvingTo(address("127.0.0.1"))
                .trusting("http://spire.local:8081/bundle/", null, " ", "not a url", "mailto:x@y", "http:///nohost",
                        "http://spire.local:8081/bundle", "https://anchor.local")
                .build();
        assertEquals(8081, policy.check("http://spire.local:8081/bundle").port());
        assertEquals(8081, policy.check("http://spire.local:8081/bundle/v1/keys").port());
        assertEquals(443, policy.check("https://anchor.local/anything/at/all").port());
        assertEquals(443, policy.check("https://anchor.local").port());
        assertEquals(Reason.REFUSED_URL, refusal(policy, "http://spire.local:8082/bundle"));
        assertEquals(Reason.REFUSED_URL, refusal(policy, "http://spire.local/bundle"));
        assertEquals(Reason.REFUSED_URL, refusal(policy, "http://spire.local:8081/bundles"));
        assertEquals(Reason.REFUSED_URL, refusal(policy, "http://spire.local:8081/"));
        assertEquals(Reason.REFUSED_URL, refusal(policy, "http://other.local:8081/bundle"));
        assertEquals(Reason.REFUSED_ADDRESS, refusal(policy, "https://spire.local:8081/bundle"));
        assertEquals(Reason.REFUSED_URL, refusal(policy, "http://spire.local:8081/bundle/../admin"));
        assertEquals(Reason.REFUSED_URL, refusal(policy, "http://spire.local:8081/bundle/%2e%2e/admin"));
        assertEquals(Reason.REFUSED_URL, refusal(policy, "http://spire.local:8081/bundle/./x"));
    }

    @Test
    void endpointsCompareByEverythingThatPinsThem() {
        AddressPolicy.Endpoint a = AddressPolicy.Endpoint.of("https://a.test/p");
        assertEquals(a, AddressPolicy.Endpoint.of("HTTPS://A.test:443/p/"));
        assertEquals(a.hashCode(), AddressPolicy.Endpoint.of("https://a.test:443/p").hashCode());
        assertNotEquals(a, AddressPolicy.Endpoint.of("http://a.test:443/p"));
        assertNotEquals(a, AddressPolicy.Endpoint.of("https://b.test/p"));
        assertNotEquals(a, AddressPolicy.Endpoint.of("https://a.test:444/p"));
        assertNotEquals(a, AddressPolicy.Endpoint.of("https://a.test/q"));
        assertNotEquals(a, "https://a.test/p");
        assertTrue(a.matches("https", "a.test", 443, "/p"));
        assertFalse(a.matches("https", "a.test", 443, null));
        assertTrue(AddressPolicy.Endpoint.of("https://a.test").matches("https", "a.test", 443, null));
        assertTrue(AddressPolicy.Endpoint.of("https://[::1]/").matches("https", "::1", 443, "/"));
        assertNull(AddressPolicy.Endpoint.of("spire.local/bundle"));
        assertNull(AddressPolicy.Endpoint.of("ftp://a.test/"));
    }

    @Test
    void resolutionFailuresAreUnresolved() {
        assertEquals(Reason.UNRESOLVED, refusal(AddressPolicy.builder().resolver(host -> {
            throw new UnknownHostException(host);
        }).build(), "https://nowhere.test/"));
        assertEquals(Reason.UNRESOLVED, refusal(AddressPolicy.builder().resolver(host -> {
            throw new SecurityException("no");
        }).build(), "https://nowhere.test/"));
        assertEquals(Reason.UNRESOLVED, refusal(AddressPolicy.builder().resolver(host -> null).build(), "https://nowhere.test/"));
        assertEquals(Reason.UNRESOLVED, refusal(AddressPolicy.builder().resolver(host -> new InetAddress[0]).build(),
                "https://nowhere.test/"));
        assertEquals(Reason.UNRESOLVED, refusal(AddressPolicy.builder().resolver(host -> new InetAddress[] {null}).build(),
                "https://nowhere.test/"));
        assertThrows(NullPointerException.class, () -> AddressPolicy.builder().resolver(null));
        assertThrows(NullPointerException.class, () -> AddressPolicy.builder().addressExemptHosts(null));
    }

    @Test
    void theResolverIsAskedOncePerCheck() throws Exception {
        AtomicInteger lookups = new AtomicInteger();
        AddressPolicy policy = AddressPolicy.builder().resolver(host -> {
            lookups.incrementAndGet();
            return new InetAddress[] {PUBLIC, address("2606:4700::1111")};
        }).build();
        assertEquals(2, policy.check("https://twice.example/").addresses().size());
        assertEquals(1, lookups.get());
    }

    @Test
    void theJvmResolverResolvesLiteralsWithoutAsking() throws Exception {
        assertEquals(address("127.0.0.1"), AddressPolicy.builder().allowPrivateNetworks(true).build()
                .check("https://127.0.0.1/").addresses().get(0));
        assertEquals(Reason.REFUSED_ADDRESS, refusal(AddressPolicy.strict(), "https://127.0.0.1/"));
    }

    @ParameterizedTest
    @CsvSource({
        "example.com,false", "127.0.0.1,true", "::1,true", "1.2.3,false", "1.2.3.4.5,false", "1.2.3.,false",
        "1.2.3.1234,false", "1.2.a.4,false", "1.2.-3.4,false", "999.1.1.1,true", "10.0.0.1.example,false"
    })
    void literalsAreToldFromNames(String host, boolean literal) {
        assertEquals(literal, AddressPolicy.isLiteral(host));
    }

    @Test
    void bracketsComeOffOnlyWhenTheyEnclose() {
        assertEquals("::1", AddressPolicy.unbracket("[::1]"));
        assertEquals("[::1", AddressPolicy.unbracket("[::1"));
        assertEquals("::1]", AddressPolicy.unbracket("::1]"));
        assertEquals("[", AddressPolicy.unbracket("["));
        assertEquals("a", AddressPolicy.unbracket("a"));
    }
}
