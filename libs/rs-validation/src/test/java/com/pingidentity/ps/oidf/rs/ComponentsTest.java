package com.pingidentity.ps.oidf.rs;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.conformance.Requirement;
import com.pingidentity.ps.oidf.platform.http.AddressPolicy;
import com.pingidentity.ps.oidf.platform.http.OutboundHttp;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import org.jose4j.jwk.EcJwkGenerator;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.JsonWebKeySet;
import org.jose4j.jwk.OctetSequenceJsonWebKey;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.keys.EllipticCurves;
import org.junit.jupiter.api.Test;

/** The pieces the validator is built from: nonces, the replay store, the key sources and the typ rule. */
class ComponentsTest {

    // ---- DpopNonces -------------------------------------------------------------------------------------------------

    private static final byte[] SECRET = "0123456789abcdef0123456789abcdef".getBytes(StandardCharsets.US_ASCII);

    /** RFC 9449 §8: "Nonce values MUST be unpredictable." Another secret gives another nonce for the same window. */
    @Test
    @Requirement("RFC9449 §8")
    void aNonceDependsOnTheSecretAndTheWindow() {
        DpopRefusalTest.MutableClock clock = new DpopRefusalTest.MutableClock(Instant.parse("2026-09-28T00:00:00Z"));
        DpopNonces a = new DpopNonces(SECRET, Duration.ofSeconds(30), clock);
        byte[] other = SECRET.clone();
        other[0] ^= 1;
        DpopNonces b = new DpopNonces(other, Duration.ofSeconds(30), clock);
        String now = a.current();
        assertNotEquals(now, b.current());
        assertEquals(DpopNonces.Check.CURRENT, a.check(now));
        assertEquals(DpopNonces.Check.INVALID, b.check(now));
        assertTrue(now.matches("[A-Za-z0-9_-]{43}"), "base64url, within RFC 9449 section 8.1's NQCHAR");
        clock.now = clock.now.plusSeconds(30);
        assertEquals(DpopNonces.Check.PREVIOUS, a.check(now));
        assertNotEquals(now, a.current());
        clock.now = clock.now.plusSeconds(30);
        assertEquals(DpopNonces.Check.INVALID, a.check(now));
    }

    @Test
    void aShortSecretOrWindowIsRefused() {
        assertThrows(IllegalArgumentException.class, () -> new DpopNonces(new byte[31]));
        assertThrows(IllegalArgumentException.class,
                () -> new DpopNonces(SECRET, Duration.ofMillis(999), Clock.systemUTC()));
        assertEquals(DpopNonces.Check.CURRENT, new DpopNonces(SECRET).check(new DpopNonces(SECRET).current()));
    }

    // ---- InMemoryReplayStore ----------------------------------------------------------------------------------------

    @Test
    @Requirement("RFC9449 §11.1")
    void theInMemoryStoreRemembersAKeyForItsWindowOnly() throws Exception {
        DpopRefusalTest.MutableClock clock = new DpopRefusalTest.MutableClock(Instant.parse("2026-09-28T00:00:00Z"));
        InMemoryReplayStore store = new InMemoryReplayStore(10, clock);
        assertTrue(store.firstUse("k", Duration.ofSeconds(5)));
        assertFalse(store.firstUse("k", Duration.ofSeconds(5)));
        clock.now = clock.now.plusSeconds(5);
        assertTrue(store.firstUse("k", Duration.ofSeconds(5)), "the window has passed");
    }

    /** Full, it sweeps what has expired; still full, it answers as unavailable rather than letting a proof through. */
    @Test
    void aFullInMemoryStoreSweepsThenRefuses() throws Exception {
        DpopRefusalTest.MutableClock clock = new DpopRefusalTest.MutableClock(Instant.parse("2026-09-28T00:00:00Z"));
        InMemoryReplayStore store = new InMemoryReplayStore(2, clock);
        assertTrue(store.firstUse("a", Duration.ofSeconds(1)));
        assertTrue(store.firstUse("b", Duration.ofSeconds(10)));
        assertThrows(IOException.class, () -> store.firstUse("c", Duration.ofSeconds(1)));
        assertFalse(store.firstUse("b", Duration.ofSeconds(10)), "a known key is still answered when full");
        clock.now = clock.now.plusSeconds(2);
        assertTrue(store.firstUse("c", Duration.ofSeconds(1)), "a is swept");
        assertEquals(2, store.size());
        assertThrows(IllegalArgumentException.class, () -> new InMemoryReplayStore(0, clock));
        assertEquals(0, new InMemoryReplayStore().size());
    }

    // ---- AccessTokenType --------------------------------------------------------------------------------------------

    @Test
    void theTypeRule() {
        assertTrue(AccessTokenType.RFC9068.accepts("at+jwt"));
        assertTrue(AccessTokenType.RFC9068.accepts("application/at+jwt"));
        assertTrue(AccessTokenType.RFC9068.accepts("AT+JWT"));
        assertFalse(AccessTokenType.RFC9068.accepts("JWT"));
        assertFalse(AccessTokenType.RFC9068.accepts(null));
        assertTrue(AccessTokenType.ABSENT.accepts(null));
        assertFalse(AccessTokenType.ABSENT.accepts("at+jwt"));
        AccessTokenType exact = AccessTokenType.exactly("custom+jwt");
        assertTrue(exact.accepts("Custom+JWT"));
        assertFalse(exact.accepts("application/custom+jwt"));
        assertThrows(IllegalArgumentException.class, () -> AccessTokenType.exactly(" "));
        assertEquals("at+jwt or application/at+jwt", AccessTokenType.RFC9068.toString());
        assertEquals("no typ header", AccessTokenType.ABSENT.toString());
        assertEquals("custom+jwt", exact.toString());
    }

    // ---- StaticJwks ---------------------------------------------------------------------------------------------------

    @Test
    void staticKeysAreIndexedByKidAndOnlyPublicSigningKeysAreKept() throws Exception {
        PublicJsonWebKey sig = EcJwkGenerator.generateJwk(EllipticCurves.P256);
        sig.setKeyId("a");
        PublicJsonWebKey enc = EcJwkGenerator.generateJwk(EllipticCurves.P256);
        enc.setKeyId("b");
        enc.setUse("enc");
        PublicJsonWebKey noKid = EcJwkGenerator.generateJwk(EllipticCurves.P256);
        PublicJsonWebKey emptyKid = EcJwkGenerator.generateJwk(EllipticCurves.P256);
        emptyKid.setKeyId("");
        PublicJsonWebKey used = EcJwkGenerator.generateJwk(EllipticCurves.P256);
        used.setKeyId("c");
        used.setUse("sig");
        OctetSequenceJsonWebKey secret = new OctetSequenceJsonWebKey(new javax.crypto.spec.SecretKeySpec(new byte[32], "HmacSHA256"));
        secret.setKeyId("d");
        StaticJwks jwks = new StaticJwks(List.of(Fixture.publicOnly(sig), Fixture.publicOnly(enc), Fixture.publicOnly(noKid),
                Fixture.publicOnly(emptyKid), Fixture.publicOnly(used), secret));
        assertEquals(1, jwks.keys("a").size());
        assertTrue(jwks.keys("b").isEmpty());
        assertEquals(1, jwks.keys("c").size());
        assertTrue(jwks.keys("d").isEmpty());
        assertTrue(jwks.keys("A").isEmpty(), "exact, case and all");
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> new StaticJwks(List.of(sig)));
        assertTrue(e.getMessage().contains("private key"), e.getMessage());
    }

    // ---- RemoteJwks ---------------------------------------------------------------------------------------------------

    private static String jwks(JsonWebKey... keys) {
        return new JsonWebKeySet(keys).toJson(JsonWebKey.OutputControlLevel.PUBLIC_ONLY);
    }

    @Test
    void remoteKeysAreCachedAndAnUnknownKidRefreshesAtABoundedRate() throws Exception {
        PublicJsonWebKey one = EcJwkGenerator.generateJwk(EllipticCurves.P256);
        one.setKeyId("one");
        PublicJsonWebKey two = EcJwkGenerator.generateJwk(EllipticCurves.P256);
        two.setKeyId("two");
        AtomicReference<String> document = new AtomicReference<>(jwks(one));
        AtomicInteger fetches = new AtomicInteger();
        DpopRefusalTest.MutableClock clock = new DpopRefusalTest.MutableClock(Instant.parse("2026-09-28T00:00:00Z"));
        RemoteJwks remote = new RemoteJwks("https://pf.example.com/pf/JWKS", () -> {
            fetches.incrementAndGet();
            return document.get();
        }, Duration.ofSeconds(30), Duration.ofMinutes(10), clock);

        assertEquals(1, remote.keys("one").size());
        assertEquals(1, remote.keys("one").size());
        assertEquals(1, fetches.get(), "cached");

        document.set(jwks(one, two));
        assertTrue(remote.keys("two").isEmpty(), "inside the refresh interval of the first fetch: not fetched again");
        assertTrue(remote.keys("made-up").isEmpty());
        assertEquals(1, fetches.get());

        clock.now = clock.now.plusSeconds(30);
        assertEquals(1, remote.keys("two").size(), "an unknown kid fetches once the interval has passed");
        assertEquals(2, fetches.get());

        document.set(jwks(two));
        clock.now = clock.now.plusSeconds(600);
        assertTrue(remote.keys("one").isEmpty(), "past the maximum age the cache is fetched again and one is gone");
        assertEquals(3, fetches.get());
    }

    @Test
    void aJwksThatCannotBeReadIsUnavailableNotEmpty() throws Exception {
        PublicJsonWebKey one = EcJwkGenerator.generateJwk(EllipticCurves.P256);
        one.setKeyId("one");
        AtomicReference<String> document = new AtomicReference<>(null);
        DpopRefusalTest.MutableClock clock = new DpopRefusalTest.MutableClock(Instant.parse("2026-09-28T00:00:00Z"));
        RemoteJwks remote = new RemoteJwks("https://pf.example.com/pf/JWKS", () -> {
            if (document.get() == null) {
                throw new IOException("connection refused");
            }
            return document.get();
        }, Duration.ofSeconds(30), Duration.ofMinutes(10), clock);

        IOException never = assertThrows(IOException.class, () -> remote.keys("one"));
        assertTrue(never.getMessage().contains("connection refused"), never.getMessage());

        document.set(jwks(one));
        clock.now = clock.now.plusSeconds(30);
        assertEquals(1, remote.keys("one").size());

        document.set("{not json");
        clock.now = clock.now.plusSeconds(600);
        assertEquals(1, remote.keys("one").size(), "a failed refresh keeps the keys already held");
        assertThrows(IOException.class, () -> remote.keys("two"), "after a failed refresh an unknown kid is not known");

        clock.now = clock.now.plusSeconds(599);
        assertEquals(1, remote.keys("one").size(), "held keys are used until they are twice the maximum age old");
        clock.now = clock.now.plusSeconds(1);
        IOException stale = assertThrows(IOException.class, () -> remote.keys("one"),
                "past twice the maximum age a failing fetch cannot keep a withdrawn key verifying");
        assertTrue(stale.getMessage().contains("twice"), stale.getMessage());

        document.set(jwks(one));
        clock.now = clock.now.plusSeconds(30);
        assertEquals(1, remote.keys("one").size(), "a successful fetch trusts the keys again");
    }

    /** The real transport: platform.http against a local server, the deadline and the status checked. */
    @Test
    void remoteKeysComeThroughPlatformHttp() throws Exception {
        PublicJsonWebKey one = EcJwkGenerator.generateJwk(EllipticCurves.P256);
        one.setKeyId("one");
        AtomicInteger status = new AtomicInteger(200);
        HttpServer server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        byte[] body = jwks(one).getBytes(StandardCharsets.UTF_8);
        List<String> accepts = new ArrayList<>();
        server.createContext("/jwks", exchange -> {
            accepts.add(exchange.getRequestHeaders().getFirst("Accept"));
            exchange.sendResponseHeaders(status.get(), body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        });
        server.start();
        try {
            OutboundHttp http = OutboundHttp.builder(AddressPolicy.builder().allowHttp(true).allowPrivateNetworks(true)
                    .build()).build();
            String uri = "http://127.0.0.1:" + server.getAddress().getPort() + "/jwks";
            assertEquals(1, new RemoteJwks(http, uri).keys("one").size());
            assertEquals(List.of("application/json"), accepts);
            status.set(500);
            IOException e = assertThrows(IOException.class, () -> new RemoteJwks(http, uri, Duration.ofSeconds(2),
                    Duration.ofSeconds(1), Duration.ofMinutes(1), Clock.systemUTC()).keys("one"));
            assertTrue(e.getMessage().contains("answered 500"), e.getMessage());
        } finally {
            server.stop(0);
        }
    }
}
