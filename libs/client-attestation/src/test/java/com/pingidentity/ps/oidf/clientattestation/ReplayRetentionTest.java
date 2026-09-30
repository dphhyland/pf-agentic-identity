package com.pingidentity.ps.oidf.clientattestation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.clientattestation.AttestationReplayCache.Verdict;
import com.pingidentity.ps.oidf.platform.profile.DeploymentProfile;
import com.pingidentity.ps.oidf.platform.redis.RedisClient;
import com.pingidentity.ps.oidf.platform.redis.RedisConfig;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.NumericDate;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Replay retention derived from the acceptance window, not from first use (plan item S4c, finding F-0036): the
 * stores' absolute form, and the authorization server's PoP and DPoP retention of {@code iat + maxAge + 2 x skew}.
 */
class ReplayRetentionTest {
    private static final String ATTESTER = "https://attester.example.com";
    private static final String CLIENT_ID = "https://rp.example.com";
    private static final String OP_ISSUER = "https://op.example.com";
    private static final String TOKEN_ENDPOINT = OP_ISSUER + "/as/token.oauth2";
    private static final long T = 1_900_000_000L;

    private PublicJsonWebKey attesterKey;
    private PublicJsonWebKey instanceKey;

    @BeforeEach
    void setUp() throws Exception {
        AttestationRarModels.resetForTest(Map.of());
        attesterKey = TestJwts.ec("attester-1");
        instanceKey = TestJwts.ec("instance-1");
    }

    @AfterEach
    void readTheProcessEnvironmentAgain() {
        AttestationRarModels.resetForTest(null);
    }

    // ---- the in-memory store -------------------------------------------------------------------------------

    @Test
    void memoryRemembersAJtiThroughTheWholeOfItsLastSecond() {
        MutableClock clock = new MutableClock(Instant.ofEpochSecond(T));
        InMemoryAttestationReplayCache cache = new InMemoryAttestationReplayCache(16, clock);
        assertEquals(Verdict.FIRST_USE, cache.recordUntil("c", "j", T + 100));
        clock.set(Instant.ofEpochSecond(T + 99));
        assertEquals(Verdict.REPLAY, cache.recordUntil("c", "j", T + 100), "one second before the retention");
        clock.set(Instant.ofEpochMilli((T + 100) * 1000L + 999L));
        assertEquals(Verdict.REPLAY, cache.recordUntil("c", "j", T + 100), "the last millisecond of its last second");
        clock.set(Instant.ofEpochSecond(T + 101));
        assertEquals(Verdict.STALE, cache.recordUntil("c", "j", T + 100),
                "one second after the retention the proof itself can no longer be accepted");
        assertEquals(Verdict.FIRST_USE, cache.recordUntil("c", "j", T + 200),
                "and the old entry no longer counts against a new window");
    }

    @Test
    void memoryRefusesAPastRetentionWithoutRecordingIt() {
        MutableClock clock = new MutableClock(Instant.ofEpochSecond(T));
        InMemoryAttestationReplayCache cache = new InMemoryAttestationReplayCache(16, clock);
        assertEquals(Verdict.STALE, cache.recordUntil("c", "j", T - 1));
        assertEquals(0, cache.size());
        assertThrows(IllegalArgumentException.class, () -> cache.recordUntil("c", " ", T + 1));
        assertThrows(IllegalArgumentException.class, () -> cache.recordUntil("c", null, T + 1));
        assertThrows(IllegalArgumentException.class, () -> new InMemoryAttestationReplayCache(0, clock));
    }

    @Test
    void aFullMemoryForgetsExpiredEntriesBeforeLiveOnes() {
        MutableClock clock = new MutableClock(Instant.ofEpochSecond(T));
        InMemoryAttestationReplayCache cache = new InMemoryAttestationReplayCache(2, clock);
        assertEquals(Verdict.FIRST_USE, cache.recordUntil("c", "short", T + 10));
        assertEquals(Verdict.FIRST_USE, cache.recordUntil("c", "long", T + 1000));
        clock.set(Instant.ofEpochSecond(T + 11));
        assertEquals(Verdict.FIRST_USE, cache.recordUntil("c", "new", T + 1000));
        assertEquals(Verdict.REPLAY, cache.recordUntil("c", "long", T + 1000),
                "the live entry survived: the expired one made the room");
    }

    @Test
    void anUnboundedMemoryIsNeverSwept() {
        MutableClock clock = new MutableClock(Instant.ofEpochSecond(T));
        InMemoryAttestationReplayCache cache = new InMemoryAttestationReplayCache(AttestationReplayCache.UNBOUNDED, clock);
        for (int i = 0; i < 10; i++) {
            assertEquals(Verdict.FIRST_USE, cache.recordUntil("c", "j" + i, T + 1));
        }
        assertEquals(10, cache.size());
    }

    @Test
    @SuppressWarnings("deprecation")
    void theRelativeFormCountsFromTheStoresOwnClock() {
        MutableClock clock = new MutableClock(Instant.ofEpochSecond(T));
        InMemoryAttestationReplayCache cache = new InMemoryAttestationReplayCache(16, clock);
        assertEquals(Verdict.FIRST_USE, cache.record("c", "j", 300L));
        clock.set(Instant.ofEpochSecond(T + 300));
        assertEquals(Verdict.REPLAY, cache.record("c", "j", 300L));
        clock.set(Instant.ofEpochSecond(T + 601));
        assertEquals(Verdict.FIRST_USE, cache.record("c", "j", 0L), "a TTL of 0 is at least a second");
    }

    @Test
    @SuppressWarnings("deprecation")
    void theInterfacesRelativeFormAsksForAnAbsoluteRetention() {
        long[] asked = new long[1];
        AttestationReplayCache cache = (clientId, jti, retainUntil) -> {
            asked[0] = retainUntil;
            return Verdict.FIRST_USE;
        };
        long before = Instant.now().getEpochSecond();
        assertEquals(Verdict.FIRST_USE, cache.record("c", "j", 300L));
        assertTrue(asked[0] >= before + 300L && asked[0] <= Instant.now().getEpochSecond() + 300L, String.valueOf(asked[0]));
        assertTrue(cache.firstSeen("c", "j", 0L));
        assertTrue(asked[0] >= before + 1L, "a TTL of 0 or less is at least a second");
    }

    // ---- the Redis store (the fake server; RedisLiveTest runs the same against a real one) ------------------

    @Test
    void redisExpiresTheKeyAtTheEndOfTheRetentionSecond() throws Exception {
        try (FakeRedisServer redis = new FakeRedisServer("s3cr3t");
             RedisAttestationStore store = new RedisAttestationStore(client(redis.url()), true, StoreNamespace.CAS, 300L,
                     Clock.systemUTC())) {
            long now = Instant.now().getEpochSecond();
            // Retained through the current second only: at most a second of PX, computed once.
            assertEquals(Verdict.FIRST_USE, store.recordUntil("c", "j", now));
            assertEquals(Verdict.REPLAY, store.recordUntil("c", "j", Instant.now().getEpochSecond()));
            Thread.sleep(1100L);
            assertEquals(Verdict.FIRST_USE, store.recordUntil("c", "j", Instant.now().getEpochSecond() + 60L),
                    "the key expired when its second ended");
        }
    }

    @Test
    void redisAnswersAPastRetentionWithoutAskingTheServer() throws Exception {
        MutableClock clock = new MutableClock(Instant.ofEpochSecond(T));
        // Nothing listens here: a verdict other than STORE_UNAVAILABLE proves the server was not asked.
        try (RedisAttestationStore store = new RedisAttestationStore(client("redis://:pw@127.0.0.1:1"), true,
                StoreNamespace.CAS, 300L, clock)) {
            assertEquals(Verdict.STALE, store.recordUntil("c", "j", T - 1));
            assertEquals(Verdict.STORE_UNAVAILABLE, store.recordUntil("c", "j", T));
            assertEquals(Verdict.STORE_UNAVAILABLE, store.recordUntil("c", "j", Long.MAX_VALUE),
                    "a retention too far off to express in milliseconds saturates rather than wrapping into the past");
            assertThrows(IllegalArgumentException.class, () -> store.recordUntil("c", "", T));
            assertThrows(IllegalArgumentException.class, () -> store.recordUntil("c", null, T));
        }
    }

    @Test
    @SuppressWarnings("deprecation")
    void redisRelativeFormCountsFromTheStoresClock() throws Exception {
        try (FakeRedisServer redis = new FakeRedisServer("s3cr3t");
             RedisAttestationStore store = new RedisAttestationStore(client(redis.url()), true, StoreNamespace.CAS, 300L,
                     Clock.systemUTC())) {
            assertEquals(Verdict.FIRST_USE, store.record("c", "j", 300L));
            assertEquals(Verdict.REPLAY, store.record("c", "j", 300L));
        }
    }

    // ---- the authorization server's PoP and DPoP retention ---------------------------------------------------

    @Test
    void theRetentionIsTheWindowPlusTwoSkewsAndNeverLessThanBefore() {
        assertEquals(T + 300 + 120, ClientAttestationVerifier.retentionFor(T, 300, 60, T));
        assertEquals(T + 300 + 120, ClientAttestationVerifier.retentionFor(T, 300, 60, T + 60),
                "a proof accepted at the far edge of its skew is still remembered until iat + maxAge + 2 x skew");
        assertEquals(T + 300 + 60, ClientAttestationVerifier.retentionFor(T - 200, 300, 60, T),
                "an iat behind the clock keeps the pre-S4c floor of maxAge + skew from now");
        assertEquals(Long.MAX_VALUE, ClientAttestationVerifier.retentionFor(Long.MAX_VALUE - 5, 300, 60, T));
        assertEquals(T + 360, ClientAttestationVerifier.retentionFor(Long.MIN_VALUE + 5, 300, 60, T));
    }

    /**
     * Two nodes share one store, and the second's clock is a full skew behind the store's. A PoP the first node
     * accepted at its {@code iat} is still acceptable to the second until {@code iat + maxAge + 2 x skew} on the
     * store's clock, so it has to be remembered that long. Before S4c it was remembered for {@code maxAge + skew}
     * from first use, and the second node accepted it again inside that last skew.
     */
    @Test
    void aPopAcceptedByOneNodeIsARefusedReplayOnALaggingNodeUntilTheRetentionEnds() throws Exception {
        long iat = Instant.now().getEpochSecond();
        MutableClock storeClock = new MutableClock(Instant.ofEpochSecond(iat));
        MutableClock nodeB = new MutableClock(Instant.ofEpochSecond(iat));
        InMemoryAttestationReplayCache shared = new InMemoryAttestationReplayCache(64, storeClock);
        ClientAttestationVerifier a = verifier(shared, Clock.fixed(Instant.ofEpochSecond(iat), ZoneOffset.UTC));
        ClientAttestationVerifier b = verifier(shared, nodeB);

        String attestation = attestation();
        String pop = pop("p-edge", iat);
        a.verify(attestation, pop, null, "POST", TOKEN_ENDPOINT, CLIENT_ID);

        // One second before the retention (iat + 419 on the store): node B reads iat + 359, inside its window.
        storeClock.set(Instant.ofEpochSecond(iat + 419));
        nodeB.set(Instant.ofEpochSecond(iat + 359));
        ClientAttestationException replay = assertThrows(ClientAttestationException.class,
                () -> b.verify(attestation, pop, null, "POST", TOKEN_ENDPOINT, CLIENT_ID));
        assertEquals("Replay detected for proof jti", replay.getMessage());

        // One second after it (iat + 421): node B reads iat + 361, and the proof is stale there too.
        storeClock.set(Instant.ofEpochSecond(iat + 421));
        nodeB.set(Instant.ofEpochSecond(iat + 361));
        ClientAttestationException stale = assertThrows(ClientAttestationException.class,
                () -> b.verify(attestation, pop, null, "POST", TOKEN_ENDPOINT, CLIENT_ID));
        assertTrue(stale.getMessage().startsWith("PoP is stale"), stale.getMessage());
    }

    @Test
    void aDpopProofIsRememberedUntilItsWindowEndsOnEveryNode() throws Exception {
        long iat = Instant.now().getEpochSecond();
        MutableClock storeClock = new MutableClock(Instant.ofEpochSecond(iat));
        MutableClock nodeB = new MutableClock(Instant.ofEpochSecond(iat));
        InMemoryAttestationReplayCache shared = new InMemoryAttestationReplayCache(64, storeClock);
        ClientAttestationVerifier a = verifier(shared, Clock.fixed(Instant.ofEpochSecond(iat), ZoneOffset.UTC));
        ClientAttestationVerifier b = verifier(shared, nodeB);

        String attestation = attestation();
        String dpop = dpop("d-edge", iat);
        a.verify(attestation, null, dpop, "POST", TOKEN_ENDPOINT, CLIENT_ID);

        storeClock.set(Instant.ofEpochSecond(iat + 419));
        nodeB.set(Instant.ofEpochSecond(iat + 359));
        ClientAttestationException replay = assertThrows(ClientAttestationException.class,
                () -> b.verify(attestation, null, dpop, "POST", TOKEN_ENDPOINT, CLIENT_ID));
        assertEquals("Replay detected for proof jti", replay.getMessage());

        storeClock.set(Instant.ofEpochSecond(iat + 421));
        nodeB.set(Instant.ofEpochSecond(iat + 361));
        ClientAttestationException stale = assertThrows(ClientAttestationException.class,
                () -> b.verify(attestation, null, dpop, "POST", TOKEN_ENDPOINT, CLIENT_ID));
        assertTrue(stale.getMessage().startsWith("DPoP is stale"), stale.getMessage());
    }

    @Test
    void aStoreWhoseClockHasPassedTheRetentionRefusesTheProofAsStale() throws Exception {
        long iat = Instant.now().getEpochSecond();
        // The store's clock is far ahead of the verifier's: the retention the verifier asks for has passed there.
        InMemoryAttestationReplayCache ahead = new InMemoryAttestationReplayCache(64,
                Clock.fixed(Instant.ofEpochSecond(iat + 10_000), ZoneOffset.UTC));
        ClientAttestationVerifier v = verifier(ahead, Clock.fixed(Instant.ofEpochSecond(iat), ZoneOffset.UTC));
        ClientAttestationException stale = assertThrows(ClientAttestationException.class,
                () -> v.verify(attestation(), pop("p-ahead", iat), null, "POST", TOKEN_ENDPOINT, CLIENT_ID));
        assertEquals("Proof is stale", stale.getMessage());
    }

    @Test
    void aPopFromTheFutureIsRefusedByTheConfiguredClock() throws Exception {
        long now = Instant.now().getEpochSecond();
        // The verifier's clock is two skews behind the PoP's iat: from its point of view the PoP is not yet valid.
        ClientAttestationVerifier behind = verifier(new InMemoryAttestationReplayCache(),
                Clock.fixed(Instant.ofEpochSecond(now - 121), ZoneOffset.UTC));
        ClientAttestationException e = assertThrows(ClientAttestationException.class,
                () -> behind.verify(attestation(), pop("p-future", now), null, "POST", TOKEN_ENDPOINT, CLIENT_ID));
        assertEquals("PoP 'iat' is in the future", e.getMessage());
    }

    @Test
    void aMaxAgeOfZeroOrLessIsRefused() {
        ClientAttestationConfig.Builder b = ClientAttestationConfig.builder();
        assertThrows(IllegalArgumentException.class, () -> b.popMaxAgeSeconds(0L));
        assertThrows(IllegalArgumentException.class, () -> b.dpopMaxAgeSeconds(-1L));
        assertThrows(NullPointerException.class, () -> b.clock(null));
        assertEquals(Clock.systemUTC(), ClientAttestationConfig.builder().build().clock());
    }

    // ---- helpers --------------------------------------------------------------------------------------------

    private ClientAttestationVerifier verifier(AttestationReplayCache cache, Clock clock) {
        ClientAttestationConfig config = ClientAttestationConfig.builder()
                .expectedAudience(OP_ISSUER)
                .expectedHtu(TOKEN_ENDPOINT)
                .clock(clock)
                .build();
        AttesterKeyResolver resolver = (iss, chain) -> List.of(JsonWebKey.Factory.newJwk(TestJwts.publicParams(attesterKey)));
        return new ClientAttestationVerifier(resolver, config, cache, new InMemoryAttestationChallengeService());
    }

    private String attestation() throws Exception {
        JwtClaims att = new JwtClaims();
        att.setIssuer(ATTESTER);
        att.setSubject(CLIENT_ID);
        att.setIssuedAtToNow();
        att.setExpirationTime(NumericDate.fromSeconds(NumericDate.now().getValue() + 600L));
        att.setClaim("cnf", Map.of("jwk", TestJwts.publicParams(instanceKey)));
        return TestJwts.sign(attesterKey, "ES256", "oauth-client-attestation+jwt", att);
    }

    private String pop(String jti, long iat) throws Exception {
        JwtClaims pop = new JwtClaims();
        pop.setIssuer(CLIENT_ID);
        pop.setAudience(OP_ISSUER);
        pop.setJwtId(jti);
        pop.setIssuedAt(NumericDate.fromSeconds(iat));
        return TestJwts.sign(instanceKey, "ES256", "oauth-client-attestation-pop+jwt", pop);
    }

    private String dpop(String jti, long iat) throws Exception {
        JwtClaims d = new JwtClaims();
        d.setClaim("htm", "POST");
        d.setClaim("htu", TOKEN_ENDPOINT);
        d.setJwtId(jti);
        d.setIssuedAt(NumericDate.fromSeconds(iat));
        return TestJwts.signWithJwkHeader(instanceKey, "ES256", "dpop+jwt", d);
    }

    private static RedisClient client(String url) {
        return new RedisClient(RedisConfig.builder(url).profile(DeploymentProfile.DEVELOPMENT).build());
    }

    static final class MutableClock extends Clock {
        private volatile Instant now;

        MutableClock(Instant now) {
            this.now = now;
        }

        void set(Instant instant) {
            this.now = instant;
        }

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return this.now;
        }
    }
}
