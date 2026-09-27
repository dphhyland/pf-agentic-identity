package com.pingidentity.ps.oidf.clientattestation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.clientattestation.AttestationChallengeService.Consumption;
import com.pingidentity.ps.oidf.clientattestation.AttestationReplayCache.Verdict;
import com.pingidentity.ps.oidf.clientattestation.EvidenceBindingStore.Binding;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class RedisAttestationStoreTest {

    private FakeRedisServer redis;
    private RedisAttestationStore store;

    @BeforeEach
    void start() throws Exception {
        redis = new FakeRedisServer("s3cr3t");
        store = store(redis.url(), StoreNamespace.AS, 300L);
    }

    /** A store over a plaintext URL, as a development rig runs it; the fake server speaks no TLS. */
    private static RedisAttestationStore store(String url, StoreNamespace namespace, long ttlSeconds) {
        return new RedisAttestationStore(new MiniRedisClient(url, null, false), true, namespace, ttlSeconds, Clock.systemUTC());
    }

    @Test
    void thePublicConstructorReadsTheProfileAndRefusesPlaintextInProduction() {
        if (DeploymentProfile.isProduction(System::getenv)) {
            assertThrows(IllegalArgumentException.class, () -> new RedisAttestationStore(redis.url(), 300L));
            assertThrows(IllegalArgumentException.class, () -> new RedisAttestationStore(redis.url(), StoreNamespace.CAS, 300L));
        }
    }

    private static long now() {
        return Instant.now().getEpochSecond();
    }

    @AfterEach
    void stop() throws Exception {
        store.close();
        redis.close();
    }

    @Test
    void issuedChallengeCanBeConsumedOnce() {
        String challenge = store.issue();
        assertNotNull(challenge);
        assertTrue(store.consume(challenge));
        assertFalse(store.consume(challenge), "challenge must be single-use");
    }

    @Test
    void unknownChallengeRejected() {
        assertFalse(store.consume("not-a-real-challenge"));
        assertFalse(store.consume(null));
        assertFalse(store.consume(""));
    }

    @Test
    void challengesAreUnique() {
        assertNotEquals(store.issue(), store.issue());
    }

    @Test
    void expiredChallengeRejected() throws Exception {
        try (RedisAttestationStore shortTtl = store(redis.url(), StoreNamespace.AS, 1L)) {
            String challenge = shortTtl.issue();
            Thread.sleep(1100L);
            assertFalse(shortTtl.consume(challenge), "challenge must expire after its TTL");
        }
    }

    @Test
    void secondStoreSeesChallengesFromFirst() throws Exception {
        // Two store instances (≈ two cluster nodes / two classloaders) sharing one Redis.
        try (RedisAttestationStore other = store(redis.url(), StoreNamespace.AS, 300L)) {
            String challenge = store.issue();
            assertTrue(other.consume(challenge), "challenge must be visible across store instances");
            assertFalse(store.consume(challenge), "consumption must be visible across store instances");
        }
    }

    @Test
    void firstUseAcceptedReplayRejected() {
        assertTrue(store.firstSeen("client-a", "jti-1", 300L));
        assertFalse(store.firstSeen("client-a", "jti-1", 300L));
    }

    @Test
    void differentJtiAndClientAreIndependent() {
        assertTrue(store.firstSeen("client-a", "jti-1", 300L));
        assertTrue(store.firstSeen("client-a", "jti-2", 300L));
        assertTrue(store.firstSeen("client-b", "jti-1", 300L));
    }

    @Test
    void blankJtiRejected() {
        assertThrows(IllegalArgumentException.class, () -> store.firstSeen("client-a", "  ", 300L));
    }

    @Test
    void wrongPasswordIsAnUnavailableStoreNotAReplay() throws Exception {
        try (RedisAttestationStore bad = store("redis://default:wrong@127.0.0.1:" + redis.port(), StoreNamespace.AS, 300L)) {
            assertThrows(StoreUnavailableException.class, bad::issue);
            assertThrows(IllegalStateException.class, bad::issue, "the 0.3.0 contract still holds");
            assertEquals(Consumption.STORE_UNAVAILABLE, bad.consumeChallenge("anything"));
            assertEquals(Verdict.STORE_UNAVAILABLE, bad.record("client-a", "jti-1", 300L));
            assertEquals(Binding.STORE_UNAVAILABLE, bad.bind("d", "k", "client-a", now() + 60L));
            assertThrows(StoreUnavailableException.class, () -> bad.consume("anything"),
                    "the boolean view must not say 'unknown challenge' for an outage");
            assertThrows(StoreUnavailableException.class, () -> bad.firstSeen("client-a", "jti-1", 300L),
                    "the boolean view must not say 'replay' for an outage");
        }
    }

    @Test
    void redisDownIsAnUnavailableStoreNotAReplay() throws Exception {
        String challenge = store.issue();
        redis.close();
        assertEquals(Consumption.STORE_UNAVAILABLE, store.consumeChallenge(challenge));
        assertEquals(Verdict.STORE_UNAVAILABLE, store.record("client-a", "jti-9", 300L));
        assertEquals(Binding.STORE_UNAVAILABLE, store.bind("d", "k", "client-a", now() + 60L));
        assertThrows(StoreUnavailableException.class, store::issue);
    }

    @Test
    void verdictsAreTriState() {
        assertEquals(Verdict.FIRST_USE, store.record("client-a", "jti-1", 300L));
        assertEquals(Verdict.REPLAY, store.record("client-a", "jti-1", 300L));
        String challenge = store.issue();
        assertEquals(Consumption.CONSUMED, store.consumeChallenge(challenge));
        assertEquals(Consumption.UNKNOWN, store.consumeChallenge(challenge));
        assertEquals(Consumption.UNKNOWN, store.consumeChallenge(" "));
        assertEquals(Consumption.UNKNOWN, store.consumeChallenge(null));
        assertThrows(IllegalArgumentException.class, () -> store.record("client-a", null, 300L));
    }

    @Test
    void keysLiveUnderTheStoresNamespace() throws Exception {
        String challenge = store.issue();
        store.record("https://client.example", "jti-1", 300L);
        store.bind("digest-1", "jkt-1", "https://client.example", now() + 60L);
        assertEquals(java.util.Set.of(
                "oidf:as:challenge:" + challenge,
                "oidf:as:jti:https://client.example jti-1",
                "oidf:as:evidence:digest-1"), redis.keys());
        try (RedisAttestationStore cas = store(redis.url(), StoreNamespace.CAS, 300L)) {
            assertEquals(StoreNamespace.CAS, cas.namespace());
            assertEquals(Verdict.FIRST_USE, cas.record("https://client.example", "jti-1", 300L),
                    "a jti spent at the AS is not spent at the CAS: the namespaces are separate records");
            assertEquals(Consumption.UNKNOWN, cas.consumeChallenge(challenge),
                    "a challenge issued in one namespace is unknown in another");
            assertTrue(redis.keys().contains("oidf:cas:jti:https://client.example jti-1"));
        }
    }

    @Test
    void aTtlOfZeroIsRecordedForASecondNotForever() {
        assertEquals(Verdict.FIRST_USE, store.record("client-a", "jti-0", 0L));
        assertEquals(Verdict.REPLAY, store.record("client-a", "jti-0", 0L));
    }

    // ---- evidence binding --------------------------------------------------------------------------

    @Test
    void evidenceBindsToItsFirstPresenterAndTheSamePresenterMayReturn() {
        assertEquals(Binding.BOUND, store.bind("sha-1", "jkt-1", "https://client.example", now() + 600L));
        assertEquals(Binding.BOUND, store.bind("sha-1", "jkt-1", "https://client.example", now() + 600L),
                "re-presenting the same evidence with the same key is the rightful holder attesting again");
    }

    @Test
    void anotherKeyOrAnotherClientPresentingBoundEvidenceIsAConflict() {
        assertEquals(Binding.BOUND, store.bind("sha-1", "jkt-1", "https://client.example", now() + 600L));
        assertEquals(Binding.CONFLICT, store.bind("sha-1", "jkt-2", "https://client.example", now() + 600L),
                "a thief who presents second is refused");
        assertEquals(Binding.CONFLICT, store.bind("sha-1", "jkt-1", "https://other.example", now() + 600L),
                "the same key for another client is not the same binding");
        assertEquals(Binding.BOUND, store.bind("sha-1", "jkt-1", "https://client.example", now() + 600L),
                "the conflicts did not disturb the binding");
    }

    @Test
    void aBindingLivesOnlyAsLongAsItsEvidence() throws Exception {
        assertEquals(Binding.BOUND, store.bind("sha-1", "jkt-1", "c", now() + 1L));
        Thread.sleep(1100L);
        assertEquals(Binding.BOUND, store.bind("sha-1", "jkt-2", "c", now() + 600L),
                "expired evidence expires its binding with it; a fresh presenter may take the key");
    }

    @Test
    void evidenceThatHasAlreadyExpiredIsHeldForASecondNotForever() throws Exception {
        assertEquals(Binding.BOUND, store.bind("sha-1", "jkt-1", "c", now() - 100L));
        Thread.sleep(1100L);
        assertEquals(Binding.BOUND, store.bind("sha-1", "jkt-2", "c", now() + 600L));
    }

    @Test
    void aKeyThatExpiresBetweenTheSetAndTheGetIsTakenOnTheSecondAttempt() {
        assertEquals(Binding.BOUND, store.bind("sha-1", "jkt-1", "c", now() + 600L));
        redis.vanishAfterNextNxMiss();
        assertEquals(Binding.BOUND, store.bind("sha-1", "jkt-2", "c", now() + 600L),
                "SET NX lost to a key that then expired: the second SET NX takes it");
        assertEquals(Binding.CONFLICT, store.bind("sha-1", "jkt-1", "c", now() + 600L),
                "and the binding now belongs to the second presenter");
    }

    @Test
    void aKeyThatCanNeitherBeTakenNorReadIsUnavailableNotAConflict() {
        redis.phantomKeys();
        assertEquals(Binding.STORE_UNAVAILABLE, store.bind("sha-1", "jkt-1", "c", now() + 600L),
                "no binding could be made or read: refused as an outage, and not audited as a theft nobody attempted");
    }

    @Test
    void bindingNeedsADigestAndAKey() {
        assertThrows(IllegalArgumentException.class, () -> store.bind(null, "jkt", "c", now() + 60L));
        assertThrows(IllegalArgumentException.class, () -> store.bind(" ", "jkt", "c", now() + 60L));
        assertThrows(IllegalArgumentException.class, () -> store.bind("sha", null, "c", now() + 60L));
        assertThrows(IllegalArgumentException.class, () -> store.bind("sha", " ", "c", now() + 60L));
        assertEquals(Binding.BOUND, store.bind("sha-null-client", "jkt", null, now() + 60L),
                "a null client binds as the empty client, the same as the in-memory store");
        assertEquals(Binding.BOUND, store.bind("sha-null-client", "jkt", null, now() + 60L));
    }

    @Test
    void aSharedClientIsNotClosedByAViewThatDoesNotOwnIt() throws Exception {
        MiniRedisClient client = new MiniRedisClient(redis.url(), null, false);
        RedisAttestationStore view = new RedisAttestationStore(client, false, StoreNamespace.FED_ENDPOINT, 300L,
                Clock.fixed(Instant.now(), ZoneOffset.UTC));
        assertEquals(Verdict.FIRST_USE, view.record("c", "j", 300L));
        view.close();
        assertEquals(Verdict.REPLAY, view.record("c", "j", 300L), "the client the view shares is still open");
        assertThrows(IllegalArgumentException.class, () -> new RedisAttestationStore(client, false, StoreNamespace.AS, 0L, Clock.systemUTC()));
        client.close();
    }

    @Test
    void survivesStaleConnections() throws Exception {
        // Consume on a fresh connection, then use the (pooled, possibly stale) connection again.
        String c1 = store.issue();
        assertTrue(store.consume(c1));
        String c2 = store.issue();
        assertTrue(store.consume(c2));
    }
}
