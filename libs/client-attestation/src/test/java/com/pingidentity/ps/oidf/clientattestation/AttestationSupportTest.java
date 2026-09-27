package com.pingidentity.ps.oidf.clientattestation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Which store each surface gets: per-node memory, one per namespace, with no Redis configured; a Redis view per
 * namespace over one shared client with one; and under the production profile a {@code redis://} URL refused
 * once and then on every call, so no surface falls back to per-node state.
 */
class AttestationSupportTest {
    private static final String PROPERTY = "oidf.redis.url";

    @BeforeEach
    void noRedisFromTheEnvironment() {
        assumeTrue(System.getenv("OIDF_REDIS_URL") == null && System.getenv("REDIS_URL") == null,
                "the environment configures a Redis URL, which these tests would not control");
        System.clearProperty(PROPERTY);
        AttestationSupport.reset();
    }

    @AfterEach
    void forget() {
        System.clearProperty(PROPERTY);
        AttestationSupport.reset();
    }

    @Test
    void withoutRedisEachNamespaceHasItsOwnMemoryStore() {
        AttestationChallengeService as = AttestationSupport.challengeService(StoreNamespace.AS);
        assertTrue(as instanceof InMemoryAttestationChallengeService);
        assertSame(as, AttestationSupport.challengeService());
        assertNotSame(as, AttestationSupport.challengeService(StoreNamespace.CAS));
        AttestationReplayCache replay = AttestationSupport.replayCache(StoreNamespace.AS);
        assertTrue(replay instanceof InMemoryAttestationReplayCache);
        assertSame(replay, AttestationSupport.replayCache());
        assertNotSame(replay, AttestationSupport.replayCache(StoreNamespace.FED_ENDPOINT));
        EvidenceBindingStore bindings = AttestationSupport.evidenceBindingStore();
        assertTrue(bindings instanceof InMemoryEvidenceBindingStore);
        assertSame(bindings, AttestationSupport.evidenceBindingStore());

        AttestationSupport.configureChallengeService(16, 90L);
        assertEquals(90L, AttestationSupport.challengeService().ttlSeconds());
        AttestationSupport.configureReplayCache(16);
        assertNotSame(replay, AttestationSupport.replayCache(), "the servlet's sizing replaces the AS cache");
    }

    @Test
    void withRedisEachNamespaceIsAViewOverOneClient() {
        System.setProperty(PROPERTY, " rediss://127.0.0.1:1 ");
        AttestationChallengeService as = AttestationSupport.challengeService(StoreNamespace.AS);
        assertEquals(StoreNamespace.AS, ((RedisAttestationStore) as).namespace());
        assertSame(as, AttestationSupport.replayCache(StoreNamespace.AS), "one view serves a namespace's challenges and jtis");
        RedisAttestationStore cas = (RedisAttestationStore) AttestationSupport.evidenceBindingStore();
        assertEquals(StoreNamespace.CAS, cas.namespace());
        assertSame(cas, AttestationSupport.replayCache(StoreNamespace.CAS));
        assertSame(cas, AttestationSupport.challengeService(StoreNamespace.CAS));

        AttestationSupport.configureChallengeService(16, 120L);
        assertEquals(120L, AttestationSupport.challengeService().ttlSeconds(), "Redis takes the TTL; the size is ignored");
        assertNotSame(as, AttestationSupport.challengeService());
        AttestationSupport.configureReplayCache(16);
        assertTrue(AttestationSupport.replayCache() instanceof RedisAttestationStore);
    }

    @Test
    void withoutRedisEachNamespaceKeepsItsOwnChallengeSettings() {
        AttestationSupport.configureChallengeService(StoreNamespace.CAS, 16, 60L);
        assertEquals(60L, AttestationSupport.challengeService(StoreNamespace.CAS).ttlSeconds());
        assertEquals(AttestationChallengeService.DEFAULT_TTL_SECONDS, AttestationSupport.challengeService().ttlSeconds(),
                "the attester's TTL is not the authorization server's");
        AttestationSupport.configureChallengeService(90, 90L);
        assertEquals(90L, AttestationSupport.challengeService(StoreNamespace.AS).ttlSeconds());
        assertEquals(60L, AttestationSupport.challengeService(StoreNamespace.CAS).ttlSeconds(),
                "and the authorization server's is not the attester's");
        assertEquals(AttestationChallengeService.DEFAULT_TTL_SECONDS, AttestationSupport.challengeService(StoreNamespace.FED_ENDPOINT).ttlSeconds(),
                "a namespace nobody configured is made with the defaults, not with the last settings given");
    }

    @Test
    void withRedisEachNamespaceKeepsItsOwnChallengeTtl() {
        System.setProperty(PROPERTY, "rediss://127.0.0.1:1");
        AttestationChallengeService cas = AttestationSupport.challengeService(StoreNamespace.CAS);
        AttestationSupport.configureChallengeService(StoreNamespace.CAS, 16, 60L);
        assertEquals(60L, AttestationSupport.challengeService(StoreNamespace.CAS).ttlSeconds());
        assertNotSame(cas, AttestationSupport.challengeService(StoreNamespace.CAS), "a new view with the new TTL");
        assertSame(AttestationSupport.challengeService(StoreNamespace.CAS), AttestationSupport.evidenceBindingStore(),
                "still one view per namespace, serving its challenges, jtis and bindings");
        assertEquals(AttestationChallengeService.DEFAULT_TTL_SECONDS, AttestationSupport.challengeService().ttlSeconds());
    }

    @Test
    void aSettingTheStoreRefusesLeavesTheNamespaceWithTheStoreItHad() {
        AttestationChallengeService memory = AttestationSupport.challengeService(StoreNamespace.CAS);
        assertThrows(IllegalArgumentException.class, () -> AttestationSupport.configureChallengeService(StoreNamespace.CAS, 16, 0L));
        assertThrows(IllegalArgumentException.class, () -> AttestationSupport.configureChallengeService(StoreNamespace.CAS, 0, 60L));
        assertSame(memory, AttestationSupport.challengeService(StoreNamespace.CAS));

        System.setProperty(PROPERTY, "rediss://127.0.0.1:1");
        AttestationChallengeService redis = AttestationSupport.challengeService(StoreNamespace.CAS);
        assertThrows(IllegalArgumentException.class, () -> AttestationSupport.configureChallengeService(StoreNamespace.CAS, 16, -5L));
        assertSame(redis, AttestationSupport.challengeService(StoreNamespace.CAS));
        assertEquals(AttestationChallengeService.DEFAULT_TTL_SECONDS, redis.ttlSeconds());
    }

    @Test
    void aPlaintextUrlInProductionIsRefusedOnEveryCallAndNeverFallsBackToMemory() {
        assumeTrue(DeploymentProfile.isProduction(System::getenv), "the build sets no development profile");
        System.setProperty(PROPERTY, "redis://:pw@127.0.0.1:1");
        IllegalStateException first = assertThrows(IllegalStateException.class, () -> AttestationSupport.challengeService());
        assertTrue(first.getMessage().contains("rediss://"), first.getMessage());
        assertTrue(!first.getMessage().contains("pw@"), first.getMessage());
        IllegalStateException again = assertThrows(IllegalStateException.class, () -> AttestationSupport.evidenceBindingStore());
        assertEquals(first.getMessage(), again.getMessage(), "the refusal is remembered, not re-derived");
        assertThrows(IllegalStateException.class, () -> AttestationSupport.replayCache(StoreNamespace.FED_ENDPOINT));
    }
}
