package com.pingidentity.ps.oidf.rs;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import com.pingidentity.ps.oidf.conformance.Requirement;
import com.pingidentity.ps.oidf.platform.profile.DeploymentProfile;
import com.pingidentity.ps.oidf.platform.redis.RedisClient;
import com.pingidentity.ps.oidf.platform.redis.RedisConfig;
import java.io.IOException;
import java.time.Duration;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;

/**
 * The Redis store against a real Redis: {@code SET NX PX} as Redis runs it, shared by two validators standing in for
 * two nodes. Skipped unless {@code OIDF_TEST_REDIS_URL} names a server - the variable libs/platform's
 * {@code RedisLiveTest} reads, which build.yml's java job sets for the whole reactor.
 */
class RedisReplayStoreLiveTest {
    private static final String URL = System.getenv("OIDF_TEST_REDIS_URL");

    private static RedisClient client() {
        assumeTrue(URL != null && !URL.isBlank(), "set OIDF_TEST_REDIS_URL to run the live Redis replay store test");
        return new RedisClient(RedisConfig.builder(URL).profile(DeploymentProfile.DEVELOPMENT).build());
    }

    @Test
    @Requirement("RFC9449 §11.1")
    void aProofAcceptedByOneNodeIsRefusedByAnother() throws Exception {
        try (RedisClient client = client()) {
            ReplayStore shared = new RedisReplayStore(client.keyspace("oidf:rs-test:" + UUID.randomUUID()));
            Fixture f = new Fixture();
            DelegatedTokenValidator nodeA = f.builder(shared).build();
            DelegatedTokenValidator nodeB = f.builder(shared).build();
            String token = f.token();
            String proof = f.proof(token);
            nodeA.validate(Fixture.dpop(token, List.of(proof)));
            DelegatedTokenValidator.RsException e = assertThrows(DelegatedTokenValidator.RsException.class,
                    () -> nodeB.validate(Fixture.dpop(token, List.of(proof))));
            assertEquals("invalid_dpop_proof", e.error());
        }
    }

    @Test
    void theKeyExpiresWithItsWindow() throws Exception {
        try (RedisClient client = client()) {
            ReplayStore store = new RedisReplayStore(client.keyspace("oidf:rs-test:" + UUID.randomUUID()));
            assertTrue(store.firstUse("k", Duration.ofMillis(200)));
            assertFalse(store.firstUse("k", Duration.ofMillis(200)));
            Thread.sleep(400);
            assertTrue(store.firstUse("k", Duration.ofMillis(200)));
        }
    }

    @Test
    void aRedisThatCannotBeReachedIsAnIoException() {
        RedisClient unreachable = new RedisClient(RedisConfig.builder("redis://127.0.0.1:1")
                .profile(DeploymentProfile.DEVELOPMENT).commandTimeout(Duration.ofMillis(500)).build());
        try (unreachable) {
            ReplayStore store = new RedisReplayStore(unreachable.keyspace("oidf:rs-test"));
            assertThrows(IOException.class, () -> store.firstUse("k", Duration.ofSeconds(1)));
        }
    }
}
