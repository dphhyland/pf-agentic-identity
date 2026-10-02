/*
 * A replay store every node shares: Redis, through platform.redis.
 */
package com.pingidentity.ps.oidf.rs;

import com.pingidentity.ps.oidf.platform.redis.RedisKeyspace;
import java.io.IOException;
import java.time.Duration;
import java.util.Objects;

/**
 * A {@link ReplayStore} in Redis, shared by every node that serves the resource: {@code SET <prefix>:<key> 1 NX PX
 * <window>}, which only one caller can win for a key, and which Redis forgets when the proof's window has passed.
 *
 * <p>The embedding application owns the client and picks the prefix, for example
 * {@code new RedisReplayStore(client.keyspace("oidf:rs:dpop"))} on a {@code RedisClient} built from
 * {@code RedisConfig.current()}; the prefix keeps these keys apart from every other surface's in the one Redis.
 * A Redis that cannot be reached, or does not answer within the client's deadline, is an {@link IOException}, which
 * the validator turns into a 503: a proof is never accepted because the store could not be asked.
 */
public final class RedisReplayStore implements ReplayStore {
    private final RedisKeyspace keyspace;

    public RedisReplayStore(RedisKeyspace keyspace) {
        this.keyspace = Objects.requireNonNull(keyspace, "keyspace");
    }

    @Override
    public boolean firstUse(String key, Duration window) throws IOException {
        return this.keyspace.setIfAbsent(key, "1", window);
    }
}
