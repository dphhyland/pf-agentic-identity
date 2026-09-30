/*
 * Fixed-window counters for the operator APIs' rate limits.
 */
package com.pingidentity.ps.oidf.platform.pf.auth;

import com.pingidentity.ps.oidf.platform.redis.WindowCount;
import java.io.IOException;
import java.time.Duration;

/**
 * Counts hits per key in a fixed window that starts at the key's first hit: in Redis, shared by every node
 * ({@link RedisWindowCounter}), or in this JVM ({@link InMemoryWindowCounter}), which makes each node's limit its own -
 * weaker, not unsafe (Phase 3 decision 9), so it needs no accepted risk.
 */
public interface WindowCounter {

    /** Counts one hit for {@code key}: the count this window, this hit included, and how long the window has left. */
    WindowCount hit(String key, Duration window) throws IOException;

    /** The count this window without adding to it; a key with no live window is 0 with nothing left. */
    WindowCount peek(String key) throws IOException;
}
