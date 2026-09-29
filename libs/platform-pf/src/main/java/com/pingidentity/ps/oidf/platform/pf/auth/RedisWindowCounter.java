/*
 * Fixed-window counters in Redis, shared by every node.
 */
package com.pingidentity.ps.oidf.platform.pf.auth;

import com.pingidentity.ps.oidf.platform.redis.RedisClient;
import com.pingidentity.ps.oidf.platform.redis.RedisScript;
import com.pingidentity.ps.oidf.platform.redis.WindowCount;
import java.io.IOException;
import java.time.Duration;
import java.util.List;
import java.util.Objects;

/**
 * A {@link WindowCounter} in Redis: {@code hit} is platform.redis's {@code countInWindow} (INCR, and a PEXPIRE on the
 * window's first hit, in one script), and {@code peek} reads the count and its time to live in one script without
 * adding to it. Keys are {@code <prefix>:<key>}; the operator APIs use {@code oidf:admin:limit:auth} and
 * {@code oidf:admin:limit:mutation}.
 */
public final class RedisWindowCounter implements WindowCounter {
    /** The count and the milliseconds left, without an INCR; a key with no count is {@code [0, 0]}. */
    static final RedisScript PEEK = new RedisScript(
            "local n = redis.call('GET', KEYS[1]) "
                    + "if not n then return {0, 0} end "
                    + "local ttl = redis.call('PTTL', KEYS[1]) "
                    + "if ttl < 0 then ttl = 0 end "
                    + "return {tonumber(n), ttl}");

    private final RedisClient client;
    private final String prefix;

    public RedisWindowCounter(RedisClient client, String prefix) {
        this.client = Objects.requireNonNull(client, "client");
        this.prefix = client.keyspace(prefix).prefix();
    }

    @Override
    public WindowCount hit(String key, Duration window) throws IOException {
        return this.client.keyspace(this.prefix).countInWindow(key, window);
    }

    @Override
    public WindowCount peek(String key) throws IOException {
        Object reply = this.client.eval(PEEK, List.of(this.client.keyspace(this.prefix).key(key)), List.of());
        if (reply instanceof List<?> list && list.size() == 2 && list.get(0) instanceof Long count
                && list.get(1) instanceof Long millis) {
            return new WindowCount(count, Duration.ofMillis(millis));
        }
        throw new IOException("the window peek script answered " + reply + ", not [count, ms left]");
    }
}
