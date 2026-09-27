/*
 * One surface's keys: a prefix before each of them, so surfaces never meet in the one Redis.
 */
package com.pingidentity.ps.oidf.platform.redis;

import java.io.IOException;
import java.time.Duration;
import java.util.regex.Pattern;

/**
 * A {@link RedisClient} seen through a key prefix: every key a command here is given becomes
 * {@code <prefix>:<key>}. The prefix names the surface that owns the keys, so an operator can see which surface
 * wrote a key and flush one surface's state without touching another's. 0.4.0's prefixes - {@code oidf:as},
 * {@code oidf:cas}, {@code oidf:fed:endpoint}, {@code oidf:admin:dpop} (client-attestation's {@code StoreNamespace})
 * - are views of this kind, and write exactly the keys 0.4.0 wrote.
 */
public final class RedisKeyspace {
    private static final Pattern PREFIX = Pattern.compile("[A-Za-z0-9_.-]+(:[A-Za-z0-9_.-]+)*");

    private final RedisClient client;
    private final String prefix;

    RedisKeyspace(RedisClient client, String prefix) {
        if (prefix == null || !PREFIX.matcher(prefix).matches()) {
            throw new IllegalArgumentException("a key prefix is words joined by ':', with no ':' at either end, not " + prefix);
        }
        this.client = client;
        this.prefix = prefix;
    }

    public String prefix() {
        return this.prefix;
    }

    /** The full key for {@code key}: {@code <prefix>:<key>}. */
    public String key(String key) {
        return this.prefix + ":" + key;
    }

    public boolean set(String key, String value, Duration ttl) throws IOException {
        return this.client.set(this.key(key), value, ttl);
    }

    public boolean setIfAbsent(String key, String value, Duration ttl) throws IOException {
        return this.client.setIfAbsent(this.key(key), value, ttl);
    }

    public String get(String key) throws IOException {
        return this.client.get(this.key(key));
    }

    public long del(String key) throws IOException {
        return this.client.del(this.key(key));
    }

    public long incr(String key) throws IOException {
        return this.client.incr(this.key(key));
    }

    public boolean pexpire(String key, Duration ttl) throws IOException {
        return this.client.pexpire(this.key(key), ttl);
    }

    public boolean compareAndDelete(String key, String expected) throws IOException {
        return this.client.compareAndDelete(this.key(key), expected);
    }

    public boolean compareAndExtend(String key, String expected, Duration ttl) throws IOException {
        return this.client.compareAndExtend(this.key(key), expected, ttl);
    }

    public WindowCount countInWindow(String key, Duration window) throws IOException {
        return this.client.countInWindow(this.key(key), window);
    }
}
