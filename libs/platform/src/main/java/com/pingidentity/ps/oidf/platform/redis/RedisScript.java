/*
 * A Lua script Redis runs atomically, known by its SHA-1 so it is sent in full only when Redis lacks it.
 */
package com.pingidentity.ps.oidf.platform.redis;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.Objects;

/**
 * A script for {@link RedisClient#eval}: its source and the lower-case hex SHA-1 of it, the digest Redis files it
 * under ({@code EVALSHA}). The three the platform needs are here: leases (plan item C-4) release and renew only
 * while the caller still holds them, and a rate limit (X-A11) counts in a window that always expires.
 */
public final class RedisScript {

    /** {@code KEYS[1]} deleted only while it holds {@code ARGV[1]}: 1 when deleted, else 0. */
    public static final RedisScript COMPARE_AND_DELETE = new RedisScript(
            "if redis.call('GET', KEYS[1]) == ARGV[1] then return redis.call('DEL', KEYS[1]) else return 0 end");

    /** {@code KEYS[1]} given a TTL of {@code ARGV[2]} ms only while it holds {@code ARGV[1]}: 1 when extended, else 0. */
    public static final RedisScript COMPARE_AND_EXTEND = new RedisScript(
            "if redis.call('GET', KEYS[1]) == ARGV[1] then return redis.call('PEXPIRE', KEYS[1], ARGV[2]) else return 0 end");

    /**
     * {@code KEYS[1]} incremented, and given a TTL of {@code ARGV[1]} ms when it has none - the window's first hit,
     * or a counter something left without one: {@code [count, ms left]}.
     */
    public static final RedisScript FIXED_WINDOW = new RedisScript(
            "local n = redis.call('INCR', KEYS[1]) "
                    + "local ttl = redis.call('PTTL', KEYS[1]) "
                    + "if ttl < 0 then redis.call('PEXPIRE', KEYS[1], ARGV[1]) ttl = tonumber(ARGV[1]) end "
                    + "return {n, ttl}");

    private final String source;
    private final String sha1;

    public RedisScript(String source) {
        this.source = Objects.requireNonNull(source, "source");
        this.sha1 = sha1(source);
    }

    public String source() {
        return this.source;
    }

    /** The lower-case hex SHA-1 of the source's UTF-8 bytes. */
    public String sha1() {
        return this.sha1;
    }

    static String sha1(String source) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-1").digest(source.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("every JDK has SHA-1", e);
        }
    }
}
