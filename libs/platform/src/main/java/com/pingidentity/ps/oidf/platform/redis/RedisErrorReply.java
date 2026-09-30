/*
 * Redis answered with an error: the command was refused, the transport is fine.
 */
package com.pingidentity.ps.oidf.platform.redis;

/**
 * An error reply ({@code -ERR ...}, {@code -NOAUTH ...}, {@code -READONLY ...}): Redis refused the command, and the
 * connection is still aligned. An {@link IllegalStateException}, as 0.4.0's client threw, so a caller that treats
 * any failure as the store being unavailable ({@code catch (IOException | RuntimeException e)}) keeps doing so.
 * The message is the server's line, which names the command's problem and never a value the command carried.
 */
public final class RedisErrorReply extends IllegalStateException {
    private static final long serialVersionUID = 1L;

    private final String line;

    RedisErrorReply(String line) {
        super("Redis error reply: " + line);
        this.line = line;
    }

    /** The server's line, without the leading {@code -}. */
    public String line() {
        return this.line;
    }

    /** The error's first word, which Redis uses as its code: {@code ERR}, {@code NOSCRIPT}, {@code READONLY}. */
    public String code() {
        int space = this.line.indexOf(' ');
        return space < 0 ? this.line : this.line.substring(0, space);
    }
}
