/*
 * One hit counted in a fixed window.
 */
package com.pingidentity.ps.oidf.platform.redis;

import java.io.IOException;
import java.time.Duration;
import java.util.List;

/**
 * What {@link RedisClient#countInWindow} answers: the hits in the current window, the one just counted included, and
 * how long the window has left - the {@code Retry-After} a rate limit refusing the hit would send.
 */
public record WindowCount(long count, Duration remaining) {

    /** The script's {@code [count, ms left]}; anything else is a protocol failure. */
    static WindowCount of(Object reply) throws IOException {
        if (reply instanceof List<?> list && list.size() == 2 && list.get(0) instanceof Long count
                && list.get(1) instanceof Long millis) {
            return new WindowCount(count, Duration.ofMillis(millis));
        }
        throw new IOException("the fixed-window script answered " + reply + ", not [count, ms left]");
    }
}
