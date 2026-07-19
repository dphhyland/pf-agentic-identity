/*
 * SSF 1.0 stream status values.
 */
package com.pingidentity.ps.oidf.ssf;

/**
 * The lifecycle state of a stream per SSF 1.0 §Stream Status. {@code ENABLED} streams receive events;
 * {@code PAUSED} streams retain configuration and queued events but suspend delivery (the transmitter sets
 * this on dead-letter); {@code DISABLED} streams are inert until re-enabled.
 */
public enum StreamStatus {
    ENABLED("enabled"),
    PAUSED("paused"),
    DISABLED("disabled");

    private final String value;

    StreamStatus(String value) {
        this.value = value;
    }

    public String value() {
        return this.value;
    }

    public static StreamStatus fromValue(String value) {
        if (value != null) {
            for (StreamStatus s : values()) {
                if (s.value.equals(value)) {
                    return s;
                }
            }
        }
        throw new IllegalArgumentException("unknown stream status: " + value);
    }
}
