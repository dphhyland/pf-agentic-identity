/*
 * Fan-out sink for every emitted SET (the Kafka connector, or a no-op when disabled).
 */
package com.pingidentity.ps.oidf.ssf;

/**
 * A side-channel that receives every SET the transmitter mints, in addition to per-stream delivery. The only
 * implementation is the optional Kafka connector ({@link KafkaSetPublisher}); when Kafka is disabled the
 * {@link #NOOP} sink is used and no messaging classes are loaded. Publishing is best-effort — a sink failure
 * must never break SET minting/delivery.
 */
public interface SetPublisher {

    /**
     * Publish one emitted SET.
     *
     * @param eventType  the event-type URI
     * @param subjectKey the subject's canonical key (may be null, e.g. verification SETs)
     * @param setJws     the full signed SET (compact JWS)
     * @param iat        the SET's issued-at (epoch seconds)
     */
    void publish(String eventType, String subjectKey, String setJws, long iat);

    default void close() {
    }

    /** The disabled sink: does nothing, loads nothing. */
    SetPublisher NOOP = (eventType, subjectKey, setJws, iat) -> {
    };
}
