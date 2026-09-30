/*
 * Where federation events go - a façade over platform's EventSink.
 */
package com.pingidentity.ps.oidf.federation.event;

/**
 * Receives every {@link FederationEvent}. An implementation must not throw: recording an event is never
 * allowed to fail the request it describes.
 *
 * @deprecated Implement {@link com.pingidentity.ps.oidf.platform.events.EventSink}; plan item O-2 (Phase 3)
 *     removes this façade.
 */
@Deprecated(since = "0.5.0", forRemoval = true)
@FunctionalInterface
public interface FederationEventSink {
    void emit(FederationEvent event);
}
