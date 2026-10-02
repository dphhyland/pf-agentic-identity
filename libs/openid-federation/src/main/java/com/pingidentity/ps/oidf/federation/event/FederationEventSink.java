/*
 * Where federation events go - a façade over platform's EventSink.
 */
package com.pingidentity.ps.oidf.federation.event;

/**
 * Receives every {@link FederationEvent}. An implementation must not throw: recording an event is never
 * allowed to fail the request it describes.
 *
 * @deprecated Implement {@link com.pingidentity.ps.oidf.platform.events.EventSink}. Kept while federation code
 *     still uses it (plan item H-FED-10, checked 2026-10-01); removed at 1.0.0.
 */
@Deprecated(since = "0.5.0", forRemoval = true)
@FunctionalInterface
public interface FederationEventSink {
    void emit(FederationEvent event);
}
