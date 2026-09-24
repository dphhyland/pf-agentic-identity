/*
 * Where federation events go.
 */
package com.pingidentity.ps.oidf.federation.event;

/**
 * Receives every {@link FederationEvent}. An implementation must not throw: recording an event is never
 * allowed to fail the request it describes.
 */
@FunctionalInterface
public interface FederationEventSink {
    void emit(FederationEvent event);
}
