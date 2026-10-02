/*
 * Where events go.
 */
package com.pingidentity.ps.oidf.platform.events;

/**
 * Receives every {@link Event}. An implementation must not throw: recording an event is never allowed to fail
 * the request it describes. A sink that writes to a log applies its component's catalogue first
 * ({@link EventCatalogues#admit}) and then the {@link PiiPolicy} for its destination.
 */
@FunctionalInterface
public interface EventSink {
    void emit(Event event);
}
