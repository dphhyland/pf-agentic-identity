/*
 * A façade sink installed in platform's registry.
 */
package com.pingidentity.ps.oidf.federation.event;

import com.pingidentity.ps.oidf.platform.events.Event;
import com.pingidentity.ps.oidf.platform.events.EventSink;

/**
 * A {@link FederationEventSink} as platform's {@link EventSink}: what {@link FederationEvents#configure} installs,
 * and what {@link FederationEvents#sink()} unwraps again.
 */
@SuppressWarnings("removal")
record FacadeSink(FederationEventSink delegate) implements EventSink {
    @Override
    public void emit(Event event) {
        this.delegate.emit(FederationEvent.from(event));
    }
}
