/*
 * The event codes of the federation subsystem, and a façade over platform's event registry.
 */
package com.pingidentity.ps.oidf.federation.event;

import com.pingidentity.ps.oidf.platform.events.EventSink;
import com.pingidentity.ps.oidf.platform.events.Events;
import com.pingidentity.ps.oidf.platform.events.LoggingSink;

/**
 * Names the federation event codes, and hands events to this loader's sink - {@link Events} in
 * {@code platform.events}, where the registry now lives (plan item O-1).
 *
 * <p>Every code here is declared, with its fields and their PII classes, in
 * {@code META-INF/oidf-events/federation.json}; {@code EventsCataloguedTest} in pf-integration holds the two
 * together. {@link #ATTESTATION_VERIFIED} and {@link #ATTESTATION_REFUSED} are declared and never emitted (O-2,
 * Phase 3), and the catalogue marks them, and the other codes nothing emits yet, {@code declaredOnly}.
 *
 * <p>Same contract as before: the first {@link #configure} wins and a later one is ignored, and until something
 * configures one, events go to a {@link LoggingEventSink}. The engine classloader (OGNL issuance criteria) and the
 * webapp classloader each hold their own copy of platform, and each configures its own sink.
 *
 * @deprecated Use {@link Events}; plan item O-2 (Phase 3) moves the emitters and the codes, and removes this façade.
 */
@Deprecated(since = "0.5.0", forRemoval = true)
@SuppressWarnings("removal")
public final class FederationEvents {
    // ---- codes: the contract a log consumer branches on -------------------------------------------
    public static final String CHAIN_VALIDATED = "federation.chain.validated";
    public static final String CHAIN_REFUSED = "federation.chain.refused";
    public static final String CONSTRAINTS_FAILED = "federation.constraints.failed";
    public static final String POLICY_APPLIED = "federation.policy.applied";
    public static final String POLICY_CONFLICT = "federation.policy.conflict";
    public static final String STATEMENT_SERVED = "federation.statement.served";
    public static final String REQUEST_REFUSED = "federation.request.refused";
    public static final String RESOLVE_SERVED = "federation.resolve.served";
    public static final String RESOLVE_REFUSED = "federation.resolve.refused";
    public static final String HOSTED_ENTITY_ENROLLED = "federation.hosted_entity.enrolled";
    public static final String HOSTED_ENTITY_SUSPENDED = "federation.hosted_entity.suspended";
    public static final String HOSTED_ENTITY_REACTIVATED = "federation.hosted_entity.reactivated";
    public static final String HOSTED_ENTITY_REVOKED = "federation.hosted_entity.revoked";
    public static final String HOSTED_ENTITY_ROTATED = "federation.hosted_entity.rotated";
    public static final String HOSTED_ENTITY_UPDATED = "federation.hosted_entity.updated";
    public static final String HOSTED_ENTITY_RESOLVED = "federation.hosted_entity.resolved";
    public static final String HOSTED_ENTITY_REFUSED = "federation.hosted_entity.refused";
    public static final String REGISTRATION_CREATED = "federation.registration.created";
    public static final String REGISTRATION_REFRESHED = "federation.registration.refreshed";
    public static final String REGISTRATION_REFUSED = "federation.registration.refused";
    public static final String REGISTRATION_EXPIRED = "federation.registration.expired";
    public static final String REGISTRATION_EXPIRED_AT_ISSUANCE = "federation.registration.expired_at_issuance";
    public static final String REGISTRATION_REFRESH_DEFERRED = "federation.registration.refresh_deferred";
    public static final String REGISTRATION_DISABLED = "federation.registration.disabled";
    public static final String TRUST_MARK_GRANTED = "federation.trust_mark.granted";
    public static final String TRUST_MARK_ISSUED = "federation.trust_mark.issued";
    public static final String TRUST_MARK_REFUSED = "federation.trust_mark.refused";
    public static final String TRUST_MARK_REVOKED = "federation.trust_mark.revoked";
    public static final String TRUST_MARK_VERIFIED = "federation.trust_mark.verified";
    public static final String PDP_CONSULTED = "federation.pdp.consulted";
    public static final String TOKEN_REFUSED = "federation.token.refused";
    public static final String PDP_FAIL_OPEN = "federation.pdp.failopen";
    public static final String ANCHOR_LOADED = "federation.anchor.loaded";
    public static final String FETCH = "federation.fetch.made";
    public static final String KEY_RETIRED = "federation.key.retired";
    public static final String KEY_REVOKED = "federation.key.revoked";
    public static final String CLIENT_AUTHENTICATED = "federation.client.authenticated";
    public static final String CLIENT_REFUSED = "federation.client.refused";
    public static final String ATTESTATION_VERIFIED = "attestation.client.verified";
    public static final String ATTESTATION_REFUSED = "attestation.client.refused";

    private FederationEvents() {
    }

    /** Installs the sink for this classloader. The first call wins; later calls are ignored (a different sink at DEBUG). */
    public static void configure(FederationEventSink newSink) {
        Events.configure(newSink == null ? null : new FacadeSink(newSink));
    }

    /** True once {@link #configure} (or platform's {@link Events#configure}) has installed a sink. */
    public static boolean isConfigured() {
        return Events.isConfigured();
    }

    /**
     * The sink events currently go to: the one {@link #configure} installed, a {@link LoggingEventSink} over
     * platform's default {@link LoggingSink}, or platform's sink seen through this interface.
     */
    public static FederationEventSink sink() {
        EventSink current = Events.sink();
        if (current instanceof FacadeSink facade) {
            return facade.delegate();
        }
        if (current instanceof LoggingSink logging) {
            return new LoggingEventSink(logging);
        }
        return event -> current.emit(event.toEvent());
    }

    /** Hands {@code event} to the sink; never throws. */
    public static void emit(FederationEvent event) {
        if (event != null) {
            Events.emit(event.toEvent());
        }
    }

    /** Starts an event with {@code code}. */
    public static FederationEvent.Builder event(String code) {
        return FederationEvent.builder(code);
    }

    /** Tests only: forget the configured sink so the next {@link #configure} wins. */
    public static void reset() {
        Events.reset();
    }
}
