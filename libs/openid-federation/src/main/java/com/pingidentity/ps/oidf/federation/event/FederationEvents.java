/*
 * The process-wide event sink and the event codes.
 */
package com.pingidentity.ps.oidf.federation.event;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * Holds the one {@link FederationEventSink} for this classloader and names the event codes.
 *
 * <p>Same contract as {@code AuthoritySupport}: the first {@link #configure} wins and a later one is
 * ignored, because the servlets, the filters and the OGNL helpers all reach for the sink
 * and the order they initialise in is not under anyone's control. Until something configures one, events
 * go to a {@link LoggingEventSink}. The engine classloader (OGNL issuance criteria) and the webapp
 * classloader each hold their own copy of this class, and each configures its own sink.
 */
public final class FederationEvents {
    private static final Log LOGGER = LogFactory.getLog(FederationEvents.class);
    private static final Object LOCK = new Object();
    private static volatile FederationEventSink sink;
    private static volatile boolean configured;

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
        synchronized (LOCK) {
            if (configured) {
                if (newSink != sink) {
                    LOGGER.debug("FederationEvents sink already configured; ignoring a second configuration");
                }
                return;
            }
            sink = newSink;
            configured = true;
        }
    }

    /** True once {@link #configure} has installed a sink. */
    public static boolean isConfigured() {
        return configured;
    }

    /** The sink events currently go to. */
    public static FederationEventSink sink() {
        FederationEventSink local = sink;
        if (local == null) {
            synchronized (LOCK) {
                if (sink == null) {
                    sink = new LoggingEventSink();
                }
                local = sink;
            }
        }
        return local;
    }

    /** Hands {@code event} to the sink; never throws. */
    public static void emit(FederationEvent event) {
        if (event == null) {
            return;
        }
        try {
            sink().emit(event);
        } catch (RuntimeException ignored) {
            // A failing sink never fails the request the event describes.
        }
    }

    /** Starts an event with {@code code}. */
    public static FederationEvent.Builder event(String code) {
        return FederationEvent.builder(code);
    }

    /** Tests only: forget the configured sink so the next {@link #configure} wins. */
    public static void reset() {
        synchronized (LOCK) {
            sink = null;
            configured = false;
        }
    }
}
