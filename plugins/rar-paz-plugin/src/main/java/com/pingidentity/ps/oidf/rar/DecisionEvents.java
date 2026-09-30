/*
 * The processor's decision events: rar.decision.permitted, .denied and .failopen (plan item O-2, Phase 3 decision 7).
 */
package com.pingidentity.ps.oidf.rar;

import com.pingidentity.ps.oidf.platform.events.Events;

/**
 * What {@code enrich}'s decision step emits, once per detail it decides, through this plugin's relocated copy of
 * {@code platform.events}: the {@value #COMPONENT} catalogue ({@code META-INF/oidf-events/rar.json}) declares every code
 * and field. The principal is hashed as the plugin's log lines hash it ({@link PrincipalResolver#hashForLog}); no
 * detail value, no PDP message and no secret is ever a field.
 *
 * <p>The copy of platform is the plugin's own, so its events go to server.log through platform's logging sink (the
 * loader has no audit sink: platform-pf is not in the jar) and are counted in the plugin's own
 * {@code oidf_events_total}, beside the PDP call counters: the MBean
 * {@code com.pingidentity.ps.oidf:type=Metrics,copy="com.pingidentity.ps.oidf.rar.shaded.platform.metrics from ..."}.
 */
final class DecisionEvents {

    static final String COMPONENT = "rar";
    static final String PERMITTED = "rar.decision.permitted";
    static final String DENIED = "rar.decision.denied";
    static final String FAIL_OPEN = "rar.decision.failopen";

    /** The PDP answered, and not with a permit. */
    static final String REASON_DENY = "pdp_deny";
    /** The PDP permitted, and its answer is not within the request: a PDP may narrow, never widen. */
    static final String REASON_WIDENED = "pdp_widened";
    /** The PDP was unreachable, and the instance does not fail open. */
    static final String REASON_UNREACHABLE = "pdp_unreachable";
    /** The PDP answered and could not be believed: a malformed answer, a refused status, a TLS failure. */
    static final String REASON_FAILED = "pdp_failed";

    private DecisionEvents() {
    }

    static void permitted(String type, String principalSource, String principal, String clientId) {
        Events.event(COMPONENT, PERMITTED).success().field("type", type).field("principal_source", principalSource)
                .field("principal", PrincipalResolver.hashForLog(principal)).field("client_id", clientId).emit();
    }

    static void denied(String reason, String type, String principalSource, String principal, String clientId) {
        Events.event(COMPONENT, DENIED).failure(reason).field("type", type).field("principal_source", principalSource)
                .field("principal", PrincipalResolver.hashForLog(principal)).field("client_id", clientId).emit();
    }

    static void failOpen(String type, String principalSource, String principal, String clientId) {
        Events.event(COMPONENT, FAIL_OPEN).success().field("type", type).field("principal_source", principalSource)
                .field("principal", PrincipalResolver.hashForLog(principal)).field("client_id", clientId).emit();
    }
}
