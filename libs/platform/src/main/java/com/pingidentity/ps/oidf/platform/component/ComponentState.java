/*
 * The states a component can be in, as plan item S-9 names them.
 */
package com.pingidentity.ps.oidf.platform.component;

/**
 * Where a component of this repository stands: the seven states of plan item S-9 (fail-soft components). What
 * each state does to a component's surfaces - a 404, a 503, a pass-through, an OGNL {@code false} - and to
 * readiness is decided by S-9 and O-4, not here.
 */
public enum ComponentState {
    /** Switched off. A disabled component stays disabled until it is registered again, enabled. */
    DISABLED,
    /** Enabled and not yet ready: the state a component is registered in. */
    STARTING,
    /** Serving. */
    READY,
    /** Serving, with something it depends on impaired - a dependency blip, not a reason to leave the pool. */
    DEGRADED,
    /** Its settings are wrong; it will not serve until they are corrected and it starts again. */
    FAILED_CONFIG,
    /** Something it needs is unavailable; it may recover when that returns. */
    FAILED_DEPENDENCY,
    /** The deployment profile forbids how it is configured. */
    REFUSED;

    /** Whether entering this state needs a reason an operator can read: every state that is not serving normally. */
    public boolean needsReason() {
        return this == DEGRADED || this == FAILED_CONFIG || this == FAILED_DEPENDENCY || this == REFUSED;
    }
}
