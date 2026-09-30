/*
 * One component's state at one moment.
 */
package com.pingidentity.ps.oidf.platform.component;

import java.time.Instant;

/**
 * A component's state as {@link ComponentRegistry#snapshot()} reports it.
 *
 * @param name    the name it was registered under
 * @param enabled whether it was registered enabled
 * @param state   where it stands
 * @param reason  why, for a state that {@linkplain ComponentState#needsReason() needs one}; for any other, a note on how
 *                its enable switch was read, or empty
 * @param since   when it entered this state
 */
public record ComponentStatus(String name, boolean enabled, ComponentState state, String reason, Instant since) {
}
