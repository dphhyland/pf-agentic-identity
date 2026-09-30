/*
 * One part of a component at one moment.
 */
package com.pingidentity.ps.oidf.platform.health;

import com.pingidentity.ps.oidf.platform.component.ComponentState;
import java.time.Instant;

/**
 * A part's state as {@link ComponentParts#parts()} reports it.
 *
 * @param component the component it serves, by S-9's name
 * @param part      the class that registered it, by its simple name
 * @param state     where it stands
 * @param reason    why, for a state that {@linkplain ComponentState#needsReason() needs one}; empty otherwise
 * @param since     when it entered this state
 */
public record PartStatus(String component, String part, ComponentState state, String reason, Instant since) {
}
