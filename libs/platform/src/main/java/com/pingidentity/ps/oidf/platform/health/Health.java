/*
 * Liveness, readiness and the detail document, decided from the component registry.
 */
package com.pingidentity.ps.oidf.platform.health;

import com.pingidentity.ps.oidf.platform.component.ComponentState;
import com.pingidentity.ps.oidf.platform.component.ComponentStatus;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * What the health endpoints answer (plan item O-4), with no servlet API: platform-pf's servlet serves it.
 *
 * <ul>
 *   <li><b>Live</b> is always {@link Status#UP}: whatever answers the request is alive. The webapp answering is
 *       the whole test.</li>
 *   <li><b>Ready</b> is {@link Status#DOWN} when an enabled component is not {@link ComponentState#READY} or
 *       {@link ComponentState#DEGRADED} - starting, failed or refused - and {@link Status#UP} otherwise, a
 *       disabled component and no component at all included. DEGRADED counts as ready, per S-9: a dependency blip
 *       must not eject every node at once.</li>
 *   <li>Both say nothing but the status. The detail - each component's state and reason, its parts, the profile
 *       and the versions - is {@link #detail}, which the servlet shows only to an authorised caller.</li>
 * </ul>
 */
public final class Health {

    /** What liveness and readiness say. */
    public enum Status { UP, DOWN }

    private Health() {
    }

    /** {@link Status#DOWN} when an enabled component is neither ready nor degraded. */
    public static Status readiness(List<ComponentStatus> components) {
        for (ComponentStatus c : components) {
            if (c.enabled() && !serving(c.state())) {
                return Status.DOWN;
            }
        }
        return Status.UP;
    }

    /** Whether a component in {@code state} counts as ready: {@link ComponentState#READY} and {@link ComponentState#DEGRADED}. */
    static boolean serving(ComponentState state) {
        return state == ComponentState.READY || state == ComponentState.DEGRADED;
    }

    /** The whole body of the live and ready answers: {@code {"status":"UP"}} or {@code {"status":"DOWN"}}. */
    public static Map<String, Object> status(Status status) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("status", status.name());
        return out;
    }

    /**
     * The detail document: the readiness status, the deployment profile, the versions, and every component with
     * its state, reason, the time it entered the state and its parts.
     *
     * @param components the registry's snapshot
     * @param parts      the parts' states; a component's parts are those naming it
     * @param profile    the deployment profile's name
     * @param versions   what {@code /agentic-identity/info} shows
     */
    public static Map<String, Object> detail(List<ComponentStatus> components, List<PartStatus> parts, String profile,
            Map<String, Object> versions) {
        List<Object> list = new ArrayList<>();
        for (ComponentStatus c : components) {
            Map<String, Object> component = new LinkedHashMap<>();
            component.put("name", c.name());
            component.put("enabled", c.enabled());
            component.put("state", c.state().name());
            component.put("reason", c.reason());
            component.put("since", c.since().toString());
            List<Object> own = new ArrayList<>();
            for (PartStatus p : parts) {
                if (p.component().equals(c.name())) {
                    Map<String, Object> part = new LinkedHashMap<>();
                    part.put("name", p.part());
                    part.put("state", p.state().name());
                    part.put("reason", p.reason());
                    part.put("since", p.since().toString());
                    own.add(part);
                }
            }
            component.put("parts", own);
            list.add(component);
        }
        Map<String, Object> out = status(readiness(components));
        out.put("profile", profile);
        out.put("versions", versions);
        out.put("components", list);
        return out;
    }
}
