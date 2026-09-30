/*
 * This loader's component parts, as a static entry point for the servlets' and filters' init.
 */
package com.pingidentity.ps.oidf.platform.health;

import com.pingidentity.ps.oidf.platform.component.ComponentSwitches;
import com.pingidentity.ps.oidf.platform.component.Components;
import com.pingidentity.ps.oidf.platform.component.Supervisor;
import com.pingidentity.ps.oidf.platform.profile.ProfileRefusals;
import java.time.Clock;

/**
 * The {@link ComponentParts} over this loader's {@link Components} registry, with the enable switches
 * ({@link ComponentSwitches}) and this loader's {@link Supervisor}, and S-9's component names. A servlet or filter
 * registers its part in {@code init} and hands it its start function; {@code init} then returns, whatever
 * happened:
 *
 * <pre>{@code
 * this.part = Startup.begin(Startup.AUTO_REGISTRATION, "TokenEndpointAutoRegistrationFilter");
 * this.part.start(() -> {
 *     ... what init did, with part.notConfigured(what) where its settings are absent, part.failedConfig(reason)
 *     where it refuses, and a throw for anything else ...
 * });
 * }</pre>
 *
 * <p>Its request methods start with platform-pf's {@code ComponentGate}, which answers for the part while its
 * component is not serving.
 *
 * <p>Statics are per loader, so the webapp's copy holds the webapp's parts; nothing in the engine's copy runs an
 * {@code init}, so its registry stays empty (docs/development/classloaders.md).
 */
public final class Startup {

    /** The federation entity: its configuration, fetch, list, resolve and Trust Mark endpoints, and explicit registration. */
    public static final String FEDERATION = "FEDERATION";
    /** Automatic registration at the token, authorization and PAR endpoints. */
    public static final String AUTO_REGISTRATION = "AUTO_REGISTRATION";
    /** {@code attest_jwt_client_auth} at the token and PAR endpoints. */
    public static final String ATTESTATION_AUTH = "ATTESTATION_AUTH";
    /** The client attester: issuing client attestations. */
    public static final String ATTESTATION_ISSUER = "ATTESTATION_ISSUER";
    /** Hosting subordinate entities for an authority. */
    public static final String HOSTING = "HOSTING";
    /** The SSF transmitter. */
    public static final String SSF = "SSF";
    /** The SSF receiver of inbound SETs. */
    public static final String SSF_RECEIVER = "SSF_RECEIVER";
    /** The federation operator (admin) API. */
    public static final String OPERATOR_API = "OPERATOR_API";
    /** FAPI 2.0 enforcement for the clients it names. */
    public static final String FAPI = "FAPI";

    private static final ComponentParts PARTS = new ComponentParts(Components.registry(), Clock.systemUTC(),
            component -> ComponentSwitches.process().verdict(component), Supervisor.shared());

    private Startup() {
    }

    /**
     * See {@link ComponentParts#begin(String, String)}; and a part of a component the production profile refuses
     * ({@link ProfileRefusals#reason}) is {@code REFUSED} at once, with the refusal as its reason, so its
     * {@link ComponentParts.Part#start start} runs nothing and its gate answers 503 (plan item PR-5). A component
     * switched off stays disabled: disabling one is never a violation.
     */
    public static ComponentParts.Part begin(String component, String part) {
        ComponentParts.Part begun = PARTS.begin(component, part);
        refuseIfRefused(PARTS, begun);
        return begun;
    }

    /** Marks {@code begun} {@code REFUSED} when the profile refuses its component; answers whether it did. */
    static boolean refuseIfRefused(ComponentParts parts, ComponentParts.Part begun) {
        ComponentSwitches.Verdict verdict = parts.verdict(begun.component());
        if (verdict.kind() == ComponentSwitches.Kind.DISABLED) {
            return false;
        }
        String reason = ProfileRefusals.reason(begun.component(), verdict.kind() == ComponentSwitches.Kind.ENABLED);
        return reason != null && begun.refused(reason);
    }

    /**
     * Whether {@code component}'s switch lets it start - switched on, or inferred - for a start function that
     * configures another component's shared state on its behalf (the federation servlet configures hosting).
     * {@code false} when the switch cannot be read.
     */
    public static boolean mayStart(String component) {
        return PARTS.verdict(component).mayStart();
    }

    /** This loader's parts. */
    public static ComponentParts parts() {
        return PARTS;
    }
}
