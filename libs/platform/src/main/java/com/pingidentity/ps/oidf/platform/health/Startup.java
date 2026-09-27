/*
 * This loader's component parts, as a static entry point for the servlets' and filters' init.
 */
package com.pingidentity.ps.oidf.platform.health;

import com.pingidentity.ps.oidf.platform.component.Components;
import java.time.Clock;

/**
 * The {@link ComponentParts} over this loader's {@link Components} registry, and S-9's component names. A servlet
 * or filter registers its part at the top of {@code init}:
 *
 * <pre>{@code
 * var part = Startup.begin(Startup.AUTO_REGISTRATION, "TokenEndpointAutoRegistrationFilter");
 * try {
 *     ... init as it was, with part.disabled() or part.failedConfig(reason) where it switches off or refuses ...
 * } catch (ServletException | RuntimeException | Error e) {
 *     part.failed(e);
 *     throw e;
 * } finally {
 *     part.finish();
 * }
 * }</pre>
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

    private static final ComponentParts PARTS = new ComponentParts(Components.registry(), Clock.systemUTC());

    private Startup() {
    }

    /** See {@link ComponentParts#begin(String, String)}. */
    public static ComponentParts.Part begin(String component, String part) {
        return PARTS.begin(component, part);
    }

    /** This loader's parts. */
    public static ComponentParts parts() {
        return PARTS;
    }
}
