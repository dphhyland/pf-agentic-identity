/*
 * Who may read the health detail and /info: a caller presenting the static admin bearer token.
 */
package com.pingidentity.ps.oidf.platform.pf.health;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.function.Function;

/**
 * The static admin bearer token that guards the federation operator API ({@code FederationAdminServlet}, through
 * pf-integration's {@code AdminBearer}) also guards the health detail and {@code /agentic-identity/info} (Phase 2
 * plan, decision 6), until S8b replaces both with the operator scope {@code oidf.health.read}. platform-pf cannot
 * call {@code AdminBearer} - pf-integration depends on platform-pf, not the other way - so the same rule is written
 * here: the same token, read from the same system property and then the same environment variable, compared in
 * constant time, and fail-closed: with no token configured nobody is authorised.
 *
 * <p>An annotation-mapped servlet has no init-params, so the admin API's third source, its {@code adminToken}
 * init-param, has no counterpart here.
 */
public final class HealthAccess {

    /** The system property read first, as FederationAdminServlet reads it. */
    public static final String TOKEN_PROPERTY = "oidf.authority.admin_token";
    /** The environment variable read when the system property is unset or blank. */
    public static final String TOKEN_ENV = "OIDF_AUTHORITY_ADMIN_TOKEN";

    private HealthAccess() {
    }

    /** The configured token: the system property, else the environment variable; null when neither is set. */
    public static String resolveToken(Function<String, String> systemProperties, Function<String, String> environment) {
        String value = systemProperties.apply(TOKEN_PROPERTY);
        if (value == null || value.isBlank()) {
            value = environment.apply(TOKEN_ENV);
        }
        return value == null || value.isBlank() ? null : value;
    }

    /**
     * @param configuredToken     the token this deployment expects, or null when none is configured
     * @param authorizationHeader the request's {@code Authorization} header, or null
     * @return true only when a token is configured and the header presents exactly it as a bearer token
     */
    public static boolean isAuthorized(String configuredToken, String authorizationHeader) {
        if (configuredToken == null || configuredToken.isBlank()) {
            return false;
        }
        if (authorizationHeader == null || !authorizationHeader.regionMatches(true, 0, "Bearer ", 0, 7)) {
            return false;
        }
        String presented = authorizationHeader.substring(7).trim();
        return MessageDigest.isEqual(presented.getBytes(StandardCharsets.UTF_8), configuredToken.getBytes(StandardCharsets.UTF_8));
    }
}
