package com.pingidentity.ps.oidf.pf;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import javax.servlet.ServletConfig;

/**
 * The static bearer token guarding this module's operator endpoints.
 *
 * <p>Fail-closed by construction: an unconfigured token authorises nothing, so forgetting to set one
 * closes the endpoint rather than opening it. The comparison is constant-time — a timing side channel
 * here would leak the token a byte at a time, which is exactly what {@link MessageDigest#isEqual}
 * exists to prevent.
 *
 * <p>Factored out of {@code HostedEntityServlet}, which had the only implementation, so the other
 * operator surfaces can be gated by the same one rather than each growing its own.
 */
public final class AdminBearer {

    private AdminBearer() {
    }

    /**
     * @param configuredToken the token this deployment expects, or null when none is configured
     * @param authorizationHeader the request's {@code Authorization} header, or null
     * @return true only when a token IS configured and the header presents exactly it
     */
    public static boolean isAuthorized(String configuredToken, String authorizationHeader) {
        if (configuredToken == null || configuredToken.isBlank()) {
            return false;
        }
        if (authorizationHeader == null || !authorizationHeader.regionMatches(true, 0, "Bearer ", 0, 7)) {
            return false;
        }
        String presented = authorizationHeader.substring(7).trim();
        return MessageDigest.isEqual(
                presented.getBytes(StandardCharsets.UTF_8), configuredToken.getBytes(StandardCharsets.UTF_8));
    }

    /** Init-param, then system property, then environment variable — the module's usual precedence. */
    public static String resolveToken(ServletConfig config, String initParam, String sysProp, String envVar) {
        String value = config == null ? null : config.getInitParameter(initParam);
        if (value == null || value.isBlank()) {
            value = System.getProperty(sysProp);
        }
        if (value == null || value.isBlank()) {
            value = System.getenv(envVar);
        }
        return value == null || value.isBlank() ? null : value;
    }
}
