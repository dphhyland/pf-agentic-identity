/*
 * This module's operator routes: every method and path of the federation admin API, hosted-entity enrolment and
 * revocation, and the registered clients, with the scope each needs.
 */
package com.pingidentity.ps.oidf.pf;

import static com.pingidentity.ps.oidf.platform.pf.auth.OperatorRoute.mutation;
import static com.pingidentity.ps.oidf.platform.pf.auth.OperatorRoute.read;

import com.pingidentity.ps.oidf.platform.pf.auth.Operator;
import com.pingidentity.ps.oidf.platform.pf.auth.OperatorAuthenticator;
import com.pingidentity.ps.oidf.platform.pf.auth.OperatorRoute;
import com.pingidentity.ps.oidf.platform.pf.auth.OperatorRoutes;
import com.pingidentity.ps.oidf.platform.pf.auth.OperatorScopes;
import jakarta.servlet.ServletConfig;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

/**
 * The operator route tables of pf-integration's surfaces (plan item S8b), kept in the module whose servlets they name
 * so that OperatorApiRoutesTest can hold each table to the module's own {@code @WebServlet} mappings; platform-pf, which
 * holds the authenticator and the health endpoints' table, cannot see these servlets (pf-integration depends on it,
 * not the other way).
 *
 * <p>Each route names the scope a token must carry ({@link OperatorScopes}) and the label its {@code admin.request.*}
 * events and PingFederate's audit log carry. A read of the federation admin API needs {@code oidf.admin.read}; a
 * change to a hosted entity {@code oidf.admin.entities}; a Trust Mark grant or revocation {@code oidf.admin.trust_marks};
 * a key revocation, or moving a hosted entity to a new hosting key, {@code oidf.admin.keys}; the registered clients
 * {@code oidf.admin.clients.read}. A request that no table names - an unknown path, or a method the path does not take -
 * is answered 404 by the servlet before any token is looked at.
 *
 * <p>{@link #NOT_OPERATOR} lists what the same mappings serve that is not an operator route, and why: the test fails on
 * a method of a mapped path that is in neither.
 */
public final class OperatorApi {
    private static final org.apache.commons.logging.Log LOG = org.apache.commons.logging.LogFactory.getLog(OperatorApi.class);

    private OperatorApi() {
    }

    /** {@code /federation/admin/*}, by the path within it (the servlet's path info, without a trailing slash). */
    public static final OperatorRoutes FEDERATION_ADMIN = readable(OperatorRoutes.builder(),
            "/trust-marks", read("federation-admin.trust-marks.list", OperatorScopes.ADMIN_READ),
            "/trust-marks/audit", read("federation-admin.trust-marks.audit", OperatorScopes.ADMIN_READ),
            "/keys", read("federation-admin.keys.list", OperatorScopes.ADMIN_READ),
            "/entities", read("federation-admin.entities.list", OperatorScopes.ADMIN_READ),
            "/entities/audit", read("federation-admin.entities.audit", OperatorScopes.ADMIN_READ))
            .route("POST", "/trust-marks", mutation("federation-admin.trust-marks.grant", OperatorScopes.ADMIN_TRUST_MARKS))
            .route("POST", "/trust-marks/revoke",
                    mutation("federation-admin.trust-marks.revoke", OperatorScopes.ADMIN_TRUST_MARKS))
            .route("POST", "/keys/revoke", mutation("federation-admin.keys.revoke", OperatorScopes.ADMIN_KEYS))
            .route("POST", "/entities/suspend", mutation("federation-admin.entities.suspend", OperatorScopes.ADMIN_ENTITIES))
            .route("POST", "/entities/reactivate",
                    mutation("federation-admin.entities.reactivate", OperatorScopes.ADMIN_ENTITIES))
            .route("POST", "/entities/revoke", mutation("federation-admin.entities.revoke", OperatorScopes.ADMIN_ENTITIES))
            .route("POST", "/entities/metadata", mutation("federation-admin.entities.metadata", OperatorScopes.ADMIN_ENTITIES))
            .route("POST", "/entities/metadata-policy",
                    mutation("federation-admin.entities.metadata-policy", OperatorScopes.ADMIN_ENTITIES))
            .route("POST", "/entities/rotate-key", mutation("federation-admin.entities.rotate-key", OperatorScopes.ADMIN_KEYS))
            .build();

    /**
     * {@code /federation/agents/*} and {@code /federation/resources/*}, by servlet path and path info: enrolment is a
     * POST to the collection root, revocation a DELETE of one entity.
     */
    public static final OperatorRoutes HOSTED_ENTITIES = OperatorRoutes.builder()
            .route("POST", "/federation/agents", mutation("hosted-entities.enrol", OperatorScopes.ADMIN_ENTITIES))
            .route("POST", "/federation/resources", mutation("hosted-entities.enrol", OperatorScopes.ADMIN_ENTITIES))
            .route("DELETE", "/federation/agents/*", mutation("hosted-entities.revoke", OperatorScopes.ADMIN_ENTITIES))
            .route("DELETE", "/federation/resources/*", mutation("hosted-entities.revoke", OperatorScopes.ADMIN_ENTITIES))
            .build();

    /** {@code /federation/registered-clients}. */
    public static final OperatorRoutes REGISTERED_CLIENTS = readable(OperatorRoutes.builder(),
            "/federation/registered-clients", read("registered-clients.list", OperatorScopes.ADMIN_CLIENTS_READ))
            .build();

    /**
     * What the mapped paths serve that is not an operator route, by {@code "<method> <pattern>"}, with why: these carry
     * no operator token and never reach the authenticator.
     */
    public static final Map<String, String> NOT_OPERATOR;

    static {
        Map<String, String> open = new LinkedHashMap<>();
        for (String collection : new String[] {"/federation/agents/*", "/federation/resources/*"}) {
            open.put("GET " + collection, "a hosted entity's Entity Configuration, which resolvers fetch with no"
                    + " credentials");
            open.put("HEAD " + collection, "the same, without the body");
            open.put("PUT " + collection, "a SELF_SIGNED entity publishing its own Entity Configuration: authorised by"
                    + " the signature of the federation key the authority registered for it, not by an operator");
        }
        NOT_OPERATOR = Map.copyOf(open);
    }

    /**
     * The development static bearer this servlet's configuration names: its {@code adminToken} init-param, else the
     * {@code oidf.authority.admin_token} system property, else {@code OIDF_AUTHORITY_ADMIN_TOKEN}; null when none is
     * set. What it is for - development only, refused in production - is platform-pf's
     * {@link OperatorAuthenticator#withStaticBearer}, the one place that rule is written.
     */
    public static String staticBearer(ServletConfig config) {
        return setting(config, "adminToken", OperatorAuthenticator.STATIC_BEARER_PROPERTY, OperatorAuthenticator.STATIC_BEARER_ENV);
    }

    /**
     * This webapp's operator authenticator with {@code config}'s static bearer ({@link #staticBearer}), or null when it
     * cannot be built - a Redis client that cannot be made, or rs-validation missing beside platform-pf - which is
     * logged, and on which every operator route answers 503: a surface's init never fails on it, so hosting's public
     * resolution keeps serving.
     */
    public static OperatorAuthenticator authenticator(ServletConfig config) {
        return authenticator(() -> OperatorAuthenticator.shared().withStaticBearer(staticBearer(config)));
    }

    /** {@link #authenticator(ServletConfig)}'s rule over {@code build}. */
    static OperatorAuthenticator authenticator(java.util.function.Supplier<OperatorAuthenticator> build) {
        try {
            return build.get();
        } catch (RuntimeException | LinkageError e) {
            LOG.error("The operator authenticator could not be built, so every operator route answers 503: " + e, e);
            return null;
        }
    }

    /**
     * {@link #authorise(OperatorAuthenticator, HttpServletRequest, HttpServletResponse, OperatorRoute)} with no
     * authenticator: 503, {@code Cache-Control: no-store}, no body.
     */
    private static Operator unavailable(HttpServletResponse response) {
        response.setStatus(HttpServletResponse.SC_SERVICE_UNAVAILABLE);
        response.setHeader("Cache-Control", "no-store");
        response.setContentLength(0);
        return null;
    }

    /** Init-param, then system property, then environment variable - the module's usual precedence; blank is unset. */
    public static String setting(ServletConfig config, String initParam, String sysProp, String envVar) {
        String value = config == null ? null : config.getInitParameter(initParam);
        if (value == null || value.isBlank()) {
            value = System.getProperty(sysProp);
        }
        if (value == null || value.isBlank()) {
            value = System.getenv(envVar);
        }
        return value == null || value.isBlank() ? null : value;
    }

    /** Adds {@code GET} and {@code HEAD} for each path and route pair: HEAD is GET without the body (RFC 9110 9.3.2). */
    private static OperatorRoutes.Builder readable(OperatorRoutes.Builder builder, Object... pathsAndRoutes) {
        for (int i = 0; i < pathsAndRoutes.length; i += 2) {
            String path = (String) pathsAndRoutes[i];
            OperatorRoute route = (OperatorRoute) pathsAndRoutes[i + 1];
            builder.route("GET", path, route).route("HEAD", path, route);
        }
        return builder;
    }

    /**
     * Authenticates {@code request} for {@code route}: the operator it is from, or null when the authenticator refused
     * it and has answered the refusal itself (its 400, 401, 403, 429 or 503 with the challenges).
     */
    public static Operator authorise(OperatorAuthenticator authenticator, HttpServletRequest request,
                                     HttpServletResponse response, OperatorRoute route) {
        if (authenticator == null) {
            return unavailable(response);
        }
        if (!authenticator.authorise(request, response, route)) {
            return null;
        }
        return (Operator) request.getAttribute(OperatorAuthenticator.OPERATOR_ATTRIBUTE);
    }

    /**
     * The route {@code request} is in {@code table} at {@code path} and, when there is one, the operator it
     * authenticated as; an empty answer means the response is written - 404 for no route, or the authenticator's
     * refusal.
     */
    public static Optional<Operator> authorise(OperatorAuthenticator authenticator, OperatorRoutes table, String path,
                                               HttpServletRequest request, HttpServletResponse response,
                                               NotFound notFound) throws IOException {
        Optional<OperatorRoute> route = table.match(request.getMethod(), path);
        if (route.isEmpty()) {
            notFound.write(response);
            return Optional.empty();
        }
        return Optional.ofNullable(authorise(authenticator, request, response, route.get()));
    }

    /** How a surface answers a request no route names. */
    @FunctionalInterface
    public interface NotFound {
        void write(HttpServletResponse response) throws IOException;
    }
}
