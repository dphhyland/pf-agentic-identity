/*
 * Serves the Entity Configuration for a federation entity this authority hosts on its behalf.
 */
package com.pingidentity.ps.oidf.servlet.trustanchor;

import com.pingidentity.ps.oidf.authority.AuthoritySupport;
import com.pingidentity.ps.oidf.authority.HostedEntity;
import com.pingidentity.ps.oidf.authority.HostedEntityRegistry;
import com.pingidentity.ps.oidf.authority.RegistryHostedEntitySigner;
import com.pingidentity.ps.oidf.common.PfDataSources;
import java.io.IOException;
import java.io.PrintWriter;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Optional;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.sql.DataSource;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jose4j.json.JsonUtil;

/**
 * Serves {@code {authority}/federation/agents/{id}/.well-known/openid-federation} and
 * {@code {authority}/federation/resources/{id}/.well-known/openid-federation} — the Entity
 * Configuration for a {@link HostedEntity}, signed on its behalf via {@link AuthoritySupport}.
 *
 * <p>Namespaced under {@code /federation/}, not a bare {@code /agents/*} or {@code /resources/*}, even
 * though every other hosted-entity path in the Domain Authority design uses those shorter names. This
 * module has no documented enumeration of PingFederate's own reserved top-level paths to check a bare
 * path against, and an entity id is effectively permanent once minted — so this reuses the one prefix
 * every other servlet in this module already serves safely in production
 * ({@link OpenIdFederationServlet}'s {@code /federation/entity}, {@code /federation/fetch}, ...) rather
 * than gamble on an unverified new one.
 *
 * <p>An entity's id is always built from the {@link AuthoritySupport#authorityEntityId()} configured at
 * startup, never from the request's Host header — an entity id is permanent for the life of its
 * registry row, and deriving it per-request would mean a reverse-proxy hostname change silently orphans
 * every statement this authority ever issued about it.
 */
@WebServlet(urlPatterns = {"/federation/agents/*", "/federation/resources/*"})
public class HostedEntityServlet extends HttpServlet {
    private static final long serialVersionUID = 1L;
    private static final Log LOGGER = LogFactory.getLog(HostedEntityServlet.class);
    private static final String WELL_KNOWN_SUFFIX = "/.well-known/openid-federation";

    @Override
    public void init(ServletConfig config) throws ServletException {
        super.init(config);
        try {
            String authorityEntityId = requireInitParam(config, "authorityEntityId",
                    "oidf.authority.entity_id", "OIDF_AUTHORITY_ENTITY_ID");
            String baoUrl = optionalInitParam(config, "openBaoUrl", "oidf.openbao.url", "OIDF_OPENBAO_URL");
            String baoToken = optionalInitParam(config, "openBaoToken", "oidf.openbao.token", "OIDF_OPENBAO_TOKEN");
            AuthoritySupport.configureSigning(
                    baoUrl != null && baoToken != null
                            ? new RegistryHostedEntitySigner(baoUrl, baoToken)
                            : RegistryHostedEntitySigner.fromEnvironment(),
                    authorityEntityId);

            String jdbcUrl = optionalInitParam(config, "jdbcUrl", "oidf.authority.jdbc.url", "OIDF_AUTHORITY_JDBC_URL");
            if (jdbcUrl != null) {
                String jdbcUser = optionalInitParam(config, "jdbcUsername", "oidf.authority.jdbc.username", "OIDF_AUTHORITY_JDBC_USERNAME");
                String jdbcPassword = optionalInitParam(config, "jdbcPassword", "oidf.authority.jdbc.password", "OIDF_AUTHORITY_JDBC_PASSWORD");
                AuthoritySupport.configureJdbcRegistry(PfDataSources.direct(jdbcUrl, jdbcUser, jdbcPassword));
            } else {
                String dataStoreId = optionalInitParam(config, "dataStoreId", "oidf.authority.data_store_id", "OIDF_AUTHORITY_DATA_STORE_ID");
                if (dataStoreId != null) {
                    AuthoritySupport.configureJdbcRegistry(PfDataSources.pfManaged(dataStoreId));
                }
                // Neither set: AuthoritySupport.registry() falls back to an in-memory registry with its
                // own loud warning the first time it is actually used — nothing to configure here.
            }
        } catch (RuntimeException e) {
            throw new ServletException("Failed to initialize HostedEntityServlet", e);
        }
    }

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        Optional<String> idSegment = parseIdSegment(req.getPathInfo());
        if (idSegment.isEmpty()) {
            writeError(resp, 404, "not_found", "no such endpoint");
            return;
        }

        String entityId = AuthoritySupport.authorityEntityId() + req.getServletPath() + "/" + idSegment.get();
        HostedEntityRegistry registry = AuthoritySupport.registry();
        Optional<HostedEntity> found;
        try {
            found = registry.find(entityId);
        } catch (Exception e) {
            LOGGER.error("hosted entity lookup failed for " + entityId, e);
            writeError(resp, 500, "server_error", e.getMessage());
            return;
        }
        // A revoked or expired entity is refused identically to one that was never hosted — its status
        // is not something an unauthenticated resolver is entitled to learn.
        if (found.isEmpty() || !found.get().resolvable(Instant.now())) {
            writeError(resp, 404, "not_found", "unknown entity");
            return;
        }

        String jwt;
        try {
            jwt = AuthoritySupport.configurationBuilder().buildEntityConfiguration(found.get());
        } catch (RuntimeException e) {
            LOGGER.error("failed to sign entity configuration for " + entityId, e);
            writeError(resp, 500, "server_error", e.getMessage());
            return;
        }
        resp.setStatus(200);
        resp.setContentType("application/entity-statement+jwt");
        try (PrintWriter out = resp.getWriter()) {
            out.write(jwt);
        }
    }

    /**
     * Pulls the entity id segment out of {@code pathInfo} ({@code "/<id>/.well-known/openid-federation"}),
     * or empty if the path doesn't match that shape at all — no HTTP types involved, so this is testable
     * without a servlet container or a mocking library neither dependency this module currently carries.
     */
    static Optional<String> parseIdSegment(String pathInfo) {
        if (pathInfo == null || !pathInfo.startsWith("/") || !pathInfo.endsWith(WELL_KNOWN_SUFFIX)
                // Must leave at least one character between the leading '/' and the suffix, or the
                // substring below would be asked for a negative-length range (pathInfo is exactly
                // WELL_KNOWN_SUFFIX, i.e. no id segment at all) and throw rather than reject cleanly.
                || pathInfo.length() <= WELL_KNOWN_SUFFIX.length()) {
            return Optional.empty();
        }
        String idSegment = pathInfo.substring(1, pathInfo.length() - WELL_KNOWN_SUFFIX.length());
        if (idSegment.isBlank() || idSegment.contains("/")) {
            return Optional.empty();
        }
        return Optional.of(idSegment);
    }

    private static void writeError(HttpServletResponse resp, int status, String error, String description) throws IOException {
        resp.setStatus(status);
        resp.setContentType("application/json");
        LinkedHashMap<String, Object> body = new LinkedHashMap<>();
        body.put("error", error);
        body.put("error_description", description);
        try (PrintWriter out = resp.getWriter()) {
            out.write(JsonUtil.toJson(body));
        }
    }

    private static String requireInitParam(ServletConfig config, String initParam, String sysProp, String envVar) {
        String value = resolveInitParam(config, initParam, sysProp, envVar);
        if (value == null) {
            throw new IllegalStateException("HostedEntityServlet requires '" + initParam + "' (init-param, "
                    + sysProp + ", or " + envVar + ")");
        }
        return value;
    }

    private static String optionalInitParam(ServletConfig config, String initParam, String sysProp, String envVar) {
        return resolveInitParam(config, initParam, sysProp, envVar);
    }

    /** init-param, then system property, then environment variable — the layering this module uses throughout. */
    private static String resolveInitParam(ServletConfig config, String initParam, String sysProp, String envVar) {
        String value = config.getInitParameter(initParam);
        if (value == null || value.isBlank()) {
            value = System.getProperty(sysProp);
        }
        if (value == null || value.isBlank()) {
            value = System.getenv(envVar);
        }
        return value == null || value.isBlank() ? null : value.trim();
    }
}
