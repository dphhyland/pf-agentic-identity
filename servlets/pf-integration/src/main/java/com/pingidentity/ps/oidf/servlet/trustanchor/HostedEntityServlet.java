/*
 * Serves the Entity Configuration for a federation entity this authority hosts on its behalf.
 */
package com.pingidentity.ps.oidf.servlet.trustanchor;

import com.pingidentity.ps.oidf.pf.AdminBearer;
import com.pingidentity.ps.oidf.trustmark.TrustMarkSupport;
import com.pingidentity.ps.oidf.authority.AuthorityRegistryException;
import com.pingidentity.ps.oidf.authority.AuthoritySupport;
import com.pingidentity.ps.oidf.authority.EntityStatus;
import com.pingidentity.ps.oidf.authority.HostedEntity;
import com.pingidentity.ps.oidf.authority.HostedEntityRegistry;
import com.pingidentity.ps.oidf.authority.HostingMode;
import com.pingidentity.ps.oidf.authority.RegistryHostedEntitySigner;
import com.pingidentity.ps.oidf.federation.event.FederationEvents;
import com.pingidentity.ps.oidf.pf.FederationRuntimeConfig;
import com.pingidentity.ps.oidf.pf.PfAuditEventSink;
import com.pingidentity.ps.oidf.pf.PfDataSources;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Pattern;
import jakarta.servlet.ServletConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
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
    /** Mirrors the lighthouse trust anchor's own enrolment slug shape (harness/ui/server.py's SLUG_RE). */
    private static final Pattern SLUG = Pattern.compile("^[a-z0-9][a-z0-9-]{0,63}$");

    private String adminToken;

    public HostedEntityServlet() {
    }

    /** Test seam: the servlet with its admin token, and hosting configured by the test through {@link AuthoritySupport}. */
    HostedEntityServlet(String adminToken) {
        this.adminToken = adminToken;
    }

    @Override
    public void init(ServletConfig config) throws ServletException {
        super.init(config);
        PfAuditEventSink.install();
        try {
            // Optional at init, not required: enrolment (doPost) needs it, but resolution (doGet) does
            // not, and a servlet that refuses to boot just because enrolment isn't configured would take
            // the read path down with it too — the same fail-soft principle SsfHttp.bootstrap follows.
            this.adminToken = setting(config::getInitParameter, "adminToken", "oidf.authority.admin_token", "OIDF_AUTHORITY_ADMIN_TOKEN");
            if (!configureAuthority(config::getInitParameter)) {
                throw new IllegalStateException("HostedEntityServlet requires 'authorityEntityId' (init-param, oidf.authority.entity_id,"
                        + " or OIDF_AUTHORITY_ENTITY_ID)");
            }
        } catch (RuntimeException e) {
            throw new ServletException("Failed to initialize HostedEntityServlet", e);
        }
    }

    /**
     * Configures this deployment as a domain authority - its durable stores, the domain default {@code metadata_policy},
     * then its signer - from init-params, system properties or the environment. The federation servlet and the admin API
     * call this too, so hosting is ready before this servlet's first request; the first configuration wins.
     *
     * <p>The stores come first: hosted lookups begin once signing is configured, and one that found no store would fall
     * back to memory for good.
     *
     * @param initParams an init-param by name, or null
     * @return false when no authority entity id is configured: this deployment hosts nothing
     */
    static boolean configureAuthority(java.util.function.Function<String, String> initParams) {
        String authorityEntityId = setting(initParams, "authorityEntityId", "oidf.authority.entity_id", "OIDF_AUTHORITY_ENTITY_ID");
        if (authorityEntityId == null) {
            return false;
        }
        javax.sql.DataSource store = null;
        String jdbcUrl = setting(initParams, "jdbcUrl", "oidf.authority.jdbc.url", "OIDF_AUTHORITY_JDBC_URL");
        if (jdbcUrl != null) {
            store = PfDataSources.direct(jdbcUrl, setting(initParams, "jdbcUsername", "oidf.authority.jdbc.username", "OIDF_AUTHORITY_JDBC_USERNAME"),
                    setting(initParams, "jdbcPassword", "oidf.authority.jdbc.password", "OIDF_AUTHORITY_JDBC_PASSWORD"));
        } else {
            String dataStoreId = setting(initParams, "dataStoreId", "oidf.authority.data_store_id", "OIDF_AUTHORITY_DATA_STORE_ID");
            if (dataStoreId != null) {
                store = PfDataSources.pfManaged(dataStoreId);
            }
        }
        if (store != null) {
            AuthoritySupport.configureJdbcRegistry(store);
            // Trust Mark grants live beside the hosted entities they are mostly given to.
            if (!TrustMarkSupport.isConfigured()) {
                TrustMarkSupport.configureJdbcRegistry(store);
            }
        }
        // Neither set: AuthoritySupport.registry() falls back to an in-memory registry with its own loud warning the first
        // time it is actually used.
        AuthoritySupport.configureDomainDefaultMetadataPolicy(FederationRuntimeConfig.get().authorityMetadataPolicy());
        String baoUrl = setting(initParams, "openBaoUrl", "oidf.openbao.url", "OIDF_OPENBAO_URL");
        String baoToken = setting(initParams, "openBaoToken", "oidf.openbao.token", "OIDF_OPENBAO_TOKEN");
        AuthoritySupport.configureSigning(baoUrl != null && baoToken != null ? new RegistryHostedEntitySigner(baoUrl, baoToken)
                : RegistryHostedEntitySigner.fromEnvironment(), authorityEntityId);
        return true;
    }

    /** An init-param, else a system property, else an environment variable; blank counts as unset at every level. */
    private static String setting(java.util.function.Function<String, String> initParams, String initParam, String sysProp, String envVar) {
        String value = initParams == null ? null : blankToNull(initParams.apply(initParam));
        if (value == null) {
            value = blankToNull(System.getProperty(sysProp));
        }
        if (value == null) {
            value = blankToNull(System.getenv(envVar));
        }
        return value;
    }

    private static String blankToNull(String value) {
        return value == null || value.isBlank() ? null : value.trim();
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
            writeError(resp, 500, "server_error", "the entity configuration could not be produced");
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
            writeError(resp, 500, "server_error", "the entity configuration could not be produced");
            return;
        }
        resp.setStatus(200);
        resp.setContentType("application/entity-statement+jwt");
        try (PrintWriter out = resp.getWriter()) {
            out.write(jwt);
        }
    }

    /**
     * Registers a new hosted entity. {@code POST} to the collection root — {@code /federation/agents} or
     * {@code /federation/resources}, matching whichever of the two mappings the request came in on — not
     * to a specific id, since the id is server-assigned from the caller's requested slug.
     *
     * <p>Request body:
     * <pre>{@code
     * {
     *   "id": "payments-agent",                 // slug: ^[a-z0-9][a-z0-9-]{0,63}$, mirrors lighthouse's own
     *   "hostingKeyRef": "agent-payments-1",     // an OpenBao transit key that already exists — this
     *                                            // endpoint registers the entity, it does not provision keys
     *   "metadata": { "oauth_client": {...} },   // required, one block per entity type this entity holds
     *   "listable": false,                       // optional, default false
     *   "ownerRef": "operator:dave",              // optional, free-form accountability field
     *   "notAfterSeconds": null,                  // optional TTL from now; omit/null for no expiry
     *   "metadataPolicy": { "oauth_client": {...} } // optional; narrows the domain default, never widens it
     * }
     * }</pre>
     *
     * <p>Gated by a static bearer token (the {@code adminToken} configured at startup), compared in
     * constant time — this endpoint creates federation-trusted identities, so unlike the read path it
     * cannot be left open. Mirrors the shape of the lighthouse trust anchor's own
     * {@code POST /api/v1/admin/subordinates}, which this repo's demo harness already drives
     * programmatically, adapted to this registry's richer, multi-type-metadata model.
     */
    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        if (!authorized(req)) {
            resp.setHeader("WWW-Authenticate", "Bearer");
            writeError(resp, 401, "unauthorized", "missing or invalid admin bearer token");
            return;
        }
        String pathInfo = req.getPathInfo();
        if (pathInfo != null && !pathInfo.equals("/")) {
            writeError(resp, 404, "not_found", "POST only the collection root, e.g. /federation/agents");
            return;
        }

        Map<String, Object> body;
        try {
            body = JsonUtil.parseJson(readBody(req));
        } catch (Exception e) {
            writeError(resp, 400, "invalid_request", "malformed JSON body");
            return;
        }

        String slug = stringField(body, "id");
        if (slug == null || !SLUG.matcher(slug).matches()) {
            writeError(resp, 400, "invalid_request", "'id' must match ^[a-z0-9][a-z0-9-]{0,63}$");
            return;
        }
        String hostingKeyRef = stringField(body, "hostingKeyRef");
        if (hostingKeyRef == null) {
            writeError(resp, 400, "invalid_request", "'hostingKeyRef' is required");
            return;
        }
        Object metadataRaw = body.get("metadata");
        if (!(metadataRaw instanceof Map)) {
            writeError(resp, 400, "invalid_request", "'metadata' is required and must be an object");
            return;
        }
        @SuppressWarnings("unchecked")
        Map<String, Object> metadata = (Map<String, Object>) metadataRaw;
        boolean listable = Boolean.TRUE.equals(body.get("listable"));
        String ownerRef = stringField(body, "ownerRef");
        Instant notAfter = null;
        if (body.get("notAfterSeconds") instanceof Number n) {
            notAfter = Instant.now().plusSeconds(n.longValue());
        }

        Object policyRaw = body.get("metadataPolicy");
        if (policyRaw != null && !(policyRaw instanceof Map)) {
            writeError(resp, 400, "invalid_request", "'metadataPolicy' must be an object, one block per entity type");
            return;
        }
        @SuppressWarnings("unchecked")
        Map<String, Object> metadataPolicy = policyRaw == null ? Map.of() : (Map<String, Object>) policyRaw;

        String entityId = AuthoritySupport.authorityEntityId() + req.getServletPath() + "/" + slug;
        HostedEntity entity;
        try {
            entity = new HostedEntity(entityId, HostingMode.AUTHORITY_SIGNED, hostingKeyRef, metadata,
                    metadataPolicy, EntityStatus.ACTIVE, listable, ownerRef, Instant.now(), notAfter);
            AuthoritySupport.requireComposable(entity);
        } catch (IllegalArgumentException e) {
            writeError(resp, 400, "invalid_request", e.getMessage());
            return;
        }

        String actor = FederationAdminServlet.actor(this.adminToken, req.getHeader("X-Federation-Actor"));
        try {
            AuthoritySupport.registry().register(entity, actor);
        } catch (AuthorityRegistryException e) {
            if (AuthorityRegistryException.DUPLICATE.equals(e.reason())) {
                writeError(resp, 409, e.reason(), e.getMessage());
            } else {
                LOGGER.error("hosted entity enrolment failed for " + entityId, e);
                writeError(resp, 500, "server_error", "the entity could not be enrolled");
            }
            return;
        }
        FederationEvents.event(FederationEvents.HOSTED_ENTITY_ENROLLED).subject(entityId).role("authority").audit().field("actor", actor)
                .field("listable", listable).emit();

        LinkedHashMap<String, Object> out = new LinkedHashMap<>();
        out.put("entityId", entityId);
        out.put("entityConfigurationUrl", entityId + WELL_KNOWN_SUFFIX);
        resp.setStatus(201);
        resp.setContentType("application/json");
        try (PrintWriter w = resp.getWriter()) {
            w.write(JsonUtil.toJson(out));
        }
    }

    /** Constant-time comparison against the configured admin token — a timing side channel on this check
     *  would leak the token one byte at a time, exactly what {@link MessageDigest#isEqual} exists to prevent. */
    private boolean authorized(HttpServletRequest req) {
        return isAuthorized(this.adminToken, req.getHeader("Authorization"));
    }

    /**
     * The actual bearer-token check, factored out from {@link #authorized(HttpServletRequest)} so it's
     * testable without a servlet container. Constant-time: a timing side channel on this comparison
     * would leak the configured token one byte at a time, exactly what {@link MessageDigest#isEqual}
     * exists to prevent.
     */
    static boolean isAuthorized(String configuredAdminToken, String authorizationHeader) {
        return AdminBearer.isAuthorized(configuredAdminToken, authorizationHeader);
    }

    private static String readBody(HttpServletRequest req) throws IOException {
        try (var reader = req.getReader()) {
            StringBuilder sb = new StringBuilder();
            char[] buf = new char[4096];
            int n;
            while ((n = reader.read(buf)) != -1) {
                sb.append(buf, 0, n);
            }
            return sb.toString();
        }
    }

    private static String stringField(Map<String, Object> body, String name) {
        Object value = body.get(name);
        if (!(value instanceof String s) || s.isBlank()) {
            return null;
        }
        return s;
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
}
