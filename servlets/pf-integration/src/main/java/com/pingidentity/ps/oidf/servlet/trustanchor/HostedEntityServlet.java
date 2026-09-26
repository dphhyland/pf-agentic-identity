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
import com.pingidentity.ps.oidf.authority.HostedEntityConfigurationBuilder;
import com.pingidentity.ps.oidf.authority.SelfSignedEntityConfigurations;
import com.pingidentity.ps.oidf.authority.HostedEntityRegistry;
import com.pingidentity.ps.oidf.authority.HostingMode;
import com.pingidentity.ps.oidf.authority.RegistryHostedEntitySigner;
import com.pingidentity.ps.oidf.federation.event.FederationEvents;
import com.pingidentity.ps.oidf.federation.policy.DecisionPoint;
import com.pingidentity.ps.oidf.federation.policy.FederationPolicyDecisionPoint;
import com.pingidentity.ps.oidf.federation.policy.PolicyDecision;
import com.pingidentity.ps.oidf.federation.policy.PolicyDecisionException;
import com.pingidentity.ps.oidf.federation.policy.PolicyDecisionRequest;
import com.pingidentity.ps.oidf.pf.FederationPolicySupport;
import com.pingidentity.ps.oidf.pf.FederationRuntimeConfig.PdpSettings;
import com.pingidentity.ps.oidf.pf.PfTracking;
import com.pingidentity.ps.oidf.pf.FederationRuntimeConfig;
import com.pingidentity.ps.oidf.pf.PfAuditEventSink;
import com.pingidentity.ps.oidf.pf.PfDataSources;
import com.pingidentity.ps.oidf.pf.RequestScopedServlet;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Pattern;
import jakarta.servlet.ServletConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
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
public class HostedEntityServlet extends RequestScopedServlet {
    private static final long serialVersionUID = 1L;
    private static final Log LOGGER = LogFactory.getLog(HostedEntityServlet.class);
    private static final String WELL_KNOWN_SUFFIX = "/.well-known/openid-federation";
    private static final String PUBLISH_SUFFIX = "/entity-configuration";
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
        } catch (HostedEntityConfigurationBuilder.NotPublishedException e) {
            writeError(resp, 404, "not_found", "entity configuration not published");
            return;
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
        String mode = stringField(body, "hostingMode");
        HostingMode hostingMode;
        if (mode == null || "AUTHORITY_SIGNED".equals(mode)) {
            hostingMode = HostingMode.AUTHORITY_SIGNED;
        } else if ("SELF_SIGNED".equals(mode)) {
            hostingMode = HostingMode.SELF_SIGNED;
        } else {
            writeError(resp, 400, "invalid_request", "'hostingMode' must be AUTHORITY_SIGNED or SELF_SIGNED");
            return;
        }
        String hostingKeyRef = stringField(body, "hostingKeyRef");
        Map<String, Object> federationJwks = null;
        if (hostingMode == HostingMode.AUTHORITY_SIGNED) {
            if (hostingKeyRef == null) {
                writeError(resp, 400, "invalid_request", "'hostingKeyRef' is required");
                return;
            }
        } else {
            // SELF_SIGNED: the entity holds its own Federation Entity Key (a Secure Enclave, a YubiKey) and
            // signs its own configuration; the authority holds no key for it, only its public keys.
            if (hostingKeyRef != null) {
                writeError(resp, 400, "invalid_request", "'hostingKeyRef' must be absent for SELF_SIGNED");
                return;
            }
            try {
                federationJwks = publicFederationJwks(body.get("federationJwks"));
            } catch (IllegalArgumentException e) {
                writeError(resp, 400, "invalid_request", e.getMessage());
                return;
            }
        }
        Object metadataRaw = body.get("metadata");
        if (hostingMode == HostingMode.SELF_SIGNED && metadataRaw == null) {
            metadataRaw = Map.of();   // the entity's own configuration carries its metadata
        }
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
            entity = new HostedEntity(entityId, hostingMode, hostingKeyRef, metadata,
                    metadataPolicy, EntityStatus.ACTIVE, listable, ownerRef, Instant.now(), notAfter,
                    federationJwks, null);
            AuthoritySupport.requireComposable(entity);
        } catch (IllegalArgumentException e) {
            writeError(resp, 400, "invalid_request", e.getMessage());
            return;
        }

        String actor = FederationAdminServlet.actor(this.adminToken, req.getHeader("X-Federation-Actor"));
        Refusal refusal = askPolicy(FederationPolicySupport.decisionPointFor(DecisionPoint.HOSTED_ENTITY_ENROL), FederationPolicySupport.settings(),
                entity, AuthoritySupport.authorityEntityId(), actor);
        if (refusal != null) {
            writeError(resp, refusal.status(), refusal.error(), refusal.description());
            return;
        }
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
        if (hostingMode == HostingMode.SELF_SIGNED) {
            out.put("publishUrl", entityId + PUBLISH_SUFFIX);
        }
        resp.setStatus(201);
        resp.setContentType("application/json");
        try (PrintWriter w = resp.getWriter()) {
            w.write(JsonUtil.toJson(out));
        }
    }

    /**
     * {@code PUT <collection>/<id>/entity-configuration}: a SELF_SIGNED entity publishes the Entity
     * Configuration it signed. No bearer token - the signature, by the federation key the authority
     * registered for this entity, is the authorisation; see {@link SelfSignedEntityConfigurations}.
     */
    @Override
    protected void doPut(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        Optional<String> idSegment = parsePublishSegment(req.getPathInfo());
        if (idSegment.isEmpty()) {
            writeError(resp, 404, "not_found", "PUT <collection>/<id>/entity-configuration");
            return;
        }
        String entityId = AuthoritySupport.authorityEntityId() + req.getServletPath() + "/" + idSegment.get();
        HostedEntityRegistry registry = AuthoritySupport.registry();
        Optional<HostedEntity> found;
        try {
            found = registry.find(entityId);
        } catch (Exception e) {
            writeError(resp, 500, "server_error", e.getMessage());
            return;
        }
        if (found.isEmpty() || !found.get().resolvable(Instant.now())) {
            writeError(resp, 404, "not_found", "unknown entity");
            return;
        }
        String validated;
        try {
            validated = SelfSignedEntityConfigurations.validate(readBody(req), found.get(),
                    AuthoritySupport.authorityEntityId(), Instant.now());
        } catch (SelfSignedEntityConfigurations.InvalidConfigurationException e) {
            writeError(resp, 400, "invalid_entity_configuration", e.getMessage());
            return;
        }
        try {
            registry.publishEntityConfiguration(entityId, validated);
        } catch (AuthorityRegistryException e) {
            writeError(resp, 500, e.reason(), e.getMessage());
            return;
        }
        LOGGER.info("self-signed entity configuration published for " + entityId);
        resp.setStatus(204);
    }

    /**
     * {@code DELETE <collection>/<id>}: revoke a hosted entity (admin bearer token). Revocation is
     * permanent; the entity stops resolving and the authority stops issuing a Subordinate Statement about
     * it, so every trust chain through it fails at the next resolution.
     */
    @Override
    protected void doDelete(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        if (!authorized(req)) {
            resp.setHeader("WWW-Authenticate", "Bearer");
            writeError(resp, 401, "unauthorized", "missing or invalid admin bearer token");
            return;
        }
        String pathInfo = req.getPathInfo();
        String slug = pathInfo == null ? null : pathInfo.replaceFirst("^/", "");
        if (slug == null || !SLUG.matcher(slug).matches()) {
            writeError(resp, 404, "not_found", "DELETE <collection>/<id>");
            return;
        }
        String entityId = AuthoritySupport.authorityEntityId() + req.getServletPath() + "/" + slug;
        try {
            AuthoritySupport.registry().setStatus(entityId, EntityStatus.REVOKED, "revoked via the hosted-entity API");
        } catch (AuthorityRegistryException e) {
            int status = AuthorityRegistryException.NOT_FOUND.equals(e.reason()) ? 404 : 500;
            writeError(resp, status, e.reason(), e.getMessage());
            return;
        }
        LOGGER.info("hosted entity revoked: " + entityId);
        resp.setStatus(204);
    }

    /**
     * The SELF_SIGNED registration's keys: public only, each with a kid (its RFC 7638 thumbprint when the
     * caller gave none, which is also what OpenID Federation recommends).
     */
    @SuppressWarnings("unchecked")
    static Map<String, Object> publicFederationJwks(Object raw) {
        if (!(raw instanceof Map) || !(((Map<String, Object>) raw).get("keys") instanceof List)) {
            throw new IllegalArgumentException("'federationJwks' must be a JWK Set for SELF_SIGNED");
        }
        List<Object> keys = (List<Object>) ((Map<String, Object>) raw).get("keys");
        if (keys.isEmpty()) {
            throw new IllegalArgumentException("'federationJwks' must hold at least one key");
        }
        List<Map<String, Object>> out = new java.util.ArrayList<>();
        for (Object k : keys) {
            if (!(k instanceof Map)) {
                throw new IllegalArgumentException("every federation key must be a JWK object");
            }
            Map<String, Object> jwk = new LinkedHashMap<>((Map<String, Object>) k);
            for (String privateMember : List.of("d", "p", "q", "dp", "dq", "qi", "k")) {
                if (jwk.containsKey(privateMember)) {
                    throw new IllegalArgumentException("federation keys must be public keys");
                }
            }
            try {
                org.jose4j.jwk.JsonWebKey parsed = org.jose4j.jwk.JsonWebKey.Factory.newJwk(jwk);
                if (!jwk.containsKey("kid")) {
                    jwk.put("kid", parsed.calculateBase64urlEncodedThumbprint("SHA-256"));
                }
            } catch (Exception e) {
                throw new IllegalArgumentException("not a usable JWK: " + e.getMessage());
            }
            out.add(jwk);
        }
        return Map.of("keys", out);
    }

    /** {@code "/<id>/entity-configuration"} -> {@code <id>}, or empty. */
    static Optional<String> parsePublishSegment(String pathInfo) {
        if (pathInfo == null || !pathInfo.startsWith("/") || !pathInfo.endsWith(PUBLISH_SUFFIX)
                || pathInfo.length() <= PUBLISH_SUFFIX.length() + 1) {
            return Optional.empty();
        }
        String id = pathInfo.substring(1, pathInfo.length() - PUBLISH_SUFFIX.length());
        return SLUG.matcher(id).matches() ? Optional.of(id) : Optional.empty();
    }

    /** Why an enrolment may not go ahead. */
    record Refusal(int status, String error, String description) {
    }

    /**
     * Asks whoever decides enrolments in this deployment ({@code OIDF_PDP_DECISION_POINTS} naming
     * {@code hosted_entity_enrol}) whether {@code entity} may be enrolled: null when it may, or when nobody decides. A
     * denial is 403 {@code access_denied}, with the PDP's {@code reason_user} only when the deployment surfaces it. No
     * decision is 503, never a permit (AuthZEN 1.0 §10.1.2), unless the deployment fails open.
     *
     * <p>The PDP hears the entity's identifier, its Entity Types and the metadata it is to be enrolled with, whether it is
     * listed, and who is enrolling it (the admin token's fingerprint, never the token).
     */
    static Refusal askPolicy(FederationPolicyDecisionPoint pdp, PdpSettings settings, HostedEntity entity, String authority, String actor) {
        if (pdp == null) {
            return null;
        }
        Map<String, Object> subject = new LinkedHashMap<>();
        subject.put("entity_types", new ArrayList<>(entity.metadata().keySet()));
        subject.put("listable", entity.listable());
        Map<String, Object> context = new LinkedHashMap<>();
        context.put("metadata", entity.metadata());
        context.put("actor", actor);
        String trackingId = PfTracking.trackingId();
        if (trackingId != null) {
            context.put(PolicyDecisionRequest.REQUEST_CONTEXT, Map.of("tracking_id", trackingId));
        }
        PolicyDecisionRequest request = new PolicyDecisionRequest(DecisionPoint.HOSTED_ENTITY_ENROL, entity.entityId(), subject,
                "federation_authority", authority, Map.of(), context, trackingId);
        PolicyDecision decision;
        try {
            decision = pdp.decide(request);
        } catch (PolicyDecisionException e) {
            FederationEvents.event(FederationEvents.PDP_CONSULTED).failure("no_decision").subject(entity.entityId()).role("authority").audit()
                    .field("action", DecisionPoint.HOSTED_ENTITY_ENROL.action()).field("actor", actor).description(e.getMessage()).emit();
            if (settings.failOpen()) {
                FederationEvents.event(FederationEvents.PDP_FAIL_OPEN).failure("no_decision").subject(entity.entityId()).role("authority").audit()
                        .field("action", DecisionPoint.HOSTED_ENTITY_ENROL.action()).description("enrolled without a policy decision: OIDF_PDP_FAIL_OPEN=true")
                        .emit();
                return null;
            }
            return new Refusal(503, "temporarily_unavailable", "the policy decision this enrolment needs could not be obtained; try again shortly");
        }
        FederationEvents.event(FederationEvents.PDP_CONSULTED).subject(entity.entityId()).role("authority").audit()
                .field("action", DecisionPoint.HOSTED_ENTITY_ENROL.action()).field("actor", actor)
                .field("decision", decision.permitted() ? "permit" : "deny").field("latency_ms", decision.latencyMs())
                .field("pdp_request_id", decision.pdpRequestId())
                .field("ignored_context", decision.ignoredContextKeys().isEmpty() ? null : decision.ignoredContextKeys())
                .description(decision.reasonAdmin()).emit();
        if (decision.permitted()) {
            return null;
        }
        FederationEvents.event(FederationEvents.HOSTED_ENTITY_REFUSED).failure("policy_denied").subject(entity.entityId()).role("authority").audit()
                .field("actor", actor).description("the policy decision point refused the enrolment").emit();
        return new Refusal(403, "access_denied", settings.surfaceUserReason() && decision.reasonUser() != null ? decision.reasonUser()
                : "this deployment's policy does not allow " + entity.entityId() + " to be enrolled");
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
