/*
 * The operator's API for what this entity issues and signs with.
 */
package com.pingidentity.ps.oidf.servlet.trustanchor;

import com.pingidentity.ps.oidf.authority.AuthorityRegistryException;
import com.pingidentity.ps.oidf.authority.AuthoritySupport;
import com.pingidentity.ps.oidf.federation.EntityId;
import com.pingidentity.ps.oidf.federation.event.FederationEvents;
import com.pingidentity.ps.oidf.federation.event.LogSafe;
import com.pingidentity.ps.oidf.pf.AdminBearer;
import com.pingidentity.ps.oidf.pf.AuthorityDataSource;
import com.pingidentity.ps.oidf.pf.FederationRuntimeConfig;
import com.pingidentity.ps.oidf.keyhistory.HistoricalKey;
import com.pingidentity.ps.oidf.keyhistory.KeyHistory;
import com.pingidentity.ps.oidf.keyhistory.KeyHistorySupport;
import com.pingidentity.ps.oidf.pf.PfAuditEventSink;
import com.pingidentity.ps.oidf.trustmark.TrustMarkAuditEntry;
import com.pingidentity.ps.oidf.trustmark.TrustMarkGrant;
import com.pingidentity.ps.oidf.trustmark.TrustMarkRegistry;
import com.pingidentity.ps.oidf.trustmark.TrustMarkSupport;
import com.pingidentity.ps.oidf.trustmark.TrustMarkType;
import jakarta.servlet.ServletConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.function.Predicate;
import org.jose4j.json.JsonUtil;

/**
 * The Trust Marks this entity issues (OpenID Federation 1.0 §7) and the keys it signed with before (§8.7), behind the
 * authority's admin bearer token ({@code OIDF_AUTHORITY_ADMIN_TOKEN}, compared in constant time; with none set every
 * request is a 401).
 *
 * <ul>
 *   <li>{@code GET /federation/admin/trust-marks?sub=...} or {@code ?trust_mark_type=...}: the grants, whatever their status.</li>
 *   <li>{@code POST /federation/admin/trust-marks} with {@code {"trust_mark_type", "sub", "not_after_seconds"?}}: grants
 *       the type, or grants it again - which revokes every mark minted under the grant before; 201.</li>
 *   <li>{@code POST /federation/admin/trust-marks/revoke} with {@code {"trust_mark_type", "sub", "reason"?}}: revokes; 200.</li>
 *   <li>{@code GET /federation/admin/trust-marks/audit?trust_mark_type=...&sub=...}: one grant's history.</li>
 *   <li>{@code GET /federation/admin/keys}: the keys this entity signed with before, as its historical keys endpoint
 *       publishes them.</li>
 *   <li>{@code POST /federation/admin/keys/revoke} with {@code {"kid", "reason"?}}: revokes a retired key - with a §8.7.3
 *       reason ({@code unspecified}, {@code compromised}, {@code superseded}) or none. The key in use is not history:
 *       rotate PingFederate's signing key first. A revoked key must never sign again.</li>
 *   <li>{@code GET /federation/admin/entities} (every hosted entity, whatever its status), {@code ?entity_id=...} (one, with
 *       its metadata and policy), {@code /entities/audit?entity_id=...} (its history); {@code POST
 *       /federation/admin/entities/suspend}, {@code /reactivate}, {@code /revoke} (permanent), {@code /metadata},
 *       {@code /metadata-policy} (only narrowing the domain default) and {@code /rotate-key}, each with
 *       {@code {"entity_id", ...}} - see {@link HostedEntityAdmin}.</li>
 * </ul>
 *
 * <p>Only a type this entity is configured to issue can be granted ({@code OIDF_FEDERATION_TRUST_MARK_TYPES}), and one
 * issued to hosted entities only, only to an active one. Every change names its actor - {@code admin:} and the first
 * eight hex digits of the token's SHA-256, with the {@code X-Federation-Actor} header after it when one is sent (for
 * accountability; it grants nothing) - in the grant's history and in PingFederate's audit log.
 */
@WebServlet(urlPatterns = {"/federation/admin/*"})
public class FederationAdminServlet extends HttpServlet {
    private static final long serialVersionUID = 1L;
    private static final int MAX_ACTOR_LENGTH = 128;

    private transient String adminToken;
    private transient Map<String, TrustMarkType> types;
    private transient TrustMarkRegistry registry;
    private transient Predicate<String> activeHostedEntity;
    private transient Clock clock;
    private transient KeyHistory keyHistory;

    public FederationAdminServlet() {
    }

    /** Test seam: everything the servlet otherwise resolves from the deployment at init. */
    FederationAdminServlet(String adminToken, Map<String, TrustMarkType> types, TrustMarkRegistry registry, Predicate<String> activeHostedEntity,
                           Clock clock, KeyHistory keyHistory) {
        this.adminToken = adminToken;
        this.types = types;
        this.registry = registry;
        this.activeHostedEntity = activeHostedEntity;
        this.clock = clock;
        this.keyHistory = keyHistory;
    }

    @Override
    public void init(ServletConfig config) throws ServletException {
        super.init(config);
        PfAuditEventSink.install();
        if (this.registry != null) {
            return;
        }
        this.adminToken = AdminBearer.resolveToken(config, "adminToken", "oidf.authority.admin_token", "OIDF_AUTHORITY_ADMIN_TOKEN");
        try {
            HostedEntityServlet.configureAuthority(config::getInitParameter);
        } catch (RuntimeException e) {
            // The entity routes then answer that nothing is hosted; the rest of the API still works.
            log("Hosting could not be configured for the admin API", e);
        }
        FederationRuntimeConfig runtime = FederationRuntimeConfig.get();
        this.types = runtime.trustMarkIssuing().types();
        if (!TrustMarkSupport.isConfigured()) {
            AuthorityDataSource.fromEnvironment().ifPresent(TrustMarkSupport::configureJdbcRegistry);
        }
        this.registry = TrustMarkSupport.shared();
        this.activeHostedEntity = AuthoritySupport::isActiveHostedEntity;
        this.clock = Clock.systemUTC();
        if (runtime.keyHistory().enabled()) {
            if (!KeyHistorySupport.isConfigured()) {
                AuthorityDataSource.fromEnvironment().ifPresent(KeyHistorySupport::configureJdbcStore);
            }
            this.keyHistory = new KeyHistory(KeyHistorySupport.shared(), this.clock, Duration.ofSeconds(runtime.keyHistory().graceSeconds()));
        }
    }

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        if (!this.authorized(req, resp)) {
            return;
        }
        try {
            switch (route(req)) {
                case "/trust-marks" -> this.list(req, resp);
                case "/trust-marks/audit" -> this.audit(req, resp);
                case "/keys" -> this.keys(resp);
                case "/entities" -> write(resp, HostedEntityAdmin.list(parameter(req, "entity_id")));
                case "/entities/audit" -> write(resp, HostedEntityAdmin.audit(parameter(req, "entity_id")));
                default -> writeError(resp, 404, "not_found", "no such endpoint");
            }
        } catch (AuthorityRegistryException e) {
            FederationErrors.write(resp, 500, "server_error", e.getMessage(), e);
        }
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        if (!this.authorized(req, resp)) {
            return;
        }
        Map<String, Object> body;
        try {
            body = JsonUtil.parseJson(readBody(req));
        } catch (Exception e) {
            writeError(resp, 400, "invalid_request", "the body is not a JSON object");
            return;
        }
        try {
            String route = route(req);
            if (route.startsWith("/entities/")) {
                write(resp, HostedEntityAdmin.change(route.substring("/entities/".length()), body,
                        actor(this.adminToken, req.getHeader("X-Federation-Actor"))));
                return;
            }
            switch (route) {
                case "/trust-marks" -> this.grant(req, resp, body);
                case "/trust-marks/revoke" -> this.revoke(req, resp, body);
                case "/keys/revoke" -> this.revokeKey(req, resp, body);
                default -> writeError(resp, 404, "not_found", "no such endpoint");
            }
        } catch (AuthorityRegistryException e) {
            FederationErrors.write(resp, 500, "server_error", e.getMessage(), e);
        }
    }

    /** The path under {@code /federation/admin}, without a trailing slash. */
    private static String route(HttpServletRequest req) {
        String path = req.getPathInfo();
        if (path == null) {
            return "";
        }
        return path.endsWith("/") ? path.substring(0, path.length() - 1) : path;
    }

    private boolean authorized(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        if (AdminBearer.isAuthorized(this.adminToken, req.getHeader("Authorization"))) {
            return true;
        }
        resp.setHeader("WWW-Authenticate", "Bearer");
        writeError(resp, 401, "unauthorized", "missing or invalid admin bearer token");
        return false;
    }

    private void list(HttpServletRequest req, HttpServletResponse resp) throws IOException, AuthorityRegistryException {
        String subject = parameter(req, "sub");
        String type = parameter(req, "trust_mark_type");
        if (subject == null && type == null) {
            writeError(resp, 400, "invalid_request", "name a sub or a trust_mark_type");
            return;
        }
        List<TrustMarkGrant> grants = subject != null ? this.registry.grantsTo(subject) : this.registry.grantsOf(type);
        writeJson(resp, 200, grants.stream().filter(g -> type == null || g.type().equals(type)).map(FederationAdminServlet::json).toList());
    }

    private void audit(HttpServletRequest req, HttpServletResponse resp) throws IOException, AuthorityRegistryException {
        String subject = parameter(req, "sub");
        String type = parameter(req, "trust_mark_type");
        if (subject == null || type == null) {
            writeError(resp, 400, "invalid_request", "name the sub and the trust_mark_type");
            return;
        }
        writeJson(resp, 200, this.registry.auditTrail(type, subject).stream().map(FederationAdminServlet::json).toList());
    }

    private void grant(HttpServletRequest req, HttpServletResponse resp, Map<String, Object> body) throws IOException, AuthorityRegistryException {
        String type = text(body, "trust_mark_type");
        String subject = text(body, "sub");
        TrustMarkType configured = type == null ? null : this.types.get(type);
        if (configured == null) {
            writeError(resp, 400, "invalid_request", "this entity does not issue Trust Marks of that type");
            return;
        }
        if (subject == null || !EntityId.isValid(subject)) {
            writeError(resp, 400, "invalid_request", "sub must be an Entity Identifier");
            return;
        }
        if (configured.subjects() == TrustMarkType.Subjects.HOSTED && !this.activeHostedEntity.test(subject)) {
            writeError(resp, 400, "invalid_request", "that type is issued only to active entities this authority hosts");
            return;
        }
        Object seconds = body.get("not_after_seconds");
        if (seconds != null && !(seconds instanceof Long n && n > 0)) {
            writeError(resp, 400, "invalid_request", "not_after_seconds must be a positive whole number");
            return;
        }
        Instant notAfter = seconds == null ? null : this.clock.instant().plusSeconds((Long) seconds);
        String actor = actor(this.adminToken, req.getHeader("X-Federation-Actor"));
        TrustMarkGrant granted = this.registry.grant(type, subject, notAfter, actor);
        FederationEvents.event(FederationEvents.TRUST_MARK_GRANTED).subject(subject).role("TMI").audit().field("trust_mark_type", type)
                .field("actor", actor).field("not_after", notAfter == null ? null : notAfter.getEpochSecond()).emit();
        writeJson(resp, 201, json(granted));
    }

    private void revoke(HttpServletRequest req, HttpServletResponse resp, Map<String, Object> body) throws IOException, AuthorityRegistryException {
        String type = text(body, "trust_mark_type");
        String subject = text(body, "sub");
        if (type == null || subject == null) {
            writeError(resp, 400, "invalid_request", "name the sub and the trust_mark_type");
            return;
        }
        Optional<TrustMarkGrant> current = this.registry.find(type, subject);
        if (current.isEmpty()) {
            writeError(resp, 404, "not_found", "no such grant");
            return;
        }
        if (current.get().status() == TrustMarkGrant.Status.REVOKED) {
            writeJson(resp, 200, json(current.get()));
            return;
        }
        String reason = Optional.ofNullable(text(body, "reason")).orElse("revoked by the operator");
        String actor = actor(this.adminToken, req.getHeader("X-Federation-Actor"));
        TrustMarkGrant revoked = this.registry.revoke(type, subject, reason, actor);
        FederationEvents.event(FederationEvents.TRUST_MARK_REVOKED).subject(subject).role("TMI").audit().field("trust_mark_type", type)
                .field("actor", actor).description(reason).emit();
        writeJson(resp, 200, json(revoked));
    }

    private void keys(HttpServletResponse resp) throws IOException, AuthorityRegistryException {
        if (this.keyHistory == null) {
            writeError(resp, 404, "not_found", "this entity keeps no key history (OIDF_FEDERATION_HISTORICAL_KEYS)");
            return;
        }
        writeJson(resp, 200, this.keyHistory.retired().stream().map(HistoricalKey::asJwk).toList());
    }

    private void revokeKey(HttpServletRequest req, HttpServletResponse resp, Map<String, Object> body) throws IOException, AuthorityRegistryException {
        if (this.keyHistory == null) {
            writeError(resp, 404, "not_found", "this entity keeps no key history (OIDF_FEDERATION_HISTORICAL_KEYS)");
            return;
        }
        String kid = text(body, "kid");
        String reason = text(body, "reason");
        if (kid == null) {
            writeError(resp, 400, "invalid_request", "name the kid of the retired key");
            return;
        }
        if (reason != null && !HistoricalKey.REASONS.contains(reason)) {
            writeError(resp, 400, "invalid_request", "the reason must be unspecified, compromised or superseded (§8.7.3), or none");
            return;
        }
        try {
            writeJson(resp, 200, this.keyHistory.revoke(kid, reason, actor(this.adminToken, req.getHeader("X-Federation-Actor"))).asJwk());
        } catch (AuthorityRegistryException e) {
            if (!AuthorityRegistryException.NOT_FOUND.equals(e.reason())) {
                throw e;
            }
            writeError(resp, 404, "not_found", "no retired key has that kid; the key in use is revoked by rotating it first");
        }
    }

    /** {@code admin:<first 8 hex of SHA-256(token)>}, and the caller's own name for itself after it when it gives one. */
    static String actor(String token, String named) {
        String id = "admin:" + HexFormat.of().formatHex(sha256(token), 0, 4);
        if (named == null || named.isBlank()) {
            return id;
        }
        String trimmed = LogSafe.value(named.trim());
        return id + " (" + (trimmed.length() > MAX_ACTOR_LENGTH ? trimmed.substring(0, MAX_ACTOR_LENGTH) : trimmed) + ")";
    }

    private static byte[] sha256(String value) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is always available", e);
        }
    }

    private static Map<String, Object> json(TrustMarkGrant grant) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("trust_mark_type", grant.type());
        out.put("sub", grant.subject());
        out.put("status", grant.status().name().toLowerCase(Locale.ROOT));
        out.put("granted_at", grant.grantedAt().getEpochSecond());
        putIfPresent(out, "not_after", grant.notAfter());
        putIfPresent(out, "revoked_at", grant.revokedAt());
        if (grant.reason() != null) {
            out.put("reason", grant.reason());
        }
        if (grant.actor() != null) {
            out.put("actor", grant.actor());
        }
        return out;
    }

    private static Map<String, Object> json(TrustMarkAuditEntry entry) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("event", entry.eventCode());
        out.put("at", entry.at().getEpochSecond());
        if (entry.detail() != null) {
            out.put("detail", entry.detail());
        }
        if (entry.actor() != null) {
            out.put("actor", entry.actor());
        }
        return out;
    }

    private static void putIfPresent(Map<String, Object> out, String name, Instant instant) {
        if (instant != null) {
            out.put(name, instant.getEpochSecond());
        }
    }

    private static String parameter(HttpServletRequest req, String name) {
        String value = req.getParameter(name);
        return value == null || value.isBlank() ? null : value;
    }

    private static String text(Map<String, Object> body, String name) {
        return body.get(name) instanceof String s && !s.isBlank() ? s.trim() : null;
    }

    private static String readBody(HttpServletRequest req) throws IOException {
        StringBuilder body = new StringBuilder();
        try (var reader = req.getReader()) {
            char[] buffer = new char[4096];
            int n;
            while ((n = reader.read(buffer)) != -1) {
                body.append(buffer, 0, n);
            }
        }
        return body.toString();
    }

    private static void writeError(HttpServletResponse resp, int status, String error, String description) throws IOException {
        FederationErrors.write(resp, status, error, description, null);
    }

    private static void writeJson(HttpServletResponse resp, int status, Map<String, Object> value) throws IOException {
        write(resp, status, JsonUtil.toJson(value));
    }

    private static void writeJson(HttpServletResponse resp, int status, List<Map<String, Object>> values) throws IOException {
        StringBuilder out = new StringBuilder("[");
        for (int i = 0; i < values.size(); i++) {
            out.append(i == 0 ? "" : ",").append(JsonUtil.toJson(values.get(i)));
        }
        write(resp, status, out.append(']').toString());
    }

    @SuppressWarnings("unchecked")
    private static void write(HttpServletResponse resp, HostedEntityAdmin.Answer answer) throws IOException {
        if (answer.error() != null) {
            writeError(resp, answer.status(), answer.error(), answer.description());
        } else if (answer.body() instanceof List<?> list) {
            writeJson(resp, answer.status(), (List<Map<String, Object>>) list);
        } else {
            writeJson(resp, answer.status(), (Map<String, Object>) answer.body());
        }
    }

    private static void write(HttpServletResponse resp, int status, String json) throws IOException {
        resp.setStatus(status);
        resp.setContentType("application/json");
        resp.setHeader("Cache-Control", "no-store");
        try (PrintWriter out = resp.getWriter()) {
            out.write(json);
        }
    }
}
