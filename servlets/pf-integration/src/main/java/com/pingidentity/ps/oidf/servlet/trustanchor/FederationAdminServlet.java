/*
 * The operator's API for the Trust Marks this entity issues.
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
 * Grants and revokes the Trust Marks this entity issues (OpenID Federation 1.0 §7), behind the authority's admin bearer
 * token ({@code OIDF_AUTHORITY_ADMIN_TOKEN}, compared in constant time; with none set every request is a 401).
 *
 * <ul>
 *   <li>{@code GET /federation/admin/trust-marks?sub=...} or {@code ?trust_mark_type=...}: the grants, whatever their status.</li>
 *   <li>{@code POST /federation/admin/trust-marks} with {@code {"trust_mark_type", "sub", "not_after_seconds"?}}: grants
 *       the type, or grants it again - which revokes every mark minted under the grant before; 201.</li>
 *   <li>{@code POST /federation/admin/trust-marks/revoke} with {@code {"trust_mark_type", "sub", "reason"?}}: revokes; 200.</li>
 *   <li>{@code GET /federation/admin/trust-marks/audit?trust_mark_type=...&sub=...}: one grant's history.</li>
 * </ul>
 *
 * <p>Only a type this entity is configured to issue can be granted ({@code OIDF_FEDERATION_TRUST_MARK_TYPES}), and one
 * issued to hosted entities only, only to an active one. Every change names its actor - {@code admin:} and the first
 * eight hex digits of the token's SHA-256, with the {@code X-Federation-Actor} header after it when one is sent (for
 * accountability; it grants nothing) - in the grant's history and in PingFederate's audit log.
 */
@WebServlet(urlPatterns = {"/federation/admin/trust-marks", "/federation/admin/trust-marks/*"})
public class FederationAdminServlet extends HttpServlet {
    private static final long serialVersionUID = 1L;
    private static final int MAX_ACTOR_LENGTH = 128;

    private transient String adminToken;
    private transient Map<String, TrustMarkType> types;
    private transient TrustMarkRegistry registry;
    private transient Predicate<String> activeHostedEntity;
    private transient Clock clock;

    public FederationAdminServlet() {
    }

    /** Test seam: everything the servlet otherwise resolves from the deployment at init. */
    FederationAdminServlet(String adminToken, Map<String, TrustMarkType> types, TrustMarkRegistry registry, Predicate<String> activeHostedEntity,
                           Clock clock) {
        this.adminToken = adminToken;
        this.types = types;
        this.registry = registry;
        this.activeHostedEntity = activeHostedEntity;
        this.clock = clock;
    }

    @Override
    public void init(ServletConfig config) throws ServletException {
        super.init(config);
        PfAuditEventSink.install();
        if (this.registry != null) {
            return;
        }
        this.adminToken = AdminBearer.resolveToken(config, "adminToken", "oidf.authority.admin_token", "OIDF_AUTHORITY_ADMIN_TOKEN");
        this.types = FederationRuntimeConfig.get().trustMarkIssuing().types();
        if (!TrustMarkSupport.isConfigured()) {
            AuthorityDataSource.fromEnvironment().ifPresent(TrustMarkSupport::configureJdbcRegistry);
        }
        this.registry = TrustMarkSupport.shared();
        this.activeHostedEntity = AuthoritySupport::isActiveHostedEntity;
        this.clock = Clock.systemUTC();
    }

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        if (!this.authorized(req, resp)) {
            return;
        }
        try {
            switch (route(req)) {
                case "" -> this.list(req, resp);
                case "/audit" -> this.audit(req, resp);
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
            switch (route(req)) {
                case "" -> this.grant(req, resp, body);
                case "/revoke" -> this.revoke(req, resp, body);
                default -> writeError(resp, 404, "not_found", "no such endpoint");
            }
        } catch (AuthorityRegistryException e) {
            FederationErrors.write(resp, 500, "server_error", e.getMessage(), e);
        }
    }

    private static String route(HttpServletRequest req) {
        String path = req.getPathInfo();
        return path == null || "/".equals(path) ? "" : path;
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

    private static void write(HttpServletResponse resp, int status, String json) throws IOException {
        resp.setStatus(status);
        resp.setContentType("application/json");
        resp.setHeader("Cache-Control", "no-store");
        try (PrintWriter out = resp.getWriter()) {
            out.write(json);
        }
    }
}
