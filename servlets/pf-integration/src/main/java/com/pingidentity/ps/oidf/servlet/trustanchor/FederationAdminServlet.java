/*
 * The operator's API for what this entity issues and signs with.
 */
package com.pingidentity.ps.oidf.servlet.trustanchor;

import com.pingidentity.ps.oidf.authority.AuthorityRegistryException;
import com.pingidentity.ps.oidf.authority.AuthoritySupport;
import com.pingidentity.ps.oidf.federation.EntityId;
import com.pingidentity.ps.oidf.federation.event.FederationEvents;
import com.pingidentity.ps.oidf.pf.AuthorityDataSource;
import com.pingidentity.ps.oidf.pf.FederationRuntimeConfig;
import com.pingidentity.ps.oidf.pf.OperatorApi;
import com.pingidentity.ps.oidf.keyhistory.HistoricalKey;
import com.pingidentity.ps.oidf.keyhistory.KeyHistory;
import com.pingidentity.ps.oidf.keyhistory.KeyHistorySupport;
import com.pingidentity.ps.oidf.pf.PfAuditEventSink;
import com.pingidentity.ps.oidf.pf.RequestScopedServlet;
import com.pingidentity.ps.oidf.platform.health.ComponentParts;
import com.pingidentity.ps.oidf.platform.health.Startup;
import com.pingidentity.ps.oidf.platform.pf.auth.Operator;
import com.pingidentity.ps.oidf.platform.pf.auth.OperatorAuthenticator;
import com.pingidentity.ps.oidf.platform.pf.component.ComponentGate;
import com.pingidentity.ps.oidf.trustmark.TrustMarkAuditEntry;
import com.pingidentity.ps.oidf.trustmark.TrustMarkGrant;
import com.pingidentity.ps.oidf.trustmark.TrustMarkRegistry;
import com.pingidentity.ps.oidf.trustmark.TrustMarkSupport;
import com.pingidentity.ps.oidf.trustmark.TrustMarkType;
import jakarta.servlet.ServletConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.function.Predicate;
import org.jose4j.json.JsonUtil;

/**
 * The Trust Marks this entity issues (OpenID Federation 1.0 §7) and the keys it signed with before (§8.7), and the
 * hosted entities' administration, behind platform-pf's operator authenticator (plan item S8b): each route in
 * {@link OperatorApi#FEDERATION_ADMIN} needs a PingFederate-issued access token with its scope, DPoP-bound in
 * production; in development the static bearer ({@code OIDF_AUTHORITY_ADMIN_TOKEN}) is accepted beside it, with a WARN.
 * A path the table does not name is a 404 before any token is looked at.
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
 * issued to hosted entities only, only to an active one. Every change names its actor - the access token's
 * {@code sub}, for a client-credentials token the operator client's id - in the grant's history, the entity's history
 * and PingFederate's audit log. A caller's {@code X-Federation-Actor} header grants and names nothing: the authenticator
 * records it only as the {@code claimed_label} of its {@code admin.request.*} event (finding F-0165).
 */
// loadOnStartup: OPERATOR_API's part registers at deploy, not on the first request (finding F-0193); its init never throws.
@WebServlet(urlPatterns = {"/federation/admin/*"}, loadOnStartup = 1)
public class FederationAdminServlet extends RequestScopedServlet {
    private static final long serialVersionUID = 1L;

    /** Who may call: this webapp's operator authenticator, from init; the test seam's when a test made the servlet. */
    private transient OperatorAuthenticator authenticator;
    /** This servlet's part of OPERATOR_API, from init; null when a test's constructor made it and init never ran. */
    private transient volatile ComponentParts.Part part;
    private transient Map<String, TrustMarkType> types;
    private transient TrustMarkRegistry registry;
    private transient Predicate<String> activeHostedEntity;
    private transient Clock clock;
    private transient KeyHistory keyHistory;

    public FederationAdminServlet() {
    }

    /** Test seam: everything the servlet otherwise resolves from the deployment at init. */
    FederationAdminServlet(OperatorAuthenticator authenticator, Map<String, TrustMarkType> types, TrustMarkRegistry registry,
                           Predicate<String> activeHostedEntity, Clock clock, KeyHistory keyHistory) {
        this.authenticator = authenticator;
        this.types = types;
        this.registry = registry;
        this.activeHostedEntity = activeHostedEntity;
        this.clock = clock;
        this.keyHistory = keyHistory;
    }

    @Override
    public void init(ServletConfig config) throws ServletException {
        super.init(config);
        boolean injected = this.registry != null;
        ComponentParts.Part part = Startup.begin(Startup.OPERATOR_API, "FederationAdminServlet");
        this.part = part;
        part.start(() -> this.init(config, part, injected));
    }

    /**
     * The start function: what {@code init} did before S-9, run by {@link ComponentParts.Part#start} at deploy and again
     * by each supervisor retry after a dependency failure. What it throws is the part's state, never the container's.
     */
    private void init(ServletConfig config, ComponentParts.Part part, boolean injected) throws ServletException {
        PfAuditEventSink.install();
        if (injected) {
            return;
        }
        OperatorAuthenticator authenticator = OperatorApi.authenticator(config);
        if (!operatorConfigured(part, authenticator)) {
            return;
        }
        try {
            if (Startup.mayStart(Startup.HOSTING)) {
                HostedEntityServlet.configureAuthority(config::getInitParameter);
            }
        } catch (RuntimeException e) {
            // The entity routes then answer that nothing is hosted; the rest of the API still works.
            log("Hosting could not be configured for the admin API", e);
        }
        FederationRuntimeConfig runtime = FederationRuntimeConfig.get();
        Map<String, TrustMarkType> types = runtime.trustMarkIssuing().types();
        if (!TrustMarkSupport.isConfigured()) {
            AuthorityDataSource.fromEnvironment().ifPresent(TrustMarkSupport::configureJdbcRegistry);
        }
        Clock clock = Clock.systemUTC();
        KeyHistory keyHistory = null;
        if (runtime.keyHistory().enabled()) {
            if (!KeyHistorySupport.isConfigured()) {
                AuthorityDataSource.fromEnvironment().ifPresent(KeyHistorySupport::configureJdbcStore);
            }
            keyHistory = new KeyHistory(KeyHistorySupport.shared(), clock, Duration.ofSeconds(runtime.keyHistory().graceSeconds()));
        }
        // Published last, once everything above resolved; the gate keeps requests out until the part is ready.
        this.authenticator = authenticator;
        this.types = types;
        this.clock = clock;
        this.keyHistory = keyHistory;
        this.activeHostedEntity = AuthoritySupport::isActiveHostedEntity;
        this.registry = TrustMarkSupport.shared();
    }

    /**
     * Whether {@code authenticator} can let anyone in, recording on {@code part} why not: {@code REFUSED} while a static
     * bearer is set in production (Phase 3 decision 20; its reason says to remove it), off - or {@code FAILED_CONFIG}
     * when {@code OIDF_OPERATOR_API_ENABLED=true} - when no operator authentication is configured at all, and
     * {@code FAILED_CONFIG} when the PingFederate token settings are there but cannot authenticate anyone.
     */
    static boolean operatorConfigured(ComponentParts.Part part, OperatorAuthenticator authenticator) {
        String refusal = authenticator.productionRefusal();
        if (refusal != null) {
            part.refused(refusal);
            return false;
        }
        if (!authenticator.configured()) {
            part.notConfigured("no operator authentication is configured (OIDF_OPERATOR_AUDIENCE and the rest of"
                    + " docs/operator/operator-authentication.md, or in development OIDF_AUTHORITY_ADMIN_TOKEN)");
            return false;
        }
        if (!authenticator.usable()) {
            part.failedConfig(authenticator.problem());
            return false;
        }
        return true;
    }

    @Override
    protected void service(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        if (ComponentGate.servlet(this.part, resp)) {
            return;
        }
        super.service(req, resp);
    }

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        if (this.operator(req, resp) == null) {
            return;
        }
        this.read(route(req), req, resp);
    }

    /** Answers the read at {@code route} for an operator already let through. */
    void read(String route, HttpServletRequest req, HttpServletResponse resp) throws IOException {
        try {
            switch (route) {
                case "/trust-marks" -> this.list(req, resp);
                case "/trust-marks/audit" -> this.audit(req, resp);
                case "/keys" -> this.keys(resp);
                case "/entities" -> write(resp, HostedEntityAdmin.list(parameter(req, "entity_id")));
                case "/entities/audit" -> write(resp, HostedEntityAdmin.audit(parameter(req, "entity_id")));
                // operator() has answered 404 for a path OperatorApi.FEDERATION_ADMIN does not name, and
                // OperatorApiRoutesTest holds these cases and that table to each other; this is the belt.
                default -> writeError(resp, 404, "not_found", "no such endpoint");
            }
        } catch (AuthorityRegistryException e) {
            FederationErrors.write(resp, 500, "server_error", e.getMessage(), e);
        }
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        Operator operator = this.operator(req, resp);
        if (operator == null) {
            return;
        }
        Map<String, Object> body;
        try {
            body = JsonUtil.parseJson(readBody(req));
        } catch (Exception e) {
            writeError(resp, 400, "invalid_request", "the body is not a JSON object");
            return;
        }
        this.change(route(req), body, operator.actor(), resp);
    }

    /** Makes the change at {@code route} for {@code actor}, an operator already let through. */
    void change(String route, Map<String, Object> body, String actor, HttpServletResponse resp) throws IOException {
        try {
            if (route.startsWith("/entities/")) {
                write(resp, HostedEntityAdmin.change(route.substring("/entities/".length()), body, actor));
                return;
            }
            switch (route) {
                case "/trust-marks" -> this.grant(resp, body, actor);
                case "/trust-marks/revoke" -> this.revoke(resp, body, actor);
                case "/keys/revoke" -> this.revokeKey(resp, body, actor);
                // The belt, as in read().
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

    /**
     * The operator this request is from, by its route in {@link OperatorApi#FEDERATION_ADMIN}; null when the response is
     * written - a 404 for a path or method no route names, or the authenticator's refusal.
     */
    private Operator operator(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        return OperatorApi.authorise(this.authenticator, OperatorApi.FEDERATION_ADMIN, route(req), req, resp,
                r -> writeError(r, 404, "not_found", "no such endpoint")).orElse(null);
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

    private void grant(HttpServletResponse resp, Map<String, Object> body, String actor) throws IOException, AuthorityRegistryException {
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
        TrustMarkGrant granted = this.registry.grant(type, subject, notAfter, actor);
        FederationEvents.event(FederationEvents.TRUST_MARK_GRANTED).subject(subject).role("TMI").audit().field("trust_mark_type", type)
                .field("actor", actor).field("not_after", notAfter == null ? null : notAfter.getEpochSecond()).emit();
        writeJson(resp, 201, json(granted));
    }

    private void revoke(HttpServletResponse resp, Map<String, Object> body, String actor) throws IOException, AuthorityRegistryException {
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

    private void revokeKey(HttpServletResponse resp, Map<String, Object> body, String actor) throws IOException, AuthorityRegistryException {
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
            writeJson(resp, 200, this.keyHistory.revoke(kid, reason, actor).asJwk());
        } catch (AuthorityRegistryException e) {
            if (!AuthorityRegistryException.NOT_FOUND.equals(e.reason())) {
                throw e;
            }
            writeError(resp, 404, "not_found", "no retired key has that kid; the key in use is revoked by rotating it first");
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
