/*
 * SSF 1.0 transmitter configuration metadata endpoint.
 */
package com.pingidentity.ps.oidf.servlet.ssf;

import com.pingidentity.ps.oidf.platform.health.ComponentParts;
import com.pingidentity.ps.oidf.platform.health.Startup;
import com.pingidentity.ps.oidf.platform.pf.component.ComponentGate;
import com.pingidentity.ps.oidf.ssf.DeliveryMethod;
import com.pingidentity.ps.oidf.ssf.SsfConfiguration;
import com.pingidentity.ps.oidf.ssf.SsfEventTypes;
import com.pingidentity.ps.oidf.ssf.SsfPaths;
import com.pingidentity.ps.oidf.ssf.SsfSupport;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import jakarta.servlet.ServletConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.jose4j.json.JsonUtil;

/**
 * Serves the transmitter configuration metadata document (SSF 1.0 §Transmitter Configuration Metadata) at
 * {@code /.well-known/ssf-configuration} and under the module base path. A receiver reads this to discover the
 * stream-management, subject-management, and verification endpoints, the supported delivery methods
 * (RFC 8935 push + RFC 8936 poll), and the transmitter's {@code jwks_uri} for SET signature verification.
 *
 * <p>This servlet is also the one that starts the transmitter ({@link SsfComponents#transmitter}), from its init
 * parameters, the {@code oidf.ssf.*} system properties and the {@code OIDF_SSF_*} environment: it loads on start-up, so
 * the {@code SSF} component's part registers at deploy, and the other SSF servlets answer through its gate.
 */
@WebServlet(urlPatterns = {"/.well-known/ssf-configuration", "/ssf/.well-known/ssf-configuration"}, loadOnStartup = 1)
public class SsfConfigurationServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;

    /** This servlet's part of the {@code SSF} component; the other transmitter servlets are gated by it too. */
    private transient volatile ComponentParts.Part part;

    /**
     * Starts the transmitter as the {@code SSF} component's part ({@link SsfComponents#transmitter}): at deploy, since
     * this servlet loads on start-up, and again by the supervisor after a dependency failure. Never throws (plan item
     * S-9, finding F-0040): what goes wrong is the part's state, and its gate answers for it.
     */
    @Override
    public void init(ServletConfig config) throws ServletException {
        super.init(config);
        ComponentParts.Part part = Startup.begin(Startup.SSF, "SsfConfigurationServlet");
        this.part = part;
        SsfComponents.transmitterPart(part);
        part.start(() -> SsfComponents.transmitter(part, config));
    }

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        if (ComponentGate.oauthEndpoint(this.part, resp)) {
            return;
        }
        applyCors(resp);
        SsfConfiguration cfg = SsfSupport.configuration();
        resp.setStatus(200);
        resp.setContentType("application/json");
        resp.setHeader("Cache-Control", "public, max-age=3600");
        try (PrintWriter out = resp.getWriter()) {
            out.write(JsonUtil.toJson(metadata(cfg)));
        }
    }

    @Override
    protected void doOptions(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        if (ComponentGate.oauthEndpoint(this.part, resp)) {
            return;
        }
        applyCors(resp);
        resp.setStatus(204);
    }

    /**
     * The transmitter configuration metadata. Every member SSF 1.0 §7.1 defines, under its name there, but one:
     * {@code spec_version}, {@code issuer}, {@code jwks_uri}, {@code delivery_methods_supported},
     * {@code configuration_endpoint}, {@code status_endpoint}, {@code add_subject_endpoint},
     * {@code remove_subject_endpoint}, {@code verification_endpoint}, {@code authorization_schemes} and
     * {@code default_subjects}. The one is {@code critical_subject_members}: this transmitter names no complex-subject
     * member a receiver must interpret, and §7.2.3 says "Claims with zero elements MUST be omitted from the response."
     * {@code events_supported} and {@code all_events_supported} are this transmitter's own, which §7.2.3 allows:
     * "Other Claims MAY also be returned." Checked against §7.1 on 2026-09-30 (plan item H-SSF-3): none of the
     * defined members was missing; the endpoints are now built from the servlets' own paths ({@link SsfPaths}) rather
     * than {@code OIDF_SSF_BASE_PATH}, which is removed.
     *
     * <p>The endpoints and {@code jwks_uri} are the issuer and a path, so they are https exactly when the issuer is,
     * which §7.1 requires of each ("If present, this URL MUST use HTTP over TLS"); SsfComponents refuses an issuer
     * that is not https in production.
     */
    static Map<String, Object> metadata(SsfConfiguration cfg) {
        LinkedHashMap<String, Object> m = new LinkedHashMap<>();
        // Not decoration: SSF §7.1 reads a transmitter that omits this as implementing 1_0-ID1.
        m.put("spec_version", "1_0");
        m.put("issuer", cfg.issuer());
        m.put("jwks_uri", cfg.jwksUri());
        m.put("delivery_methods_supported", List.of(DeliveryMethod.PUSH.urn(), DeliveryMethod.POLL.urn()));
        m.put("configuration_endpoint", cfg.configurationEndpoint());
        m.put("status_endpoint", cfg.statusEndpoint());
        m.put("add_subject_endpoint", cfg.addSubjectEndpoint());
        m.put("remove_subject_endpoint", cfg.removeSubjectEndpoint());
        m.put("verification_endpoint", cfg.verificationEndpoint());
        m.put("default_subjects", cfg.defaultSubjects());
        m.put("events_supported", cfg.defaultEventTypes());
        m.put("all_events_supported", SsfEventTypes.ALL);
        m.put("authorization_schemes", List.of(Map.of("spec_urn", "urn:ietf:rfc:6749")));
        return m;
    }

    private static void applyCors(HttpServletResponse resp) {
        resp.setHeader("Access-Control-Allow-Origin", "*");
        resp.setHeader("Access-Control-Allow-Methods", "GET, OPTIONS");
        resp.setHeader("Access-Control-Allow-Headers", "Accept, Content-Type");
        resp.setHeader("Vary", "Origin");
    }
}
