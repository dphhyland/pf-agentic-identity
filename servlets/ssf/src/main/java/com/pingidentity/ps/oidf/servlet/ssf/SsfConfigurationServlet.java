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
        if (ComponentGate.servlet(this.part, resp)) {
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
        if (ComponentGate.servlet(this.part, resp)) {
            return;
        }
        applyCors(resp);
        resp.setStatus(204);
    }

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
