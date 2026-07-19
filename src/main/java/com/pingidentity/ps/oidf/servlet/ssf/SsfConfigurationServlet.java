/*
 * SSF 1.0 transmitter configuration metadata endpoint.
 */
package com.pingidentity.ps.oidf.servlet.ssf;

import com.pingidentity.ps.oidf.ssf.DeliveryMethod;
import com.pingidentity.ps.oidf.ssf.SsfConfiguration;
import com.pingidentity.ps.oidf.ssf.SsfEventTypes;
import com.pingidentity.ps.oidf.ssf.SsfSupport;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.jose4j.json.JsonUtil;

/**
 * Serves the transmitter configuration metadata document (SSF 1.0 §Transmitter Configuration Metadata) at
 * {@code /.well-known/ssf-configuration} and under the module base path. A receiver reads this to discover the
 * stream-management, subject-management, and verification endpoints, the supported delivery methods
 * (RFC 8935 push + RFC 8936 poll), and the transmitter's {@code jwks_uri} for SET signature verification.
 *
 * <p>This servlet is also the one that bootstraps {@link SsfSupport} from its init parameters, so a deployment
 * that only exposes metadata still has a fully-configured transmitter for the other SSF servlets.
 */
@WebServlet(urlPatterns = {"/.well-known/ssf-configuration", "/ssf/.well-known/ssf-configuration"})
public class SsfConfigurationServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;

    @Override
    public void init(ServletConfig config) throws ServletException {
        super.init(config);
        try {
            SsfSupport.configure(SsfConfiguration.fromServletConfig(config));
        } catch (Exception e) {
            throw new ServletException("Failed to initialize SSF configuration servlet", e);
        }
    }

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
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
    protected void doOptions(HttpServletRequest req, HttpServletResponse resp) {
        applyCors(resp);
        resp.setStatus(204);
    }

    static Map<String, Object> metadata(SsfConfiguration cfg) {
        LinkedHashMap<String, Object> m = new LinkedHashMap<>();
        m.put("issuer", cfg.issuer());
        m.put("jwks_uri", cfg.jwksUri());
        m.put("delivery_methods_supported", List.of(DeliveryMethod.PUSH.urn(), DeliveryMethod.POLL.urn()));
        m.put("configuration_endpoint", cfg.configurationEndpoint());
        m.put("status_endpoint", cfg.statusEndpoint());
        m.put("add_subject_endpoint", cfg.addSubjectEndpoint());
        m.put("remove_subject_endpoint", cfg.removeSubjectEndpoint());
        m.put("verification_endpoint", cfg.verificationEndpoint());
        m.put("default_subjects", "NONE");
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
