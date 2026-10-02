package com.pingidentity.ps.oidf.servlet.clientregistration;

import com.pingidentity.ps.oidf.platform.pf.internals.PfInternals;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.Objects;
import java.util.function.Function;
import jakarta.servlet.ServletConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import com.pingidentity.ps.oidf.federation.FederationError;
import com.pingidentity.ps.oidf.pf.FederationRuntimeConfig;
import com.pingidentity.ps.oidf.pf.PfAuditEventSink;
import com.pingidentity.ps.oidf.pf.RequestScopedServlet;
import com.pingidentity.ps.oidf.platform.health.ComponentParts;
import com.pingidentity.ps.oidf.platform.health.Startup;
import com.pingidentity.ps.oidf.platform.log.PlatformLog;
import com.pingidentity.ps.oidf.platform.pf.component.ComponentGate;
import com.pingidentity.ps.oidf.platform.settings.Settings;
import com.pingidentity.ps.oidf.servlet.trustanchor.FederationErrors;

/**
 * Servlet for OpenID Federation explicit client registration. Accepts a signed
 * entity statement ({@code application/entity-statement+jwt}) or a trust-chain
 * JSON body ({@code application/trust-chain+json}) at {@code /federation/register}
 * and returns a signed explicit-registration response.
 */
// loadOnStartup: its part of FEDERATION registers at deploy, not on the first request (finding F-0193); its init
// never throws, so starting it at deploy cannot stop the war.
@WebServlet(urlPatterns = {"/federation/register"}, loadOnStartup = 1)
public class OpenIdRegistrationServlet
extends RequestScopedServlet {
    private static final long serialVersionUID = 1L;
    private static final PlatformLog LOG = PlatformLog.get(OpenIdRegistrationServlet.class);
    private RegistrationService RegistrationService;
    /** This servlet's part of FEDERATION, from init; null when a test's constructor made it and init never ran. */
    private transient volatile ComponentParts.Part part;
    private final Function<HttpServletRequest, String> issuerResolver;
    /** The largest request body read ({@value #MAX_BODY_BYTES_SETTING}); read on the first request that needs it, 0 until then. */
    private volatile int maxBodyBytes;

    /** How large a registration request's body may be, in bytes: the {@code registration} catalogue's entry. */
    static final String MAX_BODY_BYTES_SETTING = "OIDF_REGISTRATION_MAX_BODY_BYTES";

    public OpenIdRegistrationServlet() {
        this(null, req -> PfInternals.issuer(req));
    }

    /** Test seam: a pre-built service and an issuer resolver, so the servlet runs without PF's runtime. */
    OpenIdRegistrationServlet(RegistrationService service, Function<HttpServletRequest, String> issuerResolver) {
        this(service, issuerResolver, 0);
    }

    /** Test seam: as above, with the body cap given rather than read from the settings (0: read them). */
    OpenIdRegistrationServlet(RegistrationService service, Function<HttpServletRequest, String> issuerResolver, int maxBodyBytes) {
        this.RegistrationService = service;
        this.issuerResolver = Objects.requireNonNull(issuerResolver, "issuerResolver");
        this.maxBodyBytes = maxBodyBytes;
    }

    public void init(ServletConfig config) throws ServletException {
        super.init(config);
        boolean injected = this.RegistrationService != null;
        ComponentParts.Part part = Startup.begin(Startup.FEDERATION, "OpenIdRegistrationServlet");
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
        // Its own settings first: an init-param that does not parse is a configuration no restart fixes.
        RegistrationConfiguration registrationConfiguration;
        try {
            registrationConfiguration = RegistrationConfiguration.fromServletConfig(config);
        }
        catch (Exception e) {
            throw new ServletException("Failed to initialize OpenID Registration servlet", e);
        }
        // Explicit registration validates the RP's chain against the trust controller's pinned keys. Without them it
        // can register nobody, but the rest of FEDERATION - the Entity Configuration, fetch, list, resolve - serves,
        // and a PingFederate that is its own trust anchor has to serve its Entity Configuration before anyone can
        // capture the keys to pin (F-0192). So the part is DEGRADED, not failed: ready stays up, the reason is in the
        // health detail, and every registration answers 503 until the keys are set and PingFederate restarts.
        FederationRuntimeConfig runtime = FederationRuntimeConfig.get();
        if (!runtime.isTrustControllerConfigured() || !runtime.hasTrustAnchors()) {
            String missing = !runtime.isTrustControllerConfigured() ? FederationRuntimeConfig.HOST_ENV + " is unset"
                    : FederationRuntimeConfig.TRUST_ANCHOR_JWKS_ENV + " is unset (and no " + FederationRuntimeConfig.SELF_ANCHOR_ENV + ")";
            LOG.warn("OpenIdRegistrationServlet: " + missing + " - explicit registration (OpenID Federation 1.0 §12.2)"
                    + " answers 503 until the trust anchor's keys are configured; the federation endpoints serve");
            part.degraded(missing + ": explicit registration answers 503 until the trust anchor's keys are configured");
            return;
        }
        try {
            this.RegistrationService = new RegistrationService(registrationConfiguration);
        }
        catch (Exception e) {
            throw new ServletException("Failed to initialize OpenID Registration servlet", e);
        }
    }

    @Override
    protected void service(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        if (ComponentGate.federationEndpoint(this.part, resp)) {
            return;
        }
        if (this.RegistrationService == null && this.part != null) {
            // Started DEGRADED, with no trust anchor keys to validate a chain against (F-0192): nothing to register with.
            FederationErrors.write(resp, FederationError.TEMPORARILY_UNAVAILABLE, "explicit registration is not available until"
                    + " the trust anchor's keys are configured", null);
            return;
        }
        super.service(req, resp);
    }

    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String path = req.getServletPath();
        try {
            switch (path) {
                case "/federation/register": {
                    this.handleExplicitRegister(req, resp);
                    break;
                }
                default: {
                    FederationErrors.write(resp, FederationError.NOT_FOUND, "unknown endpoint", null);
                    break;
                }
            }
        }
        catch (RegistrationRejectedException e) {
            if (e.isRetryable()) {
                // RFC 9110 §10.2.3: how long to wait before asking again - briefly when busy, the transport backoff
                // when the federation could not be reached or the budget ran out (the failure is remembered that long).
                resp.setHeader("Retry-After", e.kind() == RegistrationRejectedException.Kind.BUSY ? "2"
                        : Long.toString(RegistrationService.TRANSPORT_FAILURE_BACKOFF_SECONDS));
            }
            FederationErrors.write(resp, e.status(), e.error(), e.getMessage(), e);
        }
        catch (Exception e) {
            // A chain the validator refused is a FederationException carrying its §8.9 code
            // (invalid_trust_chain, invalid_metadata, invalid_trust_anchor, temporarily_unavailable).
            FederationErrors.write(resp, e);
        }
    }

    private void handleExplicitRegister(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        ExplicitRegistrationRequest registrationRequest;
        String contentType = req.getContentType();
        String mediaType = baseMediaType(contentType);
        String oidcIssuer = this.issuerResolver.apply(req);
        if ("application/entity-statement+jwt".equalsIgnoreCase(mediaType)) {
            String requestJwt = this.readRequestBody(req);
            registrationRequest = ExplicitRegistrationRequest.fromJwt(requestJwt, oidcIssuer);
        } else if ("application/trust-chain+json".equalsIgnoreCase(mediaType)) {
            String body = this.readRequestBody(req);
            registrationRequest = ExplicitRegistrationRequest.fromTrustChainJson(body);
        } else {
            FederationErrors.write(resp, FederationError.INVALID_REQUEST, "Unsupported content-type: " + contentType, null);
            return;
        }
        RegisteredClient registeredClient = this.RegistrationService.explicitRegister(registrationRequest, oidcIssuer);
        // §12.2.3: "A successful response MUST have an HTTP status code 200" - not 201.
        writeEntityStatement(resp, 200, registeredClient.signedJwt());
    }

    private static String baseMediaType(String contentType) {
        if (contentType == null) {
            return "";
        }
        int semi = contentType.indexOf(59);
        return (semi < 0 ? contentType : contentType.substring(0, semi)).trim();
    }

    /**
     * The request body, at most {@value #MAX_BODY_BYTES_SETTING} bytes of it. A body declared larger is refused before
     * any of it is read, and one that turns out larger once the cap is reached - chunked, or with a length that
     * understated it - is refused with nothing more read: 413.
     *
     * <p>PingFederate's own {@code pf.runtime.http.maxRequestBodySize} (200000 bytes by default) does not bound this
     * read: its jetty-runtime.xml gives it to the web app's {@code maxFormContentSize}, which limits form parameters,
     * and this body is read as a stream.
     */
    String readRequestBody(HttpServletRequest req) throws IOException, RegistrationRejectedException {
        int cap = this.maxBodyBytes();
        long declared = req.getContentLengthLong();
        if (declared > cap) {
            throw tooLarge(cap);
        }
        byte[] body = req.getInputStream().readNBytes(cap + 1);
        if (body.length > cap) {
            throw tooLarge(cap);
        }
        return new String(body, StandardCharsets.UTF_8);
    }

    private int maxBodyBytes() {
        int cap = this.maxBodyBytes;
        if (cap == 0) {
            cap = Settings.of("registration").integer(MAX_BODY_BYTES_SETTING);
            this.maxBodyBytes = cap;
        }
        return cap;
    }

    private static RegistrationRejectedException tooLarge(int cap) {
        return RegistrationRejectedException.request(413, "invalid_request", "the registration request is larger than " + cap
                + " bytes, the most this endpoint reads (" + MAX_BODY_BYTES_SETTING + ")");
    }

    private static void writeEntityStatement(HttpServletResponse resp, int status, String jwt) throws IOException {
        resp.setStatus(status);
        resp.setContentType("application/explicit-registration-response+jwt");
        try (PrintWriter out = resp.getWriter()) {
            out.write(jwt);
        }
    }
}

