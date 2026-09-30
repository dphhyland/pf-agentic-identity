/*
 * The token endpoint's response belt: what PingFederate issued to an attested client, held to the attestation's ceiling
 * before the client sees it.
 */
package com.pingidentity.ps.oidf.servlet.clientregistration;

import com.pingidentity.access.AccessGrantManagerAccessor;
import com.pingidentity.ps.oidf.clientattestation.AttestationRarModels;
import com.pingidentity.ps.oidf.platform.health.ComponentParts;
import com.pingidentity.ps.oidf.platform.health.Startup;
import com.pingidentity.ps.oidf.platform.pf.component.ComponentGate;
import com.pingidentity.ps.oidf.rar.model.Json;
import com.pingidentity.ps.oidf.rar.model.RarModelException;
import com.pingidentity.ps.oidf.rar.model.RarModels;
import com.pingidentity.ps.oidf.servlet.clientregistration.utils.ClientAttestationUtils;
import com.pingidentity.ps.oidf.servlet.clientregistration.utils.IssuedDetailsCriterion;
import com.pingidentity.sdk.accessgrant.AccessGrant;
import com.pingidentity.sdk.accessgrant.AccessGrantManager;
import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.FilterConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletOutputStream;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.WriteListener;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpServletResponseWrapper;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.function.BooleanSupplier;
import java.util.function.Supplier;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * The response belt over {@code /as/token.oauth2} (plan item S4d, F-0032): for a request whose attestation was verified,
 * the token response PingFederate writes is held here until its {@code authorization_details} are known to be within
 * the attestation's, and replaced with {@code 400 invalid_authorization_details} when they are not.
 *
 * <p>RFC 9396 §7 puts the details in the token response: "the AS MUST also return the authorization_details as granted by
 * the resource owner and assigned to the respective access token." The belt reads them there and holds them to the
 * ceiling with the same strict {@code contains} as the issuance criterion ({@link IssuedDetailsCriterion#held}). The
 * criterion, on an access-token mapping, sees the details before the token is made; the belt is the fallback for a
 * mapping that does not carry it, and it cannot see what §7 lets an AS leave out ("The AS MAY omit values in the
 * authorization_details to the client"), which PingFederate 13.1.3 did not do on the rig.
 *
 * <ul>
 *   <li>A request without {@code OAuth-Client-Attestation} or its PoP is passed on untouched: the same request and
 *       response objects, nothing buffered.</li>
 *   <li>A request with them has its response wrapped, and the wrapper decides at PingFederate's first write (or flush)
 *       whether the attestation was verified - the attribute {@link ClientAttestationUtils#VERIFIED_ATTESTATION_ATTRIBUTE},
 *       published by ClientAttestationAuth, mapped after this filter, or by the criterion route inside PingFederate. An
 *       unverified request writes straight through.</li>
 *   <li>A verified request's body is buffered up to {@value #LIMIT} bytes. An error body, one that is not JSON, one with a
 *       {@code Content-Encoding} (PingFederate 13.1.3 compresses no token response, U-0029) and a 2xx JSON body without
 *       {@code authorization_details} go out as they came. A 2xx body past the limit cannot be checked, and is replaced
 *       with {@code 500 server_error}.</li>
 *   <li>A 2xx body whose details are not within the ceiling is replaced with {@code 400 invalid_authorization_details},
 *       RFC 9396 §6's code at the token endpoint ("the AS refuses the request with the error code
 *       invalid_authorization_details (similar to invalid_scope)"), and PingFederate's grant is revoked through the SDK's
 *       {@code AccessGrantManager} when the body carried a refresh token. PingFederate has issued the access token by
 *       then, and has no seam to revoke a JWT access token: it stays valid until it expires, but the client never
 *       receives it.</li>
 * </ul>
 *
 * <p>Every refusal is {@code attestation.issued.refused} with {@code enforcer=response_belt}. Its component is
 * {@code ATTESTATION_AUTH}; its gate is the attestation filter's.
 */
public final class IssuedDetailsBelt implements Filter {
    private static final Log LOGGER = LogFactory.getLog(IssuedDetailsBelt.class);

    /** The largest token response the belt holds, in bytes. */
    static final int LIMIT = 64 * 1024;
    static final String ATTESTATION_HEADER = "OAuth-Client-Attestation";
    static final String INVALID_AUTHORIZATION_DETAILS = "invalid_authorization_details";
    static final String EXCEEDS_DESCRIPTION = "the issued authorization_details exceed what the client attestation allows";
    static final String TOO_LARGE_DESCRIPTION = "the token response could not be checked";

    /** Revokes the grant a refresh token belongs to. */
    @FunctionalInterface
    interface GrantRevoker {
        /** @return whether a grant was found and revoked */
        boolean revoke(String refreshToken) throws Exception;
    }

    private volatile ComponentParts.Part part;
    private volatile RarModels models;
    private final Supplier<RarModels> modelSource;
    private final GrantRevoker revoker;

    public IssuedDetailsBelt() {
        this(AttestationRarModels::require, IssuedDetailsBelt::revokeInPingFederate);
    }

    /** Test seam: the models and the revoker supplied. */
    IssuedDetailsBelt(Supplier<RarModels> modelSource, GrantRevoker revoker) {
        this.modelSource = modelSource;
        this.revoker = revoker;
    }

    @Override
    public void init(FilterConfig filterConfig) {
        ComponentParts.Part begun = Startup.begin(Startup.ATTESTATION_AUTH, "IssuedDetailsBelt");
        this.part = begun;
        begun.start(() -> this.models = this.modelSource.get());
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        if (ComponentGate.filter(this.part, request, response, chain, ComponentGate::attestationTraffic)) {
            return;
        }
        if (!(request instanceof HttpServletRequest http) || !(response instanceof HttpServletResponse out)
                || !ComponentGate.attestationTraffic(http)) {
            chain.doFilter(request, response);
            return;
        }
        Held held = new Held(out, () -> http.getAttribute(ClientAttestationUtils.VERIFIED_ATTESTATION_ATTRIBUTE) instanceof Map);
        chain.doFilter(request, held);
        this.finish(http, out, held);
    }

    /** Sends what PingFederate wrote, or what replaces it. */
    void finish(HttpServletRequest request, HttpServletResponse out, Held held) throws IOException {
        byte[] body = held.close();
        if (body == null) {
            return;
        }
        if (out.isCommitted()) {
            // PingFederate answered past the wrapper (sendError, say): whatever it wrote has gone, and nothing held can follow.
            LOGGER.warn((Object) ("IssuedDetailsBelt: the response was committed past the belt; " + body.length
                    + " held bytes are dropped"));
            return;
        }
        int status = held.getStatus();
        boolean success = IssuedDetailsBelt.success(status);
        String clientId = IssuedDetailsBelt.clientOf(request);
        if (success && held.overflowed()) {
            IssuedDetailsCriterion.refuse(IssuedDetailsCriterion.BELT, clientId, IssuedDetailsCriterion.TOO_LARGE, List.of(),
                    "a token response over " + LIMIT + " bytes cannot be checked; 500");
            IssuedDetailsBelt.replace(out, 500, "server_error", TOO_LARGE_DESCRIPTION);
            return;
        }
        if (success && held.encoded()) {
            LOGGER.warn((Object) ("IssuedDetailsBelt: a token response with Content-Encoding " + held.encoding()
                    + " is passed on unchecked; PingFederate 13.1.3 compresses none"));
        }
        List<Map<String, Object>> issued = success && !held.encoded() && IssuedDetailsBelt.isJson(held.getContentType())
                ? IssuedDetailsBelt.issuedIn(body) : null;
        if (issued == null || issued.isEmpty()) {
            IssuedDetailsBelt.send(out, body);
            return;
        }
        IssuedDetailsCriterion.Outcome outcome = IssuedDetailsCriterion.held(this.models,
                request.getHeader(ATTESTATION_HEADER), issued);
        if (outcome == IssuedDetailsCriterion.Outcome.WITHIN) {
            IssuedDetailsBelt.send(out, body);
            return;
        }
        this.revokeGrantOf(body, clientId);
        IssuedDetailsCriterion.refuse(IssuedDetailsCriterion.BELT, clientId, outcome.reason(), issued,
                "the issued authorization_details are not within the client attestation's; 400");
        IssuedDetailsBelt.replace(out, 400, INVALID_AUTHORIZATION_DETAILS, EXCEEDS_DESCRIPTION);
    }

    /**
     * The {@code authorization_details} of a JSON token response, as the model reads them; null when the body is not a
     * JSON object or has none; a single entry naming no type when the member is there and is not a list of objects, so
     * that it is refused rather than passed.
     */
    static List<Map<String, Object>> issuedIn(byte[] body) {
        Object parsed;
        try {
            parsed = Json.parse(new String(body, StandardCharsets.UTF_8));
        } catch (IllegalArgumentException e) {
            return null;
        }
        if (!(parsed instanceof Map<?, ?> response) || !response.containsKey("authorization_details")) {
            return null;
        }
        try {
            return RarModels.details(response.get("authorization_details"));
        } catch (RarModelException e) {
            return List.of(Map.of("_unreadable", Boolean.TRUE));
        }
    }

    /** Revokes the grant behind the body's refresh token, if it has one; logs, never throws. */
    void revokeGrantOf(byte[] body, String clientId) {
        String refreshToken = null;
        try {
            if (Json.parse(new String(body, StandardCharsets.UTF_8)) instanceof Map<?, ?> response
                    && response.get("refresh_token") instanceof String token) {
                refreshToken = token;
            }
        } catch (IllegalArgumentException e) {
            return;
        }
        if (refreshToken == null) {
            return;
        }
        try {
            boolean revoked = this.revoker.revoke(refreshToken);
            LOGGER.info((Object) ("IssuedDetailsBelt: the refused token's grant for client_id="
                    + com.pingidentity.ps.oidf.platform.events.LogSafe.value(clientId)
                    + (revoked ? " was revoked" : " was not found to revoke")));
        } catch (Throwable t) {
            LOGGER.error((Object) ("IssuedDetailsBelt: the refused token's grant could not be revoked; its refresh token was"
                    + " never sent, and its access token stays valid until it expires"), t);
        }
    }

    /** PingFederate's revocation of the grant behind {@code refreshToken} (the SDK's AccessGrantManager). */
    static boolean revokeInPingFederate(String refreshToken) throws Exception {
        AccessGrantManager manager = AccessGrantManagerAccessor.getAccessGrantManager();
        AccessGrant grant = manager.getByRefreshToken(refreshToken);
        if (grant == null) {
            return false;
        }
        manager.revokeGrant(grant.getGuid());
        return true;
    }

    /** The verified client, from the context the attestation filter published; null when there is none. */
    static String clientOf(HttpServletRequest request) {
        return request.getAttribute(ClientAttestationUtils.VERIFIED_ATTESTATION_ATTRIBUTE) instanceof Map<?, ?> context
                && context.get("client_id") instanceof String id ? id : null;
    }

    /** A 2xx status: a response the belt checks. */
    static boolean success(int status) {
        return status / 100 == 2;
    }

    static boolean isJson(String contentType) {
        return contentType != null && contentType.toLowerCase(Locale.ROOT).contains("application/json");
    }

    private static void send(HttpServletResponse out, byte[] body) throws IOException {
        out.setContentLength(body.length);
        ServletOutputStream stream = out.getOutputStream();
        stream.write(body);
        stream.flush();
    }

    /** Replaces the held response with an OAuth error; the headers PingFederate set stay, the status and body do not. */
    static void replace(HttpServletResponse out, int status, String error, String description) throws IOException {
        Map<String, Object> json = new LinkedHashMap<>();
        json.put("error", error);
        json.put("error_description", description);
        byte[] body = org.jose4j.json.JsonUtil.toJson(json).getBytes(StandardCharsets.UTF_8);
        out.setStatus(status);
        out.setContentType("application/json;charset=UTF-8");
        out.setHeader("Cache-Control", "no-store");
        out.setHeader("Pragma", "no-cache");
        IssuedDetailsBelt.send(out, body);
    }

    @Override
    public void destroy() {
    }

    /**
     * The wrapped response. Undecided until PingFederate first asks for the body's stream or writer, or flushes: then it
     * holds the body if {@code verified} says the attestation was, and writes straight through otherwise. Status and
     * headers always go to the real response; a content length and a flush are held back while the body is.
     */
    static final class Held extends HttpServletResponseWrapper {
        private enum Mode { UNDECIDED, HOLD, PASS }

        private final HttpServletResponse real;
        private final BooleanSupplier verified;
        private final ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        private Mode mode = Mode.UNDECIDED;
        private long count;
        private boolean overflowed;
        private boolean streamedOut;
        private Long contentLength;
        private String encoding;
        private ServletOutputStream stream;
        private PrintWriter writer;

        Held(HttpServletResponse real, BooleanSupplier verified) {
            super(real);
            this.real = real;
            this.verified = verified;
        }

        private Mode decide() {
            if (this.mode == Mode.UNDECIDED) {
                this.mode = this.verified.getAsBoolean() ? Mode.HOLD : Mode.PASS;
                if (this.mode == Mode.PASS && this.contentLength != null) {
                    this.real.setContentLengthLong(this.contentLength);
                }
            }
            return this.mode;
        }

        /** Whether the body is being held. */
        boolean holding() {
            return this.mode == Mode.HOLD && !this.streamedOut;
        }

        boolean overflowed() {
            return this.overflowed;
        }

        boolean encoded() {
            return this.encoding != null && !this.encoding.isBlank() && !"identity".equalsIgnoreCase(this.encoding.trim());
        }

        String encoding() {
            return this.encoding;
        }

        /**
         * The held body, once PingFederate is done; null when nothing is held - the body went straight through, or was
         * streamed out once it could no longer be held.
         */
        byte[] close() throws IOException {
            if (this.writer != null) {
                this.writer.flush();
            }
            if (this.mode == Mode.UNDECIDED && this.contentLength != null) {
                this.real.setContentLengthLong(this.contentLength);
            }
            return this.holding() ? this.bytes.toByteArray() : null;
        }

        private void write(int b) throws IOException {
            if (this.streamedOut) {
                this.real.getOutputStream().write(b);
                return;
            }
            this.count++;
            if (this.count <= LIMIT) {
                this.bytes.write(b);
                return;
            }
            if (IssuedDetailsBelt.success(this.getStatus())) {
                // A success too large to check: counted, not kept; finish replaces it.
                this.overflowed = true;
                return;
            }
            // Not a success, so not the belt's: what is held goes out, and the rest streams after it.
            this.streamedOut = true;
            if (this.contentLength != null) {
                this.real.setContentLengthLong(this.contentLength);
            }
            ServletOutputStream out = this.real.getOutputStream();
            this.bytes.writeTo(out);
            this.bytes.reset();
            out.write(b);
        }

        @Override
        public ServletOutputStream getOutputStream() throws IOException {
            if (this.decide() == Mode.PASS) {
                return this.real.getOutputStream();
            }
            if (this.stream == null) {
                this.stream = new ServletOutputStream() {
                    @Override
                    public void write(int b) throws IOException {
                        Held.this.write(b);
                    }

                    @Override
                    public boolean isReady() {
                        return true;
                    }

                    @Override
                    public void setWriteListener(WriteListener listener) {
                        throw new IllegalStateException("the token endpoint's belt holds the body; it is not written asynchronously");
                    }
                };
            }
            return this.stream;
        }

        @Override
        public PrintWriter getWriter() throws IOException {
            if (this.decide() == Mode.PASS) {
                return this.real.getWriter();
            }
            if (this.writer == null) {
                this.writer = new PrintWriter(new OutputStreamWriter(this.getOutputStream(), StandardCharsets.UTF_8), false);
            }
            return this.writer;
        }

        @Override
        public void flushBuffer() throws IOException {
            if (this.decide() == Mode.PASS) {
                this.real.flushBuffer();
            }
        }

        @Override
        public void setContentLength(int len) {
            this.setContentLengthLong(len);
        }

        @Override
        public void setContentLengthLong(long len) {
            if (this.mode == Mode.PASS) {
                this.real.setContentLengthLong(len);
            } else {
                this.contentLength = len;
            }
        }

        @Override
        public void setHeader(String name, String value) {
            if (this.heldHeader(name, value)) {
                super.setHeader(name, value);
            }
        }

        @Override
        public void addHeader(String name, String value) {
            if (this.heldHeader(name, value)) {
                super.addHeader(name, value);
            }
        }

        @Override
        public void setIntHeader(String name, int value) {
            if (this.heldHeader(name, Integer.toString(value))) {
                super.setIntHeader(name, value);
            }
        }

        /** Notes a Content-Encoding and holds back a Content-Length; answers whether the header goes to the real response. */
        private boolean heldHeader(String name, String value) {
            if ("Content-Encoding".equalsIgnoreCase(name)) {
                this.encoding = value;
            }
            if ("Content-Length".equalsIgnoreCase(name) && this.mode != Mode.PASS) {
                try {
                    this.contentLength = Long.parseLong(value.trim());
                } catch (NumberFormatException | NullPointerException e) {
                    this.contentLength = null;
                }
                return false;
            }
            return true;
        }
    }
}
