/*
 * Bridges a PingFederate logout to a CAEP session-revoked SET, by filtering the OIDC logout endpoint.
 */
package com.pingidentity.ps.oidf.servlet.ssf;

import com.pingidentity.ps.oidf.ssf.SsfEventBridge;
import com.pingidentity.ps.oidf.ssf.SubjectId;
import java.io.IOException;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * Emits a CAEP {@code session-revoked} SET whenever PingFederate processes an OIDC logout. Map this filter over
 * PF's end-session endpoint ({@code /idp/init_logout.openid}) in {@code pf-runtime.war} — exactly like
 * {@link com.pingidentity.ps.oidf.servlet.clientregistration.TokenEndpointAutoRegistrationFilter} maps the token
 * endpoint. It reads the subject from the request's {@code id_token_hint} (or a back-channel {@code logout_token},
 * or an explicit {@code sub}), lets PF perform the logout, and then calls {@link SsfEventBridge#onSessionRevoked}
 * so every stream subscribed to that subject receives a signed SET.
 *
 * <p><b>Fail-open, fail-quiet:</b> the logout always proceeds even if subject extraction or signalling throws —
 * SSF emission must never break sign-out. Emission is best-effort ({@link SsfEventBridge} swallows errors and is
 * a no-op until the SSF servlets have configured the transmitter).
 *
 * <p>Deployment (bundle the module jar into {@code pf-runtime.war}, then map the filter):
 * <pre>{@code
 *   <filter>
 *     <filter-name>SsfLogoutSignal</filter-name>
 *     <filter-class>com.pingidentity.ps.oidf.servlet.ssf.LogoutEventFilter</filter-class>
 *   </filter>
 *   <filter-mapping>
 *     <filter-name>SsfLogoutSignal</filter-name>
 *     <url-pattern>/idp/init_logout.openid</url-pattern>
 *   </filter-mapping>
 * }</pre>
 */
public final class LogoutEventFilter implements Filter {

    private static final Log LOGGER = LogFactory.getLog(LogoutEventFilter.class);
    private static final String REASON = "logout";

    /** Extract the subject a logout request concerns (null if none can be determined). */
    @FunctionalInterface
    interface SubjectExtractor {
        SubjectId extract(HttpServletRequest request);
    }

    /** Sink for the revocation signal (the runtime uses {@link SsfEventBridge}). */
    @FunctionalInterface
    interface RevocationSink {
        void revoked(SubjectId subject, String reason);
    }

    private final SubjectExtractor extractor;
    private final RevocationSink sink;

    public LogoutEventFilter() {
        this(LogoutEventFilter::extractSubject, SsfEventBridge::onSessionRevoked);
    }

    /** Test seam: inject the subject extractor and the sink (avoids the SSF runtime singletons). */
    LogoutEventFilter(SubjectExtractor extractor, RevocationSink sink) {
        this.extractor = extractor;
        this.sink = sink;
    }

    @Override
    public void init(FilterConfig filterConfig) {
        // no configuration required
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        SubjectId subject = null;
        if (request instanceof HttpServletRequest) {
            try {
                subject = this.extractor.extract((HttpServletRequest) request);
            } catch (RuntimeException e) {
                LOGGER.warn((Object) ("SSF logout signal: could not extract subject: " + e.getMessage()));
            }
        }
        try {
            chain.doFilter(request, response); // let PF perform the logout regardless
        } finally {
            if (subject != null) {
                try {
                    this.sink.revoked(subject, REASON);
                } catch (RuntimeException e) {
                    LOGGER.warn((Object) ("SSF logout signal emission failed: " + e.getMessage()));
                }
            }
        }
    }

    @Override
    public void destroy() {
        // nothing to release
    }

    /**
     * Whose session ended, from a source the caller cannot choose freely.
     *
     * <p>The subject is taken from an {@code id_token_hint} / {@code logout_token} whose signature is
     * VERIFIED against this PF's own signing keys. The old behaviour trusted the token unverified and,
     * failing that, accepted a bare {@code sub} request parameter — on an endpoint reachable without
     * authentication. The emitted SET is signed by this transmitter, so a receiver has no way to tell
     * that the transmitter was told who to name: anyone could cause a
     * {@code caep.session-revoked} to be broadcast about any subject. That is signal spoofing, and it
     * is worse than useless — a security signal an attacker can aim is a denial-of-service primitive.
     *
     * <p>An expired {@code id_token_hint} is normal at logout, so expiry is not enforced; the signature
     * and the issuer are. The raw {@code sub} parameter is accepted only when a deployment explicitly
     * opts in ({@code OIDF_SSF_LOGOUT_ALLOW_SUB_PARAM=true}), which exists for a dev rig with no real
     * id tokens to hand and warns on every use.
     */
    static SubjectId extractSubject(HttpServletRequest request) {
        return extractSubject(request, PfIdTokenVerifier.forThisDeployment());
    }

    /** Test seam: the same logic against a supplied verifier. */
    static SubjectId extractSubject(HttpServletRequest request, IdTokenVerifier verifier) {
        String token = firstNonBlank(request.getParameter("id_token_hint"), request.getParameter("logout_token"));
        if (token != null) {
            SubjectId fromToken = verifier.verifiedSubject(token);
            if (fromToken != null) {
                return fromToken;
            }
            LOGGER.info((Object) "logout: id_token_hint/logout_token did not verify against this PF's keys; "
                    + "no session-revoked signal will be emitted for it");
        }
        if (allowSubParameter()) {
            String sub = request.getParameter("sub");
            if (sub != null && !sub.isBlank()) {
                LOGGER.warn((Object) ("logout: taking the subject from an UNVERIFIED sub parameter because "
                        + ALLOW_SUB_PARAM_ENV + "=true - any caller can aim a session-revoked signal at any "
                        + "subject while this is set"));
                return SubjectId.opaque(sub);
            }
        }
        return null;
    }

    static final String ALLOW_SUB_PARAM_ENV = "OIDF_SSF_LOGOUT_ALLOW_SUB_PARAM";

    private static boolean allowSubParameter() {
        String value = System.getProperty("oidf.ssf.logout.allow.sub.param");
        if (value == null || value.isBlank()) {
            value = System.getenv(ALLOW_SUB_PARAM_ENV);
        }
        return Boolean.parseBoolean(value);
    }

    /** How a logout token is turned into a subject. Separated so it can be tested without PF. */
    interface IdTokenVerifier {
        SubjectId verifiedSubject(String jwt);
    }

    private static String firstNonBlank(String a, String b) {
        if (a != null && !a.isBlank()) {
            return a;
        }
        return b != null && !b.isBlank() ? b : null;
    }
}
