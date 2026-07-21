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
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;

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
     * Best-effort subject extraction: prefer the {@code id_token_hint} / {@code logout_token} JWT's {@code sub}
     * (+{@code iss} → an {@code iss_sub} identifier), else an explicit {@code sub} request parameter (opaque).
     * The token is parsed WITHOUT signature verification — it only identifies whose session ended; the SET the
     * receiver ultimately trusts is the signed one this transmitter mints.
     */
    static SubjectId extractSubject(HttpServletRequest request) {
        String token = firstNonBlank(request.getParameter("id_token_hint"), request.getParameter("logout_token"));
        if (token != null) {
            SubjectId fromToken = subjectFromJwt(token);
            if (fromToken != null) {
                return fromToken;
            }
        }
        String sub = request.getParameter("sub");
        return sub != null && !sub.isBlank() ? SubjectId.opaque(sub) : null;
    }

    private static SubjectId subjectFromJwt(String jwt) {
        try {
            JwtConsumer consumer = new JwtConsumerBuilder()
                    .setSkipAllValidators()
                    .setDisableRequireSignature()
                    .setSkipSignatureVerification()
                    .build();
            org.jose4j.jwt.JwtClaims claims = consumer.processToClaims(jwt);
            String sub = claims.getClaimValueAsString("sub");
            if (sub == null || sub.isBlank()) {
                return null;
            }
            String iss = claims.getClaimValueAsString("iss");
            return iss != null && !iss.isBlank() ? SubjectId.issSub(iss, sub) : SubjectId.opaque(sub);
        } catch (Exception e) {
            LOGGER.debug((Object) ("SSF logout signal: unparseable logout token: " + e.getMessage()));
            return null;
        }
    }

    private static String firstNonBlank(String a, String b) {
        if (a != null && !a.isBlank()) {
            return a;
        }
        return b != null && !b.isBlank() ? b : null;
    }
}
