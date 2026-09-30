/*
 * Bridges a PingFederate logout to a CAEP session-revoked SET, by filtering the OIDC logout endpoint.
 */
package com.pingidentity.ps.oidf.servlet.ssf;

import com.pingidentity.ps.oidf.platform.pf.component.ComponentGate;
import com.pingidentity.ps.oidf.platform.settings.SettingRefused;
import com.pingidentity.ps.oidf.platform.settings.Settings;
import com.pingidentity.ps.oidf.ssf.SsfEventBridge;
import com.pingidentity.ps.oidf.ssf.SsfEvents;
import com.pingidentity.ps.oidf.signals.SubjectId;
import java.io.IOException;
import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.FilterConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * Emits a CAEP {@code session-revoked} SET when PingFederate processes an OIDC logout. Map this filter over
 * PF's end-session endpoint ({@code /idp/init_logout.openid}) in {@code pf-runtime.war} — exactly like
 * {@link com.pingidentity.ps.oidf.servlet.clientregistration.TokenEndpointAutoRegistrationFilter} maps the token
 * endpoint. It reads the subject from the request's {@code id_token_hint} (or, on a development rig that opts in, an
 * explicit {@code sub}), lets PF handle the logout, and then calls {@link SsfEventBridge#onSessionRevoked} so every
 * stream subscribed to that subject receives a signed SET.
 *
 * <p><b>When it signals</b> (plan item H-SSF-6, finding F-0022). Only for an {@code id_token_hint} that
 * {@link PfIdTokenVerifier} accepts: signed by this PingFederate and issued by it, an ID token (not an access token, a
 * logout token or another JWT it signs with the same keys), and issued within {@value #MAX_AGE_SETTING} (default 24
 * hours) - an older hint raises nothing, however validly signed. Only when PingFederate's handling of the request did not
 * fail: the chain returned rather than threw, the status is below 400, and a redirect does not carry an
 * {@code error} parameter. And at most once per session ({@code sid}, or the subject when the token has none) and
 * {@code iat} within that bound ({@link Replay}), so a captured hint presented again raises nothing. Each refusal is an
 * {@code ssf.logout.signal.refused} event with its reason. A {@code logout_token} parameter is no longer read:
 * RP-Initiated Logout defines none at this endpoint, and a logout token is not a hint.
 *
 * <p><b>What the response can show</b> (the rig, PingFederate 13.1.3, 2026-10-01). {@code /idp/init_logout.openid}
 * answers 200 in every case: a hint it accepts gets an auto-submitting form to {@code /idp/startSLO.ping}, where
 * PingFederate asks the user to confirm and signs them off on a later request this filter does not see; a hint it
 * refuses gets its "Sign Off Error" page. So the response tells a failure this filter's own checks already catch from
 * a hand-off, never whether the sign-off itself completed, and PingFederate's audit records an OIDC logout (event
 * {@code SLO}) as a success with no subject even when no session existed. Finding F-0401 records it.
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
    /** What the logout filter is to the bridge's {@code ssf.set.dropped} events. */
    static final String SOURCE = "logout";

    /** {@code ssf.logout.signal.refused} reasons. */
    static final String HINT_INVALID = "hint_invalid";
    static final String HINT_NOT_ID_TOKEN = "hint_not_id_token";
    static final String HINT_TOO_OLD = "hint_too_old";
    static final String LOGOUT_FAILED = "logout_failed";
    static final String REPLAYED = "replayed";

    /** The bound on a hint's age. */
    static final String MAX_AGE_SETTING = "OIDF_SSF_LOGOUT_HINT_MAX_AGE_SECONDS";

    /**
     * What a logout request's hint yields: a subject with its replay key and {@code iat}, or the reason it yields none.
     * A {@code null} hint is a request with nothing to signal about.
     */
    record Hint(SubjectId subject, String replayKey, long issuedAt, String refusal) {
        static Hint of(SubjectId subject, String replayKey, long issuedAt) {
            return new Hint(subject, replayKey, issuedAt, null);
        }

        static Hint refused(String reason) {
            return new Hint(null, null, 0, reason);
        }
    }

    /** Read the hint a logout request carries (null if it carries none). */
    @FunctionalInterface
    interface HintReader {
        Hint read(HttpServletRequest request);
    }

    /** Sink for the revocation signal (the runtime uses {@link SsfEventBridge}). */
    @FunctionalInterface
    interface RevocationSink {
        void revoked(SubjectId subject, String reason, String txn);
    }

    private final HintReader reader;
    private final RevocationSink sink;
    private final Replay replay;

    public LogoutEventFilter() {
        this(LogoutEventFilter::readHint, LogoutEventFilter::revoke, new Replay(Replay.CAPACITY));
    }

    /** Test seam: inject the hint reader, the sink and the replay memory (avoids the SSF runtime singletons). */
    LogoutEventFilter(HintReader reader, RevocationSink sink, Replay replay) {
        this.reader = reader;
        this.sink = sink;
        this.replay = replay;
    }

    @Override
    public void init(FilterConfig filterConfig) {
        // no configuration required
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        // The logout always goes on (S9b): SSF disabled or failed stops only the emission, and nothing is read to
        // emit. No part - SSF's configuration servlet never ran init - leaves it to the bridge, a no-op until then.
        if (!ComponentGate.emits(SsfComponents.transmitterPart())) {
            chain.doFilter(request, response);
            return;
        }
        Hint hint = null;
        if (request instanceof HttpServletRequest) {
            try {
                hint = this.reader.read((HttpServletRequest) request);
            } catch (RuntimeException | LinkageError e) {
                // Whatever the extraction meets - PingFederate's key lookup not linking included - the logout goes on (S9b).
                LOGGER.warn((Object) ("SSF logout signal: could not extract subject: " + e.getMessage()));
            }
        }
        boolean completed = false;
        try {
            chain.doFilter(request, response); // let PF perform the logout regardless
            completed = true;
        } finally {
            if (hint != null) {
                try {
                    signal(hint, completed, response);
                } catch (RuntimeException e) {
                    LOGGER.warn((Object) ("SSF logout signal emission failed: " + e.getMessage()));
                }
            }
        }
    }

    /** After the chain: refuse, or raise the signal once. */
    void signal(Hint hint, boolean completed, ServletResponse response) {
        if (hint.refusal() != null) {
            SsfEvents.logoutRefused(hint.refusal());
            return;
        }
        if (failed(completed, response)) {
            LOGGER.info((Object) "SSF logout signal: PingFederate's logout did not succeed; no session-revoked is raised");
            SsfEvents.logoutRefused(LOGOUT_FAILED);
            return;
        }
        if (hint.replayKey() != null
                && !this.replay.firstUse(hint.replayKey(), hint.issuedAt() + maxAgeSeconds(), nowSeconds())) {
            LOGGER.info((Object) "SSF logout signal: this session and id_token_hint raised a signal already; not again");
            SsfEvents.logoutRefused(REPLAYED);
            return;
        }
        this.sink.revoked(hint.subject(), REASON, transactionId());
    }

    /**
     * Whether PingFederate's handling of the logout failed, as far as the response shows it: the chain threw, the
     * status is 400 or above, or a redirect carries an {@code error} parameter.
     */
    static boolean failed(boolean completed, ServletResponse response) {
        if (!completed) {
            return true;
        }
        if (!(response instanceof HttpServletResponse http)) {
            return false;
        }
        if (http.getStatus() >= 400) {
            return true;
        }
        String location = http.getHeader("Location");
        return location != null && ERROR_PARAMETER.matcher(location).find();
    }

    private static final java.util.regex.Pattern ERROR_PARAMETER = java.util.regex.Pattern.compile("[?&#]error=");

    @Override
    public void destroy() {
        // nothing to release
    }

    /** The production sink: the bridge, as the logout filter. */
    static void revoke(SubjectId subject, String reason, String txn) {
        SsfEventBridge.onSessionRevoked(subject, reason, txn, SOURCE);
    }

    /**
     * PingFederate's transaction id for this request ({@code transactionid} in log4j's thread context, where
     * PingFederate's {@code TransactionIdSupport} keeps it), as the SET's {@code txn}; null when there is none or log4j
     * is not there, and the emitter then mints one.
     */
    static String transactionId() {
        try {
            String id = org.apache.logging.log4j.ThreadContext.get("transactionid");
            return id == null || id.isBlank() ? null : id;
        } catch (LinkageError e) {
            return null;
        }
    }

    static long nowSeconds() {
        return System.currentTimeMillis() / 1000L;
    }

    /**
     * Whose session ended, from a source the caller cannot choose freely.
     *
     * <p>The subject is taken from an {@code id_token_hint} whose signature is VERIFIED against this PF's own signing
     * keys ({@link PfIdTokenVerifier}). The old behaviour trusted the token unverified and,
     * failing that, accepted a bare {@code sub} request parameter — on an endpoint reachable without
     * authentication. The emitted SET is signed by this transmitter, so a receiver has no way to tell
     * that the transmitter was told who to name: anyone could cause a
     * {@code caep.session-revoked} to be broadcast about any subject. That is signal spoofing, and it
     * is worse than useless — a security signal an attacker can aim is a denial-of-service primitive.
     *
     * <p>The raw {@code sub} parameter is accepted only when a deployment explicitly
     * opts in ({@code OIDF_SSF_LOGOUT_ALLOW_SUB_PARAM=true}), which exists for a dev rig with no real
     * id tokens to hand and warns on every use.
     */
    static Hint readHint(HttpServletRequest request) {
        // Built lazily, on the first token: the PF lookups behind forThisDeployment (signing keys,
        // issuer) are runtime singletons, and a logout with no token to verify has no reason to
        // touch them.
        return readHint(request, (jwt, now, maxAge) -> PfIdTokenVerifier.forThisDeployment(request).verify(jwt, now, maxAge),
                Holder.SETTINGS);
    }

    /**
     * The production composition with its two PingFederate lookups injected: PF's signing keys and the
     * issuer PF reports for this request. Exists so the composition itself can be exercised without a
     * booted server.
     */
    static Hint readHint(HttpServletRequest request, java.util.function.Function<HttpServletRequest, String> issuerOf,
                         PfIdTokenVerifier.KeySource keys, Settings settings) {
        return readHint(request, PfIdTokenVerifier.forDeployment(keys, issuerOf.apply(request)), settings);
    }

    /** Test seam: the same logic against a supplied verifier and settings. */
    static Hint readHint(HttpServletRequest request, IdTokenVerifier verifier, Settings settings) {
        String token = request.getParameter("id_token_hint");
        if (token != null && !token.isBlank()) {
            Hint verified = verifier.verify(token, nowSeconds(), maxAgeSeconds(settings));
            if (verified != null && verified.refusal() == null) {
                return verified;
            }
            LOGGER.info((Object) "logout: the id_token_hint was not accepted; no session-revoked signal will be emitted"
                    + " for it");
            if (!allowSubParameter(settings)) {
                return verified;
            }
        }
        if (allowSubParameter(settings)) {
            String sub = request.getParameter("sub");
            if (sub != null && !sub.isBlank()) {
                LOGGER.warn((Object) ("logout: taking the subject from an UNVERIFIED sub parameter because "
                        + ALLOW_SUB_PARAM_ENV + "=true - any caller can aim a session-revoked signal at any "
                        + "subject while this is set"));
                return Hint.of(SubjectId.opaque(sub), null, nowSeconds());
            }
        }
        return null;
    }

    static final String ALLOW_SUB_PARAM_ENV = "OIDF_SSF_LOGOUT_ALLOW_SUB_PARAM";

    /** The filter's catalogue, {@code META-INF/oidf-settings/ssf-logout-signal.json}. */
    static final String CATALOGUE = "ssf-logout-signal";

    /** Its settings, read from this process (the system property, then the environment); loaded on the first logout. */
    private static final class Holder {
        static final Settings SETTINGS = Settings.load(LogoutEventFilter.class.getClassLoader(), CATALOGUE);
    }

    /**
     * Whether the unverified {@code sub} parameter is taken ({@value #ALLOW_SUB_PARAM_ENV}, strict: {@code true} or
     * {@code false}; the development profile reads a legacy spelling as {@code false} with a warning). A value that
     * does not parse is an ERROR and reads as {@code false}: the logout proceeds and no one can aim a signal with it.
     */
    static boolean allowSubParameter() {
        return allowSubParameter(Holder.SETTINGS);
    }

    static boolean allowSubParameter(Settings settings) {
        try {
            return settings.bool(ALLOW_SUB_PARAM_ENV);
        } catch (SettingRefused e) {
            LOGGER.error((Object) ("SSF logout signal: " + e.getMessage() + "; the sub parameter is not taken"));
            return false;
        }
    }

    /** The bound on a hint's age, in seconds ({@value #MAX_AGE_SETTING}). */
    static long maxAgeSeconds() {
        return maxAgeSeconds(Holder.SETTINGS);
    }

    /**
     * {@value #MAX_AGE_SETTING} as {@code settings} give it; a value that does not parse is an ERROR and reads as the
     * default, so a typo neither lifts the bound nor stops the logout.
     */
    static long maxAgeSeconds(Settings settings) {
        try {
            return settings.duration(MAX_AGE_SETTING).getSeconds();
        } catch (SettingRefused e) {
            LOGGER.error((Object) ("SSF logout signal: " + e.getMessage() + "; the default of " + DEFAULT_MAX_AGE_SECONDS
                    + " s applies"));
            return DEFAULT_MAX_AGE_SECONDS;
        }
    }

    /** The default bound: 24 hours. */
    static final long DEFAULT_MAX_AGE_SECONDS = 86_400L;

    /** How a logout's {@code id_token_hint} is turned into a hint. Separated so it can be tested without PF. */
    interface IdTokenVerifier {
        /** The hint {@code jwt} yields at {@code nowSeconds}, a hint older than {@code maxAgeSeconds} refused; null for none. */
        Hint verify(String jwt, long nowSeconds, long maxAgeSeconds);
    }

    /**
     * The (session, {@code iat}) pairs that raised a signal, each remembered until the hint's age bound has passed, so
     * the same hint raises one signal at most. Per node and in memory (Phase 3 plan, decision 9: topology is unknown
     * until C-1): a hint replayed to another node within the bound raises a second signal there (finding F-0402). At
     * {@link #CAPACITY} entries the ones past their time are swept, and if none is, the oldest is dropped.
     */
    static final class Replay {
        static final int CAPACITY = 10_000;
        private final int capacity;
        private final java.util.LinkedHashMap<String, Long> seen = new java.util.LinkedHashMap<>();

        Replay(int capacity) {
            this.capacity = capacity;
        }

        /** Whether {@code key} is new; records it until {@code expiresAt}. */
        synchronized boolean firstUse(String key, long expiresAt, long now) {
            Long until = this.seen.get(key);
            if (until != null && until > now) {
                return false;
            }
            if (this.seen.size() >= this.capacity) {
                this.seen.values().removeIf(t -> t <= now);
                if (this.seen.size() >= this.capacity) {
                    java.util.Iterator<String> oldest = this.seen.keySet().iterator();
                    oldest.next();
                    oldest.remove();
                }
            }
            this.seen.put(key, expiresAt);
            return true;
        }

        synchronized int size() {
            return this.seen.size();
        }
    }
}
