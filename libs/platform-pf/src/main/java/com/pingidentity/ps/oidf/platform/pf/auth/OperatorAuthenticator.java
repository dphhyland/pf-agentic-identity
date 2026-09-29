/*
 * Authenticates a request to an operator API with a PingFederate-issued access token.
 */
package com.pingidentity.ps.oidf.platform.pf.auth;

import com.pingidentity.ps.oidf.platform.auth.ClientAuthentication;
import com.pingidentity.ps.oidf.platform.auth.TokenIntrospector;
import com.pingidentity.ps.oidf.platform.events.Events;
import com.pingidentity.ps.oidf.platform.events.LogSafe;
import com.pingidentity.ps.oidf.platform.http.AddressPolicy;
import com.pingidentity.ps.oidf.platform.http.OutboundHttp;
import com.pingidentity.ps.oidf.platform.http.TlsTrust;
import com.pingidentity.ps.oidf.platform.log.PlatformLog;
import com.pingidentity.ps.oidf.platform.pf.internals.PfInternals;
import com.pingidentity.ps.oidf.platform.profile.AcceptedRisks;
import com.pingidentity.ps.oidf.platform.profile.DeploymentProfile;
import com.pingidentity.ps.oidf.platform.redis.RedisClient;
import com.pingidentity.ps.oidf.platform.redis.RedisConfig;
import com.pingidentity.ps.oidf.platform.redis.WindowCount;
import com.pingidentity.ps.oidf.platform.settings.Settings;
import com.pingidentity.ps.oidf.rs.AccessTokenType;
import com.pingidentity.ps.oidf.rs.DelegatedTokenValidator;
import com.pingidentity.ps.oidf.rs.InMemoryReplayStore;
import com.pingidentity.ps.oidf.rs.JwksSource;
import com.pingidentity.ps.oidf.rs.RedisReplayStore;
import com.pingidentity.ps.oidf.rs.RemoteJwks;
import com.pingidentity.ps.oidf.rs.ReplayStore;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.TreeSet;
import java.util.function.Function;
import java.util.regex.Pattern;

/**
 * Who may use an operator API (plan item S8a; decision 1): a caller presenting a PingFederate-issued OAuth access token,
 * bound to a key or a certificate in production, carrying the route's scope. The actor recorded is the token's
 * subject. Plan item S8b moves every operator surface onto this; until then nothing calls it.
 *
 * <p>Each request, in order:
 * <ol>
 *   <li><b>The failed-authentication limit.</b> A client address - the container's remote address, never
 *       {@code X-Forwarded-For} - that has failed authentication {@code OIDF_OPERATOR_AUTH_FAILURES_PER_MINUTE} times
 *       (10) in the current minute is answered 429 with {@code Retry-After}, before its token is looked at, so a
 *       caller cannot keep guessing. Every 400 and 401 below counts one failure.</li>
 *   <li><b>The token.</b> Exactly one {@code Authorization} header, {@code DPoP} or {@code Bearer}, with a token68
 *       credential, and no {@code access_token} in the query. Then rs-validation's {@link DelegatedTokenValidator},
 *       in the configured mode: {@code jwt} verifies the token against PingFederate's JWKS; {@code introspection}
 *       asks PingFederate's introspection endpoint (platform.auth's TokenIntrospector: 1 s to connect, 2.5 s in all).
 *       Either way {@code iss} is PingFederate's issuer for this request ({@link PfInternals#issuer}), {@code aud}
 *       contains {@code OIDF_OPERATOR_AUDIENCE}, and {@code exp} and {@code nbf} hold.</li>
 *   <li><b>The binding.</b> A DPoP-bound token needs its proof: RFC 9449 §4.3's checks through oidf-jose's
 *       DpopProofValidator, with {@code htm} the request's method and {@code htu} {@code OIDF_OPERATOR_BASE_URL}
 *       followed by the request's path - never the {@code Host} header - its {@code ath} this token's hash, its key's
 *       thumbprint {@code cnf.jkt}, and its {@code jti} not seen before (Redis under {@code oidf:admin:dpop} when
 *       Redis is configured; otherwise this JVM, which production allows only under the {@code in-memory-state}
 *       accepted risk). A certificate-bound token ({@code cnf.x5t#S256}) is accepted where the container presents the
 *       client certificate. A token bound to nothing is refused in production, with the DPoP challenge; development
 *       accepts it with a WARN.</li>
 *   <li><b>The actor.</b> The token's {@code sub} - for a client-credentials token PingFederate makes it the client
 *       id - or, when it has none, its {@code client_id}. Never a header: {@code X-Federation-Actor} is recorded only
 *       as the event's {@code claimed_label}.</li>
 *   <li><b>The scope.</b> The route's scope must be among the token's, or the request is 403
 *       {@code insufficient_scope} with the scope named in the challenge.</li>
 *   <li><b>The change limit.</b> A route that changes something counts against the actor's
 *       {@code OIDF_OPERATOR_MUTATIONS_PER_MINUTE} (60) a minute; over it is 429 with {@code Retry-After}.</li>
 * </ol>
 *
 * <p>Every request let through and every one refused emits an event from the {@code operator} catalogue -
 * {@code admin.request.authorised} or {@code admin.request.refused} - which platform.events counts and platform-pf's
 * audit sink writes to PingFederate's audit log.
 *
 * <p>Refusals follow RFC 6750 §3: "If the protected resource request does not include authentication credentials or
 * does not contain an access token that enables access to the protected resource, the resource server MUST include the
 * HTTP "WWW-Authenticate" response header field". Every 400, 401 and 403 carries a {@code DPoP} challenge with the
 * accepted algorithms (RFC 9449 §7.1) and a {@code Bearer} challenge (for a certificate-bound token, and in
 * development an unbound one); the error goes in the challenge of the scheme the client used (RFC 9449 §7.2), or in
 * both when the request was ambiguous. A 429 carries {@code Retry-After} and a 503 nothing: no store, key source or
 * introspection endpoint that could not answer ever lets a request through.
 */
public final class OperatorAuthenticator {

    /** Where an authorised request carries its {@link Operator}. */
    public static final String OPERATOR_ATTRIBUTE = "com.pingidentity.ps.oidf.platform.pf.auth.Operator";
    /** The event catalogue's component. */
    static final String COMPONENT = "operator";
    static final String AUTHORISED = "admin.request.authorised";
    static final String REFUSED = "admin.request.refused";
    /** The Redis namespace of the operator APIs' DPoP proofs (client-attestation's StoreNamespace.ADMIN_DPOP). */
    public static final String DPOP_NAMESPACE = "oidf:admin:dpop";
    /** The Redis namespaces of the two limits. */
    public static final String FAILURES_NAMESPACE = "oidf:admin:limit:auth";
    public static final String MUTATIONS_NAMESPACE = "oidf:admin:limit:mutation";
    /** The longest {@code X-Federation-Actor} value kept as a claimed label. */
    public static final int CLAIMED_LABEL_LIMIT = 128;
    static final String CERTIFICATE_ATTRIBUTE = "jakarta.servlet.request.X509Certificate";

    private static final PlatformLog LOG = PlatformLog.get(OperatorAuthenticator.class);
    private static final Duration MINUTE = Duration.ofMinutes(1);
    /** RFC 9449 §7.1's token68, which the DPoP scheme and RFC 6750's Bearer both use. */
    private static final Pattern TOKEN68 = Pattern.compile("[A-Za-z0-9\\-._~+/]+=*");
    private static final Pattern ACCESS_TOKEN_QUERY = Pattern.compile("(^|&)access_token=");
    private static final int DESCRIPTION_LIMIT = 200;

    private final OperatorAuthConfig config;
    private final JwksSource keys;
    private final TokenIntrospector introspector;
    private final ReplayStore replayStore;
    private final WindowCounter failures;
    private final WindowCounter mutations;
    private final Function<HttpServletRequest, String> issuer;

    /**
     * An authenticator over the given parts; {@link #fromProcess()} builds the process's own.
     *
     * @param keys         PingFederate's keys, in {@code jwt} mode; null in {@code introspection} mode
     * @param introspector the introspection client, in {@code introspection} mode; null in {@code jwt} mode
     * @param issuer       PingFederate's issuer for a request: {@link PfInternals#issuer} inside PingFederate
     */
    public OperatorAuthenticator(OperatorAuthConfig config, JwksSource keys, TokenIntrospector introspector,
                                 ReplayStore replayStore, WindowCounter failures, WindowCounter mutations,
                                 Function<HttpServletRequest, String> issuer) {
        this.config = Objects.requireNonNull(config, "config");
        this.keys = keys;
        this.introspector = introspector;
        this.replayStore = Objects.requireNonNull(replayStore, "replayStore");
        this.failures = Objects.requireNonNull(failures, "failures");
        this.mutations = Objects.requireNonNull(mutations, "mutations");
        this.issuer = Objects.requireNonNull(issuer, "issuer");
    }

    /**
     * The process's authenticator: its settings from the {@code operator-auth} catalogue, its profile and accepted
     * risks, Redis when {@code OIDF_REDIS_URL} names one, PingFederate's issuer through {@link PfInternals}. A
     * configuration that cannot authenticate anyone still builds, and answers every request 503 with the reason
     * logged once here.
     */
    public static OperatorAuthenticator fromProcess() {
        DeploymentProfile profile = DeploymentProfile.current();
        boolean redis = RedisConfig.isConfigured();
        OperatorAuthConfig config = OperatorAuthConfig.from(Settings.of(OperatorAuthConfig.COMPONENT), profile,
                AcceptedRisks.current(), redis);
        return from(config, redis ? new RedisClient(RedisConfig.current()) : null, PfInternals::issuer, Clock.systemUTC());
    }

    /** {@link #fromProcess()}'s assembly, given the configuration, the Redis client (or null) and the issuer. */
    static OperatorAuthenticator from(OperatorAuthConfig config, RedisClient redis,
                                      Function<HttpServletRequest, String> issuer, Clock clock) {
        if (!config.usable()) {
            LOG.warn("The operator APIs will answer every request 503: " + config.problem());
        }
        OutboundHttp http = OutboundHttp.builder(AddressPolicy.builder()
                        .trusting(str(config.jwksUrl()), str(config.introspectionEndpoint())).build())
                .tls(TlsTrust.insecureIf(OperatorAuthConfig.INSECURE_TLS, config.insecureTls() && config.usable()))
                .build();
        JwksSource keys = null;
        TokenIntrospector introspector = null;
        if (config.mode() == OperatorAuthConfig.Mode.JWT && config.jwksUrl() != null) {
            keys = new RemoteJwks(http, config.jwksUrl().toString());
        } else if (config.mode() == OperatorAuthConfig.Mode.INTROSPECTION && config.usable()) {
            introspector = TokenIntrospector.builder(http, config.introspectionEndpoint(),
                    ClientAuthentication.clientSecretBasic(config.introspectionClientId(),
                            config.introspectionClientSecret())).build();
        }
        ReplayStore replay = redis != null ? new RedisReplayStore(redis.keyspace(DPOP_NAMESPACE))
                : new InMemoryReplayStore(InMemoryReplayStore.DEFAULT_CAPACITY, clock);
        WindowCounter failed = redis != null ? new RedisWindowCounter(redis, FAILURES_NAMESPACE)
                : new InMemoryWindowCounter(clock);
        WindowCounter changed = redis != null ? new RedisWindowCounter(redis, MUTATIONS_NAMESPACE)
                : new InMemoryWindowCounter(clock);
        return new OperatorAuthenticator(config, keys, introspector, replay, failed, changed, issuer);
    }

    private static String str(Object value) {
        return value == null ? null : value.toString();
    }

    // ---- the decision -----------------------------------------------------------------------------------------------

    /** What the authenticator decided. */
    public sealed interface Decision permits Authorised, Refused {
    }

    /** Let through, as {@code operator}. */
    public record Authorised(Operator operator) implements Decision {
    }

    /**
     * Refused.
     *
     * @param status     400, 401, 403, 429 or 503
     * @param reason     the event's reason: {@code invalid_token}, {@code insufficient_scope}, {@code too_many_failures}, ...
     * @param challenges the {@code WWW-Authenticate} values, in order; none for 429 and 503
     * @param retryAfter seconds, for a 429; null otherwise
     */
    public record Refused(int status, String reason, String description, List<String> challenges, Long retryAfter)
            implements Decision {
        public Refused {
            challenges = List.copyOf(challenges);
        }
    }

    /**
     * Authenticates {@code request} for {@code route} and, when it passes, puts its {@link Operator} in the request
     * attribute {@link #OPERATOR_ATTRIBUTE}. Emits the event either way.
     */
    public Decision authenticate(HttpServletRequest request, OperatorRoute route) {
        Objects.requireNonNull(route, "route");
        String address = request.getRemoteAddr();
        String label = claimedLabel(request.getHeader("X-Federation-Actor"));
        Refused refusal;
        String actor = null;
        try {
            Operator operator = this.decide(request, route, address, label);
            request.setAttribute(OPERATOR_ATTRIBUTE, operator);
            authorised(operator, address);
            return new Authorised(operator);
        } catch (Refusal r) {
            refusal = r.refused;
            actor = r.actor;
        }
        refused(route, refusal, actor, label, address);
        return refusal;
    }

    /**
     * {@link #authenticate}, answering a refusal itself: the status, {@code Cache-Control: no-store}, the challenges,
     * {@code Retry-After} for a 429, and no body. The surface goes on only when this answers true.
     */
    public boolean authorise(HttpServletRequest request, HttpServletResponse response, OperatorRoute route) {
        Decision decision = this.authenticate(request, route);
        if (decision instanceof Refused r) {
            response.setStatus(r.status());
            response.setHeader("Cache-Control", "no-store");
            for (String challenge : r.challenges()) {
                response.addHeader("WWW-Authenticate", challenge);
            }
            if (r.retryAfter() != null) {
                response.setHeader("Retry-After", Long.toString(r.retryAfter()));
            }
            response.setContentLength(0);
            return false;
        }
        return true;
    }

    /** A refusal thrown out of {@link #decide}, with the actor when the token named one. */
    private static final class Refusal extends Exception {
        private static final long serialVersionUID = 1L;
        private final transient Refused refused;
        private final String actor;

        Refusal(Refused refused, String actor) {
            super(refused.reason(), null, false, false);
            this.refused = refused;
            this.actor = actor;
        }
    }

    private Operator decide(HttpServletRequest request, OperatorRoute route, String address, String label)
            throws Refusal {
        if (!this.config.usable()) {
            throw unavailable("not_configured", "the operator APIs are not configured: " + this.config.problem());
        }
        this.checkFailureLimit(address);
        DelegatedTokenValidator.Scheme scheme = null;
        DelegatedTokenValidator.Result result;
        try {
            List<String> authorizations = Collections.list(request.getHeaders("Authorization"));
            if (authorizations.isEmpty()) {
                throw new DelegatedTokenValidator.RsException(null, 401, "no credentials");
            }
            String query = request.getQueryString();
            if (authorizations.size() > 1 || query != null && ACCESS_TOKEN_QUERY.matcher(query).find()) {
                throw new DelegatedTokenValidator.RsException(DelegatedTokenValidator.INVALID_REQUEST, 400,
                        "Multiple methods used to include access token");
            }
            String[] parts = authorizations.get(0).trim().split(" +", 2);
            scheme = scheme(parts[0]);
            if (scheme == null) {
                throw new DelegatedTokenValidator.RsException(null, 401, "unsupported authentication scheme");
            }
            if (parts.length < 2 || !TOKEN68.matcher(parts[1]).matches()) {
                throw new DelegatedTokenValidator.RsException(DelegatedTokenValidator.INVALID_REQUEST, 400,
                        "the credentials are not token68");
            }
            X509Certificate[] certificates = (X509Certificate[]) request.getAttribute(CERTIFICATE_ATTRIBUTE);
            result = this.validator(request).validate(new DelegatedTokenValidator.Presentation(scheme, parts[1],
                    Collections.list(request.getHeaders("DPoP")), request.getMethod(),
                    this.config.baseUrl() + request.getRequestURI(),
                    certificates == null || certificates.length == 0 ? null : certificates[0]));
        } catch (DelegatedTokenValidator.RsException e) {
            throw this.refusedToken(scheme, e, address);
        } catch (IssuerUnavailable e) {
            throw unavailable("issuer_unavailable", "PingFederate's issuer could not be read: " + e.getMessage());
        }
        String actor = actorOf(result);
        if (actor == null) {
            throw this.refusedToken(scheme, new DelegatedTokenValidator.RsException(DelegatedTokenValidator.INVALID_TOKEN,
                    401, "the access token names no subject and no client"), address);
        }
        String binding = result.binding().name().toLowerCase(Locale.ROOT);
        if (result.binding() == DelegatedTokenValidator.Binding.NONE) {
            LOG.warn("An operator request by " + LogSafe.quoted(actor) + " for " + route.name()
                    + " was let through with a token bound to nothing: development only (OIDF_DEPLOYMENT_PROFILE)");
        }
        if (!result.scopes().contains(route.scope())) {
            throw new Refusal(new Refused(403, "insufficient_scope", "the access token lacks the scope " + route.scope(),
                    this.challenges(scheme, "insufficient_scope", "The request requires higher privileges than provided"
                            + " by the access token", route.scope()), null), actor);
        }
        if (route.mutation()) {
            this.checkMutationLimit(actor);
        }
        Object clientId = result.claims().get("client_id");
        return new Operator(actor, clientId instanceof String c ? c : null, result.scopes(), binding, label, route);
    }

    /** The validator for this request's issuer: cheap to build, and PingFederate may give each virtual host its own. */
    private DelegatedTokenValidator validator(HttpServletRequest request) throws IssuerUnavailable {
        String iss;
        try {
            iss = this.issuer.apply(request);
        } catch (RuntimeException | LinkageError e) {
            throw new IssuerUnavailable(e.toString());
        }
        if (iss == null || iss.isEmpty()) {
            throw new IssuerUnavailable("PingFederate answered no issuer");
        }
        DelegatedTokenValidator.Builder b = DelegatedTokenValidator.builder(iss, this.config.audience())
                .replayStore(this.replayStore).mtls(true);
        if (this.introspector != null) {
            b.introspection(this.introspector);
        } else {
            b.keys(this.keys).accessTokenType(accessTokenType(this.config.tokenTyp()));
        }
        if (this.config.profile().isDevelopment()) {
            b.allowUnbound(this.config.profile());
        }
        return b.build();
    }

    /**
     * {@code OIDF_OPERATOR_ACCESS_TOKEN_TYP} as rs-validation's {@link AccessTokenType}: {@code at+jwt} (the default)
     * is RFC 9068's rule, {@code none} a token manager whose "Type Header Value" is blank, anything else exactly that.
     */
    static AccessTokenType accessTokenType(String typ) {
        if (typ == null || typ.isBlank() || "at+jwt".equalsIgnoreCase(typ.strip())) {
            return AccessTokenType.RFC9068;
        }
        return OperatorAuthConfig.NO_TYP.equalsIgnoreCase(typ.strip()) ? AccessTokenType.ABSENT
                : AccessTokenType.exactly(typ.strip());
    }

    private static final class IssuerUnavailable extends Exception {
        private static final long serialVersionUID = 1L;

        IssuerUnavailable(String message) {
            super(message);
        }
    }

    /** The actor: {@code sub}, or {@code client_id} when the token has no subject; null when it has neither. */
    static String actorOf(DelegatedTokenValidator.Result result) {
        if (result.subject() != null && !result.subject().isEmpty()) {
            return result.subject();
        }
        Object clientId = result.claims().get("client_id");
        return clientId instanceof String c && !c.isEmpty() ? c : null;
    }

    /**
     * The refusal for a token the validator refused: a 503 counts nothing, anything else is a failed authentication
     * against the caller's address.
     */
    private Refusal refusedToken(DelegatedTokenValidator.Scheme scheme, DelegatedTokenValidator.RsException e,
                                 String address) {
        if (e.status() == 503) {
            return unavailable("unavailable", e.getMessage());
        }
        try {
            this.failures.hit(failureKey(address), MINUTE);
        } catch (IOException io) {
            return unavailable("rate_limit_unavailable", "the failed-authentication counter could not be written: "
                    + io.getMessage());
        }
        String reason = e.error() != null ? e.error() : "no_credentials";
        return new Refusal(new Refused(e.status(), reason, e.getMessage(),
                this.challenges(e.status() == 400 ? null : scheme, e.error(), e.getMessage(), null), null), null);
    }

    private void checkFailureLimit(String address) throws Refusal {
        WindowCount seen;
        try {
            seen = this.failures.peek(failureKey(address));
        } catch (IOException e) {
            throw unavailable("rate_limit_unavailable", "the failed-authentication counter could not be read: "
                    + e.getMessage());
        }
        if (seen.count() >= this.config.authFailuresPerMinute()) {
            throw new Refusal(new Refused(429, "too_many_failures", "this address has failed authentication "
                    + seen.count() + " times this minute", List.of(), retryAfter(seen.remaining())), null);
        }
    }

    private void checkMutationLimit(String actor) throws Refusal {
        WindowCount seen;
        try {
            seen = this.mutations.hit(digest(actor), MINUTE);
        } catch (IOException e) {
            throw new Refusal(unavailableRefused("rate_limit_unavailable", "the change counter could not be written: "
                    + e.getMessage()), actor);
        }
        if (seen.count() > this.config.mutationsPerMinute()) {
            throw new Refusal(new Refused(429, "too_many_changes", "this operator has made more than "
                    + this.config.mutationsPerMinute() + " changes this minute", List.of(), retryAfter(seen.remaining())),
                    actor);
        }
    }

    private static Refusal unavailable(String reason, String description) {
        return new Refusal(unavailableRefused(reason, description), null);
    }

    private static Refused unavailableRefused(String reason, String description) {
        return new Refused(503, reason, description, List.of(), null);
    }

    /** Whole seconds, rounded up, never less than one: RFC 9110 §10.2.3's delay-seconds. */
    static long retryAfter(Duration remaining) {
        return Math.max(1L, (remaining.toMillis() + 999L) / 1000L);
    }

    /** The failed-authentication counter's key: the address itself, or {@code -} for none. */
    static String failureKey(String address) {
        return address == null || address.isEmpty() ? "-" : address;
    }

    /** base64url(SHA-256(value)): the change counter's key, so an actor's own characters never reach a key. */
    static String digest(String value) {
        try {
            return Base64.getUrlEncoder().withoutPadding().encodeToString(
                    MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    /** The scheme an {@code Authorization} header names; the name is case-insensitive (RFC 9110 §11.1). */
    static DelegatedTokenValidator.Scheme scheme(String name) {
        if ("DPoP".equalsIgnoreCase(name)) {
            return DelegatedTokenValidator.Scheme.DPOP;
        }
        return "Bearer".equalsIgnoreCase(name) ? DelegatedTokenValidator.Scheme.BEARER : null;
    }

    /**
     * The {@code WWW-Authenticate} challenges: {@code DPoP} with the accepted proof algorithms, then {@code Bearer}
     * with the realm. {@code error}, when there is one, goes in the challenge of {@code used}, or in both when
     * {@code used} is null (an ambiguous or malformed request, or none) - RFC 9449 §7.2: "If the mechanism used to
     * attempt authentication could be established unambiguously, then the corresponding challenge SHOULD be used to
     * deliver error information." {@code scope}, for {@code insufficient_scope}, goes with the error (RFC 6750 §3.1:
     * the server "MAY include the "scope" attribute with the scope necessary to access the protected resource").
     */
    List<String> challenges(DelegatedTokenValidator.Scheme used, String error, String description, String scope) {
        String detail = error == null ? null : "error=\"" + error + "\", error_description=\"" + headerSafe(description)
                + "\"" + (scope == null ? "" : ", scope=\"" + scope + "\"");
        StringBuilder dpop = new StringBuilder("DPoP algs=\"")
                .append(String.join(" ", new TreeSet<>(DelegatedTokenValidator.DEFAULT_ALGORITHMS))).append('"');
        StringBuilder bearer = new StringBuilder("Bearer realm=\"").append(headerSafe(this.config.baseUrl())).append('"');
        if (detail != null && used != DelegatedTokenValidator.Scheme.BEARER) {
            dpop.append(", ").append(detail);
        }
        if (detail != null && used != DelegatedTokenValidator.Scheme.DPOP) {
            bearer.append(", ").append(detail);
        }
        List<String> out = new ArrayList<>(2);
        out.add(dpop.toString());
        out.add(bearer.toString());
        return out;
    }

    /**
     * Text as an {@code error_description} or {@code realm} may carry it. RFC 6750 §3: "Values for the "error" and
     * "error_description" attributes ... MUST NOT include characters outside the set %x20-21 / %x23-5B / %x5D-7E."
     * Anything else becomes '?', and the text is cut at {@value #DESCRIPTION_LIMIT} characters, because some of it
     * comes from the token.
     */
    static String headerSafe(String text) {
        String value = text == null ? "" : text;
        StringBuilder out = new StringBuilder(Math.min(value.length(), DESCRIPTION_LIMIT));
        for (int i = 0; i < value.length() && i < DESCRIPTION_LIMIT; i++) {
            char c = value.charAt(i);
            out.append(c >= 0x20 && c <= 0x7e && c != '"' && c != '\\' ? c : '?');
        }
        return out.toString();
    }

    /** {@code X-Federation-Actor} as a claimed label: at most {@value #CLAIMED_LABEL_LIMIT} characters, log-safe. */
    static String claimedLabel(String header) {
        if (header == null || header.isBlank()) {
            return null;
        }
        String cut = header.length() > CLAIMED_LABEL_LIMIT ? header.substring(0, CLAIMED_LABEL_LIMIT) : header;
        return LogSafe.value(cut.strip());
    }

    // ---- events -----------------------------------------------------------------------------------------------------

    private static void authorised(Operator operator, String address) {
        Events.event(COMPONENT, AUTHORISED).audit().subject(operator.actor())
                .field("route", operator.route().name()).field("scope", operator.route().scope())
                .field("actor", operator.actor()).field("claimed_label", operator.claimedLabel())
                .field("client_address", address).field("binding", operator.binding()).emit();
    }

    private static void refused(OperatorRoute route, Refused refusal, String actor, String label, String address) {
        Events.event(COMPONENT, REFUSED).audit().failure(refusal.reason()).subject(actor)
                .description(refusal.description())
                .field("route", route.name()).field("scope", route.scope())
                .field("actor", actor).field("claimed_label", label)
                .field("client_address", address).field("status", refusal.status()).emit();
    }
}
