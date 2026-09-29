/*
 * OAuth 2.0 Token Introspection (RFC 7662), over platform's outbound HTTP.
 */
package com.pingidentity.ps.oidf.platform.auth;

import com.pingidentity.ps.oidf.platform.http.Deadline;
import com.pingidentity.ps.oidf.platform.http.OutboundHttp;
import com.pingidentity.ps.oidf.platform.http.OutboundHttpException;
import com.pingidentity.ps.oidf.platform.http.OutboundRequest;
import com.pingidentity.ps.oidf.platform.http.OutboundResponse;
import com.pingidentity.ps.oidf.platform.json.Json;
import java.io.IOException;
import java.math.BigDecimal;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Asks an authorisation server about an access token (RFC 7662) and reads the answer strictly (plan item S8a).
 *
 * <p>RFC 7662 §2.1: the protected resource sends the token as {@code token}, form-encoded, in a POST, and
 * authenticates itself as the server requires; here the caller supplies that authentication
 * ({@link ClientAuthentication}: {@code client_secret_basic} or {@code private_key_jwt}), because who the resource is
 * belongs to the caller's configuration, not to platform.
 *
 * <p>Every call is bounded: 1 s to connect (the TLS handshake included), 2.5 s in all, and a response body of at most
 * 64 KiB, through {@link OutboundHttp} and whatever {@link com.pingidentity.ps.oidf.platform.http.AddressPolicy} the
 * caller built it with. An introspection endpoint is normally the resource's own authorisation server on a private
 * address, so the caller's policy names it with {@code trusting(...)}.
 *
 * <p>The answer is an {@link Introspection}. RFC 7662 §2.2: {@code active} is "REQUIRED. Boolean indicator of whether
 * or not the presented token is currently active"; a token that is not active is a value ({@link Introspection#active()}
 * false, nothing else read), and the caller refuses the request with 401. No answer - the server could not be
 * reached, answered with a status other than 200, or with a body that is not a JSON object whose members have the
 * types RFC 7662 §2.2 gives them - is an {@link IntrospectionException}, which the caller maps to 503: the token is
 * neither accepted nor called inactive when the server has not said which it is.
 *
 * <p>The members read are the ones RFC 7662 §2.2 lists that a resource decides on - {@code scope}, {@code client_id},
 * {@code sub}, {@code aud}, {@code iss}, {@code exp}, {@code iat}, {@code nbf}, {@code token_type} - and {@code cnf}.
 * RFC 7662 itself defines no {@code cnf}; §2.2 lets an implementation "extend this structure with their own
 * service-specific response names as top-level members", and RFC 9449 §6.2 does so for DPoP: "the hash of the public
 * key to which the token is bound is conveyed to the protected resource as metainformation in a token introspection
 * response. The hash is conveyed using the same cnf content with jkt member structure as the JWK Thumbprint
 * confirmation method ... as a top-level member of the introspection response JSON", and "If the token_type member is
 * included in the introspection response, it MUST contain the value DPoP." RFC 8705 §3.2 conveys {@code x5t#S256} the
 * same way. PingFederate 13.1.3 returns both {@code cnf.jkt} and {@code token_type} {@code DPoP} for a DPoP-bound
 * token, JWT and reference alike (seen on the rig on 2026-09-29, finding U-0030).
 *
 * <p>RFC 7662 §2.2: "The response MAY be cached by the protected resource ... but at the cost of liveness of the
 * information". An active answer is kept for at most {@link #MAX_CACHE} - and never past the token's own {@code exp},
 * nor at all when it carries none - keyed by the token's SHA-256, so a revoked token keeps working for at most that
 * long on a node that has just asked about it. An inactive answer is not kept. The cache is off unless the caller
 * turns it on.
 */
public final class TokenIntrospector {

    /** How long connecting, TLS included, may take. */
    public static final Duration CONNECT_TIMEOUT = Duration.ofSeconds(1);
    /** How long the whole exchange may take. */
    public static final Duration TOTAL_TIMEOUT = Duration.ofMillis(2500);
    /** The largest response body read. */
    public static final long MAX_BODY_BYTES = 64L * 1024L;
    /** The longest an active answer is kept. */
    public static final Duration MAX_CACHE = Duration.ofSeconds(30);
    /** The most answers the cache holds; past it, expired entries are swept and, if none were, nothing new is kept. */
    public static final int CACHE_CAPACITY = 10_000;

    private final OutboundHttp http;
    private final URI endpoint;
    private final ClientAuthentication authentication;
    private final Duration cacheFor;
    private final Clock clock;
    private final int capacity;
    private final Map<String, Cached> cache = new LinkedHashMap<>();

    private record Cached(Introspection answer, long untilMillis) {
    }

    private TokenIntrospector(Builder b) {
        this.http = b.http;
        this.endpoint = b.endpoint;
        this.authentication = b.authentication;
        this.cacheFor = b.cacheFor;
        this.clock = b.clock;
        this.capacity = b.capacity;
    }

    /** An introspector asking {@code endpoint} through {@code http}, authenticating as {@code authentication}. */
    public static Builder builder(OutboundHttp http, URI endpoint, ClientAuthentication authentication) {
        return new Builder(http, endpoint, authentication);
    }

    /** The endpoint this introspector asks. */
    public URI endpoint() {
        return this.endpoint;
    }

    /**
     * What the authorisation server says about {@code token}.
     *
     * @throws IntrospectionException when there is no usable answer: the caller refuses the request with 503
     */
    public Introspection introspect(String token) throws IntrospectionException {
        if (token == null || token.isEmpty()) {
            return Introspection.INACTIVE;
        }
        String key = cacheKey(token);
        Introspection cached = this.cached(key);
        if (cached != null) {
            return cached;
        }
        Introspection answer = this.ask(token);
        this.remember(key, answer);
        return answer;
    }

    private Introspection ask(String token) throws IntrospectionException {
        ClientAuthentication.Credentials credentials;
        try {
            credentials = Objects.requireNonNull(this.authentication.credentials(this.endpoint), "credentials");
        } catch (IOException | RuntimeException e) {
            throw new IntrospectionException("the introspection client's credentials could not be made: "
                    + e.getMessage(), e);
        }
        Map<String, String> form = new LinkedHashMap<>();
        form.put("token", token);
        form.put("token_type_hint", "access_token");
        form.putAll(credentials.parameters());
        OutboundRequest.Builder request = OutboundRequest.builder(OutboundRequest.Method.POST, this.endpoint)
                .header("Accept", "application/json")
                .connectTimeout(CONNECT_TIMEOUT)
                .headerTimeout(TOTAL_TIMEOUT)
                .maxBodyBytes(MAX_BODY_BYTES);
        for (Map.Entry<String, String> header : credentials.headers().entrySet()) {
            request.header(header.getKey(), header.getValue());
        }
        request.body("application/x-www-form-urlencoded", formEncode(form));
        OutboundResponse response;
        try {
            response = this.http.send(request.build(), Deadline.after(TOTAL_TIMEOUT));
        } catch (OutboundHttpException e) {
            throw new IntrospectionException("the introspection endpoint did not answer (" + e.reason() + "): "
                    + e.getMessage(), e);
        }
        if (response.status() != 200) {
            // RFC 7662 §2.3: a failed client authentication is 401; any status but 200 is no answer about the token.
            throw new IntrospectionException("the introspection endpoint answered HTTP " + response.status());
        }
        return parse(response.bodyText());
    }

    /**
     * The answer {@code body} holds, read strictly.
     *
     * @throws IntrospectionException when it is not a JSON object, {@code active} is not a boolean, or an active
     *                                answer's member does not have the type RFC 7662 §2.2 (or RFC 9449 §6.2, for
     *                                {@code cnf}) gives it
     */
    static Introspection parse(String body) throws IntrospectionException {
        Object parsed;
        try {
            parsed = Json.parse(body);
        } catch (IllegalArgumentException e) {
            throw new IntrospectionException("the introspection response is not JSON: " + e.getMessage(), e);
        }
        if (!(parsed instanceof Map<?, ?> members)) {
            throw new IntrospectionException("the introspection response is not a JSON object");
        }
        Object active = members.get("active");
        if (!(active instanceof Boolean flag)) {
            throw new IntrospectionException("the introspection response's active member is not a boolean");
        }
        if (!flag) {
            return Introspection.INACTIVE;
        }
        String scope = string(members, "scope");
        List<String> scopes = new ArrayList<>();
        if (scope != null) {
            for (String part : scope.split(" ")) {
                if (!part.isEmpty()) {
                    scopes.add(part);
                }
            }
        }
        Map<?, ?> cnf = object(members, "cnf");
        Map<String, Object> copy = new LinkedHashMap<>();
        members.forEach((name, value) -> copy.put((String) name, value));
        return new Introspection(true, scopes, string(members, "client_id"), string(members, "sub"),
                audience(members), string(members, "iss"), seconds(members, "exp"), seconds(members, "iat"),
                seconds(members, "nbf"), string(members, "token_type"),
                cnf == null ? null : string(cnf, "jkt"), cnf == null ? null : string(cnf, "x5t#S256"), copy);
    }

    private static String string(Map<?, ?> members, String name) throws IntrospectionException {
        Object value = members.get(name);
        if (value == null) {
            return null;
        }
        if (!(value instanceof String text)) {
            throw new IntrospectionException("the introspection response's " + name + " member is not a string");
        }
        return text;
    }

    private static Map<?, ?> object(Map<?, ?> members, String name) throws IntrospectionException {
        Object value = members.get(name);
        if (value == null) {
            return null;
        }
        if (!(value instanceof Map<?, ?> map)) {
            throw new IntrospectionException("the introspection response's " + name + " member is not an object");
        }
        return map;
    }

    /** RFC 7662 §2.2 {@code aud}: "Service-specific string identifier or list of string identifiers". */
    private static List<String> audience(Map<?, ?> members) throws IntrospectionException {
        Object value = members.get("aud");
        if (value == null) {
            return List.of();
        }
        if (value instanceof String one) {
            return List.of(one);
        }
        if (value instanceof List<?> many) {
            List<String> out = new ArrayList<>(many.size());
            for (Object item : many) {
                if (!(item instanceof String text)) {
                    throw new IntrospectionException("the introspection response's aud holds a member that is not a string");
                }
                out.add(text);
            }
            return List.copyOf(out);
        }
        throw new IntrospectionException("the introspection response's aud member is neither a string nor a list");
    }

    /** RFC 7662 §2.2: {@code exp}, {@code iat} and {@code nbf} are each an "Integer timestamp". */
    private static Long seconds(Map<?, ?> members, String name) throws IntrospectionException {
        Object value = members.get(name);
        if (value == null) {
            return null;
        }
        try {
            return ((BigDecimal) value).longValueExact();
        } catch (ClassCastException | ArithmeticException e) {
            throw new IntrospectionException("the introspection response's " + name + " member is not an integer");
        }
    }

    // ---- the cache ----------------------------------------------------------------------------------------------

    private synchronized Introspection cached(String key) {
        Cached entry = this.cache.get(key);
        if (entry == null) {
            return null;
        }
        if (entry.untilMillis() <= this.clock.millis()) {
            this.cache.remove(key);
            return null;
        }
        return entry.answer();
    }

    private synchronized void remember(String key, Introspection answer) {
        long until = cacheUntil(answer, this.clock.millis(), this.cacheFor);
        if (until <= this.clock.millis()) {
            return;
        }
        if (this.cache.size() >= this.capacity) {
            long now = this.clock.millis();
            for (Iterator<Cached> it = this.cache.values().iterator(); it.hasNext();) {
                if (it.next().untilMillis() <= now) {
                    it.remove();
                }
            }
            if (this.cache.size() >= this.capacity) {
                return;
            }
        }
        this.cache.put(key, new Cached(answer, until));
    }

    /**
     * Until when an answer may be kept: never for an inactive answer or one without {@code exp}; otherwise the sooner
     * of {@code cacheFor} from now and the token's {@code exp}.
     */
    static long cacheUntil(Introspection answer, long nowMillis, Duration cacheFor) {
        if (!answer.active() || answer.exp() == null || cacheFor.isZero()) {
            return Long.MIN_VALUE;
        }
        return Math.min(nowMillis + cacheFor.toMillis(), Math.multiplyExact(answer.exp(), 1000L));
    }

    /** base64url(SHA-256(token)): the token itself is never a key in this JVM's heap longer than the call. */
    static String cacheKey(String token) {
        try {
            return Base64.getUrlEncoder().withoutPadding().encodeToString(
                    MessageDigest.getInstance("SHA-256").digest(token.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    /** How many answers the cache holds, expired ones included until they are next looked at or swept. */
    public synchronized int cached() {
        return this.cache.size();
    }

    static String formEncode(Map<String, String> form) {
        StringBuilder out = new StringBuilder();
        for (Map.Entry<String, String> e : form.entrySet()) {
            if (out.length() > 0) {
                out.append('&');
            }
            out.append(URLEncoder.encode(e.getKey(), StandardCharsets.UTF_8)).append('=')
                    .append(URLEncoder.encode(e.getValue(), StandardCharsets.UTF_8));
        }
        return out.toString();
    }

    // ---- building -----------------------------------------------------------------------------------------------

    /** Builds a {@link TokenIntrospector}. */
    public static final class Builder {
        private final OutboundHttp http;
        private final URI endpoint;
        private final ClientAuthentication authentication;
        private Duration cacheFor = Duration.ZERO;
        private Clock clock = Clock.systemUTC();
        private int capacity = CACHE_CAPACITY;

        private Builder(OutboundHttp http, URI endpoint, ClientAuthentication authentication) {
            this.http = Objects.requireNonNull(http, "http");
            this.endpoint = Objects.requireNonNull(endpoint, "endpoint");
            this.authentication = Objects.requireNonNull(authentication, "authentication");
        }

        /** Keeps an active answer for up to {@code duration}, never more than {@link #MAX_CACHE}; zero, the default, is off. */
        public Builder cacheFor(Duration duration) {
            if (duration.isNegative() || duration.compareTo(MAX_CACHE) > 0) {
                throw new IllegalArgumentException("an introspection answer is kept for 0 to 30 seconds, not " + duration);
            }
            this.cacheFor = duration;
            return this;
        }

        /** The clock the cache reads; the system's by default. */
        public Builder clock(Clock value) {
            this.clock = Objects.requireNonNull(value, "clock");
            return this;
        }

        /** Tests: a smaller cache. */
        Builder capacity(int value) {
            this.capacity = value;
            return this;
        }

        public TokenIntrospector build() {
            return new TokenIntrospector(this);
        }
    }
}
