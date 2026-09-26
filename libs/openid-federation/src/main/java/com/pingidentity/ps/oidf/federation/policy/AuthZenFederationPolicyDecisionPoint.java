/*
 * An external policy decision point, asked over AuthZEN 1.0.
 */
package com.pingidentity.ps.oidf.federation.policy;

import com.pingidentity.ps.oidf.jose.HttpGetClient;
import com.pingidentity.ps.oidf.jose.HttpPostClient;
import java.net.URI;
import java.time.Clock;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jose4j.json.JsonUtil;

/**
 * Asks an AuthZEN 1.0 Access Evaluation endpoint (§6) - PingAuthorize, or any other PDP that speaks it.
 *
 * <p>The request is POSTed as JSON with {@code X-Request-ID} set to PingFederate's tracking id (§10.1.3). Only a 200 whose
 * body carries a boolean {@code decision} is a decision; any other status, or a body that is not one, is no decision at
 * all (§10.1.2: HTTP errors "are unrelated to the outcome of an authorization decision"). A permit's {@code context} may
 * narrow what the federation allows: {@code scope} (a string or an array), {@code grant_types}, {@code response_types},
 * {@code registration_ttl_seconds} and {@code require_trust_mark}; {@code reason_admin} and {@code reason_user} carry its
 * reasons. Any other member is listed as ignored - or, when the deployment says so, the permit is refused, which §5.5
 * allows ("If the PEP does not understand information in the context response object, the PEP MAY choose to reject the
 * decision").
 */
public final class AuthZenFederationPolicyDecisionPoint implements FederationPolicyDecisionPoint {
    private static final Log LOGGER = LogFactory.getLog(AuthZenFederationPolicyDecisionPoint.class);
    private static final Set<String> UNDERSTOOD = Set.of("scope", "grant_types", "response_types", "registration_ttl_seconds",
            "require_trust_mark", "reason_admin", "reason_user");

    /** Where the Access Evaluation endpoint is. */
    @FunctionalInterface
    public interface Endpoint {
        URI resolve() throws PolicyDecisionException;
    }

    private final HttpPostClient http;
    private final Endpoint endpoint;
    private final Map<String, String> authHeaders;
    private final boolean rejectUnknownContext;
    private final Clock clock;

    /**
     * @param authHeaders          headers that authenticate this deployment to the PDP ({@code Authorization: Bearer ...},
     *                             or a shared-secret header)
     * @param rejectUnknownContext whether a permit whose context this deployment does not understand is refused
     */
    public AuthZenFederationPolicyDecisionPoint(HttpPostClient http, Endpoint endpoint, Map<String, String> authHeaders,
                                                boolean rejectUnknownContext, Clock clock) {
        this.http = Objects.requireNonNull(http, "http");
        this.endpoint = Objects.requireNonNull(endpoint, "endpoint");
        this.authHeaders = authHeaders == null ? Map.of() : Map.copyOf(authHeaders);
        this.rejectUnknownContext = rejectUnknownContext;
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    /** The evaluation endpoint of the PDP at {@code baseUrl}: its default path (§10.1, Table 1). */
    public static Endpoint at(String baseUrl) {
        URI endpoint = URI.create(stripSlash(baseUrl) + "/access/v1/evaluation");
        return () -> endpoint;
    }

    /** A configured evaluation endpoint, used as it is. */
    public static Endpoint exactly(String evaluationUrl) {
        URI endpoint = URI.create(evaluationUrl);
        return () -> endpoint;
    }

    /**
     * The evaluation endpoint the PDP identified by {@code pdp} publishes in its metadata (§9.2), read on first use and
     * kept once read; a metadata document naming another PDP is not used (§9.2.3).
     */
    public static Endpoint discovered(HttpGetClient http, String pdp) {
        Objects.requireNonNull(http, "http");
        return new Endpoint() {
            private volatile URI found;

            @Override
            public URI resolve() throws PolicyDecisionException {
                URI local = this.found;
                if (local == null) {
                    local = discover(http, pdp);
                    this.found = local;
                }
                return local;
            }
        };
    }

    static URI discover(HttpGetClient http, String pdp) throws PolicyDecisionException {
        URI identifier = URI.create(pdp);
        if (identifier.getRawAuthority() == null) {
            throw new PolicyDecisionException("the policy decision point's identifier is not a URL with a host (AuthZEN §9.1)");
        }
        String metadataUrl = identifier.getScheme() + "://" + identifier.getRawAuthority() + "/.well-known/authzen-configuration"
                + stripSlash(identifier.getRawPath());
        Map<String, Object> metadata;
        try {
            metadata = JsonUtil.parseJson(http.get(metadataUrl, "application/json"));
        } catch (Exception e) {
            throw new PolicyDecisionException("the policy decision point's metadata could not be read", e);
        }
        if (!pdp.equals(metadata.get("policy_decision_point"))) {
            throw new PolicyDecisionException("the policy decision point's metadata names another decision point (AuthZEN §9.2.3)");
        }
        if (!(metadata.get("access_evaluation_endpoint") instanceof String evaluation) || !evaluation.startsWith("https://")) {
            throw new PolicyDecisionException("the policy decision point publishes no https access_evaluation_endpoint");
        }
        return URI.create(evaluation);
    }

    private static String stripSlash(String value) {
        return value.endsWith("/") ? value.substring(0, value.length() - 1) : value;
    }

    @Override
    public PolicyDecision decide(PolicyDecisionRequest request) throws PolicyDecisionException {
        URI url = this.endpoint.resolve();
        Map<String, String> headers = new LinkedHashMap<>(this.authHeaders);
        if (request.requestId() != null) {
            headers.put("X-Request-ID", request.requestId());
        }
        long started = this.clock.millis();
        HttpPostClient.Response response;
        try {
            response = this.http.post(url.toString(), "application/json", JsonUtil.toJson(request.toAuthZen()), headers, "application/json");
        } catch (Exception e) {
            throw new PolicyDecisionException("the policy decision point could not be reached", e);
        }
        long latency = this.clock.millis() - started;
        if (response.status() != 200) {
            throw new PolicyDecisionException("the policy decision point answered " + response.status() + ", which is no decision (AuthZEN §10.1.2)");
        }
        String echoed = response.header("X-Request-ID").orElse(null);
        if (request.requestId() != null && !request.requestId().equals(echoed)) {
            LOGGER.warn("The policy decision point did not echo X-Request-ID " + request.requestId() + " (AuthZEN §10.1.3)");
        }
        Map<String, Object> body;
        try {
            body = JsonUtil.parseJson(response.body());
        } catch (Exception e) {
            throw new PolicyDecisionException("the policy decision point's answer is not JSON");
        }
        if (!(body.get("decision") instanceof Boolean permitted)) {
            throw new PolicyDecisionException("the policy decision point's answer has no boolean decision (AuthZEN §5.5)");
        }
        Map<?, ?> context = body.get("context") instanceof Map<?, ?> c ? c : Map.of();
        Set<String> ignored = new LinkedHashSet<>();
        for (Object key : context.keySet()) {
            if (!UNDERSTOOD.contains(String.valueOf(key))) {
                ignored.add(String.valueOf(key));
            }
        }
        String reasonAdmin = reason(context.get("reason_admin"));
        String reasonUser = reason(context.get("reason_user"));
        if (!permitted) {
            return new PolicyDecision(false, NarrowingObligations.NONE, reasonAdmin, reasonUser, echoed, latency, ignored);
        }
        if (this.rejectUnknownContext && !ignored.isEmpty()) {
            return new PolicyDecision(false, NarrowingObligations.NONE, "the permit carries context this deployment does not understand: "
                    + ignored + " (AuthZEN §5.5)", null, echoed, latency, ignored);
        }
        return new PolicyDecision(true, obligations(context), reasonAdmin, reasonUser, echoed, latency, ignored);
    }

    /** A permit's narrowing context; a member of the wrong shape is no decision, not a looser one. */
    private static NarrowingObligations obligations(Map<?, ?> context) throws PolicyDecisionException {
        Object ttl = context.get("registration_ttl_seconds");
        if (ttl != null && !(ttl instanceof Number n && n.longValue() >= 0 && n.doubleValue() == n.longValue())) {
            throw new PolicyDecisionException("the permit's registration_ttl_seconds is not a whole number of seconds");
        }
        Object scope = context.get("scope");
        return new NarrowingObligations(scope instanceof String s ? scopes(s) : strings(scope, "scope"),
                strings(context.get("grant_types"), "grant_types"), strings(context.get("response_types"), "response_types"),
                ttl == null ? null : ((Number) ttl).longValue(),
                context.get("require_trust_mark") instanceof String mark ? Set.of(mark) : strings(context.get("require_trust_mark"), "require_trust_mark"));
    }

    /** A space-separated scope string (RFC 6749 §3.3) as a set; an empty one allows no scope at all. */
    private static Set<String> scopes(String scope) {
        Set<String> out = new LinkedHashSet<>();
        for (String token : scope.trim().split("\\s+")) {
            if (!token.isEmpty()) {
                out.add(token);
            }
        }
        return out;
    }

    private static Set<String> strings(Object value, String name) throws PolicyDecisionException {
        if (value == null) {
            return null;
        }
        if (!(value instanceof List<?> list) || !list.stream().allMatch(v -> v instanceof String)) {
            throw new PolicyDecisionException("the permit's " + name + " is not a list of strings");
        }
        Set<String> out = new LinkedHashSet<>();
        list.forEach(v -> out.add((String) v));
        return out;
    }

    /** A reason as the PDP gave it: a string, or an object such as {@code {"403": "..."}} as in the §5.5.2.1 example, flattened. */
    private static String reason(Object value) {
        if (value == null) {
            return null;
        }
        return value instanceof String s ? s : JsonUtil.toJson(value instanceof Map<?, ?> m ? castMap(m) : Map.of("reason", String.valueOf(value)));
    }

    @SuppressWarnings("unchecked")
    private static Map<String, ?> castMap(Map<?, ?> map) {
        return (Map<String, ?>) map;
    }
}
