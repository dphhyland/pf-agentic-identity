/*
 * One question for a policy decision point.
 */
package com.pingidentity.ps.oidf.federation.policy;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;

/**
 * May the federation entity {@code subjectId} do what {@code point} names to {@code resourceType}/{@code resourceId}, in
 * this context? Rendered as an AuthZEN 1.0 Access Evaluation request (§6.1): the subject is always a
 * {@code federation_entity} - the entity the request is about, never a user - and the action is the decision point's.
 *
 * @param point              what is being decided
 * @param subjectId          the federation entity's Entity Identifier
 * @param subjectProperties  what is known of it: its Entity Types, its verified Trust Marks, the anchor its chain reached
 * @param resourceType       what it acts on: {@code openid_provider}, {@code hosted_entity}
 * @param resourceId         which one
 * @param actionProperties   how: the endpoint a registration came through
 * @param context            the rest - what it asks for, when its chain expires; a {@code request} member holds what is
 *                           particular to this one request, and is left out when decisions are cached
 * @param requestId          the {@code X-Request-ID} to send, PingFederate's tracking id; may be null
 */
public record PolicyDecisionRequest(DecisionPoint point, String subjectId, Map<String, Object> subjectProperties, String resourceType,
                                    String resourceId, Map<String, Object> actionProperties, Map<String, Object> context, String requestId) {
    /** The context member that belongs to one request only. */
    public static final String REQUEST_CONTEXT = "request";

    public PolicyDecisionRequest {
        Objects.requireNonNull(point, "point");
        Objects.requireNonNull(subjectId, "subjectId");
        Objects.requireNonNull(resourceType, "resourceType");
        Objects.requireNonNull(resourceId, "resourceId");
        subjectProperties = sorted(subjectProperties);
        actionProperties = sorted(actionProperties);
        context = sorted(context);
    }

    /** A copy in key order, so a request renders - and is cached - the same however it was put together. */
    private static Map<String, Object> sorted(Map<String, Object> map) {
        return map == null ? Map.of() : Collections.unmodifiableMap(new TreeMap<>(map));
    }

    /** The AuthZEN §6.1 request body. */
    public Map<String, Object> toAuthZen() {
        return this.body(true);
    }

    /** What a cached decision is keyed on: the request, less what is particular to this one. */
    public Map<String, Object> cacheKey() {
        return this.body(false);
    }

    private Map<String, Object> body(boolean withRequestContext) {
        Map<String, Object> subject = new LinkedHashMap<>();
        subject.put("type", "federation_entity");
        subject.put("id", this.subjectId);
        if (!this.subjectProperties.isEmpty()) {
            subject.put("properties", this.subjectProperties);
        }
        Map<String, Object> action = new LinkedHashMap<>();
        action.put("name", this.point.action());
        if (!this.actionProperties.isEmpty()) {
            action.put("properties", this.actionProperties);
        }
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("subject", subject);
        body.put("action", action);
        body.put("resource", Map.of("type", this.resourceType, "id", this.resourceId));
        Map<String, Object> context = new LinkedHashMap<>(this.context);
        if (!withRequestContext) {
            context.remove(REQUEST_CONTEXT);
        }
        if (!context.isEmpty()) {
            body.put("context", context);
        }
        return body;
    }
}
