/*
 * The policy decision a token waits for.
 */
package com.pingidentity.ps.oidf.servlet.clientregistration.utils;

import com.pingidentity.ps.oidf.federation.event.FederationEvents;
import com.pingidentity.ps.oidf.federation.policy.DecisionPoint;
import com.pingidentity.ps.oidf.federation.policy.FederationPolicyDecisionPoint;
import com.pingidentity.ps.oidf.federation.policy.NarrowingObligations;
import com.pingidentity.ps.oidf.federation.policy.PolicyDecision;
import com.pingidentity.ps.oidf.federation.policy.PolicyDecisionException;
import com.pingidentity.ps.oidf.federation.policy.PolicyDecisionRequest;
import com.pingidentity.ps.oidf.pf.FederationRuntimeConfig.PdpSettings;
import com.pingidentity.ps.oidf.pf.PfTracking;
import jakarta.servlet.http.HttpServletRequest;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.sourceid.saml20.adapter.attribute.AttributeValue;

/**
 * Asks whoever decides federation requests - when {@code OIDF_PDP_DECISION_POINTS} names {@code token_issuance} - whether a
 * client may have the token PingFederate is about to issue. It runs inside an OGNL issuance criterion, which can only say
 * yes or no, so a permit's obligations are checks here, not changes: every scope the token would carry must be among the
 * permit's {@code scope}, and the request's grant type among its {@code grant_types}. A {@code require_trust_mark} cannot
 * be verified at issuance, so it refuses the token; {@code registration_ttl_seconds} and {@code response_types} say
 * nothing about a token and are ignored.
 *
 * <p>What the PDP hears: the client, and the anchor and Entity Type it was registered through; the grant type and how the
 * client authenticated; the scopes and resources the token would carry and the client's address - the address is part of
 * what a cached decision is kept under; and PingFederate's tracking id.
 */
final class TokenIssuancePolicy {
    /** The criteria keys PingFederate gives an access token mapping (its {@code SourceContextType}). */
    static final String SCOPES = "context.OAuthScopes";
    static final String RESOURCES = "context.OAuthResources";
    static final String CLIENT_IP = "context.ClientIp";
    static final String CLIENT_AUTHN_TYPE = "context.ClientAuthnType";
    /** Where registration recorded the anchor and Entity Type ({@code FederationClientParams}). */
    static final String TRUST_ANCHOR = "extproperties.federation_trust_anchor";
    static final String ENTITY_TYPE = "extproperties.federation_entity_type";

    private TokenIssuancePolicy() {
    }

    /**
     * Whether {@code clientId} may have this token: true when nobody decides tokens, or the decision point permits and the
     * token meets what the permit requires; false when it refuses, or gives no decision and the deployment does not fail
     * open.
     */
    static boolean permits(Map<?, ?> criteria, String clientId, String opIssuer, HttpServletRequest request, FederationPolicyDecisionPoint pdp,
                           PdpSettings settings) {
        if (pdp == null) {
            return true;
        }
        List<String> scopes = values(criteria, SCOPES);
        String grantType = request.getParameter("grant_type");
        PolicyDecision decision;
        try {
            decision = pdp.decide(request(criteria, clientId, opIssuer, scopes, grantType));
        } catch (PolicyDecisionException e) {
            FederationEvents.event(FederationEvents.PDP_CONSULTED).failure("no_decision").subject(clientId).role("OP").audit()
                    .field("action", DecisionPoint.TOKEN_ISSUANCE.action()).description(e.getMessage()).emit();
            if (settings.failOpen()) {
                FederationEvents.event(FederationEvents.PDP_FAIL_OPEN).failure("no_decision").subject(clientId).role("OP").audit()
                        .field("action", DecisionPoint.TOKEN_ISSUANCE.action())
                        .description("issued without a policy decision: OIDF_PDP_FAIL_OPEN=true").emit();
                return true;
            }
            return refused(clientId, "no_decision", null, "the policy decision this token needs could not be obtained");
        }
        FederationEvents.event(FederationEvents.PDP_CONSULTED).subject(clientId).role("OP").audit()
                .field("action", DecisionPoint.TOKEN_ISSUANCE.action()).field("decision", decision.permitted() ? "permit" : "deny")
                .field("latency_ms", decision.latencyMs()).field("pdp_request_id", decision.pdpRequestId())
                .field("ignored_context", decision.ignoredContextKeys().isEmpty() ? null : decision.ignoredContextKeys())
                .description(decision.reasonAdmin()).emit();
        if (!decision.permitted()) {
            return refused(clientId, "policy_denied", null, "the policy decision point refused the token");
        }
        String unmet = unmet(decision.obligations(), scopes, grantType);
        if (unmet != null) {
            return refused(clientId, "obligation_unmet", unmet, "the token does not meet what the permit requires");
        }
        return true;
    }

    /** The first of a permit's obligations this token does not meet, by name; null when it meets them all. */
    static String unmet(NarrowingObligations obligations, List<String> scopes, String grantType) {
        if (obligations.scopes() != null && !obligations.scopes().containsAll(scopes)) {
            return "scope";
        }
        if (obligations.grantTypes() != null && (grantType == null || !obligations.grantTypes().contains(grantType))) {
            return "grant_types";
        }
        return obligations.requiredTrustMarks().isEmpty() ? null : "require_trust_mark";
    }

    private static boolean refused(String clientId, String reason, String obligation, String description) {
        FederationEvents.event(FederationEvents.TOKEN_REFUSED).failure(reason).subject(clientId).role("OP").audit()
                .field("obligation", obligation).description(description).emit();
        return false;
    }

    static PolicyDecisionRequest request(Map<?, ?> criteria, String clientId, String opIssuer, List<String> scopes, String grantType) {
        Map<String, Object> subject = new LinkedHashMap<>();
        putIfPresent(subject, "trust_anchor", value(criteria, TRUST_ANCHOR));
        putIfPresent(subject, "entity_type", value(criteria, ENTITY_TYPE));
        Map<String, Object> action = new LinkedHashMap<>();
        putIfPresent(action, "grant_type", grantType);
        putIfPresent(action, "client_authn_type", value(criteria, CLIENT_AUTHN_TYPE));
        Map<String, Object> context = new LinkedHashMap<>();
        context.put("scope", scopes);
        List<String> resources = values(criteria, RESOURCES);
        if (!resources.isEmpty()) {
            context.put("resources", resources);
        }
        putIfPresent(context, "client_ip", value(criteria, CLIENT_IP));
        String trackingId = PfTracking.trackingId();
        if (trackingId != null) {
            context.put(PolicyDecisionRequest.REQUEST_CONTEXT, Map.of("tracking_id", trackingId));
        }
        return new PolicyDecisionRequest(DecisionPoint.TOKEN_ISSUANCE, clientId, subject, "openid_provider", opIssuer, action, context,
                trackingId);
    }

    /**
     * A criteria value's words: each of its values split on white space, so one {@code "read write"} and two values
     * {@code read}, {@code write} read the same. None when the key is absent or holds no attribute.
     */
    static List<String> values(Map<?, ?> criteria, String key) {
        List<String> words = new ArrayList<>();
        if (criteria.get(key) instanceof AttributeValue attribute) {
            for (String value : attribute.getValuesAsCollection()) {
                for (String word : String.valueOf(value).trim().split("\\s+")) {
                    if (!word.isEmpty() && !"null".equals(word)) {
                        words.add(word);
                    }
                }
            }
        }
        return words;
    }

    /** A criteria value, or null - PingFederate maps an extended property a client has no value for as blank or "null". */
    static String value(Map<?, ?> criteria, String key) {
        String value = criteria.get(key) instanceof AttributeValue attribute ? attribute.getValue() : null;
        return value == null || value.isBlank() || "null".equals(value) ? null : value;
    }

    private static void putIfPresent(Map<String, Object> map, String name, String value) {
        if (value != null) {
            map.put(name, value);
        }
    }
}
