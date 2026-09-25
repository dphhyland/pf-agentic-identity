/*
 * The policy decision a registration waits for.
 */
package com.pingidentity.ps.oidf.servlet.clientregistration;

import com.pingidentity.ps.oidf.federation.TrustChainValidationResult;
import com.pingidentity.ps.oidf.federation.event.FederationEvents;
import com.pingidentity.ps.oidf.federation.event.LogSafe;
import com.pingidentity.ps.oidf.federation.policy.DecisionPoint;
import com.pingidentity.ps.oidf.federation.policy.FederationPolicyDecisionPoint;
import com.pingidentity.ps.oidf.federation.policy.NarrowingObligations;
import com.pingidentity.ps.oidf.federation.policy.PolicyDecision;
import com.pingidentity.ps.oidf.federation.policy.PolicyDecisionException;
import com.pingidentity.ps.oidf.federation.policy.PolicyDecisionRequest;
import com.pingidentity.ps.oidf.pf.FederationPolicySupport;
import com.pingidentity.ps.oidf.pf.FederationRuntimeConfig.PdpSettings;
import com.pingidentity.ps.oidf.pf.PfTracking;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.Function;

/**
 * Asks whoever decides federation requests in this deployment ({@link FederationPolicySupport}) whether a registration
 * may go ahead - after the federation's own checks, before anything is stored - and returns what a permit narrows.
 *
 * <ul>
 *   <li>A denial refuses the registration: 400 {@code invalid_client_metadata}. The PDP's {@code reason_user} is the
 *       description only when {@code OIDF_PDP_SURFACE_USER_REASON=true}; its {@code reason_admin} goes to the logs.</li>
 *   <li>No decision - the PDP unreachable, an error status, an answer that is not one - refuses it too, 503
 *       {@code temporarily_unavailable}: an error is never read as a permit (AuthZEN 1.0 §10.1.2). With
 *       {@code OIDF_PDP_FAIL_OPEN=true} the registration goes ahead unnarrowed instead, and a warning says so.</li>
 * </ul>
 *
 * <p>What the PDP hears (AuthZEN 1.0 §5): the entity's identifier and Entity Types, the anchor its chain reached and - when
 * this deployment verified them - its Trust Marks; what it asks for (scope, grant types, response types, redirect URIs)
 * as its resolved metadata has it, after every superior's policy; when its chain expires; and the endpoint and tracking id
 * of the request. Never its keys or statements.
 */
final class RegistrationPolicy {
    private final Function<DecisionPoint, FederationPolicyDecisionPoint> decisionPoints;
    private final PdpSettings settings;

    RegistrationPolicy(Function<DecisionPoint, FederationPolicyDecisionPoint> decisionPoints, PdpSettings settings) {
        this.decisionPoints = Objects.requireNonNull(decisionPoints, "decisionPoints");
        this.settings = Objects.requireNonNull(settings, "settings");
    }

    /** This deployment's decision points, as {@link FederationPolicySupport} built them. */
    static RegistrationPolicy fromEnvironment() {
        return new RegistrationPolicy(FederationPolicySupport::decisionPointFor, FederationPolicySupport.settings());
    }

    /**
     * The decision on registering {@code clientId}.
     *
     * @param verifiedMarks the Trust Mark types verified for it, or null when none were checked
     * @return what the permit narrows; {@link NarrowingObligations#NONE} when nobody decides, or when no decision came and
     *         the deployment fails open
     * @throws RegistrationRejectedException 400 when refused, 503 when no decision came
     */
    NarrowingObligations decide(DecisionPoint point, String clientId, String opIssuer, String endpoint, String entityType,
                                TrustChainValidationResult validation, Map<String, Object> metadata, List<String> verifiedMarks)
            throws RegistrationRejectedException {
        FederationPolicyDecisionPoint pdp = this.decisionPoints.apply(point);
        if (pdp == null) {
            return NarrowingObligations.NONE;
        }
        PolicyDecisionRequest request = request(point, clientId, opIssuer, endpoint, entityType, validation, metadata, verifiedMarks);
        PolicyDecision decision;
        try {
            decision = pdp.decide(request);
        } catch (PolicyDecisionException e) {
            return this.noDecision(point, clientId, validation, endpoint, e);
        }
        FederationEvents.event(FederationEvents.PDP_CONSULTED).subject(clientId).partner(validation.trustAnchorIssuer()).role("OP").audit()
                .field("action", point.action()).field("endpoint", endpoint).field("decision", decision.permitted() ? "permit" : "deny")
                .field("latency_ms", decision.latencyMs()).field("pdp_request_id", decision.pdpRequestId())
                .field("obligations", nullIfEmpty(obligationNames(decision.obligations())))
                .field("ignored_context", nullIfEmpty(decision.ignoredContextKeys()))
                .description(decision.reasonAdmin()).emit();
        if (decision.permitted()) {
            return decision.obligations();
        }
        RegistrationService.LOGGER.info("Federation client " + LogSafe.value(clientId) + " refused by policy"
                + (decision.reasonAdmin() == null ? "" : ": " + LogSafe.value(decision.reasonAdmin())));
        FederationEvents.event(FederationEvents.REGISTRATION_REFUSED).failure("policy_denied").subject(clientId).role("OP").audit()
                .field("entity_type", entityType).field("endpoint", endpoint).description("the policy decision point refused it").emit();
        String description = this.settings.surfaceUserReason() && decision.reasonUser() != null ? decision.reasonUser()
                : "this deployment's policy does not allow " + clientId + " to be registered";
        throw new RegistrationRejectedException(400, "invalid_client_metadata", description, RegistrationRejectedException.Kind.POLICY, null);
    }

    /** No decision came: refused, unless the deployment fails open. */
    private NarrowingObligations noDecision(DecisionPoint point, String clientId, TrustChainValidationResult validation, String endpoint,
                                            PolicyDecisionException e) throws RegistrationRejectedException {
        FederationEvents.event(FederationEvents.PDP_CONSULTED).failure("no_decision").subject(clientId).partner(validation.trustAnchorIssuer())
                .role("OP").audit().field("action", point.action()).field("endpoint", endpoint).description(e.getMessage()).emit();
        if (this.settings.failOpen()) {
            FederationEvents.event(FederationEvents.PDP_FAIL_OPEN).failure("no_decision").subject(clientId).role("OP").audit()
                    .field("action", point.action()).description("registered without a policy decision: OIDF_PDP_FAIL_OPEN=true").emit();
            return NarrowingObligations.NONE;
        }
        throw new RegistrationRejectedException(503, "temporarily_unavailable",
                "the policy decision this registration needs could not be obtained; try again shortly", RegistrationRejectedException.Kind.TRANSPORT, e);
    }

    static PolicyDecisionRequest request(DecisionPoint point, String clientId, String opIssuer, String endpoint, String entityType,
                                         TrustChainValidationResult validation, Map<String, Object> metadata, List<String> verifiedMarks) {
        Map<String, Object> subject = new LinkedHashMap<>();
        subject.put("entity_types", new ArrayList<>(validation.resolvedMetadata().keySet()));
        subject.put("trust_anchor", validation.trustAnchorIssuer());
        if (verifiedMarks != null) {
            subject.put("trust_marks", verifiedMarks);
        }
        Map<String, Object> context = new LinkedHashMap<>();
        for (String requested : List.of("scope", "grant_types", "response_types", "redirect_uris")) {
            if (metadata.get(requested) != null) {
                context.put(requested, metadata.get(requested));
            }
        }
        if (validation.expEpochSeconds() >= 0) {
            context.put("chain_expires_at", validation.expEpochSeconds());
        }
        String trackingId = PfTracking.trackingId();
        if (trackingId != null) {
            context.put(PolicyDecisionRequest.REQUEST_CONTEXT, Map.of("tracking_id", trackingId));
        }
        return new PolicyDecisionRequest(point, clientId, subject, "openid_provider", opIssuer,
                Map.of("endpoint", endpoint, "entity_type", entityType), context, trackingId);
    }

    /** A collection for an event field, or null - no field - when there is nothing in it. */
    static <T extends java.util.Collection<?>> T nullIfEmpty(T values) {
        return values.isEmpty() ? null : values;
    }

    /** What a permit narrows, by name, for the log: never the values, which may be long. */
    static List<String> obligationNames(NarrowingObligations obligations) {
        List<String> names = new ArrayList<>();
        if (obligations.scopes() != null) {
            names.add("scope");
        }
        if (obligations.grantTypes() != null) {
            names.add("grant_types");
        }
        if (obligations.responseTypes() != null) {
            names.add("response_types");
        }
        if (obligations.maxTtlSeconds() != null) {
            names.add("registration_ttl_seconds");
        }
        if (!obligations.requiredTrustMarks().isEmpty()) {
            names.add("require_trust_mark");
        }
        return names;
    }
}
