package pdp

import (
	"context"
	"fmt"
	"log"
)

// Engine decides AuthZEN requests against a Policy and an EntitlementSource.
//
// It is default-deny: every path out of Evaluate that is not an explicit permit
// is a denial carrying a reason. An Engine is safe to share across goroutines
// provided its EntitlementSource is.
type Engine struct {
	policy       *Policy
	entitlements EntitlementSource
}

// NewEngine builds an Engine. A nil EntitlementSource becomes NoEntitlements,
// which denies everything: a PDP that cannot see the system of record must not
// fall back to trusting the grant alone.
func NewEngine(p *Policy, e EntitlementSource) *Engine {
	if e == nil {
		e = NoEntitlements{}
	}
	return &Engine{policy: p, entitlements: e}
}

// Policy returns the rule set this engine decides against.
func (e *Engine) Policy() *Policy { return e.policy }

// Reason identifiers. These are stable strings a client can branch on, and they
// appear as the AuthZEN decision context id.
const (
	ReasonPermitted            = "consent_covers_request"
	ReasonUnknownResourceType  = "unknown_resource_type"
	ReasonUnknownAction        = "unknown_action"
	ReasonMissingResourceID    = "missing_resource_id"
	ReasonMissingScope         = "missing_scope"
	ReasonNoConsentForType     = "no_consent_for_resource_type"
	ReasonResourceNotConsented = "resource_not_consented"
	ReasonActionNotConsented   = "action_not_consented"
	ReasonAmountExceedsLimit   = "amount_exceeds_consented_limit"
	ReasonMalformedContext     = "malformed_context"

	// Entitlement denials: the grant permits it, but the subject does not hold
	// the access to back it up.
	ReasonSubjectNotEntitled    = "subject_not_entitled"
	ReasonEntitlementLacksRight = "entitlement_lacks_right"
	ReasonEntitlementUnavailable = "entitlement_lookup_failed"
)

// Evaluate decides a single AuthZEN request.
//
// The order of the gates is deliberate, and it is a privacy decision as much as
// a logical one. Everything the grant permits is checked first, and only inside
// that envelope is the subject's entitlement consulted. So a client asking about
// a resource it was never granted learns exactly one thing -- that it was not
// granted it -- and never whether the subject holds it. Checking entitlement
// first would turn this endpoint into an oracle for enumerating a subject's
// accounts, which section 9 of the draft forbids.
//
// Within the consent envelope the client does learn whether the subject still
// holds the access. That is not a leak: it is the entire question the client
// asked, and the reason the endpoint exists.
func (e *Engine) Evaluate(ctx context.Context, req *EvaluationRequest) *EvaluationResponse {
	constraints, err := parseConstraints(req.Context)
	if err != nil {
		// The context is what carries the grant's authority. If we cannot read
		// it we have no basis to permit, so deny rather than fall through.
		log.Printf("[WARN] malformed evaluation context: %v", err)
		return deny(ReasonMalformedContext,
			fmt.Sprintf("could not read grant constraints from the request context: %v", err),
			"Your access could not be checked. Please try again.")
	}

	resourcePolicy, ok := e.policy.Resources[req.Resource.Type]
	if !ok {
		return deny(ReasonUnknownResourceType,
			fmt.Sprintf("resource type %q is not covered by policy %q", req.Resource.Type, e.policy.Name),
			"This kind of resource cannot be accessed.")
	}

	actionPolicy, ok := e.policy.Actions[req.Action.Name]
	if !ok {
		return deny(ReasonUnknownAction,
			fmt.Sprintf("action %q is not defined by policy %q", req.Action.Name, e.policy.Name),
			"This operation is not available.")
	}

	if req.Resource.ID == "" {
		return deny(ReasonMissingResourceID,
			fmt.Sprintf("action %q on resource type %q needs a resource id to decide against consent",
				req.Action.Name, req.Resource.Type),
			"No specific resource was named in the request.")
	}

	// The action's scope must be one the user actually granted. This is the
	// coarse gate; the authorization_details check below is the fine one.
	if s := actionPolicy.RequiresScope; s != "" && !contains(constraints.Scopes, s) {
		return deny(ReasonMissingScope,
			fmt.Sprintf("action %q requires scope %q, grant %s carries %v",
				req.Action.Name, s, constraints.GrantID, constraints.Scopes),
			"You have not consented to this type of access.")
	}

	// Find the consent that governs this resource type.
	detail, ok := findDetail(constraints.Details, resourcePolicy.AuthorizationDetailsType)
	if !ok {
		return deny(ReasonNoConsentForType,
			fmt.Sprintf("grant %s carries no authorization_details of type %q, needed for resource type %q",
				constraints.GrantID, resourcePolicy.AuthorizationDetailsType, req.Resource.Type),
			"You have not consented to share this information.")
	}

	// The specific resource must be one the user named when consenting.
	if !consentCoversResource(detail, resourcePolicy.IDPaths, req.Resource.ID) {
		return deny(ReasonResourceNotConsented,
			fmt.Sprintf("resource %s/%s is not named by any of %v in the %q consent on grant %s",
				req.Resource.Type, req.Resource.ID, resourcePolicy.IDPaths,
				resourcePolicy.AuthorizationDetailsType, constraints.GrantID),
			"You have not shared this account.")
	}

	// An authorization detail with no actions constrains nothing action-wise;
	// treat that as consent to every action the policy knows, having already
	// gated on scope above.
	if len(detail.Actions) > 0 && !contains(detail.Actions, req.Action.Name) {
		return deny(ReasonActionNotConsented,
			fmt.Sprintf("action %q is not among the consented actions %v on grant %s",
				req.Action.Name, detail.Actions, constraints.GrantID),
			"You have not consented to this action on this account.")
	}

	// The grant permits it. Now: does the subject actually hold this access?
	// A consent is only ever a permission to exercise authority the subject
	// already has, so this is where a grant that has outlived the subject's
	// access finally fails.
	rights, held, err := e.entitlements.RightsOn(ctx, req.Subject.ID, req.Resource.Type, req.Resource.ID)
	if err != nil {
		// The system of record is unreachable. We cannot confirm the subject
		// holds anything, and the grant alone is not sufficient, so deny.
		log.Printf("[ERROR] entitlement lookup for %s on %s/%s: %v",
			req.Subject.ID, req.Resource.Type, req.Resource.ID, err)
		return deny(ReasonEntitlementUnavailable,
			fmt.Sprintf("entitlement lookup failed for subject %q: %v", req.Subject.ID, err),
			"Your access could not be checked. Please try again.")
	}

	if !held {
		return deny(ReasonSubjectNotEntitled,
			fmt.Sprintf("subject %q holds no %s %q, though grant %s consents to it -- "+
				"the entitlement was withdrawn after consent was given",
				req.Subject.ID, req.Resource.Type, req.Resource.ID, constraints.GrantID),
			"You no longer have access to this account.")
	}

	if !contains(rights, req.Action.Name) {
		return deny(ReasonEntitlementLacksRight,
			fmt.Sprintf("subject %q holds %v on %s/%s, which does not include %q, "+
				"though grant %s consents to it",
				req.Subject.ID, rights, req.Resource.Type, req.Resource.ID,
				req.Action.Name, constraints.GrantID),
			"Your own access to this account does not allow this.")
	}

	// Contextual limit carried by the consent, e.g. a payment cap.
	if limit := actionPolicy.MaxAmount; limit > 0 {
		if amount, present := amountOf(req.Action.Properties); present && amount > limit {
			return deny(ReasonAmountExceedsLimit,
				fmt.Sprintf("amount %.2f exceeds the %.2f limit policy %q sets on action %q",
					amount, limit, e.policy.Name, req.Action.Name),
				"This amount is above your agreed limit.")
		}
	}

	return &EvaluationResponse{
		Decision: true,
		Context: &DecisionContext{
			ID: ReasonPermitted,
			ReasonAdmin: map[string]string{"en": fmt.Sprintf(
				"grant %s consents to %q on %s/%s and subject %q holds %v over it",
				constraints.GrantID, req.Action.Name, req.Resource.Type, req.Resource.ID,
				req.Subject.ID, rights)},
			ReasonUser: map[string]string{"en": "Access is covered by your consent."},
		},
	}
}

// EvaluateBatch decides each entry of a boxcarred request, in request order.
func (e *Engine) EvaluateBatch(ctx context.Context, req *EvaluationsRequest) *EvaluationsResponse {
	out := make([]EvaluationResponse, 0, len(req.Evaluations))
	for _, entry := range req.Evaluations {
		resolved := req.resolve(entry)
		out = append(out, *e.Evaluate(ctx, &resolved))
	}
	return &EvaluationsResponse{Evaluations: out}
}

// findDetail returns the first authorization detail of the given RAR type.
func findDetail(details []authorizationDetail, wantType string) (authorizationDetail, bool) {
	for _, d := range details {
		if d.Type == wantType {
			return d, true
		}
	}
	return authorizationDetail{}, false
}

// consentCoversResource reports whether id appears at any of the policy's
// id_paths within the consent.
func consentCoversResource(d authorizationDetail, paths []string, id string) bool {
	for _, path := range paths {
		if contains(d.consentedIDs(path), id) {
			return true
		}
	}
	return false
}

// amountOf reads a numeric "amount" action property. JSON numbers decode to
// float64, but accept the other numeric shapes a caller might construct.
func amountOf(props map[string]any) (float64, bool) {
	switch v := props["amount"].(type) {
	case float64:
		return v, true
	case float32:
		return float64(v), true
	case int:
		return float64(v), true
	case int64:
		return float64(v), true
	default:
		return 0, false
	}
}

// deny builds a denial carrying both reason halves.
func deny(id, admin, user string) *EvaluationResponse {
	return &EvaluationResponse{
		Decision: false,
		Context: &DecisionContext{
			ID:          id,
			ReasonAdmin: map[string]string{"en": admin},
			ReasonUser:  map[string]string{"en": user},
		},
	}
}
