// Package pdp implements a small AuthZEN 1.0 Policy Decision Point that decides
// access requests against the constraints carried by an OAuth 2.0 grant.
//
// It exists to make the Grant Evaluation API demonstrable end to end: the GM API
// passes the grant's scopes and RFC 9396 authorization_details down in the
// AuthZEN request context, and this PDP decides whether the requested action on
// the requested resource still falls within what the user consented to.
//
// The wire types below follow the OpenID AuthZEN Authorization API 1.0 shapes,
// so this PDP can be swapped for any conformant one (PingAuthorize, Topaz, OPA)
// without touching the GM API.
package pdp

// Entity is an AuthZEN subject or resource: a type, an optional id, and
// optional free-form properties.
type Entity struct {
	Type       string         `json:"type"`
	ID         string         `json:"id,omitempty"`
	Properties map[string]any `json:"properties,omitempty"`
}

// Action is the operation being attempted.
type Action struct {
	Name       string         `json:"name"`
	Properties map[string]any `json:"properties,omitempty"`
}

// EvaluationRequest is an AuthZEN access evaluation request.
type EvaluationRequest struct {
	Subject  Entity         `json:"subject"`
	Action   Action         `json:"action"`
	Resource Entity         `json:"resource"`
	Context  map[string]any `json:"context,omitempty"`
}

// DecisionContext explains a decision.
//
// AuthZEN draws a hard line between the two reason maps and so does this PDP:
// ReasonAdmin is for operators and may name internal policy detail, ReasonUser
// is the only part safe to surface to an end user. Both are keyed by language
// tag. This mirrors the Grant Evaluation API's requirement that a denial give a
// clear user-facing reason while withholding administrative detail.
type DecisionContext struct {
	ID          string            `json:"id,omitempty"`
	ReasonAdmin map[string]string `json:"reason_admin,omitempty"`
	ReasonUser  map[string]string `json:"reason_user,omitempty"`
}

// EvaluationResponse is an AuthZEN access evaluation response.
type EvaluationResponse struct {
	Decision bool             `json:"decision"`
	Context  *DecisionContext `json:"context,omitempty"`
}

// EvaluationsRequest is the boxcarred form. Subject, Action, Resource and
// Context act as defaults that each entry in Evaluations may override.
type EvaluationsRequest struct {
	Subject     *Entity             `json:"subject,omitempty"`
	Action      *Action             `json:"action,omitempty"`
	Resource    *Entity             `json:"resource,omitempty"`
	Context     map[string]any      `json:"context,omitempty"`
	Evaluations []EvaluationRequest `json:"evaluations"`
}

// EvaluationsResponse returns one decision per entry, in request order.
type EvaluationsResponse struct {
	Evaluations []EvaluationResponse `json:"evaluations"`
}

// Metadata is the AuthZEN discovery document served at
// /.well-known/authzen-configuration.
type Metadata struct {
	PolicyDecisionPoint       string `json:"policy_decision_point"`
	AccessEvaluationEndpoint  string `json:"access_evaluation_endpoint"`
	AccessEvaluationsEndpoint string `json:"access_evaluations_endpoint"`
}

// resolve fills an entry's zero-valued fields from the batch-level defaults.
func (b *EvaluationsRequest) resolve(e EvaluationRequest) EvaluationRequest {
	if e.Subject.Type == "" && e.Subject.ID == "" && b.Subject != nil {
		e.Subject = *b.Subject
	}
	if e.Action.Name == "" && b.Action != nil {
		e.Action = *b.Action
	}
	if e.Resource.Type == "" && e.Resource.ID == "" && b.Resource != nil {
		e.Resource = *b.Resource
	}
	if e.Context == nil {
		e.Context = b.Context
	}
	return e
}
