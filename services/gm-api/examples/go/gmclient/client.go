// Package gmclient calls the Grant Evaluation API.
//
// Copy it into your project — it has no dependencies beyond the standard library, and
// it is small enough to read in one sitting.
//
// The question it answers is not "is this token valid" but "does this consent still
// permit this, right now". Those differ: a grant can be valid, unexpired and explicitly
// name an account the user closed last week.
//
//	c := gmclient.New("https://pf:9031/gm-api", tokenSource)
//	d, err := c.Evaluate(ctx, grantID, gmclient.Request{
//	    Action:   gmclient.Action{Name: "read_balance"},
//	    Resource: gmclient.Resource{Type: "account", ID: "222"},
//	})
//	if err != nil {
//	    return err // could not ask -- NOT a denial
//	}
//	if !d.Permitted {
//	    if d.Retryable() {
//	        return askUserToReconsent(d.ReasonID())
//	    }
//	    return fmt.Errorf("access is gone: %s", d.Message())
//	}
package gmclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Reason identifiers. Branch on these, never on the message: messages are written for
// humans and will change.
const (
	// Permitted.
	ReasonPermitted = "consent_covers_request"

	// The consent does not cover the request. The user can fix these by consenting again.
	ReasonResourceNotConsented = "resource_not_consented"
	ReasonActionNotConsented   = "action_not_consented"
	ReasonMissingScope         = "missing_scope"
	ReasonNoConsentForType     = "no_consent_for_resource_type"
	ReasonAmountExceedsLimit   = "amount_exceeds_consented_limit"

	// The subject does not hold the access. Re-consenting cannot help: nobody can
	// consent to what they do not have.
	ReasonSubjectNotEntitled    = "subject_not_entitled"
	ReasonEntitlementLacksRight = "entitlement_lacks_right"

	// The grant itself is gone or was never yours.
	ReasonGrantExpired  = "grant_expired"
	ReasonGrantNotFound = "grant_not_found"
	ReasonUnauthorized  = "unauthorized"

	// Your token is wrong for this operation.
	ReasonInsufficientScope = "insufficient_scope"
)

// TokenSource supplies the bearer token for a call.
//
// It is a function so a client_credentials caller can cache and refresh without this
// package knowing how. Return the token you would put after "Bearer ".
type TokenSource func(ctx context.Context) (string, error)

// StaticToken is a TokenSource for a token you already hold.
func StaticToken(token string) TokenSource {
	return func(context.Context) (string, error) { return token, nil }
}

// Client calls one Grant Management deployment.
type Client struct {
	baseURL string
	token   TokenSource
	http    *http.Client
}

// New builds a Client.
//
// baseURL is the Grant Management base: https://pf:9031/gm-api for the PingFederate
// servlet, http://host:8088/api/v1 for the Go sidecar.
func New(baseURL string, token TokenSource) *Client {
	return &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		token:   token,
		http:    &http.Client{Timeout: 15 * time.Second},
	}
}

// WithHTTPClient overrides the HTTP client, e.g. to set a custom TLS config.
func (c *Client) WithHTTPClient(h *http.Client) *Client {
	c.http = h
	return c
}

// Action is the operation being attempted. Properties are optional and passed to the
// PDP -- an amount, for instance, that policy may cap.
type Action struct {
	Name       string         `json:"name"`
	Properties map[string]any `json:"properties,omitempty"`
}

// Resource is what the action is attempted on.
type Resource struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

// Request asks whether a grant permits an action on a resource.
//
// There is deliberately no Subject field. The subject comes from the grant, not from
// you; that is what makes the answer worth anything.
type Request struct {
	Action   Action         `json:"action"`
	Resource Resource       `json:"resource"`
	Context  map[string]any `json:"context,omitempty"`
}

type reason struct {
	ID      string `json:"id"`
	Message string `json:"message"`
}

// Decision is the answer.
type Decision struct {
	Permitted bool `json:"decision"`
	Context   struct {
		Reasons []reason `json:"reasons"`
	} `json:"context"`
	Trace struct {
		Step string `json:"step"`
	} `json:"trace"`
}

// ReasonID is the stable identifier to branch on, or "" if none was given.
func (d Decision) ReasonID() string {
	if len(d.Context.Reasons) == 0 {
		return ""
	}
	return d.Context.Reasons[0].ID
}

// Message is the reason as written for a human. Safe to show a user: the API withholds
// the administrative half.
func (d Decision) Message() string {
	if len(d.Context.Reasons) == 0 {
		return ""
	}
	return d.Context.Reasons[0].Message
}

// Retryable reports whether re-consenting could change this answer.
//
// It cannot when the subject does not hold the access: nobody can consent to what they
// do not have, so sending the user back through an authorization flow will produce the
// same denial and waste their time.
func (d Decision) Retryable() bool {
	switch d.ReasonID() {
	case ReasonSubjectNotEntitled, ReasonEntitlementLacksRight:
		return false
	case ReasonPermitted:
		return false
	default:
		return true
	}
}

// Grant is what a query returns.
type Grant struct {
	Scopes []struct {
		Scope    string   `json:"scope"`
		Resource []string `json:"resource,omitempty"`
	} `json:"scopes"`
	AuthorizationDetails []map[string]any `json:"authorization_details,omitempty"`
}

// APIError is a transport-level failure: the question was not answered.
//
// A denial is not an APIError -- it comes back as a Decision with Permitted false. This
// is for the cases where there is no answer at all.
type APIError struct {
	Status      int
	Code        string `json:"error"`
	Description string `json:"error_description"`
}

func (e *APIError) Error() string {
	return fmt.Sprintf("grant management API: %d %s: %s", e.Status, e.Code, e.Description)
}

// Unavailable reports whether the API could not reach the PDP or the grant store.
//
// This is the case that must not be read as a denial. It means "I could not ask", and
// turning that into "no" is indistinguishable to your caller from a real policy
// decision. Retry, or fail closed deliberately.
func (e *APIError) Unavailable() bool { return e.Status == http.StatusServiceUnavailable }

// Unauthenticated reports whether the token was rejected.
func (e *APIError) Unauthenticated() bool { return e.Status == http.StatusUnauthorized }

// Evaluate asks whether the grant still permits the request.
//
// Requires grant_management_evaluate on the token. A refusal comes back as a Decision
// with Permitted false, not an error -- including when your token lacks the scope.
func (c *Client) Evaluate(ctx context.Context, grantID string, req Request) (*Decision, error) {
	var out Decision
	if err := c.do(ctx, http.MethodPost, c.grantPath(grantID)+"/evaluate", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Query returns the grant's scopes and consent.
//
// Requires grant_management_query. The spec's claims array is absent on PingFederate,
// whose grant model has no claims.
func (c *Client) Query(ctx context.Context, grantID string) (*Grant, error) {
	var out Grant
	if err := c.do(ctx, http.MethodGet, c.grantPath(grantID), nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Revoke ends the grant. Requires grant_management_revoke.
//
// It takes effect on the next evaluation -- no token needs to expire first.
func (c *Client) Revoke(ctx context.Context, grantID string) error {
	return c.do(ctx, http.MethodDelete, c.grantPath(grantID), nil, nil)
}

// grantPath escapes the id: it is an opaque identifier and may be anything.
func (c *Client) grantPath(grantID string) string {
	return c.baseURL + "/grants/" + url.PathEscape(grantID)
}

func (c *Client) do(ctx context.Context, method, url string, body, out any) error {
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("encode request: %w", err)
		}
		reader = bytes.NewReader(encoded)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, reader)
	if err != nil {
		return err
	}

	token, err := c.token(ctx)
	if err != nil {
		return fmt.Errorf("get token: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("call %s: %w", url, err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode == http.StatusNoContent {
		return nil
	}
	if resp.StatusCode != http.StatusOK {
		apiErr := &APIError{Status: resp.StatusCode}
		// The body may not be JSON (a proxy error page, say); the status still is.
		_ = json.Unmarshal(raw, apiErr)
		return apiErr
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	return nil
}
