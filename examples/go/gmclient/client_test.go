package gmclient

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// The whole point of the Retryable split: a user can consent again to fix a consent
// problem, but nobody can consent to access they do not have. Sending them back through
// an authorization flow for an entitlement denial wastes their time and returns the
// same answer.
func TestDecision_RetryableSplitsConsentFromEntitlement(t *testing.T) {
	tests := []struct {
		reason    string
		retryable bool
		why       string
	}{
		{ReasonResourceNotConsented, true, "the user can share the account"},
		{ReasonActionNotConsented, true, "the user can consent to the action"},
		{ReasonMissingScope, true, "the user can grant the scope"},
		{ReasonAmountExceedsLimit, true, "a smaller amount may pass"},
		{ReasonSubjectNotEntitled, false, "the user does not hold it; consent cannot conjure it"},
		{ReasonEntitlementLacksRight, false, "the user's own rights stop short"},
		{ReasonPermitted, false, "nothing to retry"},
	}

	for _, tc := range tests {
		t.Run(tc.reason, func(t *testing.T) {
			var d Decision
			d.Context.Reasons = []reason{{ID: tc.reason}}
			if got := d.Retryable(); got != tc.retryable {
				t.Errorf("Retryable() = %v, want %v: %s", got, tc.retryable, tc.why)
			}
		})
	}
}

func TestDecision_EmptyReasonsAreSafeToRead(t *testing.T) {
	var d Decision
	if d.ReasonID() != "" || d.Message() != "" {
		t.Error("a decision with no reasons must not panic or invent one")
	}
}

func TestEvaluate_ReadsADenial(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer t0ken" {
			t.Errorf("Authorization = %q", got)
		}
		if r.URL.Path != "/gm-api/grants/grant-123/evaluate" {
			t.Errorf("path = %q", r.URL.Path)
		}
		var req Request
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.Resource.ID != "222" {
			t.Errorf("resource id = %q", req.Resource.ID)
		}
		_, _ = w.Write([]byte(`{"decision":false,"context":{"reasons":[
			{"id":"subject_not_entitled","message":"You no longer have access to this account."}]}}`))
	}))
	defer srv.Close()

	d, err := New(srv.URL+"/gm-api", StaticToken("t0ken")).Evaluate(
		context.Background(), "grant-123",
		Request{Action: Action{Name: "read_balance"}, Resource: Resource{Type: "account", ID: "222"}})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if d.Permitted {
		t.Error("expected a denial")
	}
	if d.ReasonID() != ReasonSubjectNotEntitled {
		t.Errorf("ReasonID() = %q", d.ReasonID())
	}
	if d.Retryable() {
		t.Error("an entitlement denial must not invite a retry")
	}
}

// A 503 means the PDP or grant store could not be reached. It must be reported as an
// error, never as a denial: turning "I could not ask" into "no" is indistinguishable to
// the caller from a real policy decision.
func TestEvaluate_UnavailableIsAnErrorNotADenial(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"error":"service_unavailable","error_description":"PDP unreachable"}`))
	}))
	defer srv.Close()

	_, err := New(srv.URL, StaticToken("t")).Evaluate(context.Background(), "g",
		Request{Action: Action{Name: "read_balance"}, Resource: Resource{Type: "account", ID: "1"}})
	if err == nil {
		t.Fatal("a 503 must be an error, not a decision")
	}
	apiErr, ok := err.(*APIError)
	if !ok {
		t.Fatalf("want *APIError, got %T", err)
	}
	if !apiErr.Unavailable() {
		t.Error("Unavailable() should be true for 503")
	}
}

func TestEvaluate_NonJsonErrorBodyStillYieldsTheStatus(t *testing.T) {
	// A proxy or container error page is not JSON. The status is still meaningful and
	// must survive.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("<html>Unauthorized</html>"))
	}))
	defer srv.Close()

	_, err := New(srv.URL, StaticToken("t")).Evaluate(context.Background(), "g",
		Request{Action: Action{Name: "x"}, Resource: Resource{Type: "account", ID: "1"}})
	apiErr, ok := err.(*APIError)
	if !ok {
		t.Fatalf("want *APIError, got %T (%v)", err, err)
	}
	if !apiErr.Unauthenticated() {
		t.Error("Unauthenticated() should be true for 401 even with an HTML body")
	}
}

func TestRevoke_AcceptsNoContent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			t.Errorf("method = %s", r.Method)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	if err := New(srv.URL, StaticToken("t")).Revoke(context.Background(), "grant-123"); err != nil {
		t.Errorf("Revoke: %v", err)
	}
}

func TestQuery_ReadsTheConsent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"scopes":[{"scope":"accounts.read"}],
			"authorization_details":[{"type":"account_information","locations":["111","222"]}]}`))
	}))
	defer srv.Close()

	g, err := New(srv.URL, StaticToken("t")).Query(context.Background(), "grant-123")
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(g.Scopes) != 1 || g.Scopes[0].Scope != "accounts.read" {
		t.Errorf("scopes = %+v", g.Scopes)
	}
	if len(g.AuthorizationDetails) != 1 {
		t.Fatalf("authorization_details = %+v", g.AuthorizationDetails)
	}
	if g.AuthorizationDetails[0]["type"] != "account_information" {
		t.Errorf("type = %v", g.AuthorizationDetails[0]["type"])
	}
}

// Grant ids are opaque and must survive the URL intact.
func TestGrantPath_EscapesTheId(t *testing.T) {
	c := New("https://pf/gm-api", StaticToken("t"))
	if got := c.grantPath("a/b c"); got != "https://pf/gm-api/grants/a%2Fb%20c" {
		t.Errorf("grantPath = %q", got)
	}
}
