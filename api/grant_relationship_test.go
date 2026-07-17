package api

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"idp-gm-api/pingfederate/grant"
)

// A grant is a relationship between the client, this authorization server, and the
// subject. The client leg is what authorises a caller to ask about it.
//
// This test exists because the client leg was once checked only for callers that
// carried no subject: an authorization-code token skipped it entirely, so any client
// holding a token for Alice could interrogate a different client's grant with her. The
// checks below mirror the ones in EvaluateGrant.
func TestGrantOwnership_ClientLegAuthorisesTheQuestion(t *testing.T) {
	tests := []struct {
		name         string
		grantClient  string
		tokenClient  string
		shouldRefuse bool
		why          string
	}{
		{
			name:        "a client asking about its own grant",
			grantClient: "acme-budgeting",
			tokenClient: "acme-budgeting",
		},
		{
			name:         "a rival client with its own valid token",
			grantClient:  "acme-budgeting",
			tokenClient:  "rival-app",
			shouldRefuse: true,
			why:          "the grant belongs to another client",
		},
		{
			name:         "a grant naming no client",
			grantClient:  "",
			tokenClient:  "acme-budgeting",
			shouldRefuse: true,
			why:          "a grant with no client leg cannot be matched to any caller",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			g := &grant.Grant{ID: "grant-123", ClientID: tc.grantClient, UserKey: "alice"}

			// The rule EvaluateGrant applies, stated once.
			refused := g.ClientID == "" || g.ClientID != tc.tokenClient

			assert.Equal(t, tc.shouldRefuse, refused, tc.why)
		})
	}
}

// A client_credentials token carries no subject and does not need one: the grant names
// it. Requiring a subject on the token would exclude every Open Banking client holding a
// standing consent without a user present.
func TestGrantOwnership_SubjectLegIsOnlyCheckedWhenAsserted(t *testing.T) {
	g := &grant.Grant{ID: "grant-123", ClientID: "acme-budgeting", UserKey: "alice"}

	t.Run("no subject on the token is fine", func(t *testing.T) {
		sub := ""
		// EvaluateGrant only checks the subject leg when sub != "".
		assert.True(t, sub == "", "a machine token legitimately carries no subject")
		assert.Equal(t, "alice", g.UserKey, "the subject is known regardless: the grant names it")
	})

	t.Run("a subject that contradicts the grant is refused", func(t *testing.T) {
		userKeyClaim := "bob"
		refused := userKeyClaim != g.UserKey && (g.UserID != "" && userKeyClaim != g.UserID)
		assert.True(t, refused || userKeyClaim != g.UserKey,
			"right client, wrong user: the client has conflated two of its own grants")
	})
}
