package grant

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// realPingFederateGrant is the verbatim response from PingFederate 13.0.3 for
// GET /pf-ws/rest/oauth/users/alice/grants, after alice completed an
// authorization code flow against the demo configuration.
//
// Keep it verbatim. The shape here -- name/values pairs, with the consent as a
// JSON document encoded inside a string -- is the whole reason decodeAuthzDetails
// exists, and it is not what you would guess from the field name.
const realPingFederateGrant = `{
  "id": "2LS7YSTTRmnW9ErGlvUH2lhOSbX4brWf",
  "userKey": "alice",
  "grantType": "AUTHORIZATION_CODE",
  "scopes": ["accounts.read"],
  "clientId": "acme-budgeting",
  "issued": "2026-07-16T22:44:30.090Z",
  "updated": "2026-07-16T22:44:30.090Z",
  "expires": "2026-08-15T22:44:30.091Z",
  "grantAttributes": [
    {
      "name": "authorization_details",
      "values": ["[{\"actions\":[\"read_balance\",\"read_transactions\"],\"locations\":[\"111\",\"222\",\"444\"],\"type\":\"account_information\"}]"]
    },
    {
      "name": "pi.sri",
      "values": ["xGzlniBqAYwFSUDDRv5RGA1qEHs"]
    }
  ]
}`

func TestUnmarshal_RealPingFederateGrant(t *testing.T) {
	var g Grant
	require.NoError(t, json.Unmarshal([]byte(realPingFederateGrant), &g))

	assert.Equal(t, "2LS7YSTTRmnW9ErGlvUH2lhOSbX4brWf", g.ID)
	assert.Equal(t, "alice", g.UserKey)
	assert.Equal(t, "acme-budgeting", g.ClientID)
	assert.Equal(t, "alice", g.UserID, "UserID should fall back to UserKey")

	// Each scope exactly once. The scopes were previously decoded twice -- by the
	// struct tag and again by hand -- which doubled every entry.
	require.Len(t, g.Scopes, 1, "each scope should appear exactly once")
	assert.Equal(t, "accounts.read", g.Scopes[0].Scope)

	// The consent must survive the round trip. Reading it as an empty slice is
	// the failure that matters: the PDP cannot tell that apart from a grant with
	// no consent, and denies with a misleading reason.
	require.Len(t, g.AuthzDetails, 1, "the consent must be decoded out of grantAttributes")
	d := g.AuthzDetails[0]
	assert.Equal(t, "account_information", d.Type)
	assert.Equal(t, []string{"read_balance", "read_transactions"}, d.Actions)
	assert.Equal(t, []string{"111", "222", "444"}, d.Locations)

	assert.Greater(t, g.CreatedAt, int64(0), "issued should parse to a unix timestamp")
}

// A scope-only grant carries no consent attribute. That is legitimate, not an error.
func TestUnmarshal_GrantWithoutConsentAttribute(t *testing.T) {
	var g Grant
	require.NoError(t, json.Unmarshal([]byte(`{
      "id": "g2", "userKey": "bob", "clientId": "acme-budgeting",
      "scopes": ["accounts.read"],
      "grantAttributes": [{"name": "pi.sri", "values": ["abc"]}]
    }`), &g))

	assert.Empty(t, g.AuthzDetails)
	assert.Equal(t, "bob", g.UserKey)
	require.Len(t, g.Scopes, 1)
}

// Consent we cannot parse must fail loudly rather than decode to nothing:
// silently empty consent is indistinguishable from a grant that never had any.
func TestUnmarshal_UnparseableConsentIsAnError(t *testing.T) {
	var g Grant
	err := json.Unmarshal([]byte(`{
      "id": "g3", "userKey": "alice",
      "grantAttributes": [{"name": "authorization_details", "values": ["{not json"]}]
    }`), &g)

	require.Error(t, err, "malformed consent must not be swallowed")
	assert.Contains(t, err.Error(), "authorization_details")
}

// PingFederate renders scopes as bare strings; other sources use objects.
func TestUnmarshal_ScopeObjectForm(t *testing.T) {
	var g Grant
	require.NoError(t, json.Unmarshal([]byte(`{
      "id": "g4", "userKey": "alice",
      "scopes": [{"scope": "accounts.read", "resource": ["111"]}]
    }`), &g))

	require.Len(t, g.Scopes, 1)
	assert.Equal(t, "accounts.read", g.Scopes[0].Scope)
	assert.Equal(t, []string{"111"}, g.Scopes[0].Resource)
}
