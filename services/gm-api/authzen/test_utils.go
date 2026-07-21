package authzen

import "net/http"

// testAuthenticator is a simple authenticator for testing purposes
type testAuthenticator struct {
	token string
}

// NewTestAuthenticator creates a new test authenticator that implements the Authenticator interface
func NewTestAuthenticator() Authenticator {
	return &testAuthenticator{
		token: "test-token",
	}
}

// AddAuthHeader adds a test authorization header
func (a *testAuthenticator) AddAuthHeader(req *http.Request) error {
	req.Header.Set("Authorization", "Bearer "+a.token)
	return nil
}

// GetMetadata returns test OAuth metadata
func (a *testAuthenticator) GetMetadata() *OAuthConfig {
	return &OAuthConfig{
		BaseURL:      "http://test-server/token",
		ClientID:     "test-client",
		ClientSecret: "test-secret",
	}
}

// SetToken sets the token for testing purposes
func (a *testAuthenticator) SetToken(token string) {
	a.token = token
}
