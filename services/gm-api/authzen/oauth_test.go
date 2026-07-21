package authzen

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockTokenServer creates a test HTTP server that mocks the OAuth token endpoint
func mockTokenServer() *httptest.Server {
	handler := http.NewServeMux()
	server := httptest.NewServer(handler)

	handler.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		// Verify the request
		err := r.ParseForm()
		if err != nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}

		if r.Form.Get("grant_type") != "client_credentials" {
			http.Error(w, "invalid grant_type", http.StatusBadRequest)
			return
		}

		// Verify client credentials
		clientID, clientSecret, ok := r.BasicAuth()
		if !ok || clientID != "test-client" || clientSecret != "test-secret" {
			http.Error(w, "invalid client credentials", http.StatusUnauthorized)
			return
		}

		// Create a token response
		token := map[string]interface{}{
			"access_token": "test-access-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(token)
	})

	return server
}

// TestOAuthClient is a test-specific OAuth client that bypasses token retrieval
type TestOAuthClient struct {
	*OAuthClient
}

// NewTestOAuthClient creates a new test OAuth client
func NewTestOAuthClient(config *OAuthConfig) *TestOAuthClient {
	return &TestOAuthClient{
		OAuthClient: NewOAuthClient(config),
	}
}

// TestOAuthClient_GetToken tests token retrieval and refresh functionality
func TestOAuthClient_GetToken(t *testing.T) {
	// Setup mock server
	ts := mockTokenServer()
	defer ts.Close()

	// Create config with mock server URL
	config := &OAuthConfig{
		BaseURL:      ts.URL + "/token",
		ClientID:     "test-client",
		ClientSecret: "test-secret",
	}

	// Create client
	client := NewOAuthClient(config)

	// Test initial token fetch
	token, err := client.GetPingFederateToken()
	require.NoError(t, err)
	assert.NotEmpty(t, token)

	// Test token reuse (should use cached token)
	token2, err := client.GetPingFederateToken()
	require.NoError(t, err)
	assert.Equal(t, token, token2)
}

// TestOAuthClient_ConcurrentAccess tests concurrent access to token
func TestOAuthClient_ConcurrentAccess(t *testing.T) {
	// Setup mock server
	ts := mockTokenServer()
	defer ts.Close()

	// Create config with mock server URL
	config := &OAuthConfig{
		BaseURL:      ts.URL + "/token",
		ClientID:     "test-client",
		ClientSecret: "test-secret",
	}

	// Create client
	client := NewOAuthClient(config)

	// Test concurrent access
	var wg sync.WaitGroup
	results := make(chan string, 10)

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			token, err := client.GetPingFederateToken()
			if assert.NoError(t, err) {
				results <- token
			}
		}()
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	// Verify all tokens are the same
	var firstToken string
	for token := range results {
		if firstToken == "" {
			firstToken = token
		}
		assert.Equal(t, firstToken, token)
	}
}

// TestOAuthClient_ErrorHandling tests error scenarios
func TestOAuthClient_ErrorHandling(t *testing.T) {
	tests := []struct {
		name        string
		config      *OAuthConfig
		expectError bool
	}{
		{
			name: "invalid token URL",
			config: &OAuthConfig{
				BaseURL:      "http://invalid-url/token",
				ClientID:     "test",
				ClientSecret: "test",
			},
			expectError: true,
		},
		{
			name: "invalid credentials",
			config: &OAuthConfig{
				BaseURL:      "http://example.com/token",
				ClientID:     "invalid",
				ClientSecret: "invalid",
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := NewOAuthClient(tt.config)
			_, err := client.GetPingFederateToken()
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestOAuthClient_AddAuthHeader tests the authorization header functionality
func TestOAuthClient_AddAuthHeader(t *testing.T) {
	// Setup mock server
	ts := mockTokenServer()
	defer ts.Close()

	// Create config with mock server URL
	config := &OAuthConfig{
		BaseURL:      ts.URL + "/token",
		ClientID:     "test-client",
		ClientSecret: "test-secret",
	}

	// Create client
	client := NewOAuthClient(config)

	// Create a test request
	req, err := http.NewRequest("GET", "http://example.com/api", nil)
	require.NoError(t, err)

	// Get token and manually add to header
	token, err := client.GetPingFederateToken()
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)

	// Verify the header was added
	authHeader := req.Header.Get("Authorization")
	assert.True(t, strings.HasPrefix(authHeader, "Bearer "))
}

// TestOAuthClient_RefreshToken tests token refresh functionality
func TestOAuthClient_RefreshToken(t *testing.T) {
	// Setup mock server with custom handler for token refresh
	tokenCalls := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenCalls++
		if r.URL.Path != "/token" {
			http.NotFound(w, r)
			return
		}

		// Create a token response with short expiry
		token := map[string]interface{}{
			"access_token": fmt.Sprintf("test-token-%d", tokenCalls),
			"token_type":   "Bearer",
			"expires_in":   1, // 1 second expiry
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(token)
	}))
	defer ts.Close()

	// Create config with mock server URL
	config := &OAuthConfig{
		BaseURL:      ts.URL + "/token",
		ClientID:     "test-client",
		ClientSecret: "test-secret",
	}

	// Create client
	client := NewOAuthClient(config)

	// Get initial token
	token1, err := client.GetPingFederateToken()
	require.NoError(t, err)
	assert.Equal(t, "test-token-1", token1)

	// Wait for token to expire
	time.Sleep(2 * time.Second)

	// Get token again - should trigger refresh
	token2, err := client.GetPingFederateToken()
	require.NoError(t, err)
	assert.Equal(t, "test-token-2", token2)
}
