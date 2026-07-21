package authzen

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupMockServer creates a test server with mock endpoints
func setupMockServer(t *testing.T) *httptest.Server {
	t.Helper()

	handler := http.NewServeMux()

	// Discovery endpoint
	handler.HandleFunc("/.well-known/authzen-configuration", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		discoveryDoc := map[string]string{
			"evaluate_endpoint":         "/access/v1/evaluation",
			"evaluations_endpoint":      "/access/v1/evaluations",
			"subject_search_endpoint":   "/access/v1/search/subject",
			"resource_search_endpoint":  "/access/v1/search/resource",
			"action_search_endpoint":    "/access/v1/search/action",
			"policy_decision_point":     "https://pdp.example.com",
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(discoveryDoc)
	})

	// Add token endpoint for OAuth tests
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

		// Create a token response
		token := map[string]interface{}{
			"access_token": "test-access-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(token)
	})

	// Batch evaluations endpoint
	handler.HandleFunc("/access/v1/evaluations", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req BatchEvaluateRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		// Create a response with the same number of results as requests
		results := make([]BatchEvaluationResponse, len(req.Requests))
		for i := range results {
			results[i] = BatchEvaluationResponse{
				Decision: true, // Default to allowed
				Context: EvaluationResponseContext{
					Reasons: []Reason{
						{
							ID: "test-reason",
							ReasonUser: map[string]string{
								"en": "Access granted for testing",
							},
						},
					},
				},
			}
		}

		resp := BatchEvaluateResponse{Results: results}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(resp)
	})


	// Subject search endpoint
	handler.HandleFunc("/access/v1/search/subject", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req AuthZenRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		// Mock response with sample subjects
		resp := AuthZenResponse{
			Decision: true,
			Context: EvaluationResponseContext{
				Reasons: []Reason{
					{
						ID: "subject1",
						ReasonAdmin: map[string]string{"message": "User has access"},
					},
				},
			},
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})

	// Resource search endpoint
	handler.HandleFunc("/access/v1/search/resource", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req AuthZenRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		// Mock response with sample resources
		resp := AuthZenResponse{
			Decision: true,
			Context: EvaluationResponseContext{
				Reasons: []Reason{
					{
						ID: "resource1",
						ReasonAdmin: map[string]string{"message": "Resource accessible"},
					},
				},
			},
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})

	// Action search endpoint
	handler.HandleFunc("/access/v1/search/action", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req AuthZenRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		// Mock response with sample actions
		resp := AuthZenResponse{
			Decision: true,
			Context: EvaluationResponseContext{
				Reasons: []Reason{
					{
						ID: "action1",
						ReasonAdmin: map[string]string{"action": "view"},
					},
				},
			},
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})

	return httptest.NewServer(handler)
}

// TestForceSchemeFromBase tests the forceSchemeFromBase method
func TestForceSchemeFromBase(t *testing.T) {
	tests := []struct {
		name     string
		baseURL  string
		input    string
		expected string
	}{
		{
			name:     "HTTP base with HTTPS URL",
			baseURL:  "http://example.com",
			input:    "https://example.com/api",
			expected: "http://example.com/api",
		},
		{
			name:     "HTTPS base with HTTP URL",
			baseURL:  "https://example.com",
			input:    "http://example.com/api",
			expected: "https://example.com/api",
		},
		{
			name:     "HTTP base with HTTP URL",
			baseURL:  "http://example.com",
			input:    "http://example.com/api",
			expected: "http://example.com/api",
		},
		{
			name:     "HTTPS base with HTTPS URL",
			baseURL:  "https://example.com",
			input:    "https://example.com/api",
			expected: "https://example.com/api",
		},
		{
			name:     "Non-HTTP URL",
			baseURL:  "http://example.com",
			input:    "ftp://example.com/api",
			expected: "ftp://example.com/api",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a test client with the base URL
			client := &AuthZenClient{
				baseURL: tt.baseURL,
			}
			
			// Get the actual result
			actual := client.forceSchemeFromBase(tt.input)
			
			// Verify the result
			assert.Equal(t, tt.expected, actual, "URL scheme should match base URL scheme")
		})
	}
}

func TestAuthZenScenarios(t *testing.T) {
	if os.Getenv("AUTHZEN_INTEGRATION") == "1" {
		t.Skip("Skipping mock server tests in integration mode")
	}

	// Set up mock server
	server := setupMockServer(t)
	defer server.Close()

	// Create a client that uses the mock server with a test authenticator
	authenticator := NewTestAuthenticator()
	client, err := NewAuthZenClient(server.URL, authenticator)
	require.NoError(t, err, "Failed to create AuthZen client")

	t.Run("Subject Search", func(t *testing.T) {
		testSubjectSearch(t, client)
	})

	t.Run("Resource Search", func(t *testing.T) {
		testResourceSearch(t, client)
	})

	t.Run("Action Search", func(t *testing.T) {
		testActionSearch(t, client)
	})
}

// testSubjectSearch tests the Subject Search API
func testSubjectSearch(t *testing.T, client *AuthZenClient) {
	// Test searching for users who can view a specific document
	resp, err := client.SearchSubjects("document", "doc123", "view", nil)
	require.NoError(t, err, "Subject search failed")
	assert.True(t, resp.Decision, "Expected successful decision")
	assert.NotEmpty(t, resp.Context.Reasons, "Expected reasons in response")
}

// testResourceSearch tests the Resource Search API
func testResourceSearch(t *testing.T, client *AuthZenClient) {
	// Test searching for documents a specific user can view
	resp, err := client.SearchResources("user", "user123", "document", "view", nil)
	require.NoError(t, err, "Resource search failed")
	assert.True(t, resp.Decision, "Expected successful decision")
	assert.NotEmpty(t, resp.Context.Reasons, "Expected reasons in response")
}

// testActionSearch tests the Action Search API
func testActionSearch(t *testing.T, client *AuthZenClient) {
	// Test searching for actions a user can perform on a specific document
	resp, err := client.SearchActions("user", "user123", "document", "doc123", nil)
	require.NoError(t, err, "Action search failed")
	assert.True(t, resp.Decision, "Expected successful decision")
	assert.NotEmpty(t, resp.Context.Reasons, "Expected reasons in response")
}


