//go:build integration

package authzen

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestAuthZenIntegration(t *testing.T) {
	// Skip if integration tests are not enabled
	if os.Getenv("AUTHZEN_INTEGRATION") == "" {
		t.Skip("Skipping integration test. Set AUTHZEN_INTEGRATION=1 to enable.")
	}

	t.Run("Test Force HTTP", testForceHTTP)

	// Run the rest of the tests with the regular client
	t.Run("Regular Client Tests", func(t *testing.T) {
		testAuthZenClient(t, false)
	})

	// Run tests with forceHTTP=true
	t.Run("Force HTTP Client Tests", func(t *testing.T) {
		testAuthZenClient(t, true)
	})
}

func testForceHTTP(t *testing.T) {
	// Test that forceHTTP parameter works as expected
	httpClient := &http.Client{
		Timeout: 30 * time.Second,
	}

	// Create a client with forceHTTP=true
	client, err := NewAuthZenClientWithHTTPClient("https://example.com/", NewBearerAuthenticator("test-token"), httpClient, true)
	require.NoError(t, err, "Failed to create client with forceHTTP=true")

	// Check that all endpoints use http://
	endpoints := []string{
		client.evaluateEndpoint,
		client.evaluationsEndpoint,
		client.subjectSearchEndpoint,
		client.resourceSearchEndpoint,
		client.actionSearchEndpoint,
	}

	for _, endpoint := range endpoints {
		assert.True(t, strings.HasPrefix(endpoint, "http://"), "Endpoint should use HTTP: %s", endpoint)
	}
}

func testAuthZenClient(t *testing.T, forceHTTP bool) {
	// Skip if integration tests are not enabled
	if os.Getenv("AUTHZEN_INTEGRATION") == "" {
		t.Skip("Skipping integration test. Set AUTHZEN_INTEGRATION=1 to enable.")
	}

	authZenURL := os.Getenv("AUTHZEN_URL")
	if authZenURL == "" {
		t.Fatal("AUTHZEN_URL environment variable is required for integration tests")
	}

	token := os.Getenv("AUTHZEN_TOKEN")
	if token == "" {
		t.Fatal("AUTHZEN_TOKEN environment variable is required for integration tests")
	}

	t.Logf("Creating AuthZen client with base URL: %s", authZenURL)
	
	// Create a new client with the specified forceHTTP setting
	httpClient := &http.Client{
		Timeout: 30 * time.Second,
	}

	// Create the client with the specified forceHTTP setting
	client, err := NewAuthZenClientWithHTTPClient(authZenURL, NewBearerAuthenticator(token), httpClient, forceHTTP)
	if err != nil {
		t.Fatalf("Failed to create AuthZen client: %v", err)
	}
	
	// Set the auth token in the auth client
	client.authClient.token = token
	client.SetLogLevel("debug")
	
	t.Logf("AuthZen client created successfully")
	t.Logf("Using endpoints:")
	t.Logf("- Evaluate: %s", client.GetEndpointURL("evaluate"))
	t.Logf("- Subject Search: %s", client.GetEndpointURL("subject_search"))
	t.Logf("- Resource Search: %s", client.GetEndpointURL("resource_search"))
	t.Logf("- Action Search: %s", client.GetEndpointURL("action_search"))
	t.Logf("Endpoints - Evaluate: %s, Subject Search: %s, Resource Search: %s, Action Search: %s",
		client.evaluateEndpoint,
		client.subjectSearchEndpoint,
		client.resourceSearchEndpoint,
		client.actionSearchEndpoint)

	t.Run("Subject Search", func(t *testing.T) {
		testSubjectSearchIntegration(t, client)
	})

	t.Run("Resource Search", func(t *testing.T) {
		testResourceSearchIntegration(t, client)
	})

	t.Run("Action Search", func(t *testing.T) {
		testActionSearchIntegration(t, client)
	})
}

func testSubjectSearchIntegration(t *testing.T, client *AuthZenClient) {
	t.Run("Basic Subject Search", func(t *testing.T) {
		// Test with interop sample data: Find all users who can view document doc123
		resp, err := client.SearchSubjects("document", "doc123", "read", nil)
		if err != nil {
			t.Logf("Subject search failed: %v", err)
			t.FailNow()
		}
		
		respJSON, _ := json.MarshalIndent(resp, "", "  ")
		t.Logf("Subject search response: %s", respJSON)
		
		// Basic assertions about the response structure
		require.NotNil(t, resp, "Response should not be nil")
		// The API returns results directly in the response
		if resp.Results == nil {
			t.Logf("No results in response, but this might be expected. Decision: %v", resp.Decision)
		} else if len(resp.Results) > 0 {
			t.Logf("Found %d resources in the response", len(resp.Results))
		} else {
			t.Logf("No resources found, but request was successful. Decision: %v", resp.Decision)
		}
	})

	t.Run("Subject Search with Context", func(t *testing.T) {
		// Test with interop sample data and context
		context := map[string]interface{}{
			"time":         time.Now().Format(time.RFC3339),
			"ip":           "192.168.1.1",
			"organization": "interop-sample",
		}
		
		resp, err := client.SearchSubjects("document", "doc123", "read", context)
		if err != nil {
			t.Logf("Subject search with context failed: %v", err)
			t.FailNow()
		}
		
		// The API returns results directly in the response
		if resp.Results == nil {
			t.Logf("No results in response, but this might be expected. Decision: %v", resp.Decision)
		} else if len(resp.Results) > 0 {
			t.Logf("Found %d subjects in the response", len(resp.Results))
		} else {
			t.Logf("No subjects found, but request was successful. Decision: %v", resp.Decision)
		}
	})
}

func testResourceSearchIntegration(t *testing.T, client *AuthZenClient) {
	t.Run("Basic Resource Search", func(t *testing.T) {
		// Test with interop sample data: Find all documents that user alice can read
		resp, err := client.SearchResources("user", "alice", "document", "read", nil)
		if err != nil {
			t.Logf("Resource search failed: %v", err)
			t.FailNow()
		}
		
		// Log the response for debugging
		respJSON, _ := json.MarshalIndent(resp, "", "  ")
		t.Logf("Resource search response: %s", respJSON)
		
		// Basic assertions about the response structure
		require.NotNil(t, resp, "Response should not be nil")
		
		// The API can return either results or a decision with reasons
		if resp.Results != nil {
			// If we have results, log how many we found
			t.Logf("Found %d resources in the response", len(resp.Results))
		} else {
			// If no results, check for a decision
			if resp.Decision {
				t.Logf("Decision is true")
			} else {
				t.Logf("Decision is false")
			}
			
			// Log any reasons if they exist
			if resp.Context.Reasons != nil && len(resp.Context.Reasons) > 0 {
				t.Logf("Reasons: %+v", resp.Context.Reasons)
			}
		}
	})

	t.Run("Resource Search with Context", func(t *testing.T) {
		// Test with interop sample data and context
		context := map[string]interface{}{
			"time":         time.Now().Format(time.RFC3339),
			"ip":           "192.168.1.1",
			"organization": "interop-sample",
		}
		
		resp, err := client.SearchResources("user", "alice", "document", "read", context)
		if err != nil {
			t.Logf("Resource search with context failed: %v", err)
			t.FailNow()
		}
		
		require.NotNil(t, resp, "Response should not be nil")
		if len(resp.Results) > 0 {
			t.Logf("Found %d resources in the response", len(resp.Results))
		} else {
			t.Logf("No resources found, decision: %v, reasons: %+v", resp.Decision, resp.Context.Reasons)
		}
	})
}

func testActionSearchIntegration(t *testing.T, client *AuthZenClient) {
	t.Run("Basic Action Search", func(t *testing.T) {
		// Test with interop sample data: Find all actions that user alice can perform on document doc123
		resp, err := client.SearchActions("user", "alice", "document", "doc123", nil)
		if err != nil {
			t.Logf("Action search failed: %v", err)
			t.FailNow()
		}
		
		require.NotNil(t, resp, "Response should not be nil")
		if len(resp.Results) > 0 {
			t.Logf("Found %d actions in the response", len(resp.Results))
		} else {
			t.Logf("No actions found, decision: %v, reasons: %+v", resp.Decision, resp.Context.Reasons)
		}
	})

	t.Run("Action Search with Context", func(t *testing.T) {
		// Test with interop sample data and context
		context := map[string]interface{}{
			"time":         time.Now().Format(time.RFC3339),
			"ip":           "192.168.1.1",
			"organization": "interop-sample",
		}
		
		resp, err := client.SearchActions("user", "alice", "document", "doc123", context)
		if err != nil {
			t.Logf("Action search with context failed: %v", err)
			t.FailNow()
		}
		
		require.NotNil(t, resp, "Response should not be nil")
		if len(resp.Results) > 0 {
			t.Logf("Found %d actions in the response", len(resp.Results))
		} else {
			t.Logf("No actions found with context, decision: %v, reasons: %+v", resp.Decision, resp.Context.Reasons)
		}
	})

	t.Run("Action Search with Different Resource", func(t *testing.T) {
		// Test with interop sample data: Find all actions that user bob can perform on document doc456
		resp, err := client.SearchActions("user", "bob", "document", "doc456", nil)
		if err != nil {
			t.Logf("Action search for different resource failed: %v", err)
			t.FailNow()
		}
		
		require.NotNil(t, resp, "Response should not be nil")
		if len(resp.Results) > 0 {
			t.Logf("Found %d actions in the response", len(resp.Results))
		} else {
			t.Logf("No actions found for different resource, decision: %v, reasons: %+v", resp.Decision, resp.Context.Reasons)
		}
	})
}
