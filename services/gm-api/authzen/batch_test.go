package authzen

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBatchEvaluate(t *testing.T) {
	// Setup test server with a handler that captures the request
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify request method and path
		if r.URL.Path != "/access/v1/evaluations" {
			http.NotFound(w, r)
			return
		}

		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Parse the request body
		var batchReq BatchEvaluateRequest
		if err := json.NewDecoder(r.Body).Decode(&batchReq); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		// Create a proper batch response with the same number of results as requests
		batchResp := BatchEvaluateResponse{
			Results: make([]BatchEvaluationResponse, len(batchReq.Requests)),
		}

		for i, req := range batchReq.Requests {
			// For testing, we'll allow 'read' actions and deny others
			allowed := req.Action.Name == "read"
			
			reason := "Access denied"
			if allowed {
				reason = "Access granted for testing"
			}

			batchResp.Results[i] = BatchEvaluationResponse{
				Decision: allowed,
				Context: EvaluationResponseContext{
					Reasons: []Reason{
						{
							ID: "test-reason",
							ReasonUser: map[string]string{
								"en": reason,
							},
						},
					},
				},
			}
		}

		// Send the response
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(batchResp)
	}))
	defer server.Close()

	// Test cases
	tests := []struct {
		name           string
		setupClient   func() *AuthZenClient
		requests      []BatchEvaluationRequest
		expectedError bool
	}{
		{
			name: "successful batch evaluation",
			setupClient: func() *AuthZenClient {
				authenticator := NewTestAuthenticator()
				client, _ := NewAuthZenClient(server.URL, authenticator)
				// Override the evaluations endpoint to use our test server
				client.evaluationsEndpoint = server.URL + "/access/v1/evaluations"
				return client
			},
			requests: []BatchEvaluationRequest{
				{
					Subject:  Subject{Type: "user", ID: "user1"},
					Action:   Action{Name: "read"},
					Resource: Resource{Type: "document", ID: "doc1"},
				},
				{
					Subject:  Subject{Type: "user", ID: "user1"},
					Action:   Action{Name: "write"},
					Resource: Resource{Type: "document", ID: "doc1"},
				},
			},
			expectedError: false,
		},
		{
			name: "empty requests",
			setupClient: func() *AuthZenClient {
				authenticator := NewTestAuthenticator()
				client, _ := NewAuthZenClient(server.URL, authenticator)
				return client
			},
			requests:      []BatchEvaluationRequest{},
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := tt.setupClient()
			_, err := client.BatchEvaluate(tt.requests)

			if tt.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
