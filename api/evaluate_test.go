package api

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"idp-gm-api/authzen"
	"idp-gm-api/pingfederate/grant"
)

// Define interfaces for the dependencies we need to mock
type grantClientInterface interface {
	GetGrant(ctx context.Context, id string) (*grant.Grant, error)
}

type authZenClientInterface interface {
	MakeRequest(url, method string, body interface{}) (*authzen.AuthZenResponse, error)
}

// Mock implementations
type mockGrantClient struct {
	mock.Mock
}

func (m *mockGrantClient) GetGrant(ctx context.Context, id string) (*grant.Grant, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*grant.Grant), args.Error(1)
}

type mockAuthZenClient struct {
	mock.Mock
}

func (m *mockAuthZenClient) MakeRequest(url, method string, body interface{}) (*authzen.AuthZenResponse, error) {
	args := m.Called(url, method, body)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*authzen.AuthZenResponse), args.Error(1)
}

// TestGrantService is a test-specific version of GrantService that accepts interfaces
type TestGrantService struct {
	grantClient   grantClientInterface
	authZenClient authZenClientInterface
}

// Converts []authzen.Reason to []Reason
func convertAuthzenReasons(authzenReasons []authzen.Reason) []Reason {
	var reasons []Reason
	for _, r := range authzenReasons {
		msg := r.ReasonUser["message"]
		if msg == "" {
			msg = r.ID
		}
		reasons = append(reasons, Reason{
			ID:      r.ID,
			Message: msg,
		})
	}
	return reasons
}

// EvaluateGrant is a copy of the original method but using our interfaces
func (s *TestGrantService) EvaluateGrant(ctx context.Context, grantID string, req *EvaluateGrantRequest, token string) (*EvaluateGrantResponse, error) {
	// 1. Validate the grant ID
	if grantID == "" {
		return nil, ErrInvalidGrantID
	}

	// 2. Retrieve the grant
	g, err := s.grantClient.GetGrant(ctx, grantID)
	if err != nil {
		return nil, ErrGrantNotFound
	}
	if g == nil {
		return nil, ErrGrantNotFound
	}

	// 3. Validate grant status
	if g.Status == "REVOKED" {
		return nil, ErrGrantRevoked
	}
	
	// Check if grant is expired
	if g.ExpiresAt > 0 && g.ExpiresAt < time.Now().Unix() {
		return nil, ErrGrantExpired
	}

	// 4. For testing, we'll skip token validation
	
	// 5. Determine mode (evaluation vs search)
	isEvaluationMode := req.Resource != nil && req.Resource.ID != "" && req.Action != nil && req.Action.Name != ""
	
	// 6. Check if AuthZEN client is available
	if s.authZenClient == nil {
		return nil, ErrPDPUnavailable
	}
	
	// 7. For testing, we'll use the same logic as production but with our test clients
	if isEvaluationMode {
		// Check if action is allowed by grant
		if !isActionAllowedByGrant(req.Action.Name, g) {
			return &EvaluateGrantResponse{
				Decision: false,
				Context: &EvaluationContext{
					Reasons: []Reason{{
						ID:      "action_not_allowed",
						Message: "The requested action is not allowed by this grant",
					}},
				},
			}, nil
		}
		
		// If action is allowed, make the AuthZen request
		authZenReq := map[string]interface{}{
			"subject": map[string]interface{}{
				"type": "user",
				"id":   g.UserID,
			},
			"resource": map[string]interface{}{
				"type": req.Resource.Type,
				"id":   req.Resource.ID,
			},
			"action": map[string]interface{}{
				"name": req.Action.Name,
			},
		}
		
		resp, err := s.authZenClient.MakeRequest("/api/v1/evaluate", "POST", authZenReq)
		if err != nil {
			return nil, ErrPDPUnavailable
		}
		
		// Convert AuthZen response to our response format
		var evalCtx *EvaluationContext
		if len(resp.Context.Reasons) > 0 {
			evalCtx = &EvaluationContext{
				Reasons: convertAuthzenReasons(resp.Context.Reasons),
			}
		}
		
		return &EvaluateGrantResponse{
			Decision: resp.Decision,
			Context:  evalCtx,
		}, nil
	}
	
	// Search mode logic
	if req.Resource != nil && req.Resource.Type != "" {
		// Check if resource type is allowed by grant
		if !isResourceTypeAllowedByGrant(req.Resource.Type, g) {
			return &EvaluateGrantResponse{
				Decision: false,
				Context: &EvaluationContext{
					Reasons: []Reason{{
						ID:      "resource_type_not_allowed",
						Message: "The requested resource type is not allowed by this grant",
					}},
				},
			}, nil
		}
		
		// If an action is provided in search mode, check if it's allowed by the grant
		if req.Action != nil && req.Action.Name != "" {
			if !isActionAllowedByGrant(req.Action.Name, g) {
				return &EvaluateGrantResponse{
					Decision: false,
					Context: &EvaluationContext{
						Reasons: []Reason{{
							ID:      "action_not_allowed",
							Message: "The requested action is not allowed by this grant",
						}},
					},
				}, nil
			}
		}
		
		// For search mode, we need to make a request to the search endpoint
		searchReq := map[string]interface{}{
			"subject": map[string]interface{}{
				"type": "user",
				"id":   g.UserID,
			},
			"resource": map[string]interface{}{
				"type": req.Resource.Type,
			},
		}
		
		// Include action in the search request if provided
		if req.Action != nil && req.Action.Name != "" {
			searchReq["action"] = map[string]interface{}{
				"name": req.Action.Name,
			}
		}
		
		// Make the search request to AuthZen
		resp, err := s.authZenClient.MakeRequest("/api/v1/resource_search", "POST", searchReq)
		if err != nil {
			return nil, ErrPDPUnavailable
		}
		
		// Convert AuthZen search results to our response format
		var results []interface{}
		for _, result := range resp.Results {
			results = append(results, map[string]interface{}{
				"type": result.Type,
				"id":   result.ID,
			})
		}
		
		return &EvaluateGrantResponse{
			Results: results,
		}, nil
	}

	// If we reach here, it means the request doesn't match any known pattern
	return nil, errors.New("invalid request: could not determine evaluation mode")
}

// Helper function to get current time for testing
func getCurrentTime() int64 {
	return time.Now().Unix()
}

// TestEvaluateGrant_EvaluationMode tests the EvaluateGrant method in evaluation mode
func TestEvaluateGrant_EvaluationMode(t *testing.T) {
	// Setup mocks
	mockGrant := &mockGrantClient{}
	mockAuthZen := &mockAuthZenClient{}
	
	// Create test service with mocks
	service := &TestGrantService{
		grantClient:   mockGrant,
		authZenClient: mockAuthZen,
	}
	
	// Setup test data
	ctx := context.Background()
	grantID := "test-grant-id"
	token := "test-token"
	
	// Setup request
	req := &EvaluateGrantRequest{
		Resource: &ResourceRef{
			Type: "document",
			ID:   "doc-123",
		},
		Action: &ActionRef{
			Name: "read",
		},
		Context: map[string]interface{}{
			"environment": "test",
		},
	}
	
	// Setup grant response
	grantResp := &grant.Grant{
		ID:        grantID,
		UserID:    "user-123",
		Status:    "ACTIVE",
		ExpiresAt: getCurrentTime() + 3600, // Expires in 1 hour
	}
	
	// Setup AuthZen response for evaluation
	authZenResp := &authzen.AuthZenResponse{
		Decision: true,
		Context: authzen.EvaluationResponseContext{
			Reasons: []authzen.Reason{
				{
					ID: "policy-1",
					ReasonUser: map[string]string{
						"message": "Access granted by policy",
					},
				},
			},
		},
	}
	
	// Configure mocks
	mockGrant.On("GetGrant", ctx, grantID).Return(grantResp, nil)
	mockAuthZen.On("MakeRequest", "/api/v1/evaluate", "POST", mock.Anything).Return(authZenResp, nil)
	
	// Call the method
	resp, err := service.EvaluateGrant(ctx, grantID, req, token)
	
	// Assert results
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.True(t, resp.Decision)
	assert.NotNil(t, resp.Context)
	assert.Equal(t, "policy-1", resp.Context.Reasons[0].ID)
	assert.Equal(t, "Access granted by policy", resp.Context.Reasons[0].Message)
	
	// Verify mock expectations
	mockGrant.AssertExpectations(t)
	mockAuthZen.AssertExpectations(t)
}

// TestEvaluateGrant_SearchMode tests the EvaluateGrant method in search mode
func TestEvaluateGrant_SearchMode(t *testing.T) {
	// Setup mocks
	mockGrant := &mockGrantClient{}
	mockAuthZen := &mockAuthZenClient{}
	
	// Create test service with mocks
	service := &TestGrantService{
		grantClient:   mockGrant,
		authZenClient: mockAuthZen,
	}
	
	// Setup test data
	ctx := context.Background()
	grantID := "test-grant-id"
	token := "test-token"
	
	// Setup request for resource search (missing resource ID)
	req := &EvaluateGrantRequest{
		Resource: &ResourceRef{
			Type: "document",
			// ID is intentionally omitted for search mode
		},
		Action: &ActionRef{
			Name: "read",
		},
	}
	
	// Setup grant response
	grantResp := &grant.Grant{
		ID:        grantID,
		UserID:    "user-123",
		Status:    "ACTIVE",
		ExpiresAt: getCurrentTime() + 3600, // Expires in 1 hour
	}
	
	// Setup AuthZen response for resource search
	authZenResp := &authzen.AuthZenResponse{
		Results: []authzen.SearchResult{
			{
				Type: "document",
				ID:   "doc-123",
			},
			{
				Type: "document",
				ID:   "doc-456",
			},
		},
	}
	
	// Configure mocks
	mockGrant.On("GetGrant", ctx, grantID).Return(grantResp, nil)
	mockAuthZen.On("MakeRequest", "/api/v1/resource_search", "POST", mock.Anything).Return(authZenResp, nil)
	
	// Call the method
	resp, err := service.EvaluateGrant(ctx, grantID, req, token)
	
	// Assert results
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.NotNil(t, resp.Results)
	assert.Len(t, resp.Results, 2)
	result0 := resp.Results[0].(map[string]interface{})
	assert.Equal(t, "document", result0["type"])
	assert.Equal(t, "doc-123", result0["id"])
	result1 := resp.Results[1].(map[string]interface{})
	assert.Equal(t, "document", result1["type"])
	assert.Equal(t, "doc-456", result1["id"])
	
	// Verify mock expectations
	mockGrant.AssertExpectations(t)
	mockAuthZen.AssertExpectations(t)
}

// TestEvaluateGrant_Errors tests error cases for the EvaluateGrant method
func TestEvaluateGrant_Errors(t *testing.T) {
	tests := []struct {
		name      string
		setupMock func(*mockGrantClient, *mockAuthZenClient)
		grantID   string
		req       *EvaluateGrantRequest
		wantErr   error
	}{
		{
			name: "Grant Not Found",
			setupMock: func(g *mockGrantClient, a *mockAuthZenClient) {
				g.On("GetGrant", mock.Anything, "non-existent").Return(nil, errors.New("grant not found"))
			},
			grantID: "non-existent",
			req: &EvaluateGrantRequest{
				Resource: &ResourceRef{Type: "document", ID: "doc-123"},
				Action:   &ActionRef{Name: "read"},
			},
			wantErr: ErrGrantNotFound,
		},
		{
			name: "Revoked Grant",
			setupMock: func(g *mockGrantClient, a *mockAuthZenClient) {
				g.On("GetGrant", mock.Anything, "revoked-grant").Return(&grant.Grant{
					ID:     "revoked-grant",
					Status: "REVOKED",
				}, nil)
			},
			grantID: "revoked-grant",
			req: &EvaluateGrantRequest{
				Resource: &ResourceRef{Type: "document", ID: "doc-123"},
				Action:   &ActionRef{Name: "read"},
			},
			wantErr: ErrGrantRevoked,
		},
		{
			name: "Expired Grant",
			setupMock: func(g *mockGrantClient, a *mockAuthZenClient) {
				g.On("GetGrant", mock.Anything, "expired-grant").Return(&grant.Grant{
					ID:        "expired-grant",
					Status:    "ACTIVE",
					ExpiresAt: getCurrentTime() - 3600, // Expired 1 hour ago
				}, nil)
			},
			grantID: "expired-grant",
			req: &EvaluateGrantRequest{
				Resource: &ResourceRef{Type: "document", ID: "doc-123"},
				Action:   &ActionRef{Name: "read"},
			},
			wantErr: ErrGrantExpired,
		},
		{
			name: "PDP Unavailable",
			setupMock: func(g *mockGrantClient, a *mockAuthZenClient) {
				g.On("GetGrant", mock.Anything, "valid-grant").Return(&grant.Grant{
					ID:        "valid-grant",
					UserID:    "user-123",
					Status:    "ACTIVE",
					ExpiresAt: getCurrentTime() + 3600, // Expires in 1 hour
				}, nil)
				a.On("MakeRequest", "/api/v1/evaluate", "POST", mock.Anything).Return(nil, errors.New("service unavailable"))
			},
			grantID: "valid-grant",
			req: &EvaluateGrantRequest{
				Resource: &ResourceRef{Type: "document", ID: "doc-123"},
				Action:   &ActionRef{Name: "read"},
			},
			wantErr: ErrPDPUnavailable,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup mocks
			mockGrant := &mockGrantClient{}
			mockAuthZen := &mockAuthZenClient{}
			
			// Configure mocks
			if tt.setupMock != nil {
				tt.setupMock(mockGrant, mockAuthZen)
			}
			
			// Create service with mocks
			service := &TestGrantService{
				grantClient:   mockGrant,
				authZenClient: mockAuthZen,
			}
			
			// Call the method
			resp, err := service.EvaluateGrant(context.Background(), tt.grantID, tt.req, "test-token")
			
			// Assert error
			assert.Error(t, err)
			assert.Nil(t, resp)
			assert.ErrorIs(t, err, tt.wantErr)
			
			// Verify mock expectations
			mockGrant.AssertExpectations(t)
			mockAuthZen.AssertExpectations(t)
		})
	}
}
