package api

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"idp-gm-api/authzen"
	"idp-gm-api/pingfederate/grant"
)

func TestIsActionAllowedByGrant(t *testing.T) {
	tests := []struct {
		name     string
		action   string
		grant    *grant.Grant
		expected bool
	}{
		{
			name:   "No scopes or authz details - allow all",
			action: "read:document",
			grant: &grant.Grant{
				Scopes:       []grant.Scope{},
				AuthzDetails: []grant.AuthorizationDetail{},
			},
			expected: true,
		},
		{
			name:   "Exact scope match",
			action: "read:document",
			grant: &grant.Grant{
				Scopes: []grant.Scope{
					{Scope: "read:document"},
				},
			},
			expected: true,
		},
		{
			name:   "Wildcard scope match",
			action: "read:document",
			grant: &grant.Grant{
				Scopes: []grant.Scope{
					{Scope: "read:*"},
				},
			},
			expected: true,
		},
		{
			name:   "No match in scopes",
			action: "write:document",
			grant: &grant.Grant{
				Scopes: []grant.Scope{
					{Scope: "read:*"},
				},
			},
			expected: false,
		},
		{
			name:   "Action in scope resources",
			action: "read:document",
			grant: &grant.Grant{
				Scopes: []grant.Scope{
					{
						Scope:    "other:scope",
						Resource: []string{"read:document"},
					},
				},
			},
			expected: true,
		},
		{
			name:   "Action allowed by authz details",
			action: "document:read",
			grant: &grant.Grant{
				AuthzDetails: []grant.AuthorizationDetail{
					{
						Type:    "document",
						Actions: []string{"read"},
					},
				},
			},
			expected: true,
		},
		{
			name:   "Wildcard in authz details actions",
			action: "document:read",
			grant: &grant.Grant{
				AuthzDetails: []grant.AuthorizationDetail{
					{
						Type:    "document",
						Actions: []string{"*"},
					},
				},
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isActionAllowedByGrant(tt.action, tt.grant)
			assert.Equal(t, tt.expected, result, "isActionAllowedByGrant() = %v, want %v", result, tt.expected)
		})
	}
}

func TestIsResourceTypeAllowedByGrant(t *testing.T) {
	tests := []struct {
		name     string
		resource string
		grant    *grant.Grant
		expected bool
	}{
		{
			name:     "No scopes or authz details - allow all",
			resource: "document",
			grant: &grant.Grant{
				Scopes:       []grant.Scope{},
				AuthzDetails: []grant.AuthorizationDetail{},
			},
			expected: true,
		},
		{
			name:     "Exact scope match",
			resource: "document",
			grant: &grant.Grant{
				Scopes: []grant.Scope{
					{Scope: "document:read"},
				},
			},
			expected: true,
		},
		{
			name:     "Resource in scope resources",
			resource: "document",
			grant: &grant.Grant{
				Scopes: []grant.Scope{
					{
						Scope:    "other:scope",
						Resource: []string{"document"},
					},
				},
			},
			expected: true,
		},
		{
			name:     "Wildcard in scope resources",
			resource: "document:123",
			grant: &grant.Grant{
				Scopes: []grant.Scope{
					{
						Scope:    "other:scope",
						Resource: []string{"document:*"},
					},
				},
			},
			expected: true,
		},
		{
			name:     "Resource allowed by authz details type",
			resource: "document",
			grant: &grant.Grant{
				AuthzDetails: []grant.AuthorizationDetail{
					{
						Type: "document",
					},
				},
			},
			expected: true,
		},
		{
			name:     "Resource allowed by authz details locations",
			resource: "document",
			grant: &grant.Grant{
				AuthzDetails: []grant.AuthorizationDetail{
					{
						Type:     "other",
						Locations: []string{"document"},
					},
				},
			},
			expected: true,
		},
		{
			name:     "Wildcard in authz details locations",
			resource: "document:123",
			grant: &grant.Grant{
				AuthzDetails: []grant.AuthorizationDetail{
					{
						Type:     "other",
						Locations: []string{"document:*"},
					},
				},
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isResourceTypeAllowedByGrant(tt.resource, tt.grant)
			assert.Equal(t, tt.expected, result, "isResourceTypeAllowedByGrant() = %v, want %v", result, tt.expected)
		})
	}
}

// Helper function to create a test context with token claims
func createTestContext() context.Context {
	claims := map[string]interface{}{
		"sub":       "user-123",
		"client_id": "test-client",
	}
	return context.WithValue(context.Background(), "token_claims", claims)
}

// isResourceTypeAllowedByGrant checks if a resource type is allowed by the grant's scopes or authorization details
func isResourceTypeAllowedByGrant(resourceType string, g *grant.Grant) bool {
	// If no scopes or authorization details are defined, all resource types are allowed
	if len(g.Scopes) == 0 && len(g.AuthzDetails) == 0 {
		return true
	}

	// 1. Check if the resource type is allowed by any scope
	for _, scope := range g.Scopes {
		// Check the main scope string (e.g., "documents:read")
		if strings.HasPrefix(scope.Scope, resourceType+":") || scope.Scope == resourceType || scope.Scope == "*" {
			return true
		}

		// Check if the resource type is in the scope's resources
		for _, resource := range scope.Resource {
			if resource == resourceType || resource == "*" {
				return true
			}

			// Handle wildcard matching (e.g., "documents:*" matches "documents:123")
			if strings.HasSuffix(resource, ":*") && strings.HasPrefix(resourceType, strings.TrimSuffix(resource, ":*")) {
				return true
			}
		}
	}

	// 2. Check if the resource type is allowed by any authorization details
	for _, authzDetail := range g.AuthzDetails {
		// Check if the authorization detail type matches the resource type
		if authzDetail.Type == resourceType || authzDetail.Type == "*" {
			return true
		}

		// Check if the resource type is in the authorization detail's locations
		for _, location := range authzDetail.Locations {
			if location == resourceType || location == "*" {
				return true
			}

			// Handle wildcard matching
			if strings.HasSuffix(location, ":*") && strings.HasPrefix(resourceType, strings.TrimSuffix(location, ":*")) {
				return true
			}
		}

		// Check if the resource type matches the authorization detail's identifier pattern
		if authzDetail.Identifier != "" {
			// Simple check - if the resource type is part of the identifier
			if strings.Contains(authzDetail.Identifier, resourceType) {
				return true
			}
		}
	}

	// Resource type not explicitly allowed by any scope or authorization detail
	return false
}

func TestGrantConstraintIntegration(t *testing.T) {
	// Test the integration of grant constraints with the evaluation flow
	grantID := "test-grant-id"
	ctx := createTestContext()

	t.Run("Action allowed by scope", func(t *testing.T) {
		// Setup mocks
		mockGrant := &mockGrantClient{}
		mockAuthZen := &mockAuthZenClient{}

		// Create test service with mocks
		service := &TestGrantService{
			grantClient:   mockGrant,
			authZenClient: mockAuthZen,
		}

		// Setup grant with specific scope
		grant := &grant.Grant{
			ID:        grantID,
			UserID:    "user-123",
			ClientID:  "test-client",
			Status:    "ACTIVE",
			ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
			Scopes: []grant.Scope{
				{Scope: "read:*"},
			},
		}

		// Setup request
		req := &EvaluateGrantRequest{
			Resource: &ResourceRef{
				Type: "document",
				ID:   "doc-123",
			},
			Action: &ActionRef{
				Name: "read:document",
			},
		}

		// Configure mocks
		mockGrant.On("GetGrant", ctx, grantID).Return(grant, nil)

		// Set up the expected AuthZen response
		authZenResp := &authzen.AuthZenResponse{
			Decision: true,
		}
		
		// Use mock.MatchedBy to match the request body
		mockAuthZen.On("MakeRequest", "/api/v1/evaluate", "POST", mock.MatchedBy(func(body interface{}) bool {
			req, ok := body.(map[string]interface{})
			if !ok {
				return false
			}
			
			// Check required fields
			subject, ok1 := req["subject"].(map[string]interface{})
			resource, ok2 := req["resource"].(map[string]interface{})
		action, ok3 := req["action"].(map[string]interface{})
		if !ok1 || !ok2 || !ok3 {
			return false
		}
		
		// Check subject
		if subject["type"] != "user" || subject["id"] != "user-123" {
			return false
		}
		
		// Check resource
		if resource["type"] != "document" || resource["id"] != "doc-123" {
			return false
		}
		
		// Check action
		if action["name"] != "read:document" {
			return false
		}
		
		return true
	})).Return(authZenResp, nil)

		// Call the method
		resp, err := service.EvaluateGrant(ctx, grantID, req, "test-token")

		// Assert results
		assert.NoError(t, err)
		assert.NotNil(t, resp)
		assert.True(t, resp.Decision)

		// Verify mock expectations
		mockGrant.AssertExpectations(t)
		mockAuthZen.AssertExpectations(t)
	})

	t.Run("Action denied by scope", func(t *testing.T) {
		// Setup mocks
		mockGrant := &mockGrantClient{}
		mockAuthZen := &mockAuthZenClient{}

		// Create test service with mocks
		service := &TestGrantService{
			grantClient:   mockGrant,
			authZenClient: mockAuthZen,
		}

		// Setup grant with specific scope that doesn't allow the action
		grant := &grant.Grant{
			ID:        grantID,
			UserID:    "user-123",
			ClientID:  "test-client",
			Status:    "ACTIVE",
			ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
			Scopes: []grant.Scope{
				{Scope: "read:public"}, // Doesn't match our requested action
			},
		}

		// Setup request
		req := &EvaluateGrantRequest{
			Resource: &ResourceRef{
				Type: "document",
				ID:   "doc-123",
			},
			Action: &ActionRef{
				Name: "write:document",
			},
		}

		// Configure mocks
		mockGrant.On("GetGrant", ctx, grantID).Return(grant, nil)

		// We don't expect AuthZen to be called since the action is denied by scope

		// Call the method
		resp, err := service.EvaluateGrant(ctx, grantID, req, "test-token")

		// Assert results
		assert.NoError(t, err)
		assert.NotNil(t, resp)
		assert.False(t, resp.Decision)

		// Verify mock expectations
		mockGrant.AssertExpectations(t)
		mockAuthZen.AssertExpectations(t)
	})
}
