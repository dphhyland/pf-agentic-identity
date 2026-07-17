package api

import (
	"idp-gm-api/pingfederate/grant"
)

// Grant represents a grant in the API according to OIDF Grant Management API spec (section 6.4)
type Grant struct {
	// ID is the unique identifier for the grant
	ID string `json:"id,omitempty"`
	// Scopes is an array of scope objects that define the permissions granted
	Scopes []Scope `json:"scopes"`
	// Claims is an array of claim names that are authorized for this grant
	Claims []string `json:"claims"`
	// AuthorizationDetails is an array of authorization details objects
	AuthorizationDetails []AuthorizationDetail `json:"authorization_details"`
	// CreatedAt is the timestamp (seconds since epoch) when the grant was created
	CreatedAt int64 `json:"created_at"`
	// LastUpdatedAt is the timestamp (seconds since epoch) when the grant was last updated
	LastUpdatedAt int64 `json:"last_updated_at"`
	// ExpiresAt is the timestamp (seconds since epoch) when the grant expires (optional)
	ExpiresAt *int64 `json:"expires_at"`
	// UpdatedBy indicates who last updated the grant (e.g., "client", "authorization_server")
	UpdatedBy string `json:"updated_by"`
}

// GrantResponse represents a response containing grant information for a single grant
type GrantResponse struct {
	Grant
}

// GrantsResponse represents a response containing multiple grants (for list operations)
type GrantsResponse struct {
	Grants []Grant `json:"grants"`
}

// Scope represents an OAuth 2.0 scope with optional resource indicators
type Scope struct {
	// Scope is the scope value
	Scope string `json:"scope"`
	// Resource is an array of resource indicators that the scope applies to
	Resource []string `json:"resource,omitempty"`
}

// AuthorizationDetail represents an OAuth 2.0 Authorization Details object
type AuthorizationDetail struct {
	// Type is the type of the authorization detail
	Type string `json:"type"`
	// Actions is an array of actions that are authorized
	Actions []string `json:"actions,omitempty"`
	// Locations is an array of resource locations that the authorization applies to
	Locations []string `json:"locations,omitempty"`
	// Identifier is a unique identifier for the resource
	Identifier string `json:"identifier,omitempty"`
	// Data contains additional authorization details
	Data map[string]interface{} `json:"data,omitempty"`
}

// ListGrantsRequest represents the request for listing grants
type ListGrantsRequest struct {
	// UserID is the user identifier to filter grants by (required)
	UserID string `json:"user_id"`
	// Scope is a space-separated list of scopes to filter grants by
	Scope string `json:"scope,omitempty"`
	// Limit is the maximum number of grants to return (for pagination)
	Limit int `json:"limit,omitempty"`
	// Cursor is a pagination token for fetching the next page of results
	Cursor string `json:"cursor,omitempty"`
}

// UpdateGrantRequest represents the request for updating a grant
type UpdateGrantRequest struct {
	Scopes []Scope `json:"scopes,omitempty"`
}

// ErrorResponse represents an error response
type ErrorResponse struct {
	Error       string `json:"error"`
	Description string `json:"description,omitempty"`
	Code        string `json:"code,omitempty"`
}

// toAPIGrant converts a grant.Grant to an API Grant according to OIDF Grant Management API spec
func toAPIGrant(g *grant.Grant) *Grant {
	if g == nil {
		return nil
	}

	// Convert scopes to the new format
	apiScopes := make([]Scope, 0, len(g.Scopes))
	for _, s := range g.Scopes {
		scope := Scope{
			Scope: s.Scope,
		}
		// If there are resources, add them
		if len(s.Resource) > 0 {
			scope.Resource = s.Resource
		}
		apiScopes = append(apiScopes, scope)
	}

	// Handle claims - use Claims field if available, otherwise check metadata
	var claims []string
	if len(g.Claims) > 0 {
		claims = g.Claims
	} else if g.Metadata != nil {
		if claimsRaw, ok := g.Metadata["claims"].([]interface{}); ok {
			claims = make([]string, 0, len(claimsRaw))
			for _, c := range claimsRaw {
				if claim, ok := c.(string); ok {
					claims = append(claims, claim)
				}
			}
		}
	}

	// Extract authorization details from AuthzDetails field if available
	var authDetails []AuthorizationDetail
	if g.AuthzDetails != nil && len(g.AuthzDetails) > 0 {
		authDetails = make([]AuthorizationDetail, 0, len(g.AuthzDetails))
		for _, ad := range g.AuthzDetails {
			detail := AuthorizationDetail{
				Type:       ad.Type,
				Actions:     ad.Actions,
				Locations:   ad.Locations,
				Identifier:  ad.Identifier,
			}
			// Copy additional fields to Data map
			if ad.Data != nil && len(ad.Data) > 0 {
				detail.Data = make(map[string]interface{})
				for k, v := range ad.Data {
					detail.Data[k] = v
				}
			}
			authDetails = append(authDetails, detail)
		}
	}

	// Create the grant with the new structure
	apiGrant := &Grant{
		ID:                   g.ID,
		Scopes:               apiScopes,
		Claims:               claims,
		AuthorizationDetails: authDetails,
		CreatedAt:            g.CreatedAt,
		LastUpdatedAt:        g.LastUpdatedAt,
	}

	// Set expires_at if available
	if g.ExpiresAt > 0 {
		expiresAt := g.ExpiresAt
		apiGrant.ExpiresAt = &expiresAt
	}

	// Set updated_by if available
	if g.UpdatedBy != "" {
		apiGrant.UpdatedBy = g.UpdatedBy
	} else {
		apiGrant.UpdatedBy = "client" // Default value per spec
	}

	return apiGrant
}

// toGrantRequest converts an UpdateGrantRequest to a grant.GrantRequest
func toGrantRequest(req *UpdateGrantRequest) *grant.GrantRequest {
	if req == nil {
		return nil
	}

	scopes := make([]grant.Scope, len(req.Scopes))
	for i, s := range req.Scopes {
		scopes[i] = grant.Scope{
			Scope:    s.Scope,
			Resource: s.Resource,
		}
	}

	return &grant.GrantRequest{
		Scopes: scopes,
	}
}
