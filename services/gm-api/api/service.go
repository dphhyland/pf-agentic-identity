package api

import (
	"context"
	"fmt"
	"log"

	"idp-gm-api/authzen"
	"idp-gm-api/pingfederate/grant"
)

// GrantService handles business logic for grant operations
type GrantService struct {
	grantClient  *grant.Client
	authZenClient *authzen.AuthZenClient
}

// NewGrantService creates a new GrantService
func NewGrantService(grantClient *grant.Client, authZenClient *authzen.AuthZenClient) *GrantService {
	return &GrantService{
		grantClient:  grantClient,
		authZenClient: authZenClient,
	}
}

// GetGrant retrieves a grant by ID for a specific user
func (s *GrantService) GetGrant(ctx context.Context, userID, id string) (*Grant, error) {
	if id == "" {
		return nil, fmt.Errorf("grant ID is required")
	}

	if userID == "" {
		return nil, fmt.Errorf("user ID is required")
	}

	g, err := s.grantClient.GetGrant(ctx, userID, id)
	if err != nil {
		return nil, fmt.Errorf("failed to get grant: %w", err)
	}

	return toAPIGrant(g), nil
}

// ListClientGrants lists grants for a specific client
func (s *GrantService) ListClientGrants(ctx context.Context, clientID string) ([]*Grant, error) {
	params := grant.GrantQueryParams{ClientID: clientID}
	grants, err := s.grantClient.ListGrants(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("failed to list grants: %w", err)
	}
	out := make([]*Grant, len(grants))
	for i, g := range grants {
		out[i] = toAPIGrant(&g)
	}
	return out, nil
}

// ListUserGrants lists grants for a specific userKey
func (s *GrantService) ListUserGrants(ctx context.Context, userKey string) ([]*Grant, error) {
	params := grant.GrantQueryParams{UserID: userKey}
	grants, err := s.grantClient.ListGrants(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("failed to list grants: %w", err)
	}
	out := make([]*Grant, len(grants))
	for i, g := range grants {
		out[i] = toAPIGrant(&g)
	}
	return out, nil
}

// RevokeClientGrants revokes grants for client; if grantID empty revokes all.
func (s *GrantService) RevokeClientGrants(ctx context.Context, clientID, grantID string) error {
	return s.grantClient.RevokeGrants(ctx, clientID, "", grantID)
}

// RevokeUserGrants revokes grants for userKey; if grantID empty revokes all.
func (s *GrantService) RevokeUserGrants(ctx context.Context, userKey, grantID string) error {
	return s.grantClient.RevokeGrants(ctx, "", userKey, grantID)
}
func (s *GrantService) ListGrants(ctx context.Context, req *ListGrantsRequest) ([]*Grant, error) {
	log.Printf("[DEBUG] Service.ListGrants: Starting with request: %+v", req)

	if s.grantClient == nil {
		log.Printf("[ERROR] Service.ListGrants: Grant client is nil!")
		return nil, fmt.Errorf("grant client is not initialized")
	}

	if req.UserID == "" {
		log.Printf("[ERROR] Service.ListGrants: UserID is required")
		return nil, fmt.Errorf("userID is required")
	}

	log.Printf("[DEBUG] Service.ListGrants: Calling grant client ListGrants with userID: %s", req.UserID)
	
	// Create query params with the user ID from the request
	params := grant.GrantQueryParams{
		UserID: req.UserID,
	}
	
	grants, err := s.grantClient.ListGrants(ctx, params)
	if err != nil {
		log.Printf("[ERROR] Service.ListGrants: Failed to list grants: %v", err)
		return nil, fmt.Errorf("failed to list grants: %w", err)
	}

	log.Printf("[DEBUG] Service.ListGrants: Successfully retrieved %d grants for user: %s", len(grants), req.UserID)
	result := make([]*Grant, len(grants))
	for i := range grants {
		result[i] = toAPIGrant(&grants[i])
	}

	return result, nil
}

// UpdateGrant updates a grant's scopes
func (s *GrantService) UpdateGrant(ctx context.Context, id string, req *UpdateGrantRequest) (*Grant, error) {
	if id == "" {
		return nil, fmt.Errorf("grant ID is required")
	}

	grantReq := toGrantRequest(req)
	updated, err := s.grantClient.UpdateGrant(ctx, id, *grantReq)
	if err != nil {
		return nil, fmt.Errorf("failed to update grant: %w", err)
	}

	return toAPIGrant(updated), nil
}

// RevokeGrant revokes a grant
func (s *GrantService) RevokeGrant(ctx context.Context, id string) error {
	if id == "" {
		return fmt.Errorf("grant ID is required")
	}

	if err := s.grantClient.RevokeGrant(ctx, id); err != nil {
		return fmt.Errorf("failed to revoke grant: %w", err)
	}

	return nil
}
