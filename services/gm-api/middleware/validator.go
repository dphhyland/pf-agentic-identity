package middleware

import (
	"errors"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

// InMemoryTokenValidator is a simple token validator for testing purposes.
// In production, replace this with a proper JWT validator that verifies tokens
// against your OAuth provider.
type InMemoryTokenValidator struct {
	// In a real implementation, this would verify tokens against an OAuth provider
}

// NewInMemoryTokenValidator creates a new in-memory token validator
func NewInMemoryTokenValidator() *InMemoryTokenValidator {
	return &InMemoryTokenValidator{}
}

// ValidateToken validates a token and returns its claims
func (v *InMemoryTokenValidator) ValidateToken(tokenString string) (*TokenClaims, error) {
	// This is a simplified implementation for testing
	// In production, you would verify the token signature and expiration

	// For testing, we'll accept any token that starts with "test_"
	if !strings.HasPrefix(tokenString, "test_") {
		return nil, errors.New("invalid token format")
	}

	// Extract client ID from the token (for testing, we'll just use part of the token)
	clientID := "test_client"
	if len(tokenString) > 5 {
		clientID = tokenString[5:]
		if len(clientID) > 10 {
			clientID = clientID[:10]
		}
	}

	// For testing, we'll return a set of claims with some test data
	return &TokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject: "test_user",
		},
		ClientID: clientID,
		Scopes:   []string{"grant_management_query", "grant_management_revoke", "grant_management_evaluate"},
	}, nil
}
