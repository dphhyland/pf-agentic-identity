package middleware

import (
	"net/http"
	"os"
)

// AuthConfig holds configuration for authentication middleware
type AuthConfig struct {
	// TokenValidator is responsible for validating access tokens
	TokenValidator TokenValidator
	
	// RequiredScopes maps HTTP methods to the required OAuth scopes
	RequiredScopes map[string]string

	// SubjectClaimName is the name of the claim to use as the subject (e.g., "sub", "username")
	// If empty, defaults to "sub"
	SubjectClaimName string
}

// DefaultAuthConfig creates a default authentication configuration
func DefaultAuthConfig() *AuthConfig {
	subjectClaimName := "sub" // Default to standard "sub" claim
	if envClaimName := os.Getenv("SUBJECT_CLAIM_NAME"); envClaimName != "" {
		subjectClaimName = envClaimName
	}

	return &AuthConfig{
		TokenValidator:    NewInMemoryTokenValidator(),
		SubjectClaimName: subjectClaimName,
		RequiredScopes: map[string]string{
			http.MethodGet:    "grant_management_query",
			http.MethodPost:   "grant_management_evaluate",
			http.MethodPut:    "grant_management_update",
			http.MethodPatch:  "grant_management_update",
			http.MethodDelete: "grant_management_revoke",
		},
	}
}

// GetRequiredScope returns the required scope for an HTTP method
func (c *AuthConfig) GetRequiredScope(method string) string {
	if scope, ok := c.RequiredScopes[method]; ok {
		return scope
	}
	// Default to most permissive scope if method not explicitly mapped
	return "grant_management_query"
}
