package config

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"idp-gm-api/middleware"
)

// formatOnlyValidator is a token validator that only checks token format without verifying the signature
type formatOnlyValidator struct {
	subjectClaimName string
}

// ValidateToken implements TokenValidator interface
func (v *formatOnlyValidator) ValidateToken(tokenString string) (*middleware.TokenClaims, error) {
	// Parse the token without verifying the signature
	token, _, err := new(jwt.Parser).ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		return nil, fmt.Errorf("invalid token format: %w", err)
	}

	// Convert claims to TokenClaims
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("invalid token claims format")
	}

	// Log all claims for debugging
	log.Printf("[DEBUG] Token claims: %+v", claims)

	// Check if token is expired
	if exp, ok := claims["exp"].(float64); ok {
		if time.Now().Unix() > int64(exp) {
			return nil, errors.New("token is expired")
		}
	}

	// Extract subject from claims
	subjectClaimName := v.subjectClaimName
	if subjectClaimName == "" {
		subjectClaimName = "sub" // Default to standard claim name if not specified
	}

	var subject string
	if sub, ok := claims[subjectClaimName]; ok {
		subject, _ = sub.(string)
		log.Printf("[DEBUG] Found subject '%s' in claim '%s'", subject, subjectClaimName)
	} else if sub, ok := claims["sub"]; ok {
		// Fall back to standard 'sub' claim
		subject, _ = sub.(string)
		log.Printf("[DEBUG] Using fallback 'sub' claim with value: %s", subject)
	}

	if subject == "" {
		log.Printf("[DEBUG] No subject claim found in token (tried: %s, sub)", subjectClaimName)
	}

	// Extract client ID
	clientID, _ := claims["client_id"].(string)

	// Convert scopes to string slice
	var scopes []string
	switch s := claims["scope"].(type) {
	case string:
		scopes = strings.Fields(s)
	case []interface{}:
		scopes = make([]string, 0, len(s))
		for _, v := range s {
			if str, ok := v.(string); ok {
				scopes = append(scopes, str)
			}
		}
	}

	// Create and return TokenClaims with the subject
	tokenClaims := &middleware.TokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject: subject, // This will be set to the extracted subject or empty string
		},
		ClientID: clientID,
		Scopes:   scopes,
		Claims:   claims,
	}

	log.Printf("[DEBUG] Created token claims - Subject: '%s', ClientID: '%s', Scopes: %v", 
		tokenClaims.GetSubjectValue(), clientID, scopes)

	if subject == "" {
		log.Printf("[DEBUG] No subject claim found in token, using empty string")
	} else {
		log.Printf("[DEBUG] Using subject: %s", subject)
	}

	return tokenClaims, nil
}

// LoadConfig loads the authentication configuration
// If skipValidation is true, token signature validation will be bypassed but the token must still be well-formed
// If skipValidation is false, full JWKS validation will be used with optional insecureSkipVerify
func LoadConfig(skipValidation bool, insecureSkipVerify ...bool) *middleware.AuthConfig {
	jwksURL := os.Getenv("JWKS_URL")
	if jwksURL == "" {
		jwksURL = "https://localhost:9031/pf/JWKS" // Default PingFederate JWKS URL
	}

	// Get subject claim name from environment or use default
	subjectClaimName := os.Getenv("SUBJECT_CLAIM_NAME")
	if subjectClaimName == "" {
		subjectClaimName = "sub" // Default to standard claim name if not specified
	}

	log.Printf("[DEBUG] Using subject claim name: %s", subjectClaimName)

	var validator middleware.TokenValidator

	// If validation is disabled or we're in development mode, use the format-only validator
	if skipValidation {
		log.Printf("[WARNING] Running with JWT signature validation DISABLED - This should only be used for development")
		validator = &formatOnlyValidator{
			subjectClaimName: subjectClaimName,
		}
	} else {
		// Otherwise, use the JWKS validator with the specified options
		insecure := len(insecureSkipVerify) > 0 && insecureSkipVerify[0]
		if insecure {
			log.Printf("[WARNING] Running with TLS certificate verification disabled. DO NOT USE IN PRODUCTION!")
		}
		jwksValidator := middleware.NewJWKSValidator(jwksURL, insecure)
		jwksValidator.SubjectClaimName = subjectClaimName
		jwksValidator.Issuer = os.Getenv("TOKEN_ISSUER")
		if jwksValidator.Issuer == "" {
			log.Printf("[WARNING] TOKEN_ISSUER is not set - the iss claim will not be validated. " +
				"Set it to the authorization server's issuer identifier.")
		} else {
			log.Printf("[DEBUG] Validating token issuer: %s", jwksValidator.Issuer)
		}
		validator = jwksValidator
	}

	// Create and return the auth config
	return &middleware.AuthConfig{
		TokenValidator: validator,
		SubjectClaimName: subjectClaimName,
		RequiredScopes: map[string]string{
			"GET":    "grant_management_query",
			"POST":   "grant_management_evaluate",
			"PUT":    "grant_management_update",
			"PATCH":  "grant_management_update",
			"DELETE": "grant_management_revoke",
		},
	}
}

// LoadRateLimiterConfig loads rate limiting configuration
func LoadRateLimiterConfig() *middleware.RateLimiterConfig {
	return &middleware.RateLimiterConfig{
		RPS:     100,
		Burst:   50,
		ExemptIPs: []string{"127.0.0.1", "::1"}, // Exempt localhost
	}
}

// LoadCSRFConfig loads CSRF protection configuration
func LoadCSRFConfig() *middleware.CSRFConfig {
	return &middleware.CSRFConfig{
		TokenLength: 32,
		TokenHeader: "X-CSRF-Token",
		CookieName:  "csrf_token",
		Secure:      false, // Set to true in production with HTTPS
		SameSite:    http.SameSiteLaxMode,
	}
}

// mockTokenValidator is used when JWT validation is disabled
// It parses the token claims without validating the signature
type mockTokenValidator struct{
	subjectClaimName string
}

// Default token claims for testing
const (
	defaultExp = 253402300799 // 9999-12-31 23:59:59 +0000 UTC
	defaultNbf = 0
	defaultIat = 0
	defaultIssuer = "https://localhost:9031"
	defaultAudience = "default-audience"
)

// ValidateToken parses a JWT token and returns its claims without signature validation
func (v *mockTokenValidator) ValidateToken(tokenString string) (*middleware.TokenClaims, error) {
	// Parse the token without validating the signature
	token, _, err := new(jwt.Parser).ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	// Get the claims
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("invalid token claims format")
	}

	// Extract standard claims
	var clientID, subject string
	if cid, ok := claims["client_id"]; ok {
		clientID, _ = cid.(string)
	}

	// Get subject from the configured claim name or fall back to 'sub'
	subjectClaimName := v.subjectClaimName
	if subjectClaimName == "" {
		subjectClaimName = "sub"
	}

	if sub, ok := claims[subjectClaimName]; ok {
		subject, _ = sub.(string)
		log.Printf("[DEBUG] Found subject '%s' in claim '%s'", subject, subjectClaimName)
	} else if sub, ok := claims["sub"]; ok {
		// Fall back to standard 'sub' claim
		subject, _ = sub.(string)
		log.Printf("[DEBUG] Using fallback 'sub' claim with value: %s", subject)
	}

	// Extract scopes
	var scopes []string
	if scope, ok := claims["scope"]; ok {
		switch v := scope.(type) {
		case string:
			scopes = strings.Fields(v)
		case []interface{}:
			for _, s := range v {
				if str, ok := s.(string); ok {
					scopes = append(scopes, str)
				}
			}
		}
	}

	// Create registered claims with default values
	now := time.Now()
	registeredClaims := jwt.RegisteredClaims{
		Subject:  subject,
		Issuer:   "gm-api",
		IssuedAt: jwt.NewNumericDate(now),
	}

	// Set expiration if provided
	if exp, ok := claims["exp"].(float64); ok && exp > 0 {
		registeredClaims.ExpiresAt = jwt.NewNumericDate(time.Unix(int64(exp), 0))
	} else {
		// Default to 1 hour if not specified
		registeredClaims.ExpiresAt = jwt.NewNumericDate(now.Add(time.Hour))
	}

	// Set not before if provided
	if nbf, ok := claims["nbf"].(float64); ok && nbf > 0 {
		registeredClaims.NotBefore = jwt.NewNumericDate(time.Unix(int64(nbf), 0))
	}

	// Set issued at if provided
	if iat, ok := claims["iat"].(float64); ok && iat > 0 {
		registeredClaims.IssuedAt = jwt.NewNumericDate(time.Unix(int64(iat), 0))
	}

	// Set issuer if provided
	if iss, ok := claims["iss"].(string); ok && iss != "" {
		registeredClaims.Issuer = iss
	}

	// Handle audience if provided in the token
	switch aud := claims["aud"].(type) {
	case string:
		registeredClaims.Audience = []string{aud}
	case []interface{}:
		audience := make([]string, 0, len(aud))
		for _, a := range aud {
			if s, ok := a.(string); ok {
				audience = append(audience, s)
			}
		}
		registeredClaims.Audience = audience
	default:
		// Use default audience if not provided
		registeredClaims.Audience = []string{defaultAudience}
	}

	// Create and return the token claims
	return &middleware.TokenClaims{
		RegisteredClaims: registeredClaims,
		ClientID:        clientID,
		Scopes:          scopes,
	}, nil
}
