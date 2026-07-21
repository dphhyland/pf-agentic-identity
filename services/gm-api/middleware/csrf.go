// Package middleware provides HTTP middleware for the Grant Management Service.
package middleware

import (
	"crypto/hmac"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
)

// CSRFConfig holds the configuration for CSRF protection.
type CSRFConfig struct {
	// TokenLength is the length of the CSRF token in bytes.
	TokenLength int
	// TokenHeader is the HTTP header where the CSRF token is expected.
	TokenHeader string
	// CookieName is the name of the cookie that stores the CSRF token.
	CookieName string
	// Secure sets the Secure flag on the cookie.
	Secure bool
	// SameSite sets the SameSite attribute on the cookie.
	SameSite http.SameSite
}

// DefaultCSRFConfig returns a default CSRF configuration.
func DefaultCSRFConfig() *CSRFConfig {
	return &CSRFConfig{
		TokenLength: 32,
		TokenHeader: "X-CSRF-Token",
		CookieName:  "csrf_token",
		Secure:      true,
		SameSite:    http.SameSiteStrictMode,
	}
}

// CSRF is the CSRF protection middleware.
type CSRF struct {
	config *CSRFConfig
}

// NewCSRF creates a new CSRF middleware with the given configuration.
func NewCSRF(config *CSRFConfig) *CSRF {
	if config == nil {
		config = DefaultCSRFConfig()
	}
	return &CSRF{config: config}
}

// Handler returns the CSRF middleware handler.
func (c *CSRF) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip CSRF check for safe methods
		if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
			next.ServeHTTP(w, r)
			return
		}

		// Get token from header
		token := r.Header.Get(c.config.TokenHeader)
		if token == "" {
			http.Error(w, "CSRF token missing", http.StatusForbidden)
			return
		}

		// Get token from cookie
		cookie, err := r.Cookie(c.config.CookieName)
		if err != nil {
			http.Error(w, "CSRF cookie missing", http.StatusForbidden)
			return
		}

		// Compare tokens
		if !hmac.Equal([]byte(token), []byte(cookie.Value)) {
			http.Error(w, "Invalid CSRF token", http.StatusForbidden)
			return
		}

		// Token is valid, proceed to the next handler
		next.ServeHTTP(w, r)
	})
}

// GenerateToken generates a new CSRF token.
func (c *CSRF) GenerateToken() (string, error) {
	token := make([]byte, c.config.TokenLength)
	if _, err := rand.Read(token); err != nil {
		return "", fmt.Errorf("failed to generate CSRF token: %w", err)
	}
	return base64.URLEncoding.EncodeToString(token), nil
}

// SetTokenCookie sets the CSRF token in a cookie.
func (c *CSRF) SetTokenCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     c.config.CookieName,
		Value:    token,
		Path:     "/",
		Secure:   c.config.Secure,
		HttpOnly: true,
		SameSite: c.config.SameSite,
	})
}

// GetTokenFromRequest retrieves the CSRF token from the request.
func (c *CSRF) GetTokenFromRequest(r *http.Request) (string, error) {
	// First try to get from header
	token := r.Header.Get(c.config.TokenHeader)
	if token != "" {
		return token, nil
	}

	// Then try to get from form
	if err := r.ParseForm(); err == nil {
		token = r.FormValue("csrf_token")
		if token != "" {
			return token, nil
		}
	}

	// Finally try to get from cookie
	cookie, err := r.Cookie(c.config.CookieName)
	if err != nil {
		return "", errors.New("CSRF token not found in request")
	}

	return cookie.Value, nil
}

// VerifyToken verifies if the provided token matches the one in the request.
func (c *CSRF) VerifyToken(r *http.Request, token string) bool {
	cookie, err := r.Cookie(c.config.CookieName)
	if err != nil {
		return false
	}

	// Use constant time comparison to prevent timing attacks
	return hmac.Equal([]byte(token), []byte(cookie.Value))
}
