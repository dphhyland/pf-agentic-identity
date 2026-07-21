package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCSRFMiddleware(t *testing.T) {
	tests := []struct {
		name           string
		method         string
		setCookie      bool
		setHeader      bool
		sameToken      bool
		expectedStatus int
	}{
		{
			name:           "GET request skips CSRF check",
			method:         http.MethodGet,
			setCookie:      false,
			setHeader:      false,
			sameToken:      true,
			expectedStatus: http.StatusOK,
		},
		{
			name:           "POST without token is forbidden",
			method:         http.MethodPost,
			setCookie:      false,
			setHeader:      false,
			sameToken:      true,
			expectedStatus: http.StatusForbidden,
		},
		{
			name:           "POST with valid token is allowed",
			method:         http.MethodPost,
			setCookie:      true,
			setHeader:      true,
			sameToken:      true,
			expectedStatus: http.StatusOK,
		},
		{
			name:           "POST with invalid token is forbidden",
			method:         http.MethodPost,
			setCookie:      true,
			setHeader:      true,
			sameToken:      false,
			expectedStatus: http.StatusForbidden,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a test handler that will be wrapped by the CSRF middleware
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			})

			// Create CSRF middleware
			csrf := NewCSRF(nil)


			// Generate a token for testing
			token, err := csrf.GenerateToken()
			if err != nil {
				t.Fatalf("Failed to generate token: %v", err)
			}

			// Create a test request
			req := httptest.NewRequest(tt.method, "http://example.com", nil)

			// Set cookie if needed
			if tt.setCookie {
				req.AddCookie(&http.Cookie{
					Name:  csrf.config.CookieName,
					Value: token,
				})
			}

			// Set header if needed
			if tt.setHeader {
				headerToken := token
				if !tt.sameToken {
				headerToken = "invalid-token"
			}
				req.Header.Set(csrf.config.TokenHeader, headerToken)
			}

			// Create a response recorder
			rr := httptest.NewRecorder()

			// Serve the request through the middleware
			csrf.Handler(handler).ServeHTTP(rr, req)

			
			// Check the status code
			if status := rr.Code; status != tt.expectedStatus {
				t.Errorf("handler returned wrong status code: got %v want %v",
					status, tt.expectedStatus)
			}
		})
	}
}

func TestCSRFTokenGeneration(t *testing.T) {
	csrf := NewCSRF(nil)

	// Test token generation
	token1, err := csrf.GenerateToken()
	if err != nil {
		t.Fatalf("Failed to generate token: %v", err)
	}

	if token1 == "" {
		t.Error("Generated token is empty")
	}

	// Test that tokens are unique
	token2, err := csrf.GenerateToken()
	if err != nil {
		t.Fatalf("Failed to generate second token: %v", err)
	}

	if token1 == token2 {
		t.Error("Generated tokens are not unique")
	}
}

func TestCSRFVerifyToken(t *testing.T) {
	csrf := NewCSRF(nil)

	// Generate a test token
	token, err := csrf.GenerateToken()
	if err != nil {
		t.Fatalf("Failed to generate token: %v", err)
	}

	// Create a test request with the token in a cookie
	req := httptest.NewRequest("GET", "http://example.com", nil)
	req.AddCookie(&http.Cookie{
		Name:  csrf.config.CookieName,
		Value: token,
	})

	// Test valid token
	if !csrf.VerifyToken(req, token) {
		t.Error("VerifyToken failed for valid token")
	}

	// Test invalid token
	if csrf.VerifyToken(req, "invalid-token") {
		t.Error("VerifyToken passed for invalid token")
	}

	// Test missing cookie
	req = httptest.NewRequest("GET", "http://example.com", nil)
	if csrf.VerifyToken(req, token) {
		t.Error("VerifyToken passed for missing cookie")
	}
}
