package middleware

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupMockJWKSServer creates a test server that serves JWKS
func setupMockJWKSServer(t *testing.T, key *rsa.PrivateKey) *httptest.Server {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Return a valid JWKS response with the test key. Per RFC 7517 the
		// modulus is base64url-encoded big-endian bytes, not a decimal string.
		jwk := map[string]interface{}{
			"kty": "RSA",
			"n":   base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes()),
			"e":   "AQAB",
			"kid": "test-key",
		}

		jwks := map[string]interface{}{
			"keys": []map[string]interface{}{jwk},
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(jwks)
	}))

	return server
}

func TestJWKSValidator_ValidateToken_DefaultSubjectClaim(t *testing.T) {
	// Generate a test key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err, "Failed to generate test key")

	// Set up a mock JWKS server
	server := setupMockJWKSServer(t, privateKey)
	defer server.Close()

	// Setup validator with the mock server URL
	validator := NewJWKSValidator(server.URL)
	validator.httpClient = server.Client() // Use the test server's client
	validator.SubjectClaimName = ""        // Should default to "sub"

	// Create a test token with default sub claim
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"sub": "testuser",
	})
	tokenString, err := token.SignedString(privateKey)
	require.NoError(t, err, "Failed to create test token")

	// Test
	claims, err := validator.ValidateToken(tokenString)
	require.NoError(t, err, "Token validation failed")
	assert.Equal(t, "testuser", claims.Subject, "Subject should be extracted from 'sub' claim")
}

func TestJWKSValidator_ValidateToken_CustomSubjectClaim(t *testing.T) {
	// Generate a test key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err, "Failed to generate test key")

	// Set up a mock JWKS server
	server := setupMockJWKSServer(t, privateKey)
	defer server.Close()

	// Setup validator with the mock server URL
	validator := NewJWKSValidator(server.URL)
	validator.httpClient = server.Client() // Use the test server's client
	validator.SubjectClaimName = "username"

	// Create a test token with custom subject claim
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"username": "testuser",
	})
	tokenString, err := token.SignedString(privateKey)
	require.NoError(t, err, "Failed to create test token")

	// Test
	claims, err := validator.ValidateToken(tokenString)
	require.NoError(t, err, "Token validation failed")
	assert.Equal(t, "testuser", claims.Subject, "Subject should be extracted from custom claim")
}

func TestJWKSValidator_ValidateToken_FallbackToSubClaim(t *testing.T) {
	// Generate a test key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err, "Failed to generate test key")

	// Set up a mock JWKS server
	server := setupMockJWKSServer(t, privateKey)
	defer server.Close()

	// Setup validator with the mock server URL
	validator := NewJWKSValidator(server.URL)
	validator.httpClient = server.Client() // Use the test server's client
	validator.SubjectClaimName = "username" // Custom claim that doesn't exist

	// Create a test token with only standard "sub" claim
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"sub": "testuser",
	})
	tokenString, err := token.SignedString(privateKey)
	require.NoError(t, err, "Failed to create test token")

	// Test
	claims, err := validator.ValidateToken(tokenString)
	require.NoError(t, err, "Token validation failed")
	assert.Equal(t, "testuser", claims.Subject, "Subject should fall back to 'sub' claim")
}

func TestJWKSValidator_ValidateToken_MissingSubject(t *testing.T) {
	// Generate a test key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err, "Failed to generate test key")

	// Set up a mock JWKS server
	server := setupMockJWKSServer(t, privateKey)
	defer server.Close()

	// Setup validator with the mock server URL
	validator := NewJWKSValidator(server.URL)
	validator.httpClient = server.Client() // Use the test server's client
	validator.SubjectClaimName = "username"

	// Create a test token without subject claims
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"other_claim": "value",
	})
	tokenString, err := token.SignedString(privateKey)
	require.NoError(t, err, "Failed to create test token")

	// Test
	_, err = validator.ValidateToken(tokenString)
	require.Error(t, err, "Validation should fail with missing subject claim")
	assert.Contains(t, err.Error(), "missing required subject claim", "Error should indicate missing subject claim")
}

func TestAuthenticateMiddleware_SubjectClaim(t *testing.T) {
	// Setup test cases
	tests := []struct {
		name            string
		subjectClaim    string
		subjectValue    string
		expectedSubject string
		shouldFail      bool
	}{
		{
			name:            "default sub claim",
			subjectClaim:    "sub",
			subjectValue:    "testuser",
			expectedSubject: "testuser",
			shouldFail:      false,
		},
		{
			name:            "custom username claim",
			subjectClaim:    "username",
			subjectValue:    "testuser",
			expectedSubject: "testuser",
			shouldFail:      false,
		},
		{
			name:         "missing subject claim",
			subjectClaim: "username",
			subjectValue: "",
		shouldFail:   true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Sign with the same key the mock JWKS serves, so the middleware
			// exercises the real validation path rather than a stub.
			privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
			require.NoError(t, err, "Failed to generate test key")

			server := setupMockJWKSServer(t, privateKey)
			defer server.Close()

			validator := NewJWKSValidator(server.URL)
			validator.httpClient = server.Client()
			validator.SubjectClaimName = tc.subjectClaim

			// Create test token
			mapClaims := jwt.MapClaims{}
			if tc.subjectValue != "" {
				mapClaims[tc.subjectClaim] = tc.subjectValue
			}
			tokenString, err := jwt.NewWithClaims(jwt.SigningMethodRS256, mapClaims).SignedString(privateKey)
			require.NoError(t, err, "Failed to create test token")

			// Create test request with token
			req := httptest.NewRequest("GET", "/test", nil)
			req.Header.Set("Authorization", "Bearer "+tokenString)

			// Create test handler
			handlerRan := false
			handler := Authenticate(validator)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// This will be called if authentication succeeds
				handlerRan = true
				claims, ok := GetTokenClaimsFromContext(r.Context())
				require.True(t, ok, "Claims should be in context")
				require.NotNil(t, claims, "Claims should not be nil")
				assert.Equal(t, tc.expectedSubject, claims.Subject, "Subject should match expected value")
				w.WriteHeader(http.StatusOK)
			}))

			// Serve the request
			resp := httptest.NewRecorder()
			handler.ServeHTTP(resp, req)

			// Verify response
			if tc.shouldFail {
				assert.Equal(t, http.StatusUnauthorized, resp.Code, "Expected unauthorized status")
				assert.False(t, handlerRan, "Handler must not run when authentication fails")
			} else {
				assert.Equal(t, http.StatusOK, resp.Code, "Expected success status")
				assert.True(t, handlerRan, "Handler should run when authentication succeeds")
			}
		})
	}
}
