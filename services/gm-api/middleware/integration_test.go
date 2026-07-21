package middleware_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"idp-gm-api/middleware"
)

// testConfig holds test configuration
type testConfig struct {
	rps    float64
	burst  int
	secure bool
}

// testHandler is a helper function to make test requests and log rate limit headers
func testHandler(t *testing.T, r *chi.Mux, method, path string, headers map[string]string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	
	t.Logf("Request: %s %s - Status: %d", method, path, rr.Code)
	t.Logf("RateLimit-Limit: %s", rr.Header().Get("X-RateLimit-Limit"))
	t.Logf("RateLimit-Remaining: %s", rr.Header().Get("X-RateLimit-Remaining"))
	t.Logf("RateLimit-Reset: %s", rr.Header().Get("X-RateLimit-Reset"))

	return rr
}

// testRouter creates a new router with rate limiting and CSRF protection middleware
func testRouter(t *testing.T, cfg testConfig) (*chi.Mux, *middleware.CSRF, *middleware.RateLimiterConfig) {
	r := chi.NewRouter()

	// Configure rate limiting
	rateLimiter := &middleware.RateLimiterConfig{
		RPS:    cfg.rps,
		Burst:  cfg.burst,
	}

	// Reset the rate limiter to initialize its state
	rateLimiter.Reset()

	// Configure CSRF protection
	csrfConfig := &middleware.CSRFConfig{
		TokenLength: 32,
		TokenHeader: "X-CSRF-Token",
		CookieName:  "csrf_token",
		Secure:      cfg.secure,
	}

	// Create a new rate limiter middleware with the config pointer
	r.Use(middleware.RateLimit(rateLimiter))
	r.Use(middleware.RateLimitHeaders)
	
	csrf := middleware.NewCSRF(csrfConfig)
	r.Use(csrf.Handler)

	// Add test routes
	r.Get("/public", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Handle multiple HTTP methods for the protected endpoint
	r.HandleFunc("/protected", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodPost:
			w.WriteHeader(http.StatusOK)
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})

	// Add CSRF token endpoint
	r.Get("/csrf-token", func(w http.ResponseWriter, r *http.Request) {
		token, err := csrf.GenerateToken()
		if err != nil {
			http.Error(w, "Failed to generate token", http.StatusInternalServerError)
			return
		}
		csrf.SetTokenCookie(w, token)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"csrfToken":"` + token + `"}`))
	})

	return r, csrf, rateLimiter
}

func TestRateLimitAndCSRFIntegration(t *testing.T) {
	t.Run("Test rate limiting", func(t *testing.T) {
		// Configure test with 1 request per second and burst of 1
		cfg := testConfig{
			rps:    1.0,
			burst:   1,
			secure:  false,
		}

		// Create a new router for this test case
		r, _, rateLimiter := testRouter(t, cfg)
		// Reset the rate limiter to ensure a clean state
		rateLimiter.Reset()

		// First request should succeed
		req1 := httptest.NewRequest("GET", "/public", nil)
		rr1 := httptest.NewRecorder()
		r.ServeHTTP(rr1, req1)
		assert.Equal(t, http.StatusOK, rr1.Code, "First request should succeed")

		// Second request should be rate limited
		req2 := httptest.NewRequest("GET", "/public", nil)
		rr2 := httptest.NewRecorder()
		r.ServeHTTP(rr2, req2)
		assert.Equal(t, http.StatusTooManyRequests, rr2.Code, "Second request should be rate limited")

		// Verify rate limit headers
		assert.Equal(t, "1", rr2.Header().Get("X-RateLimit-Limit"), "X-RateLimit-Limit header should be set")
		assert.Equal(t, "0", rr2.Header().Get("X-RateLimit-Remaining"), "X-RateLimit-Remaining should be 0 when rate limited")
		assert.NotEmpty(t, rr2.Header().Get("X-RateLimit-Reset"), "X-RateLimit-Reset header should be set")
		assert.NotEmpty(t, rr2.Header().Get("Retry-After"), "Retry-After header should be set when rate limited")

		// Wait for rate limit to reset
		time.Sleep(1100 * time.Millisecond)

		// Request after rate limit reset should succeed
		req3 := httptest.NewRequest("GET", "/public", nil)
		rr3 := httptest.NewRecorder()
		r.ServeHTTP(rr3, req3)
		assert.Equal(t, http.StatusOK, rr3.Code, "Request after rate limit reset should succeed")
	})

	t.Run("Test CSRF protection", func(t *testing.T) {
		// Configure test with relaxed rate limiting for CSRF tests
		cfg := testConfig{
			rps:    100.0, // High RPS to avoid rate limiting during CSRF tests
			burst:   100,
			secure:  false,
		}
		// Create a new router for this test case
		r, _, _ := testRouter(t, cfg)
		// Note: We don't need to reset the CSRF store explicitly here
		// as each test case will get a fresh CSRF token

		// First, make a request to get a CSRF token
		tokenReq := httptest.NewRequest("GET", "/csrf-token", nil)
		tokenRr := httptest.NewRecorder()
		r.ServeHTTP(tokenRr, tokenReq)
		require.Equal(t, http.StatusOK, tokenRr.Code, "CSRF token request should succeed")

		// Extract token from response
		var tokenData struct {
			CSRFToken string `json:"csrfToken"`
		}
		parseJSONResponse(t, tokenRr, &tokenData)
		require.NotEmpty(t, tokenData.CSRFToken, "CSRF token should not be empty")

		// Extract cookie from the response
		cookies := tokenRr.Result().Cookies()
		var csrfCookie *http.Cookie
		for _, cookie := range cookies {
			if cookie.Name == "csrf_token" { // Match the cookie name we set in testRouter()
				csrfCookie = cookie
				break
			}
		}
		require.NotNil(t, csrfCookie, "CSRF cookie not found in response")

		t.Run("Should reject request without CSRF token", func(t *testing.T) {
			req := httptest.NewRequest("POST", "/protected", nil)
			rr := httptest.NewRecorder()
			r.ServeHTTP(rr, req)
			assert.Equal(t, http.StatusForbidden, rr.Code, "Should reject request without CSRF token")
		})

		t.Run("Should reject request with invalid CSRF token", func(t *testing.T) {
			req := httptest.NewRequest("POST", "/protected", nil)
			req.Header.Set("X-CSRF-Token", "invalid-token")
			req.AddCookie(csrfCookie)
			rr := httptest.NewRecorder()
			r.ServeHTTP(rr, req)
			assert.Equal(t, http.StatusForbidden, rr.Code, "Should reject request with invalid CSRF token")
		})

		t.Run("Should accept request with valid CSRF token", func(t *testing.T) {
			req := httptest.NewRequest("POST", "/protected", nil)
			req.Header.Set("X-CSRF-Token", tokenData.CSRFToken)
			req.AddCookie(csrfCookie)
			rr := httptest.NewRecorder()
			r.ServeHTTP(rr, req)
			assert.Equal(t, http.StatusOK, rr.Code, "Should accept request with valid CSRF token")
		})

		t.Run("Should accept GET requests without CSRF token", func(t *testing.T) {
			req := httptest.NewRequest("GET", "/protected", nil)
			rr := httptest.NewRecorder()
			r.ServeHTTP(rr, req)
			assert.Equal(t, http.StatusOK, rr.Code, "Should accept GET request without CSRF token")
		})

		t.Run("Should accept HEAD requests without CSRF token", func(t *testing.T) {
			req := httptest.NewRequest("HEAD", "/protected", nil)
			rr := httptest.NewRecorder()
			r.ServeHTTP(rr, req)
			assert.Equal(t, http.StatusOK, rr.Code, "Should accept HEAD request without CSRF token")
		})

		t.Run("Should accept OPTIONS requests without CSRF token", func(t *testing.T) {
			req := httptest.NewRequest("OPTIONS", "/protected", nil)
			rr := httptest.NewRecorder()
			r.ServeHTTP(rr, req)
			assert.Equal(t, http.StatusOK, rr.Code, "Should accept OPTIONS request without CSRF token")
		})
	})
}

// parseJSONResponse is a helper function to parse JSON responses in tests
func parseJSONResponse(t *testing.T, rr *httptest.ResponseRecorder, v interface{}) {
	t.Helper()
	require.Equal(t, "application/json", rr.Header().Get("Content-Type"))
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), v))
}
