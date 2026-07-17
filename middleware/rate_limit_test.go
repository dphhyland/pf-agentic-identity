package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"golang.org/x/time/rate"
)

func TestRateLimit(t *testing.T) {
	tests := []struct {
		name          string
		rps           float64
		burst         int
		exemptIPs     []string
		remoteAddr    string
		headers       map[string]string
		expectedCode  int
		shouldBeRateLimited bool
	}{
		{
			name:          "allow requests below limit",
			rps:           10,
			burst:         5,
			remoteAddr:    "192.168.1.1:1234",
			expectedCode:  http.StatusOK,
			shouldBeRateLimited: false,
		},
		{
			name:          "block requests above limit",
			rps:           1,
			burst:         1,
			remoteAddr:    "192.168.1.2:1234",
			expectedCode:  http.StatusTooManyRequests,
			shouldBeRateLimited: true,
		},
		{
			name:          "exempt IPs are not rate limited",
			rps:           1,
			burst:         1,
			exemptIPs:     []string{"192.168.1.3"},
			remoteAddr:    "192.168.1.3:1234",
			expectedCode:  http.StatusOK,
			shouldBeRateLimited: false,
		},
		{
			name:          "respect X-Forwarded-For header",
			rps:           1,
			burst:         1,
			headers:       map[string]string{"X-Forwarded-For": "192.168.1.4"},
			expectedCode:  http.StatusTooManyRequests,
			shouldBeRateLimited: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			})

			// Create a test request
			req := httptest.NewRequest("GET", "http://example.com/foo", nil)
			req.RemoteAddr = tt.remoteAddr
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}

			// Create rate limiter config with pointer
			config := &RateLimiterConfig{
				RPS:       tt.rps,
				Burst:     tt.burst,
				ExemptIPs: tt.exemptIPs,
			}
			// Initialize the rate limiter state
			config.Reset()

			// Apply rate limiting
			rateLimited := RateLimit(config)(handler)

			// First request should always pass (within burst)
			rr := httptest.NewRecorder()
			rateLimited.ServeHTTP(rr, req)

			if rr.Code != http.StatusOK {
				t.Errorf("first request failed with status: %d, expected: %d", rr.Code, http.StatusOK)
			}

			// Second request should be rate limited if shouldBeRateLimited is true
			rr = httptest.NewRecorder()
			rateLimited.ServeHTTP(rr, req)

			if rr.Code != tt.expectedCode {
				t.Errorf("second request returned status: %d, expected: %d", rr.Code, tt.expectedCode)
			}

			// If we expect rate limiting, check the headers
			if tt.shouldBeRateLimited {
				if rr.Header().Get("Retry-After") == "" {
					t.Error("expected Retry-After header to be set")
				}
			}
		})
	}
}

func TestRateLimitHeaders(t *testing.T) {
	// Create a test handler that just returns 200 OK
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Create a test request
	req := httptest.NewRequest("GET", "http://example.com/foo", nil)
	
	// Set up the context with our test values
	ctx := req.Context()
	ctx = context.WithValue(ctx, RateLimitRemainingKey, 9)
	ctx = context.WithValue(ctx, RateLimitLimitKey, 10)
	// Use Unix timestamp (seconds since epoch) for the reset time
	resetTime := time.Now().Add(time.Minute)
	ctx = context.WithValue(ctx, RateLimitResetKey, resetTime.Unix())
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()

	// Create a middleware stack with our test handler wrapped by RateLimitHeaders
	middleware := RateLimitHeaders(handler)

	// Serve the request through our middleware
	middleware.ServeHTTP(rr, req)

	// Check the response status code
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	// Check the response headers
	headers := []struct {
		name     string
		expected string
	}{
		{"X-RateLimit-Remaining", "9"},
		{"X-RateLimit-Limit", "10"},
	}

	for _, h := range headers {
		if got := rr.Header().Get(h.name); got != h.expected {
			t.Errorf("header %s = %q, want %q", h.name, got, h.expected)
		}
	}

	// Check that X-RateLimit-Reset is a valid date
	if reset := rr.Header().Get("X-RateLimit-Reset"); reset == "" {
		t.Error("X-RateLimit-Reset header not set")
	} else if _, err := time.Parse(time.RFC1123, reset); err != nil {
		t.Errorf("X-RateLimit-Reset header is not a valid RFC1123 date: %v", err)
	}
}

func TestRateLimitCleanup(t *testing.T) {
	// Create a rate limiter with a low cleanup interval for testing
	rps := 1.0
	burst := 1
	limiter := newIPRateLimiter(rate.Limit(rps), burst)

	// Add an IP to the limiter
	testIP := "192.168.1.100"
	limiter.getLimiter(testIP)

	// Verify the IP was added
	limiter.mu.RLock()
	_, exists := limiter.ips[testIP]
	limiter.mu.RUnlock()
	if !exists {
		t.Error("IP was not added to rate limiter")
	}

	// Wait for cleanup (in the actual implementation, this would be handled by a goroutine)
	time.Sleep(2 * time.Second)

	// The IP should still exist since we haven't implemented the cleanup in this test
	limiter.mu.RLock()
	_, exists = limiter.ips[testIP]
	limiter.mu.RUnlock()
	if !exists {
		t.Error("IP was cleaned up too quickly")
	}
}
