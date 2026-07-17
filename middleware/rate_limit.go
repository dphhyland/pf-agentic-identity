// Package middleware provides HTTP middleware components for the Grant Management API.
package middleware

import (
	"context"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// RateLimitKey is a type for context keys used by the rate limiter
type RateLimitKey string

// Rate limit context keys
const (
	// RateLimitRemainingKey is the context key for remaining requests
	RateLimitRemainingKey RateLimitKey = "rate_limit_remaining"
	// RateLimitLimitKey is the context key for the rate limit
	RateLimitLimitKey RateLimitKey = "rate_limit_limit"
	// RateLimitResetKey is the context key for when the rate limit resets
	RateLimitResetKey RateLimitKey = "rate_limit_reset"
)

// RateLimiterConfig holds configuration for the rate limiter
type RateLimiterConfig struct {
	// RPS is the maximum number of requests per second
	RPS float64 `json:"rps"`
	// Burst is the maximum burst size
	Burst int `json:"burst"`
	// ExemptIPs is a list of IP addresses that are exempt from rate limiting
	ExemptIPs []string `json:"exemptIPs,omitempty"`
	// ipLimiters maps IP addresses to their respective rate limiters and last access time
	ipLimiters map[string]*ipLimiterInfo
	mu         *sync.RWMutex
}

// Reset clears all rate limiter state, useful for testing
func (rlc *RateLimiterConfig) Reset() {
	if rlc.mu == nil {
		rlc.mu = &sync.RWMutex{}
	}
	rlc.mu.Lock()
	defer rlc.mu.Unlock()
	rlc.ipLimiters = make(map[string]*ipLimiterInfo)
}

// timeSource is an interface for getting the current time.
// This can be replaced in tests to control time.
type timeSource interface {
	Now() time.Time
}

type realTime struct{}

func (realTime) Now() time.Time { return time.Now() }

// ipLimiterInfo holds information about a rate limiter for an IP
type ipLimiterInfo struct {
	limiter    *rate.Limiter
	lastAccess time.Time
}

// ipRateLimiter holds the rate limiter for each IP
type ipRateLimiter struct {
	ips         map[string]*ipLimiterInfo
	mu          *sync.RWMutex
	r           rate.Limit
	burst       int
	stopCleanup chan struct{}
	lastCleanup time.Time
	timeSource  timeSource // For testing
}

// newIPRateLimiter creates a new rate limiter for IP addresses
func newIPRateLimiter(r rate.Limit, burst int) *ipRateLimiter {
	return &ipRateLimiter{
		ips:         make(map[string]*ipLimiterInfo),
		mu:          &sync.RWMutex{},
		r:           r,
		burst:       burst,
		stopCleanup: make(chan struct{}),
		lastCleanup: time.Now(),
		timeSource:  realTime{},
	}
}

// SetTimeSource sets the time source for testing
func (i *ipRateLimiter) SetTimeSource(ts timeSource) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.timeSource = ts
}

// getLimiter returns the rate limiter for the given IP, creating it if needed
func (i *ipRateLimiter) getLimiter(ip string) *rate.Limiter {
	i.mu.Lock()
	defer i.mu.Unlock()

	limiterInfo, exists := i.ips[ip]
	if !exists {
		limiterInfo = &ipLimiterInfo{
			limiter:    rate.NewLimiter(i.r, i.burst),
			lastAccess: i.timeSource.Now(),
		}
		i.ips[ip] = limiterInfo
	}

	// Ensure the limiter has the correct rate and burst
	if limiterInfo.limiter.Burst() != i.burst || limiterInfo.limiter.Limit() != i.r {
		limiterInfo.limiter.SetBurst(i.burst)
		limiterInfo.limiter.SetLimit(i.r)
	}

	return limiterInfo.limiter
}

// Reset clears all rate limiters (for testing)
func (i *ipRateLimiter) Reset() {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.ips = make(map[string]*ipLimiterInfo)
	i.lastCleanup = i.timeSource.Now()
}

// StopCleanup stops the cleanup goroutine
func (i *ipRateLimiter) StopCleanup() {
	if i.stopCleanup != nil {
		close(i.stopCleanup)
		i.stopCleanup = nil
	}
}

// startCleanup starts a goroutine to clean up old rate limiters
func (i *ipRateLimiter) startCleanup() {
	go func() {
		ticker := time.NewTicker(time.Hour)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				i.cleanup()
			case <-i.stopCleanup:
				return
			}
		}
	}()
}

// cleanup removes old rate limiters that haven't been used recently
func (i *ipRateLimiter) cleanup() {
	i.mu.Lock()
	defer i.mu.Unlock()

	now := i.timeSource.Now()

	// Only clean up once per second at most
	if now.Sub(i.lastCleanup) < time.Second {
		return
	}
	i.lastCleanup = now

	// Clean up limiters that have all tokens available
	for ip, limiterInfo := range i.ips {
		tokens := int(limiterInfo.limiter.Tokens())
		if tokens >= i.burst {
			delete(i.ips, ip)
		}
	}
}

// getRequestIP retrieves the client IP from the request
func getRequestIP(r *http.Request) string {
	// In tests, use a consistent IP to avoid test flakiness
	if ip := r.Header.Get("X-Test-IP"); ip != "" {
		return ip
	}

	if forwardedFor := r.Header.Get("X-Forwarded-For"); forwardedFor != "" {
		if commaIdx := strings.Index(forwardedFor, ","); commaIdx > 0 {
			return strings.TrimSpace(forwardedFor[:commaIdx])
		}
		return forwardedFor
	}

	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// RateLimit is a middleware that limits the rate of incoming requests
// Note: config is passed by pointer to avoid copying the mutex
func RateLimit(config *RateLimiterConfig) func(http.Handler) http.Handler {
	// Ensure burst is at least 1
	if config.Burst < 1 {
		config.Burst = 1
	}

	// Initialize the rate limiter state if not already done
	if config.ipLimiters == nil {
		config.ipLimiters = make(map[string]*ipLimiterInfo)
	}
	
	// Initialize the mutex if not already done
	if config.mu == nil {
		config.mu = &sync.RWMutex{}
	}

	// Start cleanup goroutine if not already running
	go func() {
		for {
			time.Sleep(time.Minute)
			config.mu.Lock()
			now := time.Now()
			for ip, limiterInfo := range config.ipLimiters {
				// Remove limiters that haven't been used in the last 10 minutes
				if now.Sub(limiterInfo.lastAccess) > 10*time.Minute {
					delete(config.ipLimiters, ip)
				}
			}
			config.mu.Unlock()
		}
	}()

	// Return the middleware function
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Get the IP address from the request
			ip := getRequestIP(r)

			// Check if IP is in the exempt list
			for _, exemptIP := range config.ExemptIPs {
				if ip == exemptIP {
					next.ServeHTTP(w, r)
					return
				}
			}

			// Get or create rate limiter for this IP
			config.mu.Lock()
			limiterInfo, exists := config.ipLimiters[ip]
			if !exists {
				limiterInfo = &ipLimiterInfo{
					limiter:    rate.NewLimiter(rate.Limit(config.RPS), config.Burst),
					lastAccess: time.Now(),
				}
				config.ipLimiters[ip] = limiterInfo
			}
			limiterInfo.lastAccess = time.Now()
			config.mu.Unlock()

			// Try to reserve a token
			if !limiterInfo.limiter.Allow() {
				// Calculate reset time (1 second from now)
				resetTime := time.Now().Add(time.Second)
				resetUnix := resetTime.Unix()

				// Set rate limit headers
				w.Header().Set("X-RateLimit-Limit", strconv.Itoa(config.Burst))
				w.Header().Set("X-RateLimit-Remaining", "0")
				w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(resetUnix, 10))
				w.Header().Set("Retry-After", strconv.FormatInt(int64(time.Until(resetTime).Seconds())+1, 10))

				http.Error(w, http.StatusText(http.StatusTooManyRequests), http.StatusTooManyRequests)
				return
			}

			// Call the next handler with rate limit information in the context
			ctx := r.Context()
			ctx = context.WithValue(ctx, RateLimitRemainingKey, int(limiterInfo.limiter.Tokens()))
			ctx = context.WithValue(ctx, RateLimitLimitKey, config.Burst)
			ctx = context.WithValue(ctx, RateLimitResetKey, time.Now().Add(time.Second).Unix())

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// responseWriter is a wrapper around http.ResponseWriter that captures the status code
type responseWriter struct {
	http.ResponseWriter
	status int
}

// WriteHeader captures the status code before writing it to the response
func (rw *responseWriter) WriteHeader(code int) {
	rw.status = code
	rw.ResponseWriter.WriteHeader(code)
}

// RateLimitHeaders is a middleware that adds rate limit headers to responses
func RateLimitHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rw := &responseWriter{ResponseWriter: w, status: http.StatusOK}

		// Call the next handler
		next.ServeHTTP(rw, r)

		// Get rate limit info from context
		ctx := r.Context()

		if limit, ok := ctx.Value(RateLimitLimitKey).(int); ok && limit > 0 {
			w.Header().Set("X-RateLimit-Limit", strconv.Itoa(limit))
		}

		if remaining, ok := ctx.Value(RateLimitRemainingKey).(int); ok && remaining >= 0 {
			w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(remaining))
		}

		if reset, ok := ctx.Value(RateLimitResetKey).(int64); ok && reset > 0 {
			// Format the reset time as RFC1123
			resetTime := time.Unix(reset, 0).UTC()
			w.Header().Set("X-RateLimit-Reset", resetTime.Format(time.RFC1123))
		}
	})
}
