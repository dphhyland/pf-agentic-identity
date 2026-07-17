// Package middleware provides HTTP middleware components for the Grant Management API.
package middleware

import (
	"sync"
	"time"
)

// mockTime is a mock implementation of timeSource for testing
type mockTime struct {
	now time.Time
}

// newMockTime creates a new mock time source
func newMockTime(initialTime time.Time) *mockTime {
	return &mockTime{now: initialTime}
}

// Now returns the current mock time
func (m *mockTime) Now() time.Time {
	return m.now
}

// Add advances the mock time by the given duration
func (m *mockTime) Add(d time.Duration) {
	m.now = m.now.Add(d)
}

// Set sets the mock time to the given time
func (m *mockTime) Set(t time.Time) {
	m.now = t
}

// testRateLimiter creates a new rate limiter with a mock time source for testing
func testRateLimiter(rps float64, burst int, initialTime time.Time) (*RateLimiterConfig, *mockTime) {
	mockTime := newMockTime(initialTime)
	config := &RateLimiterConfig{
		RPS:        rps,
		Burst:      burst,
		ipLimiters: make(map[string]*ipLimiterInfo),
		mu:         &sync.RWMutex{},
	}
	return config, mockTime
}
