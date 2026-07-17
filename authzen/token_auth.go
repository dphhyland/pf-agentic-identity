package authzen

import (
	"encoding/base64"
	"net/http"
	"time"
)

// TokenAuthClient handles authentication using a static bearer token
type TokenAuthClient struct {
	token      string
	httpClient *http.Client
}

// TokenAuthConfig contains the configuration for authentication
type TokenAuthConfig struct {
	// Token is used for Bearer token authentication
	Token string
	// Username and Password are used for Basic authentication
	Username string
	Password string
}

// NewTokenAuthClient creates a new client that uses either Bearer token or Basic authentication
func NewTokenAuthClient(config *TokenAuthConfig) *TokenAuthClient {
	return &TokenAuthClient{
		token:      config.Token,
		httpClient: &http.Client{Timeout: 10 * time.Second},
	}
}

// NewBasicAuthClient creates a new client that uses Basic authentication
func NewBasicAuthClient(username, password string) *TokenAuthClient {
	return &TokenAuthClient{
		token:      base64.StdEncoding.EncodeToString([]byte(username + ":" + password)),
		httpClient: &http.Client{Timeout: 10 * time.Second},
	}
}

// Do performs an HTTP request with the appropriate authentication
func (c *TokenAuthClient) Do(req *http.Request) (*http.Response, error) {
	if c.token != "" {
		// Check if token is base64 encoded (Basic auth)
		if _, err := base64.StdEncoding.DecodeString(c.token); err == nil {
			req.Header.Set("Authorization", "Basic "+c.token)
		} else {
			req.Header.Set("Authorization", "Bearer "+c.token)
		}
	}
	return c.httpClient.Do(req)
}

// addAuthHeader adds the appropriate authorization header to the request
func (c *TokenAuthClient) addAuthHeader(req *http.Request) (*http.Request, error) {
	if c.token != "" {
		// Check if token is base64 encoded (Basic auth)
		if _, err := base64.StdEncoding.DecodeString(c.token); err == nil {
			req.Header.Set("Authorization", "Basic "+c.token)
		} else {
			req.Header.Set("Authorization", "Bearer "+c.token)
		}
	}
	return req, nil
}
