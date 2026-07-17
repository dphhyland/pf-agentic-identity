package authzen

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

// OAuthConfig contains OAuth client configuration
type OAuthConfig struct {
	BaseURL      string `json:"base_url"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

// OAuthTokenResponse represents the token response from the OAuth server
type OAuthTokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	TokenType   string `json:"token_type"`
}

// OAuthClient handles OAuth token management
type OAuthClient struct {
	config *OAuthConfig
	token  string
	expiry time.Time
	mu     sync.Mutex
	client *http.Client
	logger *log.Logger
}

// NewOAuthClient creates a new OAuth client with the given configuration
func NewOAuthClient(config *OAuthConfig) *OAuthClient {
	if config == nil {
		config = &OAuthConfig{}
	}

	return &OAuthClient{
		config: config,
		client: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: false},
			},
		},
		logger: log.New(io.Discard, "[OAUTH] ", log.LstdFlags),
	}
}

// GetToken returns a valid access token, refreshing if necessary
func (c *OAuthClient) GetToken() (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Return cached token if it's still valid
	if c.token != "" && time.Now().Before(c.expiry.Add(-1*time.Minute)) {
		return c.token, nil
	}

	// Refresh the token
	if err := c.refreshToken(); err != nil {
		return "", fmt.Errorf("failed to refresh token: %w", err)
	}

	return c.token, nil
}

// SetLogger sets the logger for the OAuth client
func (c *OAuthClient) SetLogger(logger *log.Logger) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.logger = logger
}

// refreshToken requests a new access token using client credentials
func (c *OAuthClient) refreshToken() error {
	if c.config == nil || c.config.BaseURL == "" {
		return fmt.Errorf("OAuth client not properly configured")
	}

	url := c.config.BaseURL

	// Create form data
	formData := "grant_type=client_credentials"
	req, err := http.NewRequest("POST", url, strings.NewReader(formData))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Set Basic Auth header
	req.SetBasicAuth(c.config.ClientID, c.config.ClientSecret)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	c.logger.Printf("Requesting new OAuth token from %s", url)

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("token request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("token request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp OAuthTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return fmt.Errorf("failed to decode token response: %w", err)
	}

	if tokenResp.AccessToken == "" {
		return fmt.Errorf("empty access token received from OAuth server")
	}

	c.token = tokenResp.AccessToken
	if tokenResp.ExpiresIn > 0 {
		c.expiry = time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)
	} else {
		// Default to 1 hour if no expiry is provided
		c.expiry = time.Now().Add(1 * time.Hour)
	}

	c.logger.Printf("Successfully obtained OAuth token, expires at %s", c.expiry.Format(time.RFC3339))

	return nil
}

// EnsureToken ensures we have a valid token
func (c *OAuthClient) EnsureToken() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// If we have a valid token, return nil
	if c.token != "" && time.Now().Before(c.expiry) {
		return nil
	}

	// Otherwise, refresh the token
	return c.refreshToken()
}

// GetPingFederateToken retrieves a token from Ping Federate
func (c *OAuthClient) GetPingFederateToken() (string, error) {
	// Ensure we have a valid token
	if err := c.EnsureToken(); err != nil {
		return "", fmt.Errorf("failed to ensure valid token: %w", err)
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	return c.token, nil
}

// Do performs an HTTP request with OAuth authentication
func (c *OAuthClient) Do(req *http.Request) (*http.Response, error) {
	if err := c.EnsureToken(); err != nil {
		return nil, fmt.Errorf("failed to get token: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.token))
	log.Printf("DEBUG: Making OAuth request to: %s with token", req.URL.String())
	return c.client.Do(req)
}
