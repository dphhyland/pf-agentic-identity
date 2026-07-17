package authzen

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

)

// Authenticator is an interface that all authentication methods must implement
type Authenticator interface {
	// AddAuthHeader adds the appropriate authentication header to the request
	AddAuthHeader(req *http.Request) error
}

// BearerAuthenticator implements Authenticator using a static bearer token
type BearerAuthenticator struct {
	token string
}

// NewBearerAuthenticator creates a new BearerAuthenticator
func NewBearerAuthenticator(token string) *BearerAuthenticator {
	return &BearerAuthenticator{
		token: token,
	}
}

// AddAuthHeader adds the Bearer token to the request
func (b *BearerAuthenticator) AddAuthHeader(req *http.Request) error {
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", b.token))
	return nil
}

// NoneAuthenticator sends no credentials.
//
// It exists so a PDP that requires no authentication can be configured
// explicitly, rather than by passing a dummy bearer token and hoping the PDP
// ignores it. AUTH_TYPE=none is a deliberate statement that the PDP is
// unprotected -- appropriate for the bundled demo PDP, and for nothing that
// decides real access.
type NoneAuthenticator struct{}

// NewNoneAuthenticator creates an Authenticator that adds no credentials.
func NewNoneAuthenticator() *NoneAuthenticator { return &NoneAuthenticator{} }

// AddAuthHeader adds nothing.
func (*NoneAuthenticator) AddAuthHeader(*http.Request) error { return nil }

// OAuthAuthenticator implements Authenticator using OAuth client credentials
type OAuthAuthenticator struct {
	config     *OAuthConfig
	token     string
expiry    time.Time
	mu        sync.Mutex
	client    *http.Client
}

// NewOAuthAuthenticator creates a new OAuthAuthenticator
func NewOAuthAuthenticator(config *OAuthConfig) *OAuthAuthenticator {
	return &OAuthAuthenticator{
		config: config,
		client: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: false},
			},
		},
	}
}

// AddAuthHeader adds the OAuth token to the request
func (o *OAuthAuthenticator) AddAuthHeader(req *http.Request) error {
	o.mu.Lock()
	defer o.mu.Unlock()

	// Check if token is expired or about to expire (within 1 minute)
	if o.token == "" || time.Until(o.expiry) < time.Minute {
		if err := o.refreshToken(); err != nil {
			return fmt.Errorf("failed to refresh token: %w", err)
		}
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", o.token))
	return nil
}

// refreshToken gets a new OAuth token using client credentials
type tokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
}

func (o *OAuthAuthenticator) refreshToken() error {
	// Prepare the request
	body := fmt.Sprintf("grant_type=client_credentials&client_id=%s&client_secret=%s",
		o.config.ClientID, o.config.ClientSecret)

	req, err := http.NewRequest("POST", o.config.BaseURL+"/oauth/token", bytes.NewBufferString(body))
	if err != nil {
		return fmt.Errorf("failed to create token request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Send the request
	resp, err := o.client.Do(req)
	if err != nil {
		return fmt.Errorf("token request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("token request failed with status %d: %s", resp.StatusCode, string(body))
	}

	// Parse the response
	var tokenResp tokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return fmt.Errorf("failed to decode token response: %w", err)
	}

	// Update token and expiry
	o.token = tokenResp.AccessToken
	// Default to 1 hour if not specified
	if tokenResp.ExpiresIn == 0 {
		tokenResp.ExpiresIn = 3600
	}
	o.expiry = time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)

	return nil
}

// NewAuthenticator creates a new Authenticator based on the configuration
func NewAuthenticator(cfg *Config) (Authenticator, error) {
	switch cfg.Type {
	case AuthTypeBearer:
		return NewBearerAuthenticator(cfg.BearerToken), nil
	case AuthTypeOAuth:
		oauthCfg := &OAuthConfig{
			BaseURL:      cfg.OAuthBaseURL,
			ClientID:     cfg.OAuthClientID,
			ClientSecret: cfg.OAuthClientSecret,
		}
		return NewOAuthAuthenticator(oauthCfg), nil
	default:
		return nil, fmt.Errorf("unsupported auth type: %s", cfg.Type)
	}
}
