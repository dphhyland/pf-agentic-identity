package authzen

import (
	"fmt"
	"os"
)

// NewAuthenticatorFromEnv creates a new authenticator based on environment variables
func NewAuthenticatorFromEnv() (Authenticator, error) {
	// Load configuration from environment variables
	cfg, err := LoadConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to load auth config: %w", err)
	}

	switch cfg.Type {
	case AuthTypeBearer:
		// For bearer token authentication
		token := os.Getenv("AUTH_BEARER_TOKEN")
		if token == "" {
			return nil, fmt.Errorf("AUTH_BEARER_TOKEN environment variable is required for bearer auth")
		}
		return NewBearerAuthenticator(token), nil

	case AuthTypeOAuth:
		// For OAuth client credentials flow
		oauthCfg := &OAuthConfig{
			BaseURL:      cfg.OAuthBaseURL,
			ClientID:     cfg.OAuthClientID,
			ClientSecret: cfg.OAuthClientSecret,
		}
		return NewOAuthAuthenticator(oauthCfg), nil

	case AuthTypeNone:
		return NewNoneAuthenticator(), nil

	default:
		return nil, fmt.Errorf("unsupported auth type %q (want bearer, oauth or none)", cfg.Type)
	}
}

// NewAuthZenClientFromEnv creates a new AuthZen client with authenticator configured from environment variables
func NewAuthZenClientFromEnv(baseURL string) (*AuthZenClient, error) {
	authenticator, err := NewAuthenticatorFromEnv()
	if err != nil {
		return nil, fmt.Errorf("failed to create authenticator: %w", err)
	}

	return NewAuthZenClient(baseURL, authenticator)
}
