package authzen

import (
	"fmt"

	"github.com/kelseyhightower/envconfig"
)

// AuthType represents the type of authentication to use
type AuthType string

const (
	// AuthTypeBearer uses a static bearer token from environment variable
	AuthTypeBearer AuthType = "bearer"
	// AuthTypeOAuth uses OAuth client credentials flow
	AuthTypeOAuth  AuthType = "oauth"
	// AuthTypeNone sends no credentials. Only for a PDP that requires none --
	// the bundled demo PDP, or one already isolated on a private network.
	AuthTypeNone AuthType = "none"
)

// Config holds the authentication configuration
type Config struct {
	// Type of authentication to use (bearer or oauth)
	Type AuthType `envconfig:"AUTH_TYPE" default:"bearer"`
	
	// For bearer token authentication
	BearerToken string `envconfig:"AUTH_BEARER_TOKEN"`
	
	// For OAuth authentication
	OAuthBaseURL      string `envconfig:"OAUTH_BASE_URL"`
	OAuthClientID     string `envconfig:"OAUTH_CLIENT_ID"`
	OAuthClientSecret string `envconfig:"OAUTH_CLIENT_SECRET"`
}

// LoadConfig loads the configuration from environment variables
func LoadConfig() (*Config, error) {
	var cfg Config
	// Using envconfig for automatic environment variable loading
	err := envconfig.Process("", &cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to load config: %w", err)
	}

	// Validate configuration based on auth type
	switch cfg.Type {
	case AuthTypeBearer:
		if cfg.BearerToken == "" {
			return nil, fmt.Errorf("bearer token is required for bearer auth")
		}
	case AuthTypeOAuth:
		if cfg.OAuthBaseURL == "" || cfg.OAuthClientID == "" || cfg.OAuthClientSecret == "" {
			return nil, fmt.Errorf("OAuth configuration is incomplete")
		}
	case AuthTypeNone:
		// Nothing to validate: no credentials are sent.
	default:
		return nil, fmt.Errorf("unsupported auth type %q (want bearer, oauth or none)", cfg.Type)
	}

	return &cfg, nil
}
