package middleware

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Context keys for storing values in request context
type contextKey string

const (
	tokenContextKey contextKey = "token"
)

var (
	// ErrNoToken is returned when no token is provided
	ErrNoToken = errors.New("authorization token required")
	// ErrInvalidToken is returned when the token is invalid
	ErrInvalidToken = errors.New("invalid or expired token")
)

// TokenValidator is an interface for validating JWT tokens
type TokenValidator interface {
	// ValidateToken validates the given token string and returns the claims if valid
	ValidateToken(tokenString string) (*TokenClaims, error)
}

// TokenClaims represents the claims we expect in a JWT
type TokenClaims struct {
	jwt.RegisteredClaims
	ClientID string   `json:"client_id,omitempty"`
	Scopes   []string `json:"scope,omitempty"`
	// Claims contains all the claims from the token for dynamic access
	Claims map[string]interface{} `json:"-"`
}

// GetSubjectValue returns the subject claim value as a string
// This is a convenience method for easier access to the subject
func (c *TokenClaims) GetSubjectValue() string {
	if c == nil {
		return ""
	}
	return c.Subject
}

// GetUserKeyClaimValue returns the value of the claim specified by GRANT_USER_KEY_CLAIM environment variable
// with fallback to the subject claim if not found or empty
func (c *TokenClaims) GetUserKeyClaimValue() string {
	if c == nil {
		return ""
	}

	// Default to standard claims if custom claims not available
	if c.Claims == nil {
		return c.Subject
	}

	// Get the claim name from environment, default to "preferred_username"
	claimName := os.Getenv("GRANT_USER_KEY_CLAIM")
	if claimName == "" {
		claimName = "preferred_username"
	}

	// Try to get the claim value
	if claimValue, ok := c.Claims[claimName].(string); ok && claimValue != "" {
		return claimValue
	}

	// Fall back to subject claim if specified claim not found or empty
	return c.Subject
}

// customClaims is used to parse the JWT claims before converting to TokenClaims
type customClaims struct {
	jwt.RegisteredClaims
	ClientID string      `json:"client_id,omitempty"`
	Scope    interface{} `json:"scope,omitempty"`
	// Add a map to capture all claims for dynamic access
	Claims map[string]interface{} `json:"-"`
}

// UnmarshalJSON implements json.Unmarshaler to handle dynamic claim names
func (c *customClaims) UnmarshalJSON(data []byte) error {
	// First, unmarshal into a map to handle dynamic claim names
	var rawClaims map[string]interface{}
	if err := json.Unmarshal(data, &rawClaims); err != nil {
		return err
	}

	// Store all claims for later access
	c.Claims = make(map[string]interface{})
	for k, v := range rawClaims {
		c.Claims[k] = v
	}

	// Use type alias to avoid recursive call
	type Alias customClaims
	var alias Alias
	if err := json.Unmarshal(data, &alias); err != nil {
		return err
	}

	// Copy the fields from alias to c
	c.RegisteredClaims = alias.RegisteredClaims
	c.ClientID = alias.ClientID
	c.Scope = alias.Scope

	return nil
}

// JWKS represents a JSON Web Key Set
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// JWK represents a JSON Web Key
type JWK struct {
	Kty string   `json:"kty"`
	Use string   `json:"use,omitempty"`
	Kid string   `json:"kid,omitempty"`
	Alg string   `json:"alg,omitempty"`
	N   string   `json:"n,omitempty"`
	E   string   `json:"e,omitempty"`
	X5c []string `json:"x5c,omitempty"`
}

// JWKSValidator implements TokenValidator using a JSON Web Key Set
// This is used to validate JWT signatures against a JWKS endpoint
type JWKSValidator struct {
	// SubjectClaimName is the name of the claim to use as the subject
	// Defaults to "sub" if not set
	SubjectClaimName string

	// JWKSURL is the URL to fetch the JSON Web Key Set from
	JWKSURL string

	// Issuer is the expected "iss" claim value, i.e. the issuer identifier of
	// the authorization server. When set, tokens must carry a matching iss.
	// When empty, issuer validation is skipped and trust rests solely on the
	// signature chaining back to JWKSURL.
	Issuer string

	// HTTP client for fetching JWKS
	httpClient *http.Client

	// Cached public keys
	keys   map[string]interface{}
	keysMu sync.RWMutex

	// Serialises refreshes so that a burst of tokens carrying an unknown kid
	// results in one JWKS fetch rather than one per request. Must never be
	// taken while holding keysMu.
	refreshMu sync.Mutex

	// Last time the JWKS was refreshed
	lastRefresh time.Time

	// Refresh interval for JWKS
	refreshInterval time.Duration

	// InsecureSkipTLSVerify relaxes TLS certificate checking on the JWKS fetch,
	// for a development AS serving a self-signed cert. It has no bearing on JWT
	// signature verification, which is never skipped here.
	InsecureSkipTLSVerify bool
}

// NewJWKSValidator creates a new JWKSValidator with the specified JWKS URL
func NewJWKSValidator(jwksURL string, insecureSkipVerify ...bool) *JWKSValidator {
	httpClient := &http.Client{
		Timeout: 10 * time.Second,
	}

	// Configure TLS if insecureSkipVerify is true
	if len(insecureSkipVerify) > 0 && insecureSkipVerify[0] {
		transport := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		httpClient.Transport = transport
	}

	return &JWKSValidator{
		JWKSURL:               jwksURL,
		httpClient:            httpClient,
		keys:                  make(map[string]interface{}),
		refreshInterval:       1 * time.Hour, // Default refresh interval
		InsecureSkipTLSVerify: len(insecureSkipVerify) > 0 && insecureSkipVerify[0],
	}
}

// fetchKeys fetches the JWKS from the configured URL
func (v *JWKSValidator) fetchKeys() error {
	log.Printf("[DEBUG] Fetching JWKS from %s\n", v.JWKSURL)

	if v.JWKSURL == "" {
		return fmt.Errorf("no JWKS URL configured")
	}

	// A JWKSValidator built as a struct literal rather than via NewJWKSValidator
	// has no client; fall back rather than nil-panic inside auth middleware.
	client := v.httpClient
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}

	resp, err := client.Get(v.JWKSURL)
	if err != nil {
		return fmt.Errorf("failed to fetch JWKS: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var jwks JWKS
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return fmt.Errorf("failed to decode JWKS: %w", err)
	}

	v.keysMu.Lock()
	defer v.keysMu.Unlock()

	// Clear existing keys
	v.keys = make(map[string]interface{})

	// Process each key in the JWKS
	for _, key := range jwks.Keys {
		// Skip keys explicitly reserved for encryption. RFC 7517 makes "use"
		// optional, so a key that omits it is still a signing-key candidate --
		// requiring use=="sig" here would discard every key from an AS that
		// leaves the field out, leaving no keys to verify against.
		if key.Use == "enc" {
			continue
		}

		// Only support RSA keys for now
		if key.Kty == "RSA" {
			publicKey, err := key.rsaPublicKey()
			if err != nil {
				log.Printf("[WARN] Failed to parse RSA public key: %v\n", err)
				continue
			}

			kid := key.Kid
			if kid == "" {
				kid = "default"
			}

			v.keys[kid] = publicKey
			log.Printf("[DEBUG] Loaded public key with kid: %s\n", kid)
		}
	}

	v.lastRefresh = time.Now()
	return nil
}

// getKeyFunc returns a key function that retrieves the key from the JWKS endpoint
func (v *JWKSValidator) getKeyFunc() (jwt.Keyfunc, error) {
	// Initial fetch if needed
	v.keysMu.RLock()
	empty := len(v.keys) == 0
	v.keysMu.RUnlock()
	if empty {
		if err := v.fetchKeys(); err != nil {
			return nil, fmt.Errorf("failed to fetch initial JWKS: %w", err)
		}
	}

	return func(token *jwt.Token) (interface{}, error) {
		// A token need not carry a kid -- RFC 7515 makes the header optional --
		// and an empty kid is resolved against a single-key JWKS by lookupKey.
		kid, _ := token.Header["kid"].(string)
		log.Printf("[DEBUG] Looking for key with kid: %q\n", kid)

		key, found, lastRefresh := v.lookupKey(kid)

		// If key not found or it's time to refresh, try to refresh the JWKS.
		// fetchKeys takes keysMu itself, so no lock may be held here.
		if !found || time.Since(lastRefresh) > v.refreshInterval {
			key, found = v.refreshAndLookup(kid)
		}

		if !found {
			availableKeys := v.getKeyIDs()
			log.Printf("[ERROR] No key found for kid: %s\n", kid)
			log.Printf("[DEBUG] Available key IDs: %v\n", availableKeys)
			return nil, fmt.Errorf("no key found for kid: %s (available keys: %v)", kid, availableKeys)
		}

		log.Printf("[DEBUG] Using key with kid: %s for token validation\n", kid)
		return key, nil
	}, nil
}

// lookupKey reads a key from the cache along with the cache's last refresh time.
// An empty kid resolves to the sole cached key when the JWKS holds exactly one;
// with several keys the token is ambiguous without a kid and nothing resolves.
func (v *JWKSValidator) lookupKey(kid string) (key interface{}, found bool, lastRefresh time.Time) {
	v.keysMu.RLock()
	defer v.keysMu.RUnlock()

	if kid == "" {
		if len(v.keys) != 1 {
			return nil, false, v.lastRefresh
		}
		for _, only := range v.keys {
			return only, true, v.lastRefresh
		}
	}

	key, found = v.keys[kid]
	return key, found, v.lastRefresh
}

// refreshAndLookup refreshes the JWKS cache and re-reads kid from it. Callers
// must not hold keysMu. If the refresh fails the cache is left as-is and the
// lookup proceeds against the existing, potentially stale, keys.
func (v *JWKSValidator) refreshAndLookup(kid string) (interface{}, bool) {
	v.refreshMu.Lock()
	defer v.refreshMu.Unlock()

	// Another goroutine may have refreshed while we waited for refreshMu.
	if key, found, lastRefresh := v.lookupKey(kid); found && time.Since(lastRefresh) <= v.refreshInterval {
		return key, true
	}

	log.Printf("[DEBUG] Refreshing JWKS cache")
	if err := v.fetchKeys(); err != nil {
		log.Printf("[ERROR] Failed to refresh JWKS: %v\n", err)
		// Continue with potentially stale keys if refresh fails
	} else {
		log.Printf("[DEBUG] Successfully refreshed JWKS cache")
	}

	key, found, _ := v.lookupKey(kid)
	return key, found
}

// getKeyIDs returns a slice of available key IDs for debugging
func (v *JWKSValidator) getKeyIDs() []string {
	v.keysMu.RLock()
	defer v.keysMu.RUnlock()

	ids := make([]string, 0, len(v.keys))
	for id := range v.keys {
		ids = append(ids, id)
	}
	return ids
}

// rsaPublicKey converts a JWK to an RSA public key
func (jwk *JWK) rsaPublicKey() (*rsa.PublicKey, error) {
	// Decode the base64 URL-encoded modulus (n)
	nBytes, err := base64.RawURLEncoding.DecodeString(jwk.N)
	if err != nil {
		return nil, fmt.Errorf("failed to decode modulus: %w", err)
	}

	// Decode the base64 URL-encoded public exponent (e)
	eBytes, err := base64.RawURLEncoding.DecodeString(jwk.E)
	if err != nil {
		return nil, fmt.Errorf("failed to decode exponent: %w", err)
	}

	// Convert exponent bytes to int
	var eInt int
	for _, b := range eBytes {
		eInt = (eInt << 8) + int(b)
	}

	// Create and return the RSA public key
	return &rsa.PublicKey{
		N: new(big.Int).SetBytes(nBytes),
		E: eInt,
	}, nil
}

// ValidateToken validates a JWT token and returns its claims.
//
// The signature is always verified against the JWKS. There is deliberately no
// way to turn that off here: skipping validation entirely is what
// SKIP_JWT_VALIDATION and the format-only validator are for, and that choice
// should be made once, visibly, at construction -- not smuggled in by a flag
// whose name talks about TLS.
func (v *JWKSValidator) ValidateToken(tokenString string) (*TokenClaims, error) {
	log.Printf("[DEBUG] Starting token validation\n")
	log.Printf("[DEBUG] Token (first 50 chars): %s...\n", tokenString[:min(50, len(tokenString))])

	var claims customClaims

	keyFunc, err := v.getKeyFunc()
	if err != nil {
		log.Printf("[ERROR] Failed to get key function: %v\n", err)
		return nil, fmt.Errorf("%w: failed to get key function", ErrInvalidToken)
	}

	opts := []jwt.ParserOption{
		jwt.WithValidMethods([]string{"RS256", "RS384", "RS512"}),
	}
	if v.Issuer != "" {
		opts = append(opts, jwt.WithIssuer(v.Issuer))
	}

	token, err := jwt.ParseWithClaims(tokenString, &claims, keyFunc, opts...)
	if err != nil {
		log.Printf("[ERROR] Token validation failed: %v\n", err)
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}
	if !token.Valid {
		log.Println("[ERROR] Token is not valid")
		return nil, ErrInvalidToken
	}

	// Log the claims for debugging
	log.Printf("[DEBUG] All token claims: %+v\n", claims.Claims)

	// Convert the claims to a map for dynamic access
	claimsMap := make(map[string]interface{})
	// Add all claims from the token to the map
	for k, v := range claims.Claims {
		claimsMap[k] = v
	}
	// Add standard claims to the map
	if claims.Subject != "" {
		claimsMap["sub"] = claims.Subject
	}
	if claims.Issuer != "" {
		claimsMap["iss"] = claims.Issuer
	}
	if len(claims.Audience) > 0 {
		claimsMap["aud"] = claims.Audience
	}
	if claims.ExpiresAt != nil {
		claimsMap["exp"] = claims.ExpiresAt.Unix()
	}
	if claims.NotBefore != nil {
		claimsMap["nbf"] = claims.NotBefore.Unix()
	}
	if claims.IssuedAt != nil {
		claimsMap["iat"] = claims.IssuedAt.Unix()
	}
	if claims.ID != "" {
		claimsMap["jti"] = claims.ID
	}

	// Resolve the subject from the configured claim, falling back to the
	// standard "sub". Everything downstream keys off this -- it selects the
	// grant to evaluate and is the identifier presented to the PDP -- so a
	// token we cannot attribute to a subject is rejected rather than passed
	// on with an empty one.
	subjectClaimName := v.SubjectClaimName
	if subjectClaimName == "" {
		subjectClaimName = "sub"
	}

	subject, _ := claimsMap[subjectClaimName].(string)
	if subject == "" && subjectClaimName != "sub" {
		if fallback, _ := claimsMap["sub"].(string); fallback != "" {
			log.Printf("[DEBUG] Subject claim %q absent, falling back to \"sub\"\n", subjectClaimName)
			subject = fallback
		}
	}
	if subject == "" {
		log.Printf("[ERROR] No subject in token (looked for %q, then \"sub\")\n", subjectClaimName)
		return nil, fmt.Errorf("%w: missing required subject claim", ErrInvalidToken)
	}
	log.Printf("[DEBUG] Resolved subject %q from claim %q\n", subject, subjectClaimName)

	// Check if the token is expired (should be handled by jwt-go, but double-checking)
	if claims.ExpiresAt != nil && claims.ExpiresAt.Before(time.Now()) {
		log.Printf("[DEBUG] Token expired at %v\n", claims.ExpiresAt)
		return nil, fmt.Errorf("%w: token expired", ErrInvalidToken)
	}

	// Get the subject from the token
	result := &TokenClaims{
		RegisteredClaims: claims.RegisteredClaims,
		ClientID:         claims.ClientID,
		Claims:           claimsMap, // Include all claims for dynamic access
	}
	// Carry the resolved subject, which may have come from a non-standard claim.
	result.Subject = subject

	// Handle scopes which could be a string or []interface{}
	switch s := claims.Scope.(type) {
	case string:
		// Split space-separated scopes
		result.Scopes = strings.Fields(s)
	case []interface{}:
		// Convert []interface{} to []string
		for _, scope := range s {
			if str, ok := scope.(string); ok {
				result.Scopes = append(result.Scopes, str)
			}
		}
	}

	log.Printf("[DEBUG] Token validation successful for subject: %s\n", result.Subject)
	return result, nil
}
func Authenticate(validator TokenValidator) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			log.Printf("[AUTH] Processing request: %s %s", r.Method, r.URL.Path)

			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				errMsg := "missing Authorization header"
				log.Printf("[AUTH] Error: %s", errMsg)
				http.Error(w, ErrNoToken.Error(), http.StatusUnauthorized)
				return
			}

			// Expecting: Bearer <token>
			parts := strings.SplitN(authHeader, " ", 2)
			if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
				errMsg := fmt.Sprintf("invalid Authorization header format: %s", authHeader)
				log.Printf("[AUTH] Error: %s", errMsg)
				http.Error(w, "authorization header format must be: Bearer <token>", http.StatusUnauthorized)
				return
			}

			tokenString := parts[1]

			// Validate the token using the provided validator
			validatedClaims, err := validator.ValidateToken(tokenString)
			if err != nil {
				log.Printf("[AUTH] Token validation failed: %v", err)
				http.Error(w, "invalid or expired token", http.StatusUnauthorized)
				return
			}

			// Use the validated claims
			tokenClaims := validatedClaims

			log.Printf("[AUTH] Token processed. ClientID: %s, Subject: %s, Scopes: %v",
				tokenClaims.ClientID, tokenClaims.Subject, tokenClaims.Scopes)

			// Add the token claims to the request context
			ctx := context.WithValue(r.Context(), tokenContextKey, tokenClaims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// RequireScope is a middleware that checks if the token has the required scope
func RequireScope(requiredScope string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			log.Printf("[AUTH] Checking for required scope: %s on %s %s",
				requiredScope, r.Method, r.URL.Path)

			claims, ok := GetTokenClaimsFromContext(r.Context())
			if !ok {
				errMsg := "missing or invalid token claims"
				log.Printf("[AUTH] Error: %s", errMsg)
				http.Error(w, "unauthorized: "+errMsg, http.StatusUnauthorized)
				return
			}

			log.Printf("[AUTH] Token claims - ClientID: %s, Scopes: %v",
				claims.ClientID, claims.Scopes)

			// Check if the required scope is in the token's scopes
			hasScope := false
			for _, scope := range claims.Scopes {
				log.Printf("[AUTH] Checking scope: %s == %s", scope, requiredScope)
				if scope == requiredScope {
					hasScope = true
					break
				}
			}

			if !hasScope {
				errMsg := fmt.Sprintf("missing required scope: %s", requiredScope)
				log.Printf("[AUTH] Error: %s. Available scopes: %v", errMsg, claims.Scopes)
				http.Error(w, "insufficient_scope: "+errMsg, http.StatusForbidden)
				return
			}

			log.Printf("[AUTH] Scope check passed for required scope: %s", requiredScope)
			next.ServeHTTP(w, r)
		})
	}
}

// GetTokenClaimsFromContext retrieves the token claims from the request context
func GetTokenClaimsFromContext(ctx context.Context) (*TokenClaims, bool) {
	claims, ok := ctx.Value(tokenContextKey).(*TokenClaims)
	return claims, ok
}

// ContextWithTokenClaims returns a context carrying the given claims, as the
// Authenticate middleware would. The context key is unexported, so without this
// nothing outside the package can stand in for an authenticated request.
func ContextWithTokenClaims(ctx context.Context, claims *TokenClaims) context.Context {
	return context.WithValue(ctx, tokenContextKey, claims)
}
