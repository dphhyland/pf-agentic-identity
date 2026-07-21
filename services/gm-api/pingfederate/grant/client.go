package grant

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"idp-gm-api/middleware"
)

// Helper function to find minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// buildCurlCommand constructs an approximate curl command for the given request.
// The password is masked; Bearer token is truncated.
func buildCurlCommand(req *http.Request, username, password, token string) string {
	var b strings.Builder
	b.WriteString("curl -k -X ")
	b.WriteString(req.Method)
	b.WriteString(" \"")
	b.WriteString(req.URL.String())
	b.WriteString("\"")

	if username != "" {
		b.WriteString(" -u \"")
		b.WriteString(username)
		b.WriteString(":*****\"")
	} else if token != "" {
		b.WriteString(" -H \"Authorization: Bearer ")
		if len(token) > 10 {
			b.WriteString(token[:10] + "...\"")
		} else {
			b.WriteString(token + "\"")
		}
	}

	for name, vals := range req.Header {
		if strings.EqualFold(name, "Authorization") {
			continue // already handled above
		}
		for _, v := range vals {
			b.WriteString(" -H \"")
			b.WriteString(name)
			b.WriteString(": ")
			b.WriteString(v)
			b.WriteString("\"")
		}
	}
	return b.String()
}

// applyAuth sets the appropriate authentication and CSRF headers on the request.
func (c *Client) applyAuth(req *http.Request) {
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
		log.Printf("[DEBUG] applyAuth: using Bearer token (length %d)", len(c.Token))
	} else if c.Username != "" {
		req.SetBasicAuth(c.Username, c.Password)
		log.Printf("[DEBUG] applyAuth: using Basic Auth username %s", c.Username)
	} else {
		log.Printf("[WARN] applyAuth: no authentication credentials provided")
	}
	// CSRF header required by PingFederate admin APIs
	req.Header.Set("X-XSRF-HEADER", "PingFederate")
}

// Common errors
var (
	ErrInvalidGrantID = errors.New("invalid grant ID")
	ErrInvalidScope   = errors.New("invalid scope format")
)

// Client represents a PingFederate Grant Management API client
type Client struct {
	BaseURL    string
	HTTPClient *http.Client

	// Authentication options (choose one)
	Token    string // PINGFED_ADMIN_TOKEN
	Username string // PINGFED_ADMIN_USER
	Password string // PINGFED_ADMIN_PASS
}

// NewClient creates a new PingFederate Grant Management client
// If token is provided, it will be used for Bearer token authentication
// If username and password are provided, they will be used for Basic Auth
func NewClient(baseURL, token, username, password string) *Client {
	log.Printf("[DEBUG] Creating new Grant Management client with baseURL: %s", baseURL)
	
	if token != "" {
		log.Printf("[DEBUG] Using Bearer token authentication (length: %d)", len(token))
	} else if username != "" {
		log.Printf("[DEBUG] Using Basic Auth with username: %s", username)
	} else {
		log.Printf("[WARNING] No authentication credentials provided")
	}

	// Create a custom transport that skips TLS verification
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, // Skip TLS verification for self-signed certs
		},
	}

	return &Client{
		BaseURL: baseURL,
		HTTPClient: &http.Client{
			Timeout:   10 * time.Second,
			Transport: transport,
		},
		Token:    token,
		Username: username,
		Password: password,
	}
}

// Scope represents an OAuth 2.0 scope with optional resource indicators
type Scope struct {
	Scope    string   `json:"scope"`
	Resource []string `json:"resource,omitempty"`
}

// UnmarshalJSON implements custom unmarshaling for Scope to handle both string and object formats
func (s *Scope) UnmarshalJSON(data []byte) error {
	// First try to unmarshal as a string
	var scopeStr string
	if err := json.Unmarshal(data, &scopeStr); err == nil {
		s.Scope = scopeStr
		s.Resource = nil // No resources when scope is just a string
		return nil
	}

	// If not a string, try to unmarshal as an object
	var aux struct {
		Scope    string   `json:"scope"`
		Resource []string `json:"resource,omitempty"`
	}

	if err := json.Unmarshal(data, &aux); err != nil {
		return fmt.Errorf("failed to unmarshal scope: %w", err)
	}

	s.Scope = aux.Scope
	s.Resource = aux.Resource
	return nil
}

// MarshalJSON implements custom marshaling for Scope to ensure consistent output format
func (s Scope) MarshalJSON() ([]byte, error) {
	if len(s.Resource) == 0 {
		// If no resources, marshal as a simple string
		return json.Marshal(s.Scope)
	}
	// Otherwise marshal as an object
	return json.Marshal(struct {
		Scope    string   `json:"scope"`
		Resource []string `json:"resource,omitempty"`
	}{
		Scope:    s.Scope,
		Resource: s.Resource,
	})
}

// AuthorizationDetail represents fine-grained authorization details
type AuthorizationDetail struct {
	Type       string                 `json:"type"`
	Actions    []string               `json:"actions,omitempty"`
	Locations  []string               `json:"locations,omitempty"`
	Identifier string                 `json:"identifier,omitempty"`
	Data       map[string]interface{} `json:"data,omitempty"`

	// Description is what the user was actually shown when they approved this
	// consent, rendered by the AS's authorization detail processor. It is present
	// only on natively-stored consent, and is the closest thing available to a
	// record of what the human understood themselves to be agreeing to.
	Description string `json:"description,omitempty"`
}

// Grant represents a persistent grant according to the OAuth 2.0 Grant Management specification
type Grant struct {
	// Standard fields
	ID             string        `json:"id,omitempty"`
	ClientID       string        `json:"clientId,omitempty"`
	UserKey        string        `json:"userKey,omitempty"`  // User identifier from PingFederate
	UserID         string        `json:"user_id,omitempty"`  // Backward compatibility
	Scopes         []Scope       `json:"scopes,omitempty"`
	Claims         []string      `json:"claims,omitempty"`
	CreatedAt      int64         `json:"created_at,omitempty"`
	LastUpdatedAt  int64         `json:"last_updated_at,omitempty"`
	ExpiresAt      int64         `json:"expires_at,omitempty"`
	UpdatedBy      string        `json:"updated_by,omitempty"`
	GrantType      string        `json:"grantType,omitempty"`
	Status         string        `json:"status,omitempty"`
	Metadata       map[string]interface{} `json:"metadata,omitempty"`

	// AuthzDetails is the RFC 9396 consent. PingFederate carries it as a grant
	// attribute rather than as native RAR, so it is decoded in UnmarshalJSON
	// rather than mapped straight off a field -- see grantAttribute.
	AuthzDetails []AuthorizationDetail `json:"-"`
}

// grantAttribute is one entry of PingFederate's grantAttributes array.
//
// PF models grant attributes as name/values pairs, not as the object the
// attribute happens to contain, so authorization_details arrives as a JSON
// document *inside* a string in values. Decoding it needs a second pass.
type grantAttribute struct {
	Name   string   `json:"name"`
	Values []string `json:"values"`
}

// authorizationDetailsAttribute is the grant attribute the consent travels in when
// PingFederate has no Authorization Detail Processor deployed and the consent has to
// be injected as a persistent-grant extended attribute instead. It matches the
// extended attribute declared on the persistent grant contract in
// deploy/pingfederate/terraform/oauth-server-settings.tf.
const authorizationDetailsAttribute = "authorization_details"

// decodeAuthzDetails resolves the grant's RFC 9396 consent onto g.AuthzDetails.
//
// PingFederate can carry the consent two ways, and they are not equal:
//
//  1. Natively, as "authorizationDetails" on the grant. This is what the user was
//     actually shown and approved at the authorization endpoint, and it only
//     exists when an Authorization Detail Processor is deployed to validate the
//     type (PF ships none; see plugins/authorization-detail-processor).
//
//  2. As an "authorization_details" grant attribute holding a JSON array encoded
//     inside a string. This is the fallback for a PF with no processor, where the
//     consent has to be injected server-side rather than requested by the client.
//
// The native form wins whenever it is present, because it is the only one that
// records what a human agreed to. The attribute is whatever the AS configuration
// put there, which need not be the same thing.
//
// A grant with neither is not an error: it is a scope-only grant.
func (g *Grant) decodeAuthzDetails(data []byte) error {
	var envelope struct {
		AuthorizationDetails []AuthorizationDetail `json:"authorizationDetails"`
		GrantAttributes      []grantAttribute      `json:"grantAttributes"`
	}
	if err := json.Unmarshal(data, &envelope); err != nil {
		// The grant itself parsed; a shape we cannot read here is not fatal.
		log.Printf("[WARN] could not read grant consent fields: %v", err)
		return nil
	}

	if len(envelope.AuthorizationDetails) > 0 {
		g.AuthzDetails = envelope.AuthorizationDetails
		log.Printf("[DEBUG] using %d native authorization detail(s) from the grant",
			len(g.AuthzDetails))
		return nil
	}

	for _, attr := range envelope.GrantAttributes {
		if attr.Name != authorizationDetailsAttribute || len(attr.Values) == 0 {
			continue
		}
		var details []AuthorizationDetail
		if err := json.Unmarshal([]byte(attr.Values[0]), &details); err != nil {
			// Consent we cannot read must not be treated as no consent: that
			// would look identical to a grant that never had any, and the PDP
			// would deny with a misleading reason. Fail loudly instead.
			return fmt.Errorf("grant %s carries an unparseable %s attribute: %w",
				g.ID, authorizationDetailsAttribute, err)
		}
		g.AuthzDetails = details
		log.Printf("[DEBUG] decoded %d authorization detail(s) from grant attributes", len(details))
		return nil
	}
	return nil
}

// UnmarshalJSON implements custom unmarshaling for Grant to handle PingFederate's response format
func (g *Grant) UnmarshalJSON(data []byte) error {
	// Define an auxiliary type to avoid recursion
	type Alias Grant
	aux := &struct {
		*Alias
		Issued  string `json:"issued,omitempty"`
		Updated string `json:"updated,omitempty"`
	}{
		Alias: (*Alias)(g),
	}

	// Unmarshal into the auxiliary type
	if err := json.Unmarshal(data, &aux); err != nil {
		return fmt.Errorf("failed to unmarshal grant: %w", err)
	}

	// Convert issued/updated timestamps to unix timestamps if needed
	// (PingFederate returns ISO 8601 formatted strings)
	if aux.Issued != "" {
		t, err := time.Parse(time.RFC3339, aux.Issued)
		if err == nil {
			g.CreatedAt = t.Unix()
		}
	}

	if aux.Updated != "" {
		t, err := time.Parse(time.RFC3339, aux.Updated)
		if err == nil {
			g.LastUpdatedAt = t.Unix()
		}
	}

	// Decode the consent out of PF's grant attributes.
	if err := g.decodeAuthzDetails(data); err != nil {
		return err
	}

	// Scopes are already decoded by the struct tag above; Scope.UnmarshalJSON
	// copes with both the bare-string and object forms PF may use. Re-reading
	// them here would append a second copy of every scope.
	var rawData map[string]interface{}
	if err := json.Unmarshal(data, &rawData); err == nil {
		// Ensure UserID is set from UserKey if empty
		if g.UserID == "" && g.UserKey != "" {
			g.UserID = g.UserKey
		}

		// Ensure ID is set from the root "id" field
		if id, ok := rawData["id"].(string); ok && id != "" {
			g.ID = id
		}

		// Ensure ClientID is set from the root "clientId" field if not already set
		if clientID, ok := rawData["clientId"].(string); ok && clientID != "" && g.ClientID == "" {
			g.ClientID = clientID
		}

		// Ensure GrantType is set from the root "grantType" field if not already set
		if grantType, ok := rawData["grantType"].(string); ok && grantType != "" && g.GrantType == "" {
			g.GrantType = grantType
		}
	}

	return nil
}

// GetGrant retrieves a persistent grant by ID for a specific user
func (c *Client) GetGrant(ctx context.Context, userID, grantID string) (*Grant, error) {
	if userID == "" {
		return nil, fmt.Errorf("userID is required")
	}
	if grantID == "" {
		return nil, fmt.Errorf("grantID is required")
	}

	// Get the user key from the token claims
	claims, ok := middleware.GetTokenClaimsFromContext(ctx)
	if !ok {
		return nil, fmt.Errorf("missing token claims in context")
	}
	
	userKey := claims.GetUserKeyClaimValue()
	if userKey == "" {
		return nil, fmt.Errorf("user key not found in token claims")
	}

	// Use the user-specific endpoint with the user key
	endpoint := fmt.Sprintf("%s/pf-ws/rest/oauth/users/%s/grants/%s", 
		c.BaseURL, url.PathEscape(userKey), url.PathEscape(grantID))

	log.Printf("[DEBUG] GetGrant: Retrieving grant with ID %s for user key: %s (subject: %s)", 
		grantID, userKey, userID)
	log.Printf("[DEBUG] GetGrant: Using endpoint: %s", endpoint)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Apply authentication (Bearer token or Basic Auth) and CSRF header
	c.applyAuth(req)
	req.Header.Set("Accept", "application/json")

	log.Printf("[DEBUG] GetGrant: Full request URL: %s", req.URL.String())
	log.Printf("[DEBUG] GetGrant: Request headers: %v", req.Header)

	// Log a curl command for easy debugging
	log.Printf("[DEBUG] GetGrant: curl: %s", buildCurlCommand(req, c.Username, c.Password, c.Token))

	// Send the request
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	log.Printf("[DEBUG] GetGrant: Response status: %s", resp.Status)
	log.Printf("[DEBUG] GetGrant: Response headers: %v", resp.Header)

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	log.Printf("[DEBUG] GetGrant: Response body: %s", string(body))

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d, body: %s", resp.StatusCode, string(body))
	}

	// Parse the response
	var grant Grant
	if err := json.Unmarshal(body, &grant); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	if c.Token == "" {
		log.Printf("[DEBUG] GetGrant: WARNING - Token is empty!")
	}

	log.Printf("[DEBUG] GetGrant: Successfully retrieved grant with ID: %s", grant.ID)
	return &grant, nil
}

// validate checks if the grant request is valid
func (g *GrantRequest) validate() error {
	// No required fields for update/replace operations
	return nil
}

// ToFormValues converts the query parameters to URL values
func (p *GrantQueryParams) ToFormValues() url.Values {
	v := url.Values{}
	if p.ClientID != "" {
		v.Set("client_id", p.ClientID)
	}
	if p.UserID != "" {
		v.Set("user_id", p.UserID)
	}
	if p.Scope != "" {
		v.Set("scope", p.Scope)
	}
	if p.Status != "" {
		v.Set("status", p.Status)
	}
	if p.Limit > 0 {
		v.Set("limit", fmt.Sprintf("%d", p.Limit))
	}
	if p.Offset > 0 {
		v.Set("offset", fmt.Sprintf("%d", p.Offset))
	}
	return v
}

// grantListResponse represents the response format from PingFederate's grants API
type grantListResponse struct {
	Items []struct {
		ID             string `json:"id"`
		UserKey        string `json:"userKey"`
		GrantType      string `json:"grantType"`
		Scopes         []string `json:"scopes"`
		ClientID       string `json:"clientId"`
		Issued         string `json:"issued"`
		Updated        string `json:"updated"`
		GrantAttributes []struct {
			Name   string   `json:"name"`
			Values []string `json:"values"`
		} `json:"grantAttributes"`
	} `json:"items"`
}

// ListGrants retrieves a list of persistent grants for the current user
func (c *Client) ListGrants(ctx context.Context, params GrantQueryParams) ([]Grant, error) {
	// Get the user key from the token claims
	claims, ok := middleware.GetTokenClaimsFromContext(ctx)
	if !ok {
		return nil, fmt.Errorf("missing token claims in context")
	}
	
	userKey := claims.GetUserKeyClaimValue()
	if userKey == "" {
		return nil, fmt.Errorf("user key not found in token claims")
	}

	// Use the user-specific endpoint with the user key
	endpoint := fmt.Sprintf("%s/pf-ws/rest/oauth/users/%s/grants/", c.BaseURL, url.PathEscape(userKey))

	log.Printf("[DEBUG] ListGrants: Starting with params: %+v", params)
	log.Printf("[DEBUG] ListGrants: Using endpoint: %s (userKey: %s)", endpoint, userKey)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Apply authentication
	c.applyAuth(req)
	req.Header.Set("Accept", "application/json")

	// Log the full request URL and headers for debugging
	log.Printf("[DEBUG] ListGrants: Full request URL: %s", req.URL.String())
	log.Printf("[DEBUG] ListGrants: Request headers: %v", req.Header)

	// Log a curl command for easy debugging
	log.Printf("[DEBUG] ListGrants: curl: %s", buildCurlCommand(req, c.Username, c.Password, c.Token))

	// Send the request
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	log.Printf("[DEBUG] ListGrants: Response status: %s", resp.Status)
	log.Printf("[DEBUG] ListGrants: Response headers: %v", resp.Header)

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	log.Printf("[DEBUG] ListGrants: Response body: %s", string(body))

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d, body: %s", resp.StatusCode, string(body))
	}

	// Parse the response
	var response grantListResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	// Convert the response to our internal Grant format
	grants := make([]Grant, 0, len(response.Items))
	for _, item := range response.Items {
		// Parse the issued and updated timestamps
		issued, _ := time.Parse(time.RFC3339, item.Issued)
		updated, _ := time.Parse(time.RFC3339, item.Updated)

		// Convert scopes to our Scope format
		scopes := make([]Scope, 0, len(item.Scopes))
		for _, s := range item.Scopes {
			scopes = append(scopes, Scope{Scope: s})
		}

		// Create the grant
		grant := Grant{
			ID:            item.ID,
			ClientID:      item.ClientID,
			UserID:        item.UserKey,
			Scopes:        scopes,
			GrantType:     item.GrantType,
			CreatedAt:     issued.Unix(),
			LastUpdatedAt: updated.Unix(),
		}

		// Add any grant attributes as metadata
		if len(item.GrantAttributes) > 0 {
			grant.Metadata = make(map[string]interface{})
			for _, attr := range item.GrantAttributes {
				if len(attr.Values) > 0 {
					grant.Metadata[attr.Name] = attr.Values[0]
				}
			}
		}

		grants = append(grants, grant)
	}

	log.Printf("[DEBUG] ListGrants: Successfully retrieved %d grants", len(grants))
	return grants, nil
}

// RevokeGrants deletes grants for a client or user. If grantID is empty, it revokes all grants.
// Exactly one of clientID or userKey must be supplied.
func (c *Client) RevokeGrants(ctx context.Context, clientID, userKey, grantID string) error {
	var endpoint string
	if clientID != "" {
		endpoint = fmt.Sprintf("%s/pf-ws/rest/oauth/clients/%s/grants", c.BaseURL, url.PathEscape(clientID))
	} else if userKey != "" {
		endpoint = fmt.Sprintf("%s/pf-ws/rest/oauth/users/%s/grants", c.BaseURL, url.PathEscape(userKey))
	} else {
		return fmt.Errorf("clientID or userKey required")
	}

	if grantID != "" {
		q := url.Values{}
		q.Set("grantId", grantID)
		endpoint = endpoint + "?" + q.Encode()
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, endpoint, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	c.applyAuth(req)
	// Debug: log outbound request details
	authScheme := "none"
	if h := req.Header.Get("Authorization"); h != "" {
		authScheme = strings.SplitN(h, " ", 2)[0]
	}
	log.Printf("[DEBUG] RevokeGrants: Sending %s request to %s (auth: %s)", req.Method, req.URL.String(), authScheme)
	log.Printf("[DEBUG] RevokeGrants: Headers: %+v", req.Header)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	return nil
}

// RevokeGrant revokes a persistent grant by ID
func (c *Client) RevokeGrant(ctx context.Context, grantID string) error {
	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodDelete,
		fmt.Sprintf("%s/pf-ws/rest/oauth/grants/%s", c.BaseURL, grantID),
		nil,
	)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Apply authentication (Bearer token or Basic Auth) and CSRF header
	c.applyAuth(req)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	return nil
}

// GrantManagementAction represents the type of grant management action
type GrantManagementAction string

const (
	ActionCreate  GrantManagementAction = "create"
	ActionUpdate  GrantManagementAction = "update"
	ActionReplace GrantManagementAction = "replace"
	ActionRevoke  GrantManagementAction = "revoke"
)

// GrantRequest represents a request to create or update a grant
type GrantRequest struct {
	// Standard fields
	Scopes       []Scope              `json:"scopes,omitempty"`
	Claims       []string             `json:"claims,omitempty"`
	AuthzDetails []AuthorizationDetail `json:"authorization_details,omitempty"`
	
	// Action specifies the type of update (only used in some operations)
	Action GrantManagementAction `json:"-"`
	
	// Metadata for custom extensions
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// GrantQueryParams represents query parameters for listing grants
type GrantQueryParams struct {
	ClientID string
	UserID   string
	Scope    string
	Status   string
	Limit    int
	Offset   int
}

// UpdateGrant updates a persistent grant with the specified changes
func (c *Client) UpdateGrant(ctx context.Context, grantID string, update GrantRequest) (*Grant, error) {
	if err := update.validate(); err != nil {
		return nil, fmt.Errorf("invalid update request: %w", err)
	}

	// Ensure the action is set to update if not specified
	if update.Action == "" {
		update.Action = ActionUpdate
	}

	payload, err := json.Marshal(update)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal update payload: %w", err)
	}

	// Create a new request with the payload as the body
	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPatch,
		fmt.Sprintf("%s/pf-ws/rest/oauth/grants/%s", c.BaseURL, grantID),
		bytes.NewBuffer(payload),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Apply authentication (Bearer token or Basic Auth) and CSRF header
	c.applyAuth(req)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var grant Grant
	if err := json.NewDecoder(resp.Body).Decode(&grant); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &grant, nil
}
