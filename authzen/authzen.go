package authzen

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"runtime"
	"sort"
	"strings"
	"time"
)

// getCallerInfo returns the file and line number of the caller
func getCallerInfo() string {
	// Skip 3 frames: getCallerInfo, logX, and the original caller
	_, file, line, ok := runtime.Caller(3)
	if !ok {
		return "unknown:0"
	}
	return fmt.Sprintf("%s:%d", file, line)
}

// Endpoint constants
const (
	EndpointEvaluate      = "/api/v1/evaluate"
	EndpointSubjectSearch = "/api/v1/subject_search"
	EndpointResourceSearch = "/api/v1/resource_search"
	EndpointActionSearch  = "/api/v1/action_search"
)

// EvaluationResponseContext represents the context in an evaluation response.
//
// AuthZEN 1.0 returns a single reason per decision, carried in the ID,
// ReasonAdmin and ReasonUser fields. Reasons holds the array form that some
// PDPs emit instead, notably on search responses. Both are accepted; use
// UserReasons to read whichever the PDP populated.
type EvaluationResponseContext struct {
	ID          string            `json:"id,omitempty"`
	ReasonAdmin map[string]string `json:"reason_admin,omitempty"`
	ReasonUser  map[string]string `json:"reason_user,omitempty"`

	Reasons []Reason `json:"reasons,omitempty"`
}

// UserReasons returns the reasons in this context that are safe to show an end
// user, normalising over both response shapes.
//
// Administrative reasons are deliberately never returned: they exist to explain
// a decision to an operator and can name internal policy detail, so they must
// not reach the client.
func (c *EvaluationResponseContext) UserReasons() []Reason {
	if c == nil {
		return nil
	}

	var out []Reason
	if len(c.ReasonUser) > 0 {
		out = append(out, Reason{ID: c.ID, ReasonUser: c.ReasonUser})
	}
	for _, r := range c.Reasons {
		if len(r.ReasonUser) > 0 {
			out = append(out, Reason{ID: r.ID, ReasonUser: r.ReasonUser})
		}
	}
	return out
}

// FirstMessage returns any one user-facing message from a reason, preferring
// English. Reason messages are keyed by language tag and a PDP may return
// several; callers that surface a single string need a deterministic pick.
func (r Reason) FirstMessage() string {
	if msg, ok := r.ReasonUser["en"]; ok {
		return msg
	}
	keys := make([]string, 0, len(r.ReasonUser))
	for k := range r.ReasonUser {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		return r.ReasonUser[k]
	}
	return ""
}

// Reason represents a reason for a decision
// ID: A string value that specifies the reason within the scope of a particular response.
// ReasonAdmin: The reason, which MUST NOT be shared with the user, but useful for administrative purposes.
// ReasonUser: The reason, which MAY be shared with the user that indicates why the access was denied.
type Reason struct {
	ID         string            `json:"id"`
	ReasonAdmin map[string]string `json:"reason_admin,omitempty"`
	ReasonUser  map[string]string `json:"reason_user,omitempty"`
}

// EvaluationResponse represents the response from AuthZen
type EvaluationResponse struct {
	Decision bool                  `json:"decision"`
	Context  EvaluationResponseContext `json:"context,omitempty"`
}

// Subject represents a user or entity
type Subject struct {
	Type string `json:"type"`
	ID   string `json:"id,omitempty"`
}

// Action represents an action to be performed
type Action struct {
	Name string `json:"name"`
}

// Resource represents a resource to be accessed
type Resource struct {
	Type string `json:"type"`
	ID   string `json:"id,omitempty"`
}

// SearchResult represents a single search result
type SearchResult struct {
	Type string `json:"type"`
	ID   string `json:"id,omitempty"`
}

// SearchResults represents paginated search results
type SearchResults struct {
	Results []SearchResult `json:"results"`
	Page    struct {
		NextToken string `json:"next_token,omitempty"`
	} `json:"page,omitempty"`
}

// AuthZenResponse represents the response from AuthZen
type AuthZenResponse struct {
	Decision bool                  `json:"decision"`
	Context  EvaluationResponseContext `json:"context,omitempty"`
	Results  []SearchResult        `json:"results,omitempty"`
}

// ConvertToAuthZenResponse converts AuthZen response to our EvaluationResponse
func ConvertToAuthZenResponse(r *AuthZenResponse) *EvaluationResponse {
	return &EvaluationResponse{
		Decision: r.Decision,
		Context: EvaluationResponseContext{
			Reasons: r.Context.Reasons,
		},
	}
}

// ConvertToAuthZenSearchResponse converts AuthZen search response to our EvaluationResponse
func ConvertToAuthZenSearchResponse(resp *AuthZenResponse) *EvaluationResponse {
	return &EvaluationResponse{
		Decision: true, // Search responses should always be true
		Context: EvaluationResponseContext{
			Reasons: []Reason{},
		},
	}
}

// AuthZenRequest represents the request to AuthZen
type AuthZenRequest struct {
	Subject  Subject  `json:"subject"`
	Action   Action   `json:"action"`
	Resource Resource `json:"resource"`
	Context  map[string]interface{} `json:"context,omitempty"`
}

// BatchEvaluationRequest represents a single evaluation in a batch
type BatchEvaluationRequest struct {
    Subject  Subject                `json:"subject"`
    Action   Action                 `json:"action"`
    Resource Resource               `json:"resource"`
    Context  map[string]interface{} `json:"context,omitempty"`
}

// BatchEvaluationResponse represents a single evaluation result in a batch response
type BatchEvaluationResponse struct {
    Decision bool                    `json:"decision"`
    Context  EvaluationResponseContext `json:"context,omitempty"`
}

// BatchEvaluateRequest represents a batch evaluation request
type BatchEvaluateRequest struct {
    Requests []BatchEvaluationRequest `json:"requests"`
}

// BatchEvaluateResponse represents a batch evaluation response
type BatchEvaluateResponse struct {
    Results []BatchEvaluationResponse `json:"results"`
}

// AuthZenClient represents the AuthZen client
type AuthZenClient struct {
	baseURL    string
	httpClient *http.Client
	auth       Authenticator
	logLevel   string

	evaluateEndpoint       string
	evaluationsEndpoint    string 
	subjectSearchEndpoint  string
	resourceSearchEndpoint string
	actionSearchEndpoint   string
}

// SetLogLevel sets the logging level (debug, info, error)
func (c *AuthZenClient) SetLogLevel(level string) {
	c.logLevel = level
}

// logDebug logs a debug message if debug logging is enabled
func (c *AuthZenClient) logDebug(format string, v ...interface{}) {
	if c.logLevel == "debug" {
		log.Printf("[AUTHZEN DEBUG] %s - "+format, append([]interface{}{getCallerInfo()}, v...)...)
	}
}

// logInfo logs an info message if info logging is enabled
func (c *AuthZenClient) logInfo(format string, v ...interface{}) {
	if c.logLevel == "debug" || c.logLevel == "info" {
		log.Printf("[AUTHZEN INFO] %s - "+format, append([]interface{}{getCallerInfo()}, v...)...)
	}
}

// logError always logs error messages
func (c *AuthZenClient) logError(format string, v ...interface{}) {
	log.Printf("[ERROR] [%s] %s", getCallerInfo(), fmt.Sprintf(format, v...))
}

// forceSchemeFromBase ensures the URL uses the same scheme as the base URL.
// A discovery document can advertise its endpoints on a different scheme to the
// one we actually reach the PDP on (e.g. https endpoints behind a proxy we talk
// to over http), so absolute http(s) endpoints are coerced to the base's scheme.
// Endpoints on any other scheme are returned untouched, and relative endpoints
// are joined onto the base.
func (c *AuthZenClient) forceSchemeFromBase(rawURL string) string {
	if i := strings.Index(rawURL, "://"); i >= 0 {
		if scheme := rawURL[:i]; scheme != "http" && scheme != "https" {
			return rawURL
		}
		baseScheme := "https"
		if strings.HasPrefix(c.baseURL, "http://") {
			baseScheme = "http"
		}
		return baseScheme + rawURL[i:]
	}
	return strings.TrimSuffix(c.baseURL, "/") + "/" + strings.TrimPrefix(rawURL, "/")
}

// discoveryResponse models the AuthZen discovery document per spec
// See: https://openid.github.io/authzen/#section-6.1
// Matches the actual response from authzen.idpartners.au/.well-known/authzen-configuration

type discoveryResponse struct {
	PolicyDecisionPoint    string `json:"policy_decision_point"`
	AccessEvaluationEndpoint string `json:"access_evaluation_endpoint"`
	AccessEvaluationsEndpoint string `json:"access_evaluations_endpoint"`
	SearchSubjectEndpoint  string `json:"search_subject_endpoint"`
	SearchActionEndpoint   string `json:"search_action_endpoint"`
	SearchResourceEndpoint string `json:"search_resource_endpoint"`
}

// NewAuthZenClient creates a new AuthZen API client with the specified authenticator
func NewAuthZenClient(baseURL string, auth Authenticator) (*AuthZenClient, error) {
	if auth == nil {
		return nil, fmt.Errorf("authenticator cannot be nil")
	}
	if baseURL == "" {
		return nil, fmt.Errorf("base URL cannot be empty")
	}

	// Ensure base URL ends with a slash
	if !strings.HasSuffix(baseURL, "/") {
		baseURL += "/"
	}

	// Create a new HTTP client with a reasonable timeout
	httpClient := &http.Client{
		Timeout: 30 * time.Second,
	}

	// Create the client with the HTTP client and forceHTTP set to false by default
	return NewAuthZenClientWithHTTPClient(baseURL, auth, httpClient, false)
}

// NewAuthZenClientWithHTTPClient creates a new AuthZen API client with the specified authenticator and HTTP client
// This allows for custom HTTP client configuration, such as disabling TLS verification for local development
// The baseURL's scheme (http:// or https://) will be used for all API requests
func NewAuthZenClientWithHTTPClient(baseURL string, auth Authenticator, httpClient *http.Client, forceHTTP bool) (*AuthZenClient, error) {
	// Normalize the base URL
	baseURL = strings.TrimSpace(baseURL)
	if !strings.HasPrefix(baseURL, "http") {
		baseURL = "https://" + baseURL
	}
	if forceHTTP {
		baseURL = strings.Replace(baseURL, "https://", "http://", 1)
	}
	if auth == nil {
		return nil, fmt.Errorf("authenticator cannot be nil")
	}
	if baseURL == "" {
		return nil, fmt.Errorf("base URL cannot be empty")
	}
	if httpClient == nil {
		return nil, fmt.Errorf("http client cannot be nil")
	}

	// Normalize the base URL (ensure it ends with a single slash)
	baseURL = strings.TrimRight(baseURL, "/") + "/"

	// For discovery, we want just the hostname and scheme
	discoveryBase := baseURL
	if strings.Contains(discoveryBase, "/") && !strings.HasSuffix(discoveryBase, "/.well-known") {
		discoveryBase = strings.Split(discoveryBase, "/")[0] + "//" + strings.Split(discoveryBase, "/")[2]
	}

	// Initialize default base URL for API endpoints
	defaultBase := strings.TrimSuffix(baseURL, "/")

	// Create the client with the HTTP client
	client := &AuthZenClient{
		baseURL:    baseURL,
		httpClient: httpClient,
		auth:       auth,
		logLevel:   os.Getenv("AUTHZEN_LOGLEVEL"),
	}

	// Log the configuration
	client.logInfo("AuthZen Client Configuration:")
	client.logInfo("  - Base URL: %s", baseURL)
	client.logInfo("  - Discovery URL: %s/.well-known/authzen-configuration", discoveryBase)

	// Initialize default endpoints with scheme from base URL
	// These will be overridden by discovery if it succeeds
	client.evaluateEndpoint = client.forceSchemeFromBase(defaultBase + "/access/v1/evaluation")
	client.evaluationsEndpoint = client.forceSchemeFromBase(defaultBase + "/access/v1/evaluations")
	client.subjectSearchEndpoint = client.forceSchemeFromBase(defaultBase + "/access/v1/search/subject")
	client.resourceSearchEndpoint = client.forceSchemeFromBase(defaultBase + "/access/v1/search/resource")
	client.actionSearchEndpoint = client.forceSchemeFromBase(defaultBase + "/access/v1/search/action")

	// Perform discovery to get the endpoints
	discoveryURL := discoveryBase + "/.well-known/authzen-configuration"
	client.logInfo("Attempting discovery from: %s", discoveryURL)
	client.logInfo("===== Starting AuthZen Discovery =====")
	client.logInfo("Discovery URL: %s", discoveryURL)

	discReq, err := http.NewRequest("GET", discoveryURL, nil)
	if err != nil {
		client.logError("Error creating discovery request: %v", err)
		// Use default endpoints if discovery fails
		client.logInfo("Using default endpoints (discovery failed): %v", err)
		return client, nil
	}

	// Set headers
	discReq.Header.Set("Accept", "application/json")

	// Execute the request
	client.logInfo("Sending discovery request...")
	startTime := time.Now()
	discResp, err := client.httpClient.Do(discReq)
	elapsedTime := time.Since(startTime)

	if err != nil {
		client.logError("Discovery request failed: %v", err)
		// Log that we're using default endpoints
		client.logInfo("Using default endpoints (discovery request failed): %v", err)
		// Endpoints are already set with the correct scheme during client initialization
		return client, nil
	}
	defer discResp.Body.Close()

	client.logInfo("Discovery response status: %d %s (took %v)", discResp.StatusCode, discResp.Status, elapsedTime)
	client.logDebug("Response headers: %v", discResp.Header)

	if discResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(discResp.Body)
		client.logError("Discovery failed with status %d: %s", discResp.StatusCode, string(body))
		// Log that we're using default endpoints
		client.logInfo("Using default endpoints (discovery status %d)", discResp.StatusCode)
		return client, nil
	}

	// Parse the discovery response
	var discRespBody discoveryResponse
	if err := json.NewDecoder(discResp.Body).Decode(&discRespBody); err != nil {
		client.logError("Error parsing discovery response: %v", err)
		// Use default endpoints if parsing fails
		client.logInfo("Using default endpoints (discovery parse failed): %v", err)
		return client, nil
	}

	// Set the endpoints from the discovery response, applying scheme from base URL
	if discRespBody.AccessEvaluationEndpoint != "" {
		client.evaluateEndpoint = client.forceSchemeFromBase(discRespBody.AccessEvaluationEndpoint)
	}

	if discRespBody.AccessEvaluationsEndpoint != "" {
		client.evaluationsEndpoint = client.forceSchemeFromBase(discRespBody.AccessEvaluationsEndpoint)
	}

	if discRespBody.SearchSubjectEndpoint != "" {
		client.subjectSearchEndpoint = client.forceSchemeFromBase(discRespBody.SearchSubjectEndpoint)
	}

	if discRespBody.SearchResourceEndpoint != "" {
		client.resourceSearchEndpoint = client.forceSchemeFromBase(discRespBody.SearchResourceEndpoint)
	}

	if discRespBody.SearchActionEndpoint != "" {
		client.actionSearchEndpoint = client.forceSchemeFromBase(discRespBody.SearchActionEndpoint)
	}

	if client.logLevel == "" {
		client.logLevel = "debug"
	}

	// Log the final endpoints being used
	client.logDebug("Using AuthZen endpoints:")
	client.logDebug("  - Evaluate: %s", client.evaluateEndpoint)
	client.logDebug("  - Evaluations: %s", client.evaluationsEndpoint)
	client.logDebug("  - Subject Search: %s", client.subjectSearchEndpoint)
	client.logDebug("  - Resource Search: %s", client.resourceSearchEndpoint)
	client.logDebug("  - Action Search: %s", client.actionSearchEndpoint)
	return client, nil
}

// MakeRequest makes an HTTP request to the AuthZen API with the given method, path, and body
// and returns the parsed AuthZenResponse
func (c *AuthZenClient) MakeRequest(method, path string, body interface{}) (*AuthZenResponse, error) {
	log.Printf("=== AUTHZEN MAKEREQUEST CALLED ===\nMethod: %s\nPath: %s\nBody: %+v", method, path, body)
	log.Printf("Current log level: %s", c.logLevel)
	// If the path is already a full URL, use it as is
	// Otherwise, combine it with the base URL
	var url string
	if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") {
		url = path
	} else {
		// Ensure we don't have double slashes when joining baseURL and path
		base := strings.TrimSuffix(c.baseURL, "/")
		path = strings.TrimPrefix(path, "/")
		url = base + "/" + path
	}

	// Log the request
	c.logDebug("Making %s request to %s", method, url)

	// Convert body to JSON if provided
	var reqBody io.Reader = nil
	var jsonData []byte
	headers := make(map[string]string)
	if body != nil {
		var err error
		jsonData, err = json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request body: %w", err)
		}
		reqBody = bytes.NewBuffer(jsonData)
		headers["Content-Type"] = "application/json"
		c.logDebug("Request body: %s", string(jsonData))
	}

	// Build curl command for debugging
	var curlParts []string
	curlParts = append(curlParts, "curl", "-v", "-X", method, url)
	
	// Add standard headers
	curlParts = append(curlParts, "-H", "Accept: application/json")
	if len(jsonData) > 0 {
		curlParts = append(curlParts, "-H", "Content-Type: application/json")
	}
	
	// Create a request to get the auth header if authenticator exists
	authHeader := ""
	if c.auth != nil {
		req, _ := http.NewRequest(method, url, nil)
		if err := c.auth.AddAuthHeader(req); err == nil {
			authHeader = req.Header.Get("Authorization")
		}
	}
	
	// Add auth header to curl if available
	if authHeader != "" {
		curlParts = append(curlParts, "-H", fmt.Sprintf("Authorization: %s", authHeader))
	}
	
	// Add body if present
	if len(jsonData) > 0 {
		escapedBody := strings.ReplaceAll(string(jsonData), "'", "'\\''")
		curlParts = append(curlParts, "-d", escapedBody)
	}
	
	// Format the curl command for output with line breaks for readability
	var curlCmdBuilder strings.Builder
	for i, part := range curlParts {
		if i > 0 {
			curlCmdBuilder.WriteString(" \\")
			curlCmdBuilder.WriteString("\n  ")
		}
		if strings.Contains(part, " ") || strings.Contains(part, "|") || strings.Contains(part, "&") {
			curlCmdBuilder.WriteString("'" + part + "'")
		} else {
			curlCmdBuilder.WriteString(part)
		}
	}
	
	// Log the curl command with file and line info
	callerInfo := getCallerInfo()
	// Always log the curl command to standard output with clear markers
	log.Printf("\n\n=== AUTHZEN CURL COMMAND ===\n")
	log.Printf("Called from: %s\n", callerInfo)
	log.Printf("Base URL: %s", c.baseURL)
	log.Printf("URL: %s %s\n", method, url)
	log.Printf("CURL COMMAND (copy-paste ready):\n%s\n", curlCmdBuilder.String())
	log.Printf("=== END AUTHZEN CURL COMMAND ===\n\n")
	// Also log it through the debug logger with more context
	c.logDebug("AuthZen API Request - Method: %s, URL: %s\nCURL Command:\n%s", method, url, curlCmdBuilder.String())
	// Force flush the log output
	log.Println("=== FORCING LOG FLUSH ===")
	// Also log to stderr for better visibility
	fmt.Fprintf(os.Stderr, "\n=== AUTHZEN CURL COMMAND ===\n%s\n=== END CURL COMMAND ===\n\n", curlCmdBuilder.String())

	// Create a new request
	req, err := http.NewRequest(method, url, reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set the content type if we have a body
	if len(jsonData) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}

	// Add authentication if authenticator is set
	if c.auth != nil {
		if err := c.auth.AddAuthHeader(req); err != nil {
			return nil, fmt.Errorf("failed to add authentication: %w", err)
		}
	} else {
		c.logDebug("[%s] Warning: No authenticator set for request to %s", getCallerInfo(), url)
	}

	// Build the curl command with proper escaping
	cmd := []string{
		"curl", "-v",
		"-X", method,
		url,
		"-H", "Accept: application/json",
	}

	// Add content type if we have a body
	if body != nil {
		cmd = append(cmd, "-H", "Content-Type: application/json")
	}

	// Add auth header if available
	if authHeader != "" {
		cmd = append(cmd, "-H", fmt.Sprintf("Authorization: %s", authHeader))
	}

	// Add request body if present
	if body != nil {
		escapedJSON := strings.ReplaceAll(string(jsonData), "'", "'\\''")
		cmd = append(cmd, "-d", fmt.Sprintf("%s", escapedJSON))
	}

	// Convert command to a printable string
	var curlCmd strings.Builder
	for i, part := range cmd {
		if i > 0 {
			curlCmd.WriteString(" ")
		}
		if strings.Contains(part, " ") || strings.Contains(part, "|") || strings.Contains(part, "&") {
			curlCmd.WriteString("'" + part + "'")
		} else {
			curlCmd.WriteString(part)
		}
	}

	// Log the full curl command
	log.Printf("\n[DEBUG] Full curl command for %s %s:\n%s\n", method, url, curlCmd.String())

	// Send the request
	c.logDebug("Sending %s request to %s", method, url)
	if body != nil {
		c.logDebug("Request body: %s", string(jsonData))
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Read response body
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	c.logDebug("Response status: %d", resp.StatusCode)
	c.logDebug("Response body: %s", string(respBody))

	// Check for non-2xx status codes
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("request failed with status %d: %s", resp.StatusCode, string(respBody))
	}

	// Parse response
	var result AuthZenResponse
	
	// First try to unmarshal into the full response
	if err := json.Unmarshal(respBody, &result); err != nil {
		// If that fails, try to unmarshal into a minimal response
		var minimalResp struct {
			Decision bool `json:"decision"`
		}
		if minErr := json.Unmarshal(respBody, &minimalResp); minErr != nil {
			return nil, fmt.Errorf("failed to parse response: %w (also failed to parse as minimal response: %v)", err, minErr)
		}
		// Create a full response from the minimal one
		result = AuthZenResponse{
			Decision: minimalResp.Decision,
			Context: EvaluationResponseContext{
				Reasons: []Reason{},
			},
		}
	}

	c.logInfo("Request successful")
	return &result, nil
}

// GetEndpointURL returns the discovered endpoint for the given logical API
// Supported: "evaluate", "evaluations", "subject_search", "resource_search", "action_search"
func (c *AuthZenClient) GetEndpointURL(api string) string {
	switch api {
	case "evaluate":
		return c.evaluateEndpoint
	case "evaluations":
		return c.evaluationsEndpoint
	case "subject_search":
		return c.subjectSearchEndpoint
	case "resource_search":
		return c.resourceSearchEndpoint
	case "action_search":
		return c.actionSearchEndpoint
	default:
		return ""
	}
}

// SearchSubjects searches for subjects that match the given criteria
// See: https://openid.github.io/authzen/#name-subject-search-api
func (c *AuthZenClient) SearchSubjects(resourceType, resourceID, action string, context map[string]interface{}) (*AuthZenResponse, error) {
	req := &AuthZenRequest{
		Resource: Resource{
			Type: resourceType,
			ID:   resourceID,
		},
		Action: Action{
			Name: action,
		},
	}
	if context != nil {
		req.Context = context
	}

	endpoint := c.GetEndpointURL("subject_search")
	if endpoint == "" {
		return nil, fmt.Errorf("subject search endpoint not available")
	}

	return c.MakeRequest(http.MethodPost, endpoint, req)
}

// SearchResources searches for resources that the subject can access with the given action
// See: https://openid.github.io/authzen/#name-resource-search-api
func (c *AuthZenClient) SearchResources(subjectType, subjectID, resourceType, action string, context map[string]interface{}) (*AuthZenResponse, error) {
	req := &AuthZenRequest{
		Subject: Subject{
			Type: subjectType,
			ID:   subjectID,
		},
		Resource: Resource{
			Type: resourceType,
		},
		Action: Action{
			Name: action,
		},
	}
	if context != nil {
		req.Context = context
	}

	endpoint := c.GetEndpointURL("resource_search")
	if endpoint == "" {
		return nil, fmt.Errorf("resource search endpoint not available")
	}

	return c.MakeRequest(http.MethodPost, endpoint, req)
}

// SearchActions searches for actions that the subject can perform on the resource
// See: https://openid.github.io/authzen/#name-action-search-api
func (c *AuthZenClient) SearchActions(subjectType, subjectID, resourceType, resourceID string, context map[string]interface{}) (*AuthZenResponse, error) {
	req := &AuthZenRequest{
		Subject: Subject{
			Type: subjectType,
			ID:   subjectID,
		},
		Resource: Resource{
			Type: resourceType,
			ID:   resourceID,
		},
	}
	if context != nil {
		req.Context = context
	}

	endpoint := c.GetEndpointURL("action_search")
	if endpoint == "" {
		return nil, fmt.Errorf("action search endpoint not available")
	}

	return c.MakeRequest(http.MethodPost, endpoint, req)
}

// BatchEvaluate performs multiple authorization evaluations in a single request
// See: https://openid.github.io/authzen/#name-batch-evaluation-api
func (c *AuthZenClient) BatchEvaluate(requests []BatchEvaluationRequest) (*BatchEvaluateResponse, error) {
	if len(requests) == 0 {
		return nil, fmt.Errorf("at least one evaluation request is required")
	}

	req := &BatchEvaluateRequest{
		Requests: requests,
	}

	endpoint := c.GetEndpointURL("evaluations")
	if endpoint == "" {
		return nil, fmt.Errorf("batch evaluations endpoint not available")
	}

	// Use MakeRequest but handle the response differently
	resp, err := c.MakeRequest(http.MethodPost, endpoint, req)
	if err != nil {
		return nil, fmt.Errorf("batch evaluation request failed: %w", err)
	}

	// For batch responses, we expect a single response with multiple results
	// The AuthZenResponse may need to be transformed to match BatchEvaluateResponse
	var results []BatchEvaluationResponse
	if resp != nil {
		// If the response has a decision, it's a single result
		results = append(results, BatchEvaluationResponse{
			Decision: resp.Decision,
			Context:  resp.Context,
		})
	}

	return &BatchEvaluateResponse{
		Results: results,
	}, nil
}
