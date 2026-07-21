package api

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"

	"idp-gm-api/authzen"
	"idp-gm-api/middleware"
	"idp-gm-api/pingfederate/grant"
)

// Common errors
var (
	ErrInvalidGrantID       = errors.New("invalid grant ID")
	ErrGrantNotFound        = errors.New("grant not found")
	ErrGrantExpired         = errors.New("grant expired")
	ErrGrantRevoked         = errors.New("grant revoked")
	ErrUnauthorizedForGrant = errors.New("subject not authorized for this grant")
	ErrMissingToken         = errors.New("missing or invalid access token")
	ErrPDPUnavailable       = errors.New("policy decision point unavailable")
)

// EvaluateGrantRequest represents a request to evaluate a grant
type EvaluateGrantRequest struct {
	// Resource to evaluate access to (required for evaluation mode, optional for search)
	Resource *ResourceRef `json:"resource,omitempty"`

	// Action to evaluate (required for evaluation mode, optional for search)
	Action *ActionRef `json:"action,omitempty"`

	// Additional context for the evaluation
	Context map[string]interface{} `json:"context,omitempty"`

	// Pagination token for search results
	NextToken string `json:"next_token,omitempty"`
}

// ResourceRef represents a resource reference
type ResourceRef struct {
	Type string `json:"type"`
	ID   string `json:"id,omitempty"`
}

// ActionRef represents an action reference
type ActionRef struct {
	Name string `json:"name"`
}

// EvaluateGrantResponse represents the response from a grant evaluation
type EvaluateGrantResponse struct {
	// Decision is true if the action is allowed on the resource
	// Only present in evaluation mode
	Decision bool `json:"decision"`

	// Context contains additional information about the decision
	// Only present in evaluation mode
	Context *EvaluationContext `json:"context,omitempty"`

	// Results contains the list of resources or actions that are allowed
	// Only present in search mode
	Results []interface{} `json:"results,omitempty"`

	// Page contains pagination information for search results
	// Only present in search mode if there are more results
	Page *PageInfo `json:"page,omitempty"`
}

// EvaluationContext contains additional information about an evaluation decision
type EvaluationContext struct {
	// Reasons for the decision, if any
	Reasons []Reason `json:"reasons,omitempty"`
}

// Reason represents a reason for a decision
type Reason struct {
	// ID is a string value that specifies the reason within the scope of a particular response
	ID string `json:"id"`

	// Message is a human-readable explanation of the reason
	Message string `json:"message,omitempty"`
}

// PageInfo contains pagination information
type PageInfo struct {
	// NextToken is an opaque token that can be used to retrieve the next page of results
	NextToken string `json:"next_token,omitempty"`
}

// EvaluateGrant evaluates a grant against the AuthZEN PDP
func (s *GrantService) EvaluateGrant(ctx context.Context, clientIDParam, grantID string, req *EvaluateGrantRequest) (*EvaluateGrantResponse, error) {
	// Ensure context is not nil
	if ctx == nil {
		ctx = context.Background()
	}
	log.Printf("[DEBUG] EvaluateGrant called with clientID: %s, grantID: %s", clientIDParam, grantID)
	log.Printf("[DEBUG] Request details: %+v", req)

	// Get token claims from context
	claims, ok := middleware.GetTokenClaimsFromContext(ctx)
	if !ok || claims == nil {
		log.Printf("[ERROR] No token claims found in context")
		return nil, fmt.Errorf("missing or invalid access token")
	}

	log.Printf("[DEBUG] Token claims - ClientID: %s, Subject: %s, Scopes: %v",
		claims.ClientID, claims.Subject, claims.Scopes)

	// clientIDParam is the token's own client_id: the handler reads it off the same
	// claims. Comparing them proves nothing -- the check that matters is against the
	// grant's client, below, once the grant has been read.

	// 1. Validate the grant ID and client ID
	if grantID == "" {
		log.Printf("[ERROR] Empty grant ID provided")
		return nil, ErrInvalidGrantID
	}
	if clientIDParam == "" {
		errMsg := "client ID is required"
		log.Printf("[ERROR] %s", errMsg)
		return nil, fmt.Errorf(errMsg)
	}

	// 2. Retrieve the grant
	log.Printf("[DEBUG] Retrieving grant with ID: %s", grantID)
	// Get the user ID from the token claims using the configured subject claim
	var userID string
	if claims, ok := middleware.GetTokenClaimsFromContext(ctx); ok {
		userID = claims.GetSubjectValue()
		if userID == "" {
			errMsg := fmt.Sprintf("subject claim not found in token using claim name: %s", os.Getenv("SUBJECT_CLAIM_NAME"))
			log.Printf("[ERROR] %s", errMsg)
			return nil, fmt.Errorf("failed to get grant: %s", errMsg)
		}
		log.Printf("[DEBUG] Using UserID from token: %s (claim: %s)", userID, os.Getenv("SUBJECT_CLAIM_NAME"))
	} else {
		errMsg := "missing or invalid token claims"
		log.Printf("[ERROR] %s", errMsg)
		return nil, fmt.Errorf("failed to get grant: %s", errMsg)
	}

	g, err := s.grantClient.GetGrant(ctx, userID, grantID)
	if err != nil {
		errMsg := fmt.Sprintf("Failed to get grant: %v", err)
		log.Printf("[ERROR] %s", errMsg)
		return nil, fmt.Errorf("failed to get grant: %w", err)
	}
	if g == nil {
		errMsg := fmt.Sprintf("Grant not found: %s", grantID)
		log.Printf("[ERROR] %s", errMsg)
		return nil, ErrGrantNotFound
	}
	// Log grant details for debugging
	log.Printf("[DEBUG] Retrieved grant: ID=%s, Status=%s, UserKey=%s, UserID=%s", g.ID, g.Status, g.UserKey, g.UserID)
	// Use UserKey if available, fall back to UserID for backward compatibility
	grantUserID := g.UserKey
	if grantUserID == "" {
		grantUserID = g.UserID
	}
	log.Printf("[DEBUG] Using grant user ID for verification: %s", grantUserID)

	// 3. Validate grant status
	log.Printf("[DEBUG] Validating grant status. Current status: %s, ExpiresAt: %d", g.Status, g.ExpiresAt)
	if g.Status == "revoked" {
		errMsg := fmt.Sprintf("Grant %s is revoked", grantID)
		log.Printf("[ERROR] %s", errMsg)
		return nil, ErrGrantRevoked
	}

	// Check if grant is expired
	now := currentUnixTime()
	if g.ExpiresAt > 0 && g.ExpiresAt < now {
		errMsg := fmt.Sprintf("Grant %s expired at %d (current time: %d)", grantID, g.ExpiresAt, now)
		log.Printf("[ERROR] %s", errMsg)
		return nil, ErrGrantExpired
	}

	// 4. Get token claims from context
	tokenClaims, ok := middleware.GetTokenClaimsFromContext(ctx)
	if !ok || tokenClaims == nil {
		errMsg := "No token claims found in context"
		log.Printf("[ERROR] %s", errMsg)
		return nil, ErrMissingToken
	}
	log.Printf("[DEBUG] Token claims: %+v", tokenClaims)

	// 5. Get subject from token claims
	sub := tokenClaims.GetSubjectValue()
	log.Printf("[DEBUG] Token subject: %s", sub)

	// 6. If no subject in token, try to use the grant's userKey as the subject
	if sub == "" && g.UserKey != "" {
		sub = g.UserKey
		log.Printf("[DEBUG] Using grant userKey as subject: %s", sub)
	}

	// 7. Verify the caller may ask about this grant.
	//
	// A grant is a relationship between the client, this authorization server, and the
	// subject. The client leg is what authorises the question, and it is checked for
	// every caller -- not, as it once was, only for the ones that happen to carry no
	// subject. Without it any client holding a token for this user could interrogate a
	// different client's grant with them.
	log.Printf("[DEBUG] Verifying grant ownership - Token ClientID: %s, Grant ClientID: %s",
		tokenClaims.ClientID, g.ClientID)
	if g.ClientID == "" || tokenClaims.ClientID != g.ClientID {
		log.Printf("[ERROR] Grant %s belongs to client %q, token was issued to %q",
			grantID, g.ClientID, tokenClaims.ClientID)
		return nil, ErrUnauthorizedForGrant
	}

	// The subject leg, when the token asserts one. A client_credentials token carries no
	// subject at all and does not need to: the grant names it. Checking it here is
	// defence in depth against a client conflating two of its own grants.
	if sub != "" {
		userKeyClaimValue := tokenClaims.GetUserKeyClaimValue()
		log.Printf("[DEBUG] Verifying token subject - Token user key: %s, Grant UserID: %s, Grant UserKey: %s",
			userKeyClaimValue, g.UserID, g.UserKey)

		// Prefer UserKey, fall back to UserID.
		if userKeyClaimValue != g.UserKey && (g.UserID != "" && userKeyClaimValue != g.UserID) {
			log.Printf("[ERROR] Token user key claim (%s) does not match grant user key (%s) or user ID (%s)",
				userKeyClaimValue, g.UserKey, g.UserID)
			return nil, ErrUnauthorizedForGrant
		}
	}

	// 7. Use client ID from claims or fall back to provided clientID
	clientID := tokenClaims.ClientID
	if clientID == "" {
		log.Printf("[DEBUG] No client_id in token claims, using provided clientID: %s", clientIDParam)
		clientID = clientIDParam
	} else {
		log.Printf("[DEBUG] Using client_id from token claims: %s", clientID)
	}

	// 8. Use the existing context with claims for downstream use
	reqCtx := ctx

	// 9. Determine mode (evaluation vs search)
	// Use evaluation mode if both action and resource type are provided
	isEvaluationMode := req.Action != nil && req.Action.Name != "" &&
		req.Resource != nil && req.Resource.Type != ""
	log.Printf("[DEBUG] Operation mode: evaluation=%v (Action: %v, Resource: %v)",
		isEvaluationMode,
		req.Action,
		req.Resource)

	// 10. Check if AuthZEN client is available
	if s.authZenClient == nil {
		errMsg := "AuthZEN client is not initialized"
		log.Printf("[ERROR] %s", errMsg)
		return nil, ErrPDPUnavailable
	}

	// 11. Add only necessary grant information to the request context
	if req.Context == nil {
		req.Context = make(map[string]interface{})
	}

	// Add scopes to context
	if len(g.Scopes) > 0 {
		req.Context["scopes"] = g.Scopes
	}

	// Add authorization details if present
	if len(g.AuthzDetails) > 0 {
		authzDetails := make([]map[string]interface{}, 0, len(g.AuthzDetails))
		for _, d := range g.AuthzDetails {
			detail := map[string]interface{}{
				"type": d.Type,
			}
			if len(d.Actions) > 0 {
				detail["actions"] = d.Actions
			}
			if len(d.Locations) > 0 {
				detail["locations"] = d.Locations
			}
			if d.Identifier != "" {
				detail["identifier"] = d.Identifier
			}
			if len(d.Data) > 0 {
				detail["data"] = d.Data
			}
			authzDetails = append(authzDetails, detail)
		}
		req.Context["authorization_details"] = authzDetails
	}

	// 12. Execute the appropriate query based on mode
	if isEvaluationMode {
		// Evaluation mode - single decision
		log.Printf("[DEBUG] Executing evaluation mode for resource: %s, action: %s",
			req.Resource.ID, req.Action.Name)
		return s.executeEvaluationMode(reqCtx, s.authZenClient, g, req, sub, clientID)
	}
	// Search mode - list of resources or actions
	log.Printf("[DEBUG] Executing search mode")
	return s.executeSearchMode(reqCtx, s.authZenClient, g, req, sub, clientID)
}

func (s *GrantService) executeEvaluationMode(ctx context.Context, authZenClient *authzen.AuthZenClient, g *grant.Grant, req *EvaluateGrantRequest, sub, clientIDParam string) (*EvaluateGrantResponse, error) {
	// Create a context with timeout if not already set
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
	}

	log.Printf("[DEBUG] executeEvaluationMode - Starting evaluation for grant ID: %s, resource: %s, action: %s",
		g.ID, req.Resource.ID, req.Action.Name)

	// 1. Create AuthZEN request with enriched context
	authZenReq := &authzen.AuthZenRequest{
		Subject: authzen.Subject{
			Type: "user",
			ID:   sub, // Use the subject from the token, not the grant
		},
		Action: authzen.Action{
			Name: req.Action.Name,
		},
		Resource: authzen.Resource{
			Type: req.Resource.Type,
			ID:   req.Resource.ID,
		},
	}

	log.Printf("[DEBUG] Created AuthZEN request: %+v", authZenReq)

	// 2. Initialize context if not provided
	if authZenReq.Context == nil {
		authZenReq.Context = make(map[string]interface{})
	}

	// 3. Add OAuth context to the request
	log.Printf("[DEBUG] Adding OAuth context to request")
	oauthContext := map[string]interface{}{
		"client_id": clientIDParam,
		"grant_id":  g.ID,
	}
	authZenReq.Context["oauth"] = oauthContext
	log.Printf("[DEBUG] Added OAuth context: %+v", oauthContext)

	// 4. Add grant scopes to context if available
	if len(g.Scopes) > 0 {
		authZenReq.Context["scopes"] = g.Scopes
		log.Printf("[DEBUG] Added scopes to context: %v", g.Scopes)
	}

	// 5. Add any additional context from the request
	if req.Context != nil {
		log.Printf("[DEBUG] Adding additional context from request: %+v", req.Context)
		for k, v := range req.Context {
			// Don't override existing context
			if _, exists := authZenReq.Context[k]; !exists {
				authZenReq.Context[k] = v
				log.Printf("[DEBUG] Added context key '%s' to request", k)
			}
		}
	}

	// 6. Call AuthZEN PDP - use the evaluate endpoint
	log.Printf("[DEBUG] ====== Calling AuthZEN PDP for evaluation ======")
	endpoint := authZenClient.GetEndpointURL("evaluate")
	if endpoint == "" {
		errMsg := "AuthZEN endpoint URL is empty"
		log.Printf("[ERROR] %s", errMsg)
		return nil, ErrPDPUnavailable
	}
	log.Printf("[DEBUG] AuthZEN endpoint: %s", endpoint)

	// Log the full request in a readable format
	log.Printf("[DEBUG] AuthZEN Request Details:")
	log.Printf("[DEBUG]   Subject: %s (Type: %s)", authZenReq.Subject.ID, authZenReq.Subject.Type)
	log.Printf("[DEBUG]   Action: %s", authZenReq.Action.Name)
	log.Printf("[DEBUG]   Resource: %s (Type: %s)", authZenReq.Resource.ID, authZenReq.Resource.Type)
	log.Printf("[DEBUG]   Context: %+v", authZenReq.Context)

	// Make the actual call to AuthZEN
	log.Printf("[DEBUG] Sending request to AuthZEN PDP...")
	authZenResp, err := authZenClient.MakeRequest(http.MethodPost, endpoint, authZenReq)
	if err != nil {
		errMsg := fmt.Sprintf("AuthZEN evaluation failed: %v", err)
		log.Printf("[ERROR] %s", errMsg)
		log.Printf("[DEBUG] AuthZEN evaluation error details: %+v", err)

		// Check for context cancellation or deadline exceeded
		if ctx.Err() == context.DeadlineExceeded {
			return nil, fmt.Errorf("PDP evaluation timed out: %w", err)
		} else if ctx.Err() == context.Canceled {
			return nil, fmt.Errorf("PDP evaluation canceled: %w", err)
		}

		return nil, fmt.Errorf("PDP evaluation failed: %w", err)
	}

	// 7. Process the evaluation response
	log.Printf("[DEBUG] ====== AuthZEN evaluation successful ======")
	log.Printf("[DEBUG] Decision: %v", authZenResp.Decision)
	log.Printf("[DEBUG] Full AuthZEN response: %+v", authZenResp)

	// Convert AuthZEN response to API response, carrying the PDP's user-facing
	// reasons through. Section 8.4.3 requires a denial to explain itself while
	// withholding administrative detail, which UserReasons enforces.
	resp := &EvaluateGrantResponse{
		Decision: authZenResp.Decision,
		Context:  &EvaluationContext{Reasons: []Reason{}},
	}
	for _, r := range authZenResp.Context.UserReasons() {
		if msg := r.FirstMessage(); msg != "" {
			resp.Context.Reasons = append(resp.Context.Reasons, Reason{ID: r.ID, Message: msg})
		}
	}
	log.Printf("[DEBUG] Decision %v with %d user-facing reason(s)", resp.Decision, len(resp.Context.Reasons))

	log.Printf("[DEBUG] ====== Evaluation complete ======")
	log.Printf("[DEBUG] Final response: %+v", resp)
	return resp, nil
}

func (s *GrantService) executeSearchMode(ctx context.Context, authZenClient *authzen.AuthZenClient, g *grant.Grant, req *EvaluateGrantRequest, sub, clientIDParam string) (*EvaluateGrantResponse, error) {
	log.Printf("[DEBUG] executeSearchMode - Starting search mode for grant ID: %s, subject: %s", g.ID, sub)

	// 1. Determine search type based on request
	searchType := ""
	if req.Action != nil && req.Action.Name != "" {
		searchType = "resource"
		log.Printf("[DEBUG] Performing resource search for action: %s", req.Action.Name)
	} else if req.Resource != nil && req.Resource.Type != "" {
		searchType = "action"
		log.Printf("[DEBUG] Performing action search for resource type: %s", req.Resource.Type)
	} else {
		// If neither action nor resource is specified, it's an invalid search request
		errMsg := "search request must include either an action or a resource"
		log.Printf("[WARN] %s", errMsg)
		return &EvaluateGrantResponse{
			Results: []interface{}{},
			Context: &EvaluationContext{
				Reasons: []Reason{{
					ID:      "invalid_search_request",
					Message: errMsg,
				}},
			},
		}, nil
	}

	// 2. Prepare context with all grant information and token claims
	authZenCtx := make(map[string]interface{})

	// 3. Add request context if provided
	if req.Context != nil {
		// Make a copy of the request context to avoid modifying the original
		for k, v := range req.Context {
			authZenCtx[k] = v
		}
	}

	// 6. Add OAuth and grant context with all relevant information
	authZenCtx["oauth"] = map[string]interface{}{
		"client_id": clientIDParam,
		"grant_id":  g.ID,
	}

	// 7. Add all scopes from the grant
	if len(g.Scopes) > 0 {
		scopeStrings := make([]string, 0, len(g.Scopes))
		for _, scope := range g.Scopes {
			scopeStrings = append(scopeStrings, scope.Scope)
		}
		authZenCtx["scopes"] = scopeStrings
		log.Printf("[DEBUG] Added %d scopes to context", len(scopeStrings))
	}

	// 8. Add all token claims to context
	if claims, ok := middleware.GetTokenClaimsFromContext(ctx); ok && claims != nil {
		// Add all claims to context
		if claims.Claims != nil {
			// Convert claims to a simple map of strings
			claimMap := make(map[string]interface{})
			for k, v := range claims.Claims {
				switch val := v.(type) {
				case string:
					claimMap[k] = val
				case []string:
					claimMap[k] = val
				case []interface{}:
					// Convert []interface{} to []string if possible
					strSlice := make([]string, 0, len(val))
					for _, item := range val {
						if str, ok := item.(string); ok {
							strSlice = append(strSlice, str)
						}
					}
					if len(strSlice) > 0 {
						claimMap[k] = strSlice
					}
				default:
					// Convert any other type to string
					claimMap[k] = fmt.Sprintf("%v", v)
				}
			}
			authZenCtx["token_claims"] = claimMap
			log.Printf("[DEBUG] Added %d token claims to context", len(claimMap))
		}

		// Add scopes from token if available
		if len(claims.Scopes) > 0 {
			authZenCtx["token_scopes"] = claims.Scopes
			log.Printf("[DEBUG] Added %d token scopes to context", len(claims.Scopes))
		}
	}

	// 9. Add all authorization details from the grant
	if len(g.AuthzDetails) > 0 {
		authzDetails := make([]map[string]interface{}, 0, len(g.AuthzDetails))
		for _, detail := range g.AuthzDetails {
			detailMap := map[string]interface{}{
				"type": detail.Type,
			}
			if len(detail.Actions) > 0 {
				detailMap["actions"] = detail.Actions
			}
			if detail.Identifier != "" {
				detailMap["identifier"] = detail.Identifier
			}
			if len(detail.Locations) > 0 {
				detailMap["locations"] = detail.Locations
			}
			if len(detail.Data) > 0 {
				detailMap["data"] = detail.Data
			}
			authzDetails = append(authzDetails, detailMap)
		}
		authZenCtx["authorization_details"] = authzDetails
		log.Printf("[DEBUG] Added %d authorization details to context", len(authzDetails))
	}

	// 10. Create the appropriate search request based on search type
	var authZenResp *authzen.AuthZenResponse
	var err error

	switch searchType {
	case "resource":
		// Resource search - find resources that can be accessed with the specified action
		actionName := req.Action.Name
		resourceType := ""
		if req.Resource != nil {
			resourceType = req.Resource.Type
		}

		log.Printf("[DEBUG] Searching resources with action: %s, resource type: %s", actionName, resourceType)
		authZenResp, err = authZenClient.SearchResources(
			"user",
			sub, // Token subject is always used as the subject
			resourceType,
			actionName,
			authZenCtx,
		)

	case "action":
		// Action search - find actions that can be performed on the specified resource
		resourceType := req.Resource.Type
		resourceID := ""
		if req.Resource != nil {
			resourceID = req.Resource.ID
		}

		log.Printf("[DEBUG] Searching actions for resource: type=%s, id=%s", resourceType, resourceID)
		authZenResp, err = authZenClient.SearchActions(
			"user",
			sub, // Token subject is always used as the subject
			resourceType,
			resourceID,
			authZenCtx,
		)

	default:
		// This should never happen due to earlier validation
		errMsg := fmt.Sprintf("invalid search type: %s", searchType)
		log.Printf("[ERROR] %s", errMsg)
		return nil, fmt.Errorf(errMsg)
	}

	if err != nil {
		log.Printf("[ERROR] AuthZEN search failed: %v", err)
		return nil, fmt.Errorf("PDP search failed: %w", err)
	}

	log.Printf("[DEBUG] AuthZEN search response: %+v", authZenResp)

	// 5. Convert search results to API response
	result := &EvaluateGrantResponse{
		Decision: authZenResp.Decision,
	}

	// 6. Add results if present
	if authZenResp.Results != nil && len(authZenResp.Results) > 0 {
		results := make([]interface{}, 0, len(authZenResp.Results))

		for _, r := range authZenResp.Results {
			// For resource search, add resource references
			if req.Action != nil {
				results = append(results, ResourceRef{
					Type: r.Type,
					ID:   r.ID,
				})
			} else {
				// For action search, add action references
				results = append(results, ActionRef{
					Name: r.Type, // In action search, type contains the action name
				})
			}
		}

		result.Results = results
	}

	// 7. Add context/reasons if present. Only user-facing reasons are forwarded.
	var reasons []Reason
	for _, r := range authZenResp.Context.UserReasons() {
		if msg := r.FirstMessage(); msg != "" {
			reasons = append(reasons, Reason{ID: r.ID, Message: msg})
		}
	}
	if len(reasons) > 0 {
		result.Context = &EvaluationContext{Reasons: reasons}
	}

	log.Printf("[DEBUG] Search completed successfully with %d results", len(result.Results))
	return result, nil
}

func isActionAllowedByGrant(actionName string, g *grant.Grant) bool {
	// If no scopes or authorization details are defined, all actions are allowed (least restrictive)
	if len(g.Scopes) == 0 && len(g.AuthzDetails) == 0 {
		return true
	}

	// 1. Check if the action is explicitly allowed by any of the scopes
	for _, scope := range g.Scopes {
		// Check the main scope string (e.g., "read:documents")
		if scope.Scope == actionName || scope.Scope == "*" {
			return true
		}

		// Check for wildcard or partial matches (e.g., "read:*" matches "read:documents")
		scopeParts := strings.Split(scope.Scope, ":")
		actionParts := strings.Split(actionName, ":")

		// If the scope has more parts than the action, it can't be a match
		if len(scopeParts) > len(actionParts) {
			continue
		}

		// Check each part of the scope against the action
		matches := true
		for i := 0; i < len(scopeParts); i++ {
			if scopeParts[i] != "*" && (i >= len(actionParts) || scopeParts[i] != actionParts[i]) {
				matches = false
				break
			}
		}

		if matches {
			return true
		}

		// Check if the action is in the scope's resources (if any)
		for _, resource := range scope.Resource {
			if resource == actionName || resource == "*" {
				return true
			}
		}
	}

	// 2. Check if the action is allowed by any authorization details
	for _, authzDetail := range g.AuthzDetails {
		// Check if the authorization detail type matches the action type
		if authzDetail.Type == "" || !strings.HasPrefix(actionName, authzDetail.Type+":") {
			continue
		}

		// If no specific actions are specified, all actions of this type are allowed
		if len(authzDetail.Actions) == 0 {
			return true
		}

		// Check if the action is in the allowed actions list
		action := strings.TrimPrefix(actionName, authzDetail.Type+":")
		for _, allowedAction := range authzDetail.Actions {
			if allowedAction == action || allowedAction == "*" {
				return true
			}

			// Handle wildcard matching (e.g., "read:*" matches "read:documents")
			allowedParts := strings.Split(allowedAction, ":")
			actionParts := strings.Split(action, ":")

			matches := true
			for i := 0; i < len(allowedParts); i++ {
				if i >= len(actionParts) || (allowedParts[i] != "*" && allowedParts[i] != actionParts[i]) {
					matches = false
					break
				}
			}

			if matches {
				return true
			}
		}
	}

	// Action not explicitly allowed by any scope or authorization detail
	return false
}

// currentUnixTime returns the current Unix timestamp
func currentUnixTime() int64 {
	return time.Now().Unix()
}

// handleEvaluateGrant handles POST /grants/{id}/evaluate
func (h *Handler) handleEvaluateGrant(w http.ResponseWriter, r *http.Request) {
	log.Printf("[DEBUG] handleEvaluateGrant: Request received for grant ID: %s", chi.URLParam(r, "id"))

	// Get token claims from context set by authentication middleware
	claims, ok := middleware.GetTokenClaimsFromContext(r.Context())
	if !ok || claims == nil {
		log.Printf("[WARN] handleEvaluateGrant: No valid token claims found in request context")
		renderError(w, r, http.StatusUnauthorized, "unauthorized", "valid access token is required")
		return
	}

	log.Printf("[DEBUG] handleEvaluateGrant: Token claims - ClientID: %s, Subject: %s, Scopes: %v",
		claims.ClientID, claims.Subject, claims.Scopes)

	// Decode request body
	var req EvaluateGrantRequest
	if err := render.DecodeJSON(r.Body, &req); err != nil {
		errMsg := fmt.Sprintf("Failed to decode request body: %v", err)
		log.Printf("[ERROR] handleEvaluateGrant: %s", errMsg)
		renderError(w, r, http.StatusBadRequest, "invalid_request", "invalid request body")
		return
	}

	log.Printf("[DEBUG] handleEvaluateGrant: Processing evaluate request - GrantID: %s, Request: %+v",
		chi.URLParam(r, "id"), req)

	// Call service to evaluate grant with client ID from JWT claims
	resp, err := h.service.EvaluateGrant(r.Context(), claims.ClientID, chi.URLParam(r, "id"), &req)
	if err != nil {
		errMsg := fmt.Sprintf("EvaluateGrant service error: %v", err)
		log.Printf("[ERROR] handleEvaluateGrant: %s", errMsg)
		switch {
		case errors.Is(err, ErrInvalidGrantID):
			renderError(w, r, http.StatusBadRequest, "invalid_grant_id", err.Error())
		case errors.Is(err, ErrGrantNotFound):
			renderError(w, r, http.StatusNotFound, "grant_not_found", err.Error())
		case errors.Is(err, ErrGrantExpired) || errors.Is(err, ErrGrantRevoked):
			renderError(w, r, http.StatusForbidden, "grant_invalid", err.Error())
		case errors.Is(err, ErrUnauthorizedForGrant):
			renderError(w, r, http.StatusForbidden, "unauthorized", err.Error())
		case errors.Is(err, ErrPDPUnavailable):
			renderError(w, r, http.StatusServiceUnavailable, "service_unavailable", "policy decision service unavailable")
		default:
			renderError(w, r, http.StatusInternalServerError, "internal_error", "an internal error occurred")
		}
		return
	}

	log.Printf("[INFO] handleEvaluateGrant: Successfully evaluated grant: %+v", resp)
	render.JSON(w, r, resp)
}
