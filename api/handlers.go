package api

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
	"idp-gm-api/middleware"
)

// Handler handles HTTP requests for the Grant Management API
type Handler struct {
	service *GrantService
}

// NewHandler creates a new API handler
func NewHandler(service *GrantService) *Handler {
	return &Handler{
		service: service,
	}
}

// RegisterRoutes registers the API routes with appropriate middleware
func (h *Handler) RegisterRoutes(r chi.Router) {
	// Health check endpoint (no auth required)
	r.Get("/health", h.handleHealthCheck)

	// Client grant endpoints (PingFederate specific)
	r.Route("/clients/{clientId}/grants", func(r chi.Router) {
		r.Get("/", h.handleListClientGrants)
		r.Delete("/", h.handleRevokeClientGrants)         // all grants
		r.Delete("/{grantId}", h.handleRevokeClientGrant) // single grant
	})

	// User grant endpoints (PingFederate specific)
	r.Route("/users/{userKey}/grants", func(r chi.Router) {
		r.Get("/", h.handleListUserGrants)
		r.Delete("/", h.handleRevokeUserGrants)
		r.Delete("/{grantId}", h.handleRevokeUserGrant)
	})

	// OIDF Grant Management API endpoints
	r.Route("/grants", func(r chi.Router) {
		// List grants (GET /grants/)
		r.With(middleware.RequireScope("grant_management_query")).Get("/", h.handleListGrants)
		
		// Each operation requires exactly its own scope, per section 6.7.1.
		//
		// These are deliberately per-route rather than an r.Use on the subtree:
		// a blanket RequireScope("grant_management_query") here would apply to
		// every route below it, so evaluating a grant would demand the right to
		// read grants as well. A client that may only ask "is this still
		// allowed?" has no business also being able to enumerate the grant.
		r.Route("/{id}", func(r chi.Router) {
			// Get grant by ID (GET /grants/{id})
			r.With(middleware.RequireScope("grant_management_query")).Get("/", h.handleGetGrant)

			// Update grant scopes (PATCH /grants/{id})
			r.With(middleware.RequireScope("grant_management_update")).Patch("/", h.handleUpdateGrant)

			// Delete/revoke grant (DELETE /grants/{id})
			r.With(middleware.RequireScope("grant_management_revoke")).Delete("/", h.handleRevokeGrant)

			// Evaluate grant (POST /grants/{id}/evaluate)
			r.With(middleware.RequireScope("grant_management_evaluate")).Post("/evaluate", h.handleEvaluateGrant)
		})
	})
}

// handleListClientGrants handles GET /clients/{clientId}/grants
func (h *Handler) handleListClientGrants(w http.ResponseWriter, r *http.Request) {
    clientID := chi.URLParam(r, "clientId")
    if clientID == "" {
        renderError(w, r, http.StatusBadRequest, "missing_client_id", "client ID is required")
        return
    }
    grants, err := h.service.ListClientGrants(r.Context(), clientID)
    if err != nil {
        renderError(w, r, http.StatusInternalServerError, "internal_error", err.Error())
        return
    }
    render.JSON(w, r, map[string]interface{}{ "grants": grants })
}

// handleListUserGrants handles GET /users/{userKey}/grants
func (h *Handler) handleListUserGrants(w http.ResponseWriter, r *http.Request) {
    userKey := chi.URLParam(r, "userKey")
    if userKey == "" {
        renderError(w, r, http.StatusBadRequest, "missing_user_key", "userKey is required")
        return
    }
    grants, err := h.service.ListUserGrants(r.Context(), userKey)
    if err != nil {
        renderError(w, r, http.StatusInternalServerError, "internal_error", err.Error())
        return
    }
    render.JSON(w, r, map[string]interface{}{ "grants": grants })
}

// handleRevokeClientGrants DELETE /clients/{clientId}/grants (all)
func (h *Handler) handleRevokeClientGrants(w http.ResponseWriter, r *http.Request) {
    clientID := chi.URLParam(r, "clientId")
    if clientID == "" {
        renderError(w, r, http.StatusBadRequest, "missing_client_id", "client ID is required")
        return
    }
    if err := h.service.RevokeClientGrants(r.Context(), clientID, ""); err != nil {
        renderError(w, r, http.StatusInternalServerError, "internal_error", err.Error())
        return
    }
    render.NoContent(w, r)
}

// handleRevokeClientGrant DELETE /clients/{clientId}/grants/{grantId}
func (h *Handler) handleRevokeClientGrant(w http.ResponseWriter, r *http.Request) {
    clientID := chi.URLParam(r, "clientId")
    grantID := chi.URLParam(r, "grantId")
    if clientID == "" || grantID == "" {
        renderError(w, r, http.StatusBadRequest, "missing_params", "client ID and grant ID are required")
        return
    }
    if err := h.service.RevokeClientGrants(r.Context(), clientID, grantID); err != nil {
        renderError(w, r, http.StatusInternalServerError, "internal_error", err.Error())
        return
    }
    render.NoContent(w, r)
}

// handleRevokeUserGrants DELETE /users/{userKey}/grants
func (h *Handler) handleRevokeUserGrants(w http.ResponseWriter, r *http.Request) {
    userKey := chi.URLParam(r, "userKey")
    if userKey == "" {
        renderError(w, r, http.StatusBadRequest, "missing_user_key", "userKey is required")
        return
    }
    if err := h.service.RevokeUserGrants(r.Context(), userKey, ""); err != nil {
        renderError(w, r, http.StatusInternalServerError, "internal_error", err.Error())
        return
    }
    render.NoContent(w, r)
}

// handleRevokeUserGrant DELETE /users/{userKey}/grants/{grantId}
func (h *Handler) handleRevokeUserGrant(w http.ResponseWriter, r *http.Request) {
    userKey := chi.URLParam(r, "userKey")
    grantID := chi.URLParam(r, "grantId")
    if userKey == "" || grantID == "" {
        renderError(w, r, http.StatusBadRequest, "missing_params", "userKey and grant ID are required")
        return
    }
    if err := h.service.RevokeUserGrants(r.Context(), userKey, grantID); err != nil {
        renderError(w, r, http.StatusInternalServerError, "internal_error", err.Error())
        return
    }
    render.NoContent(w, r)
}

// handleHealthCheck responds with the API status responds with the API status
func (h *Handler) handleHealthCheck(w http.ResponseWriter, r *http.Request) {
	render.JSON(w, r, map[string]string{"status": "ok"})
}

// handleGetGrant handles GET /grants/{id}
func (h *Handler) handleGetGrant(w http.ResponseWriter, r *http.Request) {
	log.Printf("[HANDLER] Starting handleGetGrant for path: %s", r.URL.Path)

	// Extract grant ID from URL path
	grantID := chi.URLParam(r, "id")
	log.Printf("[HANDLER] Extracted grantID: %s", grantID)

	if grantID == "" {
		errMsg := "grant ID is required"
		log.Printf("[HANDLER] Error: %s", errMsg)
		renderError(w, r, http.StatusBadRequest, "missing_grant_id", errMsg)
		return
	}

	// Get client ID from JWT claims
	claims, ok := middleware.GetTokenClaimsFromContext(r.Context())
	if !ok {
		errMsg := "missing or invalid token claims"
		log.Printf("[HANDLER] Error: %s", errMsg)
		renderError(w, r, http.StatusUnauthorized, "unauthorized", errMsg)
		return
	}

	log.Printf("[HANDLER] Token claims - ClientID: %s, Scopes: %v", claims.ClientID, claims.Scopes)

	if claims.ClientID == "" {
		errMsg := "client ID not found in token"
		log.Printf("[HANDLER] Error: %s", errMsg)
		renderError(w, r, http.StatusForbidden, "forbidden", errMsg)
		return
	}

	log.Printf("[HANDLER] Fetching grant with ID: %s for user: %s", grantID, claims.Subject)

	if claims.Subject == "" {
		errMsg := "user ID not found in token"
		log.Printf("[HANDLER] Error: %s", errMsg)
		renderError(w, r, http.StatusForbidden, "forbidden", errMsg)
		return
	}

	// Get the user ID from the token claims using the configured subject claim
	var userID string
	if claims, ok := middleware.GetTokenClaimsFromContext(r.Context()); ok {
		userID = claims.GetSubjectValue()
		if userID == "" {
			errMsg := fmt.Sprintf("subject claim not found in token using claim name: %s", os.Getenv("SUBJECT_CLAIM_NAME"))
			log.Printf("[ERROR] %s", errMsg)
			renderError(w, r, http.StatusForbidden, "forbidden", errMsg)
			return
		}
		log.Printf("[DEBUG] Using UserID from token: %s (claim: %s)", userID, os.Getenv("SUBJECT_CLAIM_NAME"))
	} else {
		errMsg := "missing or invalid token claims"
		log.Printf("[ERROR] %s", errMsg)
		renderError(w, r, http.StatusUnauthorized, "unauthorized", errMsg)
		return
	}

	// Get the grant using the user ID from the token
	grant, err := h.service.GetGrant(r.Context(), userID, grantID)
	if err != nil {
		errMsg := fmt.Sprintf("failed to get grant: %v", err)
		log.Printf("[HANDLER] Error: %s", errMsg)
		renderError(w, r, http.StatusInternalServerError, "internal_error", errMsg)
		return
	}

	log.Printf("[HANDLER] Successfully retrieved grant: %+v", grant)

	// Wrap the grant in a GrantResponse to match the OIDF Grant Management API spec
	response := GrantResponse{
		Grant: *grant,
	}
	
	log.Printf("[HANDLER] Sending response for grant ID: %s", grantID)

	render.JSON(w, r, response)
}

// handleListGrants handles GET /grants
// This endpoint returns grants for the current user
func (h *Handler) handleListGrants(w http.ResponseWriter, r *http.Request) {
	log.Printf("[DEBUG] handleListGrants: Request received from %s", r.RemoteAddr)

	// Get scope from query parameters if provided
	scope := r.URL.Query().Get("scope")

	// Get user ID from the access token using the configured subject claim
	var userID string
	if claims, ok := middleware.GetTokenClaimsFromContext(r.Context()); ok {
		userID = claims.GetSubjectValue()
		if userID == "" {
			errMsg := fmt.Sprintf("subject claim not found in token using claim name: %s", os.Getenv("SUBJECT_CLAIM_NAME"))
			log.Printf("[ERROR] handleListGrants: %s", errMsg)
			renderError(w, r, http.StatusForbidden, "forbidden", errMsg)
			return
		}
		log.Printf("[DEBUG] handleListGrants: Using UserID from token: %s (claim: %s)", userID, os.Getenv("SUBJECT_CLAIM_NAME"))
	} else {
		errMsg := "missing or invalid token claims"
		log.Printf("[ERROR] handleListGrants: %s", errMsg)
		renderError(w, r, http.StatusUnauthorized, "unauthorized", errMsg)
		return
	}

	// Create request with user ID from token
	req := &ListGrantsRequest{
		UserID: userID, // User ID from the access token
		Scope:  scope,  // Optional scope filter
	}

	log.Printf("[DEBUG] handleListGrants: Fetching grants for user: %s, scope: %s", 
		req.UserID, req.Scope)

	grants, err := h.service.ListGrants(r.Context(), req)
	if err != nil {
		log.Printf("[ERROR] handleListGrants: Failed to list grants: %v", err)
		renderError(w, r, http.StatusInternalServerError, "internal_error", err.Error())
		return
	}

	log.Printf("[INFO] handleListGrants: Successfully retrieved %d grants with filter - UserID: %s, Scope: %s",
		len(grants), req.UserID, req.Scope)

	// Wrap the grants in a GrantsResponse to match the OIDF Grant Management API spec
	response := GrantsResponse{
		Grants: make([]Grant, len(grants)),
	}

	// Convert each grant to the API model
	for i, g := range grants {
		if g != nil {
			response.Grants[i] = *g
		}
	}

	render.JSON(w, r, response)
}

// handleUpdateGrant handles PATCH /grants/{id}
func (h *Handler) handleUpdateGrant(w http.ResponseWriter, r *http.Request) {
	grantID := chi.URLParam(r, "id")
	if grantID == "" {
		renderError(w, r, http.StatusBadRequest, "missing_grant_id", "grant ID is required")
		return
	}

	var req UpdateGrantRequest
	if err := render.DecodeJSON(r.Body, &req); err != nil {
		renderError(w, r, http.StatusBadRequest, "invalid_request", "invalid request body")
		return
	}

	grant, err := h.service.UpdateGrant(r.Context(), grantID, &req)
	if err != nil {
		renderError(w, r, http.StatusInternalServerError, "internal_error", err.Error())
		return
	}

	// Wrap the grant in a GrantResponse to match the OIDF Grant Management API spec
	response := GrantResponse{
		Grant: *grant,
	}

	render.JSON(w, r, response)
}

// handleRevokeGrant handles DELETE /grants/{id}
func (h *Handler) handleRevokeGrant(w http.ResponseWriter, r *http.Request) {
	grantID := chi.URLParam(r, "id")
	if grantID == "" {
		renderError(w, r, http.StatusBadRequest, "missing_grant_id", "grant ID is required")
		return
	}

	if err := h.service.RevokeGrant(r.Context(), grantID); err != nil {
		renderError(w, r, http.StatusInternalServerError, "internal_error", err.Error())
		return
	}

	render.NoContent(w, r)
}

// renderError renders an error response
func renderError(w http.ResponseWriter, r *http.Request, status int, code, message string) {
	render.Status(r, status)
	render.JSON(w, r, &ErrorResponse{
		Error:       code,
		Description: message,
	})
}
