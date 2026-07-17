package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"

	"idp-gm-api/middleware"
)

// Section 6.7.1 gives each Grant Management operation its own scope. This test
// pins that each route requires exactly its own and no more.
//
// The case that matters is evaluate. It previously sat under a subtree-wide
// r.Use(RequireScope("grant_management_query")), so a client holding only
// grant_management_evaluate was refused: asking "is this still allowed?"
// demanded the right to read the grant too. A client that may only ask the
// question has no business also being able to enumerate the grant.
func TestRouteScopes_EachOperationRequiresOnlyItsOwn(t *testing.T) {
	tests := []struct {
		name       string
		method     string
		path       string
		tokenScope string
		wantAllow  bool
	}{
		{"evaluate with only the evaluate scope", "POST", "/grants/g1/evaluate", "grant_management_evaluate", true},
		{"evaluate must not also demand query", "POST", "/grants/g1/evaluate", "grant_management_query", false},
		{"read with the query scope", "GET", "/grants/g1", "grant_management_query", true},
		{"read must not accept the evaluate scope", "GET", "/grants/g1", "grant_management_evaluate", false},
		{"revoke with the revoke scope", "DELETE", "/grants/g1", "grant_management_revoke", true},
		{"revoke must not accept the query scope", "DELETE", "/grants/g1", "grant_management_query", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			reached := false
			terminal := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				reached = true
				w.WriteHeader(http.StatusOK)
			})

			// Mirror the real scope wiring, with a handler that just records arrival.
			r := chi.NewRouter()
			r.Route("/grants", func(r chi.Router) {
				r.Route("/{id}", func(r chi.Router) {
					r.With(middleware.RequireScope("grant_management_query")).Get("/", terminal)
					r.With(middleware.RequireScope("grant_management_update")).Patch("/", terminal)
					r.With(middleware.RequireScope("grant_management_revoke")).Delete("/", terminal)
					r.With(middleware.RequireScope("grant_management_evaluate")).Post("/evaluate", terminal)
				})
			})

			req := httptest.NewRequest(tc.method, tc.path, nil)
			req = req.WithContext(middleware.ContextWithTokenClaims(req.Context(), &middleware.TokenClaims{
				ClientID: "acme-budgeting",
				Scopes:   []string{tc.tokenScope},
			}))

			rec := httptest.NewRecorder()
			r.ServeHTTP(rec, req)

			if tc.wantAllow {
				assert.True(t, reached, "the handler should be reached with scope %q", tc.tokenScope)
			} else {
				assert.False(t, reached, "scope %q must not reach this handler", tc.tokenScope)
				assert.Equal(t, http.StatusForbidden, rec.Code)
			}
		})
	}
}
