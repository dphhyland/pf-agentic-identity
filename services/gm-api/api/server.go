package api

import (
	"log"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/go-chi/render"
	"idp-gm-api/authzen"
	authmiddleware "idp-gm-api/middleware"
	"idp-gm-api/pingfederate/grant"
)

// Server represents the Grant Management API server
type Server struct {
	router  *chi.Mux
	handler *Handler
	cfg     *Config // Add config field to store server configuration
}

// Config holds the server configuration
// Config holds the server configuration
type Config struct {
	GrantClient   *grant.Client
	AuthZenClient *authzen.AuthZenClient
	AuthConfig   *authmiddleware.AuthConfig
	// RateLimiter is the configuration for rate limiting
	RateLimiter *authmiddleware.RateLimiterConfig
	// CSRFConfig is the configuration for CSRF protection
	CSRFConfig *authmiddleware.CSRFConfig
}

// NewServer creates a new API server instance
func NewServer(cfg *Config) *Server {
	// Initialize services
	grantService := NewGrantService(cfg.GrantClient, cfg.AuthZenClient)

	// Initialize handlers
	handler := NewHandler(grantService)

	s := &Server{
		router: chi.NewRouter(),
		handler: handler,
		cfg:     cfg,
	}

	s.setupMiddleware()
	s.setupRoutes()

	return s
}

// setupMiddleware configures the server middleware
func (s *Server) setupMiddleware() {
	s.router.Use(chimiddleware.RequestID)
	s.router.Use(chimiddleware.RealIP)
	s.router.Use(chimiddleware.Logger)
	s.router.Use(chimiddleware.Recoverer)
	s.router.Use(render.SetContentType(render.ContentTypeJSON))

	// Apply rate limiting if configured
	if s.cfg.RateLimiter != nil {
		s.router.Use(authmiddleware.RateLimit(s.cfg.RateLimiter))
	}

	// Add rate limit headers to responses
	s.router.Use(authmiddleware.RateLimitHeaders)

	// CORS configuration
	corsMiddleware := cors.New(cors.Options{
		AllowedOrigins:   []string{"*"}, // Adjust in production
		AllowedMethods:   []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token"},
		ExposedHeaders:   []string{"Link", "X-CSRF-Token"}, // Expose CSRF token header
		AllowCredentials: true,
		MaxAge:           300, // Maximum value not ignored by any of major browsers
	})
	s.router.Use(corsMiddleware.Handler)

	// Add CSRF protection for non-GET/HEAD/OPTIONS requests if configured
	if s.cfg.CSRFConfig != nil {
		csrf := authmiddleware.NewCSRF(s.cfg.CSRFConfig)
		s.router.Use(csrf.Handler)

		// Add a route to get a CSRF token
		s.router.Get("/api/csrf-token", func(w http.ResponseWriter, r *http.Request) {
			token, err := csrf.GenerateToken()
			if err != nil {
				http.Error(w, "Failed to generate CSRF token", http.StatusInternalServerError)
				return
			}

			// Set the token in a cookie
			csrf.SetTokenCookie(w, token)

			// Return the token in the response
			render.JSON(w, r, map[string]string{
				"csrfToken": token,
			})
		})
	}
}

// setupRoutes configures the server routes with authentication and authorization
func (s *Server) setupRoutes() {
	// Public routes (no auth required)
	s.router.Get("/health", s.handler.handleHealthCheck)

	// API v1 routes
	s.router.Route("/api/v1", func(r chi.Router) {
		// Apply authentication middleware to all API routes
		r.Use(authmiddleware.Authenticate(s.cfg.AuthConfig.TokenValidator))

		// Register the API routes with the authenticated router
		s.handler.RegisterRoutes(r)
	})
}

// ServeHTTP implements the http.Handler interface
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.router.ServeHTTP(w, r)
}

// Start starts the HTTP server
func (s *Server) Start(addr string) error {
	server := &http.Server{
		Addr:    addr,
		Handler: s.router,
		// Add timeouts to prevent slowloris attacks
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	log.Printf("Starting server on %s", addr)
	return server.ListenAndServe()
}
