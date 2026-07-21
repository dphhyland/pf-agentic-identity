package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/joho/godotenv"

	"idp-gm-api/api"
	"idp-gm-api/authzen"
	"idp-gm-api/config"
	"idp-gm-api/pingfederate/grant"
)

func setupLogging() (*os.File, error) {
	// Create logs directory if it doesn't exist
	logDir := "logs"
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create logs directory: %v", err)
	}

	// Create log file with timestamp
	logFile := filepath.Join(logDir, "gm-api-"+time.Now().Format("2006-01-02-15-04-05")+".log")
	file, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		return nil, fmt.Errorf("failed to open log file: %v", err)
	}

	// Set log output to both file and console
	multiWriter := io.MultiWriter(os.Stdout, file)
	log.SetOutput(multiWriter)
	log.SetFlags(log.LstdFlags | log.Lmicroseconds | log.Lshortfile)

	log.Printf("Logging to file: %s\n", logFile)
	return file, nil
}

func main() {
	// Load environment variables from .env file
	if err := godotenv.Load(); err != nil {
		log.Printf("Warning: Error loading .env file: %v", err)
	}

	// Setup logging first
	logFile, err := setupLogging()
	if err != nil {
		log.Fatalf("Failed to setup logging: %v", err)
	}
	defer logFile.Close()

	log.Println("Starting gm-api server...")
	
	// Configuration
	port := flag.String("port", "8080", "Port to listen on")
	pingFederateURL := flag.String("pingfederate-url", "https://localhost:9031", "PingFederate base URL")
	authToken := flag.String("auth-token", "", "Bearer token for PingFederate admin API (optional)")
	adminUser := flag.String("admin-user", "", "PingFederate admin username (optional)")
	adminPass := flag.String("admin-pass", "", "PingFederate admin password (optional)")
	authZenURL := flag.String("authzen-url", "http://localhost:8081", "AuthZEN PDP base URL")
	insecureSkipVerify := flag.Bool("insecure-skip-verify", false, "Skip TLS certificate verification (use with caution in development only)")
	noJWTValidation := flag.Bool("no-jwt-validation", false, "Disable JWT validation (use with caution in development only)")
	envSkipJWTValidation := os.Getenv("SKIP_JWT_VALIDATION") == "true"
	flag.Parse()

	// If environment variable is set, it overrides the flag
	if envSkipJWTValidation {
		*noJWTValidation = true
	}
	
	log.Println("Command line flags parsed")

	// Load configuration from environment variables
	if *port == "8080" {
		if envPort := os.Getenv("GM_PORT"); envPort != "" {
			*port = envPort
		}
	}

	// Load PingFederate configuration
	if *pingFederateURL == "https://localhost:9031" {
		if envPF := os.Getenv("GM_PINGFEDERATE_URL"); envPF != "" {
			*pingFederateURL = envPF
		}
	}

	// Load PingFederate credentials
	if *authToken == "" {
		*authToken = os.Getenv("PINGFED_ADMIN_TOKEN")
	}
	if *adminUser == "" {
		*adminUser = os.Getenv("PINGFED_ADMIN_USER")
	}
	if *adminPass == "" {
		*adminPass = os.Getenv("PINGFED_ADMIN_PASS")
	}

	// Load AuthZen configuration from environment or use default
	if envURL := os.Getenv("AUTHZEN_BASE_URL"); envURL != "" {
		*authZenURL = envURL
	} else {
		log.Printf("WARNING: AUTHZEN_BASE_URL not set, using default: %s", *authZenURL)
	}
	log.Printf("Using AuthZen URL: %s", *authZenURL)

	if *authToken == "" && *adminUser == "" {
        log.Fatal("authentication required: provide --auth-token or --admin-user/--admin-pass (or env vars)")
    }

	// Initialize PingFederate client with Basic Auth (using admin credentials from environment)
    grantClient := grant.NewClient(*pingFederateURL, "", *adminUser, *adminPass)

	// Authenticate to the PDP however AUTH_TYPE says: bearer, oauth, or none.
	authZenAuthenticator, err := authzen.NewAuthenticatorFromEnv()
	if err != nil {
		log.Fatalf("Failed to configure AuthZen authentication (check AUTH_TYPE): %v", err)
	}
	if os.Getenv("AUTH_TYPE") == string(authzen.AuthTypeNone) {
		log.Printf("WARNING: AUTH_TYPE=none - calling the PDP without credentials. " +
			"Acceptable only for a PDP that is genuinely unprotected.")
	}
	authZenClient, err := authzen.NewAuthZenClient(*authZenURL, authZenAuthenticator)
	if err != nil {
		log.Fatalf("Failed to create AuthZen client: %v", err)
	}
	// Set log level to debug for detailed logging
	authZenClient.SetLogLevel("debug")

	// Log warning if running without JWT validation
	if *noJWTValidation {
		log.Println("WARNING: Running with JWT validation DISABLED - This should only be used for development")
	} else {
		log.Println("JWT validation is ENABLED")
	}

	// Log current configuration
	log.Printf("Server configuration:")
	log.Printf("  Port: %s", *port)
	log.Printf("  PingFederate URL: %s", *pingFederateURL)
	log.Printf("  AuthZen URL: %s", *authZenURL)
	log.Printf("  Insecure Skip Verify: %v", *insecureSkipVerify)
	log.Printf("  JWT Validation: %v", !*noJWTValidation)

	// Load auth config with optional mock validator and insecure skip verify
	authConfig := config.LoadConfig(*noJWTValidation, *insecureSkipVerify)
	rateLimiterConfig := config.LoadRateLimiterConfig()

	if *insecureSkipVerify {
		log.Println("[WARNING] Running with TLS certificate verification disabled. DO NOT USE IN PRODUCTION!")
	}

	// Initialize middleware
	// Note: The rate limiter and CSRF middleware will be added in the server setup

	// Initialize API server
	server := api.NewServer(&api.Config{
		GrantClient:   grantClient,
		AuthZenClient: authZenClient,
		AuthConfig:    authConfig,
		RateLimiter:   rateLimiterConfig,
		CSRFConfig:    nil, // Disable CSRF for API access
	})

	// Start server in a goroutine
	go func() {
		addr := ":" + *port
		log.Printf("Starting HTTP server on %s\n", addr)
		if err := server.Start(addr); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Failed to start server: %v", err)
		} else if err == http.ErrServerClosed {
			log.Println("Server was shut down gracefully")
		} else {
			log.Println("Server stopped without error")
		}
	}()

	// Wait for interrupt signal to gracefully shut down the server
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	
	log.Println("Server is running. Press Ctrl+C to stop.")
	log.Println("Waiting for interrupt signal...")
	
	// Block until we receive our signal
	sig := <-quit
	log.Printf("Received signal: %v. Shutting down server...\n", sig)

	// Perform any cleanup here if needed
	log.Println("Server shutdown completed")
}
