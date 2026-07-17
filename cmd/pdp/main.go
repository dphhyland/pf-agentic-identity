// Command pdp runs the demo AuthZEN 1.0 Policy Decision Point.
//
// It serves the AuthZEN endpoints the GM API's PDP client discovers and calls:
//
//	GET  /.well-known/authzen-configuration
//	POST /access/v1/evaluation
//	POST /access/v1/evaluations
//	GET  /health
package main

import (
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"idp-gm-api/pdp"
)

func main() {
	var (
		policyPath = flag.String("policy", envOr("PDP_POLICY", "policy/openbanking.yaml"), "path to the policy YAML")
		entPath    = flag.String("entitlements", envOr("PDP_ENTITLEMENTS", "policy/entitlements.yaml"), "path to the entitlements YAML standing in for the system of record")
		addr       = flag.String("addr", ":"+envOr("PORT", "9090"), "listen address")
		issuer     = flag.String("issuer", os.Getenv("PDP_ISSUER"), "public base URL advertised in discovery metadata")
		exposeEnt  = flag.Bool("expose-entitlements", envOr("PDP_EXPOSE_ENTITLEMENTS", "false") == "true",
			"serve GET /debug/entitlements/{subject}; demo only, never enable in production")
	)
	flag.Parse()

	policy, err := pdp.LoadPolicy(*policyPath)
	if err != nil {
		log.Fatalf("[FATAL] %v", err)
	}
	log.Printf("[INFO] loaded policy %q: %d resource types, %d actions",
		policy.Name, len(policy.Resources), len(policy.Actions))

	entitlements, err := pdp.LoadEntitlements(*entPath)
	if err != nil {
		log.Fatalf("[FATAL] %v", err)
	}
	log.Printf("[INFO] loaded entitlements from %s", *entPath)
	if *exposeEnt {
		log.Printf("[WARNING] /debug/entitlements is enabled. It lets anyone enumerate a " +
			"subject's holdings and exists only to make the demo legible. Never enable this in production.")
	}

	srv := &http.Server{
		Addr:              *addr,
		Handler:           routes(pdp.NewEngine(policy, entitlements), entitlements, *issuer, *exposeEnt),
		ReadHeaderTimeout: 10 * time.Second,
		WriteTimeout:      30 * time.Second,
	}

	log.Printf("[INFO] AuthZEN PDP listening on %s", *addr)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("[FATAL] server: %v", err)
	}
}

func routes(engine *pdp.Engine, entitlements pdp.EntitlementSource, issuer string, exposeEnt bool) http.Handler {
	mux := http.NewServeMux()

	// Demo only, and not part of AuthZEN. A production PDP must never let a
	// caller enumerate what a subject holds; this exists so the demo UI can
	// show the entitlement half of the decision next to the consent half.
	if exposeEnt {
		mux.HandleFunc("GET /debug/entitlements/{subject}", func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, http.StatusOK, entitlements.Holdings(r.Context(), r.PathValue("subject")))
		})
	}

	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})

	// Discovery. The base URL is whatever the caller reached us on unless an
	// issuer is configured, so this works behind Railway's proxy and locally
	// without reconfiguration.
	mux.HandleFunc("GET /.well-known/authzen-configuration", func(w http.ResponseWriter, r *http.Request) {
		base := issuer
		if base == "" {
			base = baseURLOf(r)
		}
		writeJSON(w, http.StatusOK, pdp.Metadata{
			PolicyDecisionPoint:       base,
			AccessEvaluationEndpoint:  base + "/access/v1/evaluation",
			AccessEvaluationsEndpoint: base + "/access/v1/evaluations",
		})
	})

	mux.HandleFunc("POST /access/v1/evaluation", func(w http.ResponseWriter, r *http.Request) {
		var req pdp.EvaluationRequest
		if !decodeJSON(w, r, &req) {
			return
		}
		resp := engine.Evaluate(r.Context(), &req)
		log.Printf("[INFO] evaluation subject=%s action=%s resource=%s/%s -> %v (%s)",
			req.Subject.ID, req.Action.Name, req.Resource.Type, req.Resource.ID,
			resp.Decision, reasonID(resp))
		writeJSON(w, http.StatusOK, resp)
	})

	mux.HandleFunc("POST /access/v1/evaluations", func(w http.ResponseWriter, r *http.Request) {
		var req pdp.EvaluationsRequest
		if !decodeJSON(w, r, &req) {
			return
		}
		resp := engine.EvaluateBatch(r.Context(), &req)
		log.Printf("[INFO] batch evaluation of %d entries", len(resp.Evaluations))
		writeJSON(w, http.StatusOK, resp)
	})

	return logging(mux)
}

func reasonID(r *pdp.EvaluationResponse) string {
	if r.Context == nil {
		return ""
	}
	return r.Context.ID
}

// baseURLOf reconstructs the URL the client used to reach us, honouring the
// forwarding headers a platform proxy such as Railway sets.
func baseURLOf(r *http.Request) string {
	scheme := "http"
	if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
		scheme = strings.Split(proto, ",")[0]
	} else if r.TLS != nil {
		scheme = "https"
	}
	host := r.Host
	if fwd := r.Header.Get("X-Forwarded-Host"); fwd != "" {
		host = strings.Split(fwd, ",")[0]
	}
	return scheme + "://" + host
}

func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		log.Printf("[WARN] bad request body on %s: %v", r.URL.Path, err)
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error":             "invalid_request",
			"error_description": err.Error(),
		})
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		log.Printf("[ERROR] write response: %v", err)
	}
}

func logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("[DEBUG] %s %s (%s)", r.Method, r.URL.Path, time.Since(start))
	})
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
