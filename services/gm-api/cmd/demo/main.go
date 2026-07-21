// Command demo runs a self-contained walkthrough of the Grant Evaluation API.
//
// It stands in for the authorization server: it holds a few consents in memory
// instead of reading them from PingFederate's Persistent Grant Management API,
// and otherwise performs the same steps section 8.4.2 requires of the AS --
// check the grant is active and unexpired, then hand the grant's constraints to
// the PDP as AuthZEN request context and return the decision with its reasons.
//
// The point is to make the protocol visible without needing a PingFederate to
// hand. Everything downstream of this process -- the AuthZEN request shape, the
// PDP, the policy -- is exactly what the real GM API drives.
package main

import (
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"
)

//go:embed static
var static embed.FS

func main() {
	var (
		addr   = flag.String("addr", ":"+envOr("PORT", "8081"), "listen address")
		pdpURL = flag.String("pdp", envOr("AUTHZEN_BASE_URL", "http://localhost:9090"), "AuthZEN PDP base URL")
	)
	flag.Parse()

	app := &demo{
		pdp:    &pdpClient{baseURL: *pdpURL, http: &http.Client{Timeout: 10 * time.Second}},
		grants: demoGrants(),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("GET /api/grants", app.listGrants)
	mux.HandleFunc("GET /api/entitlements/{subject}", app.entitlements)
	mux.HandleFunc("POST /api/grants/{id}/evaluate", app.evaluate)
	mux.Handle("GET /", http.FileServerFS(mustSubFS()))

	log.Printf("[INFO] demo UI on %s, PDP at %s", *addr, *pdpURL)
	srv := &http.Server{Addr: *addr, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("[FATAL] %v", err)
	}
}

// ---- domain ----

// Grant mirrors the parts of a PingFederate persistent grant the evaluation
// flow depends on.
type Grant struct {
	ID          string                `json:"id"`
	ClientID    string                `json:"client_id"`
	ClientName  string                `json:"client_name"`
	Subject     string                `json:"subject"`
	Status      string                `json:"status"`
	Scopes      []string              `json:"scopes"`
	ExpiresAt   int64                 `json:"expires_at"`
	AuthzDetail []AuthorizationDetail `json:"authorization_details"`
	Story       string                `json:"story"`
}

// AuthorizationDetail is an RFC 9396 authorization_details entry: the machine
// readable record of what the user actually consented to.
type AuthorizationDetail struct {
	Type      string         `json:"type"`
	Actions   []string       `json:"actions,omitempty"`
	Locations []string       `json:"locations,omitempty"`
	Data      map[string]any `json:"data,omitempty"`
}

func (g *Grant) expired() bool { return g.ExpiresAt > 0 && g.ExpiresAt < time.Now().Unix() }

func demoGrants() []*Grant {
	in90Days := time.Now().Add(90 * 24 * time.Hour).Unix()

	return []*Grant{
		{
			ID: "grant-alice-accounts", ClientID: "acme-budgeting", ClientName: "Acme Budgeting",
			Subject: "alice", Status: "active", Scopes: []string{"openid", "accounts.read"},
			ExpiresAt: in90Days,
			AuthzDetail: []AuthorizationDetail{{
				Type:      "account_information",
				Actions:   []string{"read_balance", "read_transactions"},
				Locations: []string{"111", "222", "444"},
			}},
			Story: "Alice consented to share three accounts, for reading only — and this " +
				"grant is perfectly valid. But she has since closed 222, and she is only a " +
				"view-only signatory on the business account 444. Compare the consent with " +
				"what she actually holds: the grant permits more than she can give.",
		},
		{
			ID: "grant-alice-payments", ClientID: "acme-payments", ClientName: "Acme Payments",
			Subject: "alice", Status: "active", Scopes: []string{"openid", "payments.write"},
			ExpiresAt: in90Days,
			AuthzDetail: []AuthorizationDetail{{
				Type:      "payment_initiation",
				Actions:   []string{"initiate_payment"},
				Locations: []string{"pmt-1"},
			}},
			Story: "Alice authorised a single payment, and policy caps it at 1000. " +
				"Try an amount above the cap to see a contextual denial.",
		},
		{
			ID: "grant-bob-expired", ClientID: "acme-budgeting", ClientName: "Acme Budgeting",
			Subject: "bob", Status: "active", Scopes: []string{"openid", "accounts.read"},
			ExpiresAt: time.Now().Add(-24 * time.Hour).Unix(),
			AuthzDetail: []AuthorizationDetail{{
				Type:      "account_information",
				Actions:   []string{"read_balance"},
				Locations: []string{"555"},
			}},
			Story: "Bob's consent lapsed yesterday. The AS refuses before the PDP is " +
				"ever consulted, because an expired grant carries no authority.",
		},
		{
			ID: "grant-carol-revoked", ClientID: "acme-budgeting", ClientName: "Acme Budgeting",
			Subject: "carol", Status: "revoked", Scopes: []string{"openid", "accounts.read"},
			ExpiresAt: in90Days,
			AuthzDetail: []AuthorizationDetail{{
				Type:      "account_information",
				Actions:   []string{"read_balance"},
				Locations: []string{"777"},
			}},
			Story: "Carol withdrew her consent. Revocation takes effect on the next " +
				"evaluation -- no token needs to expire first.",
		},
	}
}

// ---- server ----

type demo struct {
	pdp    *pdpClient
	grants []*Grant
}

func (d *demo) find(id string) *Grant {
	for _, g := range d.grants {
		if g.ID == id {
			return g
		}
	}
	return nil
}

func (d *demo) listGrants(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, d.grants)
}

// entitlements shows what a subject actually holds, by asking the PDP's
// demo-only debug endpoint.
//
// Note what this is *not*: the GM API never asserts entitlement, and never sees
// it as part of a decision. It is the PDP that looks entitlement up, from the
// system of record, because the GM API is not the authority on what a subject
// holds. This endpoint exists purely so the UI can show you the half of the
// decision the GM API has no say in. Neither it nor the PDP endpoint behind it
// would exist in production.
func (d *demo) entitlements(w http.ResponseWriter, r *http.Request) {
	holdings, err := d.pdp.holdings(r.Context(), r.PathValue("subject"))
	if err != nil {
		log.Printf("[WARN] entitlement display lookup failed: %v", err)
		// Not fatal: the UI simply cannot show this half.
		writeJSON(w, http.StatusOK, map[string]any{})
		return
	}
	writeJSON(w, http.StatusOK, holdings)
}

// evaluateRequest is the Grant Evaluation API request body. The subject is
// deliberately absent: it comes from the grant, never from the caller.
type evaluateRequest struct {
	Action struct {
		Name       string         `json:"name"`
		Properties map[string]any `json:"properties,omitempty"`
	} `json:"action"`
	Resource struct {
		Type       string         `json:"type"`
		ID         string         `json:"id"`
		Properties map[string]any `json:"properties,omitempty"`
	} `json:"resource"`
	Context map[string]any `json:"context,omitempty"`
}

// evaluateResponse is the Grant Evaluation API response, plus the AuthZEN
// exchange it was derived from so the demo can show its working.
type evaluateResponse struct {
	Decision bool           `json:"decision"`
	Context  map[string]any `json:"context,omitempty"`
	Trace    *trace         `json:"trace,omitempty"`
}

type trace struct {
	Step            string `json:"step"`
	AuthZenRequest  any    `json:"authzen_request,omitempty"`
	AuthZenResponse any    `json:"authzen_response,omitempty"`
}

func (d *demo) evaluate(w http.ResponseWriter, r *http.Request) {
	grant := d.find(r.PathValue("id"))
	if grant == nil {
		writeErr(w, http.StatusNotFound, "grant_not_found", "no such grant")
		return
	}

	var req evaluateRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if req.Resource.Type == "" {
		// 422 per section 6.7.4: the request is well formed but names no resource.
		writeErr(w, http.StatusUnprocessableEntity, "missing_resource", "a resource type is required")
		return
	}

	// Section 8.4.2: the AS applies the grant's own state first. A revoked or
	// expired grant carries no authority, so the PDP is never consulted.
	if grant.Status == "revoked" {
		writeDecision(w, false, "grant_revoked", "This consent has been withdrawn.",
			&trace{Step: "Denied by the authorization server: the grant is revoked. The PDP was not consulted."})
		return
	}
	if grant.expired() {
		writeDecision(w, false, "grant_expired", "This consent has expired.",
			&trace{Step: "Denied by the authorization server: the grant expired. The PDP was not consulted."})
		return
	}

	// The grant's constraints become the AuthZEN request context: this is what
	// lets a general-purpose PDP decide against this specific consent.
	azReq := map[string]any{
		"subject":  map[string]any{"type": "user", "id": grant.Subject},
		"action":   map[string]any{"name": req.Action.Name, "properties": req.Action.Properties},
		"resource": map[string]any{"type": req.Resource.Type, "id": req.Resource.ID},
		"context": map[string]any{
			"oauth":                 map[string]any{"client_id": grant.ClientID, "grant_id": grant.ID},
			"scopes":                grant.Scopes,
			"authorization_details": grant.AuthzDetail,
		},
	}

	azResp, err := d.pdp.evaluate(r.Context(), azReq)
	if err != nil {
		// Section 6.7.4: the evaluation service is unreachable.
		log.Printf("[ERROR] PDP call failed: %v", err)
		writeErr(w, http.StatusServiceUnavailable, "service_unavailable", "policy decision service unavailable")
		return
	}

	decision, _ := azResp["decision"].(bool)
	resp := evaluateResponse{
		Decision: decision,
		Trace: &trace{
			Step:            "Decided by the PDP against the grant's consent.",
			AuthZenRequest:  azReq,
			AuthZenResponse: azResp,
		},
	}
	// Forward only the user-safe reason; reason_admin stays with the operator.
	if ctx, ok := azResp["context"].(map[string]any); ok {
		reason := map[string]any{}
		if id, ok := ctx["id"].(string); ok {
			reason["id"] = id
		}
		if ru, ok := ctx["reason_user"].(map[string]any); ok {
			if msg, ok := ru["en"].(string); ok {
				reason["message"] = msg
			}
		}
		if len(reason) > 0 {
			resp.Context = map[string]any{"reasons": []any{reason}}
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

func writeDecision(w http.ResponseWriter, decision bool, id, msg string, t *trace) {
	writeJSON(w, http.StatusOK, evaluateResponse{
		Decision: decision,
		Context:  map[string]any{"reasons": []any{map[string]any{"id": id, "message": msg}}},
		Trace:    t,
	})
}

// ---- PDP client ----

type pdpClient struct {
	baseURL string
	http    *http.Client
}

// holdings reads the PDP's demo-only entitlement endpoint.
func (c *pdpClient) holdings(ctx context.Context, subject string) (map[string]any, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		c.baseURL+"/debug/entitlements/"+url.PathEscape(subject), nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("PDP returned %d for entitlements: %s", resp.StatusCode, raw)
	}

	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("decode entitlements: %w", err)
	}
	return out, nil
}

func (c *pdpClient) evaluate(ctx context.Context, body any) (map[string]any, error) {
	b, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.baseURL+"/access/v1/evaluation", bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("PDP returned %d: %s", resp.StatusCode, raw)
	}

	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("decode PDP response: %w", err)
	}
	return out, nil
}

// ---- helpers ----

func mustSubFS() fs.FS {
	sub, err := fs.Sub(static, "static")
	if err != nil {
		panic(err)
	}
	return sub
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		log.Printf("[ERROR] write response: %v", err)
	}
}

func writeErr(w http.ResponseWriter, status int, code, desc string) {
	writeJSON(w, status, map[string]string{"error": code, "error_description": desc})
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
