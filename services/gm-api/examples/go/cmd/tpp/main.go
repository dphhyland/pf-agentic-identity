// Command tpp is a worked example: a third party checking a standing consent before
// acting on it.
//
// This is the Open Banking shape. No user is present. The TPP authenticates as itself
// with client_credentials, names a grant it persisted at consent time, and asks whether
// that consent still covers the account it is about to read -- before spending a refresh
// token on a call that would fail.
//
//	go run ./cmd/tpp \
//	  -pf https://localhost:9131 \
//	  -client acme-budgeting -secret "$(cat .../tpp_secret)" \
//	  -grant <agid> -account 222
package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"idp-gm-api/examples/go/gmclient"
)

func main() {
	var (
		pf      = flag.String("pf", "https://localhost:9131", "PingFederate runtime base URL")
		gm      = flag.String("gm", "", "Grant Management base URL (default: <pf>/gm-api)")
		client  = flag.String("client", "acme-budgeting", "OAuth client id")
		secret  = flag.String("secret", "", "OAuth client secret (required)")
		grantID = flag.String("grant", "", "the grant to ask about (required)")
		account = flag.String("account", "111", "account to ask about")
		action  = flag.String("action", "read_balance", "action to ask about")
		insecure = flag.Bool("insecure", true, "skip TLS verification (the demo PF is self-signed)")
	)
	flag.Parse()

	if *secret == "" || *grantID == "" {
		fmt.Fprintln(os.Stderr, "-secret and -grant are required")
		flag.Usage()
		os.Exit(2)
	}
	base := *gm
	if base == "" {
		base = strings.TrimRight(*pf, "/") + "/gm-api"
	}

	httpClient := &http.Client{Timeout: 15 * time.Second}
	if *insecure {
		httpClient.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}

	// A client_credentials token has no subject, and needs none: the subject comes off
	// the grant. The TokenSource is called per request, so a real TPP would cache and
	// refresh in here rather than mint one every time.
	tokens := clientCredentials(*pf, *client, *secret, httpClient)

	c := gmclient.New(base, tokens).WithHTTPClient(httpClient)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// What did the user actually consent to? Useful for showing them, and for deciding
	// whether it is even worth asking.
	if grant, err := c.Query(ctx, *grantID); err != nil {
		log.Printf("could not read the grant: %v", err)
	} else {
		var scopes []string
		for _, s := range grant.Scopes {
			scopes = append(scopes, s.Scope)
		}
		fmt.Printf("consent: scopes=%v\n", scopes)
		for _, d := range grant.AuthorizationDetails {
			fmt.Printf("         %v over %v\n", d["actions"], d["locations"])
		}
	}

	// The question that matters.
	decision, err := c.Evaluate(ctx, *grantID, gmclient.Request{
		Action:   gmclient.Action{Name: *action},
		Resource: gmclient.Resource{Type: "account", ID: *account},
	})
	if err != nil {
		// Not a denial. We could not ask.
		var apiErr *gmclient.APIError
		if ok := asAPIError(err, &apiErr); ok && apiErr.Unavailable() {
			log.Fatalf("could not reach the decision service: %v -- retry, do not assume denied", err)
		}
		log.Fatalf("evaluate failed: %v", err)
	}

	fmt.Printf("\n%s on account %s -> ", *action, *account)
	if decision.Permitted {
		fmt.Printf("PERMIT\n  %s\n", decision.Message())
		fmt.Println("\n  Safe to spend the refresh token and make the call.")
		return
	}

	fmt.Printf("DENY  (%s)\n  %s\n", decision.ReasonID(), decision.Message())
	if decision.Retryable() {
		fmt.Println("\n  A consent problem. Send the user through authorization again for this resource.")
	} else {
		// The distinction that saves a pointless round trip through the user.
		fmt.Println("\n  Not a consent problem: the user does not hold this access.")
		fmt.Println("  Re-consenting cannot fix it. Do not send them through authorization.")
	}
	os.Exit(1)
}

// clientCredentials mints a token for the TPP itself. No user, no subject.
func clientCredentials(pf, id, secret string, httpClient *http.Client) gmclient.TokenSource {
	return func(ctx context.Context) (string, error) {
		form := url.Values{}
		form.Set("grant_type", "client_credentials")
		// Only what this program needs. A token that could also revoke would be more
		// authority than the job requires.
		form.Set("scope", "grant_management_query grant_management_evaluate")

		req, err := http.NewRequestWithContext(ctx, http.MethodPost,
			strings.TrimRight(pf, "/")+"/as/token.oauth2", strings.NewReader(form.Encode()))
		if err != nil {
			return "", err
		}
		req.SetBasicAuth(id, secret)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		resp, err := httpClient.Do(req)
		if err != nil {
			return "", fmt.Errorf("token endpoint: %w", err)
		}
		defer resp.Body.Close()

		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		if resp.StatusCode != http.StatusOK {
			return "", fmt.Errorf("token endpoint returned %d: %s", resp.StatusCode, body)
		}
		var out struct {
			AccessToken string `json:"access_token"`
		}
		if err := json.Unmarshal(body, &out); err != nil {
			return "", fmt.Errorf("decode token response: %w", err)
		}
		if out.AccessToken == "" {
			return "", fmt.Errorf("token endpoint returned no access_token: %s", body)
		}
		return out.AccessToken, nil
	}
}

// asAPIError is errors.As, spelled out to keep the example's imports obvious.
func asAPIError(err error, target **gmclient.APIError) bool {
	if e, ok := err.(*gmclient.APIError); ok {
		*target = e
		return true
	}
	return false
}
