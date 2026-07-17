package pdp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

// AccountsAPIEntitlements reads entitlement from the bank's own accounts service.
//
// This is the other half of the authority, and the half no grant can assert. The grant says
// the client may read account CHK-1001; only the bank knows whether the subject still holds
// CHK-1001 at all. StaticEntitlements stands in for that system of record with a file; this
// asks the real one, so "you no longer have access to this account" is a fact about the bank
// rather than a fixture that has to be kept in step with it by hand.
//
// Two properties this depends on, both deliberate in the accounts API:
//
//   - The lookup is READ-ONLY. The accounts API opens a customer file on first touch, but only
//     when the caller authenticates AS that customer (X-Auth-Principal == customer_id). We send
//     no principal header, so an unknown subject is a 404 and never a newly created customer.
//     An entitlement question must not bring into existence the thing it is asking about.
//   - A CLOSED account is not held. The store keeps closed accounts with status != "open", and
//     a consent that names one is precisely the case worth showing: the grant is valid, names
//     the account, and is worth nothing.
type AccountsAPIEntitlements struct {
	baseURL string
	client  *http.Client
}

// rightsOverOwnAccount is what holding an open account means here.
//
// The demo bank has no per-account rights model — a customer owns their accounts outright — so
// ownership confers the full set. A real deployment reads these per account (Alice is a
// signatory on the business account with view rights only, and a consent to move money from it
// was never worth anything); the shape below is where that would be read, not invented.
var rightsOverOwnAccount = []string{"read_balance", "read_transactions", "initiate_payment"}

func NewAccountsAPIEntitlements(baseURL string) *AccountsAPIEntitlements {
	return &AccountsAPIEntitlements{
		baseURL: baseURL,
		client:  &http.Client{Timeout: 10 * time.Second},
	}
}

type acctEntry struct {
	ID     string `json:"id"`
	Type   string `json:"type"`
	Status string `json:"status"`
}

type acctListResponse struct {
	Accounts []acctEntry `json:"accounts"`
}

// fetch returns the subject's open accounts. A 404 means the bank has no file for this
// subject, which is a real answer — they hold nothing — not an error.
func (a *AccountsAPIEntitlements) fetch(ctx context.Context, subject string) ([]acctEntry, error) {
	endpoint := fmt.Sprintf("%s/customers/%s/accounts", a.baseURL, url.PathEscape(subject))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	// No X-Auth-Principal on purpose: see the type comment. With one, the accounts API would
	// self-provision a customer file for an unknown subject and the answer would always be yes.
	resp, err := a.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("accounts api: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("accounts api: %s returned %d", endpoint, resp.StatusCode)
	}

	var out acctListResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("accounts api: decode: %w", err)
	}
	return out.Accounts, nil
}

func (a *AccountsAPIEntitlements) RightsOn(ctx context.Context, subject, resourceType, resourceID string) ([]string, bool, error) {
	// The bank is the system of record for accounts and nothing else. Claiming to know about
	// other resource types would be asserting an entitlement no one here can see.
	if resourceType != "account" {
		return nil, false, nil
	}
	accounts, err := a.fetch(ctx, subject)
	if err != nil {
		// Propagate: an entitlement lookup that FAILED is not the same as one that came back
		// empty, and the engine must not read a transport error as "holds nothing".
		return nil, false, err
	}
	for _, acct := range accounts {
		if acct.ID != resourceID {
			continue
		}
		if acct.Status != "open" {
			// Held once, closed now. The grant may still name it; the authority is gone.
			return nil, false, nil
		}
		return rightsOverOwnAccount, true, nil
	}
	return nil, false, nil
}

func (a *AccountsAPIEntitlements) Holdings(ctx context.Context, subject string) HoldingsByType {
	accounts, err := a.fetch(ctx, subject)
	if err != nil || len(accounts) == 0 {
		return nil
	}
	byID := RightsByResourceID{}
	for _, acct := range accounts {
		if acct.Status == "open" {
			byID[acct.ID] = rightsOverOwnAccount
		}
	}
	if len(byID) == 0 {
		return nil
	}
	return HoldingsByType{"account": byID}
}
